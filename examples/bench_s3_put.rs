//! S3 chunk-PUT benchmark — HEAD-before-PUT vs unconditional PUT.
//!
//! `DedupService::settle_batch` writes every NEW chunk of every upload via
//! `put_blob_from_bytes_unsynced`. S3/Azure never overrode it, so the trait
//! default routed it through `put_blob_from_bytes`, whose "idempotent" HEAD
//! probe made every chunk write pay 2 request round-trips. Content-addressed
//! keys make re-PUTs overwrite-safe, so the new override PUTs directly.
//!
//! The stub S3 endpoint (in-process axum, per-request latency injection)
//! counts HEAD/PUT requests:
//!   BEFORE — put_blob_from_bytes        (HEAD 404 + PUT per chunk)
//!   AFTER  — put_blob_from_bytes_unsynced (PUT per chunk)
//!
//! Section 2 measures the removed Azure `data.to_vec()` copy in isolation.
//!
//! Gates: AFTER request count == chunks (vs 2x), AFTER wall < BEFORE wall.
//!
//! No Postgres. Run:
//!   cargo run --release --features bench --example bench_s3_put
//! Tunables: BENCH_CHUNKS (500), BENCH_CHUNK_KB (256), BENCH_CONCURRENCY (8),
//!           BENCH_RTT_MS (10)

use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use oxicloud::application::ports::blob_storage_ports::BlobStorageBackend;
use oxicloud::common::config::S3StorageConfig;
use oxicloud::infrastructure::services::s3_blob_backend::S3BlobBackend;

fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[derive(Clone, Default)]
struct Counters {
    heads: Arc<AtomicU64>,
    puts: Arc<AtomicU64>,
}

async fn stub_s3(latency: Duration, counters: Counters) -> String {
    use axum::http::{Method, StatusCode};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
        let counters = counters.clone();
        async move {
            tokio::time::sleep(latency).await;
            match *req.method() {
                Method::HEAD => {
                    counters.heads.fetch_add(1, Ordering::Relaxed);
                    StatusCode::NOT_FOUND
                }
                Method::PUT => {
                    // Drain the body like a real endpoint would.
                    let _ = axum::body::to_bytes(req.into_body(), usize::MAX).await;
                    counters.puts.fetch_add(1, Ordering::Relaxed);
                    StatusCode::OK
                }
                _ => StatusCode::OK,
            }
        }
    });
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    format!("http://{addr}")
}

async fn drive(
    backend: Arc<S3BlobBackend>,
    chunks: usize,
    chunk_kb: usize,
    concurrency: usize,
    unsynced: bool,
) -> f64 {
    let payload = Bytes::from(vec![0x5au8; chunk_kb * 1024]);
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let t = Instant::now();
    let mut set = tokio::task::JoinSet::new();
    for i in 0..chunks {
        let b = backend.clone();
        let p = payload.clone();
        let sem = sem.clone();
        set.spawn(async move {
            let _permit = sem.acquire().await.expect("sem");
            let hash = format!("{i:064x}");
            let n = if unsynced {
                b.put_blob_from_bytes_unsynced(&hash, p).await.expect("put")
            } else {
                b.put_blob_from_bytes(&hash, p).await.expect("put")
            };
            assert_eq!(n as usize, chunk_kb * 1024);
        });
    }
    while let Some(r) = set.join_next().await {
        r.expect("join");
    }
    t.elapsed().as_secs_f64() * 1000.0
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let chunks: usize = env_or("BENCH_CHUNKS", 500);
    let chunk_kb: usize = env_or("BENCH_CHUNK_KB", 256);
    let concurrency: usize = env_or("BENCH_CONCURRENCY", 8);
    let rtt_ms: u64 = env_or("BENCH_RTT_MS", 10);

    let counters = Counters::default();
    let endpoint = stub_s3(Duration::from_millis(rtt_ms), counters.clone()).await;
    let backend = Arc::new(S3BlobBackend::new(&S3StorageConfig {
        endpoint_url: Some(endpoint),
        bucket: "bench".into(),
        region: "us-east-1".into(),
        access_key: "bench".into(),
        secret_key: "bench".into(),
        force_path_style: true,
    }));

    println!(
        "# {chunks} x {chunk_kb} KiB chunk PUTs at concurrency {concurrency}, {rtt_ms} ms/request stub"
    );
    println!(
        "{:<26} {:>10} {:>8} {:>8} {:>8}",
        "variant", "wall ms", "HEADs", "PUTs", "vs OLD"
    );

    // BEFORE: the trait-default route (put_blob_from_bytes = HEAD + PUT).
    let before = drive(backend.clone(), chunks, chunk_kb, concurrency, false).await;
    let before_heads = counters.heads.swap(0, Ordering::Relaxed);
    let before_puts = counters.puts.swap(0, Ordering::Relaxed);
    println!(
        "{:<26} {:>10.0} {:>8} {:>8} {:>8}",
        "BEFORE (HEAD+PUT)", before, before_heads, before_puts, "1.0x"
    );

    // AFTER: the unsynced override (PUT only).
    let after = drive(backend.clone(), chunks, chunk_kb, concurrency, true).await;
    let after_heads = counters.heads.swap(0, Ordering::Relaxed);
    let after_puts = counters.puts.swap(0, Ordering::Relaxed);
    println!(
        "{:<26} {:>10.0} {:>8} {:>8} {:>8}",
        "AFTER (PUT only)",
        after,
        after_heads,
        after_puts,
        format!("{:.1}x", before / after)
    );

    // ── Section 2: the removed Azure to_vec() copy, in isolation ───────
    let mb = 4;
    let data = Bytes::from(vec![0x77u8; mb * 1024 * 1024]);
    let reps = 200;
    let t = Instant::now();
    for _ in 0..reps {
        let v = data.to_vec();
        std::hint::black_box(&v);
    }
    let copy_ms = t.elapsed().as_secs_f64() * 1000.0 / reps as f64;
    println!(
        "\n# [2] removed Azure per-chunk copy: to_vec() of {mb} MiB = {copy_ms:.2} ms + {mb} MiB transient alloc per chunk"
    );

    // ── Gates ───────────────────────────────────────────────────────────
    if after_heads != 0 || after_puts != chunks as u64 {
        eprintln!(
            "GATE FAIL: AFTER issued {after_heads} HEADs / {after_puts} PUTs (expected 0 / {chunks})"
        );
        std::process::exit(1);
    }
    if after >= before {
        eprintln!(
            "GATE FAIL: AFTER ({after:.0} ms) not faster than BEFORE ({before:.0} ms) — rollback"
        );
        std::process::exit(1);
    }
    println!(
        "GATE PASS: {}-request walk -> {} requests, {:.1}x faster",
        before_heads + before_puts,
        after_puts,
        before / after
    );
}
