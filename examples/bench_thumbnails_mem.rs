//! Phase 0 — Task 0.3: peak-RAM and saturated-throughput baseline.
//!
//! Two measurements criterion does not give us:
//!   1. **Peak heap per decode** — via a counting global allocator wrapping the
//!      system allocator. We snapshot the high-water mark of bytes allocated
//!      around a single `render_all` call, i.e. the transient decode/resize/
//!      encode footprint. This is the number the `Semaphore` (`cpus/2`) exists
//!      to bound, and the one shrink-on-load (Task 1.1) should collapse.
//!   2. **Throughput under saturation** — N = cores threads hammering the same
//!      image for a fixed window → photos/sec and effective ms/photo, mirroring
//!      a burst of hundreds of uploads.
//!
//! Heap bytes here are *logical allocation* (what the program requested), not
//! RSS. For a Max-RSS cross-check on macOS run the binary under:
//!   `/usr/bin/time -l ./target/release/examples/bench_thumbnails_mem`
//!
//! Run: `cargo run --release --features bench --example bench_thumbnails_mem`

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use oxicloud::bench_support::{self, CorpusCase};
use oxicloud::infrastructure::services::thumbnail_service::{ThumbnailService, ThumbnailSize};

// ---------------------------------------------------------------------------
// Counting allocator
// ---------------------------------------------------------------------------

struct TrackingAlloc;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = unsafe { System.realloc(ptr, layout, new_size) };
        if !p.is_null() {
            if new_size >= layout.size() {
                let delta = new_size - layout.size();
                let now = CURRENT.fetch_add(delta, Ordering::Relaxed) + delta;
                PEAK.fetch_max(now, Ordering::Relaxed);
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        p
    }
}

#[global_allocator]
static GLOBAL: TrackingAlloc = TrackingAlloc;

fn current() -> usize {
    CURRENT.load(Ordering::Relaxed)
}
fn peak() -> usize {
    PEAK.load(Ordering::Relaxed)
}
fn reset_peak_to_current() {
    PEAK.store(CURRENT.load(Ordering::Relaxed), Ordering::Relaxed);
}

const MB: f64 = 1024.0 * 1024.0;

// ---------------------------------------------------------------------------
// Measurements
// ---------------------------------------------------------------------------

struct PeakRow {
    name: &'static str,
    format: &'static str,
    width: u32,
    height: u32,
    megapixels: f64,
    input_bytes: usize,
    output_bytes: usize,
    single_ms: f64,
    peak_heap_bytes: usize,
}

/// Single-thread: peak transient heap + latency for one `render_all`.
fn measure_peak(case: &CorpusCase) -> PeakRow {
    // Warm up (let any one-time lazy allocations settle) and discard.
    let _ = ThumbnailService::bench_render_all(&case.bytes).expect("render_all warmup");

    let mut best_peak = 0usize;
    let mut best_ms = f64::INFINITY;
    let mut output_bytes = 0usize;
    for _ in 0..3 {
        reset_peak_to_current();
        let base = current();
        let t = Instant::now();
        let out = ThumbnailService::bench_render_all(&case.bytes).expect("render_all");
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        let pk = peak().saturating_sub(base);
        output_bytes = out.iter().map(|(_, n)| *n).sum();
        black_box(&out);
        best_peak = best_peak.max(pk);
        best_ms = best_ms.min(ms);
    }

    PeakRow {
        name: case.name,
        format: case.format,
        width: case.width,
        height: case.height,
        megapixels: case.megapixels(),
        input_bytes: case.bytes.len(),
        output_bytes,
        single_ms: best_ms,
        peak_heap_bytes: best_peak,
    }
}

struct ThroughputRow {
    name: &'static str,
    width: u32,
    height: u32,
    megapixels: f64,
    threads: usize,
    seconds: f64,
    photos: u64,
    photos_per_sec: f64,
    eff_ms_per_photo: f64,
}

/// N=threads workers render the same image until the window elapses.
fn measure_throughput(case: &CorpusCase, threads: usize, window: Duration) -> ThroughputRow {
    let counter = AtomicU64::new(0);
    let start = Instant::now();
    let deadline = start + window;

    thread::scope(|s| {
        for _ in 0..threads {
            let counter = &counter;
            let bytes = &case.bytes;
            s.spawn(move || {
                while Instant::now() < deadline {
                    let out = ThumbnailService::bench_render_all(bytes).expect("render_all");
                    black_box(out.len());
                    counter.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });

    let elapsed = start.elapsed().as_secs_f64();
    let photos = counter.load(Ordering::Relaxed);
    let pps = photos as f64 / elapsed;
    ThroughputRow {
        name: case.name,
        width: case.width,
        height: case.height,
        megapixels: case.megapixels(),
        threads,
        seconds: elapsed,
        photos,
        photos_per_sec: pps,
        eff_ms_per_photo: if pps > 0.0 { 1000.0 / pps } else { 0.0 },
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

fn main() {
    let threads = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let corpus = bench_support::load_or_generate();
    assert!(!corpus.is_empty(), "corpus is empty — generation failed");

    println!("\n###########################################################");
    println!("# Phase 0 baseline — thumbnail render (current `image` crate)");
    println!("# cores (available_parallelism): {threads}");
    println!("# corpus dir: {}", bench_support::corpus_dir().display());
    println!("# heap = logical allocation high-water mark (not RSS)");
    println!("###########################################################\n");

    // --- Table A: peak RAM + single-thread latency + output size ---
    println!("== A. Per-image: peak heap, single-thread latency, output size ==");
    println!(
        "| {:<17} | {:<5} | {:>11} | {:>6} | {:>8} | {:>9} | {:>13} | {:>11} |",
        "case", "fmt", "source", "MP", "input KB", "out KB", "render_all ms", "peak heap MB"
    );
    println!(
        "|{:-<19}|{:-<7}|{:-<13}|{:-<8}|{:-<10}|{:-<11}|{:-<15}|{:-<13}|",
        "", "", "", "", "", "", "", ""
    );
    let mut peak_rows = Vec::new();
    for case in &corpus {
        let row = measure_peak(case);
        println!(
            "| {:<17} | {:<5} | {:>5}×{:<5} | {:>6.1} | {:>8} | {:>9} | {:>13.2} | {:>11.1} |",
            row.name,
            row.format,
            row.width,
            row.height,
            row.megapixels,
            row.input_bytes / 1024,
            row.output_bytes / 1024,
            row.single_ms,
            row.peak_heap_bytes as f64 / MB,
        );
        peak_rows.push(row);
    }

    // --- Table B: saturated throughput (JPEG photo sizes only) ---
    println!("\n== B. Saturated throughput ({threads} threads, 3s window) ==");
    println!(
        "| {:<17} | {:>11} | {:>6} | {:>7} | {:>8} | {:>11} | {:>14} |",
        "case", "source", "MP", "threads", "photos", "photos/sec", "eff ms/photo"
    );
    println!(
        "|{:-<19}|{:-<13}|{:-<8}|{:-<9}|{:-<10}|{:-<13}|{:-<16}|",
        "", "", "", "", "", "", ""
    );
    let mut tp_rows = Vec::new();
    for case in corpus.iter().filter(|c| is_throughput_case(c.name)) {
        let row = measure_throughput(case, threads, Duration::from_secs(3));
        println!(
            "| {:<17} | {:>5}×{:<5} | {:>6.1} | {:>7} | {:>8} | {:>11.1} | {:>14.2} |",
            row.name,
            row.width,
            row.height,
            row.megapixels,
            row.threads,
            row.photos,
            row.photos_per_sec,
            row.eff_ms_per_photo,
        );
        tp_rows.push(row);
    }

    // --- Table C: quality — shrink-on-load vs full decode (Task 1.1 gate) ---
    println!("\n== C. Quality: shrink-on-load vs full-decode, Preview 400px ==");
    println!(
        "| {:<17} | {:>11} | {:>7} | {:>9} |",
        "case", "thumb dims", "SSIM", "PSNR dB"
    );
    println!("|{:-<19}|{:-<13}|{:-<9}|{:-<11}|", "", "", "", "");
    for case in corpus.iter().filter(|c| {
        matches!(
            c.name,
            "jpeg_12mp" | "jpeg_24mp" | "jpeg_48mp" | "small_300"
        )
    }) {
        let new_jpeg =
            ThumbnailService::bench_render_thumbnail(&case.bytes, ThumbnailSize::Preview)
                .expect("shrink-on-load render");
        let ref_jpeg = reference_render_full_decode(&case.bytes, 400);
        let (a, aw, ah) = decode_to_luma(&new_jpeg);
        let (b, bw, bh) = decode_to_luma(&ref_jpeg);
        if (aw, ah) != (bw, bh) {
            println!(
                "| {:<17} | {:>4}×{:<4} ⚠ ref {}×{} (dim mismatch) |",
                case.name, aw, ah, bw, bh
            );
            continue;
        }
        let ssim = block_ssim(&a, &b, aw, ah);
        let psnr = psnr(&a, &b);
        let flag = if ssim >= 0.98 { "" } else { "  ⚠ below 0.98" };
        println!(
            "| {:<17} | {:>4}×{:<4} | {:>7.4} | {:>9.2} |{}",
            case.name, aw, ah, ssim, psnr, flag
        );
    }

    write_json(threads, &peak_rows, &tp_rows);

    println!(
        "\nWrote machine-readable baseline → {}",
        json_path().display()
    );
    println!(
        "For Max RSS / CPU time cross-check, re-run under:\n  /usr/bin/time -l ./target/release/examples/bench_thumbnails_mem\n"
    );
}

/// Throughput is only meaningful on the realistic upload load — the JPEG photo
/// sizes. (Tiny / GIF / WebP cases stay in the per-image table.)
fn is_throughput_case(name: &str) -> bool {
    matches!(name, "jpeg_12mp" | "jpeg_24mp" | "jpeg_48mp")
}

fn json_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("bench-baseline-fase0.json")
}

fn write_json(threads: usize, peak_rows: &[PeakRow], tp_rows: &[ThroughputRow]) {
    let per_image: Vec<_> = peak_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "case": r.name,
                "format": r.format,
                "width": r.width,
                "height": r.height,
                "megapixels": r.megapixels,
                "input_bytes": r.input_bytes,
                "output_bytes": r.output_bytes,
                "single_ms": r.single_ms,
                "peak_heap_bytes": r.peak_heap_bytes,
            })
        })
        .collect();

    let throughput: Vec<_> = tp_rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "case": r.name,
                "width": r.width,
                "height": r.height,
                "megapixels": r.megapixels,
                "threads": r.threads,
                "seconds": r.seconds,
                "photos": r.photos,
                "photos_per_sec": r.photos_per_sec,
                "eff_ms_per_photo": r.eff_ms_per_photo,
            })
        })
        .collect();

    let doc = serde_json::json!({
        "phase": 0,
        "label": "baseline-image-crate",
        "cores": threads,
        "per_image": per_image,
        "throughput": throughput,
    });

    if let Err(e) = std::fs::write(
        json_path(),
        serde_json::to_string_pretty(&doc).unwrap_or_default(),
    ) {
        eprintln!("could not write {}: {e}", json_path().display());
    }
}

// ---------------------------------------------------------------------------
// Quality verification helpers (Table C)
// ---------------------------------------------------------------------------

/// Reference thumbnail: identical resample + q80 JPEG encode as production, but
/// forced through a **full decode** (no shrink-on-load). Comparing against this
/// isolates exactly the quality impact of DCT scale-on-decode. EXIF orientation
/// is not applied here, so only run it on orientation=1 corpus cases.
fn reference_render_full_decode(bytes: &[u8], max_dim: u32) -> Vec<u8> {
    let img = image::load_from_memory(bytes).expect("ref full decode");
    let (ow, oh) = (img.width(), img.height());
    let (nw, nh) = if ow > oh {
        (max_dim, (oh as f32 * (max_dim as f32 / ow as f32)) as u32)
    } else {
        ((ow as f32 * (max_dim as f32 / oh as f32)) as u32, max_dim)
    };
    let rgb = img
        .resize(nw, nh, image::imageops::FilterType::CatmullRom)
        .to_rgb8();
    let mut buf = Vec::new();
    let enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, 80);
    rgb.write_with_encoder(enc).expect("ref encode");
    buf
}

/// Decode a JPEG thumbnail back to an 8-bit luma plane for comparison.
fn decode_to_luma(jpeg: &[u8]) -> (Vec<u8>, u32, u32) {
    let img = image::load_from_memory(jpeg).expect("decode thumbnail");
    let luma = img.to_luma8();
    let (w, h) = (luma.width(), luma.height());
    (luma.into_raw(), w, h)
}

/// Mean SSIM over non-overlapping 8×8 blocks (luma). 1.0 = identical.
fn block_ssim(a: &[u8], b: &[u8], w: u32, h: u32) -> f64 {
    const C1: f64 = (0.01 * 255.0) * (0.01 * 255.0);
    const C2: f64 = (0.03 * 255.0) * (0.03 * 255.0);
    let (w, h) = (w as usize, h as usize);
    let bs = 8usize;
    let mut acc = 0.0;
    let mut blocks = 0.0;
    let mut by = 0;
    while by < h {
        let mut bx = 0;
        while bx < w {
            let (mut sa, mut sb, mut saa, mut sbb, mut sab, mut n) = (0.0, 0.0, 0.0, 0.0, 0.0, 0.0);
            for y in by..(by + bs).min(h) {
                for x in bx..(bx + bs).min(w) {
                    let ia = a[y * w + x] as f64;
                    let ib = b[y * w + x] as f64;
                    sa += ia;
                    sb += ib;
                    saa += ia * ia;
                    sbb += ib * ib;
                    sab += ia * ib;
                    n += 1.0;
                }
            }
            let (ma, mb) = (sa / n, sb / n);
            let va = (saa / n - ma * ma).max(0.0);
            let vb = (sbb / n - mb * mb).max(0.0);
            let cov = sab / n - ma * mb;
            let s = ((2.0 * ma * mb + C1) * (2.0 * cov + C2))
                / ((ma * ma + mb * mb + C1) * (va + vb + C2));
            acc += s;
            blocks += 1.0;
            bx += bs;
        }
        by += bs;
    }
    if blocks > 0.0 { acc / blocks } else { 1.0 }
}

/// Peak signal-to-noise ratio (luma). ∞ for identical inputs.
fn psnr(a: &[u8], b: &[u8]) -> f64 {
    let n = a.len().min(b.len());
    if n == 0 {
        return f64::INFINITY;
    }
    let mse: f64 = a
        .iter()
        .zip(b.iter())
        .take(n)
        .map(|(&x, &y)| {
            let d = x as f64 - y as f64;
            d * d
        })
        .sum::<f64>()
        / n as f64;
    if mse == 0.0 {
        f64::INFINITY
    } else {
        10.0 * (255.0 * 255.0 / mse).log10()
    }
}
