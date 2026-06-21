//! Phase 0 — Task 0.2: thumbnail render latency + output-size baseline.
//!
//! Measures the CPU-bound render path (decode → EXIF orientation → resize →
//! JPEG encode) per size and for the all-sizes upload path, across the size/
//! format corpus. `Throughput::Elements(1)` makes criterion report images/sec
//! alongside ms/image. Output byte sizes (bandwidth/disk proxy) are printed once
//! as a table before the timed runs.
//!
//! Run: `cargo bench --features bench`
//! HTML report: `target/criterion/report/index.html`

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use oxicloud::bench_support::{self, CorpusCase};
use oxicloud::infrastructure::services::thumbnail_service::{ThumbnailService, ThumbnailSize};

const SIZES: [ThumbnailSize; 3] = [
    ThumbnailSize::Icon,
    ThumbnailSize::Preview,
    ThumbnailSize::Large,
];

/// Print the output-size table (per-size encoded JPEG bytes) once. This is the
/// bandwidth/disk half of the Task 0.2 deliverable.
fn print_output_sizes(corpus: &[CorpusCase]) {
    println!("\n=== Output size baseline (encoded JPEG bytes per thumbnail) ===");
    println!(
        "| {:<17} | {:<5} | {:>11} | {:>8} | {:>7} | {:>8} | {:>8} |",
        "case", "fmt", "source", "input KB", "icon B", "preview B", "large B"
    );
    println!(
        "|{:-<19}|{:-<7}|{:-<13}|{:-<10}|{:-<9}|{:-<10}|{:-<10}|",
        "", "", "", "", "", "", ""
    );
    for case in corpus {
        let sizes = ThumbnailService::bench_render_all(&case.bytes).unwrap_or_default();
        let get = |want: ThumbnailSize| {
            sizes
                .iter()
                .find(|(s, _)| *s == want)
                .map(|(_, n)| *n)
                .unwrap_or(0)
        };
        println!(
            "| {:<17} | {:<5} | {:>5}×{:<5} | {:>8} | {:>6} | {:>8} | {:>8} |",
            case.name,
            case.format,
            case.width,
            case.height,
            case.bytes.len() / 1024,
            get(ThumbnailSize::Icon),
            get(ThumbnailSize::Preview),
            get(ThumbnailSize::Large),
        );
    }
    println!();
}

fn configure(group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>) {
    // Big images (48 MP) are slow per-iter; keep the suite bounded but stable.
    group
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(6));
}

fn bench_thumbnails(c: &mut Criterion) {
    let corpus = bench_support::load_or_generate();
    assert!(!corpus.is_empty(), "corpus is empty — generation failed");
    print_output_sizes(&corpus);

    // Per-size single-thumbnail latency (the lazy request path).
    for size in SIZES {
        let mut group = c.benchmark_group(format!("render_thumbnail/{size:?}"));
        configure(&mut group);
        for case in &corpus {
            group.throughput(Throughput::Elements(1));
            group.bench_with_input(BenchmarkId::from_parameter(case.name), case, |b, case| {
                b.iter(|| {
                    let out =
                        ThumbnailService::bench_render_thumbnail(black_box(&case.bytes), size)
                            .expect("render_thumbnail");
                    black_box(out.len())
                });
            });
        }
        group.finish();
    }

    // All-sizes-in-one-decode latency (the eager upload path).
    let mut group = c.benchmark_group("render_all");
    configure(&mut group);
    for case in &corpus {
        group.throughput(Throughput::Elements(1));
        group.bench_with_input(BenchmarkId::from_parameter(case.name), case, |b, case| {
            b.iter(|| {
                let out =
                    ThumbnailService::bench_render_all(black_box(&case.bytes)).expect("render_all");
                black_box(out.len())
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_thumbnails);
criterion_main!(benches);
