use {
    criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main},
    std::hint::black_box,
    typenet_stack::checksum,
};

/// A representative range of input sizes: a bare IPv4/TCP header, a standard Ethernet MTU payload,
/// the largest possible IPv4 packet, and an even larger packet that could overflow a 32-bit
/// accumulator.
const INPUT_SIZES: [usize; 4] = [20, 1500, 65_535, checksum::DEFERRED_CARRIES_MAX_BYTES + 16];

type LabeledImplementation = (&'static str, fn(&[u8]) -> u16);

/// The set of checksum implementations to compare.
const IMPLEMENTATIONS: [LabeledImplementation; 4] = [
    ("production", checksum::calculate),
    ("always_folded", checksum::always_folded_cksum),
    ("naive_wrapping", checksum::naive_wrapping_cksum),
    ("range_checked", checksum::range_checked_cksum),
];

/// Compares the production checksum implementation against alternative implementations only exposed
/// for benchmarking purposes.
fn bench_checksum(c: &mut Criterion) {
    let mut group = c.benchmark_group("checksum");

    for size in INPUT_SIZES {
        let input = vec![0xABu8; size];

        group.throughput(Throughput::Bytes(size as u64)); // Report throughput in bytes/sec

        for (label, cksum_fn) in IMPLEMENTATIONS {
            group.bench_with_input(BenchmarkId::new(label, size), &input, |b, data| {
                b.iter(|| cksum_fn(black_box(data)));
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_checksum);
criterion_main!(benches);
