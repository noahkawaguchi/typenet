use {
    crate::worker::ConnectionOutcome, std::time::Duration, typenet_utils::error::TraceableResult,
};

pub(crate) struct Report {
    pub attempted: usize,
    pub verified: usize,
    pub bytes_transferred: usize,
    pub wall_time: Duration,
    pub throughput_bytes_per_sec: f64,
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub max: Duration,
}

/// Aggregates per-connection outcomes into overall success counts, throughput, and latency
/// percentiles.
#[must_use]
#[expect(
    clippy::cast_precision_loss,
    reason = "Throughput reporting only needs approximate precision"
)]
pub(crate) fn summarize(
    outcomes: &[TraceableResult<ConnectionOutcome>],
    wall_time: Duration,
) -> Report {
    let successes = outcomes
        .iter()
        .filter_map(|outcome| outcome.as_ref().ok())
        .filter(|outcome| outcome.verified)
        .collect::<Vec<_>>();

    let bytes_transferred = successes
        .iter()
        .fold(0usize, |acc, outcome| acc.saturating_add(outcome.bytes_echoed));

    let mut latencies = successes
        .iter()
        .map(|outcome| outcome.round_trip)
        .collect::<Vec<_>>();

    latencies.sort_unstable();

    Report {
        attempted: outcomes.len(),
        verified: successes.len(),
        bytes_transferred,
        wall_time,
        throughput_bytes_per_sec: bytes_transferred as f64 / wall_time.as_secs_f64(),
        p50: percentile(&latencies, 50),
        p95: percentile(&latencies, 95),
        p99: percentile(&latencies, 99),
        max: latencies.last().copied().unwrap_or(Duration::ZERO),
    }
}

/// Returns the `pct`-th percentile (0-100) of `sorted`, which must already be sorted ascending.
fn percentile(sorted: &[Duration], pct: usize) -> Duration {
    let Some(last_index) = sorted.len().checked_sub(1) else { return Duration::ZERO };

    let index = last_index
        .saturating_mul(pct)
        .checked_div(100)
        .unwrap_or(last_index);

    sorted.get(index).copied().unwrap_or(Duration::ZERO)
}

/// Prints a human-readable summary of `report` to stdout.
pub(crate) fn print(report: &Report) {
    println!("Attempted connections : {}", report.attempted);
    println!("Verified echoes       : {}", report.verified);
    println!("Failed/mismatched     : {}", report.attempted.saturating_sub(report.verified));
    println!("Bytes transferred     : {}", report.bytes_transferred);
    println!("Wall time             : {:.3}s", report.wall_time.as_secs_f64());
    println!("Throughput            : {:.2} MB/s", report.throughput_bytes_per_sec / 1_000_000.0);
    println!("Latency p50           : {:?}", report.p50);
    println!("Latency p95           : {:?}", report.p95);
    println!("Latency p99           : {:?}", report.p99);
    println!("Latency max           : {:?}", report.max);
}
