use {
    crate::worker::ConnectionOutcome, std::time::Duration, typenet_utils::error::TraceableResult,
};

pub(crate) struct Report {
    pub attempted: usize,
    pub verified: usize,
    pub mismatched: usize,
    pub errored: usize,
    pub bytes_transferred: usize,
    pub wall_time: Duration,
    pub throughput_bytes_per_sec: Option<f64>,
    pub p50: Option<Duration>,
    pub p95: Option<Duration>,
    pub p99: Option<Duration>,
    pub max: Option<Duration>,
}

/// Aggregates per-connection outcomes into success/mismatch/error counts, throughput, and latency
/// percentiles.
///
/// # Errors
///
/// Returns `Err` if computing a latency percentile fails (which should never happen).
#[expect(
    clippy::cast_precision_loss,
    reason = "Throughput reporting only needs approximate precision"
)]
pub(crate) fn summarize(
    outcomes: &[TraceableResult<ConnectionOutcome>],
    wall_time: Duration,
) -> TraceableResult<Report> {
    let mismatched = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Ok(o) if !o.verified))
        .count();

    let errored = outcomes.iter().filter(|outcome| outcome.is_err()).count();

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

    let (p50, p95, p99, max) = if latencies.is_empty() {
        (None, None, None, None)
    } else {
        (
            Some(percentile(&latencies, 50)?),
            Some(percentile(&latencies, 95)?),
            Some(percentile(&latencies, 99)?),
            latencies.last().copied(),
        )
    };

    let seconds = wall_time.as_secs_f64();
    let throughput_bytes_per_sec = (seconds > 0.0).then(|| bytes_transferred as f64 / seconds);

    Ok(Report {
        attempted: outcomes.len(),
        verified: successes.len(),
        mismatched,
        errored,
        bytes_transferred,
        wall_time,
        throughput_bytes_per_sec,
        p50,
        p95,
        p99,
        max,
    })
}

/// Returns the `pct`-th percentile (0-100) of `sorted`, which must be non-empty and already sorted
/// ascending.
///
/// # Errors
///
/// Returns `Err` if `sorted` is empty or the computed index is out of range. (Neither should happen
/// given the constraints above.)
fn percentile(sorted: &[Duration], pct: usize) -> TraceableResult<Duration> {
    let last_index = sorted
        .len()
        .checked_sub(1)
        .ok_or("Cannot compute a percentile of an empty latency set")?;

    let index = last_index.saturating_mul(pct) / 100;

    sorted
        .get(index)
        .copied()
        .ok_or_else(|| format!("Index {index} out of range for {} latencies", sorted.len()).into())
}

/// Prints a human-readable summary of `report` to stdout.
pub(crate) fn print(report: &Report) {
    println!("Attempted connections : {}", report.attempted);
    println!("Verified echoes       : {}", report.verified);
    println!("Mismatched echoes     : {}", report.mismatched);
    println!("Connection errors     : {}", report.errored);

    println!("Bytes transferred     : {}", report.bytes_transferred);
    println!("Wall time             : {:.3}s", report.wall_time.as_secs_f64());

    println!("Throughput            : {}", fmt_throughput(report.throughput_bytes_per_sec));
    println!("Latency p50           : {}", fmt_latency(report.p50));
    println!("Latency p95           : {}", fmt_latency(report.p95));
    println!("Latency p99           : {}", fmt_latency(report.p99));
    println!("Latency max           : {}", fmt_latency(report.max));
}

fn fmt_throughput(bytes_per_sec: Option<f64>) -> String {
    bytes_per_sec.map_or_else(|| "n/a".to_owned(), |b| format!("{:.2} MB/s", b / 1_000_000.0))
}

fn fmt_latency(latency: Option<Duration>) -> String {
    latency.map_or_else(|| "n/a".to_owned(), |d| format!("{d:?}"))
}
