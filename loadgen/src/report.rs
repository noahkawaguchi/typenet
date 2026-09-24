use {
    crate::worker::ConnectionOutcome,
    std::{fmt, time::Duration},
    typenet_utils::error::TraceableResult,
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
    pub server_cpu: Option<Duration>,
    pub server_cpu_pct_of_wall: Option<f64>,
}

impl Report {
    /// Aggregates per-connection outcomes into success/mismatch/error counts, throughput, and
    /// latency percentiles, and relates `server_cpu` (if measured) to `wall_time`.
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
        server_cpu: Option<Duration>,
    ) -> TraceableResult<Self> {
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

        let wall_secs = wall_time.as_secs_f64();

        let throughput_bytes_per_sec =
            (wall_secs > 0.0).then(|| bytes_transferred as f64 / wall_secs);

        let server_cpu_pct_of_wall = (wall_secs > 0.0)
            .then(|| server_cpu.map(|cpu| cpu.as_secs_f64() / wall_secs * 100.0))
            .flatten();

        Ok(Self {
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
            server_cpu,
            server_cpu_pct_of_wall,
        })
    }
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

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Attempted connections : {}", self.attempted)?;
        writeln!(f, "Verified echoes       : {}", self.verified)?;
        writeln!(f, "Mismatched echoes     : {}", self.mismatched)?;
        writeln!(f, "Connection errors     : {}", self.errored)?;
        writeln!(f)?;
        writeln!(f, "Bytes transferred     : {}", self.bytes_transferred)?;
        writeln!(f, "Wall time             : {}", fmt_duration(Some(self.wall_time)))?;
        writeln!(f, "Server CPU time       : {}", fmt_duration(self.server_cpu))?;
        writeln!(f, "Server CPU / wall     : {}", fmt_percent(self.server_cpu_pct_of_wall))?;
        writeln!(f, "Throughput            : {}", fmt_throughput(self.throughput_bytes_per_sec))?;
        writeln!(f)?;
        writeln!(f, "Latency p50           : {}", fmt_duration(self.p50))?;
        writeln!(f, "Latency p95           : {}", fmt_duration(self.p95))?;
        writeln!(f, "Latency p99           : {}", fmt_duration(self.p99))?;
        writeln!(f, "Latency max           : {}", fmt_duration(self.max))
    }
}

fn fmt_throughput(bytes_per_sec: Option<f64>) -> String {
    bytes_per_sec.map_or_else(|| "n/a".to_owned(), |b| format!("{:.2} MB/s", b / 1_000_000.0))
}

fn fmt_duration(duration: Option<Duration>) -> String {
    duration.map_or_else(|| "n/a".to_owned(), |d| format!("{d:?}"))
}

fn fmt_percent(percent: Option<f64>) -> String {
    percent.map_or_else(|| "n/a".to_owned(), |p| format!("{p:.1}%"))
}
