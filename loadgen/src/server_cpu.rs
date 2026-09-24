use {
    std::{fs, time::Duration},
    typenet_utils::error::TraceableResult,
};

/// The process name the kernel reports in `/proc/<pid>/comm` for the server binary.
const SERVER_COMM: &str = "typenet-server";

/// Best-effort measurement of the server's CPU time across a load test. Problems are reported to
/// stderr instead of failing the run.
pub(crate) struct ServerCpuMeter {
    pid: u32,
    start: Duration,
}

impl ServerCpuMeter {
    /// Finds the single running server process and records its current CPU time. Returns `None` if
    /// the server cannot be found or measured.
    pub(crate) fn start() -> Option<Self> {
        find_server_pid()
            .and_then(|pid| cpu_time(pid).map(|start| Self { pid, start }))
            .inspect_err(|e| eprintln!("Not measuring server CPU time: {e}"))
            .ok()
    }

    /// Returns the CPU time the server consumed since `start`, or `None` if it cannot be measured.
    pub(crate) fn stop(self) -> Option<Duration> {
        cpu_time(self.pid)
            .and_then(|end| {
                end.checked_sub(self.start)
                    .ok_or_else(|| "Server CPU time decreased (did the server restart?)".into())
            })
            .inspect_err(|e| eprintln!("Not measuring server CPU time: {e}"))
            .ok()
    }
}

/// Finds the PID of the running server by scanning `/proc/*/comm`.
///
/// # Errors
///
/// Returns `Err` if `/proc` cannot be read or there is not exactly one running server process.
fn find_server_pid() -> TraceableResult<u32> {
    let mut pids = fs::read_dir("/proc")?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            // Processes can exit mid-scan, so an unreadable `comm` just means no match
            fs::read_to_string(format!("/proc/{pid}/comm"))
                .is_ok_and(|comm| comm.trim_end() == SERVER_COMM)
        });

    match (pids.next(), pids.next()) {
        (Some(pid), None) => Ok(pid),
        (None, _) => Err(format!("No running {SERVER_COMM} process found").into()),
        (Some(_), Some(_)) => Err(format!("Multiple running {SERVER_COMM} processes found").into()),
    }
}

/// Returns the total CPU time consumed so far by the live threads of process `pid`, summing the
/// nanosecond run time (the first field) of each `/proc/<pid>/task/<tid>/schedstat`.
///
/// Threads that exited before the call are not counted, which is fine for the server because its
/// worker threads live for the entire process.
///
/// # Errors
///
/// Returns `Err` if the process does not exist or a thread's `schedstat` cannot be read or parsed.
fn cpu_time(pid: u32) -> TraceableResult<Duration> {
    fs::read_dir(format!("/proc/{pid}/task"))?.try_fold(Duration::ZERO, |total, entry| {
        total
            .checked_add(Duration::from_nanos(
                fs::read_to_string(entry?.path().join("schedstat"))?
                    .split_ascii_whitespace()
                    .next()
                    .ok_or("Empty schedstat file")?
                    .parse::<u64>()
                    .map_err(|e| format!("Failed to parse schedstat run time nanos: {e}"))?,
            ))
            .ok_or_else(|| "Server CPU time overflowed `Duration`".into())
    })
}
