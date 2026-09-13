use std::{
    io,
    os::fd::{AsFd, AsRawFd as _, BorrowedFd},
    time::Duration,
};

/// The result of polling `read_fd`, and optionally `shutdown_fd`, for readability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    /// `read_fd` became readable and `shutdown_fd` did not.
    Readable,

    /// `shutdown_fd` became readable and `read_fd` did not.
    Shutdown,

    /// Both `read_fd` and `shutdown_fd` became readable.
    Both,

    /// The timeout elapsed with neither `read_fd` nor `shutdown_fd` becoming readable.
    Timeout,
}

/// Polls `read_fd` for readability, additionally waking early if `shutdown_fd` becomes readable
/// first.
///
/// `shutdown_fd` exists so that a thread blocked here can be woken by writing to a shared eventfd
/// even if the shutdown signal itself was delivered to a different thread. Pass `None` to poll only
/// `read_fd`.
///
/// If `timeout` is `Some(duration)`, blocks for at most `duration`, otherwise blocks indefinitely
/// (i.e. until `read_fd` or `shutdown_fd` is readable, or the syscall is interrupted).
///
/// # Errors
///
/// Returns `Err` for errors from the `poll()` syscall. Specifically, if a signal is caught while
/// blocked and `SA_RESTART` is not set, returns `Err` with `io::ErrorKind::Interrupted`.
#[expect(unsafe_code, reason = "libc syscall to poll for fd readiness")]
pub fn readable(
    read_fd: impl AsFd,
    shutdown_fd: Option<BorrowedFd<'_>>,
    timeout: Option<Duration>,
) -> io::Result<PollOutcome> {
    // Set input `events` to `POLLIN` to signify interest in there being data to read
    let mut fds = [
        libc::pollfd { fd: read_fd.as_fd().as_raw_fd(), events: libc::POLLIN, revents: 0 },
        libc::pollfd {
            // A negative `fd` is ignored by `poll()`, with `revents` left at 0
            fd: shutdown_fd.map_or(-1, |sfd| sfd.as_raw_fd()),
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    // -1 means block indefinitely
    let timeout_ms =
        timeout.map_or(-1, |duration| duration.as_millis().try_into().unwrap_or(libc::c_int::MAX));

    // SAFETY: `fds.as_mut_ptr()` is a valid, aligned, writable pointer to two initialized `pollfd`
    // structs, and 2 is their correct length.
    match unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) } {
        ..0 => Err(io::Error::last_os_error()),

        0 => Ok(PollOutcome::Timeout),

        // `revents` is a bitmask of which events actually occurred, so `POLLIN` being set for
        // `read_fd` means it became readable
        1 if fds[0].revents & libc::POLLIN != 0 => Ok(PollOutcome::Readable),

        1 => Ok(PollOutcome::Shutdown),

        2.. => Ok(PollOutcome::Both),
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        pretty_assertions::assert_eq,
        std::{
            io::Write as _,
            os::unix::net::UnixStream,
            thread::{self, JoinHandle},
        },
        typenet_utils::error::TraceableResult,
    };

    /// Joins on a writer thread with error handling.
    fn join_writer(writer: JoinHandle<io::Result<()>>) -> TraceableResult {
        writer
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("Writer thread panicked")))
            .map_err(Into::into)
    }

    #[test]
    fn readable_when_data_is_available() -> TraceableResult {
        let (mut tx, rx) = UnixStream::pair()?;
        tx.write_all(b"hi")?;
        assert_eq!(readable(&rx, None, Some(Duration::ZERO))?, PollOutcome::Readable);
        Ok(())
    }

    #[test]
    fn timed_out_when_no_data_is_available() -> TraceableResult {
        let (_tx, rx) = UnixStream::pair()?;
        assert_eq!(readable(&rx, None, Some(Duration::ZERO))?, PollOutcome::Timeout);
        Ok(())
    }

    #[test]
    fn handles_extreme_durations() -> TraceableResult {
        let (mut tx, rx) = UnixStream::pair()?;
        tx.write_all(b"hi")?;
        assert_eq!(readable(&rx, None, Some(Duration::MAX))?, PollOutcome::Readable);
        Ok(())
    }

    #[test]
    fn blocks_until_data_arrives_when_timeout_is_none() -> TraceableResult {
        let (mut tx, rx) = UnixStream::pair()?;

        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            tx.write_all(b"hi")
        });

        assert_eq!(readable(&rx, None, None)?, PollOutcome::Readable);

        join_writer(writer)
    }

    #[test]
    fn readable_when_data_arrives_in_time() -> TraceableResult {
        let (mut tx, rx) = UnixStream::pair()?;

        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            tx.write_all(b"hi")
        });

        assert_eq!(readable(&rx, None, Some(Duration::from_millis(100)))?, PollOutcome::Readable);

        join_writer(writer)
    }

    #[test]
    fn timed_out_when_data_arrives_too_late() -> TraceableResult {
        let (mut tx, rx) = UnixStream::pair()?;

        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            tx.write_all(b"hi")
        });

        assert_eq!(readable(&rx, None, Some(Duration::from_millis(50)))?, PollOutcome::Timeout);

        join_writer(writer)
    }

    #[test]
    fn woken_when_only_shutdown_fd_is_readable() -> TraceableResult {
        let (_tx, rx) = UnixStream::pair()?;
        let (mut shutdown_tx, shutdown_rx) = UnixStream::pair()?;
        shutdown_tx.write_all(b"shutdown")?;

        assert_eq!(
            readable(&rx, Some(shutdown_rx.as_fd()), Some(Duration::from_millis(50)))?,
            PollOutcome::Shutdown
        );

        Ok(())
    }

    #[test]
    fn shutdown_fd_readable_wakes_a_would_be_indefinite_block() -> TraceableResult {
        let (_tx, rx) = UnixStream::pair()?;
        let (mut shutdown_tx, shutdown_rx) = UnixStream::pair()?;

        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            shutdown_tx.write_all(b"shutdown")
        });

        assert_eq!(readable(&rx, Some(shutdown_rx.as_fd()), None)?, PollOutcome::Shutdown);

        join_writer(writer)
    }

    #[test]
    fn notices_when_both_read_fd_and_shutdown_fd_are_readable() -> TraceableResult {
        let (mut tx, rx) = UnixStream::pair()?;
        tx.write_all(b"hi")?;

        let (mut shutdown_tx, shutdown_rx) = UnixStream::pair()?;
        shutdown_tx.write_all(b"shutdown")?;

        assert_eq!(
            readable(&rx, Some(shutdown_rx.as_fd()), Some(Duration::ZERO))?,
            PollOutcome::Both
        );

        Ok(())
    }
}
