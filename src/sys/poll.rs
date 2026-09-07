use std::{
    io,
    os::fd::{AsFd, AsRawFd as _},
    time::Duration,
};

/// Polls `fd` for readability. If `timeout` is `Some(duration)`, blocks for at most `duration`,
/// otherwise blocks indefinitely (i.e. until `fd` is readable or the syscall is interrupted).
///
/// Returns `Ok(true)` if `fd` becomes readable before the timeout elapses, or `Ok(false)` if
/// the timeout elapses first.
///
/// # Errors
///
/// Returns `Err` for errors from the `poll()` syscall. Specifically, if a signal is caught while
/// blocked and `SA_RESTART` is not set, returns `Err` with `io::ErrorKind::Interrupted`.
#[expect(unsafe_code, reason = "libc syscall to poll for fd readiness")]
pub fn readable(fd: impl AsFd, timeout: Option<Duration>) -> io::Result<bool> {
    // Set input `events` to `POLLIN` to signify interest in there being data to read for `fd`
    let mut pfd = libc::pollfd { fd: fd.as_fd().as_raw_fd(), events: libc::POLLIN, revents: 0 };

    // -1 means block indefinitely
    let timeout_ms =
        timeout.map_or(-1, |duration| duration.as_millis().try_into().unwrap_or(libc::c_int::MAX));

    // SAFETY: `&raw mut pfd` is a valid, aligned, writable pointer to a `pollfd` on the stack,
    // and 1 is its correct length (`pfd` points to one item).
    match unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) } {
        ..0 => Err(io::Error::last_os_error()),

        // Timed out
        0 => Ok(false),

        // Number of elements whose `revents` fields have been set to nonzero (only one here)
        1.. => Ok(true),
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::error::Result,
        std::{
            io::Write as _,
            os::unix::net::UnixStream,
            thread::{self, JoinHandle},
        },
    };

    /// Joins on a writer thread with error handling.
    fn join_writer(writer: JoinHandle<io::Result<()>>) -> Result {
        writer
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("Writer thread panicked")))
            .map_err(Into::into)
    }

    #[test]
    fn true_when_data_is_available() -> Result {
        let (mut tx, rx) = UnixStream::pair()?;
        tx.write_all(b"hi")?;
        assert!(readable(&rx, Some(Duration::ZERO))?);
        Ok(())
    }

    #[test]
    fn false_when_no_data_is_available() -> Result {
        let (_tx, rx) = UnixStream::pair()?;
        assert!(!readable(&rx, Some(Duration::ZERO))?);
        Ok(())
    }

    #[test]
    fn handles_extreme_durations() -> Result {
        let (mut tx, rx) = UnixStream::pair()?;
        tx.write_all(b"hi")?;
        assert!(readable(&rx, Some(Duration::MAX))?);
        Ok(())
    }

    #[test]
    fn blocks_until_data_arrives_when_timeout_is_none() -> Result {
        let (mut tx, rx) = UnixStream::pair()?;

        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            tx.write_all(b"hi")
        });

        assert!(readable(&rx, None)?);

        join_writer(writer)
    }

    #[test]
    fn true_when_data_arrives_in_time() -> Result {
        let (mut tx, rx) = UnixStream::pair()?;

        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(50));
            tx.write_all(b"hi")
        });

        assert!(readable(&rx, Some(Duration::from_millis(100)))?);

        join_writer(writer)
    }

    #[test]
    fn false_when_data_arrives_too_late() -> Result {
        let (mut tx, rx) = UnixStream::pair()?;

        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            tx.write_all(b"hi")
        });

        assert!(!readable(&rx, Some(Duration::from_millis(50)))?);

        join_writer(writer)
    }
}
