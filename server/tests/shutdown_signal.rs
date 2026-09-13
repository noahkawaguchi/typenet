//! Test confirming that the shutdown signal handler installs successfully, flips the shutdown
//! flag, and wakes the shutdown eventfd.
//!
//! Written as an integration test so it runs as its own process, since installing and running the
//! signal handler mutates process-wide state.

use {
    pretty_assertions::assert_eq,
    std::{io, os::unix::net::UnixStream, time::Duration},
    typenet_server::sys::{ShutdownSignal, poll},
    typenet_utils::error::TraceableResult,
};

#[test]
#[expect(unsafe_code, reason = "libc FFI to raise a real SIGINT for testing the handler")]
fn shutdown_flag_starts_false_and_flips_on_sigint() -> TraceableResult {
    let shutdown = ShutdownSignal::install()?;

    // A dummy primary fd that's never readable to focus on testing the shutdown eventfd
    let (_tx, never_readable) = UnixStream::pair()?;

    assert!(!shutdown.load_flag());

    assert_eq!(
        poll::readable(&never_readable, Some(shutdown.borrow_eventfd()), Some(Duration::ZERO))?,
        poll::PollOutcome::Timeout
    );

    // SAFETY: raising `SIGINT` on the current thread is well-defined, and the handler installed
    // above is async-signal-safe (see its comments), so this cannot corrupt thread state.
    if unsafe { libc::raise(libc::SIGINT) } != 0 {
        return Err(io::Error::last_os_error().into());
    }

    assert!(shutdown.load_flag());

    assert_eq!(
        poll::readable(&never_readable, Some(shutdown.borrow_eventfd()), Some(Duration::ZERO))?,
        poll::PollOutcome::Shutdown
    );

    Ok(())
}
