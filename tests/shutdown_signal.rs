//! Test confirming that the shutdown signal handler installs successfully and flips the shutdown
//! flag.
//!
//! Written as an integration test so it runs as its own process, since installing a signal handler
//! and flipping the static shutdown flag mutate process-wide state.

use {
    std::io,
    typenet::{error::Result, sys::ShutdownSignal},
};

#[test]
#[expect(unsafe_code, reason = "libc FFI to raise a real SIGINT for testing the handler")]
fn shutdown_flag_starts_false_and_flips_on_sigint() -> Result {
    let shutdown = ShutdownSignal::install()?;

    assert!(!shutdown.load());

    // SAFETY: raising `SIGINT` on the current thread is well-defined, and the handler installed
    // above is async-signal-safe (a single relaxed store), so this cannot corrupt thread state.
    if unsafe { libc::raise(libc::SIGINT) } != 0 {
        return Err(io::Error::last_os_error().into());
    }

    assert!(shutdown.load());

    Ok(())
}
