//! Test confirming that `ShutdownSignal::block_sigint_on_this_thread` actually prevents the calling
//! thread's own blocking syscall from being interrupted by a `SIGINT` targeted at it, unlike an
//! unmasked thread would be.
//!
//! In production, the entire process receives the `SIGINT` (equivalent to `libc::kill`) and then
//! only one thread sees it, but `libc::pthread_kill` is used here to deterministically send the
//! signal to the thread with it blocked, rather than allowing the kernel choose a different
//! unblocked thread.
//!
//! Written as an integration test so it runs as its own process, since installing the signal
//! handler and altering a thread's signal mask both mutate process/thread state that would leak
//! across tests sharing a process.

use {
    std::{assert_matches, io, os::unix::net::UnixStream, sync::mpsc, thread, time::Duration},
    typenet_server::sys::{ShutdownSignal, poll},
    typenet_utils::error::TraceableResult,
};

#[test]
#[expect(unsafe_code, reason = "libc FFI to target a spawned thread with a real SIGINT")]
fn thread_that_blocks_sigint_is_not_interrupted_by_it() -> TraceableResult {
    // Keep the fd open for the whole test so it cannot be reused by a socket and then potentially
    // corrupted by the signal handler
    let _shutdown = ShutdownSignal::install()?; // `SA_RESTART` unset

    let (_tx, rx) = UnixStream::pair()?;
    let (tid_tx, tid_rx) = mpsc::channel();

    let blocked = thread::spawn(move || {
        ShutdownSignal::block_sigint_on_this_thread()
            .map_err(|e| io::Error::other(e.to_string()))?;

        tid_tx
            // SAFETY: `pthread_self` has no preconditions and always succeeds.
            .send(unsafe { libc::pthread_self() })
            .map_err(io::Error::other)?;

        poll::readable(&rx, None, Some(Duration::from_millis(200)))
    });

    let tid = tid_rx.recv().map_err(io::Error::other)?;

    // Bias toward the thread already being blocked inside `poll()` before the signal arrives
    thread::sleep(Duration::from_millis(50));

    // SAFETY: `tid` names the still-alive `blocked` thread (joined below), and `SIGINT` is a valid
    // signal number.
    if unsafe { libc::pthread_kill(tid, libc::SIGINT) } != 0 {
        return Err(io::Error::last_os_error().into());
    }

    let result = blocked
        .join()
        .map_err(|_| io::Error::other("Blocked thread panicked"))?;

    // If the mask hadn't taken effect, this would be `Err(e)` with `e.kind() ==
    // io::ErrorKind::Interrupted`.
    assert_matches!(result, Ok(poll::PollOutcome::Timeout));

    Ok(())
}
