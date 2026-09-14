//! Test confirming that a `SIGINT` delivered to only one thread still wakes a different thread
//! blocked in its own `poll()` call via the shared shutdown eventfd, rather than that other thread
//! needing its own direct interruption.

use {
    std::{assert_matches, io, os::unix::net::UnixStream, sync::mpsc, thread, time::Duration},
    typenet_server::{
        sys::{
            ShutdownSignal,
            poll::{self, PollOutcome},
        },
        thread_panic_msg,
    },
    typenet_utils::error::TraceableResult,
};

#[test]
#[expect(unsafe_code, reason = "libc FFI to target only one of two spawned threads with SIGINT")]
fn eventfd_wakes_a_thread_that_never_receives_sigint_directly() -> TraceableResult {
    let shutdown = ShutdownSignal::install()?;

    let (_targeted_tx, targeted_rx) = UnixStream::pair()?;
    let (_bystander_tx, bystander_rx) = UnixStream::pair()?;
    let (tid_tx, tid_rx) = mpsc::channel();

    thread::scope(|scope| {
        let targeted = scope.spawn(|| {
            tid_tx
                // SAFETY: `pthread_self` has no preconditions and always succeeds.
                .send(unsafe { libc::pthread_self() })
                .map_err(io::Error::other)?;

            poll::readable(&targeted_rx, Some(shutdown.borrow_eventfd()), None)
        });

        let bystander =
            scope.spawn(|| poll::readable(&bystander_rx, Some(shutdown.borrow_eventfd()), None));

        let targeted_tid = tid_rx.recv().map_err(io::Error::other)?;

        // Bias toward both threads already being blocked inside `poll()` before the signal arrives
        thread::sleep(Duration::from_millis(50));

        // SAFETY: `tid` names the still-alive targeted thread (joined below), and `SIGINT` is a
        // valid signal number.
        if unsafe { libc::pthread_kill(targeted_tid, libc::SIGINT) } != 0 {
            return Err(io::Error::last_os_error().into());
        }

        let targeted_result = targeted.join().map_err(thread_panic_msg)?;
        let bystander_result = bystander.join().map_err(thread_panic_msg)?;

        assert_matches!(targeted_result, Err(e) if e.kind() == io::ErrorKind::Interrupted);
        assert_matches!(bystander_result, Ok(PollOutcome::Shutdown));

        Ok(())
    })
}
