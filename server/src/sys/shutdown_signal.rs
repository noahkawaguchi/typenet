use {
    std::{
        io, mem,
        os::fd::{AsFd as _, BorrowedFd, FromRawFd as _, OwnedFd},
        ptr,
        sync::atomic::{AtomicBool, AtomicI32, Ordering},
    },
    typenet_utils::error::TraceableResult,
};

/// The flag for graceful shutdown, private to this module.
static SHUTDOWN_FLAG: AtomicBool = AtomicBool::new(false);

/// The raw fd of the shutdown eventfd. `ShutdownSignal::install` replaces the sentinel -1 with the
/// real fd before installing the handler itself, so the handler should never observe the sentinel.
///
/// Assumes C `int` is equivalent to Rust `i32` (which should be true on any Linux system), causing
/// a compilation error otherwise.
static SHUTDOWN_EVENTFD_FD: AtomicI32 = AtomicI32::new(-1);

/// Signal handler to atomically set the shutdown flag and make the shutdown eventfd readable,
/// broadcasting shutdown to all threads polling it.
///
/// Worker threads other than the one the signal was actually delivered to have no way to learn
/// about shutdown other than this write making the eventfd readable, so a silent failure would
/// leave them stuck forever. An eventfd write is all-or-nothing for exactly 8 bytes, so anything
/// else means that guarantee no longer holds. Accordingly, retry a failed write if merely
/// interrupted by another signal, but abort on a partial write or any other failure.
#[expect(unsafe_code, reason = "libc syscalls to write to the shutdown eventfd, retry, and abort")]
extern "C" fn shutdown_signal_handler(_sig: libc::c_int) {
    SHUTDOWN_FLAG.store(true, Ordering::Relaxed);

    let fd = SHUTDOWN_EVENTFD_FD.load(Ordering::Relaxed);
    let one = 1u64;

    loop {
        // Write 1 into the shutdown eventfd, which will make it readable when `poll()` is called.
        //
        // SAFETY: `&raw const one` is a valid pointer to `size_of::<u64>()` initialized bytes.
        // Writing to an eventfd is a plain `write()` syscall, so it's async-signal-safe. `fd` is
        // expected to be a valid, open eventfd. If it's ever not (including the -1 sentinel, which
        // `install` replaces before this handler can be installed), this simply fails with `EBADF`
        // rather than doing anything unsafe.
        let bytes_written = unsafe { libc::write(fd, (&raw const one).cast(), size_of::<u64>()) };

        if bytes_written == size_of::<u64>().cast_signed() {
            break;
        }

        if bytes_written < 0 {
            // SAFETY: `__errno_location` takes no arguments and always returns a valid pointer to
            // the calling thread's `errno`, which `write` above just set.
            let errno_ptr = unsafe { libc::__errno_location() };

            // SAFETY: `errno_ptr` was just obtained above and points to a live, initialized C
            // `int`. Reading it is async-signal-safe and does not allocate.
            if unsafe { *errno_ptr } == libc::EINTR {
                continue;
            }
        }

        // SAFETY: `abort()` is async-signal-safe and terminates the process immediately.
        unsafe { libc::abort() };
    }
}

/// Struct for encapsulating shutdown signal logic, including installing the shutdown signal
/// handler, managing the shutdown eventfd, and atomically checking the status of the flag.
pub struct ShutdownSignal {
    flag: &'static AtomicBool,
    eventfd: OwnedFd,
}

impl ShutdownSignal {
    /// Installs the SIGINT handler for graceful shutdown and creates the shutdown eventfd. The
    /// returned value must be held to read the flag or get the eventfd.
    ///
    /// The `SA_RESTART` flag will not be set, meaning a blocking `read()` system call will be
    /// interrupted and return `EINTR` without being automatically restarted.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the eventfd could not be created or the signal handler could not be
    /// installed.
    #[expect(unsafe_code, reason = "libc system calls to create the eventfd and install handler")]
    pub fn install() -> TraceableResult<Self> {
        // SAFETY: `0` (initial counter value) and `0` (no flags) are valid arguments to
        // `eventfd()`.
        let eventfd_raw = unsafe { libc::eventfd(0, 0) };

        if eventfd_raw < 0 {
            return Err(io::Error::last_os_error().into());
        }

        // Store the fd before installing the handler that reads it
        SHUTDOWN_EVENTFD_FD.store(eventfd_raw, Ordering::Relaxed);

        // Use `sigaction` to ensure the `SA_RESTART` flag is not set.
        //
        // SAFETY: All fields of `sigaction` have valid all-zero bit patterns.
        let mut sa: libc::sigaction = unsafe { mem::zeroed() };

        sa.sa_sigaction = shutdown_signal_handler as *const () as libc::sighandler_t;

        // SAFETY: `&raw mut sa.sa_mask` is a valid, aligned, writable pointer to an owned
        // `sigset_t` on the stack for `sigemptyset` to write an empty set of signals through.
        if unsafe { libc::sigemptyset(&raw mut sa.sa_mask) } != 0 {
            return Err(io::Error::last_os_error().into());
        }

        // SAFETY:
        // - `SIGINT` is a valid `signum`.
        // - `&raw const sa` is a valid, aligned pointer to a fully initialized `sigaction`.
        // - A null `oldact` is permitted.
        // - `shutdown_signal_handler` is async-signal-safe (see its comments).
        if unsafe { libc::sigaction(libc::SIGINT, &raw const sa, ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }

        // SAFETY: `eventfd_raw` is a valid, open fd returned by `eventfd()` above, uniquely owned
        // from this point on (nothing else holds or closes it).
        let eventfd = unsafe { OwnedFd::from_raw_fd(eventfd_raw) };

        Ok(Self { flag: &SHUTDOWN_FLAG, eventfd })
    }

    /// Atomically loads the status of the flag representing whether or not to shut down.
    #[must_use]
    pub fn load_flag(&self) -> bool { self.flag.load(Ordering::Relaxed) }

    /// Borrows the shutdown eventfd so it can be polled for readability. It becomes (and forever
    /// stays) readable once a shutdown signal is received.
    #[must_use]
    pub fn borrow_eventfd(&self) -> BorrowedFd<'_> { self.eventfd.as_fd() }

    /// Blocks `SIGINT` on the calling thread only, so it stops being a candidate for delivery of
    /// that signal in a multithreaded process.
    ///
    /// Must be called after any threads meant to still receive `SIGINT` has already been spawned,
    /// so those threads inherit the mask from before this call, not after.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the signal mask could not be read or set.
    #[expect(unsafe_code, reason = "libc syscalls to block a signal")]
    pub fn block_sigint_on_this_thread() -> TraceableResult {
        // SAFETY: `set` is fully initialized by `sigemptyset` before any other use.
        let mut set: libc::sigset_t = unsafe { mem::zeroed() };

        // SAFETY: `&raw mut set` is a valid, aligned, writable pointer to an owned `sigset_t` on
        // the stack.
        if unsafe { libc::sigemptyset(&raw mut set) } != 0 {
            return Err(io::Error::last_os_error().into());
        }

        // SAFETY: `SIGINT` is a valid signum and `&raw mut set` points to the same initialized
        // `sigset_t` emptied above.
        if unsafe { libc::sigaddset(&raw mut set, libc::SIGINT) } != 0 {
            return Err(io::Error::last_os_error().into());
        }

        // SAFETY: `SIG_BLOCK` is a valid `how`, `&raw const set` is a valid, aligned pointer to a
        // fully initialized `sigset_t`, and a null `oldset` is permitted. `pthread_sigmask`
        // only ever affects the calling thread's mask.
        //
        // (Unlike most libc functions, `pthread_sigmask` reports failure via its return value, not
        // `errno`, so the error is built from that return value directly rather than
        // `last_os_error`.)
        match unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, ptr::null_mut()) } {
            0 => Ok(()),
            errno => Err(io::Error::from_raw_os_error(errno).into()),
        }
    }
}
