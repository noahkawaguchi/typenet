use {
    std::{
        io,
        sync::atomic::{AtomicBool, Ordering},
    },
    typenet_utils::error::TraceableResult,
};

/// The flag for graceful shutdown, private to this module.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Signal handler to atomically set the shutdown flag when called.
extern "C" fn shutdown_signal_handler(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

/// Struct for encapsulating shutdown signal logic, including installing the shutdown signal handler
/// and atomically checking the status of the flag.
pub struct ShutdownSignal {
    flag: &'static AtomicBool,
}

impl ShutdownSignal {
    /// Installs the SIGINT handler for graceful shutdown. The returned value must be held to read
    /// the flag.
    ///
    /// The `SA_RESTART` flag will not be set, meaning a blocking `read()` system call will be
    /// interrupted and return `EINTR` without being automatically restarted.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the signal handler could not be installed.
    #[expect(unsafe_code, reason = "libc system calls to install handler")]
    pub fn install() -> TraceableResult<Self> {
        // Use `sigaction` here to ensure the `SA_RESTART` flag is not set

        // SAFETY: All fields of `sigaction` have valid all-zero bit patterns.
        let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };

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
        // - `shutdown_signal_handler` is async-signal-safe because its body is a single relaxed
        //   store to a lock-free `AtomicBool`.
        if unsafe { libc::sigaction(libc::SIGINT, &raw const sa, std::ptr::null_mut()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }

        Ok(Self { flag: &SHUTDOWN })
    }

    /// Atomically loads the status of the flag representing whether or not to shut down.
    #[must_use]
    pub fn load(&self) -> bool { self.flag.load(Ordering::Relaxed) }
}
