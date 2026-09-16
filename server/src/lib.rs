#[cfg(not(target_os = "linux"))]
compile_error!("This crate only supports Linux because it directly uses low-level Linux APIs");

pub mod application;
pub mod config;
pub mod server;

pub mod sys {
    pub mod poll;
    pub mod tun;
    pub use shutdown_signal::ShutdownSignal;

    mod shutdown_signal;
}

mod logger;

use std::{any::Any, borrow::Cow};

/// Extracts the panic message from `payload` (which should be the `Err` payload from joining a
/// thread) if it is a `String` or `&'static str`, otherwise returns a generic message.
#[must_use]
pub fn thread_panic_msg(payload: Box<dyn Any + Send + 'static>) -> Cow<'static, str> {
    match payload.downcast::<String>() {
        Ok(s) => Cow::Owned(*s),

        Err(inner) => inner
            .downcast::<&'static str>()
            .map_or(Cow::Borrowed("<non-string panic payload>"), |s| Cow::Borrowed(*s)),
    }
}
