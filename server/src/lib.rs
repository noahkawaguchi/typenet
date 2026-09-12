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
