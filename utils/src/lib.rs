#[cfg(not(unix))]
compile_error!("This crate only supports Unix-like systems because it reads from `/dev/urandom`");

pub mod error;
pub mod sys;
pub mod try_ops;
