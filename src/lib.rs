#[cfg(not(target_os = "linux"))]
compile_error!("This crate only supports Linux because it directly uses low-level Linux APIs");

pub mod config;
pub mod error;
pub mod server;
pub mod sys;

#[cfg(feature = "bench-internals")]
pub mod checksum;

#[cfg(not(feature = "bench-internals"))]
mod checksum;

mod addr_pairs;
mod endpoint;
mod ipv4_header;
mod logger;
mod protocol;
mod try_ops;

/// The Maximum Transmission Unit of standard Ethernet (frames up to 1500 bytes of IP packet data).
const ETHERNET_MTU: usize = 1500;
