#![cfg_attr(
    all(not(test), feature = "test-utils"),
    expect(clippy::wildcard_imports, reason = "Test-only utilities")
)]

#[cfg(feature = "test-utils")]
pub use protocol::tcp::{TcpConnections, TcpSegment};

pub mod endpoint;
pub mod engine;
pub mod ipv4_packet;

#[cfg(feature = "bench-internals")]
pub mod checksum;

#[cfg(not(feature = "bench-internals"))]
mod checksum;

mod addr_pairs;
mod display;
mod ipv4_header;
mod protocol;

/// The Maximum Transmission Unit of standard Ethernet (frames up to 1500 bytes of IP packet data).
pub const ETHERNET_MTU: usize = 1500;
