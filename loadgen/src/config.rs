use {
    std::{
        net::IpAddr,
        num::{NonZeroU16, NonZeroUsize},
    },
    typenet_utils::{error::TraceableResult, sys},
};

pub(crate) struct Config {
    /// The IP address of the echo server to load test.
    pub target_addr: IpAddr,

    /// The TCP port of the echo server to load test.
    pub target_port: NonZeroU16,

    /// The number of concurrent TCP connections to open.
    pub connection_count: NonZeroUsize,

    /// The number of random bytes to send and expect echoed back on each connection.
    pub payload_size: NonZeroUsize,
}

impl Config {
    /// Loads config from environment variables or falls back to defaults.
    ///
    /// # Errors
    ///
    /// Returns `Err` if an environment variable is present but unparsable, including a `0` for any
    /// of the fields that must be nonzero.
    pub(crate) fn load() -> TraceableResult<Self> {
        Ok(Self {
            // NOTE: matches the default `server-addr` in the `justfile` ("10.0.0.2")
            target_addr: sys::parse_env("TYPENET_LOADGEN_ADDR")?
                .unwrap_or_else(|| IpAddr::from([10, 0, 0, 2])),

            // NOTE: matches the default `server-port` in the `justfile` ("8080")
            target_port: sys::parse_env("TYPENET_LOADGEN_PORT")?
                .unwrap_or(const { NonZeroU16::new(8080).expect("8080 != 0") }),

            connection_count: sys::parse_env("TYPENET_LOADGEN_CONNECTIONS")?
                .unwrap_or(const { NonZeroUsize::new(50).expect("50 != 0") }),

            payload_size: sys::parse_env("TYPENET_LOADGEN_PAYLOAD_BYTES")?
                .unwrap_or(const { NonZeroUsize::new(65536).expect("65536 != 0") }),
        })
    }
}
