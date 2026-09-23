use {
    std::{any::type_name, env, fmt::Display, net::IpAddr, str::FromStr},
    typenet_utils::error::TraceableResult,
};

pub(crate) struct Config {
    /// The IP address of the echo server to load test.
    pub target_addr: IpAddr,

    /// The TCP port of the echo server to load test.
    pub target_port: u16,

    /// The number of concurrent TCP connections to open.
    pub connection_count: usize,

    /// The number of random bytes to send and expect echoed back on each connection.
    pub payload_size: usize,
}

impl Config {
    /// Loads config from environment variables or falls back to defaults.
    ///
    /// # Errors
    ///
    /// Returns `Err` if an environment variable is present but unparsable.
    pub(crate) fn load() -> TraceableResult<Self> {
        Ok(Self {
            // NOTE: matches the default `server-addr` in the `justfile` ("10.0.0.2")
            target_addr: Self::parse_env("TYPENET_LOADGEN_ADDR")?
                .unwrap_or_else(|| IpAddr::from([10, 0, 0, 2])),

            // NOTE: matches the default `server-port` in the `justfile` ("8080")
            target_port: Self::parse_env("TYPENET_LOADGEN_PORT")?.unwrap_or(8080),

            connection_count: Self::parse_env("TYPENET_LOADGEN_CONNECTIONS")?.unwrap_or(50),

            payload_size: Self::parse_env("TYPENET_LOADGEN_PAYLOAD_BYTES")?.unwrap_or(65536),
        })
    }

    /// Reads in an environment variable using `key` and parses it as `T`, or if not found, returns
    /// `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the environment variable is present but is not valid Unicode or cannot be
    /// parsed as `T`.
    fn parse_env<T>(key: &str) -> TraceableResult<Option<T>>
    where
        T: FromStr,
        T::Err: Display,
    {
        match env::var(key) {
            Err(env::VarError::NotPresent) => Ok(None),

            Err(env::VarError::NotUnicode(_)) => {
                Err(format!("Environment variable {key} present but not valid Unicode").into())
            }

            Ok(val) => val
                .parse()
                .map_err(|e| {
                    format!(
                        "Environment variable {key} present but could not be parsed as {}: {e}",
                        type_name::<T>()
                    )
                    .into()
                })
                .map(Some),
        }
    }
}
