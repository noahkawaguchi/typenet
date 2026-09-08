use {
    crate::{error::TraceableResult, logger::LogLevel},
    std::{any::type_name, env, fmt::Display, str::FromStr, time::Duration},
};

pub struct Config {
    /// The name of the TUN device to attach to.
    pub tun_name: String,

    /// The initial retransmission timeout, i.e. how long to wait before retransmitting an unacked
    /// TCP segment the first time before exponential backoff.
    pub(crate) initial_rto: Duration,

    /// The number of times to retransmit an unacked TCP segment before giving up and dropping the
    /// connection.
    pub(crate) max_retries: u8,

    /// The amount of time to wait for established TCP connections to finish closing after a
    /// shutdown signal before exiting unconditionally.
    pub(crate) grace_period: Duration,

    /// The level of output for logging.
    pub(crate) log_level: LogLevel,
}

impl Config {
    /// Loads config from environment variables or falls back to defaults.
    ///
    /// # Errors
    ///
    /// Returns `Err` if an environment variable is present but unparsable.
    pub fn load() -> TraceableResult<Self> {
        Ok(Self {
            // NOTE: "TYPENET_TUN_NAME" is also read in the `justfile` with a "tun0" fallback
            tun_name: Self::get_env_or_else(|| String::from("tun0"), "TYPENET_TUN_NAME")?,

            initial_rto: Duration::from_millis(Self::get_env_or_else(
                || if cfg!(debug_assertions) { 250 } else { 1000 },
                "TYPENET_INIT_RTO_MILLIS",
            )?),

            max_retries: Self::get_env_or_else(|| 15, "TYPENET_MAX_RETRANSMITS")?,

            grace_period: Duration::from_secs(Self::get_env_or_else(
                || if cfg!(debug_assertions) { 5 } else { 60 },
                "TYPENET_GRACE_SECS",
            )?),

            log_level: Self::get_env_or_else(LogLevel::default, "TYPENET_LOG_LEVEL")?,
        })
    }

    /// Reads in an environment variable using `key`, or if not found, computes a default from a
    /// closure.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the environment variable is present but is not valid Unicode or cannot be
    /// parsed as `T`.
    fn get_env_or_else<T, F>(op: F, key: &str) -> TraceableResult<T>
    where
        T: FromStr,
        T::Err: Display,
        F: FnOnce() -> T,
    {
        match env::var(key) {
            Err(env::VarError::NotPresent) => Ok(op()),

            Err(env::VarError::NotUnicode(_)) => {
                Err(format!("Environment variable {key} present but not valid Unicode").into())
            }

            Ok(val) => val.parse().map_err(|e| {
                format!(
                    "Environment variable {key} present but could not be parsed as {}: {e}",
                    type_name::<T>()
                )
                .into()
            }),
        }
    }
}
