use {
    crate::{application::ServerApp, logger::LogLevel},
    std::{
        any::type_name, env, fmt::Display, num::NonZeroUsize, str::FromStr, thread, time::Duration,
    },
    typenet_utils::error::TraceableResult,
};

pub struct Config {
    /// The name of the TUN device to attach to.
    pub tun_name: String,

    /// The number of worker threads to run, each attached to its own queue of the same multi-queue
    /// TUN device.
    pub worker_count: NonZeroUsize,

    /// The application logic to use for the server.
    pub(crate) app: ServerApp,

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
            tun_name: Self::parse_env("TYPENET_TUN_NAME")?.unwrap_or_else(|| String::from("tun0")),

            worker_count: Self::parse_env("TYPENET_WORKER_COUNT")?
                .unwrap_or_else(|| thread::available_parallelism().unwrap_or(NonZeroUsize::MIN)),

            app: Self::parse_env("TYPENET_APP")?.unwrap_or_default(),

            initial_rto: Duration::from_millis(
                Self::parse_env("TYPENET_INIT_RTO_MILLIS")?.unwrap_or(if cfg!(debug_assertions) {
                    250
                } else {
                    1000
                }),
            ),

            max_retries: Self::parse_env("TYPENET_MAX_RETRANSMITS")?.unwrap_or(15),

            grace_period: Duration::from_secs(
                Self::parse_env("TYPENET_GRACE_SECS")?.unwrap_or(if cfg!(debug_assertions) {
                    5
                } else {
                    60
                }),
            ),

            log_level: Self::parse_env("TYPENET_LOG_LEVEL")?.unwrap_or_default(),
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
