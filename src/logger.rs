use {
    crate::{
        endpoint::Endpoint,
        error::{TraceableError, TraceableResult},
        protocol::router::{Ipv4Packet, PrettyProtocol as _},
    },
    std::{
        fmt,
        io::{self, Write as _},
        str::FromStr,
        time::Instant,
    },
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum LogLevel {
    /// No output at all.
    Silent = 0,

    /// Server startup and shutdown information, but nothing about individual packets.
    ServerInfo = 1,

    /// Minimal indicators for each packet with no details.
    PktQuiet = 2,

    /// Packet header details but only payload lengths and whether they are UTF-8.
    PktDetails = 3,

    /// Packet header details and payload content.
    #[default]
    PktFull = 4,
}

impl FromStr for LogLevel {
    type Err = TraceableError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "0" => Ok(Self::Silent),
            "1" => Ok(Self::ServerInfo),
            "2" => Ok(Self::PktQuiet),
            "3" => Ok(Self::PktDetails),
            "4" => Ok(Self::PktFull),
            other => {
                Err(format!("Log level must be a digit between 0 and 4 inclusive, got {other}")
                    .into())
            }
        }
    }
}

impl From<LogLevel> for u8 {
    fn from(value: LogLevel) -> Self { value as Self }
}

/// Wrapper struct for displaying the time elapsed since the inner `Instant`.
struct Timestamp(Instant);

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let elapsed = Instant::now().saturating_duration_since(self.0);
        let secs = elapsed.as_secs();
        let (mins, sub_min_secs) = (secs / 60, secs % 60);
        let (hrs, sub_hr_mins) = (mins / 60, mins % 60);
        write!(f, "{hrs:02}:{sub_hr_mins:02}:{sub_min_secs:02}.{:03}", elapsed.subsec_millis())
    }
}

pub struct Logger {
    /// The level of output for logging.
    level: LogLevel,

    /// The `Instant` at which `self` was created.
    birth: Instant,
}

impl Logger {
    pub(crate) fn new(level: LogLevel) -> Self { Self { level, birth: Instant::now() } }

    /// Prints a visual divider to stdout if and how the log level allows.
    pub(crate) fn divider(&self) {
        match self.level {
            LogLevel::Silent | LogLevel::ServerInfo => {}
            // Buffered until the next newline or flush, which is desired
            LogLevel::PktQuiet => print!(" "),
            LogLevel::PktDetails | LogLevel::PktFull => println!("\n{:=<80}\n", ""),
        }
    }

    /// Logs a bare newline from the server without a timestamp.
    pub(crate) fn server_newline(&self) {
        if self.level >= LogLevel::ServerInfo {
            println!();
        }
    }

    /// Logs information about the server to stdout if the log level allows.
    pub(crate) fn server_info(&self, msg: impl fmt::Display) {
        if self.level >= LogLevel::ServerInfo {
            println!("[{}] {msg}", Timestamp(self.birth));
        }
    }

    /// Logs receipt or transmission of a packet to stdout if and how the log level allows.
    pub(crate) fn pkt_io<S: Endpoint>(&self, pkt: &Ipv4Packet<'_, S>) -> TraceableResult {
        match self.level {
            LogLevel::Silent | LogLevel::ServerInfo => {}

            LogLevel::PktQuiet => {
                print!("{}", S::INDICATOR);
                io::stdout().flush()?;
            }

            level @ (LogLevel::PktDetails | LogLevel::PktFull) => {
                println!(
                    "{}\n{pkt}\n{}",
                    Timestamp(self.birth),
                    pkt.pretty_payload(level == LogLevel::PktFull)
                );
            }
        }

        Ok(())
    }

    /// Logs packet-related information and formatting other than the packets themselves to stdout
    /// if the log level allows.
    pub(crate) fn pkt_extra(&self, msg: impl fmt::Display) {
        if self.level >= LogLevel::PktDetails {
            println!("{msg}");
        }
    }

    /// Logs an error handling a packet to stderr if the log level allows.
    pub(crate) fn pkt_err(&self, msg: impl fmt::Display) {
        if self.level >= LogLevel::PktDetails {
            eprintln!("[{}] {msg}", Timestamp(self.birth));
        }
    }
}
