use {
    std::{
        fmt::{self, Write as _},
        io::{self, Write as _},
        str::FromStr,
        time::Instant,
    },
    typenet_stack::{
        display::PrettyProtocol as _,
        endpoint::{Endpoint, Local},
        engine::PacketOutcome,
        ipv4_packet::Ipv4Packet,
    },
    typenet_utils::error::{TraceableError, TraceableResult},
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
struct TimestampCalculator(Instant);

impl fmt::Display for TimestampCalculator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let elapsed = Instant::now().saturating_duration_since(self.0);
        let secs = elapsed.as_secs();
        let (mins, sub_min_secs) = (secs / 60, secs % 60);
        let (hrs, sub_hr_mins) = (mins / 60, mins % 60);
        write!(f, "{hrs:02}:{sub_hr_mins:02}:{sub_min_secs:02}.{:03}", elapsed.subsec_millis())
    }
}

pub(crate) struct Logger {
    /// The level of output for logging.
    level: LogLevel,

    /// The logger's birth `Instant` wrapped in a struct that calculates the timestamp offset when
    /// displayed.
    time_calc: TimestampCalculator,

    /// Identifies which worker thread this logger belongs to.
    worker_id: usize,

    /// Accumulates output for one logical record so it can be written to stdout in a single locked
    /// write and can't be interleaved with another worker thread's output.
    buf: String,
}

impl Drop for Logger {
    /// Flushes any buffered output to stdout. If the flush fails, reports it to stderr.
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            eprintln!("Failed to flush logger output for worker {}: {e}", self.worker_id);
        }
    }
}

impl Logger {
    pub(crate) const fn new(level: LogLevel, birth: Instant, worker_id: usize) -> Self {
        Self { level, time_calc: TimestampCalculator(birth), worker_id, buf: String::new() }
    }

    /// Writes and clears any output buffered since the last call to `flush` in a single locked
    /// write so it can't be interleaved with another worker thread's output.
    fn flush(&mut self) -> TraceableResult {
        if !self.buf.is_empty() {
            let mut stdout = io::stdout().lock();
            stdout.write_all(self.buf.as_bytes())?;
            stdout.flush()?;
            self.buf.clear();
        }

        Ok(())
    }

    /// If the log level allows, buffers a log of information about the server, then flushes the
    /// buffer.
    pub(crate) fn server_info(&mut self, msg: impl fmt::Display) -> TraceableResult {
        if self.level >= LogLevel::ServerInfo {
            writeln!(self.buf, "[w{} {}] {msg}", self.worker_id, self.time_calc)?;
            self.flush()?;
        }

        Ok(())
    }

    /// Buffers a log of a bare newline from the server without a timestamp.
    pub(crate) fn server_newline(&mut self) {
        if self.level >= LogLevel::ServerInfo {
            self.buf.push('\n');
        }
    }

    /// If and how the log level allows, buffers a log of an exchange (incoming packet and optional
    /// reply), then flushes the buffer.
    pub(crate) fn exchange(&mut self, outcome: &PacketOutcome) -> TraceableResult {
        self.divider()?;

        self.pkt_received()?;
        self.pkt_io(&outcome.incoming)?;

        if self.level >= LogLevel::PktDetails {
            self.buf.push('\n');
        }

        match &outcome.reply {
            None => {
                if self.level >= LogLevel::PktDetails {
                    self.buf.push_str("<no reply>\n");
                }
            }

            Some(reply) => {
                self.pkt_sent(false)?;
                self.pkt_io(reply)?;
            }
        }

        self.divider()?;
        self.flush()
    }

    /// If and how the log level allows, buffers a log of a single packet transmission not in reply
    /// to an incoming packet, then flushes the buffer. For the more verbose log levels, labels it
    /// as a retransmission if `retransmission` is `true`.
    pub(crate) fn non_reply_transmission(
        &mut self,
        pkt: &Ipv4Packet<Local>,
        retransmission: bool,
    ) -> TraceableResult {
        self.divider()?;
        self.pkt_sent(retransmission)?;
        self.pkt_io(pkt)?;
        self.divider()?;
        self.flush()
    }

    /// Buffers a log of an error handling a packet if the log level allows.
    pub(crate) fn pkt_err(&mut self, msg: impl fmt::Display) -> TraceableResult {
        if self.level >= LogLevel::PktDetails {
            writeln!(self.buf, "[w{} {}] {msg}", self.worker_id, self.time_calc)?;
        }

        Ok(())
    }

    /// Buffers a log of receipt or transmission of a packet if and how the log level allows.
    fn pkt_io<S: Endpoint>(&mut self, pkt: &Ipv4Packet<'_, S>) -> TraceableResult {
        if self.level >= LogLevel::PktDetails {
            writeln!(self.buf, "{pkt}\n{}", pkt.pretty_payload(self.level == LogLevel::PktFull))?;
        }

        Ok(())
    }

    /// Buffers a log of the fact of receiving a packet (not the packet itself) if and how the log
    /// level allows.
    fn pkt_received(&mut self) -> TraceableResult {
        match self.level {
            LogLevel::Silent | LogLevel::ServerInfo => {}
            LogLevel::PktQuiet => self.buf.push('↓'),
            LogLevel::PktDetails | LogLevel::PktFull => {
                writeln!(self.buf, "[w{} {}] Packet received", self.worker_id, self.time_calc)?;
            }
        }

        Ok(())
    }

    /// Buffers a log of the fact of sending a packet (not the packet itself) if and how the log
    /// level allows.
    fn pkt_sent(&mut self, retransmission: bool) -> TraceableResult {
        match self.level {
            LogLevel::Silent | LogLevel::ServerInfo => {}
            LogLevel::PktQuiet => self.buf.push('↑'),
            LogLevel::PktDetails | LogLevel::PktFull => writeln!(
                self.buf,
                "[w{} {}] Packet sent{}",
                self.worker_id,
                self.time_calc,
                if retransmission { " (retransmission)" } else { "" }
            )?,
        }

        Ok(())
    }

    /// Buffers a visual divider if and how the log level allows.
    fn divider(&mut self) -> TraceableResult {
        match self.level {
            LogLevel::Silent | LogLevel::ServerInfo => {}
            LogLevel::PktQuiet => self.buf.push(' '),
            LogLevel::PktDetails | LogLevel::PktFull => writeln!(self.buf, "{:-<80}", "")?,
        }

        Ok(())
    }
}
