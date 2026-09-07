use {
    crate::{
        ETHERNET_MTU, Result,
        config::Config,
        endpoint::{Local, Remote},
        ipv4_header::Ipv4Header,
        logger::Logger,
        protocol::{
            RtoConfig, TcpConnections, TcpSegment,
            router::{Encode, ProtocolRouter},
        },
        try_ops::{TryAdd as _, TryGet as _},
    },
    std::{
        io::{self, Read, Write},
        os::fd::AsFd,
        time::{Duration, Instant},
    },
};

/// The minimum allowed TCP retransmission timeout (same as the Linux kernel as defined in
/// `include/net/tcp.h`).
const TCP_RTO_MIN: Duration = Duration::from_millis(200);

/// The maximum allowed TCP retransmission timeout (same as the Linux kernel as defined in
/// `include/net/tcp.h`).
const TCP_RTO_MAX: Duration = Duration::from_mins(2);

/// The result of deciding how to react to a shutdown signal.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
enum ShutdownDecision {
    /// A previous interrupt already started draining, and there is `time_left` until the deadline.
    AlreadyDraining { time_left: Duration },

    /// This was the first interrupt, active close began, and at least one connection is still
    /// closing.
    BeganDraining { to_send: Vec<TcpSegment<Local>>, deadline: Instant },

    /// This was the first interrupt, and no connection needs to finish closing, so shutdown can
    /// happen immediately.
    NoConnections,
}

/// A parsed incoming IPv4 header and protocol router along with a reply router if one is necessary.
#[cfg_attr(test, derive(Debug))]
struct ParsedExchange<'a> {
    ipv4_hdr: Ipv4Header<Remote>,
    incoming_router: ProtocolRouter<'a, Remote>,
    reply_router: Option<ProtocolRouter<'a, Local>>,
}

/// Reads and writes IPv4 packets to and from `device`, maintaining TCP connection state and echoing
/// payloads as necessary.
///
/// When polling `device` with `poll_readable` is interrupted and `shutdown_check` returns `true`,
/// actively closes all established TCP connections and waits up to `shutdown_grace_period` for them
/// to finish before returning.
///
/// # Errors
///
/// Returns `Err` for errors related to packet I/O, but logs and continues for errors related to
/// parsing and replying to individual packets.
pub fn run<D, P, S>(device: &mut D, poll_readable: P, shutdown_check: S, config: &Config) -> Result
where
    D: Read + Write + AsFd,
    P: Fn(&D, Option<Duration>) -> io::Result<bool>,
    S: Fn() -> bool,
{
    let logger = Logger::new(config.log_level);

    logger.server_info(format_args!(
        "Waiting for packets on TUN device {} (Ctrl+C to stop)",
        config.tun_name
    ));

    Server {
        write_buf: [0u8; ETHERNET_MTU],
        tcp_connections: TcpConnections::new(
            RtoConfig { initial: config.initial_rto, min: TCP_RTO_MIN, max: TCP_RTO_MAX },
            config.max_retries,
        ),
        logger,
        device,
        poll_readable,
        shutdown_check,
        shutdown_grace_period: config.grace_period,
        shutdown_deadline: None,
    }
    .run()
}

struct Server<'a, D, P, S> {
    write_buf: [u8; ETHERNET_MTU],
    tcp_connections: TcpConnections,
    logger: Logger,
    device: &'a mut D,
    poll_readable: P,
    shutdown_check: S,
    shutdown_grace_period: Duration,

    /// Deadline that bounds how long to wait for established connections to finish closing before
    /// exiting unconditionally. Set once a shutdown signal starts active close.
    shutdown_deadline: Option<Instant>,
}

impl<D, P, S> Server<'_, D, P, S>
where
    D: Read + Write + AsFd,
    P: Fn(&D, Option<Duration>) -> io::Result<bool>,
    S: Fn() -> bool,
{
    fn run(&mut self) -> Result {
        let mut read_buf = [0u8; ETHERNET_MTU];

        self.logger.divider();

        loop {
            match (self.poll_readable)(self.device, self.poll_timeout(Instant::now())) {
                // If `poll()` was interrupted and returned `EINTR`, check if a shutdown signal has
                // been received
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    if (self.shutdown_check)() && self.handle_shutdown_interrupt(Instant::now())? {
                        break Ok(());
                    }
                    // Interrupted by a signal unrelated to shutdown -> just re-poll
                }

                Err(e) => break Err(e.into()),

                Ok(false) if self.grace_period_elapsed(Instant::now()) => {
                    self.logger.server_newline();
                    self.logger.server_info(format_args!(
                        "Grace period elapsed with {} remaining connection(s), exiting",
                        self.tcp_connections.len()
                    ));

                    break Ok(());
                }

                // A retransmit deadline elapsed -> retransmit all expired segments
                Ok(false) => {
                    for tcp_seg in self.tcp_connections.make_retransmissions() {
                        self.logger
                            .pkt_extra(" ==== Packet sent (retransmission) ====");

                        self.send_pkt(&tcp_seg)?;
                        self.logger.divider();
                    }
                }

                // The device became readable within the timeout -> regular read and reply
                Ok(true) => {
                    let bytes_read = match self.device.read(&mut read_buf) {
                        // If `read()` was interrupted and returned `EINTR`, react to the shutdown
                        // signal in the same way as for a `poll()` interruption
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                            if (self.shutdown_check)()
                                && self.handle_shutdown_interrupt(Instant::now())?
                            {
                                break Ok(());
                            }

                            // Interrupted by a signal unrelated to shutdown -> just re-poll
                            continue;
                        }

                        Err(e) => break Err(e.into()),
                        Ok(n) => n,
                    };

                    match self.parse_incoming(read_buf.try_get(..bytes_read)?) {
                        Err(e) => self.logger.pkt_err(e),

                        Ok(exchange) => {
                            self.logger.pkt_extra(" ==== Packet received ====");
                            self.logger
                                .pkt_io(&exchange.ipv4_hdr, &exchange.incoming_router)?;

                            match exchange.reply_router {
                                None => self.logger.pkt_extra("\n<no reply>"),

                                Some(reply) => {
                                    self.logger.pkt_extra("\n ==== Packet sent ====");
                                    self.send_pkt(&reply)?;
                                }
                            }
                        }
                    }

                    self.logger.divider();

                    if self.shutting_down_and_no_connections_closing() {
                        self.logger.server_newline();
                        self.logger
                            .server_info("All connections closed within grace period, exiting");

                        break Ok(());
                    }
                }
            }
        }
    }

    /// Reacts to an `EINTR` caused by the shutdown signal, performing I/O resulting from the
    /// shutdown decision as necessary. Returns whether to proceed to shutdown immediately.
    fn handle_shutdown_interrupt(&mut self, now: Instant) -> Result<bool> {
        self.logger.server_newline(); // Because ^C is probably in the terminal

        Ok(match self.decide_shutdown(now)? {
            ShutdownDecision::AlreadyDraining { time_left } => {
                self.logger.server_info(format_args!(
                    "Draining connections, {}.{:03}s left",
                    time_left.as_secs(),
                    time_left.subsec_millis()
                ));

                false
            }

            ShutdownDecision::BeganDraining { to_send, deadline } => {
                self.logger
                    .server_info("Shutdown signal received, closing established connections...");

                self.logger.divider();

                for tcp_seg in to_send {
                    self.logger.pkt_extra(" ==== Packet sent ====");
                    self.send_pkt(&tcp_seg)?;
                }

                self.logger.divider();
                self.shutdown_deadline = Some(deadline);
                false
            }

            ShutdownDecision::NoConnections => {
                self.logger.server_info(
                    "Shutdown signal received with no established connections, exiting",
                );

                true
            }
        })
    }

    /// Writes the protocol-specific header and payload of `outgoing` into the write buffer,
    /// prefixed with an IPv4 header, then writes the resulting packet to the device and logs its
    /// transmission.
    fn send_pkt(&mut self, outgoing: &impl Encode<Local>) -> Result {
        let proto_len = outgoing.write_into(&mut self.write_buf[Ipv4Header::REPLY_HDR_LEN..])?;

        let ipv4_hdr = Ipv4Header::try_new(outgoing.proto(), outgoing.get_ip_pair(), proto_len)?;
        ipv4_hdr.write_into(&mut self.write_buf);

        self.device
            .write_all(self.write_buf.try_get(..ipv4_hdr.total_len.into())?)?;

        self.logger.pkt_io(&ipv4_hdr, outgoing)?;

        Ok(())
    }
}

impl<D, P, S> Server<'_, D, P, S> {
    /// Computes how long to block when polling, which is the time remaining until the earlier of
    /// the shutdown deadline and the next pending retransmission, or if nether is set, returns
    /// `None` to block indefinitely.
    fn poll_timeout(&self, now: Instant) -> Option<Duration> {
        [self.shutdown_deadline, self.tcp_connections.next_retransmit_deadline()]
            .into_iter()
            .flatten()
            .min()
            .map(|deadline| deadline.saturating_duration_since(now))
    }

    /// Returns whether `now` has reached or passed the shutdown deadline if there is one, or
    /// `false` if there is no deadline.
    fn grace_period_elapsed(&self, now: Instant) -> bool {
        self.shutdown_deadline
            .is_some_and(|deadline| deadline <= now)
    }

    /// Returns whether a shutdown is in progress and there are no connections currently mid-close.
    fn shutting_down_and_no_connections_closing(&self) -> bool {
        self.shutdown_deadline.is_some() && !self.tcp_connections.closing_in_progress()
    }

    /// Decides how to react to a shutdown signal. If not already draining, initiates active close.
    fn decide_shutdown(&mut self, now: Instant) -> Result<ShutdownDecision, String> {
        Ok(if let Some(deadline) = self.shutdown_deadline {
            ShutdownDecision::AlreadyDraining { time_left: deadline.saturating_duration_since(now) }
        } else {
            let to_send = self.tcp_connections.close_established();

            if self.tcp_connections.closing_in_progress() {
                ShutdownDecision::BeganDraining {
                    to_send,
                    deadline: now.try_add(self.shutdown_grace_period)?,
                }
            } else {
                ShutdownDecision::NoConnections
            }
        })
    }

    /// Parses `data` as an IPv4 header and protocol-specific header and payload, returning the
    /// incoming packet parsed into structs ready to be logged, and optionally a reply if one is
    /// required.
    fn parse_incoming<'a>(&mut self, data: &'a [u8]) -> Result<ParsedExchange<'a>, String> {
        let (ipv4_hdr, ipv4_payload) =
            Ipv4Header::parse(data).map_err(|e| format!("Skipping packet: {e}"))?;

        let incoming_router =
            ProtocolRouter::parse(ipv4_payload, ipv4_hdr.protocol, ipv4_hdr.ip_pair)
                .map_err(|e| format!("Skipping packet: {e}"))?;

        let reply_router = incoming_router
            .create_reply(&mut self.tcp_connections)
            .map_err(|e| format!("Error creating reply: {e}"))?;

        Ok(ParsedExchange { ipv4_hdr, incoming_router, reply_router })
    }
}

#[cfg(test)]
mod tests {
    mod grace_period;
    mod interrupt;
    mod mocks;
    mod pkt_handling;
    mod propagate;
    mod retransmit;
    mod shutdown;
    mod timeout;

    use {
        super::*,
        crate::logger::LogLevel,
        mocks::*,
        pretty_assertions::assert_matches,
        std::cell::{Cell, RefCell},
    };

    /// A zero grace period, meaning the very next iteration's poll timeout is already past the
    /// deadline (real time always advances between the two `Instant::now()` calls), allowing tests
    /// to force the "grace period elapsed" exit deterministically without sleeping.
    const IMMEDIATE_GRACE_PERIOD: Duration = Duration::ZERO;

    /// A grace period of one year, more than long enough that it cannot plausibly elapse between
    /// two nearby `Instant::now()` calls. Deliberately not `Duration::MAX` because adding that to
    /// `Instant::now()` overflows and is itself a different error case.
    const ONE_YEAR_GRACE_PERIOD: Duration = Duration::from_hours(24 * 365);

    /// Builds and runs a test server, bypassing regular construction so tests can seed
    /// `tcp_connections` with pre-established connections.
    fn run_test_server(
        tcp_connections: TcpConnections,
        device: &mut MockDevice,
        poll_readable: impl Fn(&MockDevice, Option<Duration>) -> io::Result<bool>,
        shutdown_check: impl Fn() -> bool,
        shutdown_grace_period: Duration,
    ) -> Result {
        Server {
            write_buf: [0u8; ETHERNET_MTU],
            tcp_connections,
            logger: Logger::new(LogLevel::Silent),
            device,
            poll_readable,
            shutdown_check,
            shutdown_grace_period,
            shutdown_deadline: None,
        }
        .run()
    }

    /// Creates a `Server` for tests of the decision-only methods to partially override using struct
    /// update syntax. Has placeholder `()` for all the generics since those fields are not used.
    fn decision_test_server() -> Server<'static, (), (), ()> {
        Server {
            write_buf: [0u8; ETHERNET_MTU],
            tcp_connections: TcpConnections::default(),
            logger: Logger::new(LogLevel::Silent),
            // "Memory leak" of zero bytes, so no memory leak (or allocation)
            device: Box::leak(Box::new(())),
            poll_readable: (),
            shutdown_check: (),
            shutdown_grace_period: ONE_YEAR_GRACE_PERIOD,
            shutdown_deadline: None,
        }
    }
}
