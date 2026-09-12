use {
    crate::{application::ServerApp, config::Config, logger::Logger},
    std::{
        io::{self, Read, Write},
        os::fd::AsFd,
        time::{Duration, Instant},
    },
    typenet_stack::{
        ETHERNET_MTU,
        endpoint::Local,
        engine::{Engine, ShutdownOutcome},
        ipv4_packet::Ipv4Packet,
    },
    typenet_utils::{error::TraceableResult, try_ops::TryGet as _},
};

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
pub fn run<D, P, S>(
    device: &mut D,
    poll_readable: P,
    shutdown_check: S,
    config: &Config,
) -> TraceableResult
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
        engine: Engine::new(
            config.app,
            config.initial_rto,
            config.max_retries,
            config.grace_period,
        ),
        logger,
        device,
        poll_readable,
        shutdown_check,
    }
    .run()
}

struct Server<'a, D, P, S> {
    write_buf: [u8; ETHERNET_MTU],
    engine: Engine<ServerApp>,
    logger: Logger,
    device: &'a mut D,
    poll_readable: P,
    shutdown_check: S,
}

impl<D, P, S> Server<'_, D, P, S>
where
    D: Read + Write + AsFd,
    P: Fn(&D, Option<Duration>) -> io::Result<bool>,
    S: Fn() -> bool,
{
    fn run(&mut self) -> TraceableResult {
        let mut read_buf = [0u8; ETHERNET_MTU];

        self.logger.divider();

        loop {
            match (self.poll_readable)(self.device, self.engine.poll_timeout(Instant::now())) {
                // If `poll()` was interrupted and returned `EINTR`, check if a shutdown signal has
                // been received
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    if (self.shutdown_check)() && self.handle_shutdown_interrupt(Instant::now())? {
                        break Ok(());
                    }
                    // Interrupted by a signal unrelated to shutdown -> just re-poll
                }

                Err(e) => break Err(e.into()),

                Ok(false) if self.engine.grace_period_elapsed(Instant::now()) => {
                    self.logger.server_newline();
                    self.logger.server_info(format_args!(
                        "Grace period elapsed with {} remaining connection(s), exiting",
                        self.engine.connection_count()
                    ));

                    break Ok(());
                }

                // A retransmit deadline elapsed -> retransmit all expired segments
                Ok(false) => {
                    for retransmission in self.engine.make_retransmissions() {
                        self.logger
                            .pkt_extra(" ==== Packet sent (retransmission) ====");

                        self.send_pkt(&retransmission?)?;
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

                    match self.engine.handle_packet(read_buf.try_get(..bytes_read)?) {
                        Err(e) => self.logger.pkt_err(e),

                        Ok(outcome) => {
                            self.logger.pkt_extra(" ==== Packet received ====");
                            self.logger.pkt_io(&outcome.incoming)?;

                            match outcome.reply {
                                None => self.logger.pkt_extra("\n<no reply>"),

                                Some(reply) => {
                                    self.logger.pkt_extra("\n ==== Packet sent ====");
                                    self.send_pkt(&reply)?;
                                }
                            }
                        }
                    }

                    self.logger.divider();

                    if self.engine.draining_complete() {
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
    fn handle_shutdown_interrupt(&mut self, now: Instant) -> TraceableResult<bool> {
        self.logger.server_newline(); // Because ^C is probably in the terminal

        Ok(match self.engine.handle_shutdown(now)? {
            ShutdownOutcome::AlreadyDraining { time_left } => {
                self.logger.server_info(format_args!(
                    "Draining connections, {}.{:03}s left",
                    time_left.as_secs(),
                    time_left.subsec_millis()
                ));

                false
            }

            ShutdownOutcome::BeganDraining { to_send } => {
                self.logger
                    .server_info("Shutdown signal received, closing established connections...");

                self.logger.divider();

                for pkt in to_send {
                    self.logger.pkt_extra(" ==== Packet sent ====");
                    self.send_pkt(&pkt)?;
                }

                self.logger.divider();
                false
            }

            ShutdownOutcome::NoConnections => {
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
    fn send_pkt(&mut self, outgoing: &Ipv4Packet<Local>) -> TraceableResult {
        outgoing.write_into(&mut self.write_buf)?;

        self.device
            .write_all(self.write_buf.try_get(..outgoing.total_len().into())?)?;

        self.logger.pkt_io(outgoing)
    }
}

#[cfg(test)]
mod tests {
    mod interrupt;
    mod mocks;
    mod pkt_handling;
    mod propagate;
    mod retransmit;
    mod shutdown;

    use {
        super::*,
        crate::logger::LogLevel,
        mocks::*,
        pretty_assertions::assert_matches,
        std::cell::{Cell, RefCell},
        typenet_stack::{TcpConnections, TcpSegment},
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
    ) -> TraceableResult {
        Server {
            write_buf: [0u8; ETHERNET_MTU],
            engine: Engine::test_new(ServerApp::Echo, tcp_connections, shutdown_grace_period),
            logger: Logger::new(LogLevel::Silent),
            device,
            poll_readable,
            shutdown_check,
        }
        .run()
    }
}
