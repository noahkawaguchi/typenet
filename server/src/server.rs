use {
    crate::{application::ServerApp, config::Config, logger::Logger, sys::poll::PollOutcome},
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
    birth: Instant,
    worker_id: usize,
) -> TraceableResult
where
    D: Read + Write + AsFd,
    P: Fn(&D, Option<Duration>, bool) -> io::Result<PollOutcome>,
    S: Fn() -> bool,
{
    let mut logger = Logger::new(config.log_level, birth, worker_id);

    logger.server_info(format_args!(
        "Waiting for packets on TUN device {} (Ctrl+C to stop)",
        config.tun_name
    ))?;

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
        draining: false,
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

    /// Whether this thread has already reacted to a shutdown signal at least once. Used to stop
    /// polling the shutdown eventfd after this thread has become aware of shutdown, because
    /// otherwise the `poll()` call would always return immediately saying the shutdown eventfd is
    /// readable and the loop would spin.
    draining: bool,
}

impl<D, P, S> Server<'_, D, P, S>
where
    D: Read + Write + AsFd,
    P: Fn(&D, Option<Duration>, bool) -> io::Result<PollOutcome>,
    S: Fn() -> bool,
{
    fn run(&mut self) -> TraceableResult {
        let mut read_buf = [0u8; ETHERNET_MTU];

        loop {
            match (self.poll_readable)(
                self.device,
                self.engine.poll_timeout(Instant::now()),
                !self.draining,
            ) {
                // If `poll()` was interrupted and returned `EINTR`, check if a shutdown signal has
                // been received
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    self.logger.server_newline(); // Because ^C is probably in the terminal

                    if (self.shutdown_check)() && self.handle_shutdown_interrupt(Instant::now())? {
                        break Ok(());
                    }
                    // Interrupted by a signal unrelated to shutdown -> just re-poll
                }

                Err(e) => break Err(e.into()),

                // Some other worker thread received the shutdown signal's `EINTR` -> same reaction
                // as if this thread had received it
                Ok(PollOutcome::Shutdown) => {
                    if (self.shutdown_check)() && self.handle_shutdown_interrupt(Instant::now())? {
                        break Ok(());
                    }
                }

                // Grace period ended with connections left -> forcefully exit
                Ok(PollOutcome::Timeout) if self.engine.grace_period_elapsed(Instant::now()) => {
                    self.logger.server_info(format_args!(
                        "Grace period elapsed with {} remaining connection(s), exiting",
                        self.engine.connection_count()
                    ))?;

                    break Ok(());
                }

                // A retransmit deadline elapsed -> retransmit all expired segments
                Ok(PollOutcome::Timeout) => {
                    for retransmission in self.engine.make_retransmissions() {
                        let pkt = retransmission?;
                        self.send_pkt(&pkt)?;
                        self.logger.non_reply_transmission(&pkt, true)?;
                    }
                }

                // The device became readable within the timeout -> regular read and reply. If the
                // shutdown eventfd also became readable, check for shutdown after handling the
                // packet.
                Ok(poll_outcome @ (PollOutcome::Readable | PollOutcome::Both)) => {
                    // Unlike `poll()`, `read()` here never needs to watch the shutdown
                    // eventfd because it only ever runs once this fd is readable, and since each
                    // worker thread owns its own queue fd exclusively, that data is still there
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
                        Err(e) => self.logger.pkt_err(e)?,

                        Ok(pkt_outcome) => {
                            if let Some(reply) = &pkt_outcome.reply {
                                self.send_pkt(reply)?;
                            }

                            self.logger.exchange(&pkt_outcome)?;
                        }
                    }

                    if poll_outcome == PollOutcome::Both
                        && (self.shutdown_check)()
                        && self.handle_shutdown_interrupt(Instant::now())?
                    {
                        break Ok(());
                    }

                    if self.engine.draining_complete() {
                        self.logger
                            .server_info("All connections closed within grace period, exiting")?;

                        break Ok(());
                    }
                }
            }
        }
    }

    /// Reacts to an `EINTR` caused by the shutdown signal, performing I/O resulting from the
    /// shutdown decision as necessary. Returns whether to proceed to shutdown immediately.
    fn handle_shutdown_interrupt(&mut self, now: Instant) -> TraceableResult<bool> {
        self.draining = true;

        Ok(match self.engine.handle_shutdown(now)? {
            ShutdownOutcome::AlreadyDraining { time_left } => {
                self.logger.server_info(format_args!(
                    "Draining connections, {}.{:03}s left",
                    time_left.as_secs(),
                    time_left.subsec_millis()
                ))?;

                false
            }

            ShutdownOutcome::BeganDraining { to_send } => {
                self.logger
                    .server_info("Shutdown signal received, closing established connections...")?;

                for pkt in to_send {
                    self.send_pkt(&pkt)?;
                    self.logger.non_reply_transmission(&pkt, false)?;
                }

                false
            }

            ShutdownOutcome::NoConnections => {
                self.logger.server_info(
                    "Shutdown signal received with no established connections, exiting",
                )?;

                true
            }
        })
    }

    /// Writes the protocol-specific header and payload of `outgoing` into the write buffer,
    /// prefixed with an IPv4 header, then writes the resulting packet to the device.
    fn send_pkt(&mut self, outgoing: &Ipv4Packet<Local>) -> TraceableResult {
        outgoing.write_into(&mut self.write_buf)?;

        self.device
            .write_all(self.write_buf.try_get(..outgoing.total_len().into())?)
            .map_err(Into::into)
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
        poll_readable: impl Fn(&MockDevice, Option<Duration>, bool) -> io::Result<PollOutcome>,
        shutdown_check: impl Fn() -> bool,
        shutdown_grace_period: Duration,
    ) -> TraceableResult {
        Server {
            write_buf: [0u8; ETHERNET_MTU],
            engine: Engine::test_new(ServerApp::Echo, tcp_connections, shutdown_grace_period),
            logger: Logger::new(LogLevel::Silent, Instant::now(), 0),
            device,
            poll_readable,
            shutdown_check,
            draining: false,
        }
        .run()
    }
}
