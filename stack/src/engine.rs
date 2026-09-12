use {
    crate::{
        application::Application,
        endpoint::{Local, Remote},
        ipv4_packet::Ipv4Packet,
        protocol::tcp::TcpConnections,
    },
    std::time::{Duration, Instant},
    typenet_utils::{error::TraceableResult, try_ops::TryAdd as _},
};

/// The result of handling one incoming packet, including the parsed packet ready to be logged and a
/// reply if one is required.
#[cfg_attr(test, derive(Debug))]
pub struct PacketOutcome<'a> {
    pub incoming: Ipv4Packet<'a, Remote>,
    pub reply: Option<Ipv4Packet<'a, Local>>,
}

/// The result of deciding how to react to a shutdown signal.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum ShutdownOutcome {
    /// A previous call already started draining, and there is `time_left` until the deadline.
    AlreadyDraining { time_left: Duration },

    /// This was the first call to result in active close, and at least one connection is still
    /// closing.
    BeganDraining { to_send: Vec<Ipv4Packet<'static, Local>> },

    /// This was the first call to result in active close, but no connection needed to finish
    /// closing.
    NoConnections,
}

/// Owns all protocol state (currently just TCP connections) and decision logic, independent of any
/// I/O.
///
/// Callers drive `Self` by feeding in incoming packets and timer/shutdown events, and are
/// responsible for actually reading/writing bytes and tracking wall-clock deadlines against
/// `poll_timeout`.
pub struct Engine<A: Application> {
    app: A,
    tcp_connections: TcpConnections,
    shutdown_grace_period: Duration,

    /// Deadline that bounds how long to wait for established connections to finish closing before
    /// giving up unconditionally. Set once a shutdown signal starts active close.
    shutdown_deadline: Option<Instant>,
}

impl<A: Application> Engine<A> {
    #[must_use]
    pub fn new(
        app: A,
        initial_rto: Duration,
        max_retries: u8,
        shutdown_grace_period: Duration,
    ) -> Self {
        Self {
            app,
            tcp_connections: TcpConnections::new(initial_rto, max_retries),
            shutdown_grace_period,
            shutdown_deadline: None,
        }
    }

    /// Builds a `Self` directly from `tcp_connections`, bypassing regular construction so tests
    /// (including those outside this module) can use seeded connections.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub const fn test_new(
        app: A,
        tcp_connections: TcpConnections,
        shutdown_grace_period: Duration,
    ) -> Self {
        Self { app, tcp_connections, shutdown_grace_period, shutdown_deadline: None }
    }

    /// The number of tracked connections (currently TCP is the only protocol with tracked state).
    #[must_use]
    pub fn connection_count(&self) -> usize { self.tcp_connections.len() }

    /// Parses `data` as an IPv4 header and protocol-specific header and payload, returning the
    /// incoming packet parsed into structs ready to be logged, and a reply if one is required.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the packet cannot be parsed or the reply cannot be created.
    pub fn handle_packet<'a>(&mut self, data: &'a [u8]) -> TraceableResult<PacketOutcome<'a>> {
        let incoming = Ipv4Packet::parse(data).map_err(|e| format!("Skipping packet: {e}"))?;

        let reply = incoming
            .create_reply(&mut self.app, &mut self.tcp_connections)
            .map_err(|e| format!("Error creating reply: {e}"))?;

        Ok(PacketOutcome { incoming, reply })
    }

    /// Returns all segments due for retransmission, updating their retry counts and deadlines or
    /// dropping the connection entirely if retries are exhausted.
    pub fn make_retransmissions(
        &mut self,
    ) -> impl Iterator<Item = TraceableResult<Ipv4Packet<'static, Local>>> + use<A> {
        self.tcp_connections
            .make_retransmissions()
            .into_iter()
            .map(TryFrom::try_from)
    }

    /// Decides how to react to a shutdown signal at time `now`. If not already draining, initiates
    /// active close of all established connections.
    ///
    /// # Errors
    ///
    /// Returns `Err` for arithmetic overflow in packet lengths or the shutdown timer.
    pub fn handle_shutdown(&mut self, now: Instant) -> TraceableResult<ShutdownOutcome> {
        Ok(if let Some(deadline) = self.shutdown_deadline {
            ShutdownOutcome::AlreadyDraining { time_left: deadline.saturating_duration_since(now) }
        } else {
            let to_send = self
                .tcp_connections
                .close_established()
                .map(TryFrom::try_from)
                .collect::<TraceableResult<_>>()?;

            if self.tcp_connections.closing_in_progress() {
                self.shutdown_deadline = Some(now.try_add(self.shutdown_grace_period)?);
                ShutdownOutcome::BeganDraining { to_send }
            } else {
                ShutdownOutcome::NoConnections
            }
        })
    }

    /// Computes how long to block when polling, which is the time remaining until the earlier of
    /// the shutdown deadline and the next pending retransmission, or if neither is set, returns
    /// `None` to block indefinitely.
    #[must_use]
    pub fn poll_timeout(&self, now: Instant) -> Option<Duration> {
        [self.shutdown_deadline, self.tcp_connections.next_retransmit_deadline()]
            .into_iter()
            .flatten()
            .min()
            .map(|deadline| deadline.saturating_duration_since(now))
    }

    /// Returns whether `now` has reached or passed the shutdown deadline if there is one, or
    /// `false` if there is no deadline.
    #[must_use]
    pub fn grace_period_elapsed(&self, now: Instant) -> bool {
        self.shutdown_deadline
            .is_some_and(|deadline| deadline <= now)
    }

    /// Returns whether a shutdown is in progress and there are no connections currently mid-close.
    #[must_use]
    pub fn draining_complete(&self) -> bool {
        self.shutdown_deadline.is_some() && !self.tcp_connections.closing_in_progress()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            ETHERNET_MTU,
            application::TestApp,
            ipv4_header::Ipv4Header,
            protocol::{Encode as _, tcp::TcpSegment},
        },
        pretty_assertions::assert_matches,
        typenet_utils::try_ops::TryGet as _,
    };

    /// A grace period of one year, more than long enough that it cannot plausibly elapse between
    /// two nearby `Instant::now()` calls.
    const ONE_YEAR_GRACE_PERIOD: Duration = Duration::from_hours(24 * 365);

    /// Builds an `Engine` from `tcp_connections` with a one-year grace period for tests that don't
    /// care about shutdown timing.
    fn test_engine(tcp_connections: TcpConnections) -> Engine<TestApp> {
        Engine::test_new(TestApp, tcp_connections, ONE_YEAR_GRACE_PERIOD)
    }

    mod handle_packet {
        use super::*;

        #[test]
        fn ipv4_parse_error_is_skipped() {
            assert_matches!(
                test_engine(TcpConnections::default()).handle_packet(&[0u8; 5]),
                Err(e) if e.to_string().contains("Skipping packet")
                    && e.to_string().contains("IPv4")
            );
        }

        #[test]
        fn ipv4_ok_but_tcp_parse_error_is_skipped() -> TraceableResult {
            // A valid IPv4 header claiming a 4-byte TCP payload (far too short), so IPv4 parsing
            // succeeds while TCP parsing fails.

            let fixture = TcpSegment::CLIENT_SYN;
            let mut buf = [0u8; ETHERNET_MTU];

            let ipv4_hdr =
                Ipv4Header::test_try_new_remote(fixture.proto(), fixture.get_ip_pair(), 4)?;
            ipv4_hdr.test_write_into_remote(&mut buf);

            assert_matches!(
                test_engine(TcpConnections::default())
                    .handle_packet(buf.try_get(..ipv4_hdr.total_len.into())?),
                Err(e) if e.to_string().contains("Skipping packet") && e.to_string().contains("TCP")
            );

            Ok(())
        }

        #[test]
        fn syn_parses_and_produces_a_reply() -> TraceableResult {
            let bytes = TcpSegment::CLIENT_SYN.encode_test_pkt()?;

            assert_matches!(
                test_engine(TcpConnections::default()).handle_packet(&bytes),
                Ok(PacketOutcome { reply: Some(_), .. })
            );

            Ok(())
        }

        #[test]
        fn handshake_ack_parses_and_produces_no_reply() -> TraceableResult {
            let bytes = TcpSegment::CLIENT_ACK_COMPLETING_HANDSHAKE.encode_test_pkt()?;

            assert_matches!(
                test_engine(TcpConnections::default().with_syn_rcv()).handle_packet(&bytes),
                Ok(PacketOutcome { reply: None, .. })
            );

            Ok(())
        }
    }

    mod make_retransmissions {
        use {super::*, pretty_assertions::assert_eq};

        #[test]
        fn forwards_due_segments_from_tcp_connections() -> TraceableResult {
            let mut engine =
                test_engine(TcpConnections::test_new(Duration::ZERO, 5).with_syn_rcv());

            assert_eq!(
                engine
                    .make_retransmissions()
                    .collect::<TraceableResult<Vec<_>>>()?,
                [TcpSegment::SERVER_SYN_ACK.try_into()?]
            );

            Ok(())
        }
    }

    mod handle_shutdown {
        use {super::*, pretty_assertions::assert_eq};

        #[test]
        fn no_connections_reports_no_connections_and_does_not_set_deadline() -> TraceableResult {
            let mut engine = test_engine(TcpConnections::default());

            assert_eq!(engine.handle_shutdown(Instant::now())?, ShutdownOutcome::NoConnections);
            assert!(engine.shutdown_deadline.is_none());

            Ok(())
        }

        #[test]
        fn established_connection_begins_draining_and_sets_deadline() -> TraceableResult {
            let mut engine = test_engine(TcpConnections::default().after_handshake());
            let now = Instant::now();

            assert_eq!(
                engine.handle_shutdown(now)?,
                ShutdownOutcome::BeganDraining {
                    to_send: vec![TcpSegment::SERVER_FIN_ACK_INITIATING_CLOSE.try_into()?]
                }
            );

            assert_eq!(engine.shutdown_deadline, Some(now.try_add(ONE_YEAR_GRACE_PERIOD)?));

            Ok(())
        }

        #[test]
        fn second_call_reports_time_left_without_resending() -> TraceableResult {
            let mut engine = test_engine(TcpConnections::default().after_handshake());
            let now = Instant::now();
            engine.handle_shutdown(now)?;

            let later = now + Duration::from_secs(5);
            let expected_deadline = now.try_add(ONE_YEAR_GRACE_PERIOD)?;

            assert_eq!(
                engine.handle_shutdown(later)?,
                ShutdownOutcome::AlreadyDraining {
                    time_left: expected_deadline.saturating_duration_since(later),
                }
            );

            Ok(())
        }

        #[test]
        fn overflowing_deadline_errors_instead_of_panicking() {
            let mut engine = Engine::test_new(
                TestApp,
                TcpConnections::default().after_handshake(),
                Duration::MAX,
            );

            assert_matches!(
                engine.handle_shutdown(Instant::now()),
                Err(e) if e.to_string().contains("Overflowed")
            );
        }
    }

    mod poll_timeout {
        use {super::*, pretty_assertions::assert_eq};

        #[test]
        fn neither_deadline_gives_no_timeout() {
            assert_eq!(test_engine(TcpConnections::default()).poll_timeout(Instant::now()), None);
        }

        #[test]
        fn shutdown_deadline_alone_gives_duration() -> TraceableResult {
            const GRACE_PERIOD: Duration = Duration::from_secs(10);

            let now = Instant::now();
            let mut engine = test_engine(TcpConnections::default());
            engine.shutdown_deadline = Some(now.try_add(GRACE_PERIOD)?);

            assert_eq!(engine.poll_timeout(now), Some(GRACE_PERIOD));

            Ok(())
        }

        #[test]
        fn pending_retransmission_alone_gives_duration() {
            const INITIAL_RTO: Duration = Duration::from_millis(750);

            let now = Instant::now();

            let engine = test_engine(
                TcpConnections::test_new(INITIAL_RTO, 5).with_syn_rcv_and_pkt_last_sent(now),
            );

            assert_eq!(engine.poll_timeout(now), Some(INITIAL_RTO));
        }

        #[test]
        fn earlier_retransmit_deadline_taken_over_later_shutdown_deadline() -> TraceableResult {
            const INITIAL_RTO: Duration = Duration::from_millis(250);

            let now = Instant::now();

            let mut engine = test_engine(
                TcpConnections::test_new(INITIAL_RTO, 5).with_syn_rcv_and_pkt_last_sent(now),
            );
            engine.shutdown_deadline = Some(now.try_add(Duration::from_secs(30))?);

            assert_eq!(
                engine.poll_timeout(now),
                Some(INITIAL_RTO),
                "The near-term retransmit deadline should win the `min`, not the far future \
                 shutdown deadline"
            );

            Ok(())
        }

        #[test]
        fn earlier_shutdown_deadline_taken_over_later_retransmit_deadline() -> TraceableResult {
            const GRACE_PERIOD: Duration = Duration::from_millis(250);

            let now = Instant::now();

            let mut engine =
                test_engine(TcpConnections::test_new(Duration::from_secs(30), 5).with_syn_rcv());
            engine.shutdown_deadline = Some(now.try_add(GRACE_PERIOD)?);

            assert_eq!(
                engine.poll_timeout(now),
                Some(GRACE_PERIOD),
                "The near-term shutdown deadline should win the `min`, not the far future \
                 retransmit deadline"
            );

            Ok(())
        }

        #[test]
        fn past_deadline_saturates_to_zero() -> TraceableResult {
            let now = Instant::now();
            let mut engine = test_engine(TcpConnections::default());

            engine.shutdown_deadline = Some(
                now.checked_sub(Duration::from_secs(10))
                    .ok_or("underflow")?,
            );

            assert_eq!(engine.poll_timeout(now), Some(Duration::ZERO));

            Ok(())
        }
    }

    mod grace_period_elapsed {
        use super::*;

        #[test]
        fn not_elapsed_with_no_deadline() {
            assert!(!test_engine(TcpConnections::default()).grace_period_elapsed(Instant::now()));
        }

        #[test]
        fn not_elapsed_before_deadline() -> TraceableResult {
            let now = Instant::now();
            let mut engine = test_engine(TcpConnections::default());
            engine.shutdown_deadline = Some(now.try_add(Duration::from_secs(10))?);

            assert!(!engine.grace_period_elapsed(now));

            Ok(())
        }

        #[test]
        fn elapsed_past_deadline() -> TraceableResult {
            let now = Instant::now();
            let mut engine = test_engine(TcpConnections::default());

            engine.shutdown_deadline = Some(
                now.checked_sub(Duration::from_secs(10))
                    .ok_or("underflow")?,
            );

            assert!(engine.grace_period_elapsed(now));

            Ok(())
        }

        #[test]
        fn elapsed_at_deadline() {
            let now = Instant::now();
            let mut engine = test_engine(TcpConnections::default());
            engine.shutdown_deadline = Some(now);

            assert!(engine.grace_period_elapsed(now));
        }
    }

    mod draining_complete {
        use super::*;

        #[test]
        fn false_with_no_deadline_and_nothing_closing() {
            assert!(!test_engine(TcpConnections::default()).draining_complete());
        }

        #[test]
        fn false_with_no_deadline_but_something_closing() {
            let mut tcp_connections = TcpConnections::default().after_handshake();
            tcp_connections.close_established().for_each(drop);
            assert!(!test_engine(tcp_connections).draining_complete());
        }

        #[test]
        fn false_with_deadline_but_still_closing() {
            let mut tcp_connections = TcpConnections::default().after_handshake();
            tcp_connections.close_established().for_each(drop);

            let mut engine = test_engine(tcp_connections);
            engine.shutdown_deadline = Some(Instant::now());

            assert!(!engine.draining_complete());
        }

        #[test]
        fn true_with_deadline_and_nothing_closing() {
            let mut engine = test_engine(TcpConnections::default());
            engine.shutdown_deadline = Some(Instant::now());
            assert!(engine.draining_complete());
        }
    }
}
