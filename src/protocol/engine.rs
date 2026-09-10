use {
    crate::{
        endpoint::{Local, Remote},
        error::TraceableResult,
        ipv4_header::Ipv4Header,
        protocol::{RtoConfig, TcpConnections, TcpSegment, router::ProtocolRouter},
        try_ops::TryAdd as _,
    },
    std::time::{Duration, Instant},
};

/// A parsed incoming IPv4 header and protocol-specific header and payload, ready to be logged.
#[cfg_attr(test, derive(Debug))]
pub struct IncomingExchange<'a> {
    pub ipv4_hdr: Ipv4Header<Remote>,
    pub router: ProtocolRouter<'a, Remote>,
}

/// The result of handling one incoming packet, including the packet itself parsed for logging and a
/// reply if one is required.
#[cfg_attr(test, derive(Debug))]
pub struct PacketOutcome<'a> {
    pub incoming: IncomingExchange<'a>,
    pub reply: Option<ProtocolRouter<'a, Local>>,
}

/// The result of deciding how to react to a shutdown signal.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum ShutdownOutcome {
    /// A previous call already started draining, and there is `time_left` until the deadline.
    AlreadyDraining { time_left: Duration },

    /// This was the first call to result in active close, and at least one connection is still
    /// closing.
    BeganDraining { to_send: Vec<TcpSegment<Local>> },

    /// This was the first call to result in active close, but no connection needed to finish
    /// closing.
    NoConnections,
}

/// Owns all protocol state (currently just TCP connections) and decision logic, independent of any
/// I/O. Callers drive `Self` by feeding in incoming packets and timer/shutdown events, and are
/// responsible for actually reading/writing bytes and tracking wall-clock deadlines against
/// `poll_timeout`.
pub struct Engine {
    tcp_connections: TcpConnections,
    shutdown_grace_period: Duration,

    /// Deadline that bounds how long to wait for established connections to finish closing before
    /// giving up unconditionally. Set once a shutdown signal starts active close.
    shutdown_deadline: Option<Instant>,
}

impl Engine {
    pub fn new(rto_config: RtoConfig, max_retries: u8, shutdown_grace_period: Duration) -> Self {
        Self {
            tcp_connections: TcpConnections::new(rto_config, max_retries),
            shutdown_grace_period,
            shutdown_deadline: None,
        }
    }

    /// Builds a `Self` directly from `tcp_connections`, bypassing regular construction so tests
    /// (including those outside this module) can use seeded connections.
    #[cfg(test)]
    pub(crate) const fn test_new(
        tcp_connections: TcpConnections,
        shutdown_grace_period: Duration,
    ) -> Self {
        Self { tcp_connections, shutdown_grace_period, shutdown_deadline: None }
    }

    /// The number of tracked connections (currently TCP is the only protocol with tracked state).
    pub fn connection_count(&self) -> usize { self.tcp_connections.len() }

    /// Parses `data` as an IPv4 header and protocol-specific header and payload, returning the
    /// incoming packet parsed into structs ready to be logged, and a reply if one is required.
    pub fn handle_packet<'a>(&mut self, data: &'a [u8]) -> TraceableResult<PacketOutcome<'a>> {
        let (ipv4_hdr, ipv4_payload) =
            Ipv4Header::parse(data).map_err(|e| format!("Skipping packet: {e}"))?;

        let router = ProtocolRouter::parse(ipv4_payload, ipv4_hdr.protocol, ipv4_hdr.ip_pair)
            .map_err(|e| format!("Skipping packet: {e}"))?;

        let reply = router
            .create_reply(&mut self.tcp_connections)
            .map_err(|e| format!("Error creating reply: {e}"))?;

        Ok(PacketOutcome { incoming: IncomingExchange { ipv4_hdr, router }, reply })
    }

    /// Returns all segments due for retransmission, updating their retry counts and deadlines or
    /// dropping the connection entirely if retries are exhausted.
    pub fn make_retransmissions(&mut self) -> Vec<TcpSegment<Local>> {
        self.tcp_connections.make_retransmissions()
    }

    /// Decides how to react to a shutdown signal at time `now`. If not already draining, initiates
    /// active close of all established connections.
    pub fn handle_shutdown(&mut self, now: Instant) -> TraceableResult<ShutdownOutcome> {
        if let Some(deadline) = self.shutdown_deadline {
            return Ok(ShutdownOutcome::AlreadyDraining {
                time_left: deadline.saturating_duration_since(now),
            });
        }

        let to_send = self.tcp_connections.close_established();

        Ok(if self.tcp_connections.closing_in_progress() {
            self.shutdown_deadline = Some(now.try_add(self.shutdown_grace_period)?);
            ShutdownOutcome::BeganDraining { to_send }
        } else {
            ShutdownOutcome::NoConnections
        })
    }

    /// Computes how long to block when polling, which is the time remaining until the earlier of
    /// the shutdown deadline and the next pending retransmission, or if neither is set, returns
    /// `None` to block indefinitely.
    pub fn poll_timeout(&self, now: Instant) -> Option<Duration> {
        [self.shutdown_deadline, self.tcp_connections.next_retransmit_deadline()]
            .into_iter()
            .flatten()
            .min()
            .map(|deadline| deadline.saturating_duration_since(now))
    }

    /// Returns whether `now` has reached or passed the shutdown deadline if there is one, or
    /// `false` if there is no deadline.
    pub fn grace_period_elapsed(&self, now: Instant) -> bool {
        self.shutdown_deadline
            .is_some_and(|deadline| deadline <= now)
    }

    /// Returns whether a shutdown is in progress and there are no connections currently mid-close.
    pub fn draining_complete(&self) -> bool {
        self.shutdown_deadline.is_some() && !self.tcp_connections.closing_in_progress()
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{ETHERNET_MTU, protocol::router::Encode as _, try_ops::TryGet as _},
        pretty_assertions::assert_matches,
    };

    /// A grace period of one year, more than long enough that it cannot plausibly elapse between
    /// two nearby `Instant::now()` calls.
    const ONE_YEAR_GRACE_PERIOD: Duration = Duration::from_hours(24 * 365);

    /// Builds an `Engine` from `tcp_connections` with a one-year grace period for tests that don't
    /// care about shutdown timing.
    fn test_engine(tcp_connections: TcpConnections) -> Engine {
        Engine::test_new(tcp_connections, ONE_YEAR_GRACE_PERIOD)
    }

    /// Encodes `seg` into a full IPv4 packet so it can be handed to `handle_packet` as raw bytes.
    fn encode_pkt(seg: &TcpSegment<Remote>) -> TraceableResult<Vec<u8>> {
        let mut buf = [0u8; ETHERNET_MTU];
        let proto_len = seg.write_into(&mut buf[Ipv4Header::REPLY_HDR_LEN..])?;

        let ipv4_hdr = Ipv4Header::test_try_new_remote(seg.proto(), seg.get_ip_pair(), proto_len)?;
        ipv4_hdr.test_write_into_remote(&mut buf);

        Ok(buf.try_get(..ipv4_hdr.total_len.into())?.to_vec())
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
            let bytes = encode_pkt(&TcpSegment::CLIENT_SYN)?;

            assert_matches!(
                test_engine(TcpConnections::default()).handle_packet(&bytes),
                Ok(PacketOutcome {
                    incoming: IncomingExchange { router: ProtocolRouter::Tcp(_), .. },
                    reply: Some(ProtocolRouter::Tcp(_)),
                })
            );

            Ok(())
        }

        #[test]
        fn handshake_ack_parses_and_produces_no_reply() -> TraceableResult {
            let bytes = encode_pkt(&TcpSegment::CLIENT_ACK_COMPLETING_HANDSHAKE)?;

            assert_matches!(
                test_engine(TcpConnections::default().with_syn_rcv()).handle_packet(&bytes),
                Ok(PacketOutcome {
                    incoming: IncomingExchange { router: ProtocolRouter::Tcp(_), .. },
                    reply: None,
                })
            );

            Ok(())
        }
    }

    mod make_retransmissions {
        use {super::*, pretty_assertions::assert_eq};

        #[test]
        fn forwards_due_segments_from_tcp_connections() {
            let mut engine =
                test_engine(TcpConnections::new(RtoConfig::default(), 5).with_syn_rcv());

            assert_eq!(engine.make_retransmissions(), vec![TcpSegment::SERVER_SYN_ACK]);
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
                    to_send: vec![TcpSegment::SERVER_FIN_ACK_INITIATING_CLOSE]
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
                TcpConnections::new(RtoConfig { initial: INITIAL_RTO, ..Default::default() }, 5)
                    .with_syn_rcv_and_pkt_last_sent(now),
            );

            assert_eq!(engine.poll_timeout(now), Some(INITIAL_RTO));
        }

        #[test]
        fn earlier_retransmit_deadline_taken_over_later_shutdown_deadline() -> TraceableResult {
            const INITIAL_RTO: Duration = Duration::from_millis(250);

            let now = Instant::now();

            let mut engine = test_engine(
                TcpConnections::new(RtoConfig { initial: INITIAL_RTO, ..Default::default() }, 5)
                    .with_syn_rcv_and_pkt_last_sent(now),
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

            let mut engine = test_engine(
                TcpConnections::new(
                    RtoConfig { initial: Duration::from_secs(30), ..Default::default() },
                    5,
                )
                .with_syn_rcv(),
            );
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
            tcp_connections.close_established();
            assert!(!test_engine(tcp_connections).draining_complete());
        }

        #[test]
        fn false_with_deadline_but_still_closing() {
            let mut tcp_connections = TcpConnections::default().after_handshake();
            tcp_connections.close_established();

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
