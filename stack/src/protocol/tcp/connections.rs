#[cfg(test)]
use typenet_utils::error::TraceableResult;
use {
    crate::{
        direction::Out,
        endpoint::{Addr, Local, Port, Remote},
        protocol::tcp::{
            FIN_BYTE_OUT, TcpSegment,
            flags::TcpFlags,
            pending_segment::PendingSegment,
            send_info::SendInfo,
            state::{ConnState, TcpState},
        },
    },
    std::{
        collections::{HashMap, HashSet},
        str::FromStr,
        time::{Duration, Instant},
    },
    typenet_utils::error::TraceableError,
};

/// The minimum allowed TCP retransmission timeout (same as the Linux kernel as defined in
/// `include/net/tcp.h`).
const TCP_RTO_MIN: Duration = Duration::from_millis(200);

/// The maximum allowed TCP retransmission timeout (same as the Linux kernel as defined in
/// `include/net/tcp.h`).
const TCP_RTO_MAX: Duration = Duration::from_mins(2);

/// The initial, minimum, and maximum retransmission timeouts.
pub(super) struct RtoConfig {
    /// The initial RTO, i.e. how long to wait before retransmitting an unacked segment the first
    /// time before exponential backoff.
    pub(super) initial: Duration,

    /// The minimum allowed RTO, primarily used if the initial RTO is too small.
    pub(super) min: Duration,

    /// The maximum allowed RTO, primarily used after many rounds of exponential backoff.
    pub(super) max: Duration,
}

#[cfg(any(test, feature = "test-utils"))]
impl Default for RtoConfig {
    /// Creates a default `Self` for testing purposes where the initial and min are `Duration::ZERO`
    /// and the max is `Duration::MAX`.
    fn default() -> Self {
        Self { initial: Duration::ZERO, min: Duration::ZERO, max: Duration::MAX }
    }
}

/// The local ports on which new TCP connections are accepted (RFC 9293 "LISTEN" state, entered via
/// passive OPEN).
#[derive(Default, Clone)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug, PartialEq, Eq))]
#[expect(private_interfaces, reason = "not created directly outside the crate, only parsed")]
pub enum TcpListenPorts {
    /// Accept new connections on every port.
    #[default]
    All,

    /// Accept new connections only on these ports. Empty means no new connections are accepted.
    /// Port 0 is excluded, since it is reserved (RFC 6335, Section 6) and can never be the
    /// destination of a valid segment.
    Ports(HashSet<Port<Local>>),
}

impl FromStr for TcpListenPorts {
    type Err = TraceableError;

    /// Parses `s` as a comma-separated list of ports, tolerating whitespace around each one and
    /// duplicate entries.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the list is empty or any entry is not a valid nonzero port.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.split(',')
            .map(|raw| raw.trim().parse())
            .collect::<Result<_, _>>()
            .map_err(|_| format!("not a valid comma-separated list of ports: {s}").into())
            .map(Self::Ports)
    }
}

/// Key identifying a TCP connection.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub(super) struct ConnKey {
    pub(super) client_ip: Addr<Remote>,
    pub(super) client_port: Port<Remote>,
    pub(super) server_ip: Addr<Local>,
    pub(super) server_port: Port<Local>,
}

/// Tracks per-connection state keyed by the 4-tuple.
#[cfg_attr(
    not(feature = "test-utils"),
    expect(unreachable_pub, reason = "only exported with the `test-utils` feature")
)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Default))]
pub struct TcpConnections {
    table: HashMap<ConnKey, ConnState>,

    /// The local ports on which new connections are accepted.
    listen_ports: TcpListenPorts,

    /// The initial, minimum, and maximum retransmission timeouts.
    rto_config: RtoConfig,

    /// The number of times to retransmit an unacked segment before giving up and dropping the
    /// connection.
    max_retries: u8,
}

impl TcpConnections {
    #[cfg_attr(
        not(feature = "test-utils"),
        expect(unreachable_pub, reason = "only exported with the `test-utils` feature")
    )]
    #[must_use]
    pub fn new(initial_rto: Duration, max_retries: u8, listen_ports: TcpListenPorts) -> Self {
        Self {
            table: HashMap::new(),
            listen_ports,
            rto_config: RtoConfig { initial: initial_rto, min: TCP_RTO_MIN, max: TCP_RTO_MAX },
            max_retries,
        }
    }

    /// Same as production `Self::new`, except the minimum and maximum RTOs are `Duration::ZERO` and
    /// `Duration::MAX`, and new connections are accepted on every port.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn test_new(initial_rto: Duration, max_retries: u8) -> Self {
        Self {
            table: HashMap::new(),
            listen_ports: TcpListenPorts::All,
            rto_config: RtoConfig { initial: initial_rto, min: Duration::ZERO, max: Duration::MAX },
            max_retries,
        }
    }

    pub(crate) fn len(&self) -> usize { self.table.len() }

    /// Returns whether new connections are accepted on the local port `port`.
    pub(super) fn is_listening(&self, port: Port<Local>) -> bool {
        match &self.listen_ports {
            TcpListenPorts::All => true,
            TcpListenPorts::Ports(ports) => ports.contains(&port),
        }
    }

    /// Inserts `conn` into the table under `key`, replacing any existing connection.
    pub(super) fn insert(&mut self, key: ConnKey, conn: ConnState) { self.table.insert(key, conn); }

    /// Removes and returns the connection under `key`, if present.
    pub(super) fn remove(&mut self, key: &ConnKey) -> Option<ConnState> { self.table.remove(key) }

    /// Returns whether any connection is currently mid-close (FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT,
    /// CLOSING, or LAST-ACK), i.e. has sent or received a FIN but not yet completed teardown.
    pub(crate) fn closing_in_progress(&self) -> bool {
        // Explicitly match on all variants despite the `bool` result to ensure that any changes to
        // the enum must be addressed here
        self.table.values().any(|conn| match conn.tcp_state {
            TcpState::SynReceived(_) | TcpState::Established(_) => false,
            TcpState::FinWait1(_)
            | TcpState::FinWait2(_)
            | TcpState::CloseWait(_)
            | TcpState::Closing(_)
            | TcpState::LastAck(_) => true,
        })
    }

    /// Returns the earliest `Instant` at which a pending segment for any connection becomes due for
    /// retransmission, or `None` if no connection has any pending segments.
    pub(crate) fn next_retransmit_deadline(&self) -> Option<Instant> {
        self.table
            .values()
            .flat_map(|conn| &conn.data.pending)
            .map(|seg| seg.time_due(&self.rto_config))
            .min()
    }

    /// Reproduces every pending unacked segment that is due for retransmission. If any connection
    /// has a due segment that has already been retried `max_retries` times, gives up and removes
    /// that connection entirely.
    pub(crate) fn make_retransmissions(&mut self) -> Vec<TcpSegment<Out>> {
        let now = Instant::now();

        let due_keys = self
            .table
            .iter()
            .filter_map(|(&key, conn)| {
                conn.data
                    .pending
                    .iter()
                    .any(|seg| seg.time_due(&self.rto_config) <= now)
                    .then_some(key)
            })
            .collect::<Vec<_>>();

        let mut retransmissions = Vec::new();

        for key in due_keys {
            let Some(conn) = self.table.get_mut(&key) else { continue };

            if conn.data.pending.iter().any(|seg| {
                seg.time_due(&self.rto_config) <= now && seg.exhausted_retries(self.max_retries)
            }) {
                self.table.remove(&key);
                continue;
            }

            retransmissions.extend(conn.data.pending.iter_mut().filter_map(|seg| {
                (seg.time_due(&self.rto_config) <= now)
                    .then(|| TcpSegment::from_key_and_info(key, seg.retransmit_info(now)))
            }));
        }

        retransmissions
    }

    /// Issues the RFC 9293 "CLOSE" call (Section 3.10.4) on everything, returning a FIN-ACK reply
    /// for each connection that needs one. Per state:
    ///
    /// - LISTEN: stops accepting new connections on every port, so any later SYN is refused.
    /// - ESTABLISHED: initiates active close, transitioning to FIN-WAIT-1.
    /// - CLOSE-WAIT: nothing to do here, since our FIN already follows once the send buffer drains.
    /// - FIN-WAIT-1, FIN-WAIT-2, CLOSING, and LAST-ACK: already closing, so nothing to do.
    /// - SYN-RECEIVED: currently untouched, although the RFC calls for sending a FIN and entering
    ///   FIN-WAIT-1.
    pub(crate) fn close_all(&mut self) -> Vec<TcpSegment<Out>> {
        let now = Instant::now();

        self.listen_ports = TcpListenPorts::Ports(HashSet::new());

        self.table
            // Extract only established connections first as an optimization to avoid reinsertions
            // for connections that don't need to change. The real source of truth is the `match` in
            // the `filter_map`.
            .extract_if(|_, conn| matches!(conn.tcp_state, TcpState::Established(_)))
            .collect::<Vec<_>>()
            .into_iter()
            .filter_map(|(key, ConnState { tcp_state, mut data })| {
                let (maybe_seg, next_state) = match tcp_state {
                    TcpState::Established(established) => {
                        let send_info = SendInfo {
                            seq_num: data.snd_nxt,
                            ack_num: data.rcv_nxt,
                            flags: TcpFlags::FinAck,
                            payload: None,
                        };

                        data.snd_nxt += FIN_BYTE_OUT;
                        data.pending
                            .push(PendingSegment::new(send_info.clone(), now));

                        (
                            Some(TcpSegment::from_key_and_info(key, send_info)),
                            TcpState::FinWait1(established.close()),
                        )
                    }

                    other_state => (None, other_state),
                };

                self.table
                    .insert(key, ConnState { tcp_state: next_state, data });

                maybe_seg
            })
            // Eagerly run the closure instead of returning an iterator to ensure that all
            // reinsertions take place
            .collect()
    }

    /// Attempts to retrieve the connection in the table under `KEY`, returning `Err` if not
    /// present.
    #[cfg(test)]
    pub(super) fn try_get(&self) -> TraceableResult<&ConnState> {
        use crate::protocol::tcp::tests::KEY;

        self.table
            .get(&KEY)
            .ok_or_else(|| "connection not found".into())
    }

    /// Inserts `conn` into the connection table using `KEY`.
    #[cfg(test)]
    pub(super) fn test_insert(&mut self, conn: ConnState) {
        use crate::protocol::tcp::tests::KEY;

        self.table.insert(KEY, conn);
    }

    /// Replaces the ports on which new connections are accepted with `listen_ports`.
    #[cfg(test)]
    #[must_use]
    pub(super) fn with_listen_ports(mut self, listen_ports: TcpListenPorts) -> Self {
        self.listen_ports = listen_ports;
        self
    }

    /// Inserts a SYN-RECEIVED connection using `KEY`, `CLIENT_ISN`, and `SERVER_ISN` as if we had
    /// just responded to the peer's SYN with SYN-ACK.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_syn_rcv(self) -> Self { self.with_syn_rcv_and_pkt_last_sent(Instant::now()) }

    /// Inserts a SYN-RECEIVED connection using `KEY`, `CLIENT_ISN`, and `SERVER_ISN` as if we had
    /// just responded to the peer's SYN with SYN-ACK at time `sent_at`.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn with_syn_rcv_and_pkt_last_sent(mut self, sent_at: Instant) -> Self {
        use crate::protocol::tcp::{
            SYN_BYTE_IN, SYN_BYTE_OUT,
            state::{ConnData, SynReceived},
            test_utils::{CLIENT_ISN, KEY, SERVER_ISN},
        };

        self.table.insert(
            KEY,
            ConnState {
                tcp_state: TcpState::SynReceived(SynReceived),
                data: ConnData {
                    snd_nxt: SERVER_ISN + SYN_BYTE_OUT,
                    rcv_nxt: CLIENT_ISN + SYN_BYTE_IN,
                    snd_una: SERVER_ISN,
                    pending: vec![PendingSegment::new(
                        SendInfo {
                            seq_num: SERVER_ISN,
                            ack_num: CLIENT_ISN + SYN_BYTE_IN,
                            flags: TcpFlags::SynAck,
                            payload: None,
                        },
                        sent_at,
                    )],
                },
            },
        );

        self
    }

    /// Inserts an ESTABLISHED connection using `KEY` as if the initial three-way handshake had just
    /// completed.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn after_handshake(mut self) -> Self {
        use crate::protocol::tcp::test_utils::{AFTER_HANDSHAKE, KEY};

        self.table.insert(KEY, AFTER_HANDSHAKE);
        self
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        pretty_assertions::{assert_eq, assert_matches},
    };

    #[test]
    fn port_list_parses_with_whitespace_and_duplicates_tolerated() {
        fn port<const PRIMITIVE: u16>() -> Port<Local> { Port::comptime_new::<PRIMITIVE>() }

        for (input, expected) in [
            ("80", HashSet::from([port::<80>()])),
            ("80,443", HashSet::from([port::<80>(), port::<443>()])),
            (" 80 , 443 ", HashSet::from([port::<80>(), port::<443>()])),
            ("1,65535", HashSet::from([port::<1>(), port::<65535>()])),
            ("80,80,80,80", HashSet::from([port::<80>()])),
        ] {
            assert_eq!(input.parse(), Ok(TcpListenPorts::Ports(expected)), "{input:?}");
        }
    }

    #[test]
    fn port_list_rejected_when_empty_or_invalid() {
        for input in ["", " ", "abc", "70000", "-1", "80,", ",80", "80,,443", "80 443"] {
            assert_matches!(input.parse::<TcpListenPorts>(), Err(_), "{input:?}");
        }
    }

    #[test]
    fn port_list_rejected_when_any_port_is_zero() {
        for input in ["0", "80,0", "0,65535"] {
            assert_matches!(input.parse::<TcpListenPorts>(), Err(_), "{input:?}");
        }
    }
}
