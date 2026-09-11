use {
    crate::{
        addr_pairs::{Ipv4AddrPair, PortPair},
        endpoint::Local,
        protocol::tcp::{
            LOCAL_FIN_BYTE, TcpSegment,
            flags::TcpFlags,
            pending_segment::PendingSegment,
            send_info::SendInfo,
            state::{ConnState, TcpState},
        },
    },
    std::{
        collections::HashMap,
        net::Ipv4Addr,
        time::{Duration, Instant},
    },
    typenet_utils::error::TraceableResult,
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

/// Key identifying a TCP connection.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub(super) struct ConnKey {
    pub(super) client_ip: Ipv4Addr,
    pub(super) client_port: u16,
    pub(super) server_ip: Ipv4Addr,
    pub(super) server_port: u16,
}

/// Tracks per-connection state keyed by the 4-tuple.
#[cfg_attr(any(test, feature = "test-utils"), derive(Default))]
pub struct TcpConnections {
    table: HashMap<ConnKey, ConnState>,

    /// The initial, minimum, and maximum retransmission timeouts.
    rto_config: RtoConfig,

    /// The number of times to retransmit an unacked segment before giving up and dropping the
    /// connection.
    max_retries: u8,
}

impl TcpConnections {
    #[must_use]
    pub fn new(initial_rto: Duration, max_retries: u8) -> Self {
        Self {
            table: HashMap::new(),
            rto_config: RtoConfig { initial: initial_rto, min: TCP_RTO_MIN, max: TCP_RTO_MAX },
            max_retries,
        }
    }

    /// Same as production `Self::new`, except the minimum and maximum RTOs are `Duration::ZERO` and
    /// `Duration::MAX`.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn test_new(initial_rto: Duration, max_retries: u8) -> Self {
        Self {
            table: HashMap::new(),
            rto_config: RtoConfig { initial: initial_rto, min: Duration::ZERO, max: Duration::MAX },
            max_retries,
        }
    }

    pub(crate) fn len(&self) -> usize { self.table.len() }

    pub(super) fn get_mut(&mut self, key: &ConnKey) -> Option<&mut ConnState> {
        self.table.get_mut(key)
    }

    /// Adds a new SYN-RECEIVED connection to the table.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the connection's TCP state is not SYN-RECEIVED.
    pub(super) fn insert_syn_rcv(&mut self, key: ConnKey, state: ConnState) -> TraceableResult {
        matches!(state.tcp_state, TcpState::SynReceived(_))
            .then(|| {
                self.table.insert(key, state);
            })
            .ok_or_else(|| {
                "Attempted to insert a connection with a state other than SYN-RECEIVED".into()
            })
    }

    pub(super) fn remove(&mut self, key: &ConnKey) { self.table.remove(key); }

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
            .flat_map(|conn| &conn.pending)
            .map(|seg| seg.time_due(&self.rto_config))
            .min()
    }

    /// Reproduces every pending unacked segment that is due for retransmission. If any connection
    /// has a due segment that has already been retried `max_retries` times, gives up and removes
    /// that connection entirely.
    pub(crate) fn make_retransmissions(&mut self) -> Vec<TcpSegment<Local>> {
        let now = Instant::now();

        let due_keys = self
            .table
            .iter()
            .filter_map(|(&key, conn)| {
                conn.pending
                    .iter()
                    .any(|seg| seg.time_due(&self.rto_config) <= now)
                    .then_some(key)
            })
            .collect::<Vec<_>>();

        let mut retransmissions = Vec::new();

        for key in due_keys {
            let Some(conn) = self.table.get_mut(&key) else { continue };

            if conn.pending.iter().any(|seg| {
                seg.time_due(&self.rto_config) <= now && seg.exhausted_retries(self.max_retries)
            }) {
                self.table.remove(&key);
                continue;
            }

            retransmissions.extend(conn.pending.iter_mut().filter_map(|seg| {
                (seg.time_due(&self.rto_config) <= now).then(|| {
                    TcpSegment::from_pairs_and_info(
                        Ipv4AddrPair::new(key.server_ip, key.client_ip),
                        PortPair::new(key.server_port, key.client_port),
                        seg.retransmit_info(now),
                    )
                })
            }));
        }

        retransmissions
    }

    /// Initiates active close (RFC 9293 "CLOSE" call) for every connection currently ESTABLISHED,
    /// transitioning each to FIN-WAIT-1 and returning a FIN-ACK reply for it.
    pub(crate) fn close_established(&mut self) -> impl Iterator<Item = TcpSegment<Local>> {
        let now = Instant::now();

        self.table.iter_mut().filter_map(move |(key, conn)| {
            let TcpState::Established(established) = conn.tcp_state else {
                return None;
            };

            let send_info = SendInfo {
                seq_num: conn.snd_nxt,
                ack_num: conn.rcv_nxt,
                flags: TcpFlags::FinAck,
                payload: None,
            };

            conn.tcp_state = TcpState::FinWait1(established.close());
            conn.snd_nxt += LOCAL_FIN_BYTE;
            conn.pending
                .push(PendingSegment::new(send_info.clone(), now));

            Some(TcpSegment::from_pairs_and_info(
                Ipv4AddrPair::new(key.server_ip, key.client_ip),
                PortPair::new(key.server_port, key.client_port),
                send_info,
            ))
        })
    }

    /// Attempts to retrieve the connection in the table under `KEY`, returning `Err` if not
    /// present.
    #[cfg(test)]
    pub(super) fn try_get(&self) -> TraceableResult<&ConnState> {
        use crate::protocol::tcp::tests::KEY;

        self.table
            .get(&KEY)
            .ok_or_else(|| "Connection not found".into())
    }

    /// Inserts `conn` into the connection table using `KEY`.
    #[cfg(test)]
    pub(super) fn insert(&mut self, conn: ConnState) {
        use crate::protocol::tcp::tests::KEY;

        self.table.insert(KEY, conn);
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
        use {
            crate::protocol::tcp::{
                LOCAL_SYN_BYTE, REMOTE_SYN_BYTE,
                reassembly::TcpReassembly,
                state::SynReceived,
                test_utils::{CLIENT_ISN, KEY, SERVER_ISN},
            },
            std::collections::VecDeque,
        };

        self.table.insert(
            KEY,
            ConnState {
                tcp_state: TcpState::SynReceived(SynReceived),
                snd_nxt: SERVER_ISN + LOCAL_SYN_BYTE,
                rcv_nxt: CLIENT_ISN + REMOTE_SYN_BYTE,
                snd_una: SERVER_ISN,
                pending: vec![PendingSegment::new(
                    SendInfo {
                        seq_num: SERVER_ISN,
                        ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
                        flags: TcpFlags::SynAck,
                        payload: None,
                    },
                    sent_at,
                )],
                send_buffer: VecDeque::new(),
                reassembly: TcpReassembly::new(),
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
