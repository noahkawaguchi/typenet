use {
    crate::{
        ETHERNET_MTU, Result,
        endpoint::{Local, Remote},
        ipv4_header::Ipv4Header,
        protocol::tcp::{
            LOCAL_SYN_BYTE, TCP_HDR_MIN_LEN, TcpSegment,
            flags::TcpFlags,
            payload::TcpPayload,
            pending_segment::PendingSegment,
            reassembly::TcpReassembly,
            send_info::SendInfo,
            seq_space::{SeqOffset, SeqPoint},
        },
    },
    std::{collections::VecDeque, marker::PhantomData, time::Instant},
};

/// The state of a connection in the table, including its TCP state, buffered data, and other
/// locally stored information.
#[cfg_attr(test, derive(Debug, Clone))]
pub(super) struct ConnState {
    pub(super) tcp_state: TcpState,

    /// "SND.NXT = next sequence number to be sent" (RFC 9293, Section 3.4).
    pub(super) snd_nxt: SeqPoint<Local>,

    /// "RCV.NXT = next sequence number expected on an incoming segment" (RFC 9293, Section 3.4).
    pub(super) rcv_nxt: SeqPoint<Remote>,

    /// "SND.UNA = oldest unacknowledged sequence number" (RFC 9293, Section 3.4).
    pub(super) snd_una: SeqPoint<Local>,

    /// Unacked segments sent by the server, kept for retransmission purposes.
    pub(super) pending: Vec<PendingSegment>,

    /// Bytes received from the peer that are queued to be echoed once SND.WND has room for them.
    pub(super) send_buffer: VecDeque<u8>,

    /// Segments received ahead of RCV.NXT, held until the gap before them closes.
    pub(super) reassembly: TcpReassembly,
}

impl ConnState {
    /// Creates a new `Self` in the state right after receiving a SYN and sending a SYN-ACK.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the flags are not SYN-ACK.
    pub(super) fn from_syn_ack(send_info: SendInfo) -> Result<Self, &'static str> {
        (send_info.flags == TcpFlags::SynAck)
            .then(|| Self {
                // State after the initial two-way exchange
                tcp_state: TcpState::SynReceived(SynReceived),
                // SYN-ACK consumes one sequence number
                snd_nxt: send_info.seq_num + LOCAL_SYN_BYTE,
                // Our SYN-ACK's `ack_num` is the client's ISN + 1
                rcv_nxt: send_info.ack_num,
                // Our SYN-ACK is unacknowledged (this is our ISN)
                snd_una: send_info.seq_num,
                pending: vec![PendingSegment::new(send_info, Instant::now())],
                send_buffer: VecDeque::new(),
                reassembly: TcpReassembly::new(),
            })
            .ok_or(
                "Attempted to create a new `ConnState` when sending something other than SYN-ACK",
            )
    }

    #[cfg(test)]
    pub(super) const fn test_get_snd_wnd(&self) -> Option<SeqOffset<u16, Local>> {
        match self.tcp_state {
            TcpState::SynReceived(_) => None,
            TcpState::Established(established) => Some(established.window_state.snd_wnd),
            TcpState::FinWait1(fin_wait_1) => Some(fin_wait_1.window_state.snd_wnd),
            TcpState::FinWait2(fin_wait_2) => Some(fin_wait_2.window_state.snd_wnd),
            TcpState::CloseWait(close_wait) => Some(close_wait.window_state.snd_wnd),
            TcpState::Closing(closing) => Some(closing.window_state.snd_wnd),
            TcpState::LastAck(last_ack) => Some(last_ack.window_state.snd_wnd),
        }
    }
}

#[cfg(test)]
impl PartialEq for ConnState {
    fn eq(
        &self,
        &Self {
            // Include all fields except `pending` (timing dependent), explicitly destructured to
            // catch any fields added later
            tcp_state,
            snd_nxt,
            rcv_nxt,
            snd_una,
            pending: _,
            ref send_buffer,
            ref reassembly,
        }: &Self,
    ) -> bool {
        self.tcp_state == tcp_state
            && self.snd_nxt == snd_nxt
            && self.rcv_nxt == rcv_nxt
            && self.snd_una == snd_una
            && &self.send_buffer == send_buffer
            && &self.reassembly == reassembly
    }
}

/// The SND.WND, SND.WL1, and SND.WL2 values of a connection.
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
#[expect(clippy::struct_field_names, reason = "Match RFC terminology")]
pub(super) struct WindowState {
    /// SND.WND or send window. "This represents the sequence numbers that the remote (receiving)
    /// TCP endpoint is willing to receive" (RFC 9293, Section 4).
    snd_wnd: SeqOffset<u16, Local>,

    /// SND.WL1. "segment sequence number used for last window update" (RFC 9293, Section 3.3.1).
    ///
    /// Purely used for internal bookkeeping alongside `snd_wl2` to determine whether a window
    /// value is fresh or stale/reordered.
    snd_wl1: SeqPoint<Remote>,

    /// SND.WL2. "segment acknowledgment number used for last window update" (RFC 9293, Section
    /// 3.3.1).
    ///
    /// Purely used for internal bookkeeping alongside `snd_wl1` to determine whether a window
    /// value is fresh or stale/reordered.
    snd_wl2: SeqPoint<Local>,
}

#[cfg(test)]
impl WindowState {
    pub(super) const fn test_new(
        snd_wnd: SeqOffset<u16, Local>,
        snd_wl1: SeqPoint<Remote>,
        snd_wl2: SeqPoint<Local>,
    ) -> Self {
        Self { snd_wnd, snd_wl1, snd_wl2 }
    }
}

/// The set of states of a TCP connection (non-exhaustive). Variant meanings below from RFC 9293,
/// Section 3.3.2.
#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub(super) enum TcpState {
    /// "SYN-RECEIVED - represents waiting for a confirming connection request acknowledgment after
    /// having both received and sent a connection request."
    ///
    /// ISN field: "The Initial Sequence Number. The first sequence number used on a connection"
    /// (RFC 9293, Section 4).
    SynReceived(SynReceived),

    /// "ESTABLISHED - represents an open connection, data received can be delivered to the user.
    /// The normal state for the data transfer phase of the connection."
    Established(SyncedState<Established>),

    /// "FIN-WAIT-1 - represents waiting for a connection termination request from the remote TCP
    /// peer, or an acknowledgment of the connection termination request previously sent."
    ///
    /// Entered when this server actively closes the connection.
    FinWait1(SyncedState<FinWait1>),

    /// "FIN-WAIT-2 - represents waiting for a connection termination request from the remote TCP
    /// peer."
    ///
    /// Reached from `FinWait1` once our FIN has been acknowledged.
    FinWait2(SyncedState<FinWait2>),

    /// "CLOSE-WAIT - represents waiting for a connection termination request from the local user."
    ///
    /// Reached via passive close, once the remote peer's FIN has been received. Any data still
    /// queued in `send_buffer` continues draining here and our own FIN is only sent (moving to
    /// LAST-ACK) once the buffer is fully drained.
    CloseWait(SyncedState<CloseWait>),

    /// "CLOSING - represents waiting for a connection termination request acknowledgment from the
    /// remote TCP peer."
    ///
    /// Reached via simultaneous close, when the remote peer's FIN arrives before our own FIN has
    /// been acknowledged.
    Closing(SyncedState<Closing>),

    /// "LAST-ACK - represents waiting for an acknowledgment of the connection termination request
    /// previously sent to the remote TCP peer (this termination request sent to the remote TCP peer
    /// already included an acknowledgment of the termination request sent from the remote TCP
    /// peer)."
    ///
    /// Reached via passive close, after acknowledging the remote peer's FIN with our own.
    LastAck(SyncedState<LastAck>),
}

/// Defines unit structs for all identifiers passed as comma-separated arguments, including the
/// appropriate derives and visibility for use in `TcpState`.
macro_rules! tcp_state_inner_structs {
    ($($state:ident),+ $(,)?) => {
        $(
            #[derive(PartialEq, Eq, Clone, Copy)]
            #[cfg_attr(test, derive(Debug))]
            pub(super) struct $state;
        )+
    };
}

tcp_state_inner_structs!(SynReceived, Established, FinWait1, FinWait2, CloseWait, Closing, LastAck);

impl SynReceived {
    /// Enters ESTABLISHED, setting SND.WND, SND.WL1, and SND.WL2 (RFC 9293, Section 3.10.7.4,
    /// "Fifth, check the ACK field," "SYN-RECEIVED STATE").
    #[expect(clippy::unused_self, reason = "Require an instance for state transition")]
    pub(super) const fn establish(self, seg: &TcpSegment<Remote>) -> SyncedState<Established> {
        SyncedState {
            window_state: WindowState {
                snd_wnd: seg.window,
                snd_wl1: seg.seq_num,
                snd_wl2: seg.ack_num,
            },
            phantom: PhantomData,
        }
    }
}

/// One of the synchronized TCP states.
#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct SyncedState<T> {
    window_state: WindowState,
    phantom: PhantomData<T>,
}

/// Given the pattern `($from:ty => $fn_name:ident => $to:ty)`, creates a method on
/// `SyncedState<$from>` called `$fn_name` that returns `SyncedState<$to>`.
macro_rules! synced_state_transition {
    ($from:ty => $fn_name:ident => $to:ty) => {
        impl SyncedState<$from> {
            pub(super) const fn $fn_name(self) -> SyncedState<$to> {
                SyncedState { window_state: self.window_state, phantom: PhantomData }
            }
        }
    };
}

synced_state_transition!(Established => rcv_fin => CloseWait);
synced_state_transition!(CloseWait => send_fin => LastAck);
synced_state_transition!(Established => close => FinWait1);
synced_state_transition!(FinWait1 => rcv_ack_of_fin => FinWait2);
synced_state_transition!(FinWait1 => rcv_fin_before_fin_is_acked => Closing);

impl<T> SyncedState<T> {
    /// Per RFC 9293, Section 3.10.7.4, "Fifth, check the ACK field," "ESTABLISHED STATE," processes
    /// an incoming segment's acknowledgment against the send-side state, updating SND.WND, SND.WL1,
    /// SND.WL2, SND.UNA, and the retransmission queue as necessary, both mutating `conn` in place
    /// and returning an updated `Self`.
    ///
    /// Ignores ACKs that are old (before SND.UNA) or for data not yet sent (past SND.NXT). Ignores
    /// duplicate ACKs (SND.UNA == SEG.ACK) for updates to SND.UNA and the retransmission queue.
    #[must_use = "Returns updated state as a new instance"]
    pub(super) fn incoming_ack_update(
        self,
        conn: &mut ConnState,
        seg: &TcpSegment<Remote>,
    ) -> Self {
        if conn.snd_una.precedes_or_eq(seg.ack_num) && seg.ack_num.precedes_or_eq(conn.snd_nxt) {
            // Exclude duplicate ACKs: SND.UNA < SEG.ACK <= SND.NXT
            if conn.snd_una.precedes(seg.ack_num) {
                conn.snd_una = seg.ack_num;

                // ACKs are cumulative, so only keep pending segments not fully covered by SEG.ACK
                conn.pending
                    .retain(|pending_seg| !pending_seg.is_covered_by(seg.ack_num));
            }

            // Include duplicate ACKs: SND.UNA <= SEG.ACK <= SND.NXT
            //     and
            // Guard against an old/reordered segment clobbering the window with stale data:
            //     SND.WL1 < SEG.SEQ or (SND.WL1 == SEG.SEQ and SND.WL2 <= SEG.ACK)
            if self.window_state.snd_wl1.precedes(seg.seq_num)
                || (self.window_state.snd_wl1 == seg.seq_num
                    && self.window_state.snd_wl2.precedes_or_eq(seg.ack_num))
            {
                Self {
                    window_state: WindowState {
                        snd_wnd: seg.window,
                        snd_wl1: seg.seq_num,
                        snd_wl2: seg.ack_num,
                    },
                    phantom: PhantomData,
                }
            } else {
                self
            }
        } else {
            self
        }
    }

    #[cfg(test)]
    pub(super) const fn test_new(window_state: WindowState) -> Self {
        Self { window_state, phantom: PhantomData }
    }
}

/// Represents being in a state where data is allowed to go out on the wire because our send side is
/// open, i.e. a synchronized state before our FIN has been sent. Private to this module to uphold
/// the invariant that this is only allowed in ESTABLISHED and CLOSE-WAIT.
trait SendSideOpen {}
impl SendSideOpen for Established {}
impl SendSideOpen for CloseWait {}

#[expect(private_bounds, reason = "Ensure only states allowed in this module can send data")]
impl<T: SendSideOpen> SyncedState<T> {
    /// Removes and returns as many bytes as possible from the front of the send buffer, bounded by
    /// the peer's currently advertised window and the maximum length of a segment, or returns
    /// `Ok(None)` if nothing can be sent. Does not mutate any other state.
    pub(super) fn drain_transmittable(&self, conn: &mut ConnState) -> Result<Option<TcpPayload>> {
        /// The maximum number of bytes that a single TCP payload can have. Constant because the
        /// current implementation never sends options in IP or TCP headers.
        const MAX_PAYLOAD_LEN: usize =
            ETHERNET_MTU - Ipv4Header::REPLY_HDR_LEN - TCP_HDR_MIN_LEN as usize;

        let sent_but_not_acked = conn
            .snd_nxt
            .offset_past(conn.snd_una)
            .ok_or("`drain_transmittable` called with SND.UNA not preceding or equaling SND.NXT")?;

        let space_in_window = SeqOffset::<u32, Local>::from(self.window_state.snd_wnd)
            .saturating_sub(sent_but_not_acked);

        let bytes_to_send = usize::try_from(space_in_window)?
            .min(conn.send_buffer.len())
            .min(MAX_PAYLOAD_LEN);

        TcpPayload::try_from_iter(conn.send_buffer.drain(..bytes_to_send)).map_err(Into::into)
    }
}
