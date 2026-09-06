use {
    crate::{
        Result,
        endpoint::{Local, Remote},
        protocol::{
            TcpConnections, TcpSegment,
            tcp::{
                LOCAL_FIN_BYTE, REMOTE_FIN_BYTE, REMOTE_SYN_BYTE,
                connections::ConnKey,
                flags::TcpFlags,
                payload::{LenOrDefault as _, TcpPayload},
                pending_segment::PendingSegment,
                seq_space::SeqPoint,
                state::{
                    CloseWait, Closing, ConnState, Established, FinWait1, FinWait2, LastAck,
                    SynReceived, SyncedState, TcpState,
                },
            },
        },
        sys,
    },
    std::time::Instant,
};

/// Comprises fields that differ when determining a segment to send and handles core reply logic.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct SendInfo {
    pub(super) seq_num: SeqPoint<Local>,
    pub(super) ack_num: SeqPoint<Remote>,
    pub(super) flags: TcpFlags,
    pub(super) payload: Option<TcpPayload>,
}

/// Possible outcomes after checking SEG.SEQ for acceptability.
enum SeqCheck {
    /// SEG.SEQ == RCV.NXT exactly.
    InOrder,
    /// SEG.SEQ is in RCV.WND but not in order.
    OutOfOrder,
    /// SEG.SEQ is out of RCV.WND.
    Unacceptable,
}

impl SeqCheck {
    /// Determines whether SEG.SEQ falls exactly at RCV.NXT, within RCV.WND but out of order, or
    /// outside RCV.WND.
    fn check(seg: &TcpSegment<Remote>, conn: &ConnState) -> Self {
        if seg.seq_num == conn.rcv_nxt {
            Self::InOrder
        } else if seg
            .seq_num
            .in_window(conn.rcv_nxt, TcpSegment::<Local>::RCV_WND.into())
        {
            Self::OutOfOrder
        } else {
            Self::Unacceptable
        }
    }
}

impl SendInfo {
    /// Creates a pure ACK `Self` with SEG.SEQ=SND.NXT and SEG.ACK=RCV.NXT.
    const fn pure_ack(conn: &ConnState) -> Self {
        Self { seq_num: conn.snd_nxt, ack_num: conn.rcv_nxt, flags: TcpFlags::Ack, payload: None }
    }

    /// Creates a RST with its SEG.SEQ set to `seg.ack_num`.
    const fn rst(seg: &TcpSegment<Remote>) -> Self {
        Self {
            seq_num: seg.ack_num,
            // ack_num is 0 because sending bare RST with no ACK flag leaves SEG.ACK undefined
            ack_num: SeqPoint::new(0),
            flags: TcpFlags::Rst,
            payload: None,
        }
    }

    /// Creates a `Self` for replying to `seg`, or returns `Ok(None)` for no reply, updating
    /// connection state accordingly.
    pub(super) fn decide_reply(
        seg: &TcpSegment<Remote>,
        connections: &mut TcpConnections,
    ) -> Result<Option<Self>> {
        let key = ConnKey {
            client_ip: seg.ip_pair.src,
            client_port: seg.ports.src,
            server_ip: seg.ip_pair.dst,
            server_port: seg.ports.dst,
        };

        // Closure to deduplicate processing of state-specific helpers' return values
        let known_conn_case = |(maybe_send_info, remove_conn), conns: &mut TcpConnections| {
            if remove_conn {
                conns.remove(&key);
            }
            maybe_send_info
        };

        Ok(match connections.get_mut(&key) {
            None => Self::handle_unknown_conn(seg, connections, key)?,

            Some(conn) => known_conn_case(
                match conn.tcp_state {
                    TcpState::SynReceived(syn_received) => {
                        Self::handle_syn_rcv(seg, conn, syn_received)?
                    }

                    TcpState::Established(established) => {
                        Self::handle_established(seg, conn, established)?
                    }

                    TcpState::FinWait1(fin_wait_1) => {
                        Self::handle_fin_wait_1(seg, conn, fin_wait_1)
                    }

                    TcpState::FinWait2(fin_wait_2) => {
                        Self::handle_fin_wait_2(seg, conn, fin_wait_2)
                    }

                    TcpState::CloseWait(close_wait) => {
                        Self::handle_close_wait(seg, conn, close_wait)?
                    }

                    TcpState::Closing(closing) => Self::handle_closing(seg, conn, closing),

                    TcpState::LastAck(last_ack) => Self::handle_last_ack(seg, conn, last_ack),
                },
                connections,
            ),
        })
    }

    fn handle_unknown_conn(
        seg: &TcpSegment<Remote>,
        connections: &mut TcpConnections,
        key: ConnKey,
    ) -> Result<Option<Self>> {
        Ok(match seg.flags {
            // SYN (step 1 of handshake) -> store new connection, reply with SYN-ACK (step 2).
            TcpFlags::Syn => {
                let send_info = Self {
                    seq_num: SeqPoint::new(sys::random_u32()?),
                    ack_num: seg.seq_num + REMOTE_SYN_BYTE,
                    flags: TcpFlags::SynAck,
                    payload: None,
                };

                connections.insert_syn_rcv(key, ConnState::from_syn_ack(send_info.clone())?)?;

                Some(send_info)
            }

            // RST from an unknown connection -> per RFC 9293, Sections 3.10.7.1 and 3.10.7.2,
            // silently drop the segment (never RST a RST).
            TcpFlags::Rst | TcpFlags::RstAck => None,

            // Something else with ACK set (non-RST) -> per RFC 9293, Sections 3.10.7.1 and
            // 3.10.7.2, send <SEQ=SEG.ACK><CTL=RST>.
            TcpFlags::SynAck | TcpFlags::Ack | TcpFlags::FinAck => Some(Self::rst(seg)),
        })
    }

    /// Common fallback cases among known connections.
    #[expect(clippy::match_same_arms, reason = "Clearly express various challenge ACK scenarios")]
    fn known_conn_common_fallback(
        seg: &TcpSegment<Remote>,
        conn: &ConnState,
    ) -> (Option<Self>, bool) {
        let challenge_ack = (Some(Self::pure_ack(conn)), false);

        match (seg.flags, SeqCheck::check(seg, conn)) {
            // RST on a known connection -> RFC 9293, Section 3.10.7.4 has three cases for when
            // the RST bit is set, protecting against a blind reset attack (as described in RFC
            // 5961, Section 3):

            // Case 1: SEG.SEQ outside window -> silently drop segment
            (TcpFlags::Rst | TcpFlags::RstAck, SeqCheck::Unacceptable) => (None, false),
            // Case 2: SEG.SEQ == RCV.NXT -> reset connection, no reply
            (TcpFlags::Rst | TcpFlags::RstAck, SeqCheck::InOrder) => (None, true),
            // Case 3: SEG.SEQ in window but != RCV.NXT -> don't reset, send challenge ACK
            (TcpFlags::Rst | TcpFlags::RstAck, SeqCheck::OutOfOrder) => challenge_ack,

            // Non-RST with unacceptable SEG.SEQ -> current state ACK.
            (
                TcpFlags::Syn | TcpFlags::SynAck | TcpFlags::Ack | TcpFlags::FinAck,
                SeqCheck::Unacceptable,
            ) => challenge_ack,

            // Stray SYN/SYN-ACK on a synchronized connection -> send a challenge ACK, do not reset
            // the connection (RFC 9293, Section 3.10.7.4, "Fourth, check the SYN bit").
            (TcpFlags::Syn | TcpFlags::SynAck, _)
                if !matches!(conn.tcp_state, TcpState::SynReceived(_)) =>
            {
                challenge_ack
            }

            // Non-RST with acceptable SEG.SEQ refused at every previous point (rare) -> RST.
            (
                TcpFlags::Syn | TcpFlags::SynAck | TcpFlags::Ack | TcpFlags::FinAck,
                SeqCheck::InOrder | SeqCheck::OutOfOrder,
            ) => (Some(Self::rst(seg)), false),
        }
    }

    /// Handles the reply decision and state updates for a SYN-RECEIVED connection, returning a
    /// reply if necessary and a `bool` representing whether the connection should be removed.
    fn handle_syn_rcv(
        seg: &TcpSegment<Remote>,
        conn: &mut ConnState,
        syn_received: SynReceived,
    ) -> Result<(Option<Self>, bool)> {
        let acceptable_ack =
            conn.snd_una.precedes(seg.ack_num) && seg.ack_num.precedes_or_eq(conn.snd_nxt);

        Ok(match (seg.flags, &seg.payload, SeqCheck::check(seg, conn), acceptable_ack) {
            // Duplicate SYN while awaiting the handshake ACK (client's retransmission timer resent
            // the SYN) -> resend the same SYN-ACK (which was likely lost) using the already-stored
            // ISN.
            (TcpFlags::Syn, ..) => {
                let send_info = Self {
                    seq_num: conn.snd_una, // ISN
                    ack_num: seg.seq_num + REMOTE_SYN_BYTE,
                    flags: TcpFlags::SynAck,
                    payload: None,
                };

                conn.pending
                    .push(PendingSegment::new(send_info.clone(), Instant::now()));

                (Some(send_info), false)
            }

            // Acceptable handshake-completing ACK (step 3), arriving in order -> transition to
            // ESTABLISHED, echoing any payload and/or previously buffered out-of-order data that is
            // now contiguous with the just-arrived payload if the peer's window allows. If the
            // peer's previously buffered FIN has now been reached, enter LAST-ACK instead of
            // continuing normally.
            (TcpFlags::Ack, maybe_payload, SeqCheck::InOrder, true) => {
                let established = Self::complete_handshake(seg, conn, syn_received);

                if let Some(payload) = maybe_payload {
                    conn.rcv_nxt += payload.len().into();
                    conn.send_buffer.extend(payload.as_bytes());
                }

                let mut reassembled = Vec::new();
                conn.rcv_nxt = conn
                    .reassembly
                    .drain_contiguous(conn.rcv_nxt, &mut reassembled);
                let anything_to_send = maybe_payload.is_some() || !reassembled.is_empty();
                conn.send_buffer.extend(reassembled);

                (
                    if conn.reassembly.fin_reached(conn.rcv_nxt) {
                        conn.rcv_nxt += REMOTE_FIN_BYTE;
                        Some(Self::close_wait_or_last_ack(conn, established.rcv_fin())?)
                    } else if anything_to_send {
                        Some(match established.drain_transmittable(conn)? {
                            Some(to_send) => Self::data_payload(conn, to_send),
                            None => Self::pure_ack(conn),
                        })
                    } else {
                        None
                    },
                    false,
                )
            }

            // Acceptable handshake-completing FIN-ACK (step 3 combined with the peer's own close),
            // arriving in order -> complete the handshake, transitioning to ESTABLISHED (RFC 9293,
            // Section 3.10.7.4, "Fifth, check the ACK field"), then immediately start closing
            // ("Eighth, check the FIN bit"), skipping CLOSE-WAIT under the current simplification,
            // the same as a FIN-ACK arriving on an ESTABLISHED connection. Also echo as much
            // trailing data as possible, if any.
            (TcpFlags::FinAck, maybe_payload, SeqCheck::InOrder, true) => {
                let established = Self::complete_handshake(seg, conn, syn_received);
                (
                    Some(Self::close_on_in_order_fin(
                        seg,
                        conn,
                        maybe_payload.as_ref(),
                        established,
                    )?),
                    false,
                )
            }

            // Acceptable handshake-completing ACK or FIN-ACK, arriving out of order but still
            // within the receive window, with valid SEG.ACK -> complete the handshake. Any payload
            // can't be delivered yet, since data before it is still missing, so buffer it for later
            // reassembly. Any FIN also can't be processed yet, so buffer its position.
            (TcpFlags::Ack | TcpFlags::FinAck, maybe_payload, SeqCheck::OutOfOrder, true) => {
                Self::complete_handshake(seg, conn, syn_received);
                if let Some(payload) = maybe_payload {
                    conn.reassembly.insert(seg.seq_num, payload.clone());
                }
                if seg.flags == TcpFlags::FinAck {
                    conn.reassembly
                        .mark_fin(seg.seq_num + maybe_payload.len_or_default());
                }
                (Some(Self::pure_ack(conn)), false)
            }

            _ => Self::known_conn_common_fallback(seg, conn),
        })
    }

    /// Completes the initial three-way handshake, updating the state of `conn` and returning a copy
    /// of the inner struct that was placed inside `conn.tcp_state`.
    fn complete_handshake(
        seg: &TcpSegment<Remote>,
        conn: &mut ConnState,
        syn_received: SynReceived,
    ) -> SyncedState<Established> {
        let established = syn_received.establish(seg);

        conn.tcp_state = TcpState::Established(established);
        conn.snd_una = seg.ack_num;
        conn.pending.clear(); // Only the SYN-ACK just acknowledged could have been pending

        established
    }

    /// Handles the reply decision and state updates for an ESTABLISHED connection, returning a
    /// reply if necessary and a `bool` representing whether the connection should be removed.
    fn handle_established(
        seg: &TcpSegment<Remote>,
        conn: &mut ConnState,
        established: SyncedState<Established>,
    ) -> Result<(Option<Self>, bool)> {
        Ok(match (seg.flags, &seg.payload, SeqCheck::check(seg, conn)) {
            // ACK acknowledging data the server has not yet sent (ack_num is past snd_nxt) ->
            // per RFC 9293, Section 3.10.7.4, drop the segment and reply with an ACK reflecting
            // current state.
            (TcpFlags::Ack, _, _) if conn.snd_nxt.precedes(seg.ack_num) => {
                (Some(Self::pure_ack(conn)), false)
            }

            // Pure ACK (acknowledgment of data sent by the server) -> advance SND.UNA, then send
            // however much the window allows from the data queued to be sent, if any.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder) => {
                let new_established = established.incoming_ack_update(conn, seg);
                conn.tcp_state = TcpState::Established(new_established);
                (
                    new_established
                        .drain_transmittable(conn)?
                        .map(|to_send| Self::data_payload(conn, to_send)),
                    false,
                )
            }

            // In-order data packet -> ACK receipt of data, advance RCV.NXT, and echo any payload
            // and previously buffered out-of-order data that is now contiguous (as much as fits in
            // the peer's window).
            //
            // If the peer's previously buffered FIN has now been reached, enter LAST-ACK (passive
            // close) instead of continuing normally.
            (TcpFlags::Ack, Some(payload), SeqCheck::InOrder) => {
                let new_established = established.incoming_ack_update(conn, seg);

                conn.tcp_state = TcpState::Established(new_established);
                conn.rcv_nxt += payload.len().into();
                conn.send_buffer.extend(payload.as_bytes());

                let mut reassembled = Vec::new();
                conn.rcv_nxt = conn
                    .reassembly
                    .drain_contiguous(conn.rcv_nxt, &mut reassembled);
                conn.send_buffer.extend(reassembled);

                (
                    Some(if conn.reassembly.fin_reached(conn.rcv_nxt) {
                        conn.rcv_nxt += REMOTE_FIN_BYTE;
                        Self::close_wait_or_last_ack(conn, new_established.rcv_fin())?
                    } else {
                        match new_established.drain_transmittable(conn)? {
                            Some(to_send) => Self::data_payload(conn, to_send),
                            None => Self::pure_ack(conn),
                        }
                    }),
                    false,
                )
            }

            // Out-of-order data still within the receive window -> buffer it for later reassembly,
            // replying with a duplicate ACK so the peer knows what's still missing.
            (TcpFlags::Ack, Some(payload), SeqCheck::OutOfOrder) => {
                conn.tcp_state = TcpState::Established(established.incoming_ack_update(conn, seg));
                conn.reassembly.insert(seg.seq_num, payload.clone());
                (Some(Self::pure_ack(conn)), false)
            }

            // FIN-ACK (connection teardown), arriving in order -> echo any trailing data (as much
            // as the window allows, same as plain in-order data), then start closing to wait for
            // client's final ACK, replying with FIN-ACK. Unlike FIN-WAIT-1/2, our own FIN hasn't
            // gone out yet, so we can piggyback the data echo on this same reply.
            (TcpFlags::FinAck, maybe_payload, SeqCheck::InOrder) => (
                Some(Self::close_on_in_order_fin(seg, conn, maybe_payload.as_ref(), established)?),
                false,
            ),

            // Out-of-order FIN-ACK still within the receive window -> buffer any trailing data and
            // remember the FIN's position for later reassembly, replying with a duplicate ACK, same
            // as out-of-order data-only segments.
            (TcpFlags::FinAck, maybe_payload, SeqCheck::OutOfOrder) => {
                conn.tcp_state = TcpState::Established(established.incoming_ack_update(conn, seg));
                if let Some(payload) = maybe_payload {
                    conn.reassembly.insert(seg.seq_num, payload.clone());
                }
                conn.reassembly
                    .mark_fin(seg.seq_num + maybe_payload.len_or_default());
                (Some(Self::pure_ack(conn)), false)
            }

            _ => Self::known_conn_common_fallback(seg, conn),
        })
    }

    /// Creates a `Self` for the payload `to_send`, advancing SND.NXT and recording the outgoing
    /// segment as pending.
    fn data_payload(conn: &mut ConnState, to_send: TcpPayload) -> Self {
        let send_len = to_send.len().into();

        let send_info = Self {
            seq_num: conn.snd_nxt,
            ack_num: conn.rcv_nxt,
            flags: TcpFlags::Ack,
            payload: Some(to_send),
        };

        conn.snd_nxt += send_len;
        conn.pending
            .push(PendingSegment::new(send_info.clone(), Instant::now()));

        send_info
    }

    /// Handles a FIN arriving in order in `seg`, advancing RCV.NXT past any trailing payload and
    /// the FIN itself, updating send-side state, and then proceeding to CLOSE-WAIT or LAST-ACK
    /// depending on whether all buffered data can be sent.
    fn close_on_in_order_fin(
        seg: &TcpSegment<Remote>,
        conn: &mut ConnState,
        maybe_payload: Option<&TcpPayload>,
        old_established: SyncedState<Established>,
    ) -> Result<Self> {
        if let Some(payload) = maybe_payload {
            conn.rcv_nxt += payload.len().into();
            conn.send_buffer.extend(payload.as_bytes());
        }

        conn.rcv_nxt += REMOTE_FIN_BYTE;

        let new_established = old_established.incoming_ack_update(conn, seg);
        Self::close_wait_or_last_ack(conn, new_established.rcv_fin())
    }

    /// Drains as much of `send_buffer` as the peer's window currently allows. If that empties the
    /// buffer, our own FIN is sent (piggybacked on any final chunk of data) and `conn` moves to
    /// LAST-ACK. Otherwise, the drained chunk is sent as a plain data ACK, and `conn` remains in
    /// CLOSE-WAIT, to be drained further once the peer sends more ACKs.
    fn close_wait_or_last_ack(
        conn: &mut ConnState,
        close_wait: SyncedState<CloseWait>,
    ) -> Result<Self> {
        let to_send = close_wait.drain_transmittable(conn)?;

        Ok(if conn.send_buffer.is_empty() {
            let send_len = to_send.len_or_default();

            conn.tcp_state = TcpState::LastAck(close_wait.send_fin());

            let send_info = Self {
                seq_num: conn.snd_nxt,
                ack_num: conn.rcv_nxt,
                flags: TcpFlags::FinAck,
                payload: to_send,
            };

            conn.snd_nxt += send_len;
            conn.snd_nxt += LOCAL_FIN_BYTE;

            conn.pending
                .push(PendingSegment::new(send_info.clone(), Instant::now()));

            send_info
        } else {
            conn.tcp_state = TcpState::CloseWait(close_wait);

            match to_send {
                Some(payload) => Self::data_payload(conn, payload),
                None => Self::pure_ack(conn),
            }
        })
    }

    /// Handles the reply decision and state updates for a FIN-WAIT-1 connection, returning a reply
    /// if necessary and a `bool` representing whether the connection should be removed.
    fn handle_fin_wait_1(
        seg: &TcpSegment<Remote>,
        conn: &mut ConnState,
        fin_wait_1: SyncedState<FinWait1>,
    ) -> (Option<Self>, bool) {
        let our_fin_acked = seg.ack_num == conn.snd_nxt;

        match (seg.flags, &seg.payload, SeqCheck::check(seg, conn), our_fin_acked) {
            // In-order data arriving after we've sent our own FIN but before the peer's FIN has
            // arrived (half closed) -> ACK it, don't echo because we have no send side left, and
            // advance RCV.NXT.
            (TcpFlags::Ack, Some(payload), SeqCheck::InOrder, _) => {
                conn.rcv_nxt += payload.len().into();
                let send_info = Self::pure_ack(conn);
                conn.tcp_state = TcpState::FinWait1(fin_wait_1.incoming_ack_update(conn, seg));
                (Some(send_info), false)
            }

            // Our FIN has been acknowledged (and nothing else) -> FIN-WAIT-2, no reply.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder, true) => {
                conn.tcp_state =
                    TcpState::FinWait2(fin_wait_1.incoming_ack_update(conn, seg).rcv_ack_of_fin());
                (None, false)
            }

            // Partial ACK not yet covering our FIN -> update send-side state like a plain ACK, keep
            // waiting in FIN-WAIT-1 for the ACK that covers it.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder, false) => {
                conn.tcp_state = TcpState::FinWait1(fin_wait_1.incoming_ack_update(conn, seg));
                (None, false)
            }

            // Peer's FIN arrives before ours is acknowledged (simultaneous close), and it also
            // acknowledges our FIN -> ACK it and remove the connection (skipping
            // FIN-WAIT-2/TIME-WAIT).
            //
            // Our own FIN has already been sent, so any trailing data can't be echoed (same as
            // plain data arriving in FIN-WAIT-1), but RCV.NXT must still advance past it.
            (TcpFlags::FinAck, maybe_payload, SeqCheck::InOrder, true) => {
                conn.rcv_nxt += maybe_payload.len_or_default();
                conn.rcv_nxt += REMOTE_FIN_BYTE;
                (Some(Self::pure_ack(conn)), true)
            }

            // Peer's FIN arrives before ours is acknowledged (simultaneous close), but it doesn't
            // acknowledge our FIN -> ACK it and move to CLOSING to await the ACK of our FIN.
            //
            // Our own FIN has already been sent, so any trailing data can't be echoed (same as
            // plain data arriving in FIN-WAIT-1), but RCV.NXT must still advance past it.
            (TcpFlags::FinAck, maybe_payload, SeqCheck::InOrder, false) => {
                conn.rcv_nxt += maybe_payload.len_or_default();
                conn.rcv_nxt += REMOTE_FIN_BYTE;
                let send_info = Self::pure_ack(conn);

                conn.tcp_state = TcpState::Closing(
                    fin_wait_1
                        .incoming_ack_update(conn, seg)
                        .rcv_fin_before_fin_is_acked(),
                );

                (Some(send_info), false)
            }

            _ => Self::known_conn_common_fallback(seg, conn),
        }
    }

    /// Handles the reply decision and state updates for a FIN-WAIT-2 connection, returning a reply
    /// if necessary and a `bool` representing whether the connection should be removed.
    fn handle_fin_wait_2(
        seg: &TcpSegment<Remote>,
        conn: &mut ConnState,
        fin_wait_2: SyncedState<FinWait2>,
    ) -> (Option<Self>, bool) {
        match (seg.flags, &seg.payload, SeqCheck::check(seg, conn)) {
            // In-order data arriving after we've sent our own FIN but before the peer's FIN has
            // arrived (half closed) -> ACK it, don't echo because we have no send side left, and
            // advance RCV.NXT.
            (TcpFlags::Ack, Some(payload), SeqCheck::InOrder) => {
                conn.rcv_nxt += payload.len().into();
                let send_info = Self::pure_ack(conn);
                conn.tcp_state = TcpState::FinWait2(fin_wait_2.incoming_ack_update(conn, seg));
                (Some(send_info), false)
            }

            // Plain ACK with nothing new (e.g. a window update) while waiting for the peer's FIN ->
            // update send-side state like a plain ACK, no reply.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder) => {
                conn.tcp_state = TcpState::FinWait2(fin_wait_2.incoming_ack_update(conn, seg));
                (None, false)
            }

            // Peer's FIN arrives in order -> ACK it and finish closing (no TIME-WAIT). Our own FIN
            // has already been sent, so any trailing data can't be echoed, but the ACK must still
            // reflect RCV.NXT advanced past it as well as the FIN.
            (TcpFlags::FinAck, maybe_payload, SeqCheck::InOrder) => {
                conn.rcv_nxt += maybe_payload.len_or_default();
                conn.rcv_nxt += REMOTE_FIN_BYTE;
                (Some(Self::pure_ack(conn)), true)
            }

            _ => Self::known_conn_common_fallback(seg, conn),
        }
    }

    /// Handles the reply decision and state updates for a CLOSE-WAIT connection, returning a reply
    /// if necessary and a `bool` representing whether the connection should be removed.
    fn handle_close_wait(
        seg: &TcpSegment<Remote>,
        conn: &mut ConnState,
        close_wait: SyncedState<CloseWait>,
    ) -> Result<(Option<Self>, bool)> {
        Ok(match (seg.flags, &seg.payload, SeqCheck::check(seg, conn)) {
            // ACK of previously sent data (or a window update) while still draining the send buffer
            // -> update send-side state, then try to send more and/or proceed to LAST-ACK.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder) => {
                let new_close_wait = close_wait.incoming_ack_update(conn, seg);
                (Some(Self::close_wait_or_last_ack(conn, new_close_wait)?), false)
            }

            _ => Self::known_conn_common_fallback(seg, conn),
        })
    }

    /// Handles the reply decision and state updates for a CLOSING connection, returning a reply if
    /// necessary and a `bool` representing whether the connection should be removed.
    fn handle_closing(
        seg: &TcpSegment<Remote>,
        conn: &mut ConnState,
        closing: SyncedState<Closing>,
    ) -> (Option<Self>, bool) {
        let our_fin_acked = seg.ack_num == conn.snd_nxt;

        match (seg.flags, &seg.payload, SeqCheck::check(seg, conn), our_fin_acked) {
            // Simultaneous close, peer's ACK of our FIN arrives -> remove connection, no reply.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder, true) => (None, true),

            // Partial ACK not yet covering our FIN -> update send-side state like a plain ACK, keep
            // waiting in CLOSING for the ACK that covers it.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder, false) => {
                conn.tcp_state = TcpState::Closing(closing.incoming_ack_update(conn, seg));
                (None, false)
            }

            _ => Self::known_conn_common_fallback(seg, conn),
        }
    }

    /// Handles the reply decision and state updates for a LAST-ACK connection, returning a reply if
    /// necessary and a `bool` representing whether the connection should be removed.
    fn handle_last_ack(
        seg: &TcpSegment<Remote>,
        conn: &mut ConnState,
        last_ack: SyncedState<LastAck>,
    ) -> (Option<Self>, bool) {
        let our_fin_acked = seg.ack_num == conn.snd_nxt;

        match (seg.flags, &seg.payload, SeqCheck::check(seg, conn), our_fin_acked) {
            // Partial ACK not yet covering our FIN -> update send-side state like a plain ACK, keep
            // waiting in LAST-ACK for the real final ACK.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder, false) => {
                conn.tcp_state = TcpState::LastAck(last_ack.incoming_ack_update(conn, seg));
                (None, false)
            }

            // Final ACK completing passive close, fully acknowledging our FIN -> remove connection,
            // no reply.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder, true) => (None, true),

            _ => Self::known_conn_common_fallback(seg, conn),
        }
    }
}
