use {
    crate::{
        application::Application,
        direction::{In, Out},
        protocol::tcp::{
            FIN_BYTE_IN, FIN_BYTE_OUT, SYN_BYTE_IN, SYN_BYTE_OUT, TcpSegment,
            connections::{ConnKey, TcpConnections},
            flags::TcpFlags,
            payload::{LenOrDefault as _, TcpPayload},
            pending_segment::PendingSegment,
            seq_space::SeqPoint,
            state::{
                CloseWait, Closing, ConnData, ConnState, Established, FinWait1, FinWait2, LastAck,
                SynReceived, SyncedState, TcpState,
            },
        },
    },
    std::time::Instant,
    typenet_utils::{error::TraceableResult, sys},
};

/// Comprises fields that differ when determining a segment to send and handles core reply logic.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct SendInfo {
    pub(super) seq_num: SeqPoint<Out>,
    pub(super) ack_num: SeqPoint<In>,
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
    fn check(seg: &TcpSegment<In>, conn: &ConnData) -> Self {
        if seg.seq_num == conn.rcv_nxt {
            Self::InOrder
        } else if seg
            .seq_num
            .in_window(conn.rcv_nxt, TcpSegment::<Out>::RCV_WND.into())
        {
            Self::OutOfOrder
        } else {
            Self::Unacceptable
        }
    }
}

impl SendInfo {
    /// Creates a pure ACK `Self` with SEG.SEQ=SND.NXT and SEG.ACK=RCV.NXT.
    const fn pure_ack(conn: &ConnData) -> Self {
        Self { seq_num: conn.snd_nxt, ack_num: conn.rcv_nxt, flags: TcpFlags::Ack, payload: None }
    }

    /// Creates a RST with its SEG.SEQ set to `seg.ack_num`.
    const fn rst(seg: &TcpSegment<In>) -> Self {
        Self {
            seq_num: seg.ack_num,
            // ack_num is 0 because sending bare RST with no ACK flag leaves SEG.ACK undefined
            ack_num: SeqPoint::new(0),
            flags: TcpFlags::Rst,
            payload: None,
        }
    }

    /// Creates a `Self` for replying to `seg` according to `app`, or returns `Ok(None)` for no
    /// reply, updating `connections` accordingly. If handling a known connection fails, the
    /// connection is dropped (not reinserted into `connections`) rather than kept in a possibly
    /// inconsistent state, so the peer's next segment is answered with RST.
    pub(super) fn decide_reply(
        app: &mut impl Application,
        seg: &TcpSegment<In>,
        connections: &mut TcpConnections,
    ) -> TraceableResult<Option<Self>> {
        let key = ConnKey {
            client_ip: seg.ip_pair.src,
            client_port: seg.ports.src,
            server_ip: seg.ip_pair.dst,
            server_port: seg.ports.dst,
        };

        if let Some(ConnState { tcp_state, mut data }) = connections.remove(&key) {
            Self::handle_known_conn(app, seg, &mut data, tcp_state).map(
                |(maybe_send_info, maybe_next_state)| {
                    if let Some(next_state) = maybe_next_state {
                        connections.insert(key, ConnState { tcp_state: next_state, data });
                    }
                    maybe_send_info
                },
            )
        } else {
            Self::handle_unknown_conn(seg, connections, key)
        }
    }

    fn handle_unknown_conn(
        seg: &TcpSegment<In>,
        connections: &mut TcpConnections,
        key: ConnKey,
    ) -> TraceableResult<Option<Self>> {
        Ok(match seg.flags {
            // SYN (step 1 of handshake) -> store new connection, reply with SYN-ACK (step 2).
            TcpFlags::Syn => {
                let send_info = Self {
                    seq_num: SeqPoint::new(sys::random_u32()?),
                    ack_num: seg.seq_num + SYN_BYTE_IN,
                    flags: TcpFlags::SynAck,
                    payload: None,
                };

                connections.insert(
                    key,
                    ConnState {
                        tcp_state: TcpState::SynReceived(SynReceived),
                        data: ConnData {
                            // SYN-ACK consumes one sequence number
                            snd_nxt: send_info.seq_num + SYN_BYTE_OUT,
                            // Our SYN-ACK's `ack_num` is the client's ISN + 1
                            rcv_nxt: send_info.ack_num,
                            // Our SYN-ACK is unacknowledged (this is our ISN)
                            snd_una: send_info.seq_num,
                            pending: vec![PendingSegment::new(send_info.clone(), Instant::now())],
                        },
                    },
                );

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

    /// Handles the reply decision and state updates for a known connection, returning a reply if
    /// necessary and the next TCP state, or `None` if the connection should be removed.
    fn handle_known_conn(
        app: &mut impl Application,
        seg: &TcpSegment<In>,
        conn: &mut ConnData,
        tcp_state: TcpState,
    ) -> TraceableResult<(Option<Self>, Option<TcpState>)> {
        Ok(match tcp_state {
            TcpState::SynReceived(syn_received) => {
                Self::handle_syn_rcv(app, seg, conn, syn_received)?
            }
            TcpState::Established(established) => {
                Self::handle_established(app, seg, conn, established)?
            }
            TcpState::FinWait1(fin_wait_1) => Self::handle_fin_wait_1(seg, conn, fin_wait_1),
            TcpState::FinWait2(fin_wait_2) => Self::handle_fin_wait_2(seg, conn, fin_wait_2),
            TcpState::CloseWait(close_wait) => Self::handle_close_wait(seg, conn, close_wait)?,
            TcpState::Closing(closing) => Self::handle_closing(seg, conn, closing),
            TcpState::LastAck(last_ack) => Self::handle_last_ack(seg, conn, last_ack),
        })
    }

    /// Common fallback cases among known connections, returning a reply if necessary and the next
    /// TCP state, or `None` if the connection should be removed.
    #[expect(clippy::match_same_arms, reason = "Clearly express various challenge ACK scenarios")]
    fn known_conn_common_fallback(
        seg: &TcpSegment<In>,
        conn: &ConnData,
        tcp_state: TcpState,
    ) -> (Option<Self>, Option<TcpState>) {
        macro_rules! challenge_ack {
            () => {
                (Some(Self::pure_ack(conn)), Some(tcp_state))
            };
        }

        match (seg.flags, SeqCheck::check(seg, conn)) {
            // RST on a known connection -> RFC 9293, Section 3.10.7.4 has three cases for when
            // the RST bit is set, protecting against a blind reset attack (as described in RFC
            // 5961, Section 3):

            // Case 1: SEG.SEQ outside window -> silently drop segment
            (TcpFlags::Rst | TcpFlags::RstAck, SeqCheck::Unacceptable) => (None, Some(tcp_state)),
            // Case 2: SEG.SEQ == RCV.NXT -> reset connection, no reply
            (TcpFlags::Rst | TcpFlags::RstAck, SeqCheck::InOrder) => (None, None),
            // Case 3: SEG.SEQ in window but != RCV.NXT -> don't reset, send challenge ACK
            (TcpFlags::Rst | TcpFlags::RstAck, SeqCheck::OutOfOrder) => challenge_ack!(),

            // Non-RST with unacceptable SEG.SEQ -> current state ACK.
            (
                TcpFlags::Syn | TcpFlags::SynAck | TcpFlags::Ack | TcpFlags::FinAck,
                SeqCheck::Unacceptable,
            ) => challenge_ack!(),

            // Stray SYN/SYN-ACK on a synchronized connection -> send a challenge ACK, do not reset
            // the connection (RFC 9293, Section 3.10.7.4, "Fourth, check the SYN bit").
            (TcpFlags::Syn | TcpFlags::SynAck, _)
                if !matches!(tcp_state, TcpState::SynReceived(_)) =>
            {
                challenge_ack!()
            }

            // Non-RST with acceptable SEG.SEQ refused at every previous point (rare) -> RST.
            (
                TcpFlags::Syn | TcpFlags::SynAck | TcpFlags::Ack | TcpFlags::FinAck,
                SeqCheck::InOrder | SeqCheck::OutOfOrder,
            ) => (Some(Self::rst(seg)), Some(tcp_state)),
        }
    }

    /// Handles the reply decision and state updates for a SYN-RECEIVED connection, returning a
    /// reply if necessary and the next TCP state, or `None` if the connection should be removed.
    fn handle_syn_rcv(
        app: &mut impl Application,
        seg: &TcpSegment<In>,
        conn: &mut ConnData,
        syn_received: SynReceived,
    ) -> TraceableResult<(Option<Self>, Option<TcpState>)> {
        let acceptable_ack =
            conn.snd_una.precedes(seg.ack_num) && seg.ack_num.precedes_or_eq(conn.snd_nxt);

        Ok(match (seg.flags, &seg.payload, SeqCheck::check(seg, conn), acceptable_ack) {
            // Duplicate SYN while awaiting the handshake ACK (client's retransmission timer resent
            // the SYN) -> resend the same SYN-ACK (which was likely lost) using the already-stored
            // ISN.
            (TcpFlags::Syn, ..) => {
                let send_info = Self {
                    seq_num: conn.snd_una, // ISN
                    ack_num: seg.seq_num + SYN_BYTE_IN,
                    flags: TcpFlags::SynAck,
                    payload: None,
                };

                conn.pending
                    .push(PendingSegment::new(send_info.clone(), Instant::now()));

                (Some(send_info), Some(TcpState::SynReceived(syn_received)))
            }

            // Acceptable handshake-completing ACK (step 3), arriving in order -> transition to
            // ESTABLISHED, delivering any payload to the application, sending back whatever it
            // responds with (if the peer's window allows). Nothing can have been buffered for
            // reassembly yet, since out-of-order data is only accepted after the handshake
            // completes.
            (TcpFlags::Ack, maybe_payload, SeqCheck::InOrder, true) => {
                let mut established = Self::complete_handshake(seg, conn, syn_received);

                if let Some(payload) = maybe_payload {
                    conn.rcv_nxt += payload.len().into();
                    app.handle_tcp(payload.as_bytes(), established.send_buf_mut());
                }

                if established.has_unsent_data() {
                    (
                        Some(match established.drain_transmittable(conn)? {
                            Some(to_send) => Self::data_payload(conn, to_send),
                            None => Self::pure_ack(conn),
                        }),
                        Some(TcpState::Established(established)),
                    )
                } else {
                    (None, Some(TcpState::Established(established)))
                }
            }

            // Acceptable handshake-completing FIN-ACK (step 3 combined with the peer's own close),
            // arriving in order -> complete the handshake, transitioning to ESTABLISHED (RFC 9293,
            // Section 3.10.7.4, "Fifth, check the ACK field"), then immediately start closing
            // ("Eighth, check the FIN bit"), skipping CLOSE-WAIT under the current simplification,
            // the same as a FIN-ACK arriving on an ESTABLISHED connection. Also deliver as much
            // trailing data as possible to the application, if any.
            (TcpFlags::FinAck, maybe_payload, SeqCheck::InOrder, true) => {
                let established = Self::complete_handshake(seg, conn, syn_received);
                let (send_info, next_state) = Self::close_on_in_order_fin(
                    app,
                    seg,
                    conn,
                    maybe_payload.as_ref(),
                    established,
                )?;
                (Some(send_info), Some(next_state))
            }

            // Acceptable handshake-completing ACK or FIN-ACK, arriving out of order but still
            // within the receive window, with valid SEG.ACK -> complete the handshake. Any payload
            // can't be delivered yet, since data before it is still missing, so buffer it for later
            // reassembly. Any FIN also can't be processed yet, so buffer its position.
            (TcpFlags::Ack | TcpFlags::FinAck, maybe_payload, SeqCheck::OutOfOrder, true) => {
                let mut established = Self::complete_handshake(seg, conn, syn_received);
                if let Some(payload) = maybe_payload {
                    established
                        .reassembly_mut()
                        .insert(seg.seq_num, payload.clone());
                }
                if seg.flags == TcpFlags::FinAck {
                    established
                        .reassembly_mut()
                        .mark_fin(seg.seq_num + maybe_payload.len_or_default());
                }
                (Some(Self::pure_ack(conn)), Some(TcpState::Established(established)))
            }

            _ => Self::known_conn_common_fallback(seg, conn, TcpState::SynReceived(syn_received)),
        })
    }

    /// Completes the initial three-way handshake, updating `conn` and returning the new ESTABLISHED
    /// state.
    fn complete_handshake(
        seg: &TcpSegment<In>,
        conn: &mut ConnData,
        syn_received: SynReceived,
    ) -> SyncedState<Established> {
        conn.snd_una = seg.ack_num;
        conn.pending.clear(); // Only the SYN-ACK just acknowledged could have been pending
        syn_received.establish(seg)
    }

    /// Handles the reply decision and state updates for an ESTABLISHED connection, returning a
    /// reply if necessary and the next TCP state, or `None` if the connection should be removed.
    fn handle_established(
        app: &mut impl Application,
        seg: &TcpSegment<In>,
        conn: &mut ConnData,
        established: SyncedState<Established>,
    ) -> TraceableResult<(Option<Self>, Option<TcpState>)> {
        Ok(match (seg.flags, &seg.payload, SeqCheck::check(seg, conn)) {
            // ACK acknowledging data the server has not yet sent (SEG.ACK > SND.NXT) -> drop the
            // segment and reply with an ACK reflecting current state (RFC 9293, Section 3.10.7.4,
            // "Fifth, check the ACK field").
            (TcpFlags::Ack, _, SeqCheck::InOrder | SeqCheck::OutOfOrder)
                if conn.snd_nxt.precedes(seg.ack_num) =>
            {
                (Some(Self::pure_ack(conn)), Some(TcpState::Established(established)))
            }

            // Pure ACK (acknowledgment of data sent by the server) -> advance SND.UNA, then send
            // however much the window allows from the data queued to be sent, if any.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder) => {
                let mut new_established = established.incoming_ack_update(conn, seg);
                (
                    new_established
                        .drain_transmittable(conn)?
                        .map(|to_send| Self::data_payload(conn, to_send)),
                    Some(TcpState::Established(new_established)),
                )
            }

            // In-order data packet -> ACK receipt of data, advance RCV.NXT, and deliver any payload
            // and previously buffered out-of-order data that is now contiguous to the application,
            // sending back whatever it responds with (as much as fits in the peer's window).
            //
            // If the peer's previously buffered FIN has now been reached, enter LAST-ACK (passive
            // close) instead of continuing normally.
            (TcpFlags::Ack, Some(payload), SeqCheck::InOrder) => {
                let mut new_established = established.incoming_ack_update(conn, seg);

                conn.rcv_nxt += payload.len().into();
                app.handle_tcp(payload.as_bytes(), new_established.send_buf_mut());

                {
                    // Scope to ensure it isn't possible to access the split for longer than
                    // necessary
                    let (reassembly, send_buffer) = new_established.buffers_mut();
                    for reassembled in reassembly.drain_contiguous(&mut conn.rcv_nxt) {
                        app.handle_tcp(reassembled.as_bytes(), send_buffer);
                    }
                }

                if new_established.reassembly().fin_reached(conn.rcv_nxt) {
                    conn.rcv_nxt += FIN_BYTE_IN;
                    let (send_info, next_state) =
                        Self::close_wait_or_last_ack(conn, new_established.rcv_fin())?;
                    (Some(send_info), Some(next_state))
                } else {
                    (
                        Some(match new_established.drain_transmittable(conn)? {
                            Some(to_send) => Self::data_payload(conn, to_send),
                            None => Self::pure_ack(conn),
                        }),
                        Some(TcpState::Established(new_established)),
                    )
                }
            }

            // Out-of-order data still within the receive window -> buffer it for later reassembly,
            // replying with a duplicate ACK so the peer knows what's still missing.
            (TcpFlags::Ack, Some(payload), SeqCheck::OutOfOrder) => {
                let mut new_established = established.incoming_ack_update(conn, seg);
                new_established
                    .reassembly_mut()
                    .insert(seg.seq_num, payload.clone());
                (Some(Self::pure_ack(conn)), Some(TcpState::Established(new_established)))
            }

            // FIN-ACK (connection teardown), arriving in order -> deliver any trailing data to the
            // application (as much as the window allows, same as plain in-order data), then start
            // closing to wait for client's final ACK, replying with FIN-ACK. Unlike FIN-WAIT-1/2,
            // our own FIN hasn't gone out yet, so we can piggyback the application's response on
            // this same reply.
            (TcpFlags::FinAck, maybe_payload, SeqCheck::InOrder) => {
                let (send_info, next_state) = Self::close_on_in_order_fin(
                    app,
                    seg,
                    conn,
                    maybe_payload.as_ref(),
                    established,
                )?;
                (Some(send_info), Some(next_state))
            }

            // Out-of-order FIN-ACK still within the receive window -> buffer any trailing data and
            // remember the FIN's position for later reassembly, replying with a duplicate ACK, same
            // as out-of-order data-only segments.
            (TcpFlags::FinAck, maybe_payload, SeqCheck::OutOfOrder) => {
                let mut new_established = established.incoming_ack_update(conn, seg);
                if let Some(payload) = maybe_payload {
                    new_established
                        .reassembly_mut()
                        .insert(seg.seq_num, payload.clone());
                }
                new_established
                    .reassembly_mut()
                    .mark_fin(seg.seq_num + maybe_payload.len_or_default());
                (Some(Self::pure_ack(conn)), Some(TcpState::Established(new_established)))
            }

            _ => Self::known_conn_common_fallback(seg, conn, TcpState::Established(established)),
        })
    }

    /// Creates a `Self` for the payload `to_send`, advancing SND.NXT and recording the outgoing
    /// segment as pending.
    fn data_payload(conn: &mut ConnData, to_send: TcpPayload) -> Self {
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
    /// depending on whether all buffered data can be sent. Returns the reply and the next TCP
    /// state.
    fn close_on_in_order_fin(
        app: &mut impl Application,
        seg: &TcpSegment<In>,
        conn: &mut ConnData,
        maybe_payload: Option<&TcpPayload>,
        mut old_established: SyncedState<Established>,
    ) -> TraceableResult<(Self, TcpState)> {
        if let Some(payload) = maybe_payload {
            conn.rcv_nxt += payload.len().into();
            app.handle_tcp(payload.as_bytes(), old_established.send_buf_mut());
        }

        conn.rcv_nxt += FIN_BYTE_IN;

        let new_established = old_established.incoming_ack_update(conn, seg);
        Self::close_wait_or_last_ack(conn, new_established.rcv_fin())
    }

    /// Drains as much of the send buffer as the peer's window currently allows. If that empties
    /// the buffer, our own FIN is sent (piggybacked on any final chunk of data) and the next state
    /// is LAST-ACK. Otherwise, the drained chunk is sent as a plain data ACK, and the connection
    /// remains in CLOSE-WAIT, to be drained further once the peer sends more ACKs. Returns the
    /// reply and the next TCP state.
    fn close_wait_or_last_ack(
        conn: &mut ConnData,
        mut close_wait: SyncedState<CloseWait>,
    ) -> TraceableResult<(Self, TcpState)> {
        let to_send = close_wait.drain_transmittable(conn)?;

        Ok(if close_wait.has_unsent_data() {
            let send_info = match to_send {
                Some(payload) => Self::data_payload(conn, payload),
                None => Self::pure_ack(conn),
            };

            (send_info, TcpState::CloseWait(close_wait))
        } else {
            let send_len = to_send.len_or_default();

            let send_info = Self {
                seq_num: conn.snd_nxt,
                ack_num: conn.rcv_nxt,
                flags: TcpFlags::FinAck,
                payload: to_send,
            };

            conn.snd_nxt += send_len;
            conn.snd_nxt += FIN_BYTE_OUT;

            conn.pending
                .push(PendingSegment::new(send_info.clone(), Instant::now()));

            (send_info, TcpState::LastAck(close_wait.send_fin()))
        })
    }

    /// Handles the reply decision and state updates for a FIN-WAIT-1 connection, returning a reply
    /// if necessary and the next TCP state, or `None` if the connection should be removed.
    fn handle_fin_wait_1(
        seg: &TcpSegment<In>,
        conn: &mut ConnData,
        fin_wait_1: SyncedState<FinWait1>,
    ) -> (Option<Self>, Option<TcpState>) {
        let our_fin_acked = seg.ack_num == conn.snd_nxt;

        match (seg.flags, &seg.payload, SeqCheck::check(seg, conn), our_fin_acked) {
            // In-order data arriving after we've sent our own FIN but before the peer's FIN has
            // arrived (half closed) -> ACK it, don't deliver to the application because we have no
            // send side left to reply on, and advance RCV.NXT.
            (TcpFlags::Ack, Some(payload), SeqCheck::InOrder, _) => {
                conn.rcv_nxt += payload.len().into();
                (
                    Some(Self::pure_ack(conn)),
                    Some(TcpState::FinWait1(fin_wait_1.incoming_ack_update(conn, seg))),
                )
            }

            // Our FIN has been acknowledged (and nothing else) -> FIN-WAIT-2, no reply.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder, true) => (
                None,
                Some(TcpState::FinWait2(
                    fin_wait_1.incoming_ack_update(conn, seg).rcv_ack_of_fin(),
                )),
            ),

            // Partial ACK not yet covering our FIN -> update send-side state like a plain ACK, keep
            // waiting in FIN-WAIT-1 for the ACK that covers it.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder, false) => {
                (None, Some(TcpState::FinWait1(fin_wait_1.incoming_ack_update(conn, seg))))
            }

            // Peer's FIN arrives before ours is acknowledged (simultaneous close), and it also
            // acknowledges our FIN -> ACK it and remove the connection (skipping
            // FIN-WAIT-2/TIME-WAIT).
            //
            // Our own FIN has already been sent, so any trailing data isn't delivered to the
            // application because we have no send side left to reply on (same as plain data
            // arriving in FIN-WAIT-1), but RCV.NXT must still advance past it.
            (TcpFlags::FinAck, maybe_payload, SeqCheck::InOrder, true) => {
                conn.rcv_nxt += maybe_payload.len_or_default();
                conn.rcv_nxt += FIN_BYTE_IN;
                (Some(Self::pure_ack(conn)), None)
            }

            // Peer's FIN arrives before ours is acknowledged (simultaneous close), but it doesn't
            // acknowledge our FIN -> ACK it and move to CLOSING to await the ACK of our FIN.
            //
            // Our own FIN has already been sent, so any trailing data isn't delivered to the
            // application because we have no send side left to reply on (same as plain data
            // arriving in FIN-WAIT-1), but RCV.NXT must still advance past it.
            (TcpFlags::FinAck, maybe_payload, SeqCheck::InOrder, false) => {
                conn.rcv_nxt += maybe_payload.len_or_default();
                conn.rcv_nxt += FIN_BYTE_IN;
                (
                    Some(Self::pure_ack(conn)),
                    Some(TcpState::Closing(
                        fin_wait_1
                            .incoming_ack_update(conn, seg)
                            .rcv_fin_before_fin_is_acked(),
                    )),
                )
            }

            _ => Self::known_conn_common_fallback(seg, conn, TcpState::FinWait1(fin_wait_1)),
        }
    }

    /// Handles the reply decision and state updates for a FIN-WAIT-2 connection, returning a reply
    /// if necessary and the next TCP state, or `None` if the connection should be removed.
    fn handle_fin_wait_2(
        seg: &TcpSegment<In>,
        conn: &mut ConnData,
        fin_wait_2: SyncedState<FinWait2>,
    ) -> (Option<Self>, Option<TcpState>) {
        match (seg.flags, &seg.payload, SeqCheck::check(seg, conn)) {
            // In-order data arriving after we've sent our own FIN but before the peer's FIN has
            // arrived (half closed) -> ACK it, don't deliver to the application because we have no
            // send side left to reply on, and advance RCV.NXT.
            (TcpFlags::Ack, Some(payload), SeqCheck::InOrder) => {
                conn.rcv_nxt += payload.len().into();
                (
                    Some(Self::pure_ack(conn)),
                    Some(TcpState::FinWait2(fin_wait_2.incoming_ack_update(conn, seg))),
                )
            }

            // Plain ACK with nothing new (e.g. a window update) while waiting for the peer's FIN ->
            // update send-side state like a plain ACK, no reply.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder) => {
                (None, Some(TcpState::FinWait2(fin_wait_2.incoming_ack_update(conn, seg))))
            }

            // Peer's FIN arrives in order -> ACK it and finish closing (no TIME-WAIT). Our own FIN
            // has already been sent, so any trailing data isn't delivered to the application
            // because we have no send side left to reply on, but the ACK must still
            // reflect RCV.NXT advanced past it as well as the FIN.
            (TcpFlags::FinAck, maybe_payload, SeqCheck::InOrder) => {
                conn.rcv_nxt += maybe_payload.len_or_default();
                conn.rcv_nxt += FIN_BYTE_IN;
                (Some(Self::pure_ack(conn)), None)
            }

            _ => Self::known_conn_common_fallback(seg, conn, TcpState::FinWait2(fin_wait_2)),
        }
    }

    /// Handles the reply decision and state updates for a CLOSE-WAIT connection, returning a reply
    /// if necessary and the next TCP state, or `None` if the connection should be removed.
    fn handle_close_wait(
        seg: &TcpSegment<In>,
        conn: &mut ConnData,
        close_wait: SyncedState<CloseWait>,
    ) -> TraceableResult<(Option<Self>, Option<TcpState>)> {
        Ok(match (seg.flags, &seg.payload, SeqCheck::check(seg, conn)) {
            // ACK of previously sent data (or a window update) while still draining the send buffer
            // -> update send-side state, then try to send more and/or proceed to LAST-ACK.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder) => {
                let new_close_wait = close_wait.incoming_ack_update(conn, seg);
                let (send_info, next_state) = Self::close_wait_or_last_ack(conn, new_close_wait)?;
                (Some(send_info), Some(next_state))
            }

            _ => Self::known_conn_common_fallback(seg, conn, TcpState::CloseWait(close_wait)),
        })
    }

    /// Handles the reply decision and state updates for a CLOSING connection, returning a reply if
    /// necessary and the next TCP state, or `None` if the connection should be removed.
    fn handle_closing(
        seg: &TcpSegment<In>,
        conn: &mut ConnData,
        closing: SyncedState<Closing>,
    ) -> (Option<Self>, Option<TcpState>) {
        let our_fin_acked = seg.ack_num == conn.snd_nxt;

        match (seg.flags, &seg.payload, SeqCheck::check(seg, conn), our_fin_acked) {
            // Simultaneous close, peer's ACK of our FIN arrives -> remove connection, no reply.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder, true) => (None, None),

            // Partial ACK not yet covering our FIN -> update send-side state like a plain ACK, keep
            // waiting in CLOSING for the ACK that covers it.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder, false) => {
                (None, Some(TcpState::Closing(closing.incoming_ack_update(conn, seg))))
            }

            _ => Self::known_conn_common_fallback(seg, conn, TcpState::Closing(closing)),
        }
    }

    /// Handles the reply decision and state updates for a LAST-ACK connection, returning a reply if
    /// necessary and the next TCP state, or `None` if the connection should be removed.
    fn handle_last_ack(
        seg: &TcpSegment<In>,
        conn: &mut ConnData,
        last_ack: SyncedState<LastAck>,
    ) -> (Option<Self>, Option<TcpState>) {
        let our_fin_acked = seg.ack_num == conn.snd_nxt;

        match (seg.flags, &seg.payload, SeqCheck::check(seg, conn), our_fin_acked) {
            // Partial ACK not yet covering our FIN -> update send-side state like a plain ACK, keep
            // waiting in LAST-ACK for the real final ACK.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder, false) => {
                (None, Some(TcpState::LastAck(last_ack.incoming_ack_update(conn, seg))))
            }

            // Final ACK completing passive close, fully acknowledging our FIN -> remove connection,
            // no reply.
            (TcpFlags::Ack, None, SeqCheck::InOrder | SeqCheck::OutOfOrder, true) => (None, None),

            _ => Self::known_conn_common_fallback(seg, conn, TcpState::LastAck(last_ack)),
        }
    }
}
