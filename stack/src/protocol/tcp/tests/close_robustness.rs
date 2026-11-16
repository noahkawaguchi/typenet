use {super::*, pretty_assertions::assert_eq};

/// Four of the states that are in the process of terminating after we've sent our FIN: FIN-WAIT-1,
/// FIN-WAIT-2, CLOSING, and LAST-ACK. All have the window state right after the initial three-way
/// handshake.
const STATES_AFTER_SENDING_FIN: [TcpState; 4] = [
    TcpState::FinWait1(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE, FinWait1)),
    TcpState::FinWait2(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE, FinWait2)),
    TcpState::Closing(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE, Closing)),
    TcpState::LastAck(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE, LastAck)),
];

/// Constructors for CLOSING and LAST-ACK (the states after sending our FIN where the peer's FIN has
/// also been received) with a given window state, for tests that need to build the same state both
/// before and after a window update.
const PEER_FIN_RECEIVED_STATES: [fn(WindowState) -> TcpState; 2] = [
    |window| TcpState::Closing(SyncedState::test_new(window, Closing)),
    |window| TcpState::LastAck(SyncedState::test_new(window, LastAck)),
];

/// Flag, payload, and offset from RCV.NXT combinations for segments carrying data and/or a FIN,
/// both in order and out of order, where an empty string means no payload.
const DATA_OR_FIN_AFTER_PEERS_FIN: [(TcpFlags, &str, SeqOffset<u32, In>); 5] = [
    (TcpFlags::Ack, "Hi", SeqOffset::new(0)),
    (TcpFlags::Ack, "Hi", HELLO_LEN_IN),
    (TcpFlags::FinAck, "", SeqOffset::new(0)),
    (TcpFlags::FinAck, "Hi", SeqOffset::new(0)),
    (TcpFlags::FinAck, "Hi", HELLO_LEN_IN),
];

/// Flag and payload combinations for out-of-order segments that carry data and/or a FIN, where an
/// empty string means no payload.
const OUT_OF_ORDER_DATA_OR_FIN: [(TcpFlags, &str); 3] =
    [(TcpFlags::Ack, "Hi"), (TcpFlags::FinAck, ""), (TcpFlags::FinAck, "Hi")];

#[test]
fn partial_ack_after_sending_our_fin_does_not_close_or_reset() -> TraceableResult {
    // In any of the states after sending our FIN, our own FIN can be acked separately from data
    // sent alongside it (e.g. the peer acks previously buffered chunks before finally acking the
    // byte that covers the FIN). Regardless of which of those states the connection is in, an ACK
    // that doesn't yet reach SND.NXT (i.e., doesn't yet cover the FIN) must not be treated as the
    // final ACK completing the close or get a RST.

    for tcp_state in STATES_AFTER_SENDING_FIN {
        let mut connections = TcpConnections::default();

        // SND.NXT includes our own already-sent FIN, one past SND.UNA
        let initial_state = ConnState {
            tcp_state: tcp_state.clone(),
            data: ConnData {
                snd_nxt: AFTER_HANDSHAKE.data.snd_nxt + FIN_BYTE_OUT,
                ..AFTER_HANDSHAKE.data
            },
        };

        connections.test_insert(initial_state.clone());

        // SEG.ACK == SND.UNA, not yet SND.NXT, so this doesn't cover our FIN
        let partial_ack = TcpSegment {
            seq_num: CLIENT_ISN + SYN_BYTE_IN,
            ack_num: SERVER_ISN + SYN_BYTE_OUT,
            ..CLIENT_PKT
        };

        assert_eq!(
            partial_ack.create_test_reply(&mut connections)?,
            None,
            "A partial ACK not yet covering our FIN should get no reply (in state {tcp_state:?})"
        );

        assert_eq!(
            connections.try_get()?,
            &initial_state,
            "The connection should remain in the same state, not be closed or reset (in state \
             {tcp_state:?})"
        );
    }

    Ok(())
}

#[test]
fn stale_retransmission_after_sending_our_fin_gets_duplicate_ack() -> TraceableResult {
    // A retransmission of data the server already fully processed can arrive in any of the states
    // after we've sent our FIN. Regardless of which of those states the connection is in, this
    // should get a duplicate ACK reflecting the current state, with the connection otherwise left
    // untouched, just like in ESTABLISHED.

    for tcp_state in STATES_AFTER_SENDING_FIN {
        let mut connections = TcpConnections::default();
        let initial_state = ConnState { tcp_state: tcp_state.clone(), ..AFTER_HANDSHAKE };
        connections.test_insert(initial_state.clone());

        // Carries a sequence number from before RCV.NXT, i.e. data already fully processed
        let stale_retransmission = TcpSegment {
            seq_num: CLIENT_ISN,
            ack_num: SERVER_ISN + SYN_BYTE_OUT,
            payload: TcpPayload::from_test_str("stale")?,
            ..CLIENT_PKT
        };

        assert_eq!(
            stale_retransmission.create_test_reply(&mut connections)?,
            Some(TcpSegment {
                seq_num: SERVER_ISN + SYN_BYTE_OUT,
                ack_num: CLIENT_ISN + SYN_BYTE_IN,
                ..SERVER_REPLY
            }),
            "A stale retransmission should get a duplicate ACK, not a RST (in state {tcp_state:?})"
        );

        assert_eq!(
            connections.try_get()?,
            &initial_state,
            "The connection should be untouched, not reset (in state {tcp_state:?})"
        );
    }

    Ok(())
}

#[test]
fn stale_retransmission_in_close_wait_gets_duplicate_ack_not_rst() -> TraceableResult {
    // A retransmission of data already fully processed can still arrive while a connection is in
    // CLOSE-WAIT, waiting to drain the rest of its queued data before it can send its own FIN.
    // This should get a duplicate ACK reflecting the current state, leaving the connection and its
    // queued data untouched, not a RST.

    let mut connections = TcpConnections::default();
    let initial_state = ConnState {
        tcp_state: TcpState::CloseWait(SyncedState::test_new(
            WINDOW_AFTER_HANDSHAKE,
            CloseWait::test_new(*b"leftover"),
        )),
        ..AFTER_HANDSHAKE
    };
    connections.test_insert(initial_state.clone());

    let stale_retransmission = TcpSegment {
        seq_num: CLIENT_ISN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        payload: TcpPayload::from_test_str("stale")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        stale_retransmission.create_test_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN,
            ..SERVER_REPLY
        }),
        "A stale retransmission should get a duplicate ACK, not a RST"
    );

    assert_eq!(connections.try_get()?, &initial_state, "The connection should be untouched");

    Ok(())
}

#[test]
fn stale_pure_ack_after_sending_our_fin_gets_duplicate_ack() -> TraceableResult {
    // A pure ACK whose SEG.SEQ fails the sequence acceptability check can arrive in any of the
    // states after we've sent our FIN. It must be dropped and get a current state reply, not get a
    // RST or advance the connection's close progress.

    for tcp_state in STATES_AFTER_SENDING_FIN {
        let mut connections = TcpConnections::default();
        let initial_state = ConnState { tcp_state: tcp_state.clone(), ..AFTER_HANDSHAKE };
        connections.test_insert(initial_state.clone());

        // Carries a sequence number from before RCV.NXT, and a distinctive window that must not get
        // adopted
        let stale_pure_ack = TcpSegment {
            seq_num: CLIENT_ISN,
            ack_num: SERVER_ISN + SYN_BYTE_OUT,
            window: SeqOffset::new(1234),
            ..CLIENT_PKT
        };

        assert_eq!(
            stale_pure_ack.create_test_reply(&mut connections)?,
            Some(TcpSegment {
                seq_num: SERVER_ISN + SYN_BYTE_OUT,
                ack_num: CLIENT_ISN + SYN_BYTE_IN,
                ..SERVER_REPLY
            }),
            "A stale pure ACK should get a duplicate ACK, not a RST (in state {tcp_state:?})"
        );

        assert_eq!(
            connections.try_get()?,
            &initial_state,
            "The connection should be untouched, not reset (in state {tcp_state:?})"
        );
    }

    Ok(())
}

#[test]
fn stale_pure_ack_in_close_wait_gets_duplicate_ack() -> TraceableResult {
    // A pure ACK whose sequence number falls before what's already been received can arrive while a
    // connection is in CLOSE-WAIT, waiting to drain its queued data before sending its own FIN.
    // It must be dropped and get a current-state reply, not accepted or allowed to disturb the
    // connection's progress toward closing.

    let mut connections = TcpConnections::default();
    let initial_state = ConnState {
        tcp_state: TcpState::CloseWait(SyncedState::test_new(
            WINDOW_AFTER_HANDSHAKE,
            CloseWait::test_new(*b"leftover"),
        )),
        ..AFTER_HANDSHAKE
    };
    connections.test_insert(initial_state.clone());

    // Carries a sequence number from before RCV.NXT, and a distinctive window that must not get
    // adopted
    let stale_pure_ack = TcpSegment {
        seq_num: CLIENT_ISN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        window: SeqOffset::new(1234),
        ..CLIENT_PKT
    };

    assert_eq!(
        stale_pure_ack.create_test_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN,
            ..SERVER_REPLY
        }),
        "A stale pure ACK should get a duplicate ACK, not a RST"
    );

    assert_eq!(connections.try_get()?, &initial_state, "The connection should be untouched");

    Ok(())
}

#[test]
fn out_of_order_data_or_fin_in_fin_wait_gets_duplicate_ack() -> TraceableResult {
    // While in FIN-WAIT-1 or FIN-WAIT-2, the peer may still be sending, so a reordered segment
    // carrying data and/or its FIN can arrive ahead of earlier data and in the window. Since these
    // states have no reassembly buffer, it should get a duplicate ACK at the unchanged RCV.NXT,
    // without its data being accepted or its FIN starting the close. The in-order retransmission of
    // the missing data must then still be accepted normally, proving the connection was not
    // disturbed.

    /// Constructors for FIN-WAIT-1 and FIN-WAIT-2 with a given window state, for building the same
    /// state both before and after a window update.
    const FIN_WAIT_STATES: [fn(WindowState) -> TcpState; 2] = [
        |window| TcpState::FinWait1(SyncedState::test_new(window, FinWait1)),
        |window| TcpState::FinWait2(SyncedState::test_new(window, FinWait2)),
    ];

    for make_state in FIN_WAIT_STATES {
        for (flags, payload_str) in OUT_OF_ORDER_DATA_OR_FIN {
            let mut connections = TcpConnections::default();

            // SND.NXT includes our own already-sent FIN, one past SND.UNA
            let mut expected_state = ConnState {
                tcp_state: make_state(WINDOW_AFTER_HANDSHAKE),
                data: ConnData {
                    snd_nxt: AFTER_HANDSHAKE.data.snd_nxt + FIN_BYTE_OUT,
                    ..AFTER_HANDSHAKE.data
                },
            };
            connections.test_insert(expected_state.clone());

            // Arrives 5 bytes ahead of RCV.NXT, as if "Hello" had been lost, and doesn't
            // acknowledge our FIN
            let out_of_order = TcpSegment {
                seq_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN,
                ack_num: SERVER_ISN + SYN_BYTE_OUT,
                flags,
                payload: TcpPayload::from_test_str(payload_str)?,
                ..CLIENT_PKT
            };

            assert_eq!(
                out_of_order.create_test_reply(&mut connections)?,
                Some(TcpSegment {
                    seq_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
                    ack_num: CLIENT_ISN + SYN_BYTE_IN,
                    ..SERVER_REPLY
                }),
                "An out-of-order segment should get a duplicate ACK at the unchanged RCV.NXT, not \
                 a RST (in state {:?}, flags {flags:?}, payload {payload_str:?})",
                expected_state.tcp_state,
            );

            // The ACK field is still processed, so the window state is updated, but RCV.NXT is not
            // advanced and the FIN (if any) is not acted on
            expected_state.tcp_state = make_state(WindowState::test_new(
                out_of_order.window,
                out_of_order.seq_num,
                out_of_order.ack_num,
            ));

            assert_eq!(
                connections.try_get()?,
                &expected_state,
                "The connection should stay in the same state with RCV.NXT unchanged (flags \
                 {flags:?}, payload {payload_str:?})"
            );

            // The missing "Hello" finally arrives in order
            let gap_filler = TcpSegment {
                seq_num: CLIENT_ISN + SYN_BYTE_IN,
                ack_num: SERVER_ISN + SYN_BYTE_OUT,
                payload: TcpPayload::from_test_str("Hello")?,
                ..CLIENT_PKT
            };

            assert_eq!(
                gap_filler.create_test_reply(&mut connections)?,
                Some(TcpSegment {
                    seq_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
                    ack_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN,
                    ..SERVER_REPLY
                }),
                "The in-order retransmission should be ACKed normally, covering only itself since \
                 the out-of-order segment was dropped (flags {flags:?}, payload {payload_str:?})"
            );

            // The window state stays pinned to the out-of-order segment's values, since "Hello" has
            // an earlier SEG.SEQ
            expected_state.data.rcv_nxt += HELLO_LEN_IN;

            assert_eq!(
                connections.try_get()?,
                &expected_state,
                "The connection should still be in the same state, not closing (flags {flags:?}, \
                 payload {payload_str:?})"
            );
        }
    }

    Ok(())
}

#[test]
fn out_of_order_data_or_fin_acking_our_fin_moves_fin_wait_1_to_fin_wait_2() -> TraceableResult {
    // The ACK field of an acceptable segment is processed even if its text can't be yet (RFC 9293,
    // Section 3.10.7.4, "Fifth, check the ACK field"). In FIN-WAIT-1, that includes entering
    // FIN-WAIT-2 if our FIN is now acknowledged, while the out-of-order text itself still only gets
    // a duplicate ACK.

    for (flags, payload_str) in OUT_OF_ORDER_DATA_OR_FIN {
        let mut connections = TcpConnections::default();

        // SND.NXT includes our own already-sent FIN, one past SND.UNA
        let mut expected_state = ConnState {
            tcp_state: TcpState::FinWait1(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE, FinWait1)),
            data: ConnData {
                snd_nxt: AFTER_HANDSHAKE.data.snd_nxt + FIN_BYTE_OUT,
                ..AFTER_HANDSHAKE.data
            },
        };
        connections.test_insert(expected_state.clone());

        // Arrives 5 bytes ahead of RCV.NXT and acknowledges our FIN
        let out_of_order = TcpSegment {
            seq_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN,
            ack_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
            flags,
            payload: TcpPayload::from_test_str(payload_str)?,
            ..CLIENT_PKT
        };

        assert_eq!(
            out_of_order.create_test_reply(&mut connections)?,
            Some(TcpSegment {
                seq_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
                ack_num: CLIENT_ISN + SYN_BYTE_IN,
                ..SERVER_REPLY
            }),
            "An out-of-order segment should get a duplicate ACK at the unchanged RCV.NXT, not a \
             RST (flags {flags:?}, payload {payload_str:?})"
        );

        expected_state.tcp_state = TcpState::FinWait2(SyncedState::test_new(
            WindowState::test_new(out_of_order.window, out_of_order.seq_num, out_of_order.ack_num),
            FinWait2,
        ));
        expected_state.data.snd_una += FIN_BYTE_OUT;

        assert_eq!(
            connections.try_get()?,
            &expected_state,
            "The ACK of our FIN should move the connection to FIN-WAIT-2, with RCV.NXT unchanged \
             (flags {flags:?}, payload {payload_str:?})"
        );
    }

    Ok(())
}

#[test]
fn data_or_fin_after_peers_fin_is_ignored() -> TraceableResult {
    // In CLOSING and LAST-ACK, the peer's FIN has already been received, so a segment carrying new
    // data or another FIN means a misbehaving peer. RFC 9293, Section 3.10.7.4 says to ignore the
    // segment text ("Seventh, process the segment text") and remain in the same state ("Eighth,
    // check the FIN bit"), not to send a RST. The ACK field is still processed ("Fifth, check the
    // ACK field"), here not yet covering our FIN.

    for make_state in PEER_FIN_RECEIVED_STATES {
        for (flags, payload_str, offset) in DATA_OR_FIN_AFTER_PEERS_FIN {
            let mut connections = TcpConnections::default();

            // Both FINs have been sent, and SND.NXT is one past SND.UNA since ours is unacked
            let mut expected_state = ConnState {
                tcp_state: make_state(WINDOW_AFTER_HANDSHAKE),
                data: ConnData {
                    snd_nxt: AFTER_HANDSHAKE.data.snd_nxt + FIN_BYTE_OUT,
                    rcv_nxt: AFTER_HANDSHAKE.data.rcv_nxt + FIN_BYTE_IN,
                    ..AFTER_HANDSHAKE.data
                },
            };
            connections.test_insert(expected_state.clone());

            let after_peers_fin = TcpSegment {
                seq_num: CLIENT_ISN + SYN_BYTE_IN + FIN_BYTE_IN + offset,
                ack_num: SERVER_ISN + SYN_BYTE_OUT,
                flags,
                payload: TcpPayload::from_test_str(payload_str)?,
                ..CLIENT_PKT
            };

            assert_eq!(
                after_peers_fin.create_test_reply(&mut connections)?,
                None,
                "Data or a FIN after the peer's FIN should be ignored, not get a RST (in state \
                 {:?}, flags {flags:?}, payload {payload_str:?}, offset {offset:?})",
                expected_state.tcp_state,
            );

            // The ACK field is still processed, so the window state is updated, but RCV.NXT is not
            // advanced
            expected_state.tcp_state = make_state(WindowState::test_new(
                after_peers_fin.window,
                after_peers_fin.seq_num,
                after_peers_fin.ack_num,
            ));

            assert_eq!(
                connections.try_get()?,
                &expected_state,
                "The connection should stay in the same state with RCV.NXT unchanged (flags \
                 {flags:?}, payload {payload_str:?}, offset {offset:?})"
            );
        }
    }

    Ok(())
}

#[test]
fn data_or_fin_after_peers_fin_acking_our_fin_removes_connection() -> TraceableResult {
    // The ACK field of a segment carrying data or a FIN after the peer's own FIN is still processed
    // even though its text is ignored (RFC 9293, Section 3.10.7.4, "Fifth, check the ACK field"),
    // so if it acknowledges our FIN, it completes the close just like a pure ACK would.

    for make_state in PEER_FIN_RECEIVED_STATES {
        for (flags, payload_str, offset) in DATA_OR_FIN_AFTER_PEERS_FIN {
            let mut connections = TcpConnections::default();
            let initial_tcp_state = make_state(WINDOW_AFTER_HANDSHAKE);

            // Both FINs have been sent, and SND.NXT is one past SND.UNA since ours is unacked
            connections.test_insert(ConnState {
                tcp_state: initial_tcp_state.clone(),
                data: ConnData {
                    snd_nxt: AFTER_HANDSHAKE.data.snd_nxt + FIN_BYTE_OUT,
                    rcv_nxt: AFTER_HANDSHAKE.data.rcv_nxt + FIN_BYTE_IN,
                    ..AFTER_HANDSHAKE.data
                },
            });

            assert_eq!(
                TcpSegment {
                    seq_num: CLIENT_ISN + SYN_BYTE_IN + FIN_BYTE_IN + offset,
                    ack_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
                    flags,
                    payload: TcpPayload::from_test_str(payload_str)?,
                    ..CLIENT_PKT
                }
                .create_test_reply(&mut connections)?,
                None,
                "No reply expected, not a RST (in state {initial_tcp_state:?}, flags {flags:?}, \
                 payload {payload_str:?}, offset {offset:?})"
            );

            assert_matches!(
                connections.try_get(),
                Err(_),
                "The ACK of our FIN should remove the connection (in state {initial_tcp_state:?}, \
                 flags {flags:?}, payload {payload_str:?}, offset {offset:?})"
            );
        }
    }

    Ok(())
}

#[test]
fn data_or_fin_in_close_wait_is_ignored_with_duplicate_ack() -> TraceableResult {
    // In CLOSE-WAIT, the peer's FIN has already been received, so a segment carrying new data or
    // another FIN means a misbehaving peer. RFC 9293, Section 3.10.7.4 says to ignore the segment
    // text ("Seventh, process the segment text") and remain in CLOSE-WAIT ("Eighth, check the FIN
    // bit"), not to send a RST. The ACK field is still processed ("Fifth, check the ACK field"),
    // here advertising a zero window, so none of the queued data can be sent and the reply is a
    // pure ACK at the unchanged RCV.NXT.

    for (flags, payload_str, offset) in DATA_OR_FIN_AFTER_PEERS_FIN {
        let mut connections = TcpConnections::default();

        // The peer's FIN has been received, and ours hasn't been sent yet
        let mut expected_state = ConnState {
            tcp_state: TcpState::CloseWait(SyncedState::test_new(
                WINDOW_AFTER_HANDSHAKE,
                CloseWait::test_new(*b"leftover"),
            )),
            data: ConnData {
                rcv_nxt: AFTER_HANDSHAKE.data.rcv_nxt + FIN_BYTE_IN,
                ..AFTER_HANDSHAKE.data
            },
        };
        connections.test_insert(expected_state.clone());

        let after_peers_fin = TcpSegment {
            seq_num: CLIENT_ISN + SYN_BYTE_IN + FIN_BYTE_IN + offset,
            ack_num: SERVER_ISN + SYN_BYTE_OUT,
            window: SeqOffset::new(0),
            flags,
            payload: TcpPayload::from_test_str(payload_str)?,
            ..CLIENT_PKT
        };

        assert_eq!(
            after_peers_fin.create_test_reply(&mut connections)?,
            Some(TcpSegment {
                seq_num: SERVER_ISN + SYN_BYTE_OUT,
                ack_num: CLIENT_ISN + SYN_BYTE_IN + FIN_BYTE_IN,
                ..SERVER_REPLY
            }),
            "Data or a FIN after the peer's FIN should get a pure ACK at the unchanged RCV.NXT, \
             not a RST (flags {flags:?}, payload {payload_str:?}, offset {offset:?})"
        );

        // The ACK field is still processed, so the window state is updated, but RCV.NXT is not
        // advanced and the queued data stays queued
        expected_state.tcp_state = TcpState::CloseWait(SyncedState::test_new(
            WindowState::test_new(
                after_peers_fin.window,
                after_peers_fin.seq_num,
                after_peers_fin.ack_num,
            ),
            CloseWait::test_new(*b"leftover"),
        ));

        assert_eq!(
            connections.try_get()?,
            &expected_state,
            "The connection should stay in CLOSE-WAIT with RCV.NXT and the send buffer unchanged \
             (flags {flags:?}, payload {payload_str:?}, offset {offset:?})"
        );
    }

    Ok(())
}

#[test]
fn data_or_fin_in_close_wait_opening_window_drains_and_sends_our_fin() -> TraceableResult {
    // The ACK field of a segment carrying data or a FIN after the peer's own FIN is still processed
    // even though its text is ignored (RFC 9293, Section 3.10.7.4, "Fifth, check the ACK field"),
    // so if it opens the window enough, CLOSE-WAIT drains the rest of its queued data and sends our
    // FIN with it, just like a pure ACK would.

    const LEFTOVER_LEN_OUT: SeqOffset<u32, Out> = SeqOffset::new(8);

    for (flags, payload_str, offset) in DATA_OR_FIN_AFTER_PEERS_FIN {
        let mut connections = TcpConnections::default();

        // The peer's FIN has been received, and ours hasn't been sent yet
        let mut expected_state = ConnState {
            tcp_state: TcpState::CloseWait(SyncedState::test_new(
                WINDOW_AFTER_HANDSHAKE,
                CloseWait::test_new(*b"leftover"),
            )),
            data: ConnData {
                rcv_nxt: AFTER_HANDSHAKE.data.rcv_nxt + FIN_BYTE_IN,
                ..AFTER_HANDSHAKE.data
            },
        };
        connections.test_insert(expected_state.clone());

        // Advertises the maximum window, enough for all the queued data
        let after_peers_fin = TcpSegment {
            seq_num: CLIENT_ISN + SYN_BYTE_IN + FIN_BYTE_IN + offset,
            ack_num: SERVER_ISN + SYN_BYTE_OUT,
            flags,
            payload: TcpPayload::from_test_str(payload_str)?,
            ..CLIENT_PKT
        };

        assert_eq!(
            after_peers_fin.create_test_reply(&mut connections)?,
            Some(TcpSegment {
                seq_num: SERVER_ISN + SYN_BYTE_OUT,
                ack_num: CLIENT_ISN + SYN_BYTE_IN + FIN_BYTE_IN,
                flags: TcpFlags::FinAck,
                payload: TcpPayload::from_test_str("leftover")?,
                ..SERVER_REPLY
            }),
            "The queued data should go out with our FIN, ACKing the unchanged RCV.NXT, not a RST \
             (flags {flags:?}, payload {payload_str:?}, offset {offset:?})"
        );

        expected_state.tcp_state = TcpState::LastAck(SyncedState::test_new(
            WindowState::test_new(
                after_peers_fin.window,
                after_peers_fin.seq_num,
                after_peers_fin.ack_num,
            ),
            LastAck,
        ));
        expected_state.data.snd_nxt += LEFTOVER_LEN_OUT + FIN_BYTE_OUT;

        assert_eq!(
            connections.try_get()?,
            &expected_state,
            "The connection should move to LAST-ACK with RCV.NXT unchanged (flags {flags:?}, \
             payload {payload_str:?}, offset {offset:?})"
        );
    }

    Ok(())
}
