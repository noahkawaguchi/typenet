use {super::*, pretty_assertions::assert_eq};

/// Four of the states that are in the process of terminating after we've sent our FIN: FIN-WAIT-1,
/// FIN-WAIT-2, CLOSING, and LAST-ACK. All have the window state right after the initial three-way
/// handshake.
const STATES_AFTER_SENDING_FIN: [TcpState; 4] = [
    TcpState::FinWait1(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE)),
    TcpState::FinWait2(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE)),
    TcpState::Closing(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE)),
    TcpState::LastAck(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE)),
];

#[test]
fn fin_ack_in_syn_received_establishes_and_closes_immediately() -> TraceableResult {
    // A FIN-ACK arriving in SYN-RECEIVED can legitimately complete the handshake and initiate
    // passive close in the same segment. RFC 9293, Section 3.10.7.4 processes "Fifth, check the ACK
    // field" (in SYN-RECEIVED completing the handshake) before "Eighth, check the FIN bit", so this
    // must establish the connection and then immediately start closing, skipping CLOSE-WAIT due to
    // the current simplification the same way a FIN-ACK in ESTABLISHED does.

    let mut connections = TcpConnections::default().with_syn_rcv();
    let mut cloned_state = connections.try_get()?.clone();

    let client_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    assert_eq!(
        client_fin_ack.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_FIN_BYTE,
            flags: TcpFlags::FinAck,
            ..SERVER_REPLY
        }),
        "Handshake-completing FIN-ACK must establish the connection then get our own FIN-ACK"
    );

    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(WindowState::test_new(
        client_fin_ack.window,
        client_fin_ack.seq_num,
        client_fin_ack.ack_num,
    )));
    cloned_state.snd_una += LOCAL_SYN_BYTE;
    cloned_state.snd_nxt += LOCAL_FIN_BYTE;
    cloned_state.rcv_nxt += REMOTE_FIN_BYTE;

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Connection should be established then immediately moved to LAST-ACK, not left in \
         SYN-RECEIVED or reset"
    );

    Ok(())
}

#[test]
fn creates_valid_fin_ack() -> TraceableResult {
    // Simulate an established connection, FIN-ACK arrives at seq=CLIENT_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    let client_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    assert_eq!(
        client_fin_ack.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_FIN_BYTE,
            flags: TcpFlags::FinAck,
            ..SERVER_REPLY
        })
    );

    // Connection is now in LAST-ACK state (waiting for client's final ACK), not yet removed
    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(WindowState::test_new(
        client_fin_ack.window,
        client_fin_ack.seq_num,
        client_fin_ack.ack_num,
    )));
    cloned_state.snd_nxt += LOCAL_SYN_BYTE;
    cloned_state.rcv_nxt += REMOTE_FIN_BYTE;

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn fin_ack_acks_prior_data_and_advances_snd_una() -> TraceableResult {
    // FIN-ACK also includes "check the ACK field" processing just like a plain ACK (RFC 9293,
    // Section 3.10.7.4). Its SEG.ACK can acknowledge data sent earlier in the connection, and that
    // must still advance SND.UNA and prune `pending`.

    // snd_nxt=snd_una=SERVER_ISN+1, rcv_nxt=CLIENT_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    // Client sends data, server echoes "Hello" back
    TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    cloned_state.snd_nxt += LOCAL_HELLO_LEN;
    cloned_state.rcv_nxt += REMOTE_HELLO_LEN;
    // snd_una left unchanged at this point because the "Hello" echo is unacked

    assert_eq!(
        {
            let pending = &connections.try_get()?.pending;
            (
                pending.len(),
                pending
                    .first()
                    .and_then(|seg| seg.peek_info().payload.as_ref().map(TcpPayload::as_bytes)),
            )
        },
        (1, Some("Hello".as_ref())),
        "Intermediate `pending` should consist of the unacked \"Hello\" echo"
    );

    // Client's FIN-ACK arrives in order (seq=CLIENT_ISN+6) and acks the echoed "Hello"
    // (ack=SERVER_ISN+6)
    let client_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    client_fin_ack.create_reply(&mut connections)?;

    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(WindowState::test_new(
        client_fin_ack.window,
        client_fin_ack.seq_num,
        client_fin_ack.ack_num,
    )));
    cloned_state.snd_nxt += LOCAL_FIN_BYTE;
    cloned_state.rcv_nxt += REMOTE_FIN_BYTE;
    cloned_state.snd_una += LOCAL_HELLO_LEN;

    let final_state = connections.try_get()?;

    assert_eq!(
        final_state, &cloned_state,
        "SEG.ACK from FIN-ACK should advance SND.UNA just like a plain ACK"
    );

    assert_eq!(
        (final_state.pending.len(), final_state.pending.first().map(|seg| seg.peek_info().flags)),
        (1, Some(TcpFlags::FinAck)),
        "The fully acked \"Hello\" echo should be pruned from `pending`, leaving only the FIN-ACK"
    );

    Ok(())
}

#[test]
fn out_of_order_fin_ack_gets_duplicate_ack_without_closing() -> TraceableResult {
    // A FIN-ACK arriving before data preceding it (seq_num != rcv_nxt, e.g. an earlier data segment
    // was lost) must not be processed yet. Doing so would signal "no more data" before the missing
    // data has been delivered. Until the gap is filled, treat it like out-of-order data by sending
    // a duplicate ACK reflecting the current RCV.NXT without starting to close, but remember its
    // FIN position for later.

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt = CLIENT_ISN+1
    let mut cloned_state = connections.try_get()?.clone();

    // FIN-ACK arrives at seq=CLIENT_ISN+6, but rcv_nxt is still CLIENT_ISN+1 (a 5-byte gap)
    let client_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    assert_eq!(
        client_fin_ack.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "Out-of-order FIN-ACK should get a duplicate ACK reflecting rcv_nxt=CLIENT_ISN+1, not a \
         FIN-ACK in response"
    );

    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        client_fin_ack.window,
        client_fin_ack.seq_num,
        client_fin_ack.ack_num,
    )));
    cloned_state.reassembly.mark_fin(client_fin_ack.seq_num);

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Connection must remain established, out-of-order FIN-ACK must not start closing, but its \
         FIN position should now be remembered"
    );

    Ok(())
}

#[test]
fn out_of_order_fin_ack_with_data_completes_close_once_gap_closes() -> TraceableResult {
    // A FIN-ACK carrying trailing data arrives in window but SEG.SEQ != RCV.NXT (an earlier data
    // segment hasn't arrived yet), so it must be buffered rather than acted on immediately. Once
    // the missing segment fills the gap, the connection should discover the peer's FIN has now been
    // reached and send our FIN in that same reply, echoing both segments' data together.

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt=CLIENT_ISN+1
    let mut cloned_state = connections.try_get()?.clone();

    // FIN-ACK carrying "Hi" arrives at seq=CLIENT_ISN+6, but rcv_nxt is still CLIENT_ISN+1
    let fin_ack_with_data = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str("Hi")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        fin_ack_with_data.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "Out-of-order FIN-ACK should get a duplicate ACK, not start closing yet"
    );

    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        fin_ack_with_data.window,
        fin_ack_with_data.seq_num,
        fin_ack_with_data.ack_num,
    )));
    cloned_state.reassembly.insert(
        fin_ack_with_data.seq_num,
        fin_ack_with_data
            .payload
            .clone()
            .ok_or("Expected fin_ack_with_data to carry a payload")?,
    );
    cloned_state
        .reassembly
        .mark_fin(fin_ack_with_data.seq_num + REMOTE_HI_LEN);

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Connection must remain ESTABLISHED, with the FIN-ACK's data buffered and its FIN \
         position remembered"
    );

    // "Hello" fills the gap
    let hello = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        hello.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN
                + REMOTE_SYN_BYTE
                + REMOTE_HELLO_LEN
                + REMOTE_HI_LEN
                + REMOTE_FIN_BYTE,
            flags: TcpFlags::FinAck,
            payload: TcpPayload::from_test_str("HelloHi")?,
            ..SERVER_REPLY
        }),
        "Filling the gap should reveal the peer's previously buffered FIN, echoing both segments' \
         data together and replying with our FIN"
    );

    // Mirror what the implementation should do internally by advancing past "Hello", then draining
    // "Hi" now that it's contiguous, leaving the buffer empty but the FIN position still
    // remembered.
    cloned_state
        .reassembly
        .drain_contiguous(hello.seq_num + REMOTE_HELLO_LEN, &mut Vec::new());

    // The window state stays pinned to the FIN-ACK's values (not changing those of the "Hello") due
    // to the window update rules, even though "Hello" fills a gap in the data
    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(WindowState::test_new(
        fin_ack_with_data.window,
        fin_ack_with_data.seq_num,
        fin_ack_with_data.ack_num,
    )));
    cloned_state.snd_nxt += LOCAL_HELLO_LEN + LOCAL_HI_LEN + LOCAL_FIN_BYTE;
    cloned_state.rcv_nxt += REMOTE_HELLO_LEN + REMOTE_HI_LEN + REMOTE_FIN_BYTE;

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

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
            tcp_state,
            snd_nxt: AFTER_HANDSHAKE.snd_nxt + LOCAL_FIN_BYTE,
            ..AFTER_HANDSHAKE
        };

        connections.insert(initial_state.clone());

        // SEG.ACK == SND.UNA, not yet SND.NXT, so this doesn't cover our FIN
        let partial_ack = TcpSegment {
            seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ..CLIENT_PKT
        };

        assert_eq!(
            partial_ack.create_reply(&mut connections)?,
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
fn final_ack_after_fin_ack_removes_connection_and_returns_none() -> TraceableResult {
    // Simulates the client's final ACK completing the 4-step close. Should get no reply (not RST)
    // so the client can close cleanly from TIME-WAIT.

    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    let client_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    client_fin_ack.create_reply(&mut connections)?;

    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(WindowState::test_new(
        client_fin_ack.window,
        client_fin_ack.seq_num,
        client_fin_ack.ack_num,
    )));
    cloned_state.snd_nxt += LOCAL_FIN_BYTE;
    cloned_state.rcv_nxt += REMOTE_FIN_BYTE;

    assert_eq!(connections.try_get()?, &cloned_state);

    // ack=SERVER_ISN+2 (our FIN-ACK seq + 1)
    assert_eq!(
        TcpSegment {
            seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_FIN_BYTE,
            ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
            ..CLIENT_PKT
        }
        .create_reply(&mut connections)?,
        None
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed after final ACK");

    Ok(())
}

#[test]
fn close_established_sends_fin_ack_and_transitions_to_fin_wait_1() -> TraceableResult {
    // snd_nxt=SERVER_ISN+1, rcv_nxt=CLIENT_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    let mut replies = connections.close_established();
    let reply = replies.pop().ok_or("Expected one reply")?;

    assert!(replies.is_empty(), "Expected exactly one reply");
    assert_eq!(
        reply,
        TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            flags: TcpFlags::FinAck,
            ..SERVER_REPLY
        }
    );

    // IP addresses are swapped: server -> client
    assert_eq!(reply.get_ip_pair(), REMOTE_TO_LOCAL_IP_PAIR.swapped());

    cloned_state.tcp_state = TcpState::FinWait1(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE));
    cloned_state.snd_nxt += LOCAL_FIN_BYTE;
    assert_eq!(connections.try_get()?, &cloned_state, "FIN consumes one sequence number");

    Ok(())
}

#[test]
fn fin_wait_1_to_fin_wait_2_on_ack_of_our_fin() -> TraceableResult {
    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Client acknowledges our FIN (ack=SERVER_ISN+2), no FIN of its own yet
    let ack_of_fin = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
        ..CLIENT_PKT
    };

    assert_eq!(ack_of_fin.create_reply(&mut connections)?, None);

    cloned_state.tcp_state = TcpState::FinWait2(SyncedState::test_new(WindowState::test_new(
        ack_of_fin.window,
        ack_of_fin.seq_num,
        ack_of_fin.ack_num,
    )));
    cloned_state.snd_una += LOCAL_FIN_BYTE;

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn fin_wait_2_closes_on_fin_ack_from_peer() -> TraceableResult {
    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Our FIN is acknowledged -> FIN-WAIT-2
    let ack_of_fin = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
        ..CLIENT_PKT
    };

    assert_eq!(ack_of_fin.create_reply(&mut connections)?, None);

    cloned_state.tcp_state = TcpState::FinWait2(SyncedState::test_new(WindowState::test_new(
        ack_of_fin.window,
        ack_of_fin.seq_num,
        ack_of_fin.ack_num,
    )));
    cloned_state.snd_una += LOCAL_FIN_BYTE;

    assert_eq!(connections.try_get()?, &cloned_state);

    // Client's FIN arrives in order
    let fin_reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        fin_reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_FIN_BYTE,
            ..SERVER_REPLY
        })
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}

#[test]
fn fin_wait_1_closes_immediately_if_peers_fin_also_acks_ours() -> TraceableResult {
    // Simultaneous close where the peer's FIN, arriving while we're still in FIN-WAIT-1, also
    // acknowledges our FIN -> fully closed immediately, skipping FIN-WAIT-2/CLOSING.

    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2

    // Client's FIN arrives in order and also acknowledges our FIN (ack=SERVER_ISN+2)
    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_FIN_BYTE,
            ..SERVER_REPLY
        })
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}

#[test]
fn data_after_our_fin_in_fin_wait_1_is_acked_without_echo() -> TraceableResult {
    // After we've sent our FIN (FIN-WAIT-1), the connection isn't fully closed until the peer's
    // FIN also arrives, so data already in flight from the peer must still be accepted and ACKed,
    // even though we have no send side left to echo it with.

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt=CLIENT_ISN+1
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
            ..SERVER_REPLY
        }),
        "Data arriving after our FIN should be ACKed without being echoed, not RST"
    );

    cloned_state.rcv_nxt += REMOTE_HELLO_LEN;
    assert_eq!(connections.try_get()?, &cloned_state, "State should remain FIN-WAIT-1");

    Ok(())
}

#[test]
fn data_after_our_fin_in_fin_wait_2_is_acked_without_echo() -> TraceableResult {
    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Our FIN is acknowledged -> FIN-WAIT-2
    let ack_of_fin = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
        ..CLIENT_PKT
    };

    assert_eq!(ack_of_fin.create_reply(&mut connections)?, None);

    cloned_state.tcp_state = TcpState::FinWait2(SyncedState::test_new(WindowState::test_new(
        ack_of_fin.window,
        ack_of_fin.seq_num,
        ack_of_fin.ack_num,
    )));
    cloned_state.snd_una += LOCAL_FIN_BYTE;

    assert_eq!(connections.try_get()?, &cloned_state);

    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
            ..SERVER_REPLY
        }),
        "Data arriving after our FIN should be ACKed without being echoed, not RST"
    );

    cloned_state.rcv_nxt += REMOTE_HELLO_LEN;
    assert_eq!(connections.try_get()?, &cloned_state, "State should remain FIN-WAIT-2");

    Ok(())
}

#[test]
fn simultaneous_close_transitions_through_closing_to_closed() -> TraceableResult {
    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Client's FIN arrives in order, but doesn't yet acknowledge our FIN (ack=SERVER_ISN+1,
    // simultaneous close) -> CLOSING
    let client_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    assert_eq!(
        client_fin_ack.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_FIN_BYTE,
            ..SERVER_REPLY
        })
    );

    cloned_state.tcp_state = TcpState::Closing(SyncedState::test_new(WindowState::test_new(
        client_fin_ack.window,
        client_fin_ack.seq_num,
        client_fin_ack.ack_num,
    )));
    cloned_state.rcv_nxt += REMOTE_FIN_BYTE;
    assert_eq!(connections.try_get()?, &cloned_state);

    // Client's ACK of our FIN finally arrives -> fully closed
    assert_eq!(
        TcpSegment {
            seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_FIN_BYTE,
            ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
            ..CLIENT_PKT
        }
        .create_reply(&mut connections)?,
        None
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}

#[test]
fn fin_ack_with_data_in_fin_wait_1_advances_rcv_nxt_past_data_and_fin() -> TraceableResult {
    // Simultaneous close where the peer's FIN carries trailing data. Our own FIN has already been
    // sent, so the data can't be echoed (same as plain data arriving in FIN-WAIT-1), but RCV.NXT
    // must still advance past both the data and the FIN's phantom byte.

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt=CLIENT_ISN+1
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Client's FIN-ACK arrives in order with data, not yet acknowledging our FIN (ack=SERVER_ISN+1)
    let fin_ack_with_data = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        fin_ack_with_data.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_FIN_BYTE,
            ..SERVER_REPLY
        }),
        "ACK should reflect RCV.NXT advanced past both the data and the FIN, not just the FIN"
    );

    cloned_state.tcp_state = TcpState::Closing(SyncedState::test_new(WindowState::test_new(
        fin_ack_with_data.window,
        fin_ack_with_data.seq_num,
        fin_ack_with_data.ack_num,
    )));
    cloned_state.rcv_nxt += REMOTE_HELLO_LEN + REMOTE_FIN_BYTE;
    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn fin_ack_with_data_in_fin_wait_1_acking_our_fin_closes_immediately() -> TraceableResult {
    // Similar to the other case with FIN-ACK with data in FIN-WAIT-1, but the peer's FIN+data also
    // acknowledges our own FIN, so the close completes immediately instead of moving to CLOSING.

    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2

    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_FIN_BYTE,
            ..SERVER_REPLY
        }),
        "ACK should reflect RCV.NXT advanced past both the data and the FIN, not just the FIN"
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}

#[test]
fn fin_ack_with_data_in_fin_wait_2_advances_rcv_nxt_past_data_and_fin() -> TraceableResult {
    // The peer's final FIN in FIN-WAIT-2 carries trailing data, so the ACK we send back must
    // reflect RCV.NXT advanced past both the data and the FIN before the connection is removed.

    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2

    // Our FIN is acknowledged -> FIN-WAIT-2
    assert_eq!(
        TcpSegment {
            seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
            ..CLIENT_PKT
        }
        .create_reply(&mut connections)?,
        None
    );

    // Client's FIN arrives in order with trailing data
    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_FIN_BYTE,
            ..SERVER_REPLY
        }),
        "ACK should reflect RCV.NXT advanced past both the data and the FIN, not just the FIN"
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}

#[test]
fn fin_ack_with_data_in_established_echoes_data_and_starts_closing() -> TraceableResult {
    // A FIN-ACK carrying trailing data on an established connection should echo the data (like
    // plain in-order data) before closing. Unlike FIN-WAIT-1/2, our own FIN hasn't been sent yet
    // here, so it can be piggybacked on the same FIN-ACK reply.

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt=CLIENT_ISN+1
    let mut cloned_state = connections.try_get()?.clone();

    let fin_ack_with_data = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        fin_ack_with_data.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_FIN_BYTE,
            flags: TcpFlags::FinAck,
            payload: TcpPayload::from_test_str("Hello")?,
            ..SERVER_REPLY
        }),
        "Data should be echoed and piggybacked on the FIN-ACK, with the ACK covering both the \
         data and the FIN"
    );

    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(WindowState::test_new(
        fin_ack_with_data.window,
        fin_ack_with_data.seq_num,
        fin_ack_with_data.ack_num,
    )));
    cloned_state.snd_nxt += LOCAL_HELLO_LEN + LOCAL_FIN_BYTE;
    cloned_state.rcv_nxt += REMOTE_HELLO_LEN + REMOTE_FIN_BYTE;

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn fin_ack_with_data_in_established_defers_fin_until_remainder_drains() -> TraceableResult {
    // If the peer's advertised window can't fit all the trailing data right now, only what fits
    // gets echoed as a plain ACK, with the rest buffered in the send buffer. Since not everything
    // has been sent yet, our own FIN must not go out yet either. The connection enters CLOSE-WAIT,
    // and once the peer acks and opens the window enough to drain the rest, the remainder is sent
    // with our FIN finally piggybacked on it, completing the move to LAST-ACK.

    const SMALL_WINDOW: SeqOffset<u16, Local> = SeqOffset::new(3);
    const LARGER_WINDOW: SeqOffset<u16, Local> = SeqOffset::new(10);
    const LO_LEN: SeqOffset<u32, Local> = SeqOffset::new(2);

    let mut connections = TcpConnections::default();
    let mut expected_state = ConnState {
        tcp_state: TcpState::Established(SyncedState::test_new(WindowState::test_new(
            SMALL_WINDOW,
            CLIENT_ISN + REMOTE_SYN_BYTE,
            SERVER_ISN + LOCAL_SYN_BYTE,
        ))),
        ..AFTER_HANDSHAKE
    };
    connections.insert(expected_state.clone());

    let fin_ack_with_data = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        window: SMALL_WINDOW,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        fin_ack_with_data.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_FIN_BYTE,
            payload: TcpPayload::from_test_str("Hel")?,
            ..SERVER_REPLY
        }),
        "Only the first 3 out of 5 bytes fit in the advertised window of 3, so our own FIN must \
         not be sent yet "
    );

    expected_state.tcp_state = TcpState::CloseWait(SyncedState::test_new(WindowState::test_new(
        fin_ack_with_data.window,
        fin_ack_with_data.seq_num,
        fin_ack_with_data.ack_num,
    )));
    expected_state.snd_nxt += SeqOffset::<u32, Local>::from(SMALL_WINDOW);
    expected_state.rcv_nxt += REMOTE_HELLO_LEN + REMOTE_FIN_BYTE;
    expected_state.send_buffer.extend(b"lo");

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "The untransmittable remainder \"lo\" should be queued in the send buffer, with the \
         connection held in CLOSE-WAIT"
    );

    // Peer acks the 3 sent bytes and opens the window enough to take the rest
    let window_update = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_FIN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + SMALL_WINDOW.into(),
        window: LARGER_WINDOW,
        ..CLIENT_PKT
    };

    assert_eq!(
        window_update.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + SMALL_WINDOW.into(),
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_FIN_BYTE,
            flags: TcpFlags::FinAck,
            payload: TcpPayload::from_test_str("lo")?,
            ..SERVER_REPLY
        }),
        "Once the buffer fully drains, our FIN should finally go out, piggybacked on the last \
         chunk"
    );

    expected_state.tcp_state = TcpState::LastAck(SyncedState::test_new(WindowState::test_new(
        window_update.window,
        window_update.seq_num,
        window_update.ack_num,
    )));
    expected_state.snd_una += SMALL_WINDOW.into();
    expected_state.snd_nxt += LO_LEN + LOCAL_FIN_BYTE;
    expected_state.send_buffer.clear();

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "The connection should now be fully drained and in LAST-ACK, awaiting the final ACK"
    );

    Ok(())
}

#[test]
fn reassembled_backlog_larger_than_one_segment_defers_fin_until_drained() -> TraceableResult {
    // Filling a gap left by packet loss can reveal more previously-buffered data than fits in a
    // single segment's payload, with the peer's FIN sitting right after all of it. Every byte of
    // that backlog must still reach the peer, so only as much as fits in one segment goes out right
    // away. The rest stays queued, and our own FIN is only sent once the whole backlog has gone
    // out.

    const MAX_PAYLOAD_LEN: usize =
        ETHERNET_MTU - Ipv4Header::REPLY_HDR_LEN - TCP_HDR_MIN_LEN as usize;

    /// Ensures that this test is reexamined if the relevant consts change.
    const _: () = assert!(MAX_PAYLOAD_LEN == 1500 - 20 - 20);

    let mut connections = TcpConnections::default().after_handshake();
    let mut expected_state = connections.try_get()?.clone();

    // The gap-filling chunk is itself already bigger than one segment
    let gap_payload = "a".repeat(MAX_PAYLOAD_LEN + 50);
    let gap_len = SeqOffset::<u32, Remote>::new(u32::try_from(gap_payload.len())?);

    let tail_payload = "b".repeat(100);
    let tail_len = SeqOffset::<u32, Remote>::new(u32::try_from(tail_payload.len())?);

    // FIN-ACK carrying the trailing chunk arrives first, out of order
    let fin_ack_tail = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + gap_len,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str(&tail_payload)?,
        ..CLIENT_PKT
    };

    fin_ack_tail.create_reply(&mut connections)?;

    expected_state.reassembly.insert(
        fin_ack_tail.seq_num,
        fin_ack_tail
            .payload
            .clone()
            .ok_or("Expected fin_ack_tail to carry a payload")?,
    );
    expected_state
        .reassembly
        .mark_fin(fin_ack_tail.seq_num + tail_len);

    // Gap-filling segment reveals the whole backlog and the FIN at once
    let gap_filler = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str(&gap_payload)?,
        ..CLIENT_PKT
    };

    let capped_payload = "a".repeat(MAX_PAYLOAD_LEN);
    let max_len = SeqOffset::<u32, Local>::new(u32::try_from(MAX_PAYLOAD_LEN)?);

    assert_eq!(
        gap_filler.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + gap_len + tail_len + REMOTE_FIN_BYTE,
            payload: TcpPayload::from_test_str(&capped_payload)?,
            ..SERVER_REPLY
        }),
        "Filling the gap reveals more data than fits in one segment, but only {MAX_PAYLOAD_LEN} \
         bytes should go out, and our own FIN must not be sent yet"
    );

    let leftover = "a".repeat(50) + &tail_payload;

    // Mirror what the implementation does internally by advancing past the gap-filling chunk, then
    // draining the now-contiguous trailing chunk out of reassembly, leaving its FIN position
    // remembered
    expected_state
        .reassembly
        .drain_contiguous(gap_filler.seq_num + gap_len, &mut Vec::new());

    // The window state stays pinned to the out-of-order FIN-ACK's values (not the gap-filling
    // chunk's, which arrives with an earlier sequence number) due to the window update rules
    expected_state.tcp_state = TcpState::CloseWait(SyncedState::test_new(WindowState::test_new(
        fin_ack_tail.window,
        fin_ack_tail.seq_num,
        fin_ack_tail.ack_num,
    )));
    expected_state.snd_nxt += max_len;
    expected_state.rcv_nxt += gap_len + tail_len + REMOTE_FIN_BYTE;
    expected_state.send_buffer.extend(leftover.as_bytes());

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "The 150-byte remainder must stay queued rather than being lost, with the connection held \
         in CLOSE-WAIT"
    );

    // Peer acks the first `MAX_PAYLOAD_LEN` bytes. The window is already wide open, so the rest can
    // go out immediately along with our FIN.
    let window_update = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + gap_len + tail_len + REMOTE_FIN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + max_len,
        ..CLIENT_PKT
    };

    assert_eq!(
        window_update.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + max_len,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + gap_len + tail_len + REMOTE_FIN_BYTE,
            flags: TcpFlags::FinAck,
            payload: TcpPayload::from_test_str(&leftover)?,
            ..SERVER_REPLY
        }),
        "Once fully drained, the leftover 150 bytes should go out with our FIN finally attached"
    );

    expected_state.tcp_state = TcpState::LastAck(SyncedState::test_new(WindowState::test_new(
        window_update.window,
        window_update.seq_num,
        window_update.ack_num,
    )));
    expected_state.snd_una += max_len;
    expected_state.snd_nxt +=
        SeqOffset::<u32, Local>::new(u32::try_from(leftover.len())?) + LOCAL_FIN_BYTE;
    expected_state.send_buffer.clear();

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "The connection should now be fully drained and in LAST-ACK, awaiting the final ACK"
    );

    Ok(())
}

#[test]
fn stale_retransmission_after_sending_our_fin_gets_duplicate_ack_not_rst() -> TraceableResult {
    // A retransmission of data the server already fully processed can arrive in any of the states
    // after we've sent our FIN. Regardless of which of those states the connection is in, this
    // should get a duplicate ACK reflecting the current state, with the connection otherwise left
    // untouched, just like in ESTABLISHED.

    for tcp_state in STATES_AFTER_SENDING_FIN {
        let mut connections = TcpConnections::default();
        let initial_state = ConnState { tcp_state, ..AFTER_HANDSHAKE };
        connections.insert(initial_state.clone());

        // Carries a sequence number from before RCV.NXT, i.e. data already fully processed
        let stale_retransmission = TcpSegment {
            seq_num: CLIENT_ISN,
            ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
            payload: TcpPayload::from_test_str("stale")?,
            ..CLIENT_PKT
        };

        assert_eq!(
            stale_retransmission.create_reply(&mut connections)?,
            Some(TcpSegment {
                seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
                ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
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
        tcp_state: TcpState::CloseWait(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE)),
        send_buffer: VecDeque::from(b"leftover".to_vec()),
        ..AFTER_HANDSHAKE
    };
    connections.insert(initial_state.clone());

    let stale_retransmission = TcpSegment {
        seq_num: CLIENT_ISN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("stale")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        stale_retransmission.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
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
        let initial_state = ConnState { tcp_state, ..AFTER_HANDSHAKE };
        connections.insert(initial_state.clone());

        // Carries a sequence number from before RCV.NXT, and a distinctive window that must not get
        // adopted
        let stale_pure_ack = TcpSegment {
            seq_num: CLIENT_ISN,
            ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
            window: SeqOffset::new(1234),
            ..CLIENT_PKT
        };

        assert_eq!(
            stale_pure_ack.create_reply(&mut connections)?,
            Some(TcpSegment {
                seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
                ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
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
        tcp_state: TcpState::CloseWait(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE)),
        send_buffer: VecDeque::from(b"leftover".to_vec()),
        ..AFTER_HANDSHAKE
    };
    connections.insert(initial_state.clone());

    // Carries a sequence number from before RCV.NXT, and a distinctive window that must not get
    // adopted
    let stale_pure_ack = TcpSegment {
        seq_num: CLIENT_ISN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        window: SeqOffset::new(1234),
        ..CLIENT_PKT
    };

    assert_eq!(
        stale_pure_ack.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "A stale pure ACK should get a duplicate ACK, not a RST"
    );

    assert_eq!(connections.try_get()?, &initial_state, "The connection should be untouched");

    Ok(())
}
