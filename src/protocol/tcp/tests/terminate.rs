use super::*;

#[test]
fn fin_ack_in_syn_received_establishes_and_closes_immediately() -> Result {
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
fn creates_valid_fin_ack() -> Result {
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
fn fin_ack_acks_prior_data_and_advances_snd_una() -> Result {
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
fn out_of_order_fin_ack_gets_duplicate_ack_without_closing() -> Result {
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
fn out_of_order_fin_ack_with_data_completes_close_once_gap_closes() -> Result {
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
fn partial_ack_in_last_ack_does_not_close_connection() -> Result {
    // A LAST-ACK connection that echoed data alongside its own FIN can be ACKed in stages (e.g.
    // the peer ACKs previously buffered chunks separately from the byte that covers the FIN). An
    // ACK that doesn't yet reach SND.NXT (i.e., doesn't yet cover the FIN) must not be
    // treated as the final ACK completing the close.

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt=CLIENT_ISN+1
    let mut cloned_state = connections.try_get()?.clone();

    // Client's FIN-ACK arrives with trailing data, echoed alongside our own FIN -> LAST-ACK
    let client_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    };

    client_fin_ack.create_reply(&mut connections)?;

    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(WindowState::test_new(
        client_fin_ack.window,
        client_fin_ack.seq_num,
        client_fin_ack.ack_num,
    )));
    cloned_state.snd_nxt += LOCAL_HELLO_LEN + LOCAL_FIN_BYTE;
    cloned_state.rcv_nxt += REMOTE_HELLO_LEN + REMOTE_FIN_BYTE;

    assert_eq!(connections.try_get()?, &cloned_state);

    // Client ACKs only the echoed "Hello" (SEG.ACK=SERVER_ISN+1+5), not the FIN yet
    // (SND.NXT=SERVER_ISN+1+5+1)
    let partial_ack = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_FIN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN,
        ..CLIENT_PKT
    };

    assert_eq!(
        partial_ack.create_reply(&mut connections)?,
        None,
        "A partial ACK not yet covering the FIN should not get a reply"
    );

    cloned_state.snd_una += LOCAL_HELLO_LEN;
    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(WindowState::test_new(
        partial_ack.window,
        partial_ack.seq_num,
        partial_ack.ack_num,
    )));

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Connection should remain in LAST-ACK, not be removed, since the FIN is still unacked"
    );

    Ok(())
}

#[test]
fn final_ack_after_fin_ack_removes_connection_and_returns_none() -> Result {
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
fn close_established_sends_fin_ack_and_transitions_to_fin_wait_1() -> Result {
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
fn fin_wait_1_to_fin_wait_2_on_ack_of_our_fin() -> Result {
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
fn fin_wait_2_closes_on_fin_ack_from_peer() -> Result {
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
fn fin_wait_1_closes_immediately_if_peers_fin_also_acks_ours() -> Result {
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
fn data_after_our_fin_in_fin_wait_1_is_acked_without_echo() -> Result {
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
fn data_after_our_fin_in_fin_wait_2_is_acked_without_echo() -> Result {
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
fn simultaneous_close_transitions_through_closing_to_closed() -> Result {
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
fn fin_ack_with_data_in_fin_wait_1_advances_rcv_nxt_past_data_and_fin() -> Result {
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
fn fin_ack_with_data_in_fin_wait_1_acking_our_fin_closes_immediately() -> Result {
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
fn fin_ack_with_data_in_fin_wait_2_advances_rcv_nxt_past_data_and_fin() -> Result {
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
fn fin_ack_with_data_in_established_echoes_data_and_starts_closing() -> Result {
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
fn fin_ack_with_data_in_established_buffers_the_untransmittable_remainder() -> Result {
    // If the peer's advertised window can't fit all the trailing data right now, only what fits
    // gets echoed alongside the FIN, with the rest buffered in the send buffer.
    //
    // However, due to the current simplification lacking a proper half-closed state, the remaining
    // data can never actually be sent afterward, since our own FIN in this same reply ends our byte
    // stream.

    const SMALL_WINDOW: SeqOffset<u16, Local> = SeqOffset::new(3);

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
            flags: TcpFlags::FinAck,
            payload: TcpPayload::from_test_str("Hel")?,
            ..SERVER_REPLY
        }),
        "Only the first 3 bytes fit in the advertised window of 3, piggybacked on the FIN-ACK"
    );

    expected_state.tcp_state = TcpState::LastAck(SyncedState::test_new(WindowState::test_new(
        fin_ack_with_data.window,
        fin_ack_with_data.seq_num,
        fin_ack_with_data.ack_num,
    )));
    expected_state.snd_nxt += SeqOffset::<u32, Local>::from(SMALL_WINDOW) + LOCAL_FIN_BYTE;
    expected_state.rcv_nxt += REMOTE_HELLO_LEN + REMOTE_FIN_BYTE;
    expected_state.send_buffer.extend(b"lo");

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "The untransmittable remainder \"lo\" should be queued in the send buffer"
    );

    Ok(())
}

#[test]
fn stale_retransmission_in_a_terminating_state_gets_duplicate_ack_not_rst() -> Result {
    // A retransmission of data the server already fully processed can arrive after the connection
    // has moved past ESTABLISHED into any of the terminating states. Regardless of which of those
    // states the connection is in, this should get a duplicate ACK reflecting the current state,
    // with the connection otherwise left untouched, just like in ESTABLISHED.

    for tcp_state in [
        TcpState::FinWait1(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE)),
        TcpState::FinWait2(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE)),
        TcpState::Closing(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE)),
        TcpState::LastAck(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE)),
    ] {
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
