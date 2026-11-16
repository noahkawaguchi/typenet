use {super::*, pretty_assertions::assert_eq};

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
            seq_num: SERVER_ISN + SYN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN,
            flags: TcpFlags::FinAck,
            ..SERVER_REPLY
        }
    );

    // IP addresses are swapped: server -> client
    assert_eq!(reply.get_ip_pair(), IP_PAIR_IN.swapped());

    cloned_state.tcp_state =
        TcpState::FinWait1(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE, FinWait1));
    cloned_state.data.snd_nxt += FIN_BYTE_OUT;
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
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
        ..CLIENT_PKT
    };

    assert_eq!(ack_of_fin.create_test_reply(&mut connections)?, None);

    cloned_state.tcp_state = TcpState::FinWait2(SyncedState::test_new(
        WindowState::test_new(ack_of_fin.window, ack_of_fin.seq_num, ack_of_fin.ack_num),
        FinWait2,
    ));
    cloned_state.data.snd_una += FIN_BYTE_OUT;

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
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
        ..CLIENT_PKT
    };

    assert_eq!(ack_of_fin.create_test_reply(&mut connections)?, None);

    cloned_state.tcp_state = TcpState::FinWait2(SyncedState::test_new(
        WindowState::test_new(ack_of_fin.window, ack_of_fin.seq_num, ack_of_fin.ack_num),
        FinWait2,
    ));
    cloned_state.data.snd_una += FIN_BYTE_OUT;

    assert_eq!(connections.try_get()?, &cloned_state);

    // Client's FIN arrives in order
    let fin_reply = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    }
    .create_test_reply(&mut connections)?;

    assert_eq!(
        fin_reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + FIN_BYTE_IN,
            ..SERVER_REPLY
        })
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}

#[test]
fn fin_wait_1_closes_immediately_if_peers_fin_also_acks_ours() -> TraceableResult {
    // The peer's FIN, arriving while we're still in FIN-WAIT-1, also acknowledges our FIN -> fully
    // closed immediately, skipping FIN-WAIT-2/CLOSING. (This is not a simultaneous close, since the
    // peer had already received our FIN before sending its own.)

    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2

    // Client's FIN arrives in order and also acknowledges our FIN (ack=SERVER_ISN+2)
    let reply = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    }
    .create_test_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + FIN_BYTE_IN,
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
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_test_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN,
            ..SERVER_REPLY
        }),
        "Data arriving after our FIN should be ACKed without being echoed, not RST"
    );

    cloned_state.data.rcv_nxt += HELLO_LEN_IN;
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
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
        ..CLIENT_PKT
    };

    assert_eq!(ack_of_fin.create_test_reply(&mut connections)?, None);

    cloned_state.tcp_state = TcpState::FinWait2(SyncedState::test_new(
        WindowState::test_new(ack_of_fin.window, ack_of_fin.seq_num, ack_of_fin.ack_num),
        FinWait2,
    ));
    cloned_state.data.snd_una += FIN_BYTE_OUT;

    assert_eq!(connections.try_get()?, &cloned_state);

    let reply = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_test_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN,
            ..SERVER_REPLY
        }),
        "Data arriving after our FIN should be ACKed without being echoed, not RST"
    );

    cloned_state.data.rcv_nxt += HELLO_LEN_IN;
    assert_eq!(connections.try_get()?, &cloned_state, "State should remain FIN-WAIT-2");

    Ok(())
}

#[test]
fn fin_ack_with_data_in_fin_wait_1_acking_our_fin_closes_immediately() -> TraceableResult {
    // The peer's FIN, arriving while we're still in FIN-WAIT-1, carries trailing data and also
    // acknowledges our own FIN. Our FIN has already been sent, so the data can't be echoed, but
    // RCV.NXT must still advance past both the data and the FIN's phantom byte. Since our FIN is
    // acknowledged, the close completes immediately instead of moving to CLOSING.

    let mut connections = TcpConnections::default().after_handshake();
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2

    let reply = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_test_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN + FIN_BYTE_IN,
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
            seq_num: CLIENT_ISN + SYN_BYTE_IN,
            ack_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
            ..CLIENT_PKT
        }
        .create_test_reply(&mut connections)?,
        None
    );

    // Client's FIN arrives in order with trailing data
    let reply = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_test_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN + FIN_BYTE_IN,
            ..SERVER_REPLY
        }),
        "ACK should reflect RCV.NXT advanced past both the data and the FIN, not just the FIN"
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}
