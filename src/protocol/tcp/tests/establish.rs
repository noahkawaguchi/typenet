use super::*;

#[test]
fn creates_valid_syn_ack() -> Result {
    let mut connections = TcpConnections::default();

    let reply = TcpSegment { seq_num: CLIENT_ISN, flags: TcpFlags::Syn, ..CLIENT_PKT }
        .create_reply(&mut connections)?;

    // seq_num is the random ISN that was stored in the connection table
    let stored_isn = connections.try_get()?.snd_una;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: stored_isn,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            flags: TcpFlags::SynAck,
            ..SERVER_REPLY
        })
    );

    Ok(())
}

#[test]
fn duplicate_syn_during_syn_received_resends_same_syn_ack() -> Result {
    // If our SYN-ACK is lost, the client's retransmission timer will resend its SYN. We must resend
    // the same SYN-ACK (same ISN), not RST the retry, and not generate a new ISN.

    // Simulate having already sent a SYN-ACK with ISN=SERVER_ISN
    let mut connections = TcpConnections::default().with_syn_rcv();
    let initial_state = connections.try_get()?.clone();

    let reply = TcpSegment { seq_num: CLIENT_ISN, flags: TcpFlags::Syn, ..CLIENT_PKT }
        .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            flags: TcpFlags::SynAck,
            ..SERVER_REPLY
        }),
        "Retransmitted SYN should get the same SYN-ACK resent, not a RST"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "State should remain SYN-RECEIVED, not reset or advance"
    );

    Ok(())
}

#[test]
fn handshake_ack_without_data_establishes_connection_and_returns_none() -> Result {
    // Simulate having sent a SYN-ACK with ISN=SERVER_ISN so ack_num=SERVER_ISN+1 is the correct
    // completion
    let mut connections = TcpConnections::default().with_syn_rcv();
    let mut cloned_state = connections.try_get()?.clone();

    let handshake_ack = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        ..CLIENT_PKT
    };

    assert_eq!(handshake_ack.create_reply(&mut connections)?, None);

    // Reproduce the state changes that should happen at connection establishment
    let window_state =
        WindowState::test_new(handshake_ack.window, handshake_ack.seq_num, handshake_ack.ack_num);
    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(window_state));
    cloned_state.rcv_nxt = CLIENT_ISN + REMOTE_SYN_BYTE;
    cloned_state.snd_una += LOCAL_SYN_BYTE;

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn handshake_ack_with_data_establishes_and_echoes() -> Result {
    // Clients may send data along with the handshake-completing ACK. This must still complete the
    // handshake and echo the data, not get a RST.

    let mut connections = TcpConnections::default().with_syn_rcv();
    let mut cloned_state = connections.try_get()?.clone();

    let handshake_ack_with_data = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        handshake_ack_with_data.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
            payload: TcpPayload::from_test_str("Hello")?,
            ..SERVER_REPLY
        }),
        "Handshake-completing ACK with data should establish the connection and echo the data"
    );

    let window_state = WindowState::test_new(
        handshake_ack_with_data.window,
        handshake_ack_with_data.seq_num,
        handshake_ack_with_data.ack_num,
    );
    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(window_state));
    cloned_state.rcv_nxt += REMOTE_HELLO_LEN;
    cloned_state.snd_nxt += LOCAL_HELLO_LEN;
    cloned_state.snd_una += LOCAL_SYN_BYTE;

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn handshake_ack_with_out_of_order_seq_and_no_data_still_completes_handshake() -> Result {
    // RFC 9293, Section 3.10.7.4, "First, check sequence number," only rejects a segment that
    // falls entirely outside the receive window. An in-window but out-of-order SEG.SEQ is still
    // acceptable, so "Fifth, check the ACK field" still applies and completes the handshake here,
    // even though the segment itself isn't in order. There's no payload to deliver or buffer in
    // this case, so RCV.NXT is untouched and nothing else happens.

    let mut connections = TcpConnections::default().with_syn_rcv();
    let mut cloned_state = connections.try_get()?.clone();

    // Correct ack_num, but seq_num doesn't match RCV.NXT = CLIENT_ISN + SYN_BYTE
    let out_of_order = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + SeqOffset::new(1),
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        ..CLIENT_PKT
    };

    assert_eq!(
        out_of_order.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "Reply should still reflect RCV.NXT unchanged, since nothing was delivered"
    );

    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        out_of_order.window,
        out_of_order.seq_num,
        out_of_order.ack_num,
    )));
    cloned_state.snd_una += LOCAL_SYN_BYTE;

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "In-window, out-of-order SEG.SEQ with an acceptable ACK field should still complete the \
         handshake"
    );

    Ok(())
}

#[test]
fn out_of_order_seq_and_invalid_ack_gets_rst() -> Result {
    // An in-window but out-of-order segment is still acceptable (RFC 9293, Section 3.10.7.4,
    // "First, check sequence number"), so the ACK field check still applies to it ("Fifth, check
    // the ACK field"). If SEG.ACK is invalid, that means a RST, not a mere current state ACK.

    let mut connections = TcpConnections::default().with_syn_rcv();
    let initial_state = connections.try_get()?.clone();

    // seq_num doesn't match RCV.NXT, and ack_num doesn't acknowledge our SYN-ACK either
    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + SeqOffset::new(1),
        ack_num: SERVER_ISN,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment { seq_num: SERVER_ISN, flags: TcpFlags::Rst, ..SERVER_REPLY }),
        "In-window, out-of-order SEG.SEQ with invalid SEG.ACK should get a RST, not a current \
         state ACK"
    );

    assert_eq!(connections.try_get()?, &initial_state, "Connection must remain SYN-RECEIVED");

    Ok(())
}

#[test]
fn out_of_order_fin_ack_in_syn_rcv_still_completes_handshake_and_records_fin() -> Result {
    // Same reasoning as the plain ACK case. An in-window but out-of-order FIN-ACK still has a
    // valid ACK field, so RFC 9293 still completes the handshake here. The FIN itself can't be
    // processed yet, so its position is remembered for later instead, the same as an out-of-order
    // FIN-ACK arriving on an ESTABLISHED connection.

    let mut connections = TcpConnections::default().with_syn_rcv();
    let mut cloned_state = connections.try_get()?.clone();

    // Correct ack_num, but seq_num doesn't match RCV.NXT = CLIENT_ISN + SYN_BYTE
    let out_of_order = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + SeqOffset::new(1),
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    assert_eq!(
        out_of_order.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "Reply should still reflect RCV.NXT unchanged, since the FIN can't be processed yet"
    );

    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        out_of_order.window,
        out_of_order.seq_num,
        out_of_order.ack_num,
    )));
    cloned_state.snd_una += LOCAL_SYN_BYTE;
    cloned_state.reassembly.mark_fin(out_of_order.seq_num);

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Handshake should complete despite the out-of-order SEG.SEQ, but then stay in \
         ESTABLISHED, with the FIN's position remembered for once the gap closes"
    );

    Ok(())
}

#[test]
fn out_of_order_handshake_ack_with_data_still_completes_handshake_and_buffers_data() -> Result {
    // Same reasoning as the plain ACK case. An in-window but out-of-order handshake-completing ACK
    // still has a valid ACK field, so the handshake completes. The payload can't be delivered
    // yet, so it's buffered for later reassembly instead.

    let mut connections = TcpConnections::default().with_syn_rcv();
    let mut cloned_state = connections.try_get()?.clone();

    // Correct ack_num, but seq_num doesn't match RCV.NXT = CLIENT_ISN + SYN_BYTE
    let out_of_order = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + SeqOffset::new(1),
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        out_of_order.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "Reply should still reflect RCV.NXT unchanged since there is a hole in the data"
    );

    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        out_of_order.window,
        out_of_order.seq_num,
        out_of_order.ack_num,
    )));
    cloned_state.snd_una += LOCAL_SYN_BYTE;
    cloned_state.reassembly.insert(
        out_of_order.seq_num,
        out_of_order
            .payload
            .clone()
            .ok_or("Expected segment to carry a payload")?,
    );

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Handshake should complete despite the out-of-order SEG.SEQ, with the data buffered for \
         later reassembly"
    );

    Ok(())
}

#[test]
fn out_of_order_handshake_completing_ack_is_echoed_once_gap_closes() -> Result {
    // "Hi" arrives as the handshake-completing ACK, but out of order (as if "Hello" preceded it).
    // The handshake completes immediately since SEG.SEQ is in window and SEG.ACK is valid, but "Hi"
    // is buffered rather than echoed. Once "Hello" fills the gap, both should be echoed together,
    // routed through the ordinary ESTABLISHED handling that already knows how to drain this buffer.

    let mut connections = TcpConnections::default().with_syn_rcv();

    let hi_reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hi")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        hi_reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "Out-of-order handshake-completing ACK should get a duplicate ACK, not an echo, since \
         \"Hi\" can't be delivered yet"
    );

    let hello_reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        hello_reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_HI_LEN,
            payload: TcpPayload::from_test_str("HelloHi")?,
            ..SERVER_REPLY
        }),
        "Both segments should be echoed together once the gap closes"
    );

    Ok(())
}
