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
fn handshake_ack_with_wrong_seq_and_no_data_gets_current_state_ack() -> Result {
    // As per RFC 9293, Section 3.10.7.4, "First, check sequence number," an unacceptable SEG.SEQ
    // must not be processed further (i.e. must not complete the handshake), regardless of whether
    // the ACK field is otherwise valid. Instead, an ACK reflecting current state is sent and the
    // segment is dropped.

    let mut connections = TcpConnections::default().with_syn_rcv();
    let initial_state = connections.try_get()?.clone();

    // Correct ack_num, but seq_num doesn't match RCV.NXT = CLIENT_ISN + SYN_BYTE
    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + SeqOffset::new(1),
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "Wrong SEG.SEQ must get an ACK reflecting current state, not complete the handshake or \
         get a RST"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "Connection must remain SYN-RECEIVED, not be established or reset"
    );

    Ok(())
}

#[test]
fn fin_ack_in_syn_rcv_with_wrong_seq_gets_current_state_ack() -> Result {
    // RFC 9293, Section 3.10.7.4, "First, check sequence number" applies regardless of which
    // control bits are set. (For example, "Eighth, check the FIN bit" is never reached if the
    // sequence number is not acceptable.) A FIN-ACK with an unacceptable SEG.SEQ during
    // SYN-RECEIVED must get a challenge ACK reflecting current state, not complete the handshake.
    // However, its FIN position is remembered for later, the same as an out-of-order FIN-ACK
    // arriving after the handshake has already completed.

    let mut connections = TcpConnections::default().with_syn_rcv();
    let mut cloned_state = connections.try_get()?.clone();

    // Correct ack_num, but seq_num doesn't match RCV.NXT = CLIENT_ISN + SYN_BYTE
    let wrong_seq_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + SeqOffset::new(1),
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    assert_eq!(
        wrong_seq_fin_ack.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "FIN-ACK in SYN-RECEIVED with wrong SEG.SEQ must get current state ACK"
    );

    cloned_state.reassembly.mark_fin(wrong_seq_fin_ack.seq_num);

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Connection must remain SYN-RECEIVED, with the FIN's position remembered"
    );

    Ok(())
}

#[test]
fn handshake_ack_with_with_wrong_seq_and_data_gets_current_state_ack() -> Result {
    // A data-carrying segment arriving during SYN-RECEIVED with an unacceptable SEG.SEQ must still
    // just get a plain ACK reflecting current state (RFC 9293, Section 3.10.7.4, "First, check
    // sequence number"), not a RST, the same as it would with no payload. However, its data is
    // buffered for later reassembly.

    let mut connections = TcpConnections::default().with_syn_rcv();
    let mut cloned_state = connections.try_get()?.clone();

    // Correct ack_num, but seq_num doesn't match RCV.NXT = CLIENT_ISN + SYN_BYTE
    let wrong_seq_with_data = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + SeqOffset::new(1),
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        wrong_seq_with_data.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "Wrong SEG.SEQ must get an ACK reflecting current state, not complete the handshake or \
         get a RST"
    );

    cloned_state.reassembly.insert(
        wrong_seq_with_data.seq_num,
        wrong_seq_with_data
            .payload
            .clone()
            .ok_or("expected wrong_seq_with_data to carry a payload")?,
    );

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Connection must remain SYN-RECEIVED, not be established or reset, with the data buffered \
         for later reassembly"
    );

    Ok(())
}
