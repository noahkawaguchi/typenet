use {super::*, pretty_assertions::assert_eq};

#[test]
fn stray_syn_out_of_window_gets_challenge_ack() -> TraceableResult {
    // RFC 9293, Section 3.10.7.4, "First, check sequence number": a segment outside the receive
    // window gets a challenge ACK (<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>) and is dropped. "Fourth,
    // check the SYN bit" is not reached.

    // snd_nxt=SERVER_ISN+1, rcv_nxt=CLIENT_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let initial_state = connections.try_get()?.clone();

    // seq=CLIENT_ISN-20 < rcv_nxt=CLIENT_ISN+1, outside the receive window, caught at "First, check
    // sequence number"
    let reply =
        TcpSegment { seq_num: CLIENT_ISN - SeqOffset::new(20), flags: TcpFlags::Syn, ..CLIENT_PKT }
            .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "Out-of-window stray SYN must produce a challenge ACK, not a RST"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "Out-of-window stray SYN must not destroy the connection"
    );

    Ok(())
}

#[test]
fn stray_syn_in_window_gets_challenge_ack() -> TraceableResult {
    // RFC 9293, Section 3.10.7.4, "Fourth, check the SYN bit": for synchronized states, RFC 5961
    // (incorporated into RFC 9293) recommends a challenge ACK irrespective of the sequence number,
    // and the connection must not be reset.

    // snd_nxt=SERVER_ISN+1, rcv_nxt=CLIENT_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let initial_state = connections.try_get()?.clone();

    // seq=CLIENT_ISN+1 == rcv_nxt, inside the receive window, reaches "Fourth, check the SYN bit"
    let reply =
        TcpSegment { seq_num: CLIENT_ISN + REMOTE_SYN_BYTE, flags: TcpFlags::Syn, ..CLIENT_PKT }
            .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "In-window stray SYN must produce a challenge ACK, not a RST"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "In-window stray SYN must not destroy the connection"
    );

    Ok(())
}

#[test]
fn stray_syn_in_fin_wait_1_gets_challenge_ack() -> TraceableResult {
    // The same RFC 9293, Section 3.10.7.4 SYN rule as above applies to all synchronized states
    // listed there, not just ESTABLISHED.

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt=CLIENT_ISN+1
    connections.close_established(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2

    let initial_state = connections.try_get()?.clone();
    assert_matches!(initial_state.tcp_state, TcpState::FinWait1(_));

    // seq=CLIENT_ISN+1 == rcv_nxt, inside the receive window, reaches "Fourth, check the SYN bit"
    let reply =
        TcpSegment { seq_num: CLIENT_ISN + REMOTE_SYN_BYTE, flags: TcpFlags::Syn, ..CLIENT_PKT }
            .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_FIN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "Stray SYN in FIN-WAIT-1 must produce a challenge ACK using snd_nxt=SERVER_ISN+2"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "Stray SYN in FIN-WAIT-1 must not destroy the connection"
    );

    Ok(())
}

#[test]
fn stray_syn_ack_gets_challenge_ack() -> TraceableResult {
    // The same RFC 9293, Section 3.10.7.4 SYN rule as above applies to SYN-ACK as well, not just
    // SYN, since SYN is checked fourth and ACK is checked fifth. As a server with only passive
    // OPEN, a SYN-ACK would never come from a real client, but this behavior should still be
    // verified for robustness and correctness reasons.

    // snd_nxt=SERVER_ISN+1, rcv_nxt=CLIENT_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let initial_state = connections.try_get()?.clone();

    // seq=CLIENT_ISN+1 == rcv_nxt, inside the receive window, reaches "Fourth, check the SYN bit"
    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        flags: TcpFlags::SynAck,
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
        "Stray SYN-ACK must produce a challenge ACK, not a RST"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "Stray SYN-ACK must not destroy the connection"
    );

    Ok(())
}
