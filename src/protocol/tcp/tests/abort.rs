use {super::*, pretty_assertions::assert_eq};

fn client_rst(seq_num: SeqPoint<Remote>) -> TcpSegment<Remote> {
    TcpSegment { seq_num, flags: TcpFlags::Rst, ..CLIENT_PKT }
}

#[test]
fn rst_in_established_at_rcv_nxt_cleans_up_connection_and_returns_none() -> TraceableResult {
    // RFC 9293, Section 3.10.7.4, RST bit set, SEG.SEQ == RCV.NXT -> reset connection

    let mut connections = TcpConnections::default().after_handshake();
    assert_eq!(client_rst(CLIENT_ISN + REMOTE_SYN_BYTE).create_reply(&mut connections)?, None);
    assert_matches!(connections.try_get(), Err(_), "Connection should be removed after RST");

    Ok(())
}

#[test]
fn rst_in_established_within_window_but_not_at_rcv_nxt_gets_challenge_ack() -> TraceableResult {
    // RFC 9293, Section 3.10.7.4, RST bit set, SEG.SEQ in receive window but SEG.SEQ != RCV.NXT ->
    // send challenge ACK, don't reset connection

    // rcv_nxt=CLIENT_ISN+1, snd_nxt=SERVER_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let initial_state = connections.try_get()?.clone();

    // seq_num=CLIENT_ISN+4 is inside the receive window [CLIENT_ISN+1, CLIENT_ISN+1+RCV.WND), but
    // seq_num=CLIENT_ISN+4 != rcv_nxt=CLIENT_ISN+1
    let reply = client_rst(CLIENT_ISN + SeqOffset::new(4)).create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "In-window non-exact RST should get a challenge ACK, not a silent drop or reset"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "Connection must not be torn down by a non-exact in-window RST"
    );

    Ok(())
}

#[test]
fn rst_in_established_with_out_of_window_seq_is_silently_dropped() -> TraceableResult {
    // RFC 9293, Section 3.10.7.4, RST bit set, SEG.SEQ outside the current receive window -> must
    // be silently ignored. (This is protection against blind RST-spoofing where an attacker knows
    // the 4-tuple but not the current sequence numbers.)

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt=CLIENT_ISN+1
    let initial_state = connections.try_get()?.clone();

    // seq_num=CLIENT_ISN-10 is just below rcv_nxt=CLIENT_ISN+1, so this RST is outside the receive
    // window
    assert_eq!(
        client_rst(CLIENT_ISN - SeqOffset::new(10)).create_reply(&mut connections)?,
        None,
        "Out-of-window RST should be silently dropped"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "Connection must not be torn down by an out-of-window RST"
    );

    Ok(())
}

#[test]
fn rst_in_syn_received_at_rcv_nxt_cleans_up_connection_and_returns_none() -> TraceableResult {
    let mut connections = TcpConnections::default().with_syn_rcv();

    assert_eq!(client_rst(CLIENT_ISN + REMOTE_SYN_BYTE).create_reply(&mut connections)?, None);
    assert_matches!(connections.try_get(), Err(_), "Connection should be removed after RST");

    Ok(())
}

#[test]
fn rst_in_syn_received_with_out_of_window_seq_is_silently_dropped() -> TraceableResult {
    // RFC 9293, Section 3.10.7.4, "Second, check the RST bit," applies its three-case blind-reset
    // protection to SYN-RECEIVED the same as any other state. SEG.SEQ outside the receive window
    // must be silently ignored, not treated as a valid reset.

    let mut connections = TcpConnections::default().with_syn_rcv(); // rcv_nxt=CLIENT_ISN+SYN_BYTE
    let initial_state = connections.try_get()?.clone();

    // seq_num=CLIENT_ISN-10 is just below rcv_nxt=CLIENT_ISN+1, so this RST is outside the receive
    // window
    assert_eq!(
        client_rst(CLIENT_ISN - SeqOffset::new(10)).create_reply(&mut connections)?,
        None,
        "Out-of-window RST should be silently dropped"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "Connection must not be torn down by an out-of-window RST"
    );

    Ok(())
}

#[test]
fn rst_in_syn_received_within_window_but_not_at_rcv_nxt_gets_challenge_ack() -> TraceableResult {
    // RFC 9293, Section 3.10.7.4, "Second, check the RST bit," applies its three-case blind-reset
    // protection to SYN-RECEIVED the same as any other state. SEG.SEQ in the receive window but not
    // exactly RCV.NXT must get a challenge ACK, not treated as a valid reset.

    // rcv_nxt=CLIENT_ISN+SYN_BYTE, snd_nxt=SERVER_ISN+SYN_BYTE
    let mut connections = TcpConnections::default().with_syn_rcv();
    let initial_state = connections.try_get()?.clone();

    // seq_num=CLIENT_ISN+4 is inside the receive window [CLIENT_ISN+1, CLIENT_ISN+1+RCV.WND), but
    // seq_num=CLIENT_ISN+4 != rcv_nxt=CLIENT_ISN+1
    let reply = client_rst(CLIENT_ISN + SeqOffset::new(4)).create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "In-window non-exact RST should get a challenge ACK, not a silent drop or reset"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "Connection must not be torn down by a non-exact in-window RST"
    );

    Ok(())
}

#[test]
fn rst_for_unknown_connection_is_silently_dropped() -> TraceableResult {
    let mut connections = TcpConnections::default();

    assert_eq!(
        client_rst(CLIENT_ISN + REMOTE_SYN_BYTE).create_reply(&mut connections)?,
        None,
        "Unknown RST should be silently dropped"
    );

    assert_matches!(connections.try_get(), Err(_), "Connection should still not exist after RST");

    Ok(())
}
