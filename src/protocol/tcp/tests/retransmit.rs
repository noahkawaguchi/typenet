use {super::*, pretty_assertions::assert_eq};

#[test]
fn syn_ack_is_resent_while_due() -> TraceableResult {
    let mut connections = TcpConnections::test_new(Duration::ZERO, 5);

    TcpSegment { seq_num: CLIENT_ISN, flags: TcpFlags::Syn, ..CLIENT_PKT }
        .create_reply(&mut connections)?;

    let isn = connections.try_get()?.snd_una;

    let mut resent = connections.make_retransmissions();
    let reply = resent.pop().ok_or("Expected one retransmitted segment")?;

    assert!(resent.is_empty(), "Expected exactly one retransmitted segment");
    assert_eq!(
        reply,
        TcpSegment {
            seq_num: isn,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            flags: TcpFlags::SynAck,
            ..SERVER_REPLY
        }
    );
    assert_eq!(reply.get_ip_pair(), REMOTE_TO_LOCAL_IP_PAIR.swapped());

    Ok(())
}

#[test]
fn pending_segment_is_cleared_once_acked() -> TraceableResult {
    let mut connections = TcpConnections::test_new(Duration::ZERO, 5);

    TcpSegment { seq_num: CLIENT_ISN, flags: TcpFlags::Syn, ..CLIENT_PKT }
        .create_reply(&mut connections)?;

    let isn = connections.try_get()?.snd_una;

    // Handshake ACK completes the connection and should clear the pending SYN-ACK
    TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: isn + LOCAL_SYN_BYTE,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert!(
        connections.make_retransmissions().is_empty(),
        "Acked segment should not be retransmitted"
    );

    Ok(())
}

#[test]
fn data_echo_is_resent_unchanged() -> TraceableResult {
    let mut connections = TcpConnections::test_new(Duration::ZERO, 5).after_handshake();

    TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    let mut resent = connections.make_retransmissions();
    let reply = resent.pop().ok_or("Expected one retransmitted segment")?;

    assert!(resent.is_empty(), "Expected exactly one retransmitted segment");
    assert_eq!(
        reply,
        TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
            payload: TcpPayload::from_test_str("Hello")?,
            ..SERVER_REPLY
        }
    );

    Ok(())
}

#[test]
fn fin_ack_is_resent_unchanged() -> TraceableResult {
    let mut connections = TcpConnections::test_new(Duration::ZERO, 5).after_handshake();
    connections.close_established();

    let mut resent = connections.make_retransmissions();
    let reply = resent.pop().ok_or("Expected one retransmitted segment")?;

    assert!(resent.is_empty(), "Expected exactly one retransmitted segment");
    assert_eq!(
        reply,
        TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            flags: TcpFlags::FinAck,
            ..SERVER_REPLY
        }
    );

    Ok(())
}

#[test]
fn multiple_unacked_segments_are_all_retransmitted() -> TraceableResult {
    // If the client pipelines multiple segments before acking the first, the server must keep
    // retransmitting every unacked segment, not just the most recently sent one.

    let mut connections = TcpConnections::test_new(Duration::ZERO, 5).after_handshake();

    // First data packet: "Hello" (5 bytes), ack=SERVER_ISN+1 -> echoed, pending segment
    // seq=SERVER_ISN+1..SERVER_ISN+6
    TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    // Second data packet: "Hi" (2 bytes), still ack=SERVER_ISN+1 (hasn't acked the first echo yet)
    // -> echoed, pending segment seq=SERVER_ISN+6..SERVER_ISN+8
    TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hi")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    let [hello, hi] = connections
        .make_retransmissions()
        .try_into()
        .map_err(|_| "Expected exactly two retransmitted segments")?;

    assert_eq!(
        hello,
        TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
            payload: TcpPayload::from_test_str("Hello")?,
            ..SERVER_REPLY
        }
    );

    assert_eq!(
        hi,
        TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_HI_LEN,
            payload: TcpPayload::from_test_str("Hi")?,
            ..SERVER_REPLY
        }
    );

    Ok(())
}

#[test]
fn gives_up_after_max_retransmits() -> TraceableResult {
    const MAX_RETRIES: u8 = 3;

    let mut connections = TcpConnections::test_new(Duration::ZERO, MAX_RETRIES);

    TcpSegment { seq_num: CLIENT_ISN, flags: TcpFlags::Syn, ..CLIENT_PKT }
        .create_reply(&mut connections)?;

    for _ in 0..MAX_RETRIES {
        let resent = connections.make_retransmissions();

        assert_eq!(resent.len(), 1, "Should still be retried");
        assert_eq!(connections.try_get()?.tcp_state, TcpState::SynReceived(SynReceived));
    }

    // Exceeds MAX_RETRIES -> give up
    let resent = connections.make_retransmissions();

    assert!(resent.is_empty(), "Should give up instead of retransmitting again");
    assert_matches!(connections.try_get(), Err(_), "Connection should be removed");

    Ok(())
}

#[test]
fn retransmissions_back_off_exponentially() -> TraceableResult {
    let mut connections = TcpConnections::test_new(Duration::from_millis(10), 3).after_handshake();

    TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert!(connections.make_retransmissions().is_empty(), "Before first timeout");

    thread::sleep(Duration::from_millis(10));
    assert_eq!(connections.make_retransmissions().len(), 1, "Retransmit 1 after 10ms timeout");

    thread::sleep(Duration::from_millis(10));
    assert!(connections.make_retransmissions().is_empty(), "10ms into 20ms timeout");

    thread::sleep(Duration::from_millis(10));
    assert_eq!(connections.make_retransmissions().len(), 1, "Retransmit 2 after 20ms timeout");

    thread::sleep(Duration::from_millis(20));
    assert!(connections.make_retransmissions().is_empty(), "20ms into 40ms timeout");

    thread::sleep(Duration::from_millis(20));
    assert_eq!(connections.make_retransmissions().len(), 1, "Retransmit 3 after 40ms timeout");

    assert!(connections.make_retransmissions().is_empty(), "Give up after 3 retransmissions");

    Ok(())
}
