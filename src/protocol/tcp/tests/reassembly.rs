use super::*;

#[test]
fn out_of_order_data_is_buffered_and_gets_duplicate_ack() -> Result {
    // "Hi" arrives positioned as if "Hello" (5 bytes) had already been received, but "Hello" hasn't
    // actually arrived yet, so this segment is out of order.

    let mut connections = TcpConnections::default().after_handshake();

    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hi")?,
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
        "Out-of-order data should get a duplicate ACK at the current RCV.NXT, not an echo"
    );

    assert_eq!(
        connections.try_get()?.reassembly.len(),
        1,
        "The out-of-order segment should be buffered rather than discarded"
    );

    Ok(())
}

#[test]
fn buffered_out_of_order_data_is_echoed_once_gap_closes() -> Result {
    // "Hi" arrives out of order first (buffered, not echoed), then "Hello" fills the gap before it.
    // Both should be echoed together in a single coalesced reply once the gap closes.

    let mut connections = TcpConnections::default().after_handshake();

    TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hi")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

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
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_HI_LEN,
            payload: TcpPayload::from_test_str("HelloHi")?,
            ..SERVER_REPLY
        }),
        "Both segments should be echoed together once the gap closes"
    );

    assert_eq!(
        connections.try_get()?.reassembly.len(),
        0,
        "The reassembly buffer should be empty after draining"
    );

    Ok(())
}

#[test]
fn seq_one_before_rcv_nxt_is_rejected() -> Result {
    // The receive window starts at RCV.NXT (RFC 9293, Section 3.10.7.4, "First, check sequence
    // number"), so a segment landing exactly one byte before it is the nearest possible byte still
    // outside the window. It must get a challenge ACK reflecting the connection's current state,
    // and its payload must never reach the reassembly buffer.

    let mut connections = TcpConnections::default().after_handshake();
    let initial_state = connections.try_get()?.clone();

    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE - SeqOffset::new(1),
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hi")?,
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
        "A segment one byte before RCV.NXT should get a challenge ACK"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "A segment one byte before RCV.NXT must not be buffered or otherwise alter connection \
         state"
    );

    Ok(())
}

#[test]
fn seq_at_last_acceptable_offset_is_still_buffered() -> Result {
    // RCV.NXT + RCV.WND - 1 is the last byte still inside the receive window (RFC 9293, Section
    // 3.10.7.4, "First, check sequence number"). A segment landing there carries acceptable data,
    // so it must be treated as ordinary in-window, out-of-order data by being buffered for
    // reassembly and answered with a duplicate ACK.

    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    let hi = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + TcpSegment::<Local>::RCV_WND.into()
            - SeqOffset::new(1),
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hi")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        hi.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "The last in-window offset should still get a duplicate ACK, not a challenge ACK"
    );

    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        hi.window, hi.seq_num, hi.ack_num,
    )));
    cloned_state.reassembly.insert(
        hi.seq_num,
        hi.payload
            .clone()
            .ok_or("Expected \"Hi\" segment to carry a payload")?,
    );

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "The last in-window offset should still be buffered for reassembly, updating window state \
         the same as any other out-of-order segment"
    );

    Ok(())
}

#[test]
fn seq_at_first_unacceptable_offset_is_rejected() -> Result {
    // RCV.NXT + RCV.WND is the first byte past the receive window (RFC 9293, Section 3.10.7.4,
    // "First, check sequence number"). A segment landing there must get a challenge ACK reflecting
    // the connection's current state, and its payload must never reach the reassembly buffer.

    let mut connections = TcpConnections::default().after_handshake();
    let initial_state = connections.try_get()?.clone();

    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + TcpSegment::<Local>::RCV_WND.into(),
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hi")?,
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
        "The first out-of-window offset should get a challenge ACK"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "The first out-of-window offset must not be buffered or otherwise alter connection state"
    );

    Ok(())
}
