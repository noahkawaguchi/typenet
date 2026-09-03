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
