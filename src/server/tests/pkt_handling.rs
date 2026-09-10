use {super::*, pretty_assertions::assert_eq};

#[test]
fn malformed_pkt_is_skipped_without_propagating_or_writing() -> TraceableResult {
    // 5 bytes is too short for even a minimal (20-byte) IPv4 header, so parsing fails and the
    // packet should just be logged and skipped. The second poll call is a shutdown signal, and
    // since there are no established connections, it ends the loop cleanly.

    let poll = MockPoll::with_results([Ok(true), Err(io::ErrorKind::Interrupted.into())]);
    let mut device = MockDevice::with_read_results([Ok(vec![0u8; 5])])?;

    assert_matches!(
        run_test_server(
            TcpConnections::default(),
            &mut device,
            |_, _| poll.next(),
            || true,
            IMMEDIATE_GRACE_PERIOD,
        ),
        Ok(()),
        "A malformed packet error should not propagate"
    );

    assert!(device.write_history().is_empty(), "A malformed packet should not produce a reply");

    Ok(())
}

#[test]
fn valid_syn_producing_a_reply_is_sent() -> TraceableResult {
    let poll = MockPoll::with_results([Ok(true), Err(io::ErrorKind::Interrupted.into())]);
    let mut device =
        MockDevice::with_read_results([Ok(encode_mock_pkt(&TcpSegment::CLIENT_SYN)?)])?;

    run_test_server(
        TcpConnections::default(),
        &mut device,
        |_, _| poll.next(),
        || true,
        IMMEDIATE_GRACE_PERIOD,
    )?;

    // Only asserting on length instead of content here because of the randomly generated ISN
    assert_eq!(device.write_history().len(), 1, "The SYN should get a SYN-ACK reply written");

    Ok(())
}

#[test]
fn valid_ack_completing_handshake_produces_no_reply() -> TraceableResult {
    // The second, unrelated poll error is just to end the loop right after processing the ACK,
    // without going through shutdown handling that would close the now ESTABLISHED connection and
    // write a FIN-ACK, contaminating the write count this test cares about.

    const MESSAGE: &str = "boom from poll, unrelated to the ACK just processed";

    let poll = MockPoll::with_results([Ok(true), Err(io::Error::other(MESSAGE))]);
    let mut device = MockDevice::with_read_results([Ok(encode_mock_pkt(
        &TcpSegment::CLIENT_ACK_COMPLETING_HANDSHAKE,
    )?)])?;

    assert_matches!(
        run_test_server(
            TcpConnections::default().with_syn_rcv(),
            &mut device,
            |_, _| poll.next(),
            || false,
            ONE_YEAR_GRACE_PERIOD,
        ),
        Err(e) if e.to_string().contains(MESSAGE)
    );

    assert!(
        device.write_history().is_empty(),
        "The handshake-completing ACK should not produce a reply"
    );

    Ok(())
}
