use {super::*, pretty_assertions::assert_eq};

#[test]
fn due_retransmission_is_sent_as_real_io() -> TraceableResult {
    // Zero RTO means the pending SYN-ACK is due the instant it's seeded, so the very first
    // `Ok(false)` (a poll timeout) should trigger a real resend. The second poll call is a shutdown
    // signal, and since a SYN-RECEIVED connection isn't mid-close, it exits immediately without
    // writing anything more.

    let poll = MockPoll::with_results([Ok(false), Err(io::ErrorKind::Interrupted.into())]);
    let mut device = MockDevice::with_read_results([])?;

    run_test_server(
        TcpConnections::test_new(Duration::ZERO, 5).with_syn_rcv(),
        &mut device,
        |_, _| poll.next(),
        || true,
        ONE_YEAR_GRACE_PERIOD,
    )?;

    let [write] = device.write_history() else { return Err("Expected exactly one write".into()) };

    assert_eq!(decode_mock_pkt(write)?, TcpSegment::SERVER_SYN_ACK);

    Ok(())
}

#[test]
fn retransmission_does_not_drop_the_connection() -> TraceableResult {
    // Max retries of 5 comfortably covers two retransmissions, so if the connection survives the
    // first retransmit, the second due poll should trigger another one instead of finding the
    // connection already gone.

    let poll =
        MockPoll::with_results([Ok(false), Ok(false), Err(io::ErrorKind::Interrupted.into())]);
    let mut device = MockDevice::with_read_results([])?;

    run_test_server(
        TcpConnections::test_new(Duration::ZERO, 5).with_syn_rcv(),
        &mut device,
        |_, _| poll.next(),
        || true,
        ONE_YEAR_GRACE_PERIOD,
    )?;

    let [first, second] = device.write_history() else {
        return Err(
            "The connection should survive the first retransmit and produce a second".into()
        );
    };

    for write in [first, second] {
        assert_eq!(
            decode_mock_pkt(write)?,
            TcpSegment::SERVER_SYN_ACK,
            "Every retransmission should resend the same unacked SYN-ACK unchanged"
        );
    }

    Ok(())
}

#[test]
fn gives_up_and_drops_connection_after_max_retries() -> TraceableResult {
    // With max retries of 2, the first two due polls retransmit, and the third finds the retries
    // exhausted and drops the connection instead of sending again. The final poll is a shutdown
    // signal, and with the connection already gone, it should exit immediately without another
    // write.

    let poll = MockPoll::with_results([
        Ok(false),
        Ok(false),
        Ok(false),
        Err(io::ErrorKind::Interrupted.into()),
    ]);
    let mut device = MockDevice::with_read_results([])?;

    run_test_server(
        TcpConnections::test_new(Duration::ZERO, 2).with_syn_rcv(),
        &mut device,
        |_, _| poll.next(),
        || true,
        ONE_YEAR_GRACE_PERIOD,
    )?;

    let [first, second] = device.write_history() else {
        return Err("Only 2 retransmissions should be written before giving up, not 3".into());
    };

    for write in [first, second] {
        assert_eq!(
            decode_mock_pkt(write)?,
            TcpSegment::SERVER_SYN_ACK,
            "Every retransmission should resend the same unacked SYN-ACK unchanged"
        );
    }

    Ok(())
}
