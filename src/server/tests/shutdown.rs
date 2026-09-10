use {super::*, pretty_assertions::assert_eq};

#[test]
fn exits_once_connections_finish_closing() -> TraceableResult {
    // The first poll is a shutdown signal that begins active close (FIN-ACK sent -> FIN-WAIT-1).
    // The second poll delivers the client's real closing FIN-ACK, which the connection accepts as
    // completing the close. The post-packet check should then end the loop immediately, without
    // needing the (very long) grace period to elapse.

    let poll_calls = Cell::new(0u8);
    let poll = MockPoll::with_results([Err(io::ErrorKind::Interrupted.into()), Ok(true)]);
    let mut device = MockDevice::with_read_results([Ok(encode_mock_pkt(
        &TcpSegment::CLIENT_FIN_ACK_COMPLETING_CLOSE,
    )?)])?;

    run_test_server(
        TcpConnections::default().after_handshake(),
        &mut device,
        |_, _| {
            poll_calls.set(poll_calls.get() + 1);
            poll.next()
        },
        || true,
        ONE_YEAR_GRACE_PERIOD,
    )?;

    assert_eq!(poll_calls.get(), 2, "Both poll calls should have been needed to exit");

    let [fin_ack, final_ack] = device.write_history() else {
        return Err(
            "The initial FIN-ACK and the final ACK completing the close should be written".into()
        );
    };

    assert_eq!(decode_mock_pkt(fin_ack)?, TcpSegment::SERVER_FIN_ACK_INITIATING_CLOSE);
    assert_eq!(decode_mock_pkt(final_ack)?, TcpSegment::SERVER_FINAL_ACK_COMPLETING_CLOSE);

    Ok(())
}
