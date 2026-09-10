use {super::*, pretty_assertions::assert_eq};

#[test]
fn poll_timeout_reflects_shutdown_deadline_across_a_real_run() -> TraceableResult {
    // Showing here that the loop actually uses the computed timeout when polling, and that the
    // grace period being elapsed actually ends the loop.
    //
    // Even though the exact `Duration` values come from `Instant::now()` calls, the grace period
    // and initial RTO are both `Duration::ZERO`, so the duration since a slightly later
    // `Instant::now()` call saturates to `Duration::ZERO` for the second timeout.

    let observed_timeouts = RefCell::new(Vec::new());
    let poll = MockPoll::with_results([Err(io::ErrorKind::Interrupted.into()), Ok(false)]);
    let mut device = MockDevice::with_read_results([])?;

    run_test_server(
        TcpConnections::default().after_handshake(),
        &mut device,
        |_, timeout| {
            observed_timeouts
                .try_borrow_mut()
                .map_err(io::Error::other)?
                .push(timeout);

            poll.next()
        },
        || true,
        IMMEDIATE_GRACE_PERIOD,
    )?;

    assert_eq!(
        observed_timeouts.into_inner().as_slice(),
        [None, Some(Duration::ZERO)],
        "No timeout before the interrupt, then a zero timeout once draining begins"
    );

    let [write] = device.write_history() else { return Err("Expected exactly one write".into()) };

    assert_eq!(decode_mock_pkt(write)?, TcpSegment::SERVER_FIN_ACK_INITIATING_CLOSE);

    Ok(())
}
