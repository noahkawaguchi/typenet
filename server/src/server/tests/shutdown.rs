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
    let poll =
        MockPoll::with_results([Err(io::ErrorKind::Interrupted.into()), Ok(PollOutcome::Timeout)]);
    let mut device = MockDevice::with_read_results([])?;

    run_test_server(
        TcpConnections::default().after_handshake(),
        &mut device,
        |_, timeout, _| {
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

    assert_eq!(TcpSegment::decode_test_pkt(write)?, TcpSegment::SERVER_FIN_ACK_INITIATING_CLOSE);

    Ok(())
}

#[test]
fn stops_watching_the_shutdown_fd_once_draining_begins() -> TraceableResult {
    // The shutdown eventfd is shared across worker threads and never drained so that every thread
    // polling it keeps seeing it as readable. A thread that keeps asking to watch it after it has
    // already reacted once would spin in its loop, never actually blocking in the `poll()` call
    // again.

    let observed_watch_shutdown = RefCell::new(Vec::new());
    let poll = MockPoll::with_results([Ok(PollOutcome::Shutdown), Ok(PollOutcome::Timeout)]);
    let mut device = MockDevice::with_read_results([])?;

    run_test_server(
        TcpConnections::default().after_handshake(),
        &mut device,
        |_, _, watch_shutdown| {
            observed_watch_shutdown
                .try_borrow_mut()
                .map_err(io::Error::other)?
                .push(watch_shutdown);

            poll.next()
        },
        || true,
        IMMEDIATE_GRACE_PERIOD,
    )?;

    assert_eq!(
        observed_watch_shutdown.into_inner(),
        [true, false],
        "Should watch the shutdown fd before reacting to it, then stop once draining locally"
    );

    Ok(())
}

#[test]
fn exits_once_connections_finish_closing() -> TraceableResult {
    // The first poll is a shutdown signal that begins active close (FIN-ACK sent -> FIN-WAIT-1).
    // The second poll delivers the client's real closing FIN-ACK, which the connection accepts as
    // completing the close. The post-packet check should then end the loop immediately, without
    // needing the (very long) grace period to elapse.

    let poll_calls = Cell::new(0u8);
    let poll =
        MockPoll::with_results([Err(io::ErrorKind::Interrupted.into()), Ok(PollOutcome::Readable)]);
    let mut device = MockDevice::with_read_results([Ok(
        TcpSegment::CLIENT_FIN_ACK_COMPLETING_CLOSE.encode_test_pkt()?,
    )])?;

    run_test_server(
        TcpConnections::default().after_handshake(),
        &mut device,
        |_, _, _| {
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

    assert_eq!(TcpSegment::decode_test_pkt(fin_ack)?, TcpSegment::SERVER_FIN_ACK_INITIATING_CLOSE);

    assert_eq!(
        TcpSegment::decode_test_pkt(final_ack)?,
        TcpSegment::SERVER_FINAL_ACK_COMPLETING_CLOSE
    );

    Ok(())
}

#[test]
fn woken_without_any_interrupt_still_reacts_to_shutdown() -> TraceableResult {
    // Simulates a worker thread that never receives the shutdown signal's `EINTR` directly, as
    // would happen for every worker except whichever one the kernel happens to deliver it to.
    // `PollOutcome::Shutdown` alone should be enough to notice shutdown, and with no established
    // connections, exit immediately without needing any `io::ErrorKind::Interrupted`.

    let poll = MockPoll::with_results([Ok(PollOutcome::Shutdown)]);
    let mut device = MockDevice::with_read_results([])?;

    run_test_server(
        TcpConnections::default(),
        &mut device,
        |_, _, _| poll.next(),
        || true,
        ONE_YEAR_GRACE_PERIOD,
    )
}

#[test]
fn shutdown_is_noticed_right_after_handling_a_readable_packet() -> TraceableResult {
    // A shard under continuous traffic could keep seeing the main fd as readable and never exit if
    // it didn't respond differently to the shutdown fd also being readable. Only one
    // `PollOutcome::Both` poll result is scripted here, with no trailing
    // `io::ErrorKind::Interrupted` or second poll call at all, so the loop must notice shutdown on
    // its own right after handling this single packet, not by needing another iteration to do it.

    let poll = MockPoll::with_results([Ok(PollOutcome::Both)]);

    // Too short to be a valid IPv4 header, so it's skipped without creating any connection state
    let mut device = MockDevice::with_read_results([Ok(vec![0u8; 5])])?;

    run_test_server(
        TcpConnections::default(),
        &mut device,
        |_, _, _| poll.next(),
        || true,
        ONE_YEAR_GRACE_PERIOD,
    )
}
