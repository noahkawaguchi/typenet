use super::*;

#[test]
fn poll_error_unrelated_to_interruption_propagates() -> TraceableResult {
    const MESSAGE: &str = "boom from poll";

    let poll = MockPoll::with_results([Err(io::Error::other(MESSAGE))]);
    let mut device = MockDevice::with_read_results([])?;

    assert_matches!(
        run_test_server(
            TcpConnections::default(),
            &mut device,
            |_, _| poll.next(),
            || false,
            ONE_YEAR_GRACE_PERIOD,
        ),
        Err(e) if e.to_string().contains(MESSAGE),
        "A non-interrupt poll error should propagate"
    );

    assert!(device.write_history().is_empty(), "Error should propagate without anything written");

    Ok(())
}

#[test]
fn read_error_unrelated_to_interruption_propagates() -> TraceableResult {
    const MESSAGE: &str = "boom from read";

    let poll = MockPoll::with_results([Ok(true)]);
    let mut device = MockDevice::with_read_results([Err(io::Error::other(MESSAGE))])?;

    assert_matches!(
        run_test_server(
            TcpConnections::default(),
            &mut device,
            |_, _| poll.next(),
            || false,
            ONE_YEAR_GRACE_PERIOD,
        ),
        Err(e) if e.to_string().contains(MESSAGE),
        "A non-interrupt read error should propagate"
    );

    assert!(device.write_history().is_empty(), "Error should propagate without anything written");

    Ok(())
}

#[test]
fn write_failure_while_sending_fin_ack_propagates() -> TraceableResult {
    const MESSAGE: &str = "boom from write";

    let poll = MockPoll::with_results([Err(io::ErrorKind::Interrupted.into())]);
    let mut device = MockDevice::with_read_results([])?.with_failing_writes(MESSAGE);

    assert_matches!(
        run_test_server(
            TcpConnections::default().after_handshake(),
            &mut device,
            |_, _| poll.next(),
            || true,
            ONE_YEAR_GRACE_PERIOD,
        ),
        Err(e) if e.to_string().contains(MESSAGE),
        "A device write failure while closing connections should propagate"
    );

    assert!(device.write_history().is_empty(), "Error should propagate without anything written");

    Ok(())
}
