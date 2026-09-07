use {super::*, pretty_assertions::assert_eq};

#[test]
fn already_draining_reports_time_left() -> Result {
    const GRACE_PERIOD: Duration = Duration::from_secs(10);

    let now = Instant::now();

    assert_eq!(
        Server { shutdown_deadline: Some(now.try_add(GRACE_PERIOD)?), ..decision_test_server() }
            .decide_shutdown(now)?,
        ShutdownDecision::AlreadyDraining { time_left: GRACE_PERIOD }
    );

    Ok(())
}

#[test]
fn established_connection_begins_draining_with_fin_ack_and_deadline() -> Result {
    const GRACE_PERIOD: Duration = Duration::from_secs(10);

    let now = Instant::now();

    assert_matches!(
        Server {
            tcp_connections: TcpConnections::default().after_handshake(),
            shutdown_grace_period: GRACE_PERIOD,
            ..decision_test_server()
        }
        .decide_shutdown(now)?,
        ShutdownDecision::BeganDraining { to_send, deadline }
            if to_send.len() == 1 && deadline == now.try_add(GRACE_PERIOD)?
    );

    Ok(())
}

#[test]
fn no_established_connections_reports_no_connections() -> Result {
    assert_eq!(
        Server { tcp_connections: TcpConnections::default(), ..decision_test_server() }
            .decide_shutdown(Instant::now())?,
        ShutdownDecision::NoConnections
    );

    Ok(())
}

#[test]
fn overflowing_deadline_errors_instead_of_panicking() {
    assert_matches!(
        Server {
            tcp_connections: TcpConnections::default().after_handshake(),
            shutdown_grace_period: Duration::MAX,
            ..decision_test_server()
        }
        .decide_shutdown(Instant::now()),
        Err(e) if e.to_string().contains("Overflowed")
    );
}

#[test]
fn first_interrupt_with_established_connection_sends_fin_ack_and_continues() -> Result {
    // The first poll call simulates the shutdown signal, then the second lets the (already-elapsed)
    // grace period end the loop instead of running forever. Proves that the loop sends the packets
    // as real I/O when draining begins.

    let poll = MockPoll::with_results([Err(io::ErrorKind::Interrupted.into()), Ok(false)]);
    let mut device = MockDevice::with_read_results([])?;

    run_test_server(
        TcpConnections::default().after_handshake(),
        &mut device,
        |_, _| poll.next(),
        || true,
        IMMEDIATE_GRACE_PERIOD,
    )?;

    let [write] = device.write_history() else { return Err("Expected exactly one write".into()) };

    assert_eq!(decode_mock_pkt(write)?, TcpSegment::SERVER_FIN_ACK_INITIATING_CLOSE);

    Ok(())
}

#[test]
fn second_interrupt_while_draining_does_not_resend_or_exit() -> Result {
    // The first interrupt begins draining and sends FIN-ACK. The second interrupt, arriving while
    // still draining, should neither resend the FIN-ACK nor break the loop. The third, unrelated
    // poll error ends the loop deterministically and proves that the second interrupt didn't
    // already cause an exit.

    const MESSAGE: &str = "boom, unrelated to shutdown";

    let poll_calls = Cell::new(0u8);
    let poll = MockPoll::with_results([
        Err(io::ErrorKind::Interrupted.into()),
        Err(io::ErrorKind::Interrupted.into()),
        Err(io::Error::other(MESSAGE)),
    ]);
    let mut device = MockDevice::with_read_results([])?;

    assert_matches!(
        run_test_server(
            TcpConnections::default().after_handshake(),
            &mut device,
            |_, _| {
                poll_calls.set(poll_calls.get() + 1);
                poll.next()
            },
            || true,
            ONE_YEAR_GRACE_PERIOD,
        ),
        Err(e) if e.to_string().contains(MESSAGE),
        "The third, unrelated poll error should propagate, proving the loop didn't exit earlier"
    );

    assert_eq!(poll_calls.get(), 3, "All three poll calls should have been needed");

    let [write] = device.write_history() else { return Err("Expected exactly one write".into()) };

    assert_eq!(
        decode_mock_pkt(write)?,
        TcpSegment::SERVER_FIN_ACK_INITIATING_CLOSE,
        "Should be the original FIN-ACK, not a resend of a different segment"
    );

    Ok(())
}

#[test]
fn interrupt_with_no_established_connections_exits_immediately() -> Result {
    // The server should exit after the initial interrupted error, avoiding the second error, which
    // would be propagated

    let poll = MockPoll::with_results([
        Err(io::ErrorKind::Interrupted.into()),
        Err(io::ErrorKind::Other.into()),
    ]);

    let mut device = MockDevice::with_read_results([])?;

    assert_matches!(
        run_test_server(
            TcpConnections::default(),
            &mut device,
            |_, _| poll.next(),
            || true,
            IMMEDIATE_GRACE_PERIOD,
        ),
        Ok(()),
        "Server should exit before hitting the error that would be propagated"
    );

    assert!(
        device.write_history().is_empty(),
        "No connections to close, nothing should be written"
    );

    Ok(())
}

#[test]
fn interrupt_unrelated_to_shutdown_is_ignored() -> Result {
    // The shutdown check only starts returning `true` on the second poll call, so the first
    // interruption must be treated as an unrelated signal (just continue) rather than the start of
    // a shutdown. Connections start empty so that, if the first interrupt were wrongly treated as
    // real, the server would exit immediately (after only one poll call) instead of needing the
    // second, real shutdown interrupt to do so.

    let poll_calls = Cell::new(0u8);

    let poll = MockPoll::with_results([
        Err(io::ErrorKind::Interrupted.into()),
        Err(io::ErrorKind::Interrupted.into()),
    ]);

    let mut device = MockDevice::with_read_results([])?;

    run_test_server(
        TcpConnections::default(),
        &mut device,
        |_, _| {
            poll_calls.set(poll_calls.get() + 1);
            poll.next()
        },
        || poll_calls.get() >= 2,
        IMMEDIATE_GRACE_PERIOD,
    )?;

    assert_eq!(poll_calls.get(), 2, "The first interrupt should not have ended the loop early");
    assert!(device.write_history().is_empty(), "Nothing should have been written");

    Ok(())
}

#[test]
fn read_interrupt_reaches_the_same_shutdown_handling_as_poll_interrupt() -> Result {
    // Mirrors the test for poll, but the `EINTR` arrives from the `read()` call instead of the
    // `poll()`, confirming that both entry points reach the same shutdown decision handling

    let poll = MockPoll::with_results([Ok(true)]);
    let mut device = MockDevice::with_read_results([Err(io::ErrorKind::Interrupted.into())])?;

    run_test_server(
        TcpConnections::default(),
        &mut device,
        |_, _| poll.next(),
        || true,
        IMMEDIATE_GRACE_PERIOD,
    )?;

    assert!(
        device.write_history().is_empty(),
        "No connections to close, nothing should be written"
    );

    Ok(())
}
