use {super::*, pretty_assertions::assert_eq};

#[test]
fn neither_deadline_gives_no_timeout() {
    assert_eq!(decision_test_server().poll_timeout(Instant::now()), None);
}

#[test]
fn shutdown_deadline_alone_gives_duration() -> TraceableResult {
    const GRACE_PERIOD: Duration = Duration::from_secs(10);

    let now = Instant::now();

    assert_eq!(
        Server { shutdown_deadline: Some(now.try_add(GRACE_PERIOD)?), ..decision_test_server() }
            .poll_timeout(now),
        Some(GRACE_PERIOD)
    );

    Ok(())
}

#[test]
fn pending_retransmission_alone_gives_duration() {
    const INITIAL_RTO: Duration = Duration::from_millis(750);

    let now = Instant::now();

    assert_eq!(
        Server {
            tcp_connections: TcpConnections::new(
                RtoConfig { initial: INITIAL_RTO, ..Default::default() },
                5
            )
            .with_syn_rcv_and_pkt_last_sent(now),
            ..decision_test_server()
        }
        .poll_timeout(now),
        Some(INITIAL_RTO)
    );
}

#[test]
fn earlier_retransmit_deadline_taken_over_later_shutdown_deadline() -> TraceableResult {
    const INITIAL_RTO: Duration = Duration::from_millis(250);

    let now = Instant::now();

    assert_eq!(
        Server {
            tcp_connections: TcpConnections::new(
                RtoConfig { initial: INITIAL_RTO, ..Default::default() },
                5
            )
            .with_syn_rcv_and_pkt_last_sent(now),
            shutdown_deadline: Some(now.try_add(Duration::from_secs(30))?),
            ..decision_test_server()
        }
        .poll_timeout(now),
        Some(INITIAL_RTO),
        "The near-term retransmit deadline should win the `min`, not the far future shutdown \
         deadline"
    );

    Ok(())
}

#[test]
fn earlier_shutdown_deadline_taken_over_later_retransmit_deadline() -> TraceableResult {
    const GRACE_PERIOD: Duration = Duration::from_millis(250);

    let now = Instant::now();

    assert_eq!(
        Server {
            tcp_connections: TcpConnections::new(
                RtoConfig { initial: Duration::from_secs(30), ..Default::default() },
                5
            )
            .with_syn_rcv(),
            shutdown_deadline: Some(now.try_add(GRACE_PERIOD)?),
            ..decision_test_server()
        }
        .poll_timeout(now),
        Some(GRACE_PERIOD),
        "The near-term shutdown deadline should win the `min`, not the far future retransmit \
         deadline"
    );

    Ok(())
}

#[test]
fn past_deadline_saturates_to_zero() -> TraceableResult {
    let now = Instant::now();

    assert_eq!(
        Server {
            shutdown_deadline: Some(
                now.checked_sub(Duration::from_secs(10))
                    .ok_or("underflow")?
            ),
            ..decision_test_server()
        }
        .poll_timeout(now),
        Some(Duration::ZERO)
    );

    Ok(())
}

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
