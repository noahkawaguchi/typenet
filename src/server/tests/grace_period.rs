use super::*;

#[test]
fn grace_period_not_elapsed_with_no_deadline() {
    assert!(!decision_test_server().grace_period_elapsed(Instant::now()));
}

#[test]
fn grace_period_not_elapsed_before_deadline() -> TraceableResult {
    let now = Instant::now();

    assert!(
        !Server {
            shutdown_deadline: Some(now.try_add(Duration::from_secs(10))?),
            ..decision_test_server()
        }
        .grace_period_elapsed(now)
    );

    Ok(())
}

#[test]
fn grace_period_elapsed_past_deadline() -> TraceableResult {
    let now = Instant::now();

    assert!(
        Server {
            shutdown_deadline: Some(
                now.checked_sub(Duration::from_secs(10))
                    .ok_or("underflow")?
            ),
            ..decision_test_server()
        }
        .grace_period_elapsed(now)
    );

    Ok(())
}

#[test]
fn grace_period_elapsed_at_deadline() {
    let now = Instant::now();

    assert!(
        Server { shutdown_deadline: Some(now), ..decision_test_server() }.grace_period_elapsed(now)
    );
}
