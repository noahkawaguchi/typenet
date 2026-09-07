use {super::*, pretty_assertions::assert_eq};

#[test]
fn ipv4_parse_error_is_skipped() {
    assert_matches!(
        decision_test_server().parse_incoming(&[0u8; 5]),
        Err(e) if e.to_string().contains("Skipping packet") && e.to_string().contains("IPv4")
    );
}

#[test]
fn ipv4_ok_but_tcp_parse_error_is_skipped() -> Result {
    // Reads a valid IPv4 header claiming a 4-byte TCP payload (far too short), so IPv4 parsing
    // succeeds while TCP parsing fails

    let fixture = TcpSegment::CLIENT_SYN;
    let mut buf = [0u8; ETHERNET_MTU];

    let ipv4_hdr = Ipv4Header::test_try_new_remote(fixture.proto(), fixture.get_ip_pair(), 4)?;
    ipv4_hdr.test_write_into_remote(&mut buf);

    assert_matches!(
        decision_test_server().parse_incoming(buf.try_get(..ipv4_hdr.total_len.into())?),
        Err(e) if e.to_string().contains("Skipping packet") && e.to_string().contains("TCP")
    );

    Ok(())
}

#[test]
fn syn_parses_and_produces_a_reply() -> Result {
    let bytes = encode_mock_pkt(&TcpSegment::CLIENT_SYN)?;

    assert_matches!(
        Server { tcp_connections: TcpConnections::default(), ..decision_test_server() }
            .parse_incoming(&bytes),
        Ok(ParsedExchange {
            ipv4_hdr: _,
            incoming_router: ProtocolRouter::Tcp(_),
            reply_router: Some(ProtocolRouter::Tcp(_)),
        })
    );

    Ok(())
}

#[test]
fn handshake_ack_parses_and_produces_no_reply() -> Result {
    let bytes = encode_mock_pkt(&TcpSegment::CLIENT_ACK_COMPLETING_HANDSHAKE)?;

    assert_matches!(
        Server {
            tcp_connections: TcpConnections::default().with_syn_rcv(),
            ..decision_test_server()
        }
        .parse_incoming(&bytes),
        Ok(ParsedExchange {
            ipv4_hdr: _,
            incoming_router: ProtocolRouter::Tcp(_),
            reply_router: None
        })
    );

    Ok(())
}

#[test]
fn malformed_pkt_is_skipped_without_propagating_or_writing() -> Result {
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
fn valid_syn_producing_a_reply_is_sent() -> Result {
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
fn valid_ack_completing_handshake_produces_no_reply() -> Result {
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
