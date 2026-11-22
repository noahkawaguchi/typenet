use {super::*, pretty_assertions::assert_eq};

#[test]
fn syn_to_listening_port_gets_syn_ack() -> TraceableResult {
    let mut connections = TcpConnections::default()
        .with_listen_ports(TcpListenPorts::Ports(HashSet::from([Port::comptime_new::<80>()])));

    let reply = TcpSegment::CLIENT_SYN.create_test_reply(&mut connections)?;

    // seq_num is the random ISN that was stored in the connection table
    let stored_isn = connections.try_get()?.data.snd_una;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: stored_isn,
            ack_num: SeqPoint::new(0) + SYN_BYTE_IN,
            flags: TcpFlags::SynAck,
            ..SERVER_REPLY
        })
    );

    Ok(())
}

#[test]
fn syn_to_closed_port_refused_with_rst_ack() -> TraceableResult {
    for (listen_ports, description) in [
        (
            TcpListenPorts::Ports(HashSet::from([Port::comptime_new::<8080>()])),
            "listening on other ports only",
        ),
        (TcpListenPorts::Ports(HashSet::new()), "not listening on any port"),
    ] {
        let mut connections = TcpConnections::default().with_listen_ports(listen_ports);

        let reply = TcpSegment { seq_num: CLIENT_ISN, flags: TcpFlags::Syn, ..CLIENT_PKT }
            .create_test_reply(&mut connections)?;

        assert_eq!(
            reply,
            Some(TcpSegment {
                seq_num: SeqPoint::new(0),
                ack_num: CLIENT_ISN + SYN_BYTE_IN,
                flags: TcpFlags::RstAck,
                ..SERVER_REPLY
            }),
            "{description}"
        );

        assert_eq!(connections.len(), 0, "{description}: no connection should be stored");
    }

    Ok(())
}

#[test]
fn syn_with_payload_to_closed_port_acks_syn_and_payload() -> TraceableResult {
    // SEG.LEN for a SYN counts the SYN itself plus any payload, so the RST-ACK must acknowledge
    // both for the peer to accept it (RFC 9293, Section 3.10.7.1)

    let mut connections =
        TcpConnections::default().with_listen_ports(TcpListenPorts::Ports(HashSet::new()));

    let reply = TcpSegment {
        seq_num: CLIENT_ISN,
        flags: TcpFlags::Syn,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_test_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SeqPoint::new(0),
            ack_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN,
            flags: TcpFlags::RstAck,
            ..SERVER_REPLY
        })
    );

    Ok(())
}

#[test]
fn ack_to_closed_port_gets_plain_rst() -> TraceableResult {
    // Segments with ACK set get <SEQ=SEG.ACK><CTL=RST> regardless of whether the port is
    // listening, since LISTEN and CLOSED only differ for SYN (RFC 9293, Sections 3.10.7.1 and
    // 3.10.7.2)

    let mut connections =
        TcpConnections::default().with_listen_ports(TcpListenPorts::Ports(HashSet::new()));

    let reply = TcpSegment { seq_num: CLIENT_ISN, ack_num: SERVER_ISN, ..CLIENT_PKT }
        .create_test_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN,
            ack_num: SeqPoint::new(0),
            flags: TcpFlags::Rst,
            ..SERVER_REPLY
        })
    );

    assert_eq!(connections.len(), 0, "no connection should be stored");

    Ok(())
}

#[test]
fn new_connections_refused_after_close_call() -> TraceableResult {
    /// A client port other than the default used for test constants, so the SYN below requests a
    /// new connection instead of landing on the connection already stored in the draining case.
    const OTHER_CLIENT_PORT: Port<Remote> = Port::comptime_new::<4321>();

    for (mut connections, expected_len, description) in [
        (TcpConnections::default(), 0, "no connections to close"),
        (TcpConnections::default().after_handshake(), 1, "established connection draining"),
    ] {
        connections.close_all();

        let reply = TcpSegment { src_port: OTHER_CLIENT_PORT, ..TcpSegment::CLIENT_SYN }
            .create_test_reply(&mut connections)?;

        assert_eq!(
            reply,
            Some(TcpSegment {
                dst_port: OTHER_CLIENT_PORT,
                seq_num: SeqPoint::new(0),
                ack_num: SeqPoint::new(0) + SYN_BYTE_IN,
                flags: TcpFlags::RstAck,
                ..SERVER_REPLY
            }),
            "{description}"
        );

        assert_eq!(
            connections.len(),
            expected_len,
            "{description}: no new connection should be stored"
        );
    }

    Ok(())
}
