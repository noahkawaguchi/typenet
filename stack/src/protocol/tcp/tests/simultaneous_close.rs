use {super::*, pretty_assertions::assert_eq};

#[test]
fn simultaneous_close_transitions_through_closing_to_closed() -> TraceableResult {
    let mut connections = TcpConnections::default().after_handshake();
    connections.close_all(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Client's FIN arrives in order, but doesn't yet acknowledge our FIN (ack=SERVER_ISN+1,
    // simultaneous close) -> CLOSING
    let client_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    assert_eq!(
        client_fin_ack.create_test_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + FIN_BYTE_IN,
            ..SERVER_REPLY
        })
    );

    cloned_state.tcp_state = TcpState::Closing(SyncedState::test_new(
        WindowState::test_new(
            client_fin_ack.window,
            client_fin_ack.seq_num,
            client_fin_ack.ack_num,
        ),
        Closing,
    ));
    cloned_state.data.rcv_nxt += FIN_BYTE_IN;
    assert_eq!(connections.try_get()?, &cloned_state);

    // Client's ACK of our FIN finally arrives -> fully closed
    assert_eq!(
        TcpSegment {
            seq_num: CLIENT_ISN + SYN_BYTE_IN + FIN_BYTE_IN,
            ack_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
            ..CLIENT_PKT
        }
        .create_test_reply(&mut connections)?,
        None
    );

    assert_matches!(connections.try_get(), Err(_), "connection should be removed");

    Ok(())
}

#[test]
fn fin_ack_with_data_in_fin_wait_1_advances_rcv_nxt_past_data_and_fin() -> TraceableResult {
    // Simultaneous close where the peer's FIN carries trailing data. Our own FIN has already been
    // sent, so the data can't be echoed (same as plain data arriving in FIN-WAIT-1), but RCV.NXT
    // must still advance past both the data and the FIN's phantom byte.

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt=CLIENT_ISN+1
    connections.close_all(); // -> FIN-WAIT-1, snd_nxt=SERVER_ISN+2
    let mut cloned_state = connections.try_get()?.clone();

    // Client's FIN-ACK arrives in order with data, not yet acknowledging our FIN (ack=SERVER_ISN+1)
    let fin_ack_with_data = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        fin_ack_with_data.create_test_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN + FIN_BYTE_IN,
            ..SERVER_REPLY
        }),
        "ACK should reflect RCV.NXT advanced past both the data and the FIN, not just the FIN"
    );

    cloned_state.tcp_state = TcpState::Closing(SyncedState::test_new(
        WindowState::test_new(
            fin_ack_with_data.window,
            fin_ack_with_data.seq_num,
            fin_ack_with_data.ack_num,
        ),
        Closing,
    ));
    cloned_state.data.rcv_nxt += HELLO_LEN_IN + FIN_BYTE_IN;
    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}
