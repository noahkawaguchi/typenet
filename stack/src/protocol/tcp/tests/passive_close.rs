use {super::*, pretty_assertions::assert_eq};

#[test]
fn fin_ack_in_syn_received_establishes_and_closes_immediately() -> TraceableResult {
    // A FIN-ACK arriving in SYN-RECEIVED can legitimately complete the handshake and initiate
    // passive close in the same segment. RFC 9293, Section 3.10.7.4 processes "Fifth, check the ACK
    // field" (in SYN-RECEIVED completing the handshake) before "Eighth, check the FIN bit", so this
    // must establish the connection and then immediately start closing, skipping CLOSE-WAIT due to
    // the current simplification the same way a FIN-ACK in ESTABLISHED does.

    let mut connections = TcpConnections::default().with_syn_rcv();
    let mut cloned_state = connections.try_get()?.clone();

    let client_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    assert_eq!(
        client_fin_ack.create_test_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + FIN_BYTE_IN,
            flags: TcpFlags::FinAck,
            ..SERVER_REPLY
        }),
        "handshake-completing FIN-ACK must establish the connection then get our own FIN-ACK"
    );

    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(
        WindowState::test_new(
            client_fin_ack.window,
            client_fin_ack.seq_num,
            client_fin_ack.ack_num,
        ),
        LastAck,
    ));
    cloned_state.data.snd_una += SYN_BYTE_OUT;
    cloned_state.data.snd_nxt += FIN_BYTE_OUT;
    cloned_state.data.rcv_nxt += FIN_BYTE_IN;

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "connection should be established then immediately moved to LAST-ACK, not left in \
         SYN-RECEIVED or reset"
    );

    Ok(())
}

#[test]
fn creates_valid_fin_ack() -> TraceableResult {
    // Simulate an established connection, FIN-ACK arrives at seq=CLIENT_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    let client_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    assert_eq!(
        client_fin_ack.create_test_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + FIN_BYTE_IN,
            flags: TcpFlags::FinAck,
            ..SERVER_REPLY
        })
    );

    // Connection is now in LAST-ACK state (waiting for client's final ACK), not yet removed
    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(
        WindowState::test_new(
            client_fin_ack.window,
            client_fin_ack.seq_num,
            client_fin_ack.ack_num,
        ),
        LastAck,
    ));
    cloned_state.data.snd_nxt += SYN_BYTE_OUT;
    cloned_state.data.rcv_nxt += FIN_BYTE_IN;

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn fin_ack_acks_prior_data_and_advances_snd_una() -> TraceableResult {
    // FIN-ACK also includes "check the ACK field" processing just like a plain ACK (RFC 9293,
    // Section 3.10.7.4). Its SEG.ACK can acknowledge data sent earlier in the connection, and that
    // must still advance SND.UNA and prune `pending`.

    // snd_nxt=snd_una=SERVER_ISN+1, rcv_nxt=CLIENT_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    // Client sends data, server echoes "Hello" back
    TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_test_reply(&mut connections)?;

    cloned_state.data.snd_nxt += HELLO_LEN_OUT;
    cloned_state.data.rcv_nxt += HELLO_LEN_IN;
    // snd_una left unchanged at this point because the "Hello" echo is unacked

    assert_eq!(
        {
            let pending = &connections.try_get()?.data.pending;
            (
                pending.len(),
                pending
                    .first()
                    .and_then(|seg| seg.peek_info().payload.as_ref().map(TcpPayload::as_bytes)),
            )
        },
        (1, Some("Hello".as_ref())),
        "intermediate `pending` should consist of the unacked \"Hello\" echo"
    );

    // Client's FIN-ACK arrives in order (seq=CLIENT_ISN+6) and acks the echoed "Hello"
    // (ack=SERVER_ISN+6)
    let client_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT + HELLO_LEN_OUT,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    client_fin_ack.create_test_reply(&mut connections)?;

    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(
        WindowState::test_new(
            client_fin_ack.window,
            client_fin_ack.seq_num,
            client_fin_ack.ack_num,
        ),
        LastAck,
    ));
    cloned_state.data.snd_nxt += FIN_BYTE_OUT;
    cloned_state.data.rcv_nxt += FIN_BYTE_IN;
    cloned_state.data.snd_una += HELLO_LEN_OUT;

    let final_state = connections.try_get()?;

    assert_eq!(
        final_state, &cloned_state,
        "SEG.ACK from FIN-ACK should advance SND.UNA just like a plain ACK"
    );

    assert_eq!(
        (
            final_state.data.pending.len(),
            final_state
                .data
                .pending
                .first()
                .map(|seg| seg.peek_info().flags)
        ),
        (1, Some(TcpFlags::FinAck)),
        "the fully acked \"Hello\" echo should be pruned from `pending`, leaving only the FIN-ACK"
    );

    Ok(())
}

#[test]
fn out_of_order_fin_ack_gets_duplicate_ack_without_closing() -> TraceableResult {
    // A FIN-ACK arriving before data preceding it (seq_num != rcv_nxt, e.g. an earlier data segment
    // was lost) must not be processed yet. Doing so would signal "no more data" before the missing
    // data has been delivered. Until the gap is filled, treat it like out-of-order data by sending
    // a duplicate ACK reflecting the current RCV.NXT without starting to close, but remember its
    // FIN position for later.

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt = CLIENT_ISN+1
    let mut cloned_state = connections.try_get()?.clone();

    // FIN-ACK arrives at seq=CLIENT_ISN+6, but rcv_nxt is still CLIENT_ISN+1 (a 5-byte gap)
    let client_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    assert_eq!(
        client_fin_ack.create_test_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN,
            ..SERVER_REPLY
        }),
        "out-of-order FIN-ACK should get a duplicate ACK reflecting rcv_nxt=CLIENT_ISN+1, not a \
         FIN-ACK in response"
    );

    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(
        WindowState::test_new(
            client_fin_ack.window,
            client_fin_ack.seq_num,
            client_fin_ack.ack_num,
        ),
        Established::test_new([], TcpReassembly::test_new([], Some(client_fin_ack.seq_num))),
    ));

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "connection must remain established, out-of-order FIN-ACK must not start closing, but its \
         FIN position should now be remembered"
    );

    Ok(())
}

#[test]
fn out_of_order_fin_ack_with_data_completes_close_once_gap_closes() -> TraceableResult {
    // A FIN-ACK carrying trailing data arrives in window but SEG.SEQ != RCV.NXT (an earlier data
    // segment hasn't arrived yet), so it must be buffered rather than acted on immediately. Once
    // the missing segment fills the gap, the connection should discover the peer's FIN has now been
    // reached and send our FIN in that same reply, echoing both segments' data together.

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt=CLIENT_ISN+1
    let mut cloned_state = connections.try_get()?.clone();

    // FIN-ACK carrying "Hi" arrives at seq=CLIENT_ISN+6, but rcv_nxt is still CLIENT_ISN+1
    let fin_ack_with_data = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str("Hi")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        fin_ack_with_data.create_test_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN,
            ..SERVER_REPLY
        }),
        "out-of-order FIN-ACK should get a duplicate ACK, not start closing yet"
    );

    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(
        WindowState::test_new(
            fin_ack_with_data.window,
            fin_ack_with_data.seq_num,
            fin_ack_with_data.ack_num,
        ),
        Established::test_new(
            [],
            TcpReassembly::test_new(
                [(
                    fin_ack_with_data.seq_num,
                    fin_ack_with_data
                        .payload
                        .clone()
                        .ok_or("expected fin_ack_with_data to carry a payload")?,
                )],
                Some(fin_ack_with_data.seq_num + HI_LEN_IN),
            ),
        ),
    ));

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "connection must remain ESTABLISHED, with the FIN-ACK's data buffered and its FIN \
         position remembered"
    );

    // "Hello" fills the gap
    let hello = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        hello.create_test_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN + HI_LEN_IN + FIN_BYTE_IN,
            flags: TcpFlags::FinAck,
            payload: TcpPayload::from_test_str("HelloHi")?,
            ..SERVER_REPLY
        }),
        "filling the gap should reveal the peer's previously buffered FIN, echoing both segments' \
         data together and replying with our FIN"
    );

    // The window state stays pinned to the FIN-ACK's values (not changing those of the "Hello") due
    // to the window update rules, even though "Hello" fills a gap in the data
    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(
        WindowState::test_new(
            fin_ack_with_data.window,
            fin_ack_with_data.seq_num,
            fin_ack_with_data.ack_num,
        ),
        LastAck,
    ));
    cloned_state.data.snd_nxt += HELLO_LEN_OUT + HI_LEN_OUT + FIN_BYTE_OUT;
    cloned_state.data.rcv_nxt += HELLO_LEN_IN + HI_LEN_IN + FIN_BYTE_IN;

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn final_ack_after_fin_ack_removes_connection_and_returns_none() -> TraceableResult {
    // Simulates the client's final ACK completing the 4-step close. Should get no reply (not RST)
    // so the client can close cleanly from TIME-WAIT.

    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    let client_fin_ack = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    client_fin_ack.create_test_reply(&mut connections)?;

    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(
        WindowState::test_new(
            client_fin_ack.window,
            client_fin_ack.seq_num,
            client_fin_ack.ack_num,
        ),
        LastAck,
    ));
    cloned_state.data.snd_nxt += FIN_BYTE_OUT;
    cloned_state.data.rcv_nxt += FIN_BYTE_IN;

    assert_eq!(connections.try_get()?, &cloned_state);

    // ack=SERVER_ISN+2 (our FIN-ACK seq + 1)
    assert_eq!(
        TcpSegment {
            seq_num: CLIENT_ISN + SYN_BYTE_IN + FIN_BYTE_IN,
            ack_num: SERVER_ISN + SYN_BYTE_OUT + FIN_BYTE_OUT,
            ..CLIENT_PKT
        }
        .create_test_reply(&mut connections)?,
        None
    );

    assert_matches!(connections.try_get(), Err(_), "connection should be removed after final ACK");

    Ok(())
}

#[test]
fn fin_ack_with_data_in_established_echoes_data_and_starts_closing() -> TraceableResult {
    // A FIN-ACK carrying trailing data on an established connection should echo the data (like
    // plain in-order data) before closing. Unlike FIN-WAIT-1/2, our own FIN hasn't been sent yet
    // here, so it can be piggybacked on the same FIN-ACK reply.

    let mut connections = TcpConnections::default().after_handshake(); // rcv_nxt=CLIENT_ISN+1
    let mut cloned_state = connections.try_get()?.clone();

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
            seq_num: SERVER_ISN + SYN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN + FIN_BYTE_IN,
            flags: TcpFlags::FinAck,
            payload: TcpPayload::from_test_str("Hello")?,
            ..SERVER_REPLY
        }),
        "data should be echoed and piggybacked on the FIN-ACK, with the ACK covering both the \
         data and the FIN"
    );

    cloned_state.tcp_state = TcpState::LastAck(SyncedState::test_new(
        WindowState::test_new(
            fin_ack_with_data.window,
            fin_ack_with_data.seq_num,
            fin_ack_with_data.ack_num,
        ),
        LastAck,
    ));
    cloned_state.data.snd_nxt += HELLO_LEN_OUT + FIN_BYTE_OUT;
    cloned_state.data.rcv_nxt += HELLO_LEN_IN + FIN_BYTE_IN;

    assert_eq!(connections.try_get()?, &cloned_state);

    Ok(())
}

#[test]
fn fin_ack_with_data_in_established_defers_fin_until_remainder_drains() -> TraceableResult {
    // If the peer's advertised window can't fit all the trailing data right now, only what fits
    // gets echoed as a plain ACK, with the rest buffered in the send buffer. Since not everything
    // has been sent yet, our own FIN must not go out yet either. The connection enters CLOSE-WAIT,
    // and once the peer acks and opens the window enough to drain the rest, the remainder is sent
    // with our FIN finally piggybacked on it, completing the move to LAST-ACK.

    const SMALL_WINDOW: SeqOffset<u16, Out> = SeqOffset::new(3);
    const LARGER_WINDOW: SeqOffset<u16, Out> = SeqOffset::new(10);
    const LO_LEN: SeqOffset<u32, Out> = SeqOffset::new(2);

    let mut connections = TcpConnections::default();
    let mut expected_state = ConnState {
        tcp_state: TcpState::Established(SyncedState::test_new(
            WindowState::test_new(
                SMALL_WINDOW,
                CLIENT_ISN + SYN_BYTE_IN,
                SERVER_ISN + SYN_BYTE_OUT,
            ),
            Established::test_empty(),
        )),
        ..AFTER_HANDSHAKE
    };
    connections.test_insert(expected_state.clone());

    let fin_ack_with_data = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        window: SMALL_WINDOW,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        fin_ack_with_data.create_test_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN + FIN_BYTE_IN,
            payload: TcpPayload::from_test_str("Hel")?,
            ..SERVER_REPLY
        }),
        "only the first 3 out of 5 bytes fit in the advertised window of 3, so our own FIN must \
         not be sent yet "
    );

    expected_state.tcp_state = TcpState::CloseWait(SyncedState::test_new(
        WindowState::test_new(
            fin_ack_with_data.window,
            fin_ack_with_data.seq_num,
            fin_ack_with_data.ack_num,
        ),
        CloseWait::test_new(*b"lo"),
    ));
    expected_state.data.snd_nxt += SeqOffset::<u32, Out>::from(SMALL_WINDOW);
    expected_state.data.rcv_nxt += HELLO_LEN_IN + FIN_BYTE_IN;

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "the untransmittable remainder \"lo\" should be queued in the send buffer, with the \
         connection held in CLOSE-WAIT"
    );

    // Peer acks the 3 sent bytes and opens the window enough to take the rest
    let window_update = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN + FIN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT + SMALL_WINDOW.into(),
        window: LARGER_WINDOW,
        ..CLIENT_PKT
    };

    assert_eq!(
        window_update.create_test_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT + SMALL_WINDOW.into(),
            ack_num: CLIENT_ISN + SYN_BYTE_IN + HELLO_LEN_IN + FIN_BYTE_IN,
            flags: TcpFlags::FinAck,
            payload: TcpPayload::from_test_str("lo")?,
            ..SERVER_REPLY
        }),
        "once the buffer fully drains, our FIN should finally go out, piggybacked on the last \
         chunk"
    );

    expected_state.tcp_state = TcpState::LastAck(SyncedState::test_new(
        WindowState::test_new(window_update.window, window_update.seq_num, window_update.ack_num),
        LastAck,
    ));
    expected_state.data.snd_una += SMALL_WINDOW.into();
    expected_state.data.snd_nxt += LO_LEN + FIN_BYTE_OUT;
    // No send buffer to check, since LAST-ACK only exists once it has been fully drained

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "the connection should now be fully drained and in LAST-ACK, awaiting the final ACK"
    );

    Ok(())
}

#[test]
fn reassembled_backlog_larger_than_one_segment_defers_fin_until_drained() -> TraceableResult {
    // Filling a gap left by packet loss can reveal more previously-buffered data than fits in a
    // single segment's payload, with the peer's FIN sitting right after all of it. Every byte of
    // that backlog must still reach the peer, so only as much as fits in one segment goes out right
    // away. The rest stays queued, and our own FIN is only sent once the whole backlog has gone
    // out.

    const MAX_PAYLOAD_LEN: usize =
        ETHERNET_MTU - Ipv4Header::REPLY_HDR_LEN - TCP_HDR_MIN_LEN as usize;

    /// Ensures that this test is reexamined if the relevant consts change.
    const _: () = assert!(MAX_PAYLOAD_LEN == 1500 - 20 - 20);

    let mut connections = TcpConnections::default().after_handshake();
    let mut expected_state = connections.try_get()?.clone();

    // The gap-filling chunk is itself already bigger than one segment
    let gap_payload = "a".repeat(MAX_PAYLOAD_LEN + 50);
    let gap_len = SeqOffset::<u32, In>::new(u32::try_from(gap_payload.len())?);

    let tail_payload = "b".repeat(100);
    let tail_len = SeqOffset::<u32, In>::new(u32::try_from(tail_payload.len())?);

    // FIN-ACK carrying the trailing chunk arrives first, out of order
    let fin_ack_tail = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN + gap_len,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        flags: TcpFlags::FinAck,
        payload: TcpPayload::from_test_str(&tail_payload)?,
        ..CLIENT_PKT
    };

    fin_ack_tail.create_test_reply(&mut connections)?;

    // Gap-filling segment reveals the whole backlog and the FIN at once
    let gap_filler = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT,
        payload: TcpPayload::from_test_str(&gap_payload)?,
        ..CLIENT_PKT
    };

    let capped_payload = "a".repeat(MAX_PAYLOAD_LEN);
    let max_len = SeqOffset::<u32, Out>::new(u32::try_from(MAX_PAYLOAD_LEN)?);

    assert_eq!(
        gap_filler.create_test_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + gap_len + tail_len + FIN_BYTE_IN,
            payload: TcpPayload::from_test_str(&capped_payload)?,
            ..SERVER_REPLY
        }),
        "filling the gap reveals more data than fits in one segment, but only {MAX_PAYLOAD_LEN} \
         bytes should go out, and our own FIN must not be sent yet"
    );

    let leftover = "a".repeat(50) + &tail_payload;

    // The window state stays pinned to the out-of-order FIN-ACK's values (not the gap-filling
    // chunk's, which arrives with an earlier sequence number) due to the window update rules
    expected_state.tcp_state = TcpState::CloseWait(SyncedState::test_new(
        WindowState::test_new(fin_ack_tail.window, fin_ack_tail.seq_num, fin_ack_tail.ack_num),
        CloseWait::test_new(leftover.as_bytes().to_vec()),
    ));
    expected_state.data.snd_nxt += max_len;
    expected_state.data.rcv_nxt += gap_len + tail_len + FIN_BYTE_IN;

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "the 150-byte remainder must stay queued rather than being lost, with the connection held \
         in CLOSE-WAIT"
    );

    // Peer acks the first `MAX_PAYLOAD_LEN` bytes. The window is already wide open, so the rest can
    // go out immediately along with our FIN.
    let window_update = TcpSegment {
        seq_num: CLIENT_ISN + SYN_BYTE_IN + gap_len + tail_len + FIN_BYTE_IN,
        ack_num: SERVER_ISN + SYN_BYTE_OUT + max_len,
        ..CLIENT_PKT
    };

    assert_eq!(
        window_update.create_test_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + SYN_BYTE_OUT + max_len,
            ack_num: CLIENT_ISN + SYN_BYTE_IN + gap_len + tail_len + FIN_BYTE_IN,
            flags: TcpFlags::FinAck,
            payload: TcpPayload::from_test_str(&leftover)?,
            ..SERVER_REPLY
        }),
        "once fully drained, the leftover 150 bytes should go out with our FIN finally attached"
    );

    expected_state.tcp_state = TcpState::LastAck(SyncedState::test_new(
        WindowState::test_new(window_update.window, window_update.seq_num, window_update.ack_num),
        LastAck,
    ));
    expected_state.data.snd_una += max_len;
    expected_state.data.snd_nxt +=
        SeqOffset::<u32, Out>::new(u32::try_from(leftover.len())?) + FIN_BYTE_OUT;
    // No send buffer to check, since LAST-ACK only exists once it has been fully drained

    assert_eq!(
        connections.try_get()?,
        &expected_state,
        "the connection should now be fully drained and in LAST-ACK, awaiting the final ACK"
    );

    Ok(())
}
