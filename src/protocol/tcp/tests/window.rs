use super::*;

#[test]
fn new_ack_adopts_window_from_segment() -> Result {
    // A "new" ack (SND.UNA < SEG.ACK <= SND.NXT) should also update SND.WND to the incoming
    // segment's advertised window (RFC 9293, Section 3.10.7.4), not just leave it at whatever it
    // was seeded with at handshake time.

    const NEW_WND: SeqOffset<u16, Local> = SeqOffset::new(12_345);

    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    assert_ne!(
        cloned_state.test_get_snd_wnd(),
        Some(NEW_WND),
        "The initial send window must differ from the updated one for the test to be meaningful"
    );

    // "Hello" data, ack=SERVER_ISN+1 == current SND.UNA, so not yet a "new" ack -> SND.NXT advances
    // to SERVER_ISN+6, but SND.WND stays untouched
    TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    cloned_state.snd_nxt += LOCAL_HELLO_LEN;
    cloned_state.rcv_nxt += REMOTE_HELLO_LEN;

    assert_eq!(connections.try_get()?, &cloned_state, "State confirmation before window update");

    // Pure ACK of that echo, ack=SERVER_ISN+6 (now "new"), advertising a new window
    let window_update = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN,
        window: NEW_WND,
        ..CLIENT_PKT
    };

    assert_eq!(window_update.create_reply(&mut connections)?, None);

    cloned_state.snd_una += LOCAL_HELLO_LEN;
    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        window_update.window,
        window_update.seq_num,
        window_update.ack_num,
    )));

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "SND.WND should adopt the new segment's advertised window"
    );

    Ok(())
}

#[test]
fn stale_segment_does_not_clobber_send_window() -> Result {
    // An out-of-order data segment still runs the window update check from RFC 9293, Section
    // 3.10.7.4, "Fifth, check the ACK bit", "ESTABLISHED STATE" even though its data can't be
    // delivered yet, so it can push SND.WL1 ahead of RCV.NXT while the gap before it remains open.
    // A later segment landing in that gap is still in-window relative to RCV.NXT, but it's stale
    // relative to the fresher SND.WL1 the out-of-order segment already set, and must not clobber
    // the window with a different SEG.WND.

    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    // A 10-byte gap remains before it (RCV.NXT stays at CLIENT_ISN+1), but its SEG.SEQ is fresher
    // than the handshake's SND.WL1=CLIENT_ISN+1, so it still updates the window
    let out_of_order = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + SeqOffset::new(10),
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        window: SeqOffset::new(2000),
        payload: TcpPayload::from_test_str("World")?,
        ..CLIENT_PKT
    };

    assert_eq!(
        out_of_order.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "Out-of-order data should still get a duplicate ACK reflecting RCV.NXT unchanged"
    );

    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        out_of_order.window,
        out_of_order.seq_num,
        out_of_order.ack_num,
    )));
    cloned_state.reassembly.insert(
        out_of_order.seq_num,
        out_of_order
            .payload
            .clone()
            .ok_or("Expected segment to carry a payload")?,
    );

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "The out-of-order segment should still update the window despite its data being buffered"
    );

    // Lands inside the still-open gap (seq=CLIENT_ISN+6): in-window relative to
    // RCV.NXT=CLIENT_ISN+1, but stale relative to the SND.WL1=CLIENT_ISN+11 the out-of-order
    // segment just set
    assert_eq!(
        TcpSegment {
            seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + SeqOffset::new(5),
            ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
            window: SeqOffset::new(9999),
            ..CLIENT_PKT
        }
        .create_reply(&mut connections)?,
        None
    );

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "SND.WND must not adopt the stale segment's window despite it being in-window relative to \
         RCV.NXT"
    );

    Ok(())
}

#[test]
fn same_seq_but_fresher_ack_updates_window() -> Result {
    // The window update condition is "SND.WL1 < SEG.SEQ or (SND.WL1 = SEG.SEQ and SND.WL2 =<
    // SEG.ACK)" (RFC 9293, Section 3.10.7.4). The equal-SEQ branch matters for pure ACKs, which
    // don't consume sequence numbers. Two of them in a row can carry the exact same SEG.SEQ while
    // still acknowledging more data than the last (e.g. a keep-alive style followup ack), and the
    // second one must still be allowed to update SND.WND.

    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    // Two data packets build up room for cumulative ACKs without ever giving the client's own
    // seq_num a chance to move past CLIENT_ISN+8 again
    TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    cloned_state.snd_nxt += LOCAL_HELLO_LEN;
    cloned_state.rcv_nxt += REMOTE_HELLO_LEN;
    assert_eq!(connections.try_get()?, &cloned_state);

    let hi_pkt = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hi")?,
        ..CLIENT_PKT
    };

    hi_pkt.create_reply(&mut connections)?;

    cloned_state.snd_nxt += LOCAL_HI_LEN;
    cloned_state.rcv_nxt += REMOTE_HI_LEN;
    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        hi_pkt.window,
        hi_pkt.seq_num,
        hi_pkt.ack_num,
    )));

    assert_eq!(connections.try_get()?, &cloned_state);

    // First pure ACK with seq=CLIENT_ISN+8 is fresher than the handshake's SND.WL1=CLIENT_ISN+1, so
    // this legitimately sets SND.WL1=CLIENT_ISN+8, SND.WL2=SERVER_ISN+6
    let window_update_1 = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_HI_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN,
        window: SeqOffset::new(1000),
        ..CLIENT_PKT
    };

    assert_eq!(window_update_1.create_reply(&mut connections)?, None);

    cloned_state.snd_una += LOCAL_HELLO_LEN;
    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        window_update_1.window,
        window_update_1.seq_num,
        window_update_1.ack_num,
    )));

    assert_eq!(connections.try_get()?, &cloned_state, "First window update should be adopted");

    // Second pure ACK with identical seq_num (no new data sent), but a strictly higher ack_num and
    // a different window
    let window_update_2 = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_HI_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN + LOCAL_HI_LEN,
        window: SeqOffset::new(2000),
        ..CLIENT_PKT
    };

    assert_eq!(window_update_2.create_reply(&mut connections)?, None);

    cloned_state.snd_una += LOCAL_HI_LEN;
    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        window_update_2.window,
        window_update_2.seq_num,
        window_update_2.ack_num,
    )));

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "SND.WND should still update when SEQ repeats but ACK is fresher"
    );

    Ok(())
}

#[test]
fn duplicate_ack_updates_window() -> Result {
    // RFC 9293, Section 3.10.7.4 gives two different conditions: SND.UNA only advances on a
    // "new" ACK (SND.UNA < SEG.ACK <= SND.NXT), but the send window update uses the non-strict
    // SND.UNA <= SEG.ACK <= SND.NXT. A duplicate ACK (SEG.ACK == SND.UNA) must still be allowed
    // to update SND.WND, such as a window-opening segment that doesn't acknowledge any new data.

    const NEW_WND: SeqOffset<u16, Local> = SeqOffset::new(777);

    // SND.UNA=SND.NXT=SERVER_ISN+1, RCV.NXT=CLIENT_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    assert_ne!(
        cloned_state.test_get_snd_wnd(),
        Some(NEW_WND),
        "The initial send window must differ from the updated one for the test to be meaningful"
    );

    // "Hello" data, ack=SERVER_ISN+1 == current SND.UNA (not a "new" ACK) -> RCV.NXT advances to
    // CLIENT_ISN+6, SND.NXT advances to SERVER_ISN+6, SND.UNA stays at SERVER_ISN+1
    TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    cloned_state.snd_nxt += LOCAL_HELLO_LEN;
    cloned_state.rcv_nxt += REMOTE_HELLO_LEN;

    assert_eq!(connections.try_get()?, &cloned_state, "State confirmation before window update");

    // Duplicate ACK where ack_num=SERVER_ISN+1 still equals SND.UNA (nothing new acknowledged), but
    // seq_num=CLIENT_ISN+6 is fresher than the stored SND.WL1=CLIENT_ISN+1, so this must still
    // update SND.WND to the new window
    let dup_ack_fresh_seq = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        window: NEW_WND,
        ..CLIENT_PKT
    };

    assert_eq!(dup_ack_fresh_seq.create_reply(&mut connections)?, None);

    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        dup_ack_fresh_seq.window,
        dup_ack_fresh_seq.seq_num,
        dup_ack_fresh_seq.ack_num,
    )));

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "SND.WND should update on a duplicate ack (SEG.ACK == SND.UNA) as long as SND.WL1 and \
         SND.WL2 allow it"
    );

    Ok(())
}
