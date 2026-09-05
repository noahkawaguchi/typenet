use super::*;

#[test]
fn creates_valid_data_echo() -> Result {
    // rcv_nxt = client's seq at handshake ACK time
    let mut connections = TcpConnections::default().after_handshake();

    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
            payload: TcpPayload::from_test_str("Hello")?,
            ..SERVER_REPLY
        })
    );

    Ok(())
}

#[test]
fn pure_ack_on_established_connection_returns_none() -> Result {
    // Simulates the client ACKing the server's echo reply. This should get no reply (not RST) so
    // the connection stays open for more data.

    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    cloned_state.snd_nxt += LOCAL_HELLO_LEN;
    cloned_state.rcv_nxt += REMOTE_HELLO_LEN;

    // ack=SERVER_ISN + 5 bytes echoed + 1
    let pure_ack = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN,
        ..CLIENT_PKT
    };

    assert_eq!(pure_ack.create_reply(&mut connections)?, None);

    cloned_state.snd_una += LOCAL_HELLO_LEN;
    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        pure_ack.window,
        pure_ack.seq_num,
        pure_ack.ack_num,
    )));

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Connection should remain open after pure ACK"
    );

    Ok(())
}

#[test]
fn consecutive_replies_use_snd_nxt_for_seq_num() -> Result {
    // Verifies that the server updates and uses its own snd_nxt for seq_num rather than simply
    // mirroring the client's ack_num. After sending a 5-byte echo, snd_nxt=SERVER_ISN+6, then the
    // next reply's seq_num must be SERVER_ISN+6 even when the client sends a stale
    // ack_num=SERVER_ISN+1.

    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();

    // First data packet: "Hello" (5 bytes), ack=SERVER_ISN+1 (acknowledges our ISN+1)
    let reply1 = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply1,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
            payload: TcpPayload::from_test_str("Hello")?,
            ..SERVER_REPLY
        }),
        "Standard reply to the first data packet"
    );

    cloned_state.snd_nxt += LOCAL_HELLO_LEN;
    cloned_state.rcv_nxt += REMOTE_HELLO_LEN;
    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Stored snd_nxt should be SERVER_ISN + 1 + 5 bytes echoed between replies"
    );

    // Second data packet: "Hi" (2 bytes), but with stale ack=SERVER_ISN+1 (hasn't ACKed our "Hello"
    // echo)
    let reply2 = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hi")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply2,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_HI_LEN,
            payload: TcpPayload::from_test_str("Hi")?,
            ..SERVER_REPLY
        }),
        "Server's seq_num should be snd_nxt=SERVER_ISN+6, not client's stale ack_num=SERVER_ISN+1"
    );

    Ok(())
}

#[test]
fn old_ack_num_does_not_regress_snd_una() -> Result {
    // SND.UNA should only ever advance on a "new" ack (RFC 9293, Section 3.10.7.4). After two
    // exchanges bring SND.UNA up to SERVER_ISN+6, a third packet with a stale ack_num=SERVER_ISN+1
    // (now older than SND.UNA) must not move SND.UNA backward, even though the segment is
    // otherwise processed normally (seq_num still matches RCV.NXT).

    // SND.UNA=SND.NXT=SERVER_ISN+1, RCV.NXT=CLIENT_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let mut cloned_state = connections.try_get()?.clone();
    assert_eq!(cloned_state.snd_una, SERVER_ISN + LOCAL_SYN_BYTE);

    // First packet: "Hello" (5 bytes), ack=SERVER_ISN+1 -> SND.UNA is SERVER_ISN+1, SND.NXT becomes
    // SERVER_ISN+6
    let reply1 = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply1,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
            payload: TcpPayload::from_test_str("Hello")?,
            ..SERVER_REPLY
        }),
        "Standard reply to the first data packet"
    );

    cloned_state.snd_nxt += LOCAL_HELLO_LEN;
    cloned_state.rcv_nxt += REMOTE_HELLO_LEN;
    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "SND.UNA should still be SERVER_ISN+1 after the first data packet"
    );

    // Second packet: "Hi" (2 bytes), ack=SERVER_ISN+6 -> SND.UNA advances to SERVER_ISN+6, SND.NXT
    // becomes SERVER_ISN+8
    let hi_pkt = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN,
        payload: TcpPayload::from_test_str("Hi")?,
        ..CLIENT_PKT
    };

    let reply2 = hi_pkt.create_reply(&mut connections)?;

    assert_eq!(
        reply2,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_HI_LEN,
            payload: TcpPayload::from_test_str("Hi")?,
            ..SERVER_REPLY
        }),
        "Standard reply to the second data packet"
    );

    cloned_state.snd_nxt += LOCAL_HI_LEN;
    cloned_state.rcv_nxt += REMOTE_HI_LEN;
    cloned_state.snd_una += LOCAL_HELLO_LEN;
    cloned_state.tcp_state = TcpState::Established(SyncedState::test_new(WindowState::test_new(
        hi_pkt.window,
        hi_pkt.seq_num,
        hi_pkt.ack_num,
    )));

    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "SND.UNA should be SERVER_ISN+6 after the second data packet"
    );

    // Third packet: "Hey" (3 bytes), ack=SERVER_ISN+1 (now stale, older than SND.UNA=SERVER_ISN+6)
    let reply3 = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_HI_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hey")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    // The stale ack_num doesn't make the segment unacceptable (SERVER_ISN+1 <=
    // SND.NXT=SERVER_ISN+8), so it's still processed normally and "Hey" is echoed
    assert_eq!(
        reply3,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN + LOCAL_HI_LEN,
            ack_num: CLIENT_ISN
                + REMOTE_SYN_BYTE
                + REMOTE_HELLO_LEN
                + REMOTE_HI_LEN
                + REMOTE_HEY_LEN,
            payload: TcpPayload::from_test_str("Hey")?,
            ..SERVER_REPLY
        }),
        "Stale ack_num shouldn't prevent normal processing"
    );

    cloned_state.snd_nxt += LOCAL_HEY_LEN;
    cloned_state.rcv_nxt += REMOTE_HEY_LEN;
    assert_eq!(
        connections.try_get()?,
        &cloned_state,
        "Stale ack_num=SERVER_ISN+1 must not move SND.UNA backward from SERVER_ISN+6"
    );

    Ok(())
}

#[test]
fn duplicate_data_pkt_gets_duplicate_ack_without_echo() -> Result {
    // A retransmitted segment should get a duplicate ACK pointing at the current rcv_nxt, not
    // another echo. Processing a second distinct packet first makes the seq_num check meaningful
    // because the retransmitted packet's seq+len points back to CLIENT_ISN+6, but rcv_nxt is
    // CLIENT_ISN+8 after both deliveries.

    let mut connections = TcpConnections::default().after_handshake();

    let hello = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    };

    let hi = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN,
        payload: TcpPayload::from_test_str("Hi")?,
        ..CLIENT_PKT
    };

    // First packet: "Hello" (seq=CLIENT_ISN+1) -> rcv_nxt advances to CLIENT_ISN+6, snd_nxt
    // advances to SERVER_ISN+6
    assert_eq!(
        hello.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN,
            payload: TcpPayload::from_test_str("Hello")?,
            ..SERVER_REPLY
        }),
        "Standard reply to the first data packet"
    );

    // Second packet: "Hi" (seq=CLIENT_ISN+6) -> rcv_nxt advances to CLIENT_ISN+8, snd_nxt advances
    // to SERVER_ISN+8
    assert_eq!(
        hi.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_HI_LEN,
            payload: TcpPayload::from_test_str("Hi")?,
            ..SERVER_REPLY
        }),
        "Standard reply to the second data packet"
    );

    // Retransmit of "Hello": seq=CLIENT_ISN+1, but rcv_nxt is now CLIENT_ISN+8
    assert_eq!(
        hello.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE + LOCAL_HELLO_LEN + LOCAL_HI_LEN,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE + REMOTE_HELLO_LEN + REMOTE_HI_LEN,
            ..SERVER_REPLY
        }),
        "Duplicate ACK should ack rcv_nxt=CLIENT_ISN+8 with no payload, not echo \
         seq+len=CLIENT_ISN+6"
    );

    Ok(())
}

#[test]
fn stale_pure_ack_gets_duplicate_ack_without_updating_state() -> Result {
    // Per RFC 9293, Section 3.10.7.4, "First, check sequence number" applies to every segment,
    // including a payload-less ACK, and takes priority over "Fifth, check the ACK field." A pure
    // ACK whose SEG.SEQ fails that check must be dropped and get a current state reply.

    let mut connections = TcpConnections::default().after_handshake();
    let initial_state = connections.try_get()?.clone();

    // Carries a sequence number from before RCV.NXT, and a distinctive window that must not get
    // adopted
    let stale_pure_ack = TcpSegment {
        seq_num: CLIENT_ISN,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        window: SeqOffset::new(1234),
        ..CLIENT_PKT
    };

    assert_eq!(
        stale_pure_ack.create_reply(&mut connections)?,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        }),
        "A stale pure ACK should get a duplicate ACK reflecting current state"
    );

    assert_eq!(
        connections.try_get()?,
        &initial_state,
        "The connection should be untouched, its window not adopted"
    );

    Ok(())
}

#[test]
fn ack_for_unsent_data_is_dropped_and_gets_current_state_reply() -> Result {
    // Per RFC 9293 Section 3.10.7.4, an ACK acknowledging data the server hasn't sent yet (ack_num
    // past SND.NXT) must be dropped, and the reply should be a bare ACK reflecting the current
    // SND.NXT/RCV.NXT, with no payload echoed and no state change. seq_num matches RCV.NXT, so this
    // would otherwise be treated as valid in-order data.

    // SND.NXT=SERVER_ISN+1, RCV.NXT=CLIENT_ISN+1
    let mut connections = TcpConnections::default().after_handshake();
    let initial_state = connections.try_get()?.clone();

    // seq_num == RCV.NXT, but ack_num=SERVER_ISN+20 is past SND.NXT=SERVER_ISN+1
    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + SeqOffset::new(20),
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        })
    );

    assert_eq!(connections.try_get()?, &initial_state, "State must be untouched");

    Ok(())
}

#[test]
fn wraparound_ack_for_unsent_data_is_still_rejected() -> Result {
    // ISNs are random (RFC 9293, Section 3.4.1) and can land near `u32::MAX`, wrapping SND.NXT to a
    // small value. An ack_num that wraps one past SND.NXT must still be recognized as acknowledging
    // unsent data, even though a naive numeric comparison (ack_num > snd_nxt) would say 0 >
    // `u32::MAX` is false and let it through.

    let mut connections = TcpConnections::default();
    let initial_state = ConnState {
        tcp_state: TcpState::Established(SyncedState::test_new(WindowState::test_new(
            SeqOffset::new(u16::MAX),
            CLIENT_ISN + REMOTE_SYN_BYTE,
            SeqPoint::new(u32::MAX),
        ))),
        snd_nxt: SeqPoint::new(u32::MAX),
        snd_una: SeqPoint::new(u32::MAX),
        ..AFTER_HANDSHAKE
    };
    connections.insert(initial_state.clone());

    // ack=0 wraps 1 past SND.NXT=`u32::MAX`
    let reply = TcpSegment { seq_num: CLIENT_ISN + REMOTE_SYN_BYTE, ..CLIENT_PKT }
        .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SeqPoint::new(u32::MAX),
            ack_num: CLIENT_ISN + REMOTE_SYN_BYTE,
            ..SERVER_REPLY
        })
    );

    assert_eq!(connections.try_get()?, &initial_state, "State must be untouched");

    Ok(())
}

#[test]
fn data_pkt_for_unknown_connection_gets_rst() -> Result {
    // ACK with payload for a connection the server has no record of (e.g. after restart)

    let mut connections = TcpConnections::default(); // Empty, no known connections

    let reply = TcpSegment {
        seq_num: CLIENT_ISN + REMOTE_SYN_BYTE,
        ack_num: SERVER_ISN + LOCAL_SYN_BYTE,
        payload: TcpPayload::from_test_str("Hello")?,
        ..CLIENT_PKT
    }
    .create_reply(&mut connections)?;

    assert_eq!(
        reply,
        Some(TcpSegment {
            seq_num: SERVER_ISN + LOCAL_SYN_BYTE,
            flags: TcpFlags::Rst,
            ..SERVER_REPLY
        })
    );

    Ok(())
}
