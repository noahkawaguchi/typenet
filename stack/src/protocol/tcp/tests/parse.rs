use {super::*, pretty_assertions::assert_eq};

#[test]
fn correct_for_valid_segment() -> TraceableResult {
    #[rustfmt::skip]
        const DATA: [u8; 25] = [
            0x04, 0xD2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x01,              // Sequence number: 1
            0x00, 0x00, 0x00, 0x02,              // Ack number: 2
            0x50, 0x12,                          // Data offset: 5 (20 bytes), Flags: SYN|ACK
            0x72, 0x10,                          // Window size: 29,200
            0x00, 0xC4,                          // Checksum (valid for this segment and IP pair)
            0x00, 0x00,                          // Urgent pointer
            0x48, 0x65, 0x6C, 0x6C, 0x6F,        // Payload: "Hello"
        ];

    let seg = TcpSegment::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR)?;

    assert_eq!(seg.ports, PortPair::new(1234, 80));
    assert_eq!(seg.seq_num, SeqPoint::new(1));
    assert_eq!(seg.ack_num, SeqPoint::new(2));
    assert_eq!(seg.offset_bytes, 20);
    assert_eq!(seg.flags, TcpFlags::SynAck);
    assert_eq!(seg.window, SeqOffset::new(29_200));
    assert_eq!(seg.payload.as_ref().map(TcpPayload::as_bytes), Some("Hello".as_ref()));

    Ok(())
}

#[test]
fn fails_when_too_short() {
    const DATA: [u8; 4] = [0x04, 0xD2, 0x00, 0x50]; // Only 4 bytes

    assert_matches!(
        TcpSegment::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR),
        Err(e) if e.to_string().contains("Too short")
    );
}

#[test]
fn fails_for_invalid_cksum() {
    #[rustfmt::skip]
        const DATA: [u8; 25] = [
            0x04, 0xD2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0x00, 0x00, 0x00, 0x01,              // Sequence number: 1
            0x00, 0x00, 0x00, 0x02,              // Ack number: 2
            0x50, 0x12,                          // Data offset: 5 (20 bytes), Flags: SYN|ACK
            0xFF, 0xFF,                          // Window size
            0x00, 0x00,                          // Checksum (wrong, should be 0x72D4)
            0x00, 0x00,                          // Urgent pointer
            0x48, 0x65, 0x6C, 0x6C, 0x6F,        // Payload: "Hello"
        ];

    assert_matches!(
        TcpSegment::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR),
        Err(e) if e.to_string().contains("checksum")
    );
}

#[test]
fn handles_large_sequence_numbers() -> TraceableResult {
    #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x04, 0xD2,                          // Source port: 1234
            0x00, 0x50,                          // Dest port: 80
            0xFF, 0xFF, 0xFF, 0xFF,              // Sequence number: `u32::MAX`
            0xFE, 0xDC, 0xBA, 0x98,              // Ack number: 4_275_878_552
            0x50, 0x10,                          // Data offset: 5, Flags: ACK
            0xFF, 0xFF,                          // Window size
            0xDD, 0x3A,                          // Checksum (valid for this segment and IP pair)
            0x00, 0x00,                          // Urgent pointer
        ];

    let seg = TcpSegment::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR)?;

    assert_eq!(seg.seq_num, SeqPoint::new(u32::MAX));
    assert_eq!(seg.ack_num, SeqPoint::new(0xFEDC_BA98));

    Ok(())
}
