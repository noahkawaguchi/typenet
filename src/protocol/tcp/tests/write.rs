use {super::*, pretty_assertions::assert_eq};

#[test]
fn write_into_produces_correct_bytes_with_no_payload() -> Result {
    let seg = TcpSegment::<Local> {
        ip_pair: LOCAL_TO_REMOTE_IP_PAIR,
        ports: PortPair::new(80, 1234),
        seq_num: SeqPoint::new(0x1000_0000),
        ack_num: SeqPoint::new(0x0000_1001),
        offset_bytes: 20,
        flags: TcpFlags::SynAck,
        window: SeqOffset::new(29_200),
        payload: None,
    };

    let mut reply = [0u8; ETHERNET_MTU];
    let tcp_len = seg.write_into(&mut reply[20..])?;

    assert_eq!(tcp_len, 20, "no payload, so length is just the header");

    assert_eq!(&reply[20..22], &[0x00, 0x50]); // Source port: 80
    assert_eq!(&reply[22..24], &[0x04, 0xD2]); // Dest port: 1234
    assert_eq!(&reply[24..28], &[0x10, 0x00, 0x00, 0x00]); // Seq num
    assert_eq!(&reply[28..32], &[0x00, 0x00, 0x10, 0x01]); // Ack num
    assert_eq!(reply[32], 0x50); // Data offset: 5 (20 bytes), reserved bits: 0
    assert_eq!(reply[33], 0x12); // Flags: SYN|ACK
    assert_eq!(&reply[34..36], &[0x72, 0x10]); // Window size: 29,200
    assert_eq!(&reply[38..40], &[0x00, 0x00]); // Urgent pointer

    assert_eq!(pseudo_hdr_cksum(&reply[20..40], REMOTE_TO_LOCAL_IP_PAIR, Protocol::Tcp)?, 0);

    Ok(())
}

#[test]
fn write_into_produces_correct_bytes_with_payload() -> Result {
    let seg = TcpSegment::<Local> {
        ip_pair: LOCAL_TO_REMOTE_IP_PAIR,
        ports: PortPair::new(80, 1234),
        seq_num: SeqPoint::new(1),
        ack_num: SeqPoint::new(4102),
        offset_bytes: 20,
        flags: TcpFlags::Ack,
        window: SeqOffset::new(u16::MAX),
        payload: TcpPayload::from_test_str("Hello")?,
    };

    let mut reply = [0u8; ETHERNET_MTU];
    let tcp_len = seg.write_into(&mut reply[20..])?;

    assert_eq!(tcp_len, 25, "header (20 bytes) + payload (5 bytes)");

    // Payload copied immediately after the 20-byte header
    assert_eq!(&reply[40..45], b"Hello");

    assert_eq!(pseudo_hdr_cksum(&reply[20..45], REMOTE_TO_LOCAL_IP_PAIR, Protocol::Tcp)?, 0);

    Ok(())
}
