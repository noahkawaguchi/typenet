use super::*;

/// Fixed value to use as the ISN randomly chosen by the client.
pub const CLIENT_ISN: SeqPoint<Remote> = SeqPoint::new(100);

/// Fixed value to use as the ISN randomly chosen by the server.
pub const SERVER_ISN: SeqPoint<Local> = SeqPoint::new(400);

/// The number of bytes in the payload `"Hello"`, going in the local to remote direction.
pub const LOCAL_HELLO_LEN: SeqOffset<u32, Local> = SeqOffset::new(5);

/// The number of bytes in the payload `"Hi"`, going in the local to remote direction.
pub const LOCAL_HI_LEN: SeqOffset<u32, Local> = SeqOffset::new(2);

/// The number of bytes in the payload `"Hey"`, going in the local to remote direction.
pub const LOCAL_HEY_LEN: SeqOffset<u32, Local> = SeqOffset::new(3);

/// The number of bytes in the payload `"Hello"`, going in the remote to local direction.
pub const REMOTE_HELLO_LEN: SeqOffset<u32, Remote> = SeqOffset::new(5);

/// The number of bytes in the payload `"Hi"`, going in the remote to local direction.
pub const REMOTE_HI_LEN: SeqOffset<u32, Remote> = SeqOffset::new(2);

/// The number of bytes in the payload `"Hey"`, going in the remote to local direction.
pub const REMOTE_HEY_LEN: SeqOffset<u32, Remote> = SeqOffset::new(3);

/// Connection key shared by test modules.
pub const KEY: ConnKey = ConnKey {
    client_ip: REMOTE_TO_LOCAL_IP_PAIR.src,
    client_port: 1234,
    server_ip: REMOTE_TO_LOCAL_IP_PAIR.dst,
    server_port: 80,
};

/// The window state after the initial three-way handshake.
pub const WINDOW_AFTER_HANDSHAKE: WindowState = WindowState::test_new(
    SeqOffset::new(u16::MAX),
    CLIENT_ISN.const_add(REMOTE_SYN_BYTE),
    SERVER_ISN.const_add(LOCAL_SYN_BYTE),
);

/// An ESTABLISHED connection as if the initial three-way handshake had just completed. Uses the
/// test constants `CLIENT_ISN` and `SERVER_ISN`. Has the maximum SND.WND and empty
/// `pending`/`send_buffer`.
pub const AFTER_HANDSHAKE: ConnState = ConnState {
    tcp_state: TcpState::Established(SyncedState::test_new(WINDOW_AFTER_HANDSHAKE)),
    snd_nxt: SERVER_ISN.const_add(LOCAL_SYN_BYTE),
    rcv_nxt: CLIENT_ISN.const_add(REMOTE_SYN_BYTE),
    snd_una: SERVER_ISN.const_add(LOCAL_SYN_BYTE),
    pending: Vec::new(),
    send_buffer: VecDeque::new(),
    reassembly: TcpReassembly::new(),
};

/// An incoming pure ACK packet from the client (port 1234) to the server (port 80).
/// `seq_num` and `ack_num` will be 0 if not overridden.
pub const CLIENT_PKT: TcpSegment<Remote> = TcpSegment {
    ip_pair: Ipv4AddrPair::new(KEY.client_ip, KEY.server_ip),
    ports: PortPair::new(KEY.client_port, KEY.server_port),
    seq_num: SeqPoint::new(0),
    ack_num: SeqPoint::new(0),
    offset_bytes: 20,
    flags: TcpFlags::Ack,
    window: SeqOffset::new(u16::MAX),
    payload: None,
};

/// An outgoing pure ACK packet from the server (port 80) to the client (port 1234).
/// `seq_num` and `ack_num` will be 0 if not overridden.
pub const SERVER_REPLY: TcpSegment<Local> = TcpSegment {
    ip_pair: Ipv4AddrPair::new(KEY.server_ip, KEY.client_ip),
    ports: PortPair::new(KEY.server_port, KEY.client_port),
    seq_num: SeqPoint::new(0),
    ack_num: SeqPoint::new(0),
    offset_bytes: 20,
    flags: TcpFlags::Ack,
    window: SeqOffset::new(u16::MAX),
    payload: None,
};
