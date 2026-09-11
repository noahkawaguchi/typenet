use {
    super::*,
    crate::{
        ETHERNET_MTU,
        ipv4_header::Ipv4Header,
        protocol::{
            tcp::{
                connections::ConnKey,
                reassembly::TcpReassembly,
                state::{ConnState, SyncedState, TcpState, WindowState},
            },
            test_consts::REMOTE_TO_LOCAL_IP_PAIR,
        },
    },
    std::collections::VecDeque,
};

/// Fixed value to use as the ISN randomly chosen by the client.
pub const CLIENT_ISN: SeqPoint<Remote> = SeqPoint::new(100);

/// Fixed value to use as the ISN randomly chosen by the server.
pub const SERVER_ISN: SeqPoint<Local> = SeqPoint::new(400);

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

impl TcpSegment<Remote> {
    /// A SYN requesting a new connection using the regular `CLIENT_PACKET` consts, which should
    /// generate a SYN-ACK reply.
    pub const CLIENT_SYN: Self = Self { flags: TcpFlags::Syn, ..CLIENT_PKT };

    /// The handshake-completing ACK matching the module's standard test consts, which should be
    /// accepted if in SYN-RECEIVED by transitioning to ESTABLISHED and replying with `None`.
    pub const CLIENT_ACK_COMPLETING_HANDSHAKE: Self = Self {
        seq_num: CLIENT_ISN.const_add(REMOTE_SYN_BYTE),
        ack_num: SERVER_ISN.const_add(LOCAL_SYN_BYTE),
        ..CLIENT_PKT
    };

    /// The client's FIN-ACK completing active close after our own FIN was sent (FIN-WAIT-1),
    /// which also acknowledges our FIN, so the connection should close immediately.
    pub const CLIENT_FIN_ACK_COMPLETING_CLOSE: Self = Self {
        seq_num: CLIENT_ISN.const_add(REMOTE_SYN_BYTE),
        ack_num: SERVER_ISN.const_add(LOCAL_SYN_BYTE.const_add(LOCAL_FIN_BYTE)),
        flags: TcpFlags::FinAck,
        ..CLIENT_PKT
    };

    /// Encodes `self` into a full IPv4 packet for testing purposes.
    ///
    /// This is test only because a segment from the remote endpoint would never be encoded into
    /// bytes in production.
    ///
    /// # Errors
    ///
    /// Returns `Err` if encoding `self` results in more than `ETHERNET_MTU` bytes or if arithmetic
    /// overflow occurs.
    pub fn encode_test_pkt(&self) -> TraceableResult<Vec<u8>> {
        let mut buf = [0u8; ETHERNET_MTU];
        self.write_into(&mut buf[Ipv4Header::REPLY_HDR_LEN..])?;

        let ipv4_hdr =
            Ipv4Header::test_try_new_remote(self.proto(), self.get_ip_pair(), self.proto_len()?)?;

        ipv4_hdr.test_write_into_remote(&mut buf);

        Ok(buf.try_get(..ipv4_hdr.total_len.into())?.to_vec())
    }
}

impl Encode<Remote> for TcpSegment<Remote> {
    fn write_into(&self, buf: &mut [u8]) -> TraceableResult { self.inner_write_into(buf) }
    fn proto(&self) -> Protocol { Protocol::Tcp }
    fn get_ip_pair(&self) -> Ipv4AddrPair<Remote> { self.ip_pair }
    fn proto_len(&self) -> TraceableResult<u16> { self.inner_proto_len() }
}

impl TcpSegment<Local> {
    /// The server's SYN-ACK reply for the standard SYN-RECEIVED connection using the module's
    /// standard test consts.
    pub const SERVER_SYN_ACK: Self = Self {
        seq_num: SERVER_ISN,
        ack_num: CLIENT_ISN.const_add(REMOTE_SYN_BYTE),
        flags: TcpFlags::SynAck,
        ..SERVER_REPLY
    };

    /// The server's FIN-ACK reply when actively initiating close right after the handshake for
    /// the standard connection using the module's test consts.
    pub const SERVER_FIN_ACK_INITIATING_CLOSE: Self = Self {
        seq_num: SERVER_ISN.const_add(LOCAL_SYN_BYTE),
        ack_num: CLIENT_ISN.const_add(REMOTE_SYN_BYTE),
        flags: TcpFlags::FinAck,
        ..SERVER_REPLY
    };

    /// The server's final ACK completing close from FIN-WAIT-1, matching the module's standard
    /// test consts for a connection closing right after the handshake, after its FIN
    /// was both acked and matched by the peer's own FIN in the same segment.
    pub const SERVER_FINAL_ACK_COMPLETING_CLOSE: Self = Self {
        seq_num: SERVER_ISN.const_add(LOCAL_SYN_BYTE.const_add(LOCAL_FIN_BYTE)),
        ack_num: CLIENT_ISN.const_add(REMOTE_SYN_BYTE.const_add(REMOTE_FIN_BYTE)),
        ..SERVER_REPLY
    };

    /// Decodes a full IPv4 packet in the local to remote direction into a `TcpSegment` so tests
    /// can assert on structs instead of raw bytes.
    ///
    /// This is test only because a segment created locally would never be parsed from bytes in
    /// production.
    ///
    /// # Errors
    ///
    /// Returns `Err` if parsing fails.
    pub fn decode_test_pkt(bytes: &[u8]) -> TraceableResult<Self> {
        let (ipv4_hdr, payload) = Ipv4Header::test_parse_local(bytes)?;
        Self::inner_parse(payload, ipv4_hdr.ip_pair)
    }
}

#[cfg(test)]
pub use crate_only::*;

/// Items only for this crate's tests, not the `test-utils` feature.
#[cfg(test)]
mod crate_only {
    use super::*;

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
}
