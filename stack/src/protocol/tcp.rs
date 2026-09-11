pub use connections::TcpConnections;

mod connections;
mod flags;
mod payload;
mod pending_segment;
mod reassembly;
mod send_info;
mod seq_space;
mod state;

#[cfg(any(test, feature = "test-utils"))]
mod test_utils;

use {
    crate::{
        addr_pairs::{Ipv4AddrPair, PortPair},
        application::Application,
        display::{PrettyPayload, PrettyProtocol, WithThousandsSeparators as _},
        endpoint::{Endpoint, Local, Remote},
        protocol::{
            Encode, Protocol, pseudo_hdr_cksum,
            tcp::{
                flags::TcpFlags,
                payload::{LenOrDefault as _, TcpPayload},
                send_info::SendInfo,
                seq_space::{SeqOffset, SeqPoint},
            },
        },
    },
    std::fmt,
    typenet_utils::{
        error::TraceableResult,
        try_ops::{TryAdd as _, TryGet as _, TryGetMut as _},
    },
};

/// The minimum number of bytes in a TCP header (no options).
const TCP_HDR_MIN_LEN: u8 = 20;

/// The single phantom byte consumed by SYN in the stream going in the local to remote direction.
const LOCAL_SYN_BYTE: SeqOffset<u32, Local> = SeqOffset::new(1);

/// The single phantom byte consumed by FIN in the stream going in the local to remote direction.
const LOCAL_FIN_BYTE: SeqOffset<u32, Local> = SeqOffset::new(1);

/// The single phantom byte consumed by SYN in the stream going in the remote to local direction.
const REMOTE_SYN_BYTE: SeqOffset<u32, Remote> = SeqOffset::new(1);

/// The single phantom byte consumed by FIN in the stream going in the remote to local direction.
const REMOTE_FIN_BYTE: SeqOffset<u32, Remote> = SeqOffset::new(1);

/// Manages TCP headers, data, and reply logic.
///
/// Field definitions below from RFC 9293, Section 3.1. Endpoint `S` is the sender (values based on
/// the sender's ISN), while endpoint `S::Peer` is the receiver (values based on the receiver's
/// ISN).
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug, PartialEq, Eq, Clone))]
pub struct TcpSegment<S: Endpoint> {
    /// Not a part of the TCP header, but required for connection state and checksum calculation.
    ip_pair: Ipv4AddrPair<S>,

    ports: PortPair<S>,

    /// "The sequence number of the first data octet in this segment (except when the SYN flag is
    /// set). If SYN is set, the sequence number is the initial sequence number (ISN) and the first
    /// data octet is ISN+1."
    seq_num: SeqPoint<S>,

    /// "If the ACK control bit is set, this field contains the value of the next sequence number
    /// the sender of the segment is expecting to receive. Once a connection is established, this
    /// is always sent."
    ack_num: SeqPoint<S::Peer>,

    /// **This field is stored in units of bytes.**
    ///
    /// "The number of 32-bit words in the TCP header. This indicates where the data begins. The
    /// TCP header (even one including options) is an integer multiple of 32 bits long."
    offset_bytes: u8,

    flags: TcpFlags,

    /// "The number of data octets beginning with the one indicated in the acknowledgment field
    /// that the sender of this segment is willing to accept."
    window: SeqOffset<u16, S::Peer>,

    payload: Option<TcpPayload>,
}

impl TcpSegment<Remote> {
    /// Parses `data` as a TCP header and payload in the remote to local direction.
    pub(crate) fn parse(data: &[u8], ip_pair: Ipv4AddrPair<Remote>) -> TraceableResult<Self> {
        Self::inner_parse(data, ip_pair)
    }

    /// Creates a TCP header and payload for replying to `self`, or returns `Ok(None)` for no reply,
    /// updating connection state accordingly.
    pub(crate) fn create_reply(
        &self,
        app: &mut impl Application,
        connections: &mut TcpConnections,
    ) -> TraceableResult<Option<TcpSegment<Local>>> {
        SendInfo::decide_reply(app, self, connections).map(|maybe_send_info| {
            maybe_send_info.map(|send_info| {
                TcpSegment::<Local>::from_pairs_and_info(
                    self.ip_pair.swapped(),
                    self.ports.swapped(),
                    send_info,
                )
            })
        })
    }

    /// Calls `create_reply` with `TestApp` and `connections`.
    #[cfg(test)]
    fn create_test_reply(
        &self,
        connections: &mut TcpConnections,
    ) -> TraceableResult<Option<TcpSegment<Local>>> {
        use crate::application::TestApp;

        self.create_reply(&mut TestApp, connections)
    }
}

impl TcpSegment<Local> {
    /// "This represents the sequence numbers the local (receiving) TCP endpoint is willing to
    /// receive... segments overlapping the range RCV.NXT to RCV.NXT + RCV.WND - 1 carry acceptable
    /// data or control" (RFC 9293, Section 4).
    ///
    /// Currently left at max for simplicity, since backpressure tied to how fast the application
    /// actually consumes data is unimplemented. However, RCV.WND could be used in the future to
    /// bound the growth of the reassembly and send buffers, for example throttling the peer's
    /// sending rate if they keep sending more data than they are willing to receive in an echo
    /// application.
    const RCV_WND: SeqOffset<u16, Remote> = SeqOffset::new(u16::MAX);

    fn from_pairs_and_info(
        ip_pair: Ipv4AddrPair<Local>,
        ports: PortPair<Local>,
        SendInfo { seq_num, ack_num, flags, payload }: SendInfo,
    ) -> Self {
        Self {
            ip_pair,
            ports,
            seq_num,
            ack_num,
            offset_bytes: TCP_HDR_MIN_LEN,
            flags,
            window: Self::RCV_WND,
            payload,
        }
    }
}

impl Encode<Local> for TcpSegment<Local> {
    fn write_into(&self, buf: &mut [u8]) -> TraceableResult { self.inner_write_into(buf) }
    fn proto(&self) -> Protocol { Protocol::Tcp }
    fn get_ip_pair(&self) -> Ipv4AddrPair<Local> { self.ip_pair }
    fn proto_len(&self) -> TraceableResult<u16> { self.inner_proto_len() }
}

impl<S: Endpoint> TcpSegment<S> {
    /// Parses `data` as a TCP header and payload, which could be local to remote or remote to
    /// local. The local to remote direction is for tests only. Only the remote to local direction
    /// should be exposed in production code.
    fn inner_parse(data: &[u8], ip_pair: Ipv4AddrPair<S>) -> TraceableResult<Self> {
        let tcp_hdr = data
            .first_chunk::<{ TCP_HDR_MIN_LEN as usize }>()
            .ok_or_else(|| format!("Too short for TCP header ({} bytes)", data.len()))?;

        if pseudo_hdr_cksum(data, ip_pair, Protocol::Tcp)? != 0 {
            return Err("Invalid TCP checksum".into());
        }

        // Convert length in 32-bit words in the upper 4 bits to length in bytes in the full 8 bits
        let offset_bytes = tcp_hdr[12] >> 4 << 2;

        Ok(Self {
            ip_pair,
            ports: PortPair::new(
                u16::from_be_bytes([tcp_hdr[0], tcp_hdr[1]]),
                u16::from_be_bytes([tcp_hdr[2], tcp_hdr[3]]),
            ),
            seq_num: SeqPoint::new(u32::from_be_bytes([
                tcp_hdr[4], tcp_hdr[5], tcp_hdr[6], tcp_hdr[7],
            ])),
            ack_num: SeqPoint::new(u32::from_be_bytes([
                tcp_hdr[8],
                tcp_hdr[9],
                tcp_hdr[10],
                tcp_hdr[11],
            ])),
            offset_bytes,
            flags: tcp_hdr[13].try_into()?,
            window: SeqOffset::new(u16::from_be_bytes([tcp_hdr[14], tcp_hdr[15]])),
            payload: TcpPayload::try_from_iter(
                data.get(offset_bytes.into()..)
                    .into_iter()
                    .flatten()
                    .copied(),
            )?,
        })
    }

    /// Copies data from `self` to write the protocol-specific header and payload into `buf`, which
    /// could be local to remote or remote to local, returning the number of bytes written.
    ///
    /// The remote to local direction is for tests only. Only the local to remote direction
    /// should be exposed in production code.
    fn inner_write_into(&self, buf: &mut [u8]) -> TraceableResult {
        // Source and destination ports
        buf.try_get_mut(..2)?
            .copy_from_slice(&self.ports.src.to_be_bytes());
        buf.try_get_mut(2..4)?
            .copy_from_slice(&self.ports.dst.to_be_bytes());

        // Sequence number
        buf.try_get_mut(4..8)?
            .copy_from_slice(&self.seq_num.to_be_bytes());

        // Acknowledgment number
        buf.try_get_mut(8..12)?
            .copy_from_slice(&self.ack_num.to_be_bytes());

        // Data offset in upper 4 bits (bytes / 4 = 32-bit words), reserved zeros in lower 4 bits
        *buf.try_get_mut(12)? = (self.offset_bytes / 4) << 4;

        // Flags
        *buf.try_get_mut(13)? = self.flags.into();

        // Window size for flow control
        buf.try_get_mut(14..16)?
            .copy_from_slice(&self.window.to_be_bytes());

        // Checksum at bytes 16-17 calculated later with pseudo-header

        // Urgent pointer
        buf.try_get_mut(18..20)?.copy_from_slice(&[0x00, 0x00]);

        // Copy the application's payload into the reply, if any
        let tcp_len = self.inner_proto_len()?;
        if let Some(payload) = &self.payload {
            buf.try_get_mut(TCP_HDR_MIN_LEN.into()..tcp_len.into())?
                .copy_from_slice(payload.as_bytes());
        }

        // Zero out checksum field before calculating checksum
        buf.try_get_mut(16..18)?.copy_from_slice(&[0x00, 0x00]);

        let tcp_cksum =
            pseudo_hdr_cksum(buf.try_get(..tcp_len.into())?, self.ip_pair, Protocol::Tcp)?;

        buf.try_get_mut(16..18)?
            .copy_from_slice(&tcp_cksum.to_be_bytes());

        Ok(())
    }

    fn inner_proto_len(&self) -> TraceableResult<u16> {
        // TCP segment length = minimum TCP header length (20 bytes) + payload length (0+ bytes)
        u16::from(TCP_HDR_MIN_LEN).try_add(self.payload.len_or_default())
    }
}

impl<S: Endpoint> PrettyProtocol for TcpSegment<S> {
    fn pretty_payload(&self, include_content: bool) -> PrettyPayload<'_> {
        PrettyPayload {
            data: self
                .payload
                .as_ref()
                .map(TcpPayload::as_bytes)
                .unwrap_or_default(),
            include_content,
        }
    }
}

impl<S: Endpoint> fmt::Display for TcpSegment<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP | {} | seq={} ack={} win={} | {}",
            self.ports,
            self.seq_num.with_thousands_separators(),
            self.ack_num.with_thousands_separators(),
            self.window.with_thousands_separators(),
            self.flags
        )
    }
}

#[cfg(test)]
mod tests {
    mod abort;
    mod echo;
    mod establish;
    mod flow_control;
    mod parse;
    mod retransmit;
    mod stray_syn;
    mod terminate;
    mod window;
    mod write;

    pub(super) use test_utils::*;
    use {
        super::*,
        crate::{
            ETHERNET_MTU,
            application::ShoutingTestApp,
            ipv4_header::Ipv4Header,
            protocol::{
                tcp::state::{ConnState, SynReceived, SyncedState, TcpState, WindowState},
                test_consts::{LOCAL_TO_REMOTE_IP_PAIR, REMOTE_TO_LOCAL_IP_PAIR},
            },
        },
        pretty_assertions::assert_matches,
        std::{collections::VecDeque, thread, time::Duration},
    };
}
