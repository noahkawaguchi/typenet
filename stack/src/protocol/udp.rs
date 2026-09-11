use {
    crate::{
        addr_pairs::{Ipv4AddrPair, PortPair},
        endpoint::{Endpoint, Local, Remote},
        ipv4_packet::{Encode, PrettyProtocol},
        protocol::{Protocol, display::PrettyPayload, pseudo_hdr_cksum},
    },
    std::fmt,
    typenet_utils::{
        error::TraceableResult,
        try_ops::{TryAdd as _, TryGet as _, TryGetMut as _},
    },
};

/// The number of bytes in a UDP header.
const UDP_HDR_LEN: u16 = 8;

/// Manages UDP headers, data, and reply logic. Sent from `S`.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct UdpDatagram<'a, S: Endpoint> {
    /// Not a part of the UDP header, but required for checksum calculation.
    ip_pair: Ipv4AddrPair<S>,

    ports: PortPair<S>,
    payload: &'a [u8],
}

impl<'a> UdpDatagram<'a, Remote> {
    /// Parses `data` as a UDP header and payload.
    pub(crate) fn parse(data: &'a [u8], ip_pair: Ipv4AddrPair<Remote>) -> TraceableResult<Self> {
        let (udp_hdr, payload) = data
            .split_first_chunk::<{ UDP_HDR_LEN as usize }>()
            .ok_or_else(|| format!("Too short for UDP header ({} bytes)", data.len()))?;

        // A receiver should not treat a checksum field of all zeros as invalid because it means the
        // sender chose not to compute one (RFC 768, RFC 1122, Section 4.1.3.4).
        if u16::from_be_bytes([udp_hdr[6], udp_hdr[7]]) != 0
            && pseudo_hdr_cksum(data, ip_pair, Protocol::Udp)? != 0
        {
            return Err("Invalid UDP checksum".into());
        }

        Ok(Self {
            ip_pair,
            ports: PortPair::new(
                u16::from_be_bytes([udp_hdr[0], udp_hdr[1]]),
                u16::from_be_bytes([udp_hdr[2], udp_hdr[3]]),
            ),
            payload,
        })
    }

    /// Creates a UDP header and payload for replying to `self`.
    pub(crate) const fn create_reply(&self) -> UdpDatagram<'a, Local> {
        UdpDatagram::<Local> {
            ip_pair: self.ip_pair.swapped(),
            ports: self.ports.swapped(),
            payload: self.payload,
        }
    }
}

impl Encode<Local> for UdpDatagram<'_, Local> {
    fn write_into(&self, buf: &mut [u8]) -> TraceableResult {
        // Source and destination ports
        buf.try_get_mut(..2)?
            .copy_from_slice(&self.ports.src.to_be_bytes());
        buf.try_get_mut(2..4)?
            .copy_from_slice(&self.ports.dst.to_be_bytes());

        let udp_len = self.proto_len()?;
        buf.try_get_mut(4..6)?
            .copy_from_slice(&udp_len.to_be_bytes());

        // Checksum at bytes 6-7 calculated later with pseudo-header

        // Copy payload for echo
        buf.try_get_mut(UDP_HDR_LEN.into()..udp_len.into())?
            .copy_from_slice(self.payload);

        // Zero out checksum field before calculating checksum
        buf.try_get_mut(6..8)?.copy_from_slice(&[0x00, 0x00]);

        let udp_cksum =
            pseudo_hdr_cksum(buf.try_get(..udp_len.into())?, self.ip_pair, self.proto())?;

        // A computed checksum of 0 must be transmitted as 0xFFFF because a checksum field of all
        // zeros means the sender chose not to compute one (RFC 768, RFC 1122, Section 4.1.3.4).
        buf.try_get_mut(6..8)?
            .copy_from_slice(&if udp_cksum == 0 { 0xFFFF } else { udp_cksum }.to_be_bytes());

        Ok(())
    }

    fn proto(&self) -> Protocol { Protocol::Udp }

    fn get_ip_pair(&self) -> Ipv4AddrPair<Local> { self.ip_pair }

    fn proto_len(&self) -> TraceableResult<u16> {
        // UDP length: fixed UDP header length (8 bytes) + length of echo payload
        UDP_HDR_LEN.try_add(self.payload.len().try_into()?)
    }
}

impl<S: Endpoint> PrettyProtocol for UdpDatagram<'_, S> {
    fn pretty_payload(&self, include_content: bool) -> PrettyPayload<'_> {
        PrettyPayload { data: self.payload, include_content }
    }
}

impl<S: Endpoint> fmt::Display for UdpDatagram<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "UDP | {}", self.ports) }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            ETHERNET_MTU,
            protocol::test_consts::{LOCAL_TO_REMOTE_IP_PAIR, REMOTE_TO_LOCAL_IP_PAIR},
        },
        pretty_assertions::{assert_eq, assert_matches},
    };

    #[test]
    fn correctly_parses_valid_datagram() -> TraceableResult {
        #[rustfmt::skip]
        const DATA: [u8; 16] = [
            0x04, 0xD2,              // Source port: 1234
            0x00, 0x35,              // Dest port: 53 (DNS)
            0x00, 0x10,              // Length: 16 (8 byte header + 8 byte payload)
            0xA1, 0xB0,              // Checksum (valid for this datagram and IP pair)
            0x48, 0x65, 0x6C, 0x6C,  // Payload: "Hell"
            0x6F, 0x21, 0x21, 0x21,  // Payload: "o!!!"
        ];

        let dgram = UdpDatagram::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR)?;

        assert_eq!(dgram.ports, PortPair::new(1234, 53));
        assert_eq!(dgram.payload, b"Hello!!!");

        Ok(())
    }

    #[test]
    fn parsing_fails_when_too_short() {
        const DATA: [u8; 3] = [0x04, 0xD2, 0x00]; // Only 3 bytes

        assert_matches!(
            UdpDatagram::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR),
            Err(e) if e.to_string().contains("Too short")
        );
    }

    #[test]
    fn parsing_fails_on_invalid_nonzero_checksum() {
        #[rustfmt::skip]
        const DATA: [u8; 16] = [
            0x04, 0xD2,              // Source port: 1234
            0x00, 0x35,              // Dest port: 53 (DNS)
            0x00, 0x10,              // Length: 16 (8 byte header + 8 byte payload)
            0xBE, 0xEF,              // Checksum (wrong, should be 0xA1B0)
            0x48, 0x65, 0x6C, 0x6C,  // Payload: "Hell"
            0x6F, 0x21, 0x21, 0x21,  // Payload: "o!!!"
        ];

        assert_matches!(
            UdpDatagram::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR),
            Err(e) if e.to_string().contains("checksum")
        );
    }

    #[test]
    fn parsing_accepts_zero_checksum_as_not_computed() -> TraceableResult {
        #[rustfmt::skip]
        const DATA: [u8; 16] = [
            0x04, 0xD2,              // Source port: 1234
            0x00, 0x35,              // Dest port: 53 (DNS)
            0x00, 0x10,              // Length: 16 (8 byte header + 8 byte payload)
            0x00, 0x00,              // Checksum: all zeros means sender didn't compute one
            0x48, 0x65, 0x6C, 0x6C,  // Payload: "Hell"
            0x6F, 0x21, 0x21, 0x21,  // Payload: "o!!!"
        ];

        let dgram = UdpDatagram::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR)?;

        assert_eq!(dgram.ports, PortPair::new(1234, 53));
        assert_eq!(dgram.payload, b"Hello!!!");

        Ok(())
    }

    #[test]
    fn parsing_handles_empty_payload() -> TraceableResult {
        #[rustfmt::skip]
        const DATA: [u8; 8] = [
            0x1F, 0x90,              // Source port: 8080
            0x00, 0x50,              // Dest port: 80
            0x00, 0x08,              // Length: 8 (header only, no payload)
            0xCB, 0xFB,              // Checksum (valid for this datagram and IP pair)
        ];

        let dgram = UdpDatagram::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR)?;

        assert_eq!(dgram.ports, PortPair::new(8080, 80));
        assert_eq!(dgram.payload.len(), 0);

        Ok(())
    }

    #[test]
    fn extracts_ports_correctly() -> TraceableResult {
        #[rustfmt::skip]
        const DATA: [u8; 12] = [
            0xFF, 0xFF,              // Source port: 65535 (max)
            0x00, 0x01,              // Dest port: 1 (min non-zero)
            0x00, 0x0C,              // Length: 12
            0x03, 0xF9,              // Checksum (valid for this datagram and IP pair)
            0x74, 0x65, 0x73, 0x74,  // Payload: "test"
        ];

        let dgram = UdpDatagram::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR)?;

        assert_eq!(dgram.ports, PortPair::new(65535, 1));

        Ok(())
    }

    #[test]
    fn transmits_all_ones_when_computed_cksum_is_zero() -> TraceableResult {
        // Payload `[0xE6, 0xB5]` results in a pseudo-header checksum of 0x0000 for IP addresses
        // 10.0.0.1 and 10.0.0.2 (in either order) and ports 1234 and 80 (in either order).
        // However, 0xFFFF must be transmitted instead of 0x0000.

        const DGRAM: UdpDatagram<Local> = UdpDatagram {
            ip_pair: LOCAL_TO_REMOTE_IP_PAIR,
            ports: PortPair::new(1234, 80),
            payload: &[0xE6, 0xB5],
        };

        let mut buf = [0u8; ETHERNET_MTU];
        DGRAM.write_into(&mut buf)?;

        assert_eq!(&buf[6..8], &[0xFF, 0xFF]);

        Ok(())
    }

    #[test]
    fn creates_valid_echo_reply() -> TraceableResult {
        #[rustfmt::skip]
        const REQUEST: [u8; 16] = [
            0x04, 0xD2,              // Source port: 1234
            0x00, 0x35,              // Dest port: 53
            0x00, 0x10,              // Length: 16
            0xA1, 0xB0,              // Checksum (valid for this datagram and IP pair)
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x21, 0x21, 0x21,  // Payload: "Hello!!!"
        ];

        let dgram = UdpDatagram::parse(&REQUEST, REMOTE_TO_LOCAL_IP_PAIR)?;
        let mut reply_buf = [0u8; ETHERNET_MTU];
        let reply = dgram.create_reply();
        reply.write_into(&mut reply_buf[20..])?;

        // IPs should be swapped
        assert_eq!(reply.get_ip_pair(), REMOTE_TO_LOCAL_IP_PAIR.swapped());

        // Verify UDP header at offset 20
        assert_eq!(&reply_buf[20..22], &[0x00, 0x35]); // Source port: 53 (swapped)
        assert_eq!(&reply_buf[22..24], &[0x04, 0xD2]); // Dest port: 1234 (swapped)
        assert_eq!(&reply_buf[24..26], &[0x00, 0x10]); // Length: 16

        // Verify payload echoed
        assert_eq!(&reply_buf[28..36], b"Hello!!!");

        // Verify UDP length
        assert_eq!(reply.proto_len()?, 8 + 8);

        // Verify checksum
        assert_eq!(
            pseudo_hdr_cksum(&reply_buf[20..36], REMOTE_TO_LOCAL_IP_PAIR, Protocol::Udp)?,
            0
        );

        Ok(())
    }
}
