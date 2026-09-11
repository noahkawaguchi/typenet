use {
    crate::{
        addr_pairs::Ipv4AddrPair,
        checksum,
        display::{PrettyPayload, PrettyProtocol, WithThousandsSeparators as _},
        endpoint::{Endpoint, Local, Remote},
        protocol::{Encode, Protocol},
    },
    std::fmt,
    typenet_utils::{
        error::TraceableResult,
        try_ops::{TryAdd as _, TryGet as _, TryGetMut as _},
    },
};

/// The number of bytes in an ICMP header.
const ICMP_HDR_LEN: u16 = 8;

/// Manages ICMP Echo Request/Reply headers, data, and reply logic. Sent from `S`.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct IcmpEchoMsg<'a, S: Endpoint> {
    /// Not a part of the ICMP header or checksum, but used for addressing replies and to stay
    /// parallel to TCP and UDP.
    ip_pair: Ipv4AddrPair<S>,

    icmp_type: u8,
    // The code field is omitted because it is constant 0 for Echo Request/Reply
    identifier: u16,
    sequence: u16,
    payload: &'a [u8],
}

impl<S: Endpoint> IcmpEchoMsg<'_, S> {
    const ICMP_TYPE_ECHO_REQUEST: u8 = 8;
    const ICMP_TYPE_ECHO_REPLY: u8 = 0;
    const ICMP_CODE_ECHO: u8 = 0;
}

impl<'a> IcmpEchoMsg<'a, Remote> {
    /// Parses `data` as an ICMP Echo Request header and payload.
    pub(crate) fn parse(data: &'a [u8], ip_pair: Ipv4AddrPair<Remote>) -> TraceableResult<Self> {
        let (icmp_hdr, payload) = data
            .split_first_chunk::<{ ICMP_HDR_LEN as usize }>()
            .ok_or_else(|| format!("Too short for ICMP header ({} bytes)", data.len()))?;

        if checksum::calculate(data) != 0 {
            return Err("Invalid ICMP checksum".into());
        }

        let icmp_type = icmp_hdr[0];
        let icmp_code = icmp_hdr[1];

        // ICMP Echo Request (ping): type=8, code=0
        if icmp_type != Self::ICMP_TYPE_ECHO_REQUEST || icmp_code != Self::ICMP_CODE_ECHO {
            return Err(
                format!("Not an Echo Request: got type={icmp_type}, code={icmp_code}").into()
            );
        }

        Ok(Self {
            ip_pair,
            icmp_type,
            identifier: u16::from_be_bytes([icmp_hdr[4], icmp_hdr[5]]),
            sequence: u16::from_be_bytes([icmp_hdr[6], icmp_hdr[7]]),
            payload,
        })
    }

    /// Creates an ICMP header and payload for replying to `self`.
    pub(crate) const fn create_reply(&self) -> IcmpEchoMsg<'a, Local> {
        // ICMP Echo Reply:
        // - Change type from 8 to 0
        // - Keep the same identifier, sequence number, and payload data
        IcmpEchoMsg::<Local> {
            ip_pair: self.ip_pair.swapped(),
            icmp_type: Self::ICMP_TYPE_ECHO_REPLY,
            identifier: self.identifier,
            sequence: self.sequence,
            payload: self.payload,
        }
    }
}

impl Encode<Local> for IcmpEchoMsg<'_, Local> {
    fn write_into(&self, buf: &mut [u8]) -> TraceableResult {
        // Copy echo payload
        buf.try_get_mut(
            usize::from(ICMP_HDR_LEN)..usize::from(ICMP_HDR_LEN).try_add(self.payload.len())?,
        )?
        .copy_from_slice(self.payload);

        // ICMP Echo type and code
        *buf.try_get_mut(0)? = self.icmp_type;
        *buf.try_get_mut(1)? = Self::ICMP_CODE_ECHO;

        // Clear ICMP checksum field before recalculating
        buf.try_get_mut(2..4)?.copy_from_slice(&[0x00, 0x00]);

        // Identifier and sequence for echo request/reply
        buf.try_get_mut(4..6)?
            .copy_from_slice(&self.identifier.to_be_bytes());
        buf.try_get_mut(6..8)?
            .copy_from_slice(&self.sequence.to_be_bytes());

        // Calculate ICMP checksum (covers the entire ICMP message: header + payload)
        let icmp_cksum = checksum::calculate(buf.try_get(..self.proto_len()?.into())?);
        buf.try_get_mut(2..4)?
            .copy_from_slice(&icmp_cksum.to_be_bytes());

        Ok(())
    }

    fn proto(&self) -> Protocol { Protocol::Icmp }

    fn get_ip_pair(&self) -> Ipv4AddrPair<Local> { self.ip_pair }

    fn proto_len(&self) -> TraceableResult<u16> {
        // ICMP length: fixed ICMP header length (8 bytes) + length of echo payload
        ICMP_HDR_LEN.try_add(self.payload.len().try_into()?)
    }
}

impl<S: Endpoint> PrettyProtocol for IcmpEchoMsg<'_, S> {
    fn pretty_payload(&self, include_content: bool) -> PrettyPayload<'_> {
        PrettyPayload { data: self.payload, include_content }
    }
}

impl<S: Endpoint> fmt::Display for IcmpEchoMsg<'_, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ICMP | type={} code={} ({}) | identifier={} sequence={}",
            self.icmp_type,
            Self::ICMP_CODE_ECHO,
            match self.icmp_type {
                Self::ICMP_TYPE_ECHO_REQUEST => "Echo Request",
                Self::ICMP_TYPE_ECHO_REPLY => "Echo Reply",
                _ => "unknown type",
            },
            self.identifier.with_thousands_separators(),
            self.sequence.with_thousands_separators()
        )
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{ETHERNET_MTU, protocol::test_consts::REMOTE_TO_LOCAL_IP_PAIR},
        pretty_assertions::{assert_eq, assert_matches},
    };

    #[test]
    fn correctly_parses_valid_request() -> TraceableResult {
        #[rustfmt::skip]
        const DATA: [u8; 11] = [
            8, 0,              // Type 8 (Echo Request), Code 0
            0x0B, 0x11,        // Checksum
            0x12, 0x34,        // Identifier: 0x1234
            0x56, 0x78,        // Sequence: 0x5678
            0x41, 0x42, 0x43,  // Payload: "ABC"
        ];

        let msg = IcmpEchoMsg::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR)?;

        assert_eq!(msg.identifier, 0x1234);
        assert_eq!(msg.sequence, 0x5678);
        assert_eq!(msg.payload, &[0x41, 0x42, 0x43]);

        Ok(())
    }

    #[test]
    fn parsing_fails_when_too_short() {
        const DATA: [u8; 5] = [8, 0, 0x3A, 0x4B, 0x12]; // Only 5 bytes

        assert_matches!(
            IcmpEchoMsg::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR),
            Err(e) if e.to_string().contains("Too short")
        );
    }

    #[test]
    fn parsing_fails_when_wrong_icmp_type() {
        #[rustfmt::skip]
        const DATA: [u8; 8] = [
            0, 0,              // Type 0 (Echo Reply), Code 0
            0x97, 0x53,        // Checksum
            0x12, 0x34,        // Identifier
            0x56, 0x78,        // Sequence
        ];

        assert_matches!(
            IcmpEchoMsg::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR),
            Err(e) if e.to_string().contains("Not an Echo Request")
        );
    }

    #[test]
    fn parsing_fails_when_wrong_icmp_code() {
        #[rustfmt::skip]
        const DATA: [u8; 8] = [
            8, 1,              // Type 8 (Echo Request), Code 1 (invalid)
            0x8F, 0x52,        // Checksum
            0x12, 0x34,        // Identifier
            0x56, 0x78,        // Sequence
        ];

        assert_matches!(
            IcmpEchoMsg::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR),
            Err(e) if e.to_string().contains("Not an Echo Request")
        );
    }

    #[test]
    fn parsing_fails_on_invalid_cksum() {
        #[rustfmt::skip]
        const DATA: [u8; 11] = [
            8, 0,              // Type 8 (Echo Request), Code 0
            0x3A, 0x4B,        // Checksum (wrong, should be 0x0B11)
            0x12, 0x34,        // Identifier: 0x1234
            0x56, 0x78,        // Sequence: 0x5678
            0x41, 0x42, 0x43,  // Payload: "ABC"
        ];

        assert_matches!(
            IcmpEchoMsg::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR),
            Err(e) if e.to_string().contains("checksum")
        );
    }

    #[test]
    fn handles_empty_payload() -> TraceableResult {
        #[rustfmt::skip]
        const DATA: [u8; 8] = [
            8, 0,              // Type 8 (Echo Request), Code 0
            0xF7, 0xFE,        // Checksum
            0x00, 0x00,        // Identifier: 0
            0x00, 0x01,        // Sequence: 1
        ];

        let msg = IcmpEchoMsg::parse(&DATA, REMOTE_TO_LOCAL_IP_PAIR)?;

        assert_eq!(msg.identifier, 0);
        assert_eq!(msg.sequence, 1);
        assert_eq!(msg.payload.len(), 0);

        Ok(())
    }

    #[test]
    fn creates_valid_echo_reply() -> TraceableResult {
        #[rustfmt::skip]
        const REQUEST: [u8; 13] = [
            8, 0,                          // Type 8 (Echo Request), Code 0
            0x6B, 0x81,                    // Checksum
            0x12, 0x34,                    // Identifier: 0x1234
            0x56, 0x78,                    // Sequence: 0x5678
            0x48, 0x65, 0x6C, 0x6C, 0x6F,  // Payload: "Hello"
        ];

        let msg = IcmpEchoMsg::parse(&REQUEST, REMOTE_TO_LOCAL_IP_PAIR)?;
        let mut reply_buf = [0u8; ETHERNET_MTU];
        let reply = msg.create_reply();
        reply.write_into(&mut reply_buf[20..])?;

        // IPs should be swapped
        assert_eq!(reply.get_ip_pair(), REMOTE_TO_LOCAL_IP_PAIR.swapped());

        // Verify ICMP header at offset 20
        assert_eq!(reply_buf[20], 0); // Type 0 (Echo Reply)
        assert_eq!(reply_buf[21], 0); // Code 0
        assert_eq!(&reply_buf[24..26], &[0x12, 0x34]); // Identifier preserved
        assert_eq!(&reply_buf[26..28], &[0x56, 0x78]); // Sequence preserved

        // Verify payload echoed
        assert_eq!(&reply_buf[28..33], b"Hello");

        // Verify ICMP length
        assert_eq!(reply.proto_len()?, 8 + 5);

        // Verify checksum is valid (checksum of ICMP message should be 0)
        assert_eq!(checksum::calculate(&reply_buf[20..33]), 0);

        Ok(())
    }
}
