use {
    crate::{
        ETHERNET_MTU,
        addr_pairs::Ipv4AddrPair,
        checksum,
        endpoint::{Endpoint, Local, Remote},
        protocol::Protocol,
        try_ops::TryAdd as _,
    },
    std::{fmt, net::Ipv4Addr},
};

/// The minimum number of bytes in an IPv4 header (no options) as a `u8`.
const IPV4_HDR_MIN_LEN_U8: u8 = 20;

/// The minimum number of bytes in an IPv4 header (no options) as a `usize`.
const IPV4_HDR_MIN_LEN_USIZE: usize = IPV4_HDR_MIN_LEN_U8 as usize;

/// Manages IPv4 header fields for a packet sent from `S`.
#[cfg_attr(test, derive(Debug))]
pub struct Ipv4Header<S: Endpoint> {
    pub total_len: u16,
    pub protocol: Protocol,
    pub ip_pair: Ipv4AddrPair<S>,
}

impl Ipv4Header<Remote> {
    /// Parses `data` as an IPv4 packet going in the remote to local direction, returning the header
    /// fields and a slice starting at the beginning of the payload.
    pub fn parse(data: &[u8]) -> Result<(Self, &[u8]), String> { Self::inner_parse(data) }
}

impl Ipv4Header<Local> {
    /// The length in bytes of an IPv4 header for a reply packet (no options).
    pub const REPLY_HDR_LEN: usize = IPV4_HDR_MIN_LEN_USIZE;

    /// Creates an IPv4 header with the given `protocol` and `ip_pair` going in the local to remote
    /// direction. Total length is the length of the IPv4 header + `proto_len`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if adding `proto_len` to the IPv4 header length overflows `u16`.
    pub fn try_new(
        protocol: Protocol,
        ip_pair: Ipv4AddrPair<Local>,
        proto_len: u16,
    ) -> Result<Self, String> {
        Self::inner_try_new(protocol, ip_pair, proto_len)
    }

    /// Writes an IPv4 header going in the local to remote direction into `buf`, copying the header
    /// data from `self`.
    pub fn write_into(&self, buf: &mut [u8; ETHERNET_MTU]) { self.inner_write_into(buf); }
}

impl<S: Endpoint> Ipv4Header<S> {
    /// Parses `data` as an IPv4 packet that could be local to remote or remote to local, returning
    /// the header fields and a slice starting at the beginning of the payload.
    ///
    /// The local to remote direction is for tests only. Only the remote to local direction should
    /// be exposed in production code.
    fn inner_parse(data: &[u8]) -> Result<(Self, &[u8]), String> {
        let ip_hdr = data
            .first_chunk::<IPV4_HDR_MIN_LEN_USIZE>()
            .ok_or_else(|| format!("Too short for IPv4 header ({} bytes)", data.len()))?;

        // Must be IPv4
        match ip_hdr[0] >> 4 {
            4 => {}
            6 => return Err(String::from("IPv6 packet")),
            version => return Err(format!("Unexpected IP version {version}")),
        }

        if checksum::calculate(ip_hdr) != 0 {
            return Err(String::from("Invalid IPv4 header checksum"));
        }

        let ihl_bytes = usize::from(ip_hdr[0] & 0xF) * 4; // Convert 32-bit words to bytes

        Ok((
            Self {
                total_len: u16::from_be_bytes([ip_hdr[2], ip_hdr[3]]),
                protocol: ip_hdr[9].try_into()?,
                ip_pair: Ipv4AddrPair::new(
                    Ipv4Addr::new(ip_hdr[12], ip_hdr[13], ip_hdr[14], ip_hdr[15]),
                    Ipv4Addr::new(ip_hdr[16], ip_hdr[17], ip_hdr[18], ip_hdr[19]),
                ),
            },
            data.get(ihl_bytes..)
                .ok_or("IPv4 data shorter than its IHL")?,
        ))
    }

    /// Creates an IPv4 header with the given `protocol` and `ip_pair`, which could be local to
    /// remote or remote to local. Total length is the length of the IPv4 header + `proto_len`.
    ///
    /// The remote to local direction is for tests only. Only the local to remote direction should
    /// be exposed in production code.
    ///
    /// # Errors
    ///
    /// Returns `Err` if adding `proto_len` to the IPv4 header length overflows `u16`.
    fn inner_try_new(
        protocol: Protocol,
        ip_pair: Ipv4AddrPair<S>,
        proto_len: u16,
    ) -> Result<Self, String> {
        u16::from(IPV4_HDR_MIN_LEN_U8)
            .try_add(proto_len)
            .map(|total_len| Self { total_len, protocol, ip_pair })
    }

    /// Writes an IPv4 header that could be local to remote or remote to local into `buf`, copying
    /// the header data from `self`.
    ///
    /// The remote to local direction is for tests only. Only the local to remote direction should
    /// be exposed in production code.
    fn inner_write_into(&self, buf: &mut [u8; ETHERNET_MTU]) {
        // IP header (no options, 20 bytes)
        buf[0] = 0x40 | (IPV4_HDR_MIN_LEN_U8 / 4); // Version 4, IHL 5 (20 bytes)
        buf[1] = 0x00; // DSCP/ECN
        buf[2..4].copy_from_slice(&self.total_len.to_be_bytes()); // Total length
        buf[4..6].copy_from_slice(&[0x00, 0x00]); // Identification
        buf[6..8].copy_from_slice(&[0x40, 0x00]); // Flags + Fragment offset (Don't Fragment)
        buf[8] = 64; // TTL
        buf[9] = self.protocol.into(); // Protocol

        // Clear IP header checksum field before recalculating
        buf[10..12].copy_from_slice(&[0x00, 0x00]);

        buf[12..16].copy_from_slice(&self.ip_pair.src.octets());
        buf[16..20].copy_from_slice(&self.ip_pair.dst.octets());

        // Recalculate IP header checksum (covers only the IP header, always 20 bytes for replies)
        let ip_cksum = checksum::calculate(&buf[..IPV4_HDR_MIN_LEN_USIZE]);
        buf[10..12].copy_from_slice(&ip_cksum.to_be_bytes());
    }
}

impl<S: Endpoint> fmt::Display for Ipv4Header<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IPv4 | {} bytes total | {} | {}", self.total_len, self.protocol, self.ip_pair)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        pretty_assertions::{assert_eq, assert_matches},
    };

    impl Ipv4Header<Local> {
        /// Parses `data` as an IPv4 packet going in the local to remote direction, returning the
        /// header fields and a slice starting at the beginning of the payload.
        ///
        /// This is a test-only version because a header created locally would never be parsed from
        /// bytes in production.
        pub fn test_parse_local(data: &[u8]) -> Result<(Self, &[u8]), String> {
            Self::inner_parse(data)
        }
    }

    impl Ipv4Header<Remote> {
        /// Creates an IPv4 header with the given `protocol` and `ip_pair` going in the remote to
        /// local direction. Total length is the length of the IPv4 header + `proto_len`.
        ///
        /// This is a test-only version because a header from the remote endpoint would never be
        /// constructed in production (only parsed from bytes).
        ///
        /// # Errors
        ///
        /// Returns `Err` if adding `proto_len` to the IPv4 header length overflows `u16`.
        pub fn test_try_new_remote(
            protocol: Protocol,
            ip_pair: Ipv4AddrPair<Remote>,
            proto_len: u16,
        ) -> Result<Self, String> {
            Self::inner_try_new(protocol, ip_pair, proto_len)
        }

        /// Writes an IPv4 header going in the remote to local direction into `buf`, copying the
        /// header data from `self`.
        ///
        /// This is a test-only version because a header from the remote endpoint would never be
        /// encoded into bytes in production.
        pub fn test_write_into_remote(&self, buf: &mut [u8; ETHERNET_MTU]) {
            self.inner_write_into(buf);
        }
    }

    #[test]
    fn correctly_parses_valid_pkt() -> Result<(), String> {
        #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3C,  // Version 4, IHL 5, TOS 0, Total Length 60
            0x1C, 0x46, 0x40, 0x00,  // ID, Flags, Fragment Offset
            0x40, 0x06, 0xA6, 0x4D,  // TTL 64, Protocol 6 (TCP), Checksum
            192, 168, 1, 100,        // Source IP: 192.168.1.100
            172, 16, 10, 12,         // Dest IP: 172.16.10.12
        ];

        let (hdr, payload) = Ipv4Header::parse(&DATA)?;

        assert_eq!(hdr.total_len, 60);
        assert_eq!(hdr.protocol, Protocol::Tcp);
        assert_eq!(hdr.ip_pair.src, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(hdr.ip_pair.dst, Ipv4Addr::new(172, 16, 10, 12));
        assert_eq!(payload, &DATA[20..]);

        Ok(())
    }

    #[test]
    fn parsing_fails_if_too_short() {
        const DATA: [u8; 3] = [0x45, 0x00, 0x00]; // Only 3 bytes
        assert_matches!(Ipv4Header::parse(&DATA), Err(e) if e.contains("Too short"));
    }

    #[test]
    fn parsing_fails_on_invalid_cksum() {
        #[rustfmt::skip]
        const DATA: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3C,  // Version 4, IHL 5, TOS 0, Total Length 60
            0x1C, 0x46, 0x40, 0x00,  // ID, Flags, Fragment Offset
            0x40, 0x06, 0x00, 0x00,  // TTL 64, Protocol 6 (TCP), Checksum (wrong, should be 0xA64D)
            192, 168, 1, 100,        // Source IP: 192.168.1.100
            172, 16, 10, 12,         // Dest IP: 172.16.10.12
        ];

        assert_matches!(Ipv4Header::parse(&DATA), Err(e) if e.contains("checksum"));
    }

    #[test]
    fn parsing_fails_if_not_ipv4() {
        #[rustfmt::skip]
        const DATA: [u8; 24] = [
            0x60, 0x00, 0x00, 0x00,  // Version 6 (IPv6), not 4
            0x00, 0x14, 0x06, 0x40,
            0x20, 0x01, 0x0D, 0xB8,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];

        assert_matches!(Ipv4Header::parse(&DATA), Err(e) if e.contains("IPv6"));
    }

    #[test]
    fn creates_valid_ipv4_hdr_for_reply() -> Result<(), String> {
        #[rustfmt::skip]
        const REQUEST: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3C,  // Version 4, IHL 5, TOS 0, Total Length 60
            0x1C, 0x46, 0x40, 0x00,  // ID, Flags, Fragment Offset
            0x40, 0x11, 0xA6, 0x42,  // TTL 64, Protocol 17 (UDP), Checksum
            192, 168, 1, 100,        // Source IP: 192.168.1.100
            172, 16, 10, 12,         // Dest IP: 172.16.10.12
        ];

        let (hdr, _) = Ipv4Header::parse(&REQUEST)?;
        let mut reply = [0u8; ETHERNET_MTU];
        let proto_len = 48 - 20; // Total length - IPv4 reply header length
        let reply_hdr = Ipv4Header::try_new(hdr.protocol, hdr.ip_pair.swapped(), proto_len)?;
        reply_hdr.write_into(&mut reply);
        assert_eq!(reply_hdr.total_len, 48);

        // Verify IPv4 header fields
        assert_eq!(reply[0], 0x45); // Version 4, IHL 5
        assert_eq!(reply[1], 0x00); // DSCP/ECN
        assert_eq!(&reply[2..4], &[0x00, 0x30]); // Total length: 48
        assert_eq!(&reply[4..6], &[0x00, 0x00]); // Identification: 0
        assert_eq!(&reply[6..8], &[0x40, 0x00]); // Flags: Don't Fragment
        assert_eq!(reply[8], 64); // TTL: 64
        assert_eq!(reply[9], 0x11); // Protocol: 17 (UDP)

        // Verify IPs are swapped
        assert_eq!(&reply[12..16], &[172, 16, 10, 12]); // Source (was dest)
        assert_eq!(&reply[16..20], &[192, 168, 1, 100]); // Dest (was source)

        // Verify IP header checksum is valid
        assert_eq!(checksum::calculate(&reply[..20]), 0);

        Ok(())
    }
}
