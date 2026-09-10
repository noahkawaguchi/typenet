pub mod engine;
pub mod router;

pub use tcp::{RtoConfig, TcpConnections, TcpSegment};

mod display;
mod icmp_echo;
mod tcp;
mod udp;

use {
    crate::{
        ETHERNET_MTU,
        addr_pairs::Ipv4AddrPair,
        checksum,
        endpoint::Endpoint,
        error::{TraceableError, TraceableResult},
        try_ops::{TryGet as _, TryGetMut as _},
    },
    std::fmt,
};

/// Calculates the TCP/UDP checksum of the pseudo-header + `data`. `data` should cover the TCP/UDP
/// header and payload. Does not zero out the checksum field inside the header of `data` before
/// calculating.
fn pseudo_hdr_cksum<S: Endpoint>(
    data: &[u8],
    ip_pair: Ipv4AddrPair<S>,
    protocol: Protocol,
) -> TraceableResult<u16> {
    /// The number of bytes in a TCP/UDP pseudo-header.
    const PSEUDO_HDR_LEN: usize = 12;

    let proto_len = u16::try_from(data.len())?;
    let cksum_len = PSEUDO_HDR_LEN + usize::from(proto_len);

    let mut cksum_data = [0u8; PSEUDO_HDR_LEN + ETHERNET_MTU];
    cksum_data[0..4].copy_from_slice(&ip_pair.src.octets());
    cksum_data[4..8].copy_from_slice(&ip_pair.dst.octets());
    // Byte 8 is reserved padding for alignment
    cksum_data[9] = protocol.into();
    cksum_data[10..12].copy_from_slice(&proto_len.to_be_bytes());
    cksum_data
        .try_get_mut(PSEUDO_HDR_LEN..cksum_len)?
        .copy_from_slice(data);

    Ok(checksum::calculate(cksum_data.try_get(..cksum_len)?))
}

#[derive(Clone, Copy)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[repr(u8)]
pub enum Protocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
}

impl TryFrom<u8> for Protocol {
    type Error = TraceableError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        const ICMP: u8 = Protocol::Icmp as u8;
        const TCP: u8 = Protocol::Tcp as u8;
        const UDP: u8 = Protocol::Udp as u8;

        match value {
            ICMP => Ok(Self::Icmp),
            TCP => Ok(Self::Tcp),
            UDP => Ok(Self::Udp),
            other => Err(format!("Unsupported protocol {other}").into()),
        }
    }
}

impl From<Protocol> for u8 {
    fn from(value: Protocol) -> Self { value as Self }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Icmp => "ICMP",
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        })
    }
}

/// Test constants shared between protocols.
#[cfg(test)]
mod test_consts {
    use {
        crate::{
            addr_pairs::Ipv4AddrPair,
            endpoint::{Local, Remote},
        },
        std::net::Ipv4Addr,
    };

    /// A pair of IP addresses going from 10.0.0.2 to 10.0.0.1 in the remote to local direction.
    pub const REMOTE_TO_LOCAL_IP_PAIR: Ipv4AddrPair<Remote> =
        Ipv4AddrPair::new(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 1));

    /// A pair of IP addresses going from 10.0.0.1 to 10.0.0.2 in the local to remote direction.
    pub const LOCAL_TO_REMOTE_IP_PAIR: Ipv4AddrPair<Local> = REMOTE_TO_LOCAL_IP_PAIR.swapped();
}
