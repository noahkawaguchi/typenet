use {
    crate::{
        addr_pairs::Ipv4AddrPair,
        endpoint::{Endpoint, Local, Remote},
        error::TraceableResult,
        protocol::{
            Protocol,
            display::PrettyPayload,
            icmp_echo::IcmpEchoMsg,
            tcp::{TcpConnections, TcpSegment},
            udp::UdpDatagram,
        },
    },
    std::fmt,
};

/// Protocol-handling types that can be displayed as a string and can have their payload pretty
/// printed.
pub trait PrettyProtocol: fmt::Display {
    /// Wraps raw payload bytes that may be UTF-8, non-UTF-8, or empty in a `PrettyPayload` for
    /// pretty printing. If `include_content` is `false`, prints length only.
    fn pretty_payload(&self, include_content: bool) -> PrettyPayload<'_>;
}

/// Pretty protocol-handling types that can also be encoded into a byte buffer.
pub trait Encode<S: Endpoint>: PrettyProtocol {
    /// Copies data from `self` to write the protocol-specific header and payload into `buf`,
    /// returning the number of bytes written.
    fn write_into(&self, buf: &mut [u8]) -> TraceableResult<u16>;

    /// Returns the protocol of `self`.
    fn proto(&self) -> Protocol;

    /// Returns the pair of IPv4 addresses of `self`.
    fn get_ip_pair(&self) -> Ipv4AddrPair<S>;
}

/// Enum for static dispatch over the supported protocol-specific structs. Sent from `S`.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub enum ProtocolRouter<'a, S: Endpoint> {
    Icmp(IcmpEchoMsg<'a, S>),
    Tcp(TcpSegment<S>),
    Udp(UdpDatagram<'a, S>),
}

impl<'a> ProtocolRouter<'a, Remote> {
    /// Parses `data` as the header and payload of a packet of protocol type `protocol`.
    pub fn parse(
        data: &'a [u8],
        protocol: Protocol,
        ip_pair: Ipv4AddrPair<Remote>,
    ) -> TraceableResult<Self> {
        match protocol {
            Protocol::Icmp => IcmpEchoMsg::parse(data, ip_pair).map(Self::Icmp),
            Protocol::Tcp => TcpSegment::parse(data, ip_pair).map(Self::Tcp),
            Protocol::Udp => UdpDatagram::parse(data, ip_pair).map(Self::Udp),
        }
    }

    /// Creates a protocol-specific header and payload for replying to `self`, or returns `Ok(None)`
    /// for no reply.
    pub fn create_reply(
        &self,
        tcp_connections: &mut TcpConnections,
    ) -> TraceableResult<Option<ProtocolRouter<'a, Local>>> {
        Ok(match self {
            Self::Icmp(msg) => Some(ProtocolRouter::<Local>::Icmp(msg.create_reply())),

            // TCP is the only one that's actually optional or fallible
            Self::Tcp(seg) => seg
                .create_reply(tcp_connections)?
                .map(ProtocolRouter::<Local>::Tcp),

            Self::Udp(dgram) => Some(ProtocolRouter::<Local>::Udp(dgram.create_reply())),
        })
    }
}

/// Generates a function for a trait implementation, matching on the variant of `self` and calling
/// the same method on all of the inner structs. Used when the inner structs all implement the trait
/// being implemented by the enum.
macro_rules! static_dispatch {
    ($fn_name:ident(&self) -> $ret_type:ty) => {
        fn $fn_name(&self) -> $ret_type {
            match self {
                Self::Icmp(msg) => msg.$fn_name(),
                Self::Tcp(seg) => seg.$fn_name(),
                Self::Udp(dgram) => dgram.$fn_name(),
            }
        }
    };

    ($fn_name:ident(&self, $arg_type:ty) -> $ret_type:ty) => {
        fn $fn_name(&self, arg: $arg_type) -> $ret_type {
            match self {
                Self::Icmp(msg) => msg.$fn_name(arg),
                Self::Tcp(seg) => seg.$fn_name(arg),
                Self::Udp(dgram) => dgram.$fn_name(arg),
            }
        }
    };
}

impl Encode<Local> for ProtocolRouter<'_, Local> {
    static_dispatch!(write_into(&self, &mut [u8]) -> TraceableResult<u16>);
    static_dispatch!(proto(&self) -> Protocol);
    static_dispatch!(get_ip_pair(&self) -> Ipv4AddrPair<Local>);
}

impl<S: Endpoint> PrettyProtocol for ProtocolRouter<'_, S> {
    static_dispatch!(pretty_payload(&self, bool) -> PrettyPayload<'_>);
}

impl<S: Endpoint> fmt::Display for ProtocolRouter<'_, S> {
    static_dispatch!(fmt(&self, &mut fmt::Formatter) -> fmt::Result);
}
