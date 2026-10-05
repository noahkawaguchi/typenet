use {
    crate::{
        ETHERNET_MTU,
        addr_pairs::Ipv4AddrPair,
        application::Application,
        direction::{Direction, In, Out},
        display::{PrettyPayload, PrettyProtocol},
        ipv4_header::Ipv4Header,
        protocol::{
            Encode, Protocol,
            icmp_echo::IcmpEchoMsg,
            tcp::{TcpConnections, TcpSegment},
            udp::UdpDatagram,
        },
    },
    std::fmt,
    typenet_utils::error::{TraceableError, TraceableResult},
};

/// A pretty-printable IPv4 header and protocol-specific header/payload.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Ipv4Packet<'a, D: Direction> {
    ipv4_hdr: Ipv4Header<D>,
    router: ProtocolRouter<'a, D>,
}

impl<'a> Ipv4Packet<'a, In> {
    /// Parses `data` as an IPv4 header followed by a protocol-specific header and payload.
    pub(crate) fn parse(data: &'a [u8]) -> TraceableResult<Self> {
        let (ipv4_hdr, ipv4_payload) = Ipv4Header::parse(data)?;

        let router = match ipv4_hdr.protocol {
            Protocol::Icmp => {
                ProtocolRouter::Icmp(IcmpEchoMsg::parse(ipv4_payload, ipv4_hdr.ip_pair)?)
            }
            Protocol::Tcp => {
                ProtocolRouter::Tcp(TcpSegment::parse(ipv4_payload, ipv4_hdr.ip_pair)?)
            }
            Protocol::Udp => {
                ProtocolRouter::Udp(UdpDatagram::parse(ipv4_payload, ipv4_hdr.ip_pair)?)
            }
        };

        Ok(Self { ipv4_hdr, router })
    }

    /// Creates a packet for replying to `self`, or returns `Ok(None)` for no reply.
    pub(crate) fn create_reply(
        &self,
        app: &mut impl Application,
        tcp_connections: &mut TcpConnections,
    ) -> TraceableResult<Option<Ipv4Packet<'a, Out>>> {
        match &self.router {
            // ICMP Echo Request/Reply always echoes, so there's no app to pass
            ProtocolRouter::Icmp(msg) => Some(ProtocolRouter::Icmp(msg.create_reply())),

            // TCP is the only one that's actually optional or fallible
            ProtocolRouter::Tcp(seg) => seg
                .create_reply(app, tcp_connections)?
                .map(ProtocolRouter::Tcp),

            ProtocolRouter::Udp(dgram) => Some(ProtocolRouter::Udp(dgram.create_reply(app))),
        }
        .map(|router| {
            Ok(Ipv4Packet {
                ipv4_hdr: Ipv4Header::try_new(
                    router.proto(),
                    router.get_ip_pair(),
                    router.proto_len()?,
                )?,
                router,
            })
        })
        .transpose()
    }
}

impl Ipv4Packet<'_, Out> {
    /// Writes the IPv4 header and protocol-specific header/payload into `buf`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `buf` is not long enough or arithmetic overflow occurs.
    pub fn write_into(&self, buf: &mut [u8; ETHERNET_MTU]) -> TraceableResult {
        self.router
            .write_into(&mut buf[Ipv4Header::REPLY_HDR_LEN..])?;

        let ipv4_hdr = Ipv4Header::try_new(
            self.router.proto(),
            self.router.get_ip_pair(),
            self.router.proto_len()?,
        )?;

        ipv4_hdr.write_into(buf);

        Ok(())
    }

    /// Returns the length of the entire IPv4 packet.
    #[must_use]
    pub const fn total_len(&self) -> u16 { self.ipv4_hdr.total_len }
}

impl TryFrom<TcpSegment<Out>> for Ipv4Packet<'_, Out> {
    type Error = TraceableError;

    fn try_from(value: TcpSegment<Out>) -> Result<Self, Self::Error> {
        Ok(Self {
            ipv4_hdr: Ipv4Header::try_new(value.proto(), value.get_ip_pair(), value.proto_len()?)?,
            router: ProtocolRouter::Tcp(value),
        })
    }
}

impl<D: Direction> PrettyProtocol for Ipv4Packet<'_, D> {
    fn pretty_payload(&self, include_content: bool) -> PrettyPayload<'_> {
        self.router.pretty_payload(include_content)
    }
}

impl<D: Direction> fmt::Display for Ipv4Packet<'_, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}\n{}", self.ipv4_hdr, self.router)
    }
}

/// Enum for static dispatch over the supported protocol-specific structs, with traffic flowing in
/// direction `D`.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
enum ProtocolRouter<'a, D: Direction> {
    Icmp(IcmpEchoMsg<'a, D>),
    Tcp(TcpSegment<D>),
    Udp(UdpDatagram<'a, D>),
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

impl Encode<Out> for ProtocolRouter<'_, Out> {
    static_dispatch!(write_into(&self, &mut [u8]) -> TraceableResult);
    static_dispatch!(proto(&self) -> Protocol);
    static_dispatch!(get_ip_pair(&self) -> Ipv4AddrPair<Out>);
    static_dispatch!(proto_len(&self) -> TraceableResult<u16>);
}

impl<D: Direction> PrettyProtocol for ProtocolRouter<'_, D> {
    static_dispatch!(pretty_payload(&self, bool) -> PrettyPayload<'_>);
}

impl<D: Direction> fmt::Display for ProtocolRouter<'_, D> {
    static_dispatch!(fmt(&self, &mut fmt::Formatter) -> fmt::Result);
}
