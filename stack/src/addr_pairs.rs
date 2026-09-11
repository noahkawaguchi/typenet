use {
    crate::endpoint::Endpoint,
    std::{fmt, marker::PhantomData, net::Ipv4Addr},
};

/// A pair of IPv4 addresses where `src` is the address of endpoint `S` and `dst` is the address of
/// endpoint `S::Peer`.
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug, PartialEq, Eq))]
pub struct Ipv4AddrPair<S: Endpoint> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    phantom: PhantomData<S>,
}

impl<S: Endpoint> Clone for Ipv4AddrPair<S> {
    fn clone(&self) -> Self { *self }
}

impl<S: Endpoint> Copy for Ipv4AddrPair<S> {}

impl<S: Endpoint> Ipv4AddrPair<S> {
    pub const fn new(src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        Self { src, dst, phantom: PhantomData }
    }

    pub const fn swapped(self) -> Ipv4AddrPair<S::Peer> {
        Ipv4AddrPair::<S::Peer> { src: self.dst, dst: self.src, phantom: PhantomData }
    }
}

impl<S: Endpoint> fmt::Display for Ipv4AddrPair<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}

/// A pair of ports where `src` is the port of endpoint `S` and `dst` is the port of endpoint
/// `S::Peer`.
#[derive(Clone, Copy)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug, PartialEq, Eq))]
pub struct PortPair<S: Endpoint> {
    pub src: u16,
    pub dst: u16,
    phantom: PhantomData<S>,
}

impl<S: Endpoint> PortPair<S> {
    pub const fn new(src: u16, dst: u16) -> Self { Self { src, dst, phantom: PhantomData } }

    pub const fn swapped(self) -> PortPair<S::Peer> {
        PortPair::<S::Peer> { src: self.dst, dst: self.src, phantom: PhantomData }
    }
}

impl<S: Endpoint> fmt::Display for PortPair<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}
