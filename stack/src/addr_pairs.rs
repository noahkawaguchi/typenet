use {
    crate::direction::Direction,
    std::{fmt, marker::PhantomData, net::Ipv4Addr},
};

/// A pair of source and destination IPv4 addresses for traffic flowing in direction `D`.
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug, PartialEq, Eq))]
pub(crate) struct Ipv4AddrPair<D: Direction> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    phantom: PhantomData<D>,
}

impl<D: Direction> Clone for Ipv4AddrPair<D> {
    fn clone(&self) -> Self { *self }
}

impl<D: Direction> Copy for Ipv4AddrPair<D> {}

impl<D: Direction> Ipv4AddrPair<D> {
    pub(crate) const fn new(src: Ipv4Addr, dst: Ipv4Addr) -> Self {
        Self { src, dst, phantom: PhantomData }
    }

    pub(crate) const fn swapped(self) -> Ipv4AddrPair<D::Rev> {
        Ipv4AddrPair::<D::Rev> { src: self.dst, dst: self.src, phantom: PhantomData }
    }
}

impl<D: Direction> fmt::Display for Ipv4AddrPair<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}

/// A pair of source and destination ports for traffic flowing in direction `D`.
#[derive(Clone, Copy)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug, PartialEq, Eq))]
pub(crate) struct PortPair<D: Direction> {
    pub src: u16,
    pub dst: u16,
    phantom: PhantomData<D>,
}

impl<D: Direction> PortPair<D> {
    pub(crate) const fn new(src: u16, dst: u16) -> Self { Self { src, dst, phantom: PhantomData } }

    pub(crate) const fn swapped(self) -> PortPair<D::Rev> {
        PortPair::<D::Rev> { src: self.dst, dst: self.src, phantom: PhantomData }
    }
}

impl<D: Direction> fmt::Display for PortPair<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}
