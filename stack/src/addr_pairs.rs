use {
    crate::direction::Direction,
    std::{fmt, marker::PhantomData},
};

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
