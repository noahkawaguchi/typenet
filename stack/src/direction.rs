use {
    crate::endpoint::{Endpoint, Local, Remote},
    std::fmt,
};

/// A direction of traffic flow, either incoming or outgoing.
#[expect(private_bounds, reason = "sealed trait so this module owns all implementations")]
pub trait Direction: fmt::Debug + Clone + Copy + PartialEq + Eq + sealed::Sealed {
    /// The reverse direction of traffic flow.
    type Rev: Direction;

    /// The source of traffic flowing in this direction.
    type Src: Endpoint;

    /// The destination of traffic flowing in this direction.
    type Dst: Endpoint;
}

/// Marker type representing incoming traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct In;

impl Direction for In {
    type Rev = Out;
    type Src = Remote;
    type Dst = Local;
}

/// Marker type representing outgoing traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Out;

impl Direction for Out {
    type Rev = In;
    type Src = Local;
    type Dst = Remote;
}

/// Private module used to create a sealed trait.
mod sealed {
    pub(super) trait Sealed {}
    impl Sealed for super::In {}
    impl Sealed for super::Out {}
}
