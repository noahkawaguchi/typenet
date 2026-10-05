/// A direction of traffic flow, either incoming or outgoing.
#[expect(private_bounds, reason = "Sealed trait so this module owns all implementations")]
pub trait Direction: std::fmt::Debug + PartialEq + Eq + sealed::Sealed {
    /// The reverse direction of traffic flow.
    type Rev: Direction;
}

/// Marker type representing outgoing traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Out;

impl Direction for Out {
    type Rev = In;
}

/// Marker type representing incoming traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct In;

impl Direction for In {
    type Rev = Out;
}

/// Private module used to create a sealed trait.
mod sealed {
    pub(super) trait Sealed {}
    impl Sealed for super::Out {}
    impl Sealed for super::In {}
}
