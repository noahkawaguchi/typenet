/// One of the communicating parties, either local or remote.
#[expect(private_bounds, reason = "Sealed trait so this module owns all implementations")]
pub trait Endpoint: std::fmt::Debug + PartialEq + Eq + sealed::Sealed {
    /// The party that this endpoint is communicating with.
    type Peer: Endpoint;
}

/// Marker type representing a local sender or receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Local;

impl Endpoint for Local {
    type Peer = Remote;
}

/// Marker type representing a remote sender or receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Remote;

impl Endpoint for Remote {
    type Peer = Local;
}

/// Private module used to create a sealed trait.
mod sealed {
    pub(super) trait Sealed {}
    impl Sealed for super::Local {}
    impl Sealed for super::Remote {}
}
