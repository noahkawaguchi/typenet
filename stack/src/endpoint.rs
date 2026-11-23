use {
    std::{fmt, hash::Hash, marker::PhantomData, net::Ipv4Addr, num::NonZeroU16, str::FromStr},
    typenet_utils::error::TraceableError,
};

/// One of the communicating parties, either local or remote.
#[expect(private_bounds, reason = "sealed trait so this module owns all implementations")]
pub(crate) trait Endpoint:
    fmt::Debug + Clone + Copy + PartialEq + Eq + Hash + sealed::Sealed
{
}

/// Marker type representing a local sender or receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Local;

impl Endpoint for Local {}

/// Marker type representing a remote sender or receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Remote;

impl Endpoint for Remote {}

/// Port guaranteed to be nonzero and either `Local` or `Remote`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Port<E: Endpoint> {
    inner: NonZeroU16,
    phantom: PhantomData<E>,
}

impl<E: Endpoint> Port<E> {
    /// Creates a `Self` if `primitive` is nonzero.
    pub(crate) fn new(primitive: u16) -> Option<Self> {
        NonZeroU16::new(primitive).map(|inner| Self { inner, phantom: PhantomData })
    }

    /// Creates a `Self` from a `u16` at compile time. Guaranteed to either panic at compile time or
    /// evaluate to a valid `Self` constant.
    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) const fn comptime_new<const PRIMITIVE: u16>() -> Self {
        use typenet_utils::comptime;

        const { Self { inner: comptime::nonzero_u16::<PRIMITIVE>(), phantom: PhantomData } }
    }

    pub(crate) const fn to_be_bytes(self) -> [u8; 2] { self.inner.get().to_be_bytes() }
}

impl<E: Endpoint> FromStr for Port<E> {
    type Err = TraceableError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NonZeroU16::from_str(s)
            .map_err(|_| format!("failed to parse port: {s}").into())
            .map(|inner| Self { inner, phantom: PhantomData })
    }
}

impl<E: Endpoint> fmt::Display for Port<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.inner, f) }
}

/// IPv4 address guaranteed to be either `Local` or `Remote`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Addr<E: Endpoint> {
    inner: Ipv4Addr,
    phantom: PhantomData<E>,
}

impl<E: Endpoint> Addr<E> {
    /// Creates a new `Self` with the IPv4 address `a`.`b`.`c`.`d`.
    pub(crate) const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self { inner: Ipv4Addr::new(a, b, c, d), phantom: PhantomData }
    }

    /// Returns the four eight-bit integers of the inner IPv4 address.
    pub(crate) const fn octets(self) -> [u8; 4] { self.inner.octets() }
}

impl<E: Endpoint> fmt::Display for Addr<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Display::fmt(&self.inner, f) }
}

/// Private module used to create a sealed trait.
mod sealed {
    pub(super) trait Sealed {}
    impl Sealed for super::Local {}
    impl Sealed for super::Remote {}
}
