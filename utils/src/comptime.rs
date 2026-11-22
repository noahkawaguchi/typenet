use std::num::{NonZeroU16, NonZeroUsize};

/// Creates a `NonZeroU16` from a `u16` at compile time. Guaranteed to either panic at compile time
/// or evaluate to a valid `NonZeroU16` constant.
#[must_use]
pub const fn nonzero_u16<const N: u16>() -> NonZeroU16 {
    const { NonZeroU16::new(N).expect("must be nonzero") }
}

/// Creates a `NonZeroUsize` from a `usize` at compile time. Guaranteed to either panic at compile
/// time or evaluate to a valid `NonZeroUsize` constant.
#[must_use]
pub const fn nonzero_usize<const N: usize>() -> NonZeroUsize {
    const { NonZeroUsize::new(N).expect("must be nonzero") }
}
