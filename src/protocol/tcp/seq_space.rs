use {
    crate::protocol::display::ThousandsSeparated,
    std::{
        fmt,
        marker::PhantomData,
        num::{NonZeroU16, Wrapping},
        ops::{Add, AddAssign},
    },
};

/// An offset between two points in TCP sequence number space that are both from the stream
/// originating from sender `S`.
#[derive(Default, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct SeqOffset<T, S> {
    wrapping: Wrapping<T>,
    phantom: PhantomData<S>,
}

impl<T: Copy, S> Clone for SeqOffset<T, S> {
    fn clone(&self) -> Self { *self }
}

impl<T: Copy, S> Copy for SeqOffset<T, S> {}

impl<T, S> SeqOffset<T, S> {
    pub(super) const fn new(primitive: T) -> Self {
        Self { wrapping: Wrapping(primitive), phantom: PhantomData }
    }
}

impl<S> From<SeqOffset<u16, S>> for SeqOffset<u32, S> {
    fn from(value: SeqOffset<u16, S>) -> Self {
        Self { wrapping: Wrapping(value.wrapping.0.into()), phantom: PhantomData }
    }
}

impl<T: From<u16>, S> From<NonZeroU16> for SeqOffset<T, S> {
    fn from(value: NonZeroU16) -> Self {
        Self { wrapping: Wrapping(value.get().into()), phantom: PhantomData }
    }
}

impl<S> SeqOffset<u16, S> {
    pub(super) const fn to_be_bytes(self) -> [u8; 2] { self.wrapping.0.to_be_bytes() }
}

impl<S> SeqOffset<u32, S> {
    pub(super) const fn saturating_sub(self, rhs: Self) -> Self {
        Self {
            wrapping: Wrapping(self.wrapping.0.saturating_sub(rhs.wrapping.0)),
            phantom: PhantomData,
        }
    }
}

impl<T, S> TryFrom<SeqOffset<T, S>> for usize
where
    Self: TryFrom<T>,
{
    type Error = <Self as TryFrom<T>>::Error;

    fn try_from(value: SeqOffset<T, S>) -> Result<Self, Self::Error> {
        Self::try_from(value.wrapping.0)
    }
}

impl<T, S> fmt::Display for ThousandsSeparated<SeqOffset<T, S>>
where
    T: Copy,
    ThousandsSeparated<T>: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ThousandsSeparated(self.0.wrapping.0).fmt(f)
    }
}

/// A specific point in TCP sequence number space from the stream originating from sender `S`.
#[derive(Eq)]
#[cfg_attr(test, derive(Debug))]
pub(super) struct SeqPoint<S> {
    wrapping: Wrapping<u32>,
    phantom: PhantomData<S>,
}

impl<S> Clone for SeqPoint<S> {
    fn clone(&self) -> Self { *self }
}

impl<S> Copy for SeqPoint<S> {}

impl<S> PartialEq for SeqPoint<S> {
    fn eq(&self, other: &Self) -> bool { self.wrapping == other.wrapping }
}

impl<S> SeqPoint<S> {
    pub(super) const fn new(primitive: u32) -> Self {
        Self { wrapping: Wrapping(primitive), phantom: PhantomData }
    }

    pub(super) const fn to_be_bytes(self) -> [u8; 4] { self.wrapping.0.to_be_bytes() }

    /// Returns whether `self` precedes `other` in TCP sequence-number space, accounting for
    /// wraparound (RFC 9293, Section 3.4). Not transitive.
    pub(super) fn precedes(self, other: Self) -> bool {
        self.wrapping - other.wrapping >= Wrapping(1 << 31)
    }

    /// Returns whether `self` precedes or equals `other` in TCP sequence-number space, accounting
    /// for wraparound (RFC 9293, Section 3.4). Not transitive.
    pub(super) fn precedes_or_eq(self, other: Self) -> bool {
        self == other || self.precedes(other)
    }

    /// Returns the unsigned offset from `rhs` to `self`, or `None` if the offset would be negative,
    /// i.e. `rhs` does not precede or equal `self` in TCP sequence-number space (RFC 9293, Section
    /// 3.4).
    pub(super) fn offset_past(self, rhs: Self) -> Option<SeqOffset<u32, S>> {
        rhs.precedes_or_eq(self)
            .then(|| SeqOffset { wrapping: self.wrapping - rhs.wrapping, phantom: PhantomData })
    }

    /// Returns whether `self` falls within the window starting at `wnd_start` (inclusive) and
    /// ending `wnd_len` sequence numbers later (exclusive), accounting for wraparound (RFC 9293,
    /// Section 3.4).
    pub(super) fn in_window(self, wnd_start: Self, wnd_len: SeqOffset<u32, S>) -> bool {
        wnd_start.precedes_or_eq(self) && self.precedes(wnd_start + wnd_len)
    }
}

impl<S> Add<SeqOffset<u32, S>> for SeqPoint<S> {
    type Output = Self;

    fn add(self, rhs: SeqOffset<u32, S>) -> Self::Output {
        Self { wrapping: self.wrapping + rhs.wrapping, phantom: PhantomData }
    }
}

impl<S> AddAssign<SeqOffset<u32, S>> for SeqPoint<S> {
    fn add_assign(&mut self, rhs: SeqOffset<u32, S>) { *self = *self + rhs; }
}

impl<S> fmt::Display for ThousandsSeparated<SeqPoint<S>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ThousandsSeparated(self.0.wrapping.0).fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::endpoint::Local, std::ops::Sub};

    impl<S> SeqOffset<u32, S> {
        /// `self + rhs` with wrapping, but const. This should be removed once const traits are
        /// stabilized.
        pub(in super::super) const fn const_add(self, rhs: Self) -> Self {
            Self::new(self.wrapping.0.wrapping_add(rhs.wrapping.0))
        }
    }

    impl<S> Add for SeqOffset<u32, S> {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            Self { wrapping: self.wrapping + rhs.wrapping, phantom: PhantomData }
        }
    }

    impl<S> SeqPoint<S> {
        /// `self + rhs` with wrapping, but const. This should be removed once const traits are
        /// stabilized.
        pub(in super::super) const fn const_add(self, rhs: SeqOffset<u32, S>) -> Self {
            Self::new(self.wrapping.0.wrapping_add(rhs.wrapping.0))
        }

        /// `self - rhs` with wrapping, but const. This should be removed once const traits are
        /// stabilized.
        pub(in super::super) const fn const_sub(self, rhs: SeqOffset<u32, S>) -> Self {
            Self::new(self.wrapping.0.wrapping_sub(rhs.wrapping.0))
        }
    }

    impl<S> Sub<SeqOffset<u32, S>> for SeqPoint<S> {
        type Output = Self;

        fn sub(self, rhs: SeqOffset<u32, S>) -> Self::Output {
            Self { wrapping: self.wrapping - rhs.wrapping, phantom: PhantomData }
        }
    }

    mod comparison {
        use {super::*, pretty_assertions::assert_eq};

        #[test]
        fn point_equality() {
            for num in [0, 1, 42, 1 << 31, u32::MAX].map(SeqPoint::<Local>::new) {
                assert_eq!(num, num);
            }
        }

        #[test]
        fn point_comparison_is_not_transitive() {
            const A: SeqPoint<Local> = SeqPoint::new(0);
            const B: SeqPoint<Local> = SeqPoint::new(0x6000_0000);
            const C: SeqPoint<Local> = SeqPoint::new(0xC000_0000);

            assert!(A.precedes(B));
            assert!(B.precedes(C));
            assert!(!A.precedes(C));
        }

        #[test]
        #[expect(clippy::nonminimal_bool, reason = "Keep linear and circular comparisons parallel")]
        fn circular_comparison_agrees_with_linear_comparison_over_half_the_space() {
            for [prim_left, prim_right] in [[0, 1], [42, 1 << 31], [0xBEEF_CAFE, 0xCAFE_BEEF]] {
                let [seq_left, seq_right] =
                    [SeqPoint::<Local>::new(prim_left), SeqPoint::new(prim_right)];

                assert!(seq_left.precedes(seq_right));
                assert!(prim_left < prim_right);
                assert!(!seq_right.precedes(seq_left));
                assert!(!(prim_right < prim_left));
            }
        }

        #[test]
        #[expect(clippy::nonminimal_bool, reason = "Keep linear and circular comparisons parallel")]
        fn circular_comparison_differs_from_linear_comparison_over_half_the_space() {
            for [prim_left, prim_right] in
                [[u32::MAX, 0], [(1 << 31) + 42, 1], [0xBAAD_D00D, 0xD00D]]
            {
                let [seq_left, seq_right] =
                    [SeqPoint::<Local>::new(prim_left), SeqPoint::new(prim_right)];

                assert!(seq_left.precedes(seq_right));
                assert!(!(prim_left < prim_right));
                assert!(!seq_right.precedes(seq_left));
                assert!(prim_right < prim_left);
            }
        }

        #[test]
        fn antipode_and_near_antipode_comparisons_are_defined() {
            // As noted in RFC 1982, a pair of antipodes in serial number arithmetic may produce
            // results where both are strictly less than the other or strictly greater than the
            // other. This outcome is left undefined with the recommendation to avoid allowing such
            // pairs to exist. In TCP, sequence numbers of actual segments should never be this far
            // away from each other due to window sizes. Tested here for correctness and to avoid
            // off-by-one errors.

            const NUM: SeqPoint<Local> = SeqPoint::new(42);
            const ANTIPODE: SeqPoint<Local> = NUM.const_add(SeqOffset::new(1 << 31));
            const FARTHEST_GREATER: SeqPoint<Local> = ANTIPODE.const_sub(SeqOffset::new(1));
            const FARTHEST_LESS: SeqPoint<Local> = ANTIPODE.const_add(SeqOffset::new(1));

            assert!(
                NUM.precedes(FARTHEST_GREATER) && !FARTHEST_GREATER.precedes(NUM),
                "The first defined comparison one below the antipode"
            );

            assert!(
                FARTHEST_LESS.precedes(NUM) && !NUM.precedes(FARTHEST_LESS),
                "The first defined comparison one above the antipode"
            );

            assert!(
                NUM.precedes(ANTIPODE) && ANTIPODE.precedes(NUM),
                "The undefined outcome where a number and its antipode are both strictly less \
                 than the other depends on the implementation and should result in true here"
            );
        }
    }

    mod offset_past {
        use {super::*, pretty_assertions::assert_eq};

        #[test]
        fn computes_offset_when_rhs_precedes_or_equals_self() {
            for [later, earlier, expected] in [[140, 100, 40], [0, u32::MAX, 1], [42, 42, 0]] {
                assert_eq!(
                    SeqPoint::<Local>::new(later).offset_past(SeqPoint::new(earlier)),
                    Some(SeqOffset::new(expected))
                );
            }
        }

        #[test]
        fn returns_none_when_rhs_does_not_precede_or_equal_self() {
            assert_eq!(SeqPoint::<Local>::new(100).offset_past(SeqPoint::new(140)), None);
        }
    }

    mod in_window {
        use super::*;

        #[test]
        fn true_at_window_start() {
            assert!(SeqPoint::<Local>::new(100).in_window(SeqPoint::new(100), SeqOffset::new(10)));
        }

        #[test]
        fn true_in_middle() {
            assert!(SeqPoint::<Local>::new(105).in_window(SeqPoint::new(100), SeqOffset::new(10)));
        }

        #[test]
        fn true_at_last_included_point() {
            assert!(SeqPoint::<Local>::new(109).in_window(SeqPoint::new(100), SeqOffset::new(10)));
        }

        #[test]
        fn false_at_window_end_exclusive() {
            assert!(!SeqPoint::<Local>::new(110).in_window(SeqPoint::new(100), SeqOffset::new(10)));
        }

        #[test]
        fn false_before_window_start() {
            assert!(!SeqPoint::<Local>::new(99).in_window(SeqPoint::new(100), SeqOffset::new(10)));
        }

        #[test]
        fn handles_wraparound() {
            let start = SeqPoint::<Local>::new(u32::MAX - 4);
            let len = SeqOffset::new(10);
            assert!(SeqPoint::new(2).in_window(start, len));
            assert!(!SeqPoint::new(6).in_window(start, len));
        }
    }
}
