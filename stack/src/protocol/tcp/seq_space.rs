use {
    crate::{direction::Direction, display::ThousandsSeparated},
    std::{
        fmt,
        marker::PhantomData,
        num::{NonZeroU16, Wrapping},
        ops::{Add, AddAssign, Sub},
    },
};

/// A specific point in TCP sequence number space from the stream flowing in direction `D`.
#[derive(Clone, Copy, Eq)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug))]
pub(super) struct SeqPoint<D: Direction> {
    wrapping: Wrapping<u32>,
    phantom: PhantomData<D>,
}

impl<D: Direction> PartialEq for SeqPoint<D> {
    fn eq(&self, other: &Self) -> bool { self.wrapping == other.wrapping }
}

impl<D: Direction> SeqPoint<D> {
    pub(super) const fn new(primitive: u32) -> Self {
        Self { wrapping: Wrapping(primitive), phantom: PhantomData }
    }

    pub(super) const fn to_be_bytes(self) -> [u8; 4] { self.wrapping.0.to_be_bytes() }

    /// Returns whether `self` precedes `other` in TCP sequence-number space, accounting for
    /// wraparound (RFC 9293, Section 3.4). Not transitive.
    pub(super) fn precedes(self, other: Self) -> bool { (self - other).wrapping.0 < 0 }

    /// Returns whether `self` precedes or equals `other` in TCP sequence-number space, accounting
    /// for wraparound (RFC 9293, Section 3.4). Not transitive.
    pub(super) fn precedes_or_eq(self, other: Self) -> bool {
        self == other || self.precedes(other)
    }

    /// Returns whether `self` falls within the window starting at `wnd_start` (inclusive) and
    /// ending `wnd_len` sequence numbers later (exclusive), accounting for wraparound (RFC 9293,
    /// Section 3.4).
    pub(super) fn in_window(self, wnd_start: Self, wnd_len: SeqOffset<u32, D>) -> bool {
        wnd_start.precedes_or_eq(self) && self.precedes(wnd_start + wnd_len)
    }
}

impl<D: Direction> Add<SeqOffset<u32, D>> for SeqPoint<D> {
    type Output = Self;

    fn add(self, rhs: SeqOffset<u32, D>) -> Self::Output {
        Self { wrapping: self.wrapping + rhs.wrapping, phantom: PhantomData }
    }
}

impl<D: Direction> AddAssign<SeqOffset<u32, D>> for SeqPoint<D> {
    fn add_assign(&mut self, rhs: SeqOffset<u32, D>) { *self = *self + rhs; }
}

impl<D: Direction> Sub for SeqPoint<D> {
    type Output = SeqOffset<i32, D>;

    /// Signed offset of `self` past `rhs` in TCP sequence-number space. In other words, negative if
    /// `self` precedes `rhs`, non-negative otherwise.
    fn sub(self, rhs: Self) -> Self::Output {
        SeqOffset::new((self.wrapping - rhs.wrapping).0.cast_signed())
    }
}

impl<D: Direction> fmt::Display for ThousandsSeparated<SeqPoint<D>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ThousandsSeparated(self.0.wrapping.0).fmt(f)
    }
}

/// An offset between two points in TCP sequence number space that are both from the stream flowing
/// in direction `D`.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Debug))]
pub(super) struct SeqOffset<T, D: Direction> {
    wrapping: Wrapping<T>,
    phantom: PhantomData<D>,
}

impl<T, D: Direction> SeqOffset<T, D> {
    pub(super) const fn new(primitive: T) -> Self {
        Self { wrapping: Wrapping(primitive), phantom: PhantomData }
    }
}

impl<D: Direction> From<SeqOffset<u16, D>> for SeqOffset<u32, D> {
    fn from(value: SeqOffset<u16, D>) -> Self {
        Self { wrapping: Wrapping(value.wrapping.0.into()), phantom: PhantomData }
    }
}

impl<T: From<u16>, D: Direction> From<NonZeroU16> for SeqOffset<T, D> {
    fn from(value: NonZeroU16) -> Self {
        Self { wrapping: Wrapping(value.get().into()), phantom: PhantomData }
    }
}

impl<D: Direction> SeqOffset<u16, D> {
    pub(super) const fn to_be_bytes(self) -> [u8; 2] { self.wrapping.0.to_be_bytes() }
}

impl<D: Direction> From<SeqOffset<u16, D>> for usize {
    fn from(value: SeqOffset<u16, D>) -> Self { Self::from(value.wrapping.0) }
}

impl<D: Direction> TryFrom<SeqOffset<i32, D>> for usize {
    type Error = <Self as TryFrom<i32>>::Error;

    fn try_from(value: SeqOffset<i32, D>) -> Result<Self, Self::Error> {
        Self::try_from(value.wrapping.0)
    }
}

impl<T, D: Direction> fmt::Display for ThousandsSeparated<SeqOffset<T, D>>
where
    T: Copy,
    ThousandsSeparated<T>: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ThousandsSeparated(self.0.wrapping.0).fmt(f)
    }
}

#[cfg(any(test, feature = "test-utils"))]
mod test_impls {
    use super::*;

    impl<D: Direction> SeqPoint<D> {
        /// `self + rhs` with wrapping, but const. This should be removed once const traits are
        /// stabilized.
        pub(in super::super) const fn const_add(self, rhs: SeqOffset<u32, D>) -> Self {
            Self::new(self.wrapping.0.wrapping_add(rhs.wrapping.0))
        }
    }

    impl<D: Direction> SeqOffset<u32, D> {
        /// `self + rhs` with wrapping, but const. This should be removed once const traits are
        /// stabilized.
        pub(in super::super) const fn const_add(self, rhs: Self) -> Self {
            Self::new(self.wrapping.0.wrapping_add(rhs.wrapping.0))
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, crate::direction::Out};

    impl<D: Direction> SeqPoint<D> {
        /// `self - rhs` with wrapping, but const. This should be removed once const traits are
        /// stabilized.
        pub(in super::super) const fn const_sub(self, rhs: SeqOffset<u32, D>) -> Self {
            Self::new(self.wrapping.0.wrapping_sub(rhs.wrapping.0))
        }
    }

    impl<D: Direction> Sub<SeqOffset<u32, D>> for SeqPoint<D> {
        type Output = Self;

        fn sub(self, rhs: SeqOffset<u32, D>) -> Self::Output {
            Self { wrapping: self.wrapping - rhs.wrapping, phantom: PhantomData }
        }
    }

    impl<D: Direction> Add for SeqOffset<u32, D> {
        type Output = Self;

        fn add(self, rhs: Self) -> Self::Output {
            Self { wrapping: self.wrapping + rhs.wrapping, phantom: PhantomData }
        }
    }

    mod comparison {
        use {super::*, pretty_assertions::assert_eq};

        #[test]
        fn point_equality() {
            for num in [0, 1, 42, 1 << 31, u32::MAX].map(SeqPoint::<Out>::new) {
                assert_eq!(num, num);
            }
        }

        #[test]
        fn point_comparison_is_not_transitive() {
            const A: SeqPoint<Out> = SeqPoint::new(0);
            const B: SeqPoint<Out> = SeqPoint::new(0x6000_0000);
            const C: SeqPoint<Out> = SeqPoint::new(0xC000_0000);

            assert!(A.precedes(B));
            assert!(B.precedes(C));
            assert!(!A.precedes(C));
        }

        #[test]
        #[expect(clippy::nonminimal_bool, reason = "Keep linear and circular comparisons parallel")]
        fn circular_comparison_agrees_with_linear_comparison_over_half_the_space() {
            for [prim_left, prim_right] in [[0, 1], [42, 1 << 31], [0xBEEF_CAFE, 0xCAFE_BEEF]] {
                let [seq_left, seq_right] =
                    [SeqPoint::<Out>::new(prim_left), SeqPoint::new(prim_right)];

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
                    [SeqPoint::<Out>::new(prim_left), SeqPoint::new(prim_right)];

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

            const NUM: SeqPoint<Out> = SeqPoint::new(42);
            const ANTIPODE: SeqPoint<Out> = NUM.const_add(SeqOffset::new(1 << 31));
            const FARTHEST_GREATER: SeqPoint<Out> = ANTIPODE.const_sub(SeqOffset::new(1));
            const FARTHEST_LESS: SeqPoint<Out> = ANTIPODE.const_add(SeqOffset::new(1));

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

    mod subtraction {
        use {super::*, pretty_assertions::assert_eq};

        #[test]
        fn zero_when_rhs_equals_self() {
            for primitive in [0, 42, u32::MAX] {
                assert_eq!(
                    SeqPoint::<Out>::new(primitive) - SeqPoint::new(primitive),
                    SeqOffset::new(0)
                );
            }
        }

        #[test]
        fn i32_min_for_antipodes() {
            for [a, b] in [[0, 1 << 31], [42, (1 << 31) + 42], [u32::MAX, (1 << 31) - 1]]
                .map(|primitives| primitives.map(SeqPoint::new))
            {
                const MIN: SeqOffset<i32, Out> = SeqOffset::new(i32::MIN);

                assert_eq!(a - b, MIN);
                assert_eq!(b - a, MIN);
            }
        }

        #[test]
        fn positive_when_rhs_precedes_self() {
            for (later, earlier, expected) in
                [(140, 100, 40), (0, u32::MAX, 1), (1 << 31, 42, (1i32 << 31).wrapping_sub(42))]
            {
                assert_eq!(
                    SeqPoint::<Out>::new(later) - SeqPoint::new(earlier),
                    SeqOffset::new(expected)
                );
            }
        }

        #[test]
        fn negative_when_self_precedes_rhs() {
            for (earlier, later, expected) in
                [(100, 140, -40), (u32::MAX, 0, -1), (42, 1 << 31, 42i32.wrapping_sub(1 << 31))]
            {
                assert_eq!(
                    SeqPoint::<Out>::new(earlier) - SeqPoint::new(later),
                    SeqOffset::new(expected)
                );
            }
        }
    }

    mod in_window {
        use super::*;

        #[test]
        fn true_at_window_start() {
            assert!(SeqPoint::<Out>::new(100).in_window(SeqPoint::new(100), SeqOffset::new(10)));
        }

        #[test]
        fn true_in_middle() {
            assert!(SeqPoint::<Out>::new(105).in_window(SeqPoint::new(100), SeqOffset::new(10)));
        }

        #[test]
        fn true_at_last_included_point() {
            assert!(SeqPoint::<Out>::new(109).in_window(SeqPoint::new(100), SeqOffset::new(10)));
        }

        #[test]
        fn false_at_window_end_exclusive() {
            assert!(!SeqPoint::<Out>::new(110).in_window(SeqPoint::new(100), SeqOffset::new(10)));
        }

        #[test]
        fn false_before_window_start() {
            assert!(!SeqPoint::<Out>::new(99).in_window(SeqPoint::new(100), SeqOffset::new(10)));
        }

        #[test]
        fn handles_wraparound() {
            let start = SeqPoint::<Out>::new(u32::MAX - 4);
            let len = SeqOffset::new(10);
            assert!(SeqPoint::new(2).in_window(start, len));
            assert!(!SeqPoint::new(6).in_window(start, len));
        }
    }
}
