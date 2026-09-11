use {
    crate::error::TraceableResult,
    std::{
        any::type_name,
        fmt,
        slice::SliceIndex,
        time::{Duration, Instant},
    },
};

pub trait TryAdd<T>: Sized {
    /// Attempts to add `self + rhs`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if overflow occurred.
    fn try_add(self, rhs: T) -> TraceableResult<Self>;
}

/// Generates `TryAdd<Self>` implementations for all types passed as comma-separated arguments.
/// Limited to primitive integer types.
macro_rules! impl_try_add_self {
    ($($t:ty),+ $(,)?) => {
        $(
            impl TryAdd<Self> for $t {
                fn try_add(self, rhs: Self) -> TraceableResult<Self> {
                    self.checked_add(rhs).ok_or_else(|| {
                        format!("Overflowed `{}` adding {self} and {rhs}", stringify!($t)).into()
                    })
                }
            }
        )+
    };
}

impl_try_add_self!(usize, u16);

impl TryAdd<Duration> for Instant {
    fn try_add(self, rhs: Duration) -> TraceableResult<Self> {
        self.checked_add(rhs)
            .ok_or_else(|| format!("Overflowed `Instant` adding {} seconds", rhs.as_secs()).into())
    }
}

pub trait TryGet {
    /// Attempts to get a reference to the element or subslice at `index`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if out of bounds.
    fn try_get<I>(&self, index: I) -> TraceableResult<&I::Output>
    where
        I: SliceIndex<Self> + fmt::Debug + Clone;
}

impl<T> TryGet for [T] {
    fn try_get<I>(&self, index: I) -> TraceableResult<&I::Output>
    where
        I: SliceIndex<Self> + fmt::Debug + Clone,
    {
        let n = self.len();

        self.get(index.clone()).ok_or_else(|| {
            format!("Index {index:?} out of range on `[{}]` of length {n}", type_name::<T>()).into()
        })
    }
}

pub trait TryGetMut {
    /// Attempts to get a mutable reference to the element or subslice at `index`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if out of bounds.
    fn try_get_mut<I>(&mut self, index: I) -> TraceableResult<&mut I::Output>
    where
        I: SliceIndex<Self> + fmt::Debug + Clone;
}

impl<T> TryGetMut for [T] {
    fn try_get_mut<I>(&mut self, index: I) -> TraceableResult<&mut I::Output>
    where
        I: SliceIndex<Self> + fmt::Debug + Clone,
    {
        let n = self.len();

        self.get_mut(index.clone()).ok_or_else(|| {
            format!("Index {index:?} out of range on `[{}]` of length {n}", type_name::<T>()).into()
        })
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        pretty_assertions::{assert_eq, assert_matches},
    };

    #[test]
    fn try_add_errors_for_overflow() {
        assert_matches!(u16::MAX.try_add(1), Err(_));
        assert_matches!(Instant::now().try_add(Duration::MAX), Err(_));
    }

    #[test]
    fn try_add_adds_successfully() -> TraceableResult {
        assert_eq!((u16::MAX - 1).try_add(1), Ok(u16::MAX));

        let now = Instant::now();
        let an_hour = Duration::from_hours(1);

        let an_hour_from_now = now
            .checked_add(an_hour)
            .ok_or("Regular checked_add overflowed")?;

        assert_eq!(now.try_add(an_hour), Ok(an_hour_from_now));

        Ok(())
    }

    #[test]
    fn try_get_and_try_get_mut_error_out_of_bounds() {
        let data1 = [1, 2, 3, 4, 5];
        assert_matches!(data1.try_get(5), Err(_));
        assert_matches!(data1.try_get(2..10), Err(_));

        let mut data2 = [10, 20, 30, 40, 50];
        assert_matches!(data2.try_get_mut(5), Err(_));
        assert_matches!(data2.try_get_mut(2..10), Err(_));
    }

    #[test]
    fn try_get_and_try_get_mut_succeed_in_bounds() {
        let data1 = [1, 2, 3, 4, 5];
        assert_eq!(data1.try_get(2), Ok(&3));
        assert_eq!(data1.try_get(1..3), Ok(&[2, 3][..]));

        let mut data2 = [10, 20, 30, 40, 50];
        assert_eq!(data2.try_get_mut(2), Ok(&mut 30));
        assert_eq!(data2.try_get_mut(1..3), Ok(&mut [20, 30][..]));
    }
}
