use {
    crate::error::TraceableResult,
    std::{fs::File, io::Read as _, num::NonZeroUsize},
};

const URANDOM: &str = "/dev/urandom";

/// Reads a random `u32` from `/dev/urandom`.
///
/// # Errors
///
/// Returns `Err` if the read fails.
pub fn random_u32() -> TraceableResult<u32> {
    let mut buf = [0u8; 4];
    File::open(URANDOM)?.read_exact(&mut buf)?;
    Ok(u32::from_ne_bytes(buf))
}

/// Reads `size` random bytes from `/dev/urandom`.
///
/// # Errors
///
/// Returns `Err` if the read fails.
pub fn random_bytes(size: NonZeroUsize) -> TraceableResult<Vec<u8>> {
    let mut buf = vec![0u8; size.get()];
    File::open(URANDOM)?.read_exact(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use {super::*, pretty_assertions::assert_ne};

    #[test]
    fn produces_different_u32s_across_calls() -> TraceableResult {
        assert_ne!(random_u32()?, random_u32()?);
        Ok(())
    }

    #[test]
    fn produces_different_bytes_across_calls() -> TraceableResult {
        const SIZE: NonZeroUsize = NonZeroUsize::new(65536).expect("65536 != 0");
        assert_ne!(random_bytes(SIZE)?, random_bytes(SIZE)?);
        Ok(())
    }
}
