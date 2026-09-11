use {
    crate::error::TraceableResult,
    std::{fs::File, io::Read as _},
};

/// Gets a random `u32` from `/dev/urandom`.
///
/// # Errors
///
/// Returns `Err` if the read fails.
pub fn random_u32() -> TraceableResult<u32> {
    let mut buf = [0u8; 4];
    File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(u32::from_ne_bytes(buf))
}

#[cfg(test)]
mod tests {
    use {super::*, pretty_assertions::assert_ne};

    #[test]
    fn produces_different_values_across_calls() -> TraceableResult {
        assert_ne!(random_u32()?, random_u32()?);
        Ok(())
    }
}
