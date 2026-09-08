pub mod poll;
pub mod tun;
pub use shutdown_signal::ShutdownSignal;

mod shutdown_signal;

use {
    crate::error::Result,
    std::{fs::File, io::Read as _},
};

pub(crate) fn random_u32() -> Result<u32> {
    let mut buf = [0u8; 4];
    File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(u32::from_ne_bytes(buf))
}

#[cfg(test)]
mod tests {
    use {super::*, pretty_assertions::assert_ne};

    #[test]
    fn produces_different_values_across_calls() -> Result {
        assert_ne!(random_u32()?, random_u32()?);
        Ok(())
    }
}
