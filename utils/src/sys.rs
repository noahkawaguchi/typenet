use {
    crate::error::TraceableResult,
    std::{any::type_name, env, fmt, fs::File, io::Read as _, num::NonZeroUsize, str::FromStr},
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

/// Reads in an environment variable using `key` and parses it as `T`, or if not found, returns
/// `Ok(None)`.
///
/// # Errors
///
/// Returns `Err` if the environment variable is present but is not valid Unicode or cannot be
/// parsed as `T`.
pub fn parse_env<T>(key: &str) -> TraceableResult<Option<T>>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    match env::var(key) {
        Err(env::VarError::NotPresent) => Ok(None),

        Err(env::VarError::NotUnicode(_)) => {
            Err(format!("Environment variable {key} present but not valid Unicode").into())
        }

        Ok(val) => val
            .parse()
            .map_err(|e| {
                format!(
                    "Environment variable {key} present but could not be parsed as {}: {e}",
                    type_name::<T>()
                )
                .into()
            })
            .map(Some),
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        pretty_assertions::{assert_eq, assert_matches, assert_ne},
        std::{ffi::OsStr, os::unix::ffi::OsStrExt as _},
    };

    /// Sets the environment variable `key` to `val`. Each test should use a unique `key` to avoid
    /// interfering with other tests.
    #[expect(unsafe_code, reason = "Setting environment variables to test `parse_env`")]
    fn set_env(key: &str, val: impl AsRef<OsStr>) {
        // SAFETY: These test threads only access the environment through `std::env::var`, which
        // synchronizes reads and writes internally.
        unsafe { env::set_var(key, val) };
    }

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

    #[test]
    fn none_for_missing_env_var() {
        assert_eq!(parse_env::<u16>("TYPENET_TEST_ENV_NOT_PRESENT"), Ok(None));
    }

    #[test]
    fn err_for_non_unicode_env_var() {
        const KEY: &str = "TYPENET_TEST_ENV_NOT_UNICODE";
        set_env(KEY, OsStr::from_bytes(b"\xFF"));

        assert_matches!(
            parse_env::<u16>(KEY).map_err(|e| e.to_string()),
            Err(e) if e.contains("not valid Unicode"),
        );
    }

    #[test]
    fn err_for_env_var_unparsable_as_type() {
        const KEY: &str = "TYPENET_TEST_ENV_UNPARSABLE";
        set_env(KEY, "not a number");

        assert_matches!(
            parse_env::<u16>(KEY).map_err(|e| e.to_string()),
            Err(e) if e.contains("could not be parsed as u16"),
        );
    }

    #[test]
    fn parses_valid_env_var() {
        const KEY: &str = "TYPENET_TEST_ENV_VALID";
        set_env(KEY, "8080");
        assert_eq!(parse_env::<u16>(KEY), Ok(Some(8080)));
    }
}
