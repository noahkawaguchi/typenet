use std::fmt::{self, Write as _};

/// Wrapper implementing `Display` to convert the raw bytes of a payload into a printable
/// representation of its length, whether it is UTF-8, and optionally its content.
pub struct PrettyPayload<'a> {
    pub(super) data: &'a [u8],
    pub(super) include_content: bool,
}

impl fmt::Display for PrettyPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match str::from_utf8(self.data) {
            Ok("") => f.write_str("<no payload>"),

            Ok(s) => {
                write!(f, "{}-byte UTF-8 payload", s.len())?;

                if self.include_content {
                    write!(f, ": {}", s.escape_debug())?;
                }

                Ok(())
            }

            Err(_) => {
                let len = self.data.len();

                write!(f, "{len}-byte non-UTF-8 payload")?;

                if self.include_content {
                    f.write_char(':')?;

                    for (i, b) in self.data.iter().enumerate() {
                        f.write_char(if len <= 16 || i % 16 != 0 { ' ' } else { '\n' })?;
                        write!(f, "{b:02x}")?;
                    }
                }

                Ok(())
            }
        }
    }
}

/// Wrapper implementing `Display` for thousands-separator formatting.
pub(super) struct ThousandsSeparated<T>(pub(super) T);

pub(super) trait WithThousandsSeparators: Sized
where
    ThousandsSeparated<Self>: fmt::Display,
{
    /// Wraps `self` in `ThousandsSeparated` for pretty printing with thousands separators.
    fn with_thousands_separators(self) -> ThousandsSeparated<Self> { ThousandsSeparated(self) }
}

impl<T> WithThousandsSeparators for T where ThousandsSeparated<T>: fmt::Display {}

/// Generates `fmt::Display for ThousandsSeparated<T>` implementations for all types passed as
/// comma-separated arguments. Limited to unsigned integer types.
macro_rules! impl_display_thousands_separated {
    ($($t:ty),+ $(,)?) => {
        $(
            impl fmt::Display for ThousandsSeparated<$t> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    match (self.0 / 1000, self.0 % 1000) {
                        (0, rem) => write!(f, "{rem}"),
                        (thousands, rem) => write!(f, "{},{rem:03}", ThousandsSeparated(thousands)),
                    }
                }
            }
        )+
    };
}

impl_display_thousands_separated!(u16, u32);

#[cfg(test)]
mod tests {
    use {
        super::*,
        pretty_assertions::assert_eq,
        std::{num::ParseIntError, str::FromStr},
    };

    /// Removes commas from `s`, parses the result as `T`, and then adds commas back to that result.
    fn comma_round_trip<T>(s: &str) -> Result<String, T::Err>
    where
        T: FromStr,
        ThousandsSeparated<T>: fmt::Display,
    {
        s.replace(',', "")
            .parse::<T>()
            .map(|parsed| parsed.with_thousands_separators().to_string())
    }

    #[test]
    fn separates_all_widths() -> Result<(), ParseIntError> {
        for s in ["65,535", "4,321", "321", "21", "1", "0"] {
            assert_eq!(s, comma_round_trip::<u16>(s)?);
        }

        for s in [
            "4,294,967,295",
            "987,654,321",
            "87,654,321",
            "7,654,321",
            "654,321",
            "54,321",
            "4,321",
            "321",
            "21",
            "1",
            "0",
        ] {
            assert_eq!(s, comma_round_trip::<u32>(s)?);
        }

        Ok(())
    }

    #[test]
    fn handles_trailing_and_internal_zeros() -> Result<(), ParseIntError> {
        for s in ["60,000", "60,001", "4,000", "4,001", "300", "301", "20"] {
            assert_eq!(s, comma_round_trip::<u16>(s)?);
        }

        for s in [
            "4,000,000,000",
            "4,000,000,001",
            "900,000,000",
            "900,000,001",
            "80,000,000",
            "80,000,001",
            "4,000",
            "4,001",
            "300",
            "301",
            "20",
        ] {
            assert_eq!(s, comma_round_trip::<u32>(s)?);
        }

        Ok(())
    }
}
