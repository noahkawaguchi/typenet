use std::{
    backtrace::{Backtrace, BacktraceStatus},
    fmt::{self, Write as _},
    io, num,
};

pub type Result<T = (), E = Error> = std::result::Result<T, E>;

/// Custom error struct that optionally includes backtrace information (controlled by
/// `RUST_BACKTRACE=1` or `RUST_LIB_BACKTRACE=1`).
///
/// If enabled, backtraces are only shown in `Debug` representations, not `Display`.
pub struct Error {
    inner: ErrorKind,
    backtrace: Backtrace,
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.fmt(f)?;
        f.write_char('\n')?;

        match self.backtrace.status() {
            BacktraceStatus::Captured => {
                writeln!(f, "Stack backtrace (trimmed):")?;

                self.backtrace
                    .to_string()
                    .lines()
                    .skip_while(|line| !line.contains(env!("CARGO_CRATE_NAME")))
                    .take_while(|line| !line.contains("__rust_begin_short_backtrace"))
                    .try_for_each(|line| writeln!(f, "{line}"))
            }

            BacktraceStatus::Disabled => f.write_str(
                "Set `RUST_BACKTRACE=1` or `RUST_LIB_BACKTRACE=1` to display a backtrace",
            ),

            BacktraceStatus::Unsupported => f.write_str("(Backtrace unsupported)"),

            _ => f.write_str("Unexpected backtrace status"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.inner.fmt(f) }
}

#[cfg(test)]
impl PartialEq for Error {
    fn eq(&self, Self { inner, backtrace }: &Self) -> bool {
        &self.inner == inner && self.backtrace.status() == backtrace.status()
    }
}

/// Generates `impl From<E> for Error` blocks for the passed set of error types, accepting the same
/// syntax as the enum definition for `ErrorKind`.
macro_rules! impl_from_error_types {
    {$($variant:ident($err_type:ty)),+ $(,)?} => {
        $(
            impl From<$err_type> for Error {
                fn from(value: $err_type) -> Self {
                    Self {
                        inner: ErrorKind::$variant(value),
                        // Cheap no-op if `RUST_BACKTRACE` and `RUST_LIB_BACKTRACE` backtrace are
                        // both not set
                        backtrace: Backtrace::capture(),
                    }
                }
            }
        )+
    };
}

impl_from_error_types! {
    Static(&'static str),
    Dynamic(String),
    Io(io::Error),
    TryFromInt(num::TryFromIntError),
}

enum ErrorKind {
    Static(&'static str),
    Dynamic(String),
    Io(io::Error),
    TryFromInt(num::TryFromIntError),
}

impl fmt::Debug for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(s) => s.fmt(f),
            Self::Dynamic(s) => s.fmt(f),
            Self::Io(e) => write!(f, "I/O error: {e:?}"),
            Self::TryFromInt(e) => write!(f, "Integer conversion error: {e:?}"),
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(s) => s.fmt(f),
            Self::Dynamic(s) => s.fmt(f),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::TryFromInt(e) => write!(f, "Integer conversion error: {e}"),
        }
    }
}

#[cfg(test)]
impl PartialEq for ErrorKind {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Static(s1), Self::Static(s2)) => s1 == s2,

            (Self::Dynamic(s1), Self::Dynamic(s2)) => s1 == s2,

            (Self::Io(e1), Self::Io(e2)) => {
                e1.kind() == e2.kind()
                    && e1.raw_os_error() == e2.raw_os_error()
                    && e1.to_string() == e2.to_string()
            }

            (Self::TryFromInt(e1), Self::TryFromInt(e2)) => e1 == e2,

            _ => false,
        }
    }
}
