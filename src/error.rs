use std::{
    backtrace::{Backtrace, BacktraceStatus},
    fmt, io, num,
    panic::Location,
};

pub type Result<T = (), E = Error> = std::result::Result<T, E>;

/// Custom error struct that tracks caller location when created and optionally includes backtrace
/// information (controlled by `RUST_BACKTRACE=1` or `RUST_LIB_BACKTRACE=1`).
///
/// Location and backtrace if enabled are only shown in `Debug` representations, not `Display`.
pub struct Error {
    inner: ErrorKind,
    location: &'static Location<'static>,
    backtrace: Backtrace,
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[{}] {:?}", self.location, self.inner)?;

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

/// Generates `impl From<E> for Error` blocks for the passed set of error types, accepting the same
/// syntax as the enum definition for `ErrorKind`.
macro_rules! impl_from_error_types {
    {$($variant:ident($err_type:ty)),+ $(,)?} => {
        $(
            impl From<$err_type> for Error {
                #[track_caller]
                fn from(value: $err_type) -> Self {
                    Self {
                        inner: ErrorKind::$variant(value),
                        location: Location::caller(),
                        // Cheap no-op if the `RUST_BACKTRACE` or `RUST_LIB_BACKTRACE` backtrace
                        // environment variables are both not set
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
