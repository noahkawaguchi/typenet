use std::{fmt, io, num, panic::Location};

pub type Result<T = (), E = Error> = std::result::Result<T, E>;

/// Custom error struct that tracks the location of the caller when created and avoids unnecessary
/// allocations.
pub struct Error {
    error: ErrorKind,
    location: &'static Location<'static>,
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {:?}", self.location, self.error)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.location, self.error)
    }
}

/// Generates `impl From<E> for Error` blocks for the passed set of error types, accepting the same
/// syntax as the enum definition for `ErrorKind`.
macro_rules! impl_from_error_types {
    {$($variant:ident($err_type:ty)),+ $(,)?} => {
        $(
            impl From<$err_type> for Error {
                #[track_caller]
                fn from(value: $err_type) -> Self {
                    Self { error: ErrorKind::$variant(value), location: Location::caller() }
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
