use std::{borrow::Cow, fmt, panic::Location};

pub type Result<T = (), E = Error> = std::result::Result<T, E>;

/// Custom error struct that tracks the location of the caller when created and avoids unnecessary
/// allocations.
pub struct Error {
    error: ErrorKind,
    location: &'static Location<'static>,
}

impl Error {
    /// Creates a `Self` from `message`. Prefer creating the type this way over the `Box`-based
    /// method where possible to avoid unnecessary allocations.
    #[track_caller]
    pub(crate) fn msg(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorKind::Message(message.into()))
    }

    #[track_caller]
    const fn new(error: ErrorKind) -> Self { Self { error, location: Location::caller() } }
}

impl<E: Into<Box<dyn std::error::Error>>> From<E> for Error {
    #[track_caller]
    fn from(value: E) -> Self { Self::new(ErrorKind::Foreign(value.into())) }
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

enum ErrorKind {
    /// An original error message.
    Message(Cow<'static, str>),

    /// An error from another error.
    Foreign(Box<dyn std::error::Error + 'static>),
}

impl fmt::Debug for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(m) => m.fmt(f),
            Self::Foreign(e) => e.fmt(f),
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Message(m) => m.fmt(f),
            Self::Foreign(e) => e.fmt(f),
        }
    }
}
