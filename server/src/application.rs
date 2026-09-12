use {
    std::{borrow::Cow, str::FromStr},
    typenet_stack::application::Application,
    typenet_utils::error::TraceableError,
};

/// The set of applications that the server supports.
#[derive(Default, Clone, Copy)]
pub(crate) enum ServerApp {
    /// An `Application` that echoes back exactly what it receives.
    #[default]
    Echo,

    /// An `Application` that capitalizes all ASCII letters.
    Shout,
}

impl FromStr for ServerApp {
    type Err = TraceableError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "echo" => Ok(Self::Echo),
            "shout" => Ok(Self::Shout),
            _ => Err(format!("Server app must be either `echo` or `shout`, got `{s}`").into()),
        }
    }
}

impl Application for ServerApp {
    fn handle_udp<'a>(&mut self, payload: Cow<'a, [u8]>) -> Cow<'a, [u8]> {
        match self {
            Self::Echo => payload,
            Self::Shout => Cow::Owned(payload.iter().map(u8::to_ascii_uppercase).collect()),
        }
    }

    fn handle_tcp(&mut self, data: &[u8], send_buffer: &mut impl Extend<u8>) {
        match self {
            Self::Echo => send_buffer.extend(data.iter().copied()),
            Self::Shout => send_buffer.extend(data.iter().map(u8::to_ascii_uppercase)),
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        pretty_assertions::{assert_eq, assert_matches},
    };

    #[test]
    fn echo_udp_echoes_without_allocating() {
        const PAYLOAD: &[u8] = b"Hello!!!";

        let echo = ServerApp::Echo.handle_udp(Cow::Borrowed(PAYLOAD));

        // Check both `assert_eq` and `assert_matches` because borrowed and owned `Cow` are
        // considered equal for equal content
        assert_eq!(echo, PAYLOAD);
        assert_matches!(echo, Cow::Borrowed(_), "Should not allocate for a trivial echo");
    }

    #[test]
    fn echo_tcp_appends_data_to_send_buffer() {
        let mut send_buffer = Vec::from(b"Hello");
        ServerApp::Echo.handle_tcp(b"World", &mut send_buffer);
        assert_eq!(send_buffer, b"HelloWorld");
    }

    #[test]
    fn shout_udp_capitalizes_and_allocates() {
        let shout = ServerApp::Shout.handle_udp(Cow::Borrowed(b"Hello!!!"));
        assert_eq!(shout, Vec::from(b"HELLO!!!"));
        assert_matches!(shout, Cow::Owned(_), "Should allocate when transforming input");
    }

    #[test]
    fn shout_tcp_appends_capitalized_data_to_send_buffer() {
        let mut send_buffer = Vec::from(b"Hello");
        ServerApp::Shout.handle_tcp(b"World", &mut send_buffer);
        assert_eq!(send_buffer, b"HelloWORLD");
    }
}
