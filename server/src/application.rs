use {
    std::{borrow::Cow, str::FromStr},
    typenet_stack::application::Application,
    typenet_utils::error::TraceableError,
};

/// The set of applications that the server supports.
pub enum ServerApp {
    Echo(EchoApp),
    Shout(ShoutApp),
}

impl Default for ServerApp {
    fn default() -> Self { Self::Echo(EchoApp) }
}

impl FromStr for ServerApp {
    type Err = TraceableError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "echo" => Ok(Self::Echo(EchoApp)),

            "shout" => Ok(Self::Shout(ShoutApp)),

            other => {
                Err(format!("Server app must be either `echo` or `shout`, got `{other}`").into())
            }
        }
    }
}

/// A `Application` that echoes back exactly what it receives.
pub struct EchoApp;

impl Application for EchoApp {
    fn handle_udp<'a>(&mut self, payload: Cow<'a, [u8]>) -> Cow<'a, [u8]> { payload }

    fn handle_tcp(&mut self, data: &[u8], send_buffer: &mut impl Extend<u8>) {
        send_buffer.extend(data.iter().copied());
    }
}

/// An `Application` that capitalizes all ASCII.
pub struct ShoutApp;

impl Application for ShoutApp {
    fn handle_udp<'a>(&mut self, payload: Cow<'a, [u8]>) -> Cow<'a, [u8]> {
        Cow::Owned(payload.iter().map(u8::to_ascii_uppercase).collect())
    }

    fn handle_tcp(&mut self, data: &[u8], send_buffer: &mut impl Extend<u8>) {
        send_buffer.extend(data.iter().map(u8::to_ascii_uppercase));
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

        let echo = EchoApp.handle_udp(Cow::Borrowed(PAYLOAD));

        // Check both `assert_eq` and `assert_matches` because borrowed and owned `Cow` are
        // considered equal for equal content
        assert_eq!(echo, PAYLOAD);
        assert_matches!(echo, Cow::Borrowed(_), "Should not allocate for a trivial echo");
    }

    #[test]
    fn echo_tcp_appends_data_to_send_buffer() {
        let mut send_buffer = Vec::from(b"Hello");
        EchoApp.handle_tcp(b"World", &mut send_buffer);
        assert_eq!(send_buffer, b"HelloWorld");
    }

    #[test]
    fn shout_udp_capitalizes_and_allocates() {
        let shout = ShoutApp.handle_udp(Cow::Borrowed(b"Hello!!!"));
        assert_eq!(shout, Vec::from(b"HELLO!!!"));
        assert_matches!(shout, Cow::Owned(_), "Should allocate when transforming input");
    }

    #[test]
    fn shout_tcp_appends_capitalized_data_to_send_buffer() {
        let mut send_buffer = Vec::from(b"Hello");
        ShoutApp.handle_tcp(b"World", &mut send_buffer);
        assert_eq!(send_buffer, b"HelloWORLD");
    }
}
