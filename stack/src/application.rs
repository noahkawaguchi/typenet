use std::borrow::Cow;

/// Application-level behavior that decides what data to send back over UDP and TCP.
///
/// (ICMP Echo Request/Reply has no equivalent hook because mirroring the payload verbatim is what
/// that protocol is.)
pub trait Application {
    /// Decides what to send back in reply to a UDP datagram's `payload`.
    fn handle_udp<'a>(&mut self, payload: Cow<'a, [u8]>) -> Cow<'a, [u8]>;

    /// Reacts to `data` arriving on a TCP connection, appending anything to send in response to
    /// `send_buffer`.
    fn handle_tcp(&mut self, data: &[u8], send_buffer: &mut impl Extend<u8>);
}

/// A minimal echo `Application` for exercising generic code paths in this crate's own tests without
/// depending on `typenet-server`, where the real `Application` implementations live.
#[cfg(test)]
pub(crate) struct TestApp;

#[cfg(test)]
impl Application for TestApp {
    fn handle_udp<'a>(&mut self, payload: Cow<'a, [u8]>) -> Cow<'a, [u8]> { payload }

    fn handle_tcp(&mut self, data: &[u8], send_buffer: &mut impl Extend<u8>) {
        send_buffer.extend(data.iter().copied());
    }
}

/// An `Application` that capitalizes all ASCII letters. Used for tests that need to prove a reply's
/// content actually came from the application, rather than merely happening to match a hardcoded
/// echo.
#[cfg(test)]
pub(crate) struct ShoutingTestApp;

#[cfg(test)]
impl Application for ShoutingTestApp {
    fn handle_udp<'a>(&mut self, payload: Cow<'a, [u8]>) -> Cow<'a, [u8]> {
        Cow::Owned(payload.iter().map(u8::to_ascii_uppercase).collect())
    }

    fn handle_tcp(&mut self, data: &[u8], send_buffer: &mut impl Extend<u8>) {
        send_buffer.extend(data.iter().map(u8::to_ascii_uppercase));
    }
}
