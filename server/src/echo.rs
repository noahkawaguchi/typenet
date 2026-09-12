use {std::borrow::Cow, typenet_stack::application::Application};

/// The `Application` this server currently runs, echoing back exactly what it receives for both UDP
/// and TCP.
pub struct EchoApp;

impl Application for EchoApp {
    fn handle_udp<'a>(&mut self, payload: Cow<'a, [u8]>) -> Cow<'a, [u8]> { payload }

    fn handle_tcp(&mut self, data: &[u8], send_buffer: &mut impl Extend<u8>) {
        send_buffer.extend(data.iter().copied());
    }
}

#[cfg(test)]
mod tests {
    use {super::*, pretty_assertions::assert_eq};

    #[test]
    fn handle_udp_echoes_without_allocating() {
        const PAYLOAD: &[u8] = b"Hello!!!";

        assert_eq!(
            EchoApp.handle_udp(Cow::Borrowed(PAYLOAD)),
            Cow::Borrowed(PAYLOAD),
            "Should not allocate for a trivial echo"
        );
    }

    #[test]
    fn handle_tcp_appends_data_to_send_buffer() {
        let mut send_buffer = Vec::from(*b"AB");

        EchoApp.handle_tcp(b"CD", &mut send_buffer);

        assert_eq!(send_buffer, b"ABCD");
    }
}
