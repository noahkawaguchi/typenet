use {
    std::{
        io::{Read as _, Write as _},
        net::{IpAddr, Shutdown, TcpStream},
        num::NonZeroU16,
        time::{Duration, Instant},
    },
    typenet_utils::error::TraceableResult,
};

pub(crate) struct ConnectionOutcome {
    /// Whether the echoed reply matched the sent payload byte-for-byte.
    pub verified: bool,

    /// The number of bytes read back from the server.
    pub bytes_echoed: usize,

    /// The time from just before connecting until the last byte of the reply was read.
    pub round_trip: Duration,
}

/// Connects to `addr:port`, sends `payload`, half-closes the write side, reads the echoed reply to
/// EOF, and verifies it matches `payload` byte-for-byte.
///
/// # Errors
///
/// Returns `Err` for I/O failures establishing the connection or during the read/write.
pub(crate) fn run_connection(
    addr: IpAddr,
    port: NonZeroU16,
    payload: &[u8],
) -> TraceableResult<ConnectionOutcome> {
    let start = Instant::now();

    let mut stream = TcpStream::connect((addr, port.get()))?;
    stream.write_all(payload)?;
    stream.shutdown(Shutdown::Write)?;

    let mut echoed = Vec::with_capacity(payload.len());
    stream.read_to_end(&mut echoed)?;

    Ok(ConnectionOutcome {
        verified: echoed == payload,
        bytes_echoed: echoed.len(),
        round_trip: start.elapsed(),
    })
}
