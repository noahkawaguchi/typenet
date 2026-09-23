use {
    std::{
        fs::File,
        io::{Read as _, Write as _},
        net::{IpAddr, Shutdown, TcpStream},
        num::{NonZeroU16, NonZeroUsize},
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

/// Reads `size` random bytes from `/dev/urandom` to use as a payload shared across connections.
///
/// # Errors
///
/// Returns `Err` if the read fails.
pub(crate) fn generate_payload(size: NonZeroUsize) -> TraceableResult<Vec<u8>> {
    let mut payload = vec![0u8; size.get()];
    File::open("/dev/urandom")?.read_exact(&mut payload)?;
    Ok(payload)
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
