use typenet::{
    config::Config,
    error::TraceableResult,
    server,
    sys::{ShutdownSignal, poll, tun},
};

/// Runs an echo server that uses a TUN device to read and write IPv4 packets: TCP, UDP, and ICMP.
fn main() -> TraceableResult {
    let shutdown = ShutdownSignal::install()?;
    let config = Config::load()?;
    let mut tun = tun::attach(&config.tun_name)?;
    server::run(&mut tun, |fd, timeout| poll::readable(fd, timeout), || shutdown.load(), &config)
}
