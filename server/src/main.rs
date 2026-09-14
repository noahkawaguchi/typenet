use {
    std::thread,
    typenet_server::{
        config::Config,
        server,
        sys::{ShutdownSignal, poll, tun},
        thread_panic_msg,
    },
    typenet_utils::error::TraceableResult,
};

/// Runs an echo server that uses a TUN device to read and write IPv4 packets: TCP, UDP, and ICMP.
///
/// Spawns one worker thread per `Config::worker_count`, each attached to its own queue of the same
/// multi-queue TUN device and managing a disjoint set of TCP connections. (Since UDP and ICMP are
/// stateless, they can be handled independently by any thread.)
fn main() -> TraceableResult {
    let shutdown = ShutdownSignal::install()?;
    let config = Config::load()?;

    let mut tuns = (0..config.worker_count.get())
        .map(|_| tun::attach(&config.tun_name))
        .collect::<TraceableResult<Vec<_>>>()?;

    thread::scope(|scope| {
        let handles = tuns
            .iter_mut()
            .map(|tun| {
                scope.spawn(|| {
                    server::run(
                        tun,
                        |fd, timeout, watch_shutdown| {
                            poll::readable(
                                fd,
                                watch_shutdown.then(|| shutdown.borrow_eventfd()),
                                timeout,
                            )
                        },
                        || shutdown.load_flag(),
                        &config,
                    )
                })
            })
            .collect::<Vec<_>>();

        // Each worker thread above inherited the still-unblocked mask from this thread at spawn
        // time, so they can keep reacting to `SIGINT`. Blocking it here stops `SIGINT` from being
        // delivered to this thread instead of a worker (particularly used for repeated Ctrl+C
        // during graceful shutdown).
        ShutdownSignal::block_sigint_on_this_thread()?;

        handles
            .into_iter()
            .try_for_each(|handle| handle.join().map_err(thread_panic_msg)?)
    })
}
