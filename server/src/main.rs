use {
    std::{iter, thread, time::Instant},
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

    let mut tuns = iter::repeat_with(|| tun::attach(&config.tun_name))
        .take(config.worker_count.get())
        .collect::<TraceableResult<Vec<_>>>()?;

    let shutdown_eventfd = shutdown.borrow_eventfd();

    // Define an `Instant` of creation shared across all worker threads so their logged timestamps
    // are on the same clock
    let birth = Instant::now();

    thread::scope(|scope| {
        let handles = tuns
            .iter_mut()
            .enumerate()
            .map(|(worker_id, tun)| {
                // Create references outside the `spawn` closure because it needs to be marked
                // `move` for `worker_id`
                let config_ref = &config;
                let shutdown_ref = &shutdown;

                scope.spawn(move || {
                    server::run(
                        tun,
                        |fd, timeout, watch_shutdown| {
                            poll::readable(fd, watch_shutdown.then_some(shutdown_eventfd), timeout)
                        },
                        || shutdown_ref.load_flag(),
                        config_ref,
                        birth,
                        worker_id,
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
