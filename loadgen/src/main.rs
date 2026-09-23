mod config;
mod report;
mod worker;

use {
    config::Config,
    std::{thread, time::Instant},
    typenet_utils::error::TraceableResult,
};

fn main() -> TraceableResult {
    let config = Config::load()?;
    let payload = worker::generate_payload(config.payload_size)?;

    let start = Instant::now();

    let outcomes = thread::scope(|scope| {
        #[expect(clippy::needless_collect, reason = "Threads must all be spawned before any join")]
        let handles = (0..config.connection_count.get())
            .map(|_| {
                let payload_ref = &payload;
                scope.spawn(|| {
                    worker::run_connection(config.target_addr, config.target_port, payload_ref)
                })
            })
            .collect::<Vec<_>>();

        handles
            .into_iter()
            .map(|handle| handle.join().map_err(|_| "Worker thread panicked".into()))
            .collect::<TraceableResult<Vec<_>>>()
    })?;

    let report = report::summarize(&outcomes, start.elapsed())?;
    report::print(&report);

    Ok(())
}
