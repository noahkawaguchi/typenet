mod config;
mod report;
mod worker;

use {
    crate::{config::Config, report::Report},
    std::{iter, thread, time::Instant},
    typenet_utils::error::TraceableResult,
};

fn main() -> TraceableResult {
    let config = Config::load()?;
    let payload = worker::generate_payload(config.payload_size)?;

    let start = Instant::now();

    let outcomes = thread::scope(|scope| {
        iter::repeat_with(|| {
            scope.spawn(|| worker::run_connection(config.target_addr, config.target_port, &payload))
        })
        .take(config.connection_count.get())
        // Without the intermediate `collect`, this would just be a sequential loop with thread
        // creation overhead because iterators are lazy
        .collect::<Vec<_>>()
        .into_iter()
        .map(|handle| handle.join().map_err(|_| "Worker thread panicked".into()))
        .collect::<TraceableResult<Vec<_>>>()
    })?;

    println!("{}", Report::summarize(&outcomes, start.elapsed())?);

    Ok(())
}
