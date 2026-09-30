mod config;
mod report;
mod server_cpu;
mod worker;

use {
    crate::{config::Config, report::Report, server_cpu::ServerCpuMeter},
    std::{iter, thread, time::Instant},
    typenet_utils::{
        error::{TraceableResult, thread_panic_msg},
        sys,
    },
};

fn main() -> TraceableResult {
    let config = Config::load()?;

    let payloads = iter::repeat_with(|| sys::random_bytes(config.payload_size))
        .take(config.connection_count.get())
        .collect::<TraceableResult<Vec<_>>>()?;

    let server_cpu_meter = ServerCpuMeter::start();
    let start = Instant::now();

    let outcomes = thread::scope(|scope| {
        payloads
            .into_iter()
            .map(|payload| {
                scope.spawn(move || {
                    worker::run_connection(config.target_addr, config.target_port, &payload)
                })
            })
            // Without the intermediate `collect`, this would just be a sequential loop with thread
            // creation overhead because iterators are lazy
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().map_err(thread_panic_msg).map_err(Into::into))
            .collect::<TraceableResult<Vec<_>>>()
    })?;

    let wall_time = start.elapsed();
    let server_cpu = server_cpu_meter.and_then(ServerCpuMeter::stop);

    println!("{}", Report::summarize(&outcomes, wall_time, server_cpu)?);

    Ok(())
}
