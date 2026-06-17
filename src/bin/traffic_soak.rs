//! Feed a continuous, realistic, on-the-fly traffic stream through the detection
//! pipeline — no kernel, no NFQUEUE, no root. Exercises the whole upper layer
//! (IP filter → flow → Layer234 → signatures → protocol → ML → correlation) and
//! trains the learn-normal baseline so you can watch it reach `is_ready` and
//! start fast-pathing.
//!
//! Usage:  traffic_soak [num_packets]        (default 200000)

use std::net::IpAddr;

use crmonban::engine::{PipelineConfig, WorkerConfig, WorkerThread};
use crmonban::testing::synthetic::ContinuousTrafficGenerator;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let n: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200_000);

    let dst: IpAddr = "10.0.0.1".parse().unwrap();
    let mut generator = ContinuousTrafficGenerator::new(dst);
    let mut worker = WorkerThread::new(WorkerConfig::default());
    let config = PipelineConfig::default();

    let mut events = 0u64;
    let mut blocked = 0u64;
    println!(
        "feeding {} packets through the pipeline (no kernel/NFQUEUE)...\n{:>10} {:>8} {:>8} {:>8}  {}",
        n, "packets", "segment", "events", "blocked", "normal-model"
    );

    for i in 0..n {
        let pkt = generator.next_packet();
        let analysis = worker.process_full(pkt, &config).await;
        events += analysis.events.len() as u64;
        if analysis.verdict.is_blocking() {
            blocked += 1;
        }
        if i % 20_000 == 0 {
            let ready = worker.normal_model().read().is_ready(1000);
            println!(
                "{:>10} {:>8} {:>8} {:>8}  ready={}",
                i,
                generator.segment(),
                events,
                blocked,
                ready
            );
        }
    }

    println!(
        "\ndone: {} packets, {} detection events, {} blocked verdicts (final segment {})",
        n,
        events,
        blocked,
        generator.segment()
    );
}
