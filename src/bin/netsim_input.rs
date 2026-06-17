//! Closed-loop INPUT-path simulation driver.
//!
//! Stands up a mock host server, drives a batch of reactive benign clients plus
//! a known-bad attacker through the mock netfilter dataplane (conntrack funnel +
//! inline crmonban pipeline), and prints what happened: how much traffic was
//! inspected vs bypassed (the funnel), and how the attacker's packets were
//! dropped before the host ever saw them (the closed loop).
//!
//! No kernel, no NFQUEUE, no root — same as `traffic_soak`.
//!
//! Usage:  netsim_input [num_benign_clients]   (default 50)

use std::net::{IpAddr, Ipv4Addr};

use crmonban::testing::netsim::{InputNetwork, MockClient, MockServer, DEFAULT_FIRST_N};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let benign: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);

    let host = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let server = MockServer::new(host, vec![80, 443]);
    let mut net = InputNetwork::new(server, DEFAULT_FIRST_N);

    // A fleet of benign clients, each from a distinct source running a short
    // HTTP-ish conversation against the host.
    for i in 0..benign {
        let src = IpAddr::V4(Ipv4Addr::new(203, 0, 113, (i % 250 + 1) as u8));
        let sport = 40000 + (i % 20000) as u16;
        let port = if i % 3 == 0 { 443 } else { 80 };
        let rounds = 3 + (i % 4); // 3..6 request/response rounds
        net.add_client(MockClient::new(src, sport, host, port, rounds, 0x1000_0000 + i));
    }

    // One known-bad source (e.g. from threat intel): block it, then have it try
    // to connect repeatedly. Every SYN must be dropped inline.
    let attacker = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 13));
    net.dataplane_mut()
        .worker_mut()
        .block_ip(attacker, "known bad (threat intel)".to_string());
    for k in 0..20u32 {
        let mut atk = MockClient::new(attacker, 30000 + k as u16, host, 80, 2, 0x9000_0000 + k);
        let mut id = crmonban::testing::netsim::IdGen::starting_at(800_000 + (k as u64) * 100);
        for syn in atk.open(&mut id) {
            net.inject_inbound(syn);
        }
    }

    let model_ready = net.dataplane_mut().model_ready(1000);
    let stats = net.run(1_000_000).await;

    let inspect_pct = if stats.inbound > 0 {
        100.0 * stats.inspected as f64 / stats.inbound as f64
    } else {
        0.0
    };

    println!("INPUT-path simulation ({benign} benign clients + blocked attacker)\n");
    println!("  inbound packets   : {}", stats.inbound);
    println!("  outbound (replies): {}", stats.outbound);
    println!("  ── netfilter funnel ──");
    println!("  inspected (pipeline): {:>6}  ({inspect_pct:.1}% of inbound)", stats.inspected);
    println!("  bypassed (kernel)  : {:>6}", stats.bypassed);
    println!("  ── verdicts ──");
    println!("  accepted : {}", stats.accepted);
    println!("  dropped  : {}", stats.dropped);
    println!("  bans     : {}", stats.bans);
    println!("  learn-normal ready : {model_ready}");
    if stats.aborted {
        println!("  WARNING: hit step budget before quiescence");
    }
    println!(
        "\nclosed loop: the attacker's {} dropped SYNs produced 0 host replies.",
        stats.dropped
    );
}
