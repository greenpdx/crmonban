//! Closed-loop FORWARD-path simulation driver.
//!
//! The same harness as `netsim_input`, with one difference: the protected host
//! is a *router*, and the server lives behind it at a different address. Because
//! neither endpoint is the host, **both directions transit the forward hook and
//! are inspected** — so, unlike INPUT, there is no trusted "outbound" traffic.
//!
//! LAN clients reach a WAN server through the router; one compromised LAN host
//! (known-bad) has every SYN dropped before it can leave the network.
//!
//! No kernel, no NFQUEUE, no root.
//!
//! Usage:  netsim_forward [num_lan_clients]   (default 50)

use std::net::{IpAddr, Ipv4Addr};

use crmonban::testing::netsim::{IdGen, MockClient, MockServer, PathNetwork, DEFAULT_FIRST_N};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let clients: u32 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);

    let router = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)); // the crmonban box
    let server_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)); // WAN server
    let server = MockServer::new(server_ip, vec![80, 443]);
    let mut net = PathNetwork::new_forward(router, server, DEFAULT_FIRST_N);

    // LAN clients browsing the WAN server through the router.
    for i in 0..clients {
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, (i % 250 + 1) as u8));
        let sport = 40000 + (i % 20000) as u16;
        let port = if i % 3 == 0 { 443 } else { 80 };
        let rounds = 3 + (i % 4);
        net.add_client(MockClient::new(src, sport, server_ip, port, rounds, 0x1000_0000 + i));
    }

    // A compromised LAN host: block it, then have it repeatedly try to reach out.
    let attacker = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 250));
    net.dataplane_mut()
        .worker_mut()
        .block_ip(attacker, "compromised lan host".to_string());
    for k in 0..20u32 {
        let mut atk = MockClient::new(attacker, 30000 + k as u16, server_ip, 80, 2, 0x9000_0000 + k);
        let mut id = IdGen::starting_at(800_000 + (k as u64) * 100);
        for syn in atk.open(&mut id) {
            net.inject_inbound(syn);
        }
    }

    let stats = net.run(1_000_000).await;

    let inspect_pct = if stats.inbound > 0 {
        100.0 * stats.inspected as f64 / stats.inbound as f64
    } else {
        0.0
    };

    println!("FORWARD-path simulation ({clients} LAN clients + compromised host)\n");
    println!("  router            : {router}");
    println!("  WAN server        : {server_ip}");
    println!("  transit packets   : {}", stats.inbound);
    println!("  routed to FORWARD : {}  (dst != host -> routed through)", stats.forward);
    println!("  routed to INPUT   : {}  (dst == host)", stats.input);
    println!("  trusted outbound  : {}  (FORWARD originates nothing at the router)", stats.outbound);
    println!("  ── netfilter funnel (both directions) ──");
    println!("  inspected (pipeline): {:>6}  ({inspect_pct:.1}% of transit)", stats.inspected);
    println!("  bypassed (kernel)  : {:>6}", stats.bypassed);
    println!("  ── verdicts ──");
    println!("  accepted : {}", stats.accepted);
    println!("  dropped  : {}", stats.dropped);
    println!("  bans     : {}", stats.bans);
    if stats.aborted {
        println!("  WARNING: hit step budget before quiescence");
    }
    println!(
        "\nclosed loop: the compromised host's {} dropped SYNs never reached the WAN.",
        stats.dropped
    );
}
