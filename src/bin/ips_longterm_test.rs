//! Phase D — long-term detection validation, end to end through the wired
//! detector. Trains a population of normal hosts over (virtual) time, then
//! injects slow/persistent attackers and confirms the long-term path flags them
//! while the normal control stays clean.
//!
//! No kernel, no root.

use std::net::{IpAddr, Ipv4Addr};

use chrono::{Duration as ChronoDuration, Utc};

use crmonban::core::PacketAnalysis;
use crmonban::layer234::{Config, DetectorBuilder, Detector};
use crmonban::types::{IpProtocol, Packet, TcpFlags};

const S: i64 = 1_000; // ms per second
const EPOCH_MS: i64 = 60 * S;

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn fl(syn: bool, ack: bool, fin: bool, psh: bool) -> TcpFlags {
    TcpFlags { syn, ack, fin, rst: false, psh, urg: false, ece: false, cwr: false }
}

fn pkt(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, flags: TcpFlags, len: usize, ts_ms: i64) -> Packet {
    let mut p = Packet::new(0, src, dst, IpProtocol::Tcp, "test");
    if let Some(t) = p.tcp_mut() {
        t.src_port = sport;
        t.dst_port = dport;
        t.flags = flags;
        t.payload = vec![0x41; len];
    }
    p.raw_len = (40 + len) as u32;
    // Absolute virtual time, so each source's epochs roll over deterministically.
    p.timestamp = Utc::now() + ChronoDuration::milliseconds(ts_ms);
    p
}

async fn feed(det: &mut Detector, packets: Vec<Packet>) -> Vec<crmonban::core::DetectionEvent> {
    let mut events = Vec::new();
    for p in packets {
        let mut a = PacketAnalysis::new(p);
        det.process(&mut a).await;
        events.extend(a.take_events());
    }
    events
}

/// Normal host: each epoch a short session (handshake + a little data) to 443.
fn normal_traffic(src: IpAddr, dst: IpAddr, epochs: i64) -> Vec<Packet> {
    let mut v = Vec::new();
    for e in 0..epochs {
        let base = e * EPOCH_MS;
        let sp = 40000 + e as u16;
        v.push(pkt(src, dst, sp, 443, fl(true, false, false, false), 0, base));
        for i in 0..6 {
            v.push(pkt(src, dst, sp, 443, fl(false, true, false, true), 300, base + (i + 1) * S));
        }
    }
    v
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Tuned-for-test long-term config: short warmups so the demo converges.
    let mut config = Config::default();
    config.long_term.enable = true;
    config.long_term.epoch_secs = 60;
    config.long_term.horizon_epochs = 12;
    config.long_term.min_baseline_profiles = 20;
    config.long_term.min_history_epochs = 2;
    config.long_term.population_threshold = 1.0;
    config.long_term.self_drift_threshold = 1.0;
    config.long_term.auto_learn = true;

    let mut det = DetectorBuilder::from_config(&config)
        .build_with_config(&config)
        .expect("build detector");

    let dst = v4(10, 0, 0, 1);

    // ── Train: a population of normal hosts over several epochs. ──
    for s in 0..40u32 {
        let src = v4(198, 18, (s >> 8) as u8, (s & 0xff) as u8 + 1);
        let _ = feed(&mut det, normal_traffic(src, dst, 4)).await;
    }
    println!("trained long-term baseline\n");
    println!("{:<30} {:>10}  {}", "source", "long-term?", "detection");
    println!("{}", "-".repeat(70));

    // helper: does the event set contain a long-term detection, and what kind?
    // Report the LATEST long-term verdict: as a source's window matures the
    // classification stabilizes to its true kind (early evals are based on a
    // half-filled window).
    let summarize = |events: &[crmonban::core::DetectionEvent]| -> Option<String> {
        events
            .iter()
            .rev()
            .find(|e| e.message.starts_with("Long-term"))
            .map(|e| format!("{:?}", e.event_type))
    };

    // ── Control: an ordinary new host — must stay clean. ──
    let ctrl = v4(203, 0, 113, 7);
    let ev = feed(&mut det, normal_traffic(ctrl, dst, 6)).await;
    print_row("normal host (control)", &summarize(&ev));

    // ── Beaconing: one regular connection per epoch to a single port. ──
    let beacon = v4(45, 33, 9, 1);
    let mut bp = Vec::new();
    for e in 0..8 {
        let base = e * EPOCH_MS;
        let sp = 50000 + e as u16;
        bp.push(pkt(beacon, dst, sp, 443, fl(true, false, false, false), 0, base));
        bp.push(pkt(beacon, dst, sp, 443, fl(false, true, false, true), 40, base + S));
        bp.push(pkt(beacon, dst, sp, 443, fl(false, true, true, false), 0, base + 2 * S));
    }
    let ev = feed(&mut det, bp).await;
    print_row("beaconing (1 conn/epoch)", &summarize(&ev));

    // ── Exfil: large outbound volume each epoch. ──
    let exfil = v4(45, 33, 9, 2);
    let mut xp = Vec::new();
    for e in 0..6 {
        let base = e * EPOCH_MS;
        let sp = 51000 + e as u16;
        xp.push(pkt(exfil, dst, sp, 443, fl(true, false, false, false), 0, base));
        for i in 0..40 {
            xp.push(pkt(exfil, dst, sp, 443, fl(false, true, false, true), 1400, base + (i % 50 + 1) * S / 10));
        }
    }
    let ev = feed(&mut det, xp).await;
    print_row("bulk exfil (high volume)", &summarize(&ev));

    // ── Low-and-slow scan: a new destination port each epoch. ──
    let scan = v4(45, 33, 9, 3);
    let mut sp_pkts = Vec::new();
    for e in 0..30 {
        let base = e * (EPOCH_MS / 4); // a probe every 15s -> few per epoch
        sp_pkts.push(pkt(scan, dst, 40000, 1000 + e as u16, fl(true, false, false, false), 0, base));
    }
    let ev = feed(&mut det, sp_pkts).await;
    print_row("low-and-slow scan", &summarize(&ev));
}

fn print_row(name: &str, kind: &Option<String>) {
    match kind {
        Some(k) => println!("{:<30} {:>10}  {}", name, "YES", k),
        None => println!("{:<30} {:>10}  {}", name, "no", "-"),
    }
}
