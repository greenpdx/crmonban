//! Adversarial fuzz of every protocol parser via the SAME entry the packet engine
//! uses: `ProtocolDetector::analyze`. Feeds empty/short/truncated/structured/random
//! packets at every protocol port (TCP+UDP) and asserts NO parser panics. Exits
//! non-zero if any input panics. This guards the class of bug that crash-looped
//! crmonban in production (a malformed SSH packet -> `payload[6..5]` slice panic).

use std::net::{IpAddr, Ipv4Addr};
use std::panic::{self, AssertUnwindSafe};

use crmonban::protocols::{ProtocolConfig, ProtocolDetector};
use crmonban::types::{Flow, IpProtocol, Packet};

fn v4() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
}

fn mk(proto: IpProtocol, sport: u16, dport: u16, payload: &[u8]) -> Packet {
    let mut p = Packet::new(1, v4(), v4(), proto, "fuzz");
    match proto {
        IpProtocol::Tcp => {
            if let Some(t) = p.tcp_mut() {
                t.src_port = sport;
                t.dst_port = dport;
                t.payload = payload.to_vec();
            }
        }
        IpProtocol::Udp => {
            if let Some(u) = p.udp_mut() {
                u.src_port = sport;
                u.dst_port = dport;
                u.payload = payload.to_vec();
            }
        }
        _ => {}
    }
    p.raw_len = 40 + payload.len() as u32;
    p
}

fn fuzz_one(
    det: &ProtocolDetector,
    proto: IpProtocol,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Option<String> {
    let pkt = mk(proto, sport, dport, payload);
    let mut flow = Flow::new(1, &pkt);
    let r = panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = det.analyze(&pkt, &mut flow);
    }));
    match r {
        Ok(_) => None,
        Err(e) => {
            let msg = e
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            let head: Vec<u8> = payload.iter().take(24).copied().collect();
            Some(format!(
                "PANIC proto={:?} sport={} dport={} len={} head={:02x?} :: {}",
                proto,
                sport,
                dport,
                payload.len(),
                head,
                msg
            ))
        }
    }
}

fn record(o: Option<String>, total: &mut u64, panics: &mut u64, first: &mut Vec<String>) {
    *total += 1;
    if let Some(m) = o {
        *panics += 1;
        if first.len() < 40 {
            first.push(m);
        }
    }
}

// deterministic xorshift64 — no external rand dep, reproducible
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
    fn range(&mut self, n: usize) -> usize {
        (self.next() as usize) % n.max(1)
    }
}

fn main() {
    // Silence the default panic printer; we report from catch_unwind ourselves.
    panic::set_hook(Box::new(|_| {}));

    let det = ProtocolDetector::new(ProtocolConfig::default());
    let tcp_ports: [u16; 22] = [
        22, 80, 443, 53, 25, 21, 110, 143, 445, 2049, 135, 88, 3389, 5060, 1883, 502, 20000, 5900,
        587, 993, 8080, 4444,
    ];
    let udp_ports: [u16; 11] = [53, 67, 68, 161, 123, 69, 500, 1883, 5060, 502, 4500];

    let mut total = 0u64;
    let mut panics = 0u64;
    let mut first: Vec<String> = Vec::new();

    // 1. systematic short payloads (every length 0..=48, several byte patterns)
    for len in 0..=48usize {
        let pats: [Vec<u8>; 5] = [
            vec![0u8; len],
            vec![0xffu8; len],
            (0..len).map(|i| i as u8).collect(),
            (0..len).map(|i| 0xffu8.wrapping_sub(i as u8)).collect(),
            vec![0x20u8; len],
        ];
        for p in &pats {
            for &dp in &tcp_ports {
                record(fuzz_one(&det, IpProtocol::Tcp, 40000, dp, p), &mut total, &mut panics, &mut first);
                record(fuzz_one(&det, IpProtocol::Tcp, dp, 40000, p), &mut total, &mut panics, &mut first);
            }
            for &dp in &udp_ports {
                record(fuzz_one(&det, IpProtocol::Udp, 40000, dp, p), &mut total, &mut panics, &mut first);
            }
        }
    }

    // 2. protocol-magic prefixes truncated at every offset
    let magics: [&[u8]; 10] = [
        &b"SSH-2.0-OpenSSH_9.0\r\n"[..],
        &b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n"[..],
        &[0x16, 0x03, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0xfc, 0x03][..], // TLS ClientHello-ish
        &b"220 service ready\r\n"[..],
        &b"EHLO host\r\nAUTH LOGIN\r\n"[..],
        &b"USER root\r\nPASS x\r\n"[..],
        &[0, 0, 0, 2, 1, 5][..], // SSH binary: packet_len=2, pad=1 -> payload_len=0 (the prod crash shape)
        &[0xff, 0xff, 0xff, 0xff, 0xff][..],
        &[0x00, 0x01, 0x00, 0x00, 0x00, 0x01][..], // DNS-ish
        &[0x80, 0x00, 0x00, 0x00][..],
    ];
    for m in magics {
        for cut in 0..=m.len() {
            let p = &m[..cut];
            for &dp in &tcp_ports {
                record(fuzz_one(&det, IpProtocol::Tcp, 40000, dp, p), &mut total, &mut panics, &mut first);
            }
            for &dp in &udp_ports {
                record(fuzz_one(&det, IpProtocol::Udp, 40000, dp, p), &mut total, &mut panics, &mut first);
            }
        }
    }

    // 3. SSH-binary lying-length sweep (the exact prod-crash family)
    for plen in 0u8..=8 {
        for pad in 0u8..=8 {
            let mut p = vec![0u8, 0, 0, plen, pad];
            p.extend_from_slice(&[5u8, 1, 2, 3]);
            record(fuzz_one(&det, IpProtocol::Tcp, 40000, 22, &p), &mut total, &mut panics, &mut first);
        }
    }

    // 4. random fuzz — many iterations, random length/bytes/port/proto
    let mut rng = Rng(0x9E3779B97F4A7C15);
    for _ in 0..400_000u64 {
        let len = rng.range(400);
        let mut p = vec![0u8; len];
        for b in p.iter_mut() {
            *b = rng.byte();
        }
        if rng.next() & 1 == 0 {
            let dp = tcp_ports[rng.range(tcp_ports.len())];
            record(fuzz_one(&det, IpProtocol::Tcp, 40000, dp, &p), &mut total, &mut panics, &mut first);
        } else {
            let dp = udp_ports[rng.range(udp_ports.len())];
            record(fuzz_one(&det, IpProtocol::Udp, 40000, dp, &p), &mut total, &mut panics, &mut first);
        }
    }

    let _ = panic::take_hook();
    println!("proto_fuzz: {} cases fuzzed, {} panics", total, panics);
    for m in &first {
        eprintln!("{}", m);
    }
    if panics > 0 {
        std::process::exit(1);
    }
    println!("OK — no parser panicked");
}
