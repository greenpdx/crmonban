//! Realistic traffic generator for detection testing
//!
//! Generates realistic packet sequences that trigger actual detections
//! across all detection layers.

use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, TimeZone, Utc};

use crate::types::{
    Packet, TcpFlags, IpProtocol, TcpInfo, UdpInfo,
};

use super::ground_truth::GroundTruth;
use crate::types::Severity;

/// Configuration for realistic traffic generation
#[derive(Debug, Clone)]
pub struct RealisticConfig {
    /// Base timestamp for packet generation
    pub base_timestamp: DateTime<Utc>,
    /// Time window for aggregation (should match detector config)
    pub window_size_ms: u64,
    /// Packets per window to ensure detection triggers
    pub packets_per_window: usize,
}

impl Default for RealisticConfig {
    fn default() -> Self {
        Self {
            base_timestamp: Utc::now(),
            window_size_ms: 2_000, // 2 second windows (match layer2detect benchmark)
            packets_per_window: 100, // Enough packets per window for pattern detection
        }
    }
}

/// Generates realistic attack traffic that triggers detections
pub struct RealisticTrafficGenerator {
    config: RealisticConfig,
    packets: Vec<Packet>,
    ground_truth: GroundTruth,
    packet_id: u64,
    current_time_ns: u64, // Track time in nanoseconds for precision
}

impl RealisticTrafficGenerator {
    pub fn new(config: RealisticConfig) -> Self {
        let current_time_ns = config.base_timestamp.timestamp_nanos_opt().unwrap_or(0) as u64;
        Self {
            config,
            packets: Vec::new(),
            ground_truth: GroundTruth::new(),
            packet_id: 0,
            current_time_ns,
        }
    }

    /// Generate a comprehensive test suite with all attack types
    pub fn generate_all_attacks(&mut self) -> &[Packet] {
        self.packets.clear();
        self.ground_truth = GroundTruth::new();

        // Port scan attack (triggers scan detection)
        self.generate_port_scan(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );

        // SYN flood attack (triggers DoS detection)
        self.generate_syn_flood(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            80,
        );

        // SSH brute force (triggers brute force detection)
        self.generate_ssh_brute_force(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 102)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );

        // HTTP attack with SQL injection patterns
        self.generate_http_attack(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 103)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );

        // Network sweep (horizontal scan)
        self.generate_network_sweep(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 104)),
            Ipv4Addr::new(10, 0, 0, 0),
            24, // /24 network
        );

        // UDP flood
        self.generate_udp_flood(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 105)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            53, // DNS port
        );

        // Benign traffic (should not trigger detections)
        self.generate_benign_traffic(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );

        &self.packets
    }

    /// Generate vertical port scan (many ports on single target)
    /// Requirements: syn_ratio > 0.6, synack_ratio < 0.15, unique_port_ratio > 0.05
    fn generate_port_scan(&mut self, src: IpAddr, dst: IpAddr) {
        self.ground_truth.add_attacker(src, "port_scan", Severity::Medium);

        // Scan 100 ports rapidly - this triggers unique_ports detection
        // Use fewer ports but with tight timing like layer2detect benchmark
        let ports: Vec<u16> = (1..=100).collect();
        let time_increment_ns = (self.config.window_size_ms * 1_000_000) / (ports.len() as u64 + 1);

        for port in ports {
            // SYN packet to each port (no responses - stealth scan)
            let packet = self.create_tcp_packet(
                src, dst,
                40000 + self.packet_id as u16,
                port,
                TcpFlags { syn: true, ..Default::default() },
                &[],
            );
            self.packets.push(packet);
            self.current_time_ns += time_increment_ns;
        }

        // Advance to next window
        self.advance_window();
    }

    /// Generate SYN flood attack (many half-open connections)
    /// Generates high volume SYN packets to a single port without completing handshakes
    fn generate_syn_flood(&mut self, src: IpAddr, dst: IpAddr, target_port: u16) {
        self.ground_truth.add_attacker(src, "syn_flood", Severity::High);

        // Generate SYN flood with many half-open connections
        let count = self.config.packets_per_window * 2; // 200 packets
        let time_increment_ns = (self.config.window_size_ms * 1_000_000) / (count as u64 + 1);

        for i in 0..count {
            // SYN packets from varying source ports to same destination port
            // This creates many half-open connections
            let packet = self.create_tcp_packet(
                src, dst,
                30000 + (i as u16 % 30000), // Vary source port
                target_port, // Same destination port (concentrated attack)
                TcpFlags { syn: true, ..Default::default() },
                &[],
            );
            self.packets.push(packet);
            self.current_time_ns += time_increment_ns;
        }

        self.advance_window();
    }

    /// Generate SSH brute force attack (many attempts to auth port)
    /// Requirements: auth_port_ratio > 0.5, single_port_concentration > 0.7, handshake_complete > 0.3
    fn generate_ssh_brute_force(&mut self, src: IpAddr, dst: IpAddr) {
        self.ground_truth.add_attacker(src, "brute_force", Severity::High);

        // Generate many connection attempts to SSH (port 22)
        // Each attempt simulates: SYN → SYN-ACK → ACK+data (complete handshake)
        let attempts = 50; // 50 attempts with 3 packets each = 150 packets
        let time_increment_ns = (self.config.window_size_ms * 1_000_000) / (attempts as u64 * 3 + 1);

        for i in 0..attempts {
            let src_port = 50000 + (i as u16 % 15000);

            // SYN (attacker → target)
            let syn_pkt = self.create_tcp_packet(
                src, dst, src_port, 22,
                TcpFlags { syn: true, ..Default::default() },
                &[],
            );
            self.packets.push(syn_pkt);
            self.current_time_ns += time_increment_ns;

            // SYN-ACK (target → attacker) - simulated response
            let syn_ack_pkt = self.create_tcp_packet(
                dst, src, 22, src_port,
                TcpFlags { syn: true, ack: true, ..Default::default() },
                &[],
            );
            self.packets.push(syn_ack_pkt);
            self.current_time_ns += time_increment_ns;

            // ACK + auth attempt (attacker → target)
            let ssh_payload = format!("SSH-2.0-attacker\r\nuser{}\r\n", i);
            let ack_pkt = self.create_tcp_packet(
                src, dst, src_port, 22,
                TcpFlags { ack: true, psh: true, ..Default::default() },
                ssh_payload.as_bytes(),
            );
            self.packets.push(ack_pkt);
            self.current_time_ns += time_increment_ns;
        }

        self.advance_window();
    }

    /// Generate HTTP attack with malicious payloads
    /// Generates many HTTP requests with SQL injection, XSS, and scanner signatures
    fn generate_http_attack(&mut self, src: IpAddr, dst: IpAddr) {
        self.ground_truth.add_attacker(src, "sql_injection", Severity::Critical);

        // Attack templates
        let attack_templates = vec![
            b"GET /login?id=1' OR '1'='1 HTTP/1.1\r\nHost: target.com\r\n\r\n".to_vec(),
            b"GET /search?q='; DROP TABLE users;-- HTTP/1.1\r\nHost: target.com\r\n\r\n".to_vec(),
            b"POST /login HTTP/1.1\r\nHost: target.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin'--&pass=x".to_vec(),
            b"GET /page?name=<script>alert('xss')</script> HTTP/1.1\r\nHost: target.com\r\n\r\n".to_vec(),
            b"GET /files/../../../etc/passwd HTTP/1.1\r\nHost: target.com\r\n\r\n".to_vec(),
        ];

        // Fewer repetitions - 5 templates * 5 reps * 3 packets = 75 packets
        let repetitions = 5;
        let total_attacks = attack_templates.len() * repetitions;
        let time_increment_ns = (self.config.window_size_ms * 1_000_000) / (total_attacks as u64 * 3 + 1);

        for rep in 0..repetitions {
            for (i, payload) in attack_templates.iter().enumerate() {
                let src_port = 45000 + (rep * attack_templates.len() + i) as u16;

                // SYN
                let syn_pkt = self.create_tcp_packet(
                    src, dst, src_port, 80,
                    TcpFlags { syn: true, ..Default::default() },
                    &[],
                );
                self.packets.push(syn_pkt);
                self.current_time_ns += time_increment_ns;

                // SYN-ACK (simulated response)
                let syn_ack_pkt = self.create_tcp_packet(
                    dst, src, 80, src_port,
                    TcpFlags { syn: true, ack: true, ..Default::default() },
                    &[],
                );
                self.packets.push(syn_ack_pkt);
                self.current_time_ns += time_increment_ns;

                // HTTP request with attack payload
                let http_pkt = self.create_tcp_packet(
                    src, dst, src_port, 80,
                    TcpFlags { ack: true, psh: true, ..Default::default() },
                    payload,
                );
                self.packets.push(http_pkt);
                self.current_time_ns += time_increment_ns;
            }
        }

        self.advance_window();
    }

    /// Generate network sweep (horizontal scan across IPs)
    /// Scans many hosts with SYN packets - triggers ping sweep / network scan detection
    fn generate_network_sweep(&mut self, src: IpAddr, base_ip: Ipv4Addr, _prefix_len: u8) {
        self.ground_truth.add_attacker(src, "network_scan", Severity::Medium);

        // Scan 50 hosts with 2 ports each = 100 packets
        let hosts_to_scan = 50;
        let ports_per_host = [22, 80];
        let total_packets = hosts_to_scan * ports_per_host.len();
        let time_increment_ns = (self.config.window_size_ms * 1_000_000) / (total_packets as u64 + 1);

        let base_octets = base_ip.octets();

        for i in 1..=hosts_to_scan {
            let target_ip = Ipv4Addr::new(
                base_octets[0],
                base_octets[1],
                base_octets[2],
                ((base_octets[3] as usize + i) % 256) as u8,
            );

            // SYN to common ports on each host
            for &port in &ports_per_host {
                let packet = self.create_tcp_packet(
                    src,
                    IpAddr::V4(target_ip),
                    40000 + self.packet_id as u16,
                    port,
                    TcpFlags { syn: true, ..Default::default() },
                    &[],
                );
                self.packets.push(packet);
                self.current_time_ns += time_increment_ns;
            }
        }

        self.advance_window();
    }

    /// Generate UDP flood (DNS amplification style)
    /// Requirements: flood_score > 0.3, packets_per_sec > 0.01
    fn generate_udp_flood(&mut self, src: IpAddr, dst: IpAddr, port: u16) {
        self.ground_truth.add_attacker(src, "udp_flood", Severity::High);

        // Generate 100 UDP packets in the window
        let count = 100;
        let time_increment_ns = (self.config.window_size_ms * 1_000_000) / (count as u64 + 1);

        // DNS query payload - ANY record query (amplification vector)
        let dns_query = [
            0x00, 0x01, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            0x03, b'w', b'w', b'w', // www
            0x06, b'g', b'o', b'o', b'g', b'l', b'e', // google
            0x03, b'c', b'o', b'm', // com
            0x00,       // null terminator
            0x00, 0xff, // Type: ANY (amplification)
            0x00, 0x01, // Class: IN
        ];

        for i in 0..count {
            let packet = self.create_udp_packet(
                src, dst,
                30000 + (i as u16 % 30000), // Vary source port
                port, // Target port (DNS)
                &dns_query,
            );
            self.packets.push(packet);
            self.current_time_ns += time_increment_ns;
        }

        self.advance_window();
    }

    /// Generate benign traffic (should not trigger detections)
    fn generate_benign_traffic(&mut self, src: IpAddr, dst: IpAddr) {
        // Generate 20 normal connections (4 packets each = 80 packets)
        let connections = 20;
        self.ground_truth.benign_count += (connections * 4) as u64;

        let time_increment_ns = (self.config.window_size_ms * 1_000_000) / (connections as u64 * 4 + 1);

        // Normal HTTPS traffic
        for i in 0..connections {
            let src_port = 55000 + i as u16;

            // Complete TCP handshake to port 443
            let syn_pkt = self.create_tcp_packet(
                src, dst, src_port, 443,
                TcpFlags { syn: true, ..Default::default() },
                &[],
            );
            self.packets.push(syn_pkt);
            self.current_time_ns += time_increment_ns;

            let syn_ack_pkt = self.create_tcp_packet(
                dst, src, 443, src_port,
                TcpFlags { syn: true, ack: true, ..Default::default() },
                &[],
            );
            self.packets.push(syn_ack_pkt);
            self.current_time_ns += time_increment_ns;

            let ack_pkt = self.create_tcp_packet(
                src, dst, src_port, 443,
                TcpFlags { ack: true, ..Default::default() },
                &[],
            );
            self.packets.push(ack_pkt);
            self.current_time_ns += time_increment_ns;

            // Data exchange (TLS handshake simulation)
            let tls_pkt = self.create_tcp_packet(
                src, dst, src_port, 443,
                TcpFlags { ack: true, psh: true, ..Default::default() },
                &[0x16, 0x03, 0x01, 0x00, 0x05], // TLS ClientHello header
            );
            self.packets.push(tls_pkt);
            self.current_time_ns += time_increment_ns;
        }

        self.advance_window();
    }

    /// Create a TCP packet with the given parameters
    fn create_tcp_packet(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        flags: TcpFlags,
        payload: &[u8],
    ) -> Packet {
        self.packet_id += 1;

        let mut pkt = Packet::new(
            self.packet_id,
            src_ip,
            dst_ip,
            IpProtocol::Tcp,
            "synthetic",
        );

        // Set timestamp using nanosecond precision
        pkt.timestamp = self.ns_to_datetime(self.current_time_ns);
        pkt.raw_len = (40 + payload.len()) as u32; // IP + TCP + payload

        // Configure TCP info
        if let Some(tcp_info) = pkt.tcp_mut() {
            tcp_info.src_port = src_port;
            tcp_info.dst_port = dst_port;
            tcp_info.seq = 1;
            tcp_info.ack = 0;
            tcp_info.flags = flags;
            tcp_info.window = 65535;
            tcp_info.payload = payload.to_vec();
        }

        pkt
    }

    /// Create a UDP packet
    fn create_udp_packet(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Packet {
        self.packet_id += 1;

        let mut pkt = Packet::new(
            self.packet_id,
            src_ip,
            dst_ip,
            IpProtocol::Udp,
            "synthetic",
        );

        // Set timestamp using nanosecond precision
        pkt.timestamp = self.ns_to_datetime(self.current_time_ns);
        pkt.raw_len = (28 + payload.len()) as u32; // IP + UDP + payload

        // Configure UDP info
        if let Some(udp_info) = pkt.udp_mut() {
            udp_info.src_port = src_port;
            udp_info.dst_port = dst_port;
            udp_info.length = (8 + payload.len()) as u16;
            udp_info.payload = payload.to_vec();
        }

        pkt
    }

    /// Advance time to next window
    fn advance_window(&mut self) {
        self.current_time_ns += self.config.window_size_ms * 1_000_000; // ms to ns
    }

    /// Convert nanosecond timestamp to DateTime
    fn ns_to_datetime(&self, ns: u64) -> DateTime<Utc> {
        Utc.timestamp_nanos(ns as i64)
    }

    /// Get ground truth for generated traffic
    pub fn get_ground_truth(&self) -> &GroundTruth {
        &self.ground_truth
    }

    /// Get generated packets
    pub fn get_packets(&self) -> &[Packet] {
        &self.packets
    }

    /// Take ownership of packets
    pub fn take_packets(self) -> Vec<Packet> {
        self.packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_realistic_generator() {
        let config = RealisticConfig::default();
        let mut generator = RealisticTrafficGenerator::new(config);

        let packets = generator.generate_all_attacks();

        // Should generate substantial traffic
        assert!(packets.len() > 100, "Expected 100+ packets, got {}", packets.len());

        // Should have multiple attackers
        let gt = generator.get_ground_truth();
        assert!(gt.attacker_ips.len() >= 5, "Expected 5+ attackers");
    }

    #[test]
    fn test_packet_timestamps() {
        let config = RealisticConfig::default();
        let mut generator = RealisticTrafficGenerator::new(config);

        let packets = generator.generate_all_attacks();

        // Timestamps should be increasing
        let mut prev_ts = DateTime::<Utc>::MIN_UTC;
        for pkt in packets {
            assert!(pkt.timestamp >= prev_ts, "Timestamps should be monotonic");
            prev_ts = pkt.timestamp;
        }
    }
}
