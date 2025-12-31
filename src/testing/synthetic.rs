//! Synthetic attack traffic generation for testing
//!
//! Generates various types of attack traffic patterns for benchmarking detection.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::types::{
    Packet, IpProtocol, TcpFlags, Severity,
};
use super::ground_truth::GroundTruth;

/// Types of attacks that can be generated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackType {
    /// SYN flood DoS attack
    SynFlood,
    /// UDP flood attack
    UdpFlood,
    /// Port scan (SYN scan)
    PortScan,
    /// Network scan (multiple IPs)
    NetworkScan,
    /// SSH brute force
    SshBruteForce,
    /// FTP brute force
    FtpBruteForce,
    /// HTTP brute force
    HttpBruteForce,
    /// DNS amplification
    DnsAmplification,
    /// Slowloris HTTP attack
    Slowloris,
    /// XMAS scan
    XmasScan,
    /// NULL scan
    NullScan,
    /// FIN scan
    FinScan,
    /// Normal/benign traffic
    Benign,
}

impl AttackType {
    /// Get severity for this attack type
    pub fn severity(&self) -> Severity {
        match self {
            AttackType::SynFlood | AttackType::UdpFlood | AttackType::DnsAmplification => {
                Severity::Critical
            }
            AttackType::SshBruteForce | AttackType::FtpBruteForce | AttackType::HttpBruteForce => {
                Severity::High
            }
            AttackType::PortScan | AttackType::NetworkScan | AttackType::XmasScan
            | AttackType::NullScan | AttackType::FinScan => Severity::Medium,
            AttackType::Slowloris => Severity::Medium,
            AttackType::Benign => Severity::Info,
        }
    }

    /// Get label for ground truth
    pub fn label(&self) -> &'static str {
        match self {
            AttackType::SynFlood => "syn_flood",
            AttackType::UdpFlood => "udp_flood",
            AttackType::PortScan => "port_scan",
            AttackType::NetworkScan => "network_scan",
            AttackType::SshBruteForce => "ssh_brute_force",
            AttackType::FtpBruteForce => "ftp_brute_force",
            AttackType::HttpBruteForce => "http_brute_force",
            AttackType::DnsAmplification => "dns_amplification",
            AttackType::Slowloris => "slowloris",
            AttackType::XmasScan => "xmas_scan",
            AttackType::NullScan => "null_scan",
            AttackType::FinScan => "fin_scan",
            AttackType::Benign => "benign",
        }
    }
}

/// Configuration for attack generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    /// Attack type
    pub attack_type: AttackType,
    /// Number of packets to generate
    pub packet_count: u64,
    /// Packets per second (0 for no limit)
    pub rate_pps: u64,
    /// Source IP (attacker)
    pub src_ip: IpAddr,
    /// Destination IP (target)
    pub dst_ip: IpAddr,
    /// Target ports (for port scan, or single port for flood)
    pub target_ports: Vec<u16>,
    /// Randomize source port
    pub random_src_port: bool,
    /// Packet size (for flood attacks)
    pub packet_size: u16,
}

impl Default for AttackConfig {
    fn default() -> Self {
        Self {
            attack_type: AttackType::PortScan,
            packet_count: 1000,
            rate_pps: 0,
            src_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            target_ports: (1..=1024).collect(),
            random_src_port: true,
            packet_size: 64,
        }
    }
}

impl AttackConfig {
    /// Create a SYN flood configuration
    pub fn syn_flood(src: IpAddr, dst: IpAddr, port: u16, count: u64) -> Self {
        Self {
            attack_type: AttackType::SynFlood,
            packet_count: count,
            rate_pps: 10000,
            src_ip: src,
            dst_ip: dst,
            target_ports: vec![port],
            random_src_port: true,
            packet_size: 64,
        }
    }

    /// Create a port scan configuration
    pub fn port_scan(src: IpAddr, dst: IpAddr, ports: Vec<u16>) -> Self {
        Self {
            attack_type: AttackType::PortScan,
            packet_count: ports.len() as u64,
            rate_pps: 100,
            src_ip: src,
            dst_ip: dst,
            target_ports: ports,
            random_src_port: true,
            packet_size: 60,
        }
    }

    /// Create SSH brute force configuration
    pub fn ssh_brute_force(src: IpAddr, dst: IpAddr, attempts: u64) -> Self {
        Self {
            attack_type: AttackType::SshBruteForce,
            packet_count: attempts * 10, // Multiple packets per attempt
            rate_pps: 50,
            src_ip: src,
            dst_ip: dst,
            target_ports: vec![22],
            random_src_port: true,
            packet_size: 128,
        }
    }

    /// Create benign traffic configuration
    pub fn benign(src: IpAddr, dst: IpAddr, count: u64) -> Self {
        Self {
            attack_type: AttackType::Benign,
            packet_count: count,
            rate_pps: 1000,
            src_ip: src,
            dst_ip: dst,
            target_ports: vec![80, 443, 53, 25, 110],
            random_src_port: true,
            packet_size: 512,
        }
    }
}

/// Synthetic attack traffic generator
pub struct AttackGenerator {
    config: AttackConfig,
    packet_id: u64,
    packets_generated: u64,
    current_port_idx: usize,
    rng: rand::rngs::ThreadRng,
    last_packet_time: Option<Instant>,
}

impl AttackGenerator {
    /// Create a new attack generator
    pub fn new(config: AttackConfig) -> Self {
        Self {
            config,
            packet_id: 0,
            packets_generated: 0,
            current_port_idx: 0,
            rng: rand::rng(),
            last_packet_time: None,
        }
    }

    /// Generate the next packet
    pub fn next_packet(&mut self) -> Option<Packet> {
        if self.packets_generated >= self.config.packet_count {
            return None;
        }

        // Rate limiting
        if self.config.rate_pps > 0 {
            let interval = Duration::from_secs_f64(1.0 / self.config.rate_pps as f64);
            if let Some(last) = self.last_packet_time {
                let elapsed = last.elapsed();
                if elapsed < interval {
                    std::thread::sleep(interval - elapsed);
                }
            }
            self.last_packet_time = Some(Instant::now());
        }

        let packet = match self.config.attack_type {
            AttackType::SynFlood => self.generate_syn_flood(),
            AttackType::UdpFlood => self.generate_udp_flood(),
            AttackType::PortScan => self.generate_port_scan(),
            AttackType::NetworkScan => self.generate_network_scan(),
            AttackType::SshBruteForce | AttackType::FtpBruteForce | AttackType::HttpBruteForce => {
                self.generate_brute_force()
            }
            AttackType::DnsAmplification => self.generate_dns_amplification(),
            AttackType::XmasScan => self.generate_xmas_scan(),
            AttackType::NullScan => self.generate_null_scan(),
            AttackType::FinScan => self.generate_fin_scan(),
            AttackType::Slowloris => self.generate_slowloris(),
            AttackType::Benign => self.generate_benign(),
        };

        self.packet_id += 1;
        self.packets_generated += 1;

        Some(packet)
    }

    /// Generate all packets
    pub fn generate_all(&mut self) -> Vec<Packet> {
        let mut packets = Vec::with_capacity(self.config.packet_count as usize);
        while let Some(packet) = self.next_packet() {
            packets.push(packet);
        }
        packets
    }

    /// Get ground truth for generated traffic
    pub fn get_ground_truth(&self) -> GroundTruth {
        let mut gt = GroundTruth::new();

        if self.config.attack_type != AttackType::Benign {
            gt.add_attacker(
                self.config.src_ip,
                self.config.attack_type.label(),
                self.config.attack_type.severity(),
            );
        } else {
            gt.benign_count = self.config.packet_count;
        }

        gt.total_packets = self.config.packet_count;
        gt
    }

    // === Private packet generators ===

    fn generate_syn_flood(&mut self) -> Packet {
        let dst_port = self.config.target_ports.first().copied().unwrap_or(80);
        let src_port = if self.config.random_src_port {
            self.rng.random_range(1024..65535)
        } else {
            12345
        };

        let mut packet = Packet::new(
            self.packet_id,
            self.config.src_ip,
            self.config.dst_ip,
            IpProtocol::Tcp,
            "test",
        );

        // Set TCP info with SYN flag
        if let Some(tcp) = packet.tcp_mut() {
            tcp.src_port = src_port;
            tcp.dst_port = dst_port;
            tcp.flags = TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
                psh: false,
                urg: false,
                ece: false,
                cwr: false,
            };
            tcp.seq = self.rng.random();
            tcp.window = 65535;
        }

        packet.raw_len = self.config.packet_size as u32;
        packet
    }

    fn generate_udp_flood(&mut self) -> Packet {
        let dst_port = self.config.target_ports.first().copied().unwrap_or(53);
        let src_port = if self.config.random_src_port {
            self.rng.random_range(1024..65535)
        } else {
            12345
        };

        let mut packet = Packet::new(
            self.packet_id,
            self.config.src_ip,
            self.config.dst_ip,
            IpProtocol::Udp,
            "test",
        );

        if let Some(udp) = packet.udp_mut() {
            udp.src_port = src_port;
            udp.dst_port = dst_port;
            udp.length = self.config.packet_size;
        }

        packet.raw_len = self.config.packet_size as u32;
        packet
    }

    fn generate_port_scan(&mut self) -> Packet {
        let dst_port = self.config.target_ports
            .get(self.current_port_idx % self.config.target_ports.len())
            .copied()
            .unwrap_or(80);
        self.current_port_idx += 1;

        let src_port = if self.config.random_src_port {
            self.rng.random_range(1024..65535)
        } else {
            54321
        };

        let mut packet = Packet::new(
            self.packet_id,
            self.config.src_ip,
            self.config.dst_ip,
            IpProtocol::Tcp,
            "test",
        );

        if let Some(tcp) = packet.tcp_mut() {
            tcp.src_port = src_port;
            tcp.dst_port = dst_port;
            tcp.flags = TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
                psh: false,
                urg: false,
                ece: false,
                cwr: false,
            };
            tcp.seq = self.rng.random();
        }

        packet.raw_len = 60;
        packet
    }

    fn generate_network_scan(&mut self) -> Packet {
        // Vary destination IP within subnet
        let base_ip = match self.config.dst_ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                let last_octet = (self.packets_generated % 254 + 1) as u8;
                IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], last_octet))
            }
            _ => self.config.dst_ip,
        };

        let mut packet = Packet::new(
            self.packet_id,
            self.config.src_ip,
            base_ip,
            IpProtocol::Tcp,
            "test",
        );

        if let Some(tcp) = packet.tcp_mut() {
            tcp.src_port = self.rng.random_range(1024..65535);
            tcp.dst_port = 80; // Common probe port
            tcp.flags = TcpFlags {
                syn: true,
                ack: false,
                fin: false,
                rst: false,
                psh: false,
                urg: false,
                ece: false,
                cwr: false,
            };
        }

        packet.raw_len = 60;
        packet
    }

    fn generate_brute_force(&mut self) -> Packet {
        let dst_port = match self.config.attack_type {
            AttackType::SshBruteForce => 22,
            AttackType::FtpBruteForce => 21,
            AttackType::HttpBruteForce => 80,
            _ => 22,
        };

        let mut packet = Packet::new(
            self.packet_id,
            self.config.src_ip,
            self.config.dst_ip,
            IpProtocol::Tcp,
            "test",
        );

        if let Some(tcp) = packet.tcp_mut() {
            tcp.src_port = self.rng.random_range(1024..65535);
            tcp.dst_port = dst_port;
            // Established connection for brute force
            tcp.flags = TcpFlags {
                syn: false,
                ack: true,
                fin: false,
                rst: false,
                psh: true,
                urg: false,
                ece: false,
                cwr: false,
            };
            tcp.seq = self.rng.random();
            tcp.ack = self.rng.random();
        }

        packet.raw_len = self.config.packet_size as u32;
        packet
    }

    fn generate_dns_amplification(&mut self) -> Packet {
        let mut packet = Packet::new(
            self.packet_id,
            self.config.src_ip,
            self.config.dst_ip,
            IpProtocol::Udp,
            "test",
        );

        if let Some(udp) = packet.udp_mut() {
            udp.src_port = 53;
            udp.dst_port = self.rng.random_range(1024..65535);
            udp.length = 512; // Large DNS response
        }

        packet.raw_len = 512;
        packet
    }

    fn generate_xmas_scan(&mut self) -> Packet {
        let dst_port = self.config.target_ports
            .get(self.current_port_idx % self.config.target_ports.len())
            .copied()
            .unwrap_or(80);
        self.current_port_idx += 1;

        let mut packet = Packet::new(
            self.packet_id,
            self.config.src_ip,
            self.config.dst_ip,
            IpProtocol::Tcp,
            "test",
        );

        if let Some(tcp) = packet.tcp_mut() {
            tcp.src_port = self.rng.random_range(1024..65535);
            tcp.dst_port = dst_port;
            // XMAS scan: FIN, PSH, URG all set
            tcp.flags = TcpFlags {
                syn: false,
                ack: false,
                fin: true,
                rst: false,
                psh: true,
                urg: true,
                ece: false,
                cwr: false,
            };
        }

        packet.raw_len = 60;
        packet
    }

    fn generate_null_scan(&mut self) -> Packet {
        let dst_port = self.config.target_ports
            .get(self.current_port_idx % self.config.target_ports.len())
            .copied()
            .unwrap_or(80);
        self.current_port_idx += 1;

        let mut packet = Packet::new(
            self.packet_id,
            self.config.src_ip,
            self.config.dst_ip,
            IpProtocol::Tcp,
            "test",
        );

        if let Some(tcp) = packet.tcp_mut() {
            tcp.src_port = self.rng.random_range(1024..65535);
            tcp.dst_port = dst_port;
            // NULL scan: no flags
            tcp.flags = TcpFlags::default();
        }

        packet.raw_len = 60;
        packet
    }

    fn generate_fin_scan(&mut self) -> Packet {
        let dst_port = self.config.target_ports
            .get(self.current_port_idx % self.config.target_ports.len())
            .copied()
            .unwrap_or(80);
        self.current_port_idx += 1;

        let mut packet = Packet::new(
            self.packet_id,
            self.config.src_ip,
            self.config.dst_ip,
            IpProtocol::Tcp,
            "test",
        );

        if let Some(tcp) = packet.tcp_mut() {
            tcp.src_port = self.rng.random_range(1024..65535);
            tcp.dst_port = dst_port;
            // FIN scan: only FIN
            tcp.flags = TcpFlags {
                syn: false,
                ack: false,
                fin: true,
                rst: false,
                psh: false,
                urg: false,
                ece: false,
                cwr: false,
            };
        }

        packet.raw_len = 60;
        packet
    }

    fn generate_slowloris(&mut self) -> Packet {
        let mut packet = Packet::new(
            self.packet_id,
            self.config.src_ip,
            self.config.dst_ip,
            IpProtocol::Tcp,
            "test",
        );

        if let Some(tcp) = packet.tcp_mut() {
            tcp.src_port = self.rng.random_range(1024..65535);
            tcp.dst_port = 80;
            tcp.flags = TcpFlags {
                syn: false,
                ack: true,
                fin: false,
                rst: false,
                psh: true,
                urg: false,
                ece: false,
                cwr: false,
            };
            tcp.window = 1; // Small window for slow attack
        }

        // Small payload
        packet.raw_len = 100;
        packet
    }

    fn generate_benign(&mut self) -> Packet {
        let dst_port = self.config.target_ports
            .get(self.rng.random_range(0..self.config.target_ports.len()))
            .copied()
            .unwrap_or(80);

        let protocol = if dst_port == 53 {
            IpProtocol::Udp
        } else {
            IpProtocol::Tcp
        };

        let mut packet = Packet::new(
            self.packet_id,
            self.config.src_ip,
            self.config.dst_ip,
            protocol,
            "test",
        );

        match protocol {
            IpProtocol::Tcp => {
                if let Some(tcp) = packet.tcp_mut() {
                    tcp.src_port = self.rng.random_range(1024..65535);
                    tcp.dst_port = dst_port;
                    tcp.flags = TcpFlags {
                        syn: false,
                        ack: true,
                        fin: false,
                        rst: false,
                        psh: self.rng.random_bool(0.5),
                        urg: false,
                        ece: false,
                        cwr: false,
                    };
                    tcp.window = self.rng.random_range(8192..65535);
                }
            }
            IpProtocol::Udp => {
                if let Some(udp) = packet.udp_mut() {
                    udp.src_port = self.rng.random_range(1024..65535);
                    udp.dst_port = dst_port;
                    udp.length = self.rng.random_range(50..512);
                }
            }
            _ => {}
        }

        packet.raw_len = self.rng.random_range(64..1500) as u32;
        packet
    }
}

/// Mixed traffic generator combining attacks and benign traffic
pub struct MixedTrafficGenerator {
    generators: Vec<AttackGenerator>,
    current_idx: usize,
    total_generated: u64,
    ground_truth: GroundTruth,
}

impl MixedTrafficGenerator {
    /// Create a mixed traffic generator
    pub fn new(configs: Vec<AttackConfig>) -> Self {
        let mut ground_truth = GroundTruth::new();

        for config in &configs {
            if config.attack_type != AttackType::Benign {
                ground_truth.add_attacker(
                    config.src_ip,
                    config.attack_type.label(),
                    config.attack_type.severity(),
                );
            }
            ground_truth.total_packets += config.packet_count;
        }

        let generators: Vec<_> = configs.into_iter().map(AttackGenerator::new).collect();

        Self {
            generators,
            current_idx: 0,
            total_generated: 0,
            ground_truth,
        }
    }

    /// Generate next packet (round-robin from generators)
    pub fn next_packet(&mut self) -> Option<Packet> {
        if self.generators.is_empty() {
            return None;
        }

        let start_idx = self.current_idx;
        loop {
            if let Some(packet) = self.generators[self.current_idx].next_packet() {
                self.current_idx = (self.current_idx + 1) % self.generators.len();
                self.total_generated += 1;
                return Some(packet);
            }

            self.current_idx = (self.current_idx + 1) % self.generators.len();
            if self.current_idx == start_idx {
                return None;
            }
        }
    }

    /// Get ground truth for all generated traffic
    pub fn get_ground_truth(&self) -> &GroundTruth {
        &self.ground_truth
    }

    /// Get mutable ground truth
    pub fn get_ground_truth_mut(&mut self) -> &mut GroundTruth {
        &mut self.ground_truth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_scan_generator() {
        let config = AttackConfig::port_scan(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            (1..=100).collect(),
        );

        let mut generator = AttackGenerator::new(config);
        let packets = generator.generate_all();

        assert_eq!(packets.len(), 100);
        for packet in &packets {
            assert!(packet.tcp().is_some());
            if let Some(tcp) = packet.tcp() {
                assert!(tcp.flags.syn);
                assert!(!tcp.flags.ack);
            }
        }
    }

    #[test]
    fn test_syn_flood_generator() {
        let config = AttackConfig::syn_flood(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            80,
            50,
        );

        let mut generator = AttackGenerator::new(config);
        let packets = generator.generate_all();

        assert_eq!(packets.len(), 50);
        for packet in &packets {
            assert_eq!(packet.protocol(), IpProtocol::Tcp);
            if let Some(tcp) = packet.tcp() {
                assert!(tcp.flags.syn);
                assert_eq!(tcp.dst_port, 80);
            }
        }
    }

    #[test]
    fn test_mixed_traffic() {
        let configs = vec![
            AttackConfig::port_scan(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                vec![22, 80, 443],
            ),
            AttackConfig::benign(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                10,
            ),
        ];

        let mut generator = MixedTrafficGenerator::new(configs);
        let mut count = 0;
        while generator.next_packet().is_some() {
            count += 1;
        }

        assert_eq!(count, 13); // 3 scan + 10 benign
    }
}
