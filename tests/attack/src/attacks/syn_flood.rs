//! DoS/DDoS attacks
//!
//! Implements SYN flood, ICMP flood, and other DoS attacks.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use rand::Rng;

use crate::attacks::{AttackGenerator, AttackType};
use crate::generator::PacketRecord;
use crate::state_machine::TcpFlags;

/// SYN flood attack generator
pub struct SynFloodGenerator {
    target_port: u16,
    use_random_src: bool,
}

impl SynFloodGenerator {
    pub fn new(target_port: u16) -> Self {
        Self {
            target_port,
            use_random_src: true,
        }
    }

    pub fn with_fixed_src(target_port: u16) -> Self {
        Self {
            target_port,
            use_random_src: false,
        }
    }
}

impl AttackGenerator for SynFloodGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for i in 0..count {
            let actual_src = if self.use_random_src {
                // Random spoofed source IP
                IpAddr::V4(Ipv4Addr::new(
                    rng.gen_range(1..255),
                    rng.gen_range(0..255),
                    rng.gen_range(0..255),
                    rng.gen_range(1..255),
                ))
            } else {
                src_ip
            };

            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(actual_src, src_port);
            let dst = SocketAddr::new(target, self.target_port);

            let seq: u32 = rng.gen();
            let flags = TcpFlags::syn();

            let record = PacketRecord::new(i as u64, AttackType::SynFlood)
                .with_tcp(src, dst, flags, seq, 0, &[]);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::SynFlood
    }

    fn description(&self) -> &'static str {
        "SYN flood - overwhelms target with SYN packets"
    }
}

/// ICMP flood attack generator
pub struct IcmpFloodGenerator {
    payload_size: usize,
}

impl IcmpFloodGenerator {
    pub fn new() -> Self {
        Self { payload_size: 56 } // Standard ping size
    }

    pub fn with_payload_size(size: usize) -> Self {
        Self { payload_size: size }
    }
}

impl Default for IcmpFloodGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGenerator for IcmpFloodGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);

        for i in 0..count {
            let record = PacketRecord::new(i as u64, AttackType::IcmpFlood)
                .with_icmp(src_ip, target);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::IcmpFlood
    }

    fn description(&self) -> &'static str {
        "ICMP flood - ping flood attack"
    }
}

/// UDP flood attack generator
pub struct UdpFloodGenerator {
    target_port: u16,
    payload_size: usize,
}

impl UdpFloodGenerator {
    pub fn new(target_port: u16) -> Self {
        Self {
            target_port,
            payload_size: 512,
        }
    }

    pub fn with_payload_size(target_port: u16, size: usize) -> Self {
        Self {
            target_port,
            payload_size: size,
        }
    }
}

impl AttackGenerator for UdpFloodGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        // Random payload
        let mut payload = vec![0u8; self.payload_size];
        rng.fill(&mut payload[..]);

        for i in 0..count {
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, self.target_port);

            let record = PacketRecord::new(i as u64, AttackType::UdpFlood)
                .with_udp(src, dst, &payload);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::UdpFlood
    }

    fn description(&self) -> &'static str {
        "UDP flood - overwhelms target with UDP packets"
    }
}

/// HTTP flood attack generator (complete connections with requests)
pub struct HttpFloodGenerator {
    target_port: u16,
}

impl HttpFloodGenerator {
    pub fn new(target_port: u16) -> Self {
        Self { target_port }
    }
}

impl AttackGenerator for HttpFloodGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count * 4); // 4 packets per request
        let mut rng = rand::thread_rng();

        let http_requests = [
            b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\n\r\n".to_vec(),
            b"GET /index.html HTTP/1.1\r\nHost: target\r\n\r\n".to_vec(),
            b"POST /login HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"GET /api/v1/status HTTP/1.1\r\nHost: target\r\n\r\n".to_vec(),
        ];

        let packets_per_connection = count / 4;
        let mut packet_id = 0u64;

        for _ in 0..packets_per_connection {
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, self.target_port);

            let seq: u32 = rng.gen();
            let request = &http_requests[rng.gen_range(0..http_requests.len())];

            // SYN
            records.push(PacketRecord::new(packet_id, AttackType::HttpFlood)
                .with_tcp(src, dst, TcpFlags::syn(), seq, 0, &[]));
            packet_id += 1;

            // ACK (assuming SYN-ACK received)
            let ack_num = rng.gen();
            records.push(PacketRecord::new(packet_id, AttackType::HttpFlood)
                .with_tcp(src, dst, TcpFlags::ack(), seq + 1, ack_num, &[]));
            packet_id += 1;

            // PSH+ACK with HTTP request
            records.push(PacketRecord::new(packet_id, AttackType::HttpFlood)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq + 1, ack_num, request));
            packet_id += 1;

            // FIN+ACK
            records.push(PacketRecord::new(packet_id, AttackType::HttpFlood)
                .with_tcp(src, dst, TcpFlags::fin_ack(), seq + 1 + request.len() as u32, ack_num, &[]));
            packet_id += 1;
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::HttpFlood
    }

    fn description(&self) -> &'static str {
        "HTTP flood - completes connections and sends HTTP requests"
    }
}

/// Slowloris attack generator
pub struct SlowlorisGenerator {
    target_port: u16,
    connections: usize,
}

impl SlowlorisGenerator {
    pub fn new(target_port: u16, connections: usize) -> Self {
        Self {
            target_port,
            connections,
        }
    }
}

impl AttackGenerator for SlowlorisGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        // Slowloris sends incomplete HTTP headers slowly
        let partial_headers = [
            b"GET / HTTP/1.1\r\n".to_vec(),
            b"Host: target\r\n".to_vec(),
            b"X-Custom: ".to_vec(),
            b"User-Agent: Slow".to_vec(),
        ];

        let mut packet_id = 0u64;
        let packets_per_conn = count / self.connections.max(1);

        for conn in 0..self.connections {
            let src_port: u16 = 10000 + conn as u16;
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, self.target_port);

            let seq: u32 = rng.gen();

            // Initial SYN
            records.push(PacketRecord::new(packet_id, AttackType::Slowloris)
                .with_tcp(src, dst, TcpFlags::syn(), seq, 0, &[]));
            packet_id += 1;

            // ACK
            let ack_num = rng.gen();
            records.push(PacketRecord::new(packet_id, AttackType::Slowloris)
                .with_tcp(src, dst, TcpFlags::ack(), seq + 1, ack_num, &[]));
            packet_id += 1;

            // Send partial headers slowly
            let mut current_seq = seq + 1;
            for _ in 0..packets_per_conn.saturating_sub(2) {
                let header = &partial_headers[rng.gen_range(0..partial_headers.len())];
                records.push(PacketRecord::new(packet_id, AttackType::Slowloris)
                    .with_tcp(src, dst, TcpFlags::psh_ack(), current_seq, ack_num, header));
                current_seq += header.len() as u32;
                packet_id += 1;

                if packet_id as usize >= count {
                    break;
                }
            }

            if packet_id as usize >= count {
                break;
            }
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Slowloris
    }

    fn description(&self) -> &'static str {
        "Slowloris - keeps connections open with partial HTTP requests"
    }
}
