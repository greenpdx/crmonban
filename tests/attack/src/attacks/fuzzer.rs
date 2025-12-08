//! Fuzzing and evasion attacks
//!
//! Malformed packets, invalid flags, oversized packets, fragmentation.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use rand::Rng;

use crate::attacks::{AttackGenerator, AttackType};
use crate::generator::PacketRecord;
use crate::state_machine::TcpFlags;

/// Malformed TCP packet generator
pub struct MalformedTcpGenerator;

impl MalformedTcpGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MalformedTcpGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGenerator for MalformedTcpGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for i in 0..count {
            let src_port: u16 = rng.gen_range(1024..65535);
            let dst_port: u16 = rng.gen_range(1..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, dst_port);

            // Generate random malformed data
            let malformed_len = rng.gen_range(10..100);
            let malformed_data: Vec<u8> = (0..malformed_len).map(|_| rng.gen()).collect();

            // Random flags - some combinations are invalid
            let flags = TcpFlags::from_u8(rng.gen());

            let seq: u32 = rng.gen();
            let ack: u32 = rng.gen();

            let record = PacketRecord::new(i as u64, AttackType::MalformedTcp)
                .with_tcp(src, dst, flags, seq, ack, &malformed_data);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::MalformedTcp
    }

    fn description(&self) -> &'static str {
        "Malformed TCP - packets with random/invalid data"
    }
}

/// Invalid TCP flags generator
pub struct InvalidFlagsGenerator;

impl InvalidFlagsGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate invalid flag combinations
    fn invalid_flags() -> Vec<TcpFlags> {
        vec![
            // SYN+FIN (invalid - can't start and end simultaneously)
            TcpFlags { syn: true, fin: true, ..Default::default() },
            // SYN+RST (invalid)
            TcpFlags { syn: true, rst: true, ..Default::default() },
            // All flags set
            TcpFlags {
                fin: true, syn: true, rst: true, psh: true,
                ack: true, urg: true, ece: true, cwr: true,
            },
            // URG without data
            TcpFlags { urg: true, ..Default::default() },
            // PSH without ACK
            TcpFlags { psh: true, ..Default::default() },
            // FIN without ACK (unusual)
            TcpFlags { fin: true, ..Default::default() },
            // SYN+RST+FIN (very invalid)
            TcpFlags { syn: true, rst: true, fin: true, ..Default::default() },
            // ECE+CWR without SYN (unusual)
            TcpFlags { ece: true, cwr: true, ..Default::default() },
        ]
    }
}

impl Default for InvalidFlagsGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGenerator for InvalidFlagsGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();
        let invalid_flags = Self::invalid_flags();

        for i in 0..count {
            let src_port: u16 = rng.gen_range(1024..65535);
            let dst_port: u16 = rng.gen_range(1..1024); // Well-known ports
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, dst_port);

            let flags = invalid_flags[i % invalid_flags.len()].clone();
            let seq: u32 = rng.gen();
            let ack: u32 = rng.gen();

            let record = PacketRecord::new(i as u64, AttackType::InvalidFlags)
                .with_tcp(src, dst, flags, seq, ack, &[]);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::InvalidFlags
    }

    fn description(&self) -> &'static str {
        "Invalid flags - TCP packets with impossible flag combinations"
    }
}

/// Oversized packet generator
pub struct OversizedPacketGenerator {
    max_size: usize,
}

impl OversizedPacketGenerator {
    pub fn new() -> Self {
        Self { max_size: 65535 } // Max IP packet size
    }

    pub fn with_max_size(max_size: usize) -> Self {
        Self { max_size }
    }
}

impl Default for OversizedPacketGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGenerator for OversizedPacketGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for i in 0..count {
            let src_port: u16 = rng.gen_range(1024..65535);
            let dst_port: u16 = rng.gen_range(1..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, dst_port);

            // Large payload
            let payload_size = rng.gen_range(1400..self.max_size.min(8000));
            let payload: Vec<u8> = (0..payload_size).map(|_| rng.gen()).collect();

            let flags = TcpFlags::psh_ack();
            let seq: u32 = rng.gen();
            let ack: u32 = rng.gen();

            let record = PacketRecord::new(i as u64, AttackType::OversizedPacket)
                .with_tcp(src, dst, flags, seq, ack, &payload);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::OversizedPacket
    }

    fn description(&self) -> &'static str {
        "Oversized packets - large payloads to test buffer handling"
    }
}

/// Fragment attack generator (overlapping fragments, tiny fragments)
pub struct FragmentAttackGenerator;

impl FragmentAttackGenerator {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FragmentAttackGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGenerator for FragmentAttackGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        // Generate sets of fragments
        let fragment_sets = count / 3; // 3 fragments per set

        for set in 0..fragment_sets {
            let src_port: u16 = rng.gen_range(1024..65535);
            let dst_port: u16 = rng.gen_range(1..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, dst_port);

            // First fragment (offset 0)
            let frag1: Vec<u8> = (0..64).map(|_| rng.gen()).collect();
            records.push(PacketRecord::new((set * 3) as u64, AttackType::FragmentAttack)
                .with_tcp(src, dst, TcpFlags::syn(), rng.gen(), 0, &frag1));

            // Middle fragment (tiny - evasion technique)
            let frag2: Vec<u8> = (0..8).map(|_| rng.gen()).collect();
            records.push(PacketRecord::new((set * 3 + 1) as u64, AttackType::FragmentAttack)
                .with_tcp(src, dst, TcpFlags::default(), rng.gen(), 0, &frag2));

            // Overlapping fragment
            let frag3: Vec<u8> = (0..64).map(|_| rng.gen()).collect();
            records.push(PacketRecord::new((set * 3 + 2) as u64, AttackType::FragmentAttack)
                .with_tcp(src, dst, TcpFlags::default(), rng.gen(), 0, &frag3));

            if (set * 3 + 3) >= count {
                break;
            }
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::FragmentAttack
    }

    fn description(&self) -> &'static str {
        "Fragment attacks - overlapping and tiny fragments for evasion"
    }
}

/// Benign traffic generator (for the 10% non-attack traffic)
pub struct BenignTrafficGenerator {
    state_machine: crate::state_machine::TcpStateMachine,
}

impl BenignTrafficGenerator {
    pub fn new() -> Self {
        Self {
            state_machine: crate::state_machine::TcpStateMachine::new(),
        }
    }
}

impl Default for BenignTrafficGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGenerator for BenignTrafficGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        // Normal HTTP requests
        let http_requests = [
            b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n".to_vec(),
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
            b"GET /favicon.ico HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
            b"GET /style.css HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        ];

        let connections = count / 6; // ~6 packets per connection
        let mut packet_id = 0u64;

        for _ in 0..connections {
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, 80);

            // Full TCP handshake + request + teardown
            let (seq1, ack1, flags1) = self.state_machine.start_handshake(src, dst);
            records.push(PacketRecord::new(packet_id, AttackType::Benign)
                .with_tcp(src, dst, flags1, seq1, ack1, &[]));
            packet_id += 1;

            let server_seq: u32 = rng.gen();
            let (seq2, ack2, flags2) = self.state_machine.complete_handshake(src, dst, server_seq);
            records.push(PacketRecord::new(packet_id, AttackType::Benign)
                .with_tcp(src, dst, flags2, seq2, ack2, &[]));
            packet_id += 1;

            // HTTP request
            let request = &http_requests[rng.gen_range(0..http_requests.len())];
            records.push(PacketRecord::new(packet_id, AttackType::Benign)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2, ack2, request));
            packet_id += 1;

            // ACK from server (simulated)
            records.push(PacketRecord::new(packet_id, AttackType::Benign)
                .with_tcp(src, dst, TcpFlags::ack(), seq2 + request.len() as u32, ack2 + 500, &[]));
            packet_id += 1;

            // FIN from client
            records.push(PacketRecord::new(packet_id, AttackType::Benign)
                .with_tcp(src, dst, TcpFlags::fin_ack(), seq2 + request.len() as u32, ack2 + 500, &[]));
            packet_id += 1;

            // Final ACK
            records.push(PacketRecord::new(packet_id, AttackType::Benign)
                .with_tcp(src, dst, TcpFlags::ack(), seq2 + request.len() as u32 + 1, ack2 + 501, &[]));
            packet_id += 1;

            if packet_id as usize >= count {
                break;
            }
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::Benign
    }

    fn description(&self) -> &'static str {
        "Benign traffic - normal HTTP requests for baseline"
    }
}
