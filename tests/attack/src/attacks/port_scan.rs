//! Port scanning attacks
//!
//! Implements various port scanning techniques.

use std::net::{IpAddr, SocketAddr};
use rand::Rng;

use crate::attacks::{AttackGenerator, AttackType};
use crate::generator::PacketRecord;
use crate::state_machine::{TcpFlags, TcpStateMachine};

/// SYN scan generator
pub struct SynScanGenerator {
    state_machine: TcpStateMachine,
    ports: Vec<u16>,
    current_port_idx: usize,
}

impl SynScanGenerator {
    pub fn new() -> Self {
        // Common ports to scan
        let ports = vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5432, 5900, 8080, 8443,
        ];
        Self {
            state_machine: TcpStateMachine::new(),
            ports,
            current_port_idx: 0,
        }
    }

    pub fn with_ports(ports: Vec<u16>) -> Self {
        Self {
            state_machine: TcpStateMachine::new(),
            ports,
            current_port_idx: 0,
        }
    }
}

impl AttackGenerator for SynScanGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for i in 0..count {
            let src_port: u16 = rng.gen_range(1024..65535);
            let dst_port = self.ports[self.current_port_idx % self.ports.len()];
            self.current_port_idx += 1;

            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, dst_port);

            let (seq, ack, flags) = self.state_machine.start_handshake(src, dst);

            let record = PacketRecord::new(i as u64, AttackType::SynScan)
                .with_tcp(src, dst, flags, seq, ack, &[]);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::SynScan
    }

    fn description(&self) -> &'static str {
        "SYN scan - sends SYN packets to detect open ports"
    }
}

/// NULL scan generator (no flags set)
pub struct NullScanGenerator {
    ports: Vec<u16>,
    current_port_idx: usize,
}

impl NullScanGenerator {
    pub fn new() -> Self {
        let ports = vec![21, 22, 23, 25, 80, 443, 445, 3389, 8080];
        Self {
            ports,
            current_port_idx: 0,
        }
    }
}

impl AttackGenerator for NullScanGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for i in 0..count {
            let src_port: u16 = rng.gen_range(1024..65535);
            let dst_port = self.ports[self.current_port_idx % self.ports.len()];
            self.current_port_idx += 1;

            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, dst_port);

            let seq: u32 = rng.gen();
            let flags = TcpFlags::null(); // No flags

            let record = PacketRecord::new(i as u64, AttackType::NullScan)
                .with_tcp(src, dst, flags, seq, 0, &[]);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::NullScan
    }

    fn description(&self) -> &'static str {
        "NULL scan - sends packets with no flags set"
    }
}

/// Xmas scan generator (FIN, PSH, URG flags)
pub struct XmasScanGenerator {
    ports: Vec<u16>,
    current_port_idx: usize,
}

impl XmasScanGenerator {
    pub fn new() -> Self {
        let ports = vec![21, 22, 23, 25, 80, 443, 445, 3389, 8080];
        Self {
            ports,
            current_port_idx: 0,
        }
    }
}

impl AttackGenerator for XmasScanGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for i in 0..count {
            let src_port: u16 = rng.gen_range(1024..65535);
            let dst_port = self.ports[self.current_port_idx % self.ports.len()];
            self.current_port_idx += 1;

            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, dst_port);

            let seq: u32 = rng.gen();
            let flags = TcpFlags::xmas(); // FIN + PSH + URG

            let record = PacketRecord::new(i as u64, AttackType::XmasScan)
                .with_tcp(src, dst, flags, seq, 0, &[]);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::XmasScan
    }

    fn description(&self) -> &'static str {
        "Xmas scan - sends packets with FIN, PSH, URG flags"
    }
}

/// FIN scan generator
pub struct FinScanGenerator {
    ports: Vec<u16>,
    current_port_idx: usize,
}

impl FinScanGenerator {
    pub fn new() -> Self {
        let ports = vec![21, 22, 23, 25, 80, 443, 445, 3389, 8080];
        Self {
            ports,
            current_port_idx: 0,
        }
    }
}

impl AttackGenerator for FinScanGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for i in 0..count {
            let src_port: u16 = rng.gen_range(1024..65535);
            let dst_port = self.ports[self.current_port_idx % self.ports.len()];
            self.current_port_idx += 1;

            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, dst_port);

            let seq: u32 = rng.gen();
            let flags = TcpFlags::fin();

            let record = PacketRecord::new(i as u64, AttackType::FinScan)
                .with_tcp(src, dst, flags, seq, 0, &[]);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::FinScan
    }

    fn description(&self) -> &'static str {
        "FIN scan - sends packets with only FIN flag"
    }
}

/// ACK scan generator
pub struct AckScanGenerator {
    ports: Vec<u16>,
    current_port_idx: usize,
}

impl AckScanGenerator {
    pub fn new() -> Self {
        let ports = vec![21, 22, 23, 25, 80, 443, 445, 3389, 8080];
        Self {
            ports,
            current_port_idx: 0,
        }
    }
}

impl AttackGenerator for AckScanGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for i in 0..count {
            let src_port: u16 = rng.gen_range(1024..65535);
            let dst_port = self.ports[self.current_port_idx % self.ports.len()];
            self.current_port_idx += 1;

            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, dst_port);

            let seq: u32 = rng.gen();
            let ack: u32 = rng.gen();
            let flags = TcpFlags::ack();

            let record = PacketRecord::new(i as u64, AttackType::AckScan)
                .with_tcp(src, dst, flags, seq, ack, &[]);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::AckScan
    }

    fn description(&self) -> &'static str {
        "ACK scan - sends packets with only ACK flag to detect filtered ports"
    }
}

/// UDP scan generator
pub struct UdpScanGenerator {
    ports: Vec<u16>,
    current_port_idx: usize,
}

impl UdpScanGenerator {
    pub fn new() -> Self {
        let ports = vec![53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1900];
        Self {
            ports,
            current_port_idx: 0,
        }
    }
}

impl AttackGenerator for UdpScanGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for i in 0..count {
            let src_port: u16 = rng.gen_range(1024..65535);
            let dst_port = self.ports[self.current_port_idx % self.ports.len()];
            self.current_port_idx += 1;

            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, dst_port);

            // Empty payload for basic scan
            let record = PacketRecord::new(i as u64, AttackType::UdpScan)
                .with_udp(src, dst, &[]);

            records.push(record);
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::UdpScan
    }

    fn description(&self) -> &'static str {
        "UDP scan - sends empty UDP packets to detect open ports"
    }
}
