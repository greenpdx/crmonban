//! Brute force attack generators
//!
//! Implements SSH, FTP, HTTP brute force patterns.

use std::net::{IpAddr, SocketAddr};
use rand::Rng;

use crate::attacks::{AttackGenerator, AttackType};
use crate::generator::PacketRecord;
use crate::state_machine::{TcpFlags, TcpStateMachine};

/// SSH brute force generator
pub struct SshBruteForceGenerator {
    state_machine: TcpStateMachine,
    usernames: Vec<&'static str>,
    passwords: Vec<&'static str>,
}

impl SshBruteForceGenerator {
    pub fn new() -> Self {
        Self {
            state_machine: TcpStateMachine::new(),
            usernames: vec!["root", "admin", "user", "test", "ubuntu", "pi", "oracle", "postgres"],
            passwords: vec!["password", "123456", "admin", "root", "test", "toor", "pass", "qwerty"],
        }
    }
}

impl Default for SshBruteForceGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGenerator for SshBruteForceGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        // SSH auth attempts typically look like:
        // 1. TCP handshake (SYN, SYN-ACK, ACK)
        // 2. SSH version exchange
        // 3. Key exchange
        // 4. Auth attempt
        // 5. Failed -> RST or FIN

        let attempts = count / 5; // ~5 packets per attempt
        let mut packet_id = 0u64;

        for _ in 0..attempts {
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, 22);

            // SYN
            let (seq, ack, flags) = self.state_machine.start_handshake(src, dst);
            records.push(PacketRecord::new(packet_id, AttackType::SshBruteForce)
                .with_tcp(src, dst, flags, seq, ack, &[]));
            packet_id += 1;

            // ACK (after receiving SYN-ACK)
            let server_seq: u32 = rng.gen();
            let (seq2, ack2, flags2) = self.state_machine.complete_handshake(src, dst, server_seq);
            records.push(PacketRecord::new(packet_id, AttackType::SshBruteForce)
                .with_tcp(src, dst, flags2, seq2, ack2, &[]));
            packet_id += 1;

            // SSH version string
            let ssh_version = b"SSH-2.0-OpenSSH_8.9\r\n";
            records.push(PacketRecord::new(packet_id, AttackType::SshBruteForce)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2, ack2, ssh_version));
            packet_id += 1;

            // Simulated auth packet (simplified)
            let user = self.usernames[rng.gen_range(0..self.usernames.len())];
            let pass = self.passwords[rng.gen_range(0..self.passwords.len())];
            let auth_payload = format!("{}:{}", user, pass);
            records.push(PacketRecord::new(packet_id, AttackType::SshBruteForce)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2 + ssh_version.len() as u32, ack2, auth_payload.as_bytes()));
            packet_id += 1;

            // RST after failed auth
            let (seq3, ack3, flags3) = self.state_machine.reset(src, dst);
            records.push(PacketRecord::new(packet_id, AttackType::SshBruteForce)
                .with_tcp(src, dst, flags3, seq3, ack3, &[]));
            packet_id += 1;

            if packet_id as usize >= count {
                break;
            }
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::SshBruteForce
    }

    fn description(&self) -> &'static str {
        "SSH brute force - rapid authentication attempts"
    }
}

/// FTP brute force generator
pub struct FtpBruteForceGenerator {
    state_machine: TcpStateMachine,
    usernames: Vec<&'static str>,
    passwords: Vec<&'static str>,
}

impl FtpBruteForceGenerator {
    pub fn new() -> Self {
        Self {
            state_machine: TcpStateMachine::new(),
            usernames: vec!["anonymous", "ftp", "admin", "root", "user", "test"],
            passwords: vec!["anonymous", "ftp", "admin", "password", "123456", "guest"],
        }
    }
}

impl Default for FtpBruteForceGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGenerator for FtpBruteForceGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        let attempts = count / 6; // ~6 packets per attempt
        let mut packet_id = 0u64;

        for _ in 0..attempts {
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, 21);

            // TCP handshake
            let (seq, ack, flags) = self.state_machine.start_handshake(src, dst);
            records.push(PacketRecord::new(packet_id, AttackType::FtpBruteForce)
                .with_tcp(src, dst, flags, seq, ack, &[]));
            packet_id += 1;

            let server_seq: u32 = rng.gen();
            let (seq2, ack2, flags2) = self.state_machine.complete_handshake(src, dst, server_seq);
            records.push(PacketRecord::new(packet_id, AttackType::FtpBruteForce)
                .with_tcp(src, dst, flags2, seq2, ack2, &[]));
            packet_id += 1;

            // FTP USER command
            let user = self.usernames[rng.gen_range(0..self.usernames.len())];
            let user_cmd = format!("USER {}\r\n", user);
            records.push(PacketRecord::new(packet_id, AttackType::FtpBruteForce)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2, ack2, user_cmd.as_bytes()));
            packet_id += 1;

            // FTP PASS command
            let pass = self.passwords[rng.gen_range(0..self.passwords.len())];
            let pass_cmd = format!("PASS {}\r\n", pass);
            records.push(PacketRecord::new(packet_id, AttackType::FtpBruteForce)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2 + user_cmd.len() as u32, ack2, pass_cmd.as_bytes()));
            packet_id += 1;

            // QUIT
            let quit_cmd = b"QUIT\r\n";
            records.push(PacketRecord::new(packet_id, AttackType::FtpBruteForce)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2 + user_cmd.len() as u32 + pass_cmd.len() as u32, ack2, quit_cmd));
            packet_id += 1;

            // FIN
            records.push(PacketRecord::new(packet_id, AttackType::FtpBruteForce)
                .with_tcp(src, dst, TcpFlags::fin_ack(), seq2 + user_cmd.len() as u32 + pass_cmd.len() as u32 + 6, ack2, &[]));
            packet_id += 1;

            if packet_id as usize >= count {
                break;
            }
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::FtpBruteForce
    }

    fn description(&self) -> &'static str {
        "FTP brute force - rapid USER/PASS attempts"
    }
}

/// HTTP Basic Auth brute force generator
pub struct HttpBruteForceGenerator {
    state_machine: TcpStateMachine,
    target_port: u16,
    usernames: Vec<&'static str>,
    passwords: Vec<&'static str>,
}

impl HttpBruteForceGenerator {
    pub fn new(target_port: u16) -> Self {
        Self {
            state_machine: TcpStateMachine::new(),
            target_port,
            usernames: vec!["admin", "administrator", "root", "user", "guest"],
            passwords: vec!["admin", "password", "123456", "root", "admin123", "pass"],
        }
    }
}

impl AttackGenerator for HttpBruteForceGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        let attempts = count / 4;
        let mut packet_id = 0u64;

        for _ in 0..attempts {
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, self.target_port);

            // TCP handshake
            let (seq, ack, flags) = self.state_machine.start_handshake(src, dst);
            records.push(PacketRecord::new(packet_id, AttackType::HttpBruteForce)
                .with_tcp(src, dst, flags, seq, ack, &[]));
            packet_id += 1;

            let server_seq: u32 = rng.gen();
            let (seq2, ack2, flags2) = self.state_machine.complete_handshake(src, dst, server_seq);
            records.push(PacketRecord::new(packet_id, AttackType::HttpBruteForce)
                .with_tcp(src, dst, flags2, seq2, ack2, &[]));
            packet_id += 1;

            // HTTP request with Basic Auth
            let user = self.usernames[rng.gen_range(0..self.usernames.len())];
            let pass = self.passwords[rng.gen_range(0..self.passwords.len())];
            let creds = format!("{}:{}", user, pass);
            let auth = base64_encode(&creds);
            let request = format!(
                "GET /admin HTTP/1.1\r\nHost: target\r\nAuthorization: Basic {}\r\n\r\n",
                auth
            );
            records.push(PacketRecord::new(packet_id, AttackType::HttpBruteForce)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2, ack2, request.as_bytes()));
            packet_id += 1;

            // FIN
            records.push(PacketRecord::new(packet_id, AttackType::HttpBruteForce)
                .with_tcp(src, dst, TcpFlags::fin_ack(), seq2 + request.len() as u32, ack2, &[]));
            packet_id += 1;

            if packet_id as usize >= count {
                break;
            }
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::HttpBruteForce
    }

    fn description(&self) -> &'static str {
        "HTTP brute force - Basic Auth credential stuffing"
    }
}

/// Telnet brute force generator
pub struct TelnetBruteForceGenerator {
    state_machine: TcpStateMachine,
}

impl TelnetBruteForceGenerator {
    pub fn new() -> Self {
        Self {
            state_machine: TcpStateMachine::new(),
        }
    }
}

impl Default for TelnetBruteForceGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackGenerator for TelnetBruteForceGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        let usernames = ["root", "admin", "user", "guest"];
        let passwords = ["root", "admin", "password", "123456", "toor"];

        let attempts = count / 4;
        let mut packet_id = 0u64;

        for _ in 0..attempts {
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, 23);

            // TCP handshake
            let (seq, ack, flags) = self.state_machine.start_handshake(src, dst);
            records.push(PacketRecord::new(packet_id, AttackType::TelnetBruteForce)
                .with_tcp(src, dst, flags, seq, ack, &[]));
            packet_id += 1;

            let server_seq: u32 = rng.gen();
            let (seq2, ack2, flags2) = self.state_machine.complete_handshake(src, dst, server_seq);
            records.push(PacketRecord::new(packet_id, AttackType::TelnetBruteForce)
                .with_tcp(src, dst, flags2, seq2, ack2, &[]));
            packet_id += 1;

            // Username
            let user = usernames[rng.gen_range(0..usernames.len())];
            let user_data = format!("{}\r\n", user);
            records.push(PacketRecord::new(packet_id, AttackType::TelnetBruteForce)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2, ack2, user_data.as_bytes()));
            packet_id += 1;

            // Password
            let pass = passwords[rng.gen_range(0..passwords.len())];
            let pass_data = format!("{}\r\n", pass);
            records.push(PacketRecord::new(packet_id, AttackType::TelnetBruteForce)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2 + user_data.len() as u32, ack2, pass_data.as_bytes()));
            packet_id += 1;

            if packet_id as usize >= count {
                break;
            }
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::TelnetBruteForce
    }

    fn description(&self) -> &'static str {
        "Telnet brute force - credential stuffing on port 23"
    }
}

/// Simple base64 encoding (no external deps)
fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = chunk.get(1).copied().unwrap_or(0) as usize;
        let b2 = chunk.get(2).copied().unwrap_or(0) as usize;

        result.push(ALPHABET[b0 >> 2] as char);
        result.push(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        } else {
            result.push('=');
        }

        if chunk.len() > 2 {
            result.push(ALPHABET[b2 & 0x3f] as char);
        } else {
            result.push('=');
        }
    }

    result
}
