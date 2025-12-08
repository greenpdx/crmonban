//! Attack implementations
//!
//! Each attack module generates packets for a specific attack category.

pub mod port_scan;
pub mod syn_flood;
pub mod brute_force;
pub mod web_attacks;
pub mod dns_attacks;
pub mod fuzzer;

use std::net::IpAddr;
use crate::state_machine::TcpState;
use crate::generator::PacketRecord;

/// Attack type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    // Port Scanning
    SynScan,
    NullScan,
    XmasScan,
    FinScan,
    AckScan,
    UdpScan,

    // DoS/DDoS
    SynFlood,
    IcmpFlood,
    UdpFlood,
    HttpFlood,
    Slowloris,

    // Brute Force
    SshBruteForce,
    FtpBruteForce,
    HttpBruteForce,
    TelnetBruteForce,

    // Web Attacks
    SqlInjection,
    Xss,
    CommandInjection,
    PathTraversal,

    // DNS
    DnsTunneling,
    DnsAmplification,

    // Fuzzing
    MalformedTcp,
    InvalidFlags,
    OversizedPacket,
    FragmentAttack,

    // Benign traffic
    Benign,
}

impl std::fmt::Display for AttackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackType::SynScan => write!(f, "syn_scan"),
            AttackType::NullScan => write!(f, "null_scan"),
            AttackType::XmasScan => write!(f, "xmas_scan"),
            AttackType::FinScan => write!(f, "fin_scan"),
            AttackType::AckScan => write!(f, "ack_scan"),
            AttackType::UdpScan => write!(f, "udp_scan"),
            AttackType::SynFlood => write!(f, "syn_flood"),
            AttackType::IcmpFlood => write!(f, "icmp_flood"),
            AttackType::UdpFlood => write!(f, "udp_flood"),
            AttackType::HttpFlood => write!(f, "http_flood"),
            AttackType::Slowloris => write!(f, "slowloris"),
            AttackType::SshBruteForce => write!(f, "ssh_brute_force"),
            AttackType::FtpBruteForce => write!(f, "ftp_brute_force"),
            AttackType::HttpBruteForce => write!(f, "http_brute_force"),
            AttackType::TelnetBruteForce => write!(f, "telnet_brute_force"),
            AttackType::SqlInjection => write!(f, "sql_injection"),
            AttackType::Xss => write!(f, "xss"),
            AttackType::CommandInjection => write!(f, "command_injection"),
            AttackType::PathTraversal => write!(f, "path_traversal"),
            AttackType::DnsTunneling => write!(f, "dns_tunneling"),
            AttackType::DnsAmplification => write!(f, "dns_amplification"),
            AttackType::MalformedTcp => write!(f, "malformed_tcp"),
            AttackType::InvalidFlags => write!(f, "invalid_flags"),
            AttackType::OversizedPacket => write!(f, "oversized_packet"),
            AttackType::FragmentAttack => write!(f, "fragment_attack"),
            AttackType::Benign => write!(f, "benign"),
        }
    }
}

/// Trait for attack generators
pub trait AttackGenerator: Send + Sync {
    /// Generate packets for this attack
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord>;

    /// Get the attack type
    fn attack_type(&self) -> AttackType;

    /// Get description
    fn description(&self) -> &'static str;
}

/// Attack distribution configuration
#[derive(Debug, Clone)]
pub struct AttackDistribution {
    pub port_scan_pct: f32,      // 20%
    pub dos_pct: f32,            // 20%
    pub brute_force_pct: f32,    // 15%
    pub web_attacks_pct: f32,    // 15%
    pub recon_pct: f32,          // 10%
    pub evasion_pct: f32,        // 5%
    pub fuzzing_pct: f32,        // 5%
    pub benign_pct: f32,         // 10%
}

impl Default for AttackDistribution {
    fn default() -> Self {
        Self {
            port_scan_pct: 0.20,
            dos_pct: 0.20,
            brute_force_pct: 0.15,
            web_attacks_pct: 0.15,
            recon_pct: 0.10,
            evasion_pct: 0.05,
            fuzzing_pct: 0.05,
            benign_pct: 0.10,
        }
    }
}

impl AttackDistribution {
    /// Distribution with 90% attacks, 10% benign
    pub fn attack_heavy() -> Self {
        Self {
            port_scan_pct: 0.20,
            dos_pct: 0.20,
            brute_force_pct: 0.15,
            web_attacks_pct: 0.15,
            recon_pct: 0.10,
            evasion_pct: 0.05,
            fuzzing_pct: 0.05,
            benign_pct: 0.10,
        }
    }
}
