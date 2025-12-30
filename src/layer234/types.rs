//! Detection and configuration types for netvec
//!
//! This module contains detector-specific types used for configuration,
//! internal threat classification, and real-time signature updates.
//!
//! Note: Core detection types (DetectionEvent, DetectionType, etc.) are
//! imported from crmonban-types for pipeline compatibility.

use serde::{Deserialize, Serialize};

// =============================================================================
// Pipeline Stage Types
// =============================================================================

/// Configuration passed to detector stage from pipeline
///
/// This config is passed via the StageProcessor::process() method.
/// The detector also maintains internal config (DetectorConfig) set at build time.
#[derive(Debug, Clone, Default)]
pub struct DetectorStageConfig {
    /// Override anomaly threshold for this packet (if set)
    pub anomaly_threshold_override: Option<f32>,
    /// Override signature threshold for this packet (if set)
    pub signature_threshold_override: Option<f32>,
}

/// Pipeline stage identifier for the detector
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectorStage {
    /// Threat detection stage (scans, brute force, DoS, anomalies)
    ThreatDetection,
}

// Feature vector configuration
// Extended to 88 dimensions to include Layer 2-3 attack features (72-87)
pub const VECTOR_DIM: usize = 88;
pub type FeatureVector = [f32; VECTOR_DIM];

// Layer 2-3 feature indices documentation:
// 72-75: ARP features
//   72: ARP request ratio (requests / total ARP)
//   73: Gratuitous ARP ratio
//   74: MAC-IP binding change rate
//   75: Unique IPs claimed by single MAC
// 76-79: DHCP features
//   76: DHCP Discover ratio
//   77: Unique requesting MACs (normalized)
//   78: Unique DHCP servers offering
//   79: DHCP request rate
// 80-83: ICMP tunneling features
//   80: Average ICMP payload size (normalized)
//   81: ICMP payload entropy
//   82: Echo request/reply asymmetry
//   83: ICMP timing regularity (tunnel indicator)
// 84-87: IPv6 RA features
//   84: RA packets per second
//   85: Unique router sources
//   86: Prefix advertisement changes
//   87: RAs with zero lifetime (DoS indicator)

// =============================================================================
// Internal Threat Classification Types
// =============================================================================

/// Internal threat type used for heuristic detection before mapping to crmonban-types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ThreatType {
    PortScan {
        scan_type: ScanType,
        ports_touched: u32,
    },
    BruteForce {
        attempts: u32,
        target_service: String,
    },
    Anomaly {
        deviation_score: f32,
    },
    PingSweep {
        hosts_probed: u32,
    },
    Amplification {
        protocol: String,
        amplification_factor: f32,
    },
    /// SYN flood attack - high rate of SYN packets without completing handshakes
    SynFlood {
        packets_per_sec: f32,
        half_open_connections: u32,
    },
    /// UDP flood attack - high rate of UDP packets overwhelming the target
    UdpFlood {
        packets_per_sec: f32,
        bytes_per_sec: f32,
    },
    /// ICMP flood attack - high rate of ICMP echo requests to single target
    IcmpFlood {
        packets_per_sec: f32,
        target_ip_count: u32,
    },
    /// Connection exhaustion - many half-open connections overwhelming resources
    ConnectionExhaustion {
        connection_rate: f32,
        half_open_ratio: f32,
    },

    // =========================================================================
    // Layer 2 Attacks
    // =========================================================================

    /// ARP spoofing/cache poisoning - MAC-IP binding changed
    ArpSpoofing {
        spoofed_ip: String,       // Serializable form of Ipv4Addr
        attacker_mac: String,     // Hex string of MAC
        original_mac: String,     // Original MAC that was replaced
        change_count: u32,
    },
    /// ARP flood - high rate of gratuitous ARPs or one MAC claiming multiple IPs
    ArpFlood {
        packets_per_sec: f32,
        unique_ips_claimed: u32,
    },
    /// VLAN hopping - double-tagged 802.1Q frame detected
    VlanHopping {
        outer_vlan: u16,
        inner_vlan: u16,
    },
    /// DHCP starvation - many unique MACs requesting IPs
    DhcpStarvation {
        unique_macs: u32,
        requests_per_sec: f32,
    },
    /// Rogue DHCP server detected
    RogueDhcp {
        server_ip: String,        // Serializable form
        offers_count: u32,
    },

    // =========================================================================
    // Layer 3 Attacks
    // =========================================================================

    /// ICMP tunneling - data exfiltration via ICMP echo payloads
    IcmpTunnel {
        avg_payload_size: u32,
        packets_per_sec: f32,
        entropy: f32,             // Payload entropy (0.0-1.0)
    },
    /// IPv6 Router Advertisement spoofing
    Ipv6RaSpoofing {
        src_ip: String,           // Serializable form of Ipv6Addr
        router_lifetime: u16,
    },
    /// IPv6 RA flood - too many router advertisements
    Ipv6RaFlood {
        unique_routers: u32,
        ra_per_sec: f32,
    },

    // =========================================================================
    // Infrastructure Attacks (extra234 feature)
    // =========================================================================

    /// BGP hijacking - unauthorized AS announcing prefixes
    #[cfg(feature = "extra234")]
    BgpHijack {
        prefix: String,
        suspicious_as: u32,
        original_as: Option<u32>,
    },
    /// BGP prefix flapping - rapid withdrawal/announcement
    #[cfg(feature = "extra234")]
    BgpPrefixFlap {
        prefix: String,
        flap_count: u32,
    },
    /// STP root bridge attack - priority manipulation
    #[cfg(feature = "extra234")]
    StpRootAttack {
        attacker_mac: String,
        claimed_priority: u16,
    },
    /// STP Topology Change flood
    #[cfg(feature = "extra234")]
    StpTcFlood {
        tc_count: u32,
        interval_ms: u32,
    },
    /// CDP spoofing - fake device announcement
    #[cfg(feature = "extra234")]
    CdpSpoof {
        device_id: String,
        claimed_ip: Option<String>,
    },
    /// LLDP spoofing - fake neighbor discovery
    #[cfg(feature = "extra234")]
    LldpSpoof {
        chassis_id: String,
        port_id: String,
    },
    /// OSPF neighbor injection - unauthorized router
    #[cfg(feature = "extra234")]
    OspfNeighborInject {
        router_id: String,
        area_id: String,
    },
    /// OSPF DR manipulation
    #[cfg(feature = "extra234")]
    OspfDrManipulation {
        claimed_dr: String,
        area_id: String,
    },
    /// RIP route poisoning - hop count 16 or metric manipulation
    #[cfg(feature = "extra234")]
    RipPoisoning {
        route: String,
        metric: u32,
    },
    /// Unauthorized GRE tunnel detected
    #[cfg(feature = "extra234")]
    GreTunnel {
        src_ip: String,
        dst_ip: String,
        inner_proto: u16,
    },
    /// Unauthorized VXLAN tunnel detected
    #[cfg(feature = "extra234")]
    VxlanUnauthorized {
        vni: u32,
        vtep_ip: String,
    },
    /// 802.1X hub bypass - multiple MACs behind authenticated port
    #[cfg(feature = "extra234")]
    Dot1xHubBypass {
        port_macs: u32,
        port_id: String,
    },
    /// EAP-Start flood attack
    #[cfg(feature = "extra234")]
    EapFlood {
        eap_starts_per_sec: f32,
    },
    /// Rogue 802.1X authenticator detected
    #[cfg(feature = "extra234")]
    RogueAuthenticator {
        src_mac: String,
    },
}

impl ThreatType {
    /// Get the threat type name as a string for config matching
    pub fn name(&self) -> &'static str {
        match self {
            ThreatType::PortScan { .. } => "PortScan",
            ThreatType::BruteForce { .. } => "BruteForce",
            ThreatType::Anomaly { .. } => "Anomaly",
            ThreatType::PingSweep { .. } => "PingSweep",
            ThreatType::Amplification { .. } => "Amplification",
            ThreatType::SynFlood { .. } => "SynFlood",
            ThreatType::UdpFlood { .. } => "UdpFlood",
            ThreatType::IcmpFlood { .. } => "IcmpFlood",
            ThreatType::ConnectionExhaustion { .. } => "ConnectionExhaustion",
            // Layer 2 attacks
            ThreatType::ArpSpoofing { .. } => "ArpSpoofing",
            ThreatType::ArpFlood { .. } => "ArpFlood",
            ThreatType::VlanHopping { .. } => "VlanHopping",
            ThreatType::DhcpStarvation { .. } => "DhcpStarvation",
            ThreatType::RogueDhcp { .. } => "RogueDhcp",
            // Layer 3 attacks
            ThreatType::IcmpTunnel { .. } => "IcmpTunnel",
            ThreatType::Ipv6RaSpoofing { .. } => "Ipv6RaSpoofing",
            ThreatType::Ipv6RaFlood { .. } => "Ipv6RaFlood",
            // Infrastructure attacks (extra234)
            #[cfg(feature = "extra234")]
            ThreatType::BgpHijack { .. } => "BgpHijack",
            #[cfg(feature = "extra234")]
            ThreatType::BgpPrefixFlap { .. } => "BgpPrefixFlap",
            #[cfg(feature = "extra234")]
            ThreatType::StpRootAttack { .. } => "StpRootAttack",
            #[cfg(feature = "extra234")]
            ThreatType::StpTcFlood { .. } => "StpTcFlood",
            #[cfg(feature = "extra234")]
            ThreatType::CdpSpoof { .. } => "CdpSpoof",
            #[cfg(feature = "extra234")]
            ThreatType::LldpSpoof { .. } => "LldpSpoof",
            #[cfg(feature = "extra234")]
            ThreatType::OspfNeighborInject { .. } => "OspfNeighborInject",
            #[cfg(feature = "extra234")]
            ThreatType::OspfDrManipulation { .. } => "OspfDrManipulation",
            #[cfg(feature = "extra234")]
            ThreatType::RipPoisoning { .. } => "RipPoisoning",
            #[cfg(feature = "extra234")]
            ThreatType::GreTunnel { .. } => "GreTunnel",
            #[cfg(feature = "extra234")]
            ThreatType::VxlanUnauthorized { .. } => "VxlanUnauthorized",
            #[cfg(feature = "extra234")]
            ThreatType::Dot1xHubBypass { .. } => "Dot1xHubBypass",
            #[cfg(feature = "extra234")]
            ThreatType::EapFlood { .. } => "EapFlood",
            #[cfg(feature = "extra234")]
            ThreatType::RogueAuthenticator { .. } => "RogueAuthenticator",
        }
    }
}

/// Internal scan type classification
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum ScanType {
    TcpSyn,
    TcpConnect,
    TcpFin,
    TcpXmas,
    TcpNull,
    Udp,
    Unknown,
}

// =============================================================================
// Detector Configuration
// =============================================================================

#[derive(Clone, Debug)]
pub struct DetectorConfig {
    pub scan_detection: bool,
    pub bruteforce_detection: bool,
    pub anomaly_detection: bool,
    pub dos_detection: bool,
    pub anomaly_threshold: f32,
    pub signature_threshold: f32,
    pub window_size_ms: u64,
    pub min_packets_for_detection: usize,
    /// Minimum normalized packet rate to consider as potential DoS (0.1 = 10,000 pps)
    pub dos_min_packet_rate: f32,
    /// Half-open ratio threshold for SYN flood detection
    pub dos_half_open_threshold: f32,

    // Layer 2 detection settings
    /// Enable ARP spoofing/flood detection
    pub arp_detection: bool,
    /// Enable DHCP starvation/rogue server detection
    pub dhcp_detection: bool,
    /// Enable VLAN hopping detection
    pub vlan_detection: bool,

    // Layer 3 detection settings
    /// Enable ICMP tunneling detection
    pub icmp_tunnel_detection: bool,
    /// Enable IPv6 RA spoofing/flood detection
    pub ipv6_ra_detection: bool,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            scan_detection: true,
            bruteforce_detection: true,
            anomaly_detection: true,
            dos_detection: true,
            anomaly_threshold: 0.7,
            signature_threshold: 0.85,
            window_size_ms: 60_000,
            min_packets_for_detection: 10,
            dos_min_packet_rate: 0.1,
            dos_half_open_threshold: 0.7,
            // Layer 2 defaults
            arp_detection: true,
            dhcp_detection: true,
            vlan_detection: true,
            // Layer 3 defaults
            icmp_tunnel_detection: true,
            ipv6_ra_detection: true,
        }
    }
}

// =============================================================================
// Real-time Signature Update Types
// =============================================================================

/// Commands for real-time signature updates via channel
#[derive(Debug, Clone)]
pub enum SignatureUpdate {
    /// Add a new signature to the detector
    Add {
        name: String,
        vector: FeatureVector,
    },
    /// Disable a signature by name (keeps in index, marks inactive)
    Disable { name: String },
    /// Re-enable a previously disabled signature
    Enable { name: String },
}

/// Handle for sending signature updates to the detector
///
/// This handle is Clone and can be shared across multiple tasks.
/// Use it to dynamically add or disable signatures at runtime.
///
/// # Example
/// ```ignore
/// let sender = detector.signature_update_channel();
///
/// // Add new signature
/// sender.send(SignatureUpdate::Add {
///     name: "new_attack".to_string(),
///     vector: attack_vector,
/// }).await?;
///
/// // Disable old signature
/// sender.send(SignatureUpdate::Disable {
///     name: "old_signature".to_string(),
/// }).await?;
/// ```
#[derive(Clone)]
pub struct SignatureUpdateSender {
    tx: tokio::sync::mpsc::Sender<SignatureUpdate>,
}

impl SignatureUpdateSender {
    /// Create a new sender from an mpsc sender
    pub fn new(tx: tokio::sync::mpsc::Sender<SignatureUpdate>) -> Self {
        Self { tx }
    }

    /// Send a signature update to the detector
    pub async fn send(&self, update: SignatureUpdate) -> Result<(), tokio::sync::mpsc::error::SendError<SignatureUpdate>> {
        self.tx.send(update).await
    }

    /// Try to send a signature update without waiting
    pub fn try_send(&self, update: SignatureUpdate) -> Result<(), tokio::sync::mpsc::error::TrySendError<SignatureUpdate>> {
        self.tx.try_send(update)
    }
}
