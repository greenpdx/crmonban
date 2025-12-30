//! CDP (Cisco Discovery Protocol) and LLDP (Link Layer Discovery Protocol) Parsers
//!
//! Detects discovery protocol spoofing attacks:
//! - Fake device announcements
//! - Management address spoofing
//! - Device enumeration attempts
//! - Capability changes

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

// =============================================================================
// CDP (Cisco Discovery Protocol)
// =============================================================================

/// CDP TLV types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CdpTlvType {
    DeviceId,
    Addresses,
    PortId,
    Capabilities,
    Version,
    Platform,
    IpPrefix,
    VtpDomain,
    NativeVlan,
    Duplex,
    TrustBitmap,
    UntrustedCos,
    ManagementAddress,
    Unknown(u16),
}

impl CdpTlvType {
    pub fn to_u16(&self) -> u16 {
        match self {
            Self::DeviceId => 0x0001,
            Self::Addresses => 0x0002,
            Self::PortId => 0x0003,
            Self::Capabilities => 0x0004,
            Self::Version => 0x0005,
            Self::Platform => 0x0006,
            Self::IpPrefix => 0x0007,
            Self::VtpDomain => 0x0009,
            Self::NativeVlan => 0x000A,
            Self::Duplex => 0x000B,
            Self::TrustBitmap => 0x0012,
            Self::UntrustedCos => 0x0013,
            Self::ManagementAddress => 0x0016,
            Self::Unknown(v) => *v,
        }
    }

    pub fn from_u16(v: u16) -> Self {
        match v {
            0x0001 => Self::DeviceId,
            0x0002 => Self::Addresses,
            0x0003 => Self::PortId,
            0x0004 => Self::Capabilities,
            0x0005 => Self::Version,
            0x0006 => Self::Platform,
            0x0007 => Self::IpPrefix,
            0x0009 => Self::VtpDomain,
            0x000A => Self::NativeVlan,
            0x000B => Self::Duplex,
            0x0012 => Self::TrustBitmap,
            0x0013 => Self::UntrustedCos,
            0x0016 => Self::ManagementAddress,
            _ => Self::Unknown(v),
        }
    }
}

/// CDP TLV parsed value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CdpTlv {
    DeviceId(String),
    Addresses(Vec<IpAddr>),
    PortId(String),
    Capabilities(u32),
    Version(String),
    Platform(String),
    NativeVlan(u16),
    ManagementAddress(Vec<IpAddr>),
    Raw { tlv_type: u16, data: Vec<u8> },
}

/// CDP capability flags
pub mod cdp_capabilities {
    pub const ROUTER: u32 = 0x01;
    pub const TRANSPARENT_BRIDGE: u32 = 0x02;
    pub const SOURCE_ROUTE_BRIDGE: u32 = 0x04;
    pub const SWITCH: u32 = 0x08;
    pub const HOST: u32 = 0x10;
    pub const IGMP_CAPABLE: u32 = 0x20;
    pub const REPEATER: u32 = 0x40;
    pub const VOIP_PHONE: u32 = 0x80;
}

/// Parsed CDP packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdpPacket {
    pub version: u8,
    pub ttl: u8,
    pub checksum: u16,
    pub tlvs: Vec<CdpTlv>,
}

impl CdpPacket {
    /// Parse CDP packet from raw bytes
    /// CDP uses LLC/SNAP encapsulation: DSAP=0xAA, SSAP=0xAA, Control=0x03
    /// followed by OUI 00:00:0C and Protocol ID 0x2000
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Skip LLC/SNAP header if present (8 bytes)
        let offset = if data.len() >= 8
            && data[0] == 0xAA
            && data[1] == 0xAA
            && data[2] == 0x03
            && data[3] == 0x00
            && data[4] == 0x00
            && data[5] == 0x0C
            && data[6] == 0x20
            && data[7] == 0x00
        {
            8
        } else {
            0
        };

        let data = &data[offset..];

        if data.len() < 4 {
            return None;
        }

        let version = data[0];
        let ttl = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);

        let mut tlvs = Vec::new();
        let mut pos = 4;

        while pos + 4 <= data.len() {
            let tlv_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let tlv_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;

            if tlv_len < 4 || pos + tlv_len > data.len() {
                break;
            }

            let tlv_data = &data[pos + 4..pos + tlv_len];
            let tlv = Self::parse_tlv(CdpTlvType::from_u16(tlv_type), tlv_data);
            tlvs.push(tlv);

            pos += tlv_len;
        }

        Some(Self {
            version,
            ttl,
            checksum,
            tlvs,
        })
    }

    fn parse_tlv(tlv_type: CdpTlvType, data: &[u8]) -> CdpTlv {
        match tlv_type {
            CdpTlvType::DeviceId => {
                CdpTlv::DeviceId(String::from_utf8_lossy(data).trim_end_matches('\0').to_string())
            }
            CdpTlvType::PortId => {
                CdpTlv::PortId(String::from_utf8_lossy(data).trim_end_matches('\0').to_string())
            }
            CdpTlvType::Version => {
                CdpTlv::Version(String::from_utf8_lossy(data).trim_end_matches('\0').to_string())
            }
            CdpTlvType::Platform => {
                CdpTlv::Platform(String::from_utf8_lossy(data).trim_end_matches('\0').to_string())
            }
            CdpTlvType::Capabilities => {
                if data.len() >= 4 {
                    CdpTlv::Capabilities(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
                } else {
                    CdpTlv::Raw {
                        tlv_type: tlv_type.to_u16(),
                        data: data.to_vec(),
                    }
                }
            }
            CdpTlvType::Addresses | CdpTlvType::ManagementAddress => {
                let addrs = Self::parse_addresses(data);
                if matches!(tlv_type, CdpTlvType::ManagementAddress) {
                    CdpTlv::ManagementAddress(addrs)
                } else {
                    CdpTlv::Addresses(addrs)
                }
            }
            CdpTlvType::NativeVlan => {
                if data.len() >= 2 {
                    CdpTlv::NativeVlan(u16::from_be_bytes([data[0], data[1]]))
                } else {
                    CdpTlv::Raw {
                        tlv_type: tlv_type.to_u16(),
                        data: data.to_vec(),
                    }
                }
            }
            _ => CdpTlv::Raw {
                tlv_type: tlv_type.to_u16(),
                data: data.to_vec(),
            },
        }
    }

    fn parse_addresses(data: &[u8]) -> Vec<IpAddr> {
        let mut addrs = Vec::new();
        if data.len() < 4 {
            return addrs;
        }

        let count = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let mut pos = 4;

        for _ in 0..count {
            if pos + 2 > data.len() {
                break;
            }
            let proto_type = data[pos];
            let proto_len = data[pos + 1] as usize;
            pos += 2 + proto_len;

            if pos + 2 > data.len() {
                break;
            }
            let addr_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if pos + addr_len > data.len() {
                break;
            }

            if proto_type == 1 && addr_len == 4 {
                // IPv4
                addrs.push(IpAddr::V4(std::net::Ipv4Addr::new(
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                )));
            }
            pos += addr_len;
        }

        addrs
    }

    /// Get device ID from TLVs
    pub fn device_id(&self) -> Option<&str> {
        for tlv in &self.tlvs {
            if let CdpTlv::DeviceId(id) = tlv {
                return Some(id);
            }
        }
        None
    }

    /// Get capabilities from TLVs
    pub fn capabilities(&self) -> Option<u32> {
        for tlv in &self.tlvs {
            if let CdpTlv::Capabilities(caps) = tlv {
                return Some(*caps);
            }
        }
        None
    }
}

// =============================================================================
// LLDP (Link Layer Discovery Protocol) - IEEE 802.1AB
// =============================================================================

/// LLDP TLV types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LldpTlvType {
    EndOfLldpdu,
    ChassisId,
    PortId,
    Ttl,
    PortDescription,
    SystemName,
    SystemDescription,
    SystemCapabilities,
    ManagementAddress,
    OrganizationSpecific,
    Unknown(u8),
}

impl LldpTlvType {
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::EndOfLldpdu => 0,
            Self::ChassisId => 1,
            Self::PortId => 2,
            Self::Ttl => 3,
            Self::PortDescription => 4,
            Self::SystemName => 5,
            Self::SystemDescription => 6,
            Self::SystemCapabilities => 7,
            Self::ManagementAddress => 8,
            Self::OrganizationSpecific => 127,
            Self::Unknown(v) => *v,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::EndOfLldpdu,
            1 => Self::ChassisId,
            2 => Self::PortId,
            3 => Self::Ttl,
            4 => Self::PortDescription,
            5 => Self::SystemName,
            6 => Self::SystemDescription,
            7 => Self::SystemCapabilities,
            8 => Self::ManagementAddress,
            127 => Self::OrganizationSpecific,
            _ => Self::Unknown(v),
        }
    }
}

/// LLDP TLV parsed value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LldpTlv {
    ChassisId { subtype: u8, value: Vec<u8> },
    PortId { subtype: u8, value: Vec<u8> },
    Ttl(u16),
    PortDescription(String),
    SystemName(String),
    SystemDescription(String),
    SystemCapabilities { capabilities: u16, enabled: u16 },
    ManagementAddress { addr_type: u8, addr: Vec<u8> },
    OrganizationSpecific { oui: [u8; 3], subtype: u8, data: Vec<u8> },
    EndOfLldpdu,
    Raw { tlv_type: u8, data: Vec<u8> },
}

/// Parsed LLDP packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldpPacket {
    pub tlvs: Vec<LldpTlv>,
}

impl LldpPacket {
    /// Parse LLDP packet from raw bytes (after Ethertype 0x88CC)
    pub fn parse(data: &[u8]) -> Option<Self> {
        let mut tlvs = Vec::new();
        let mut pos = 0;

        while pos + 2 <= data.len() {
            let header = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let tlv_type = (header >> 9) as u8;
            let tlv_len = (header & 0x01FF) as usize;
            pos += 2;

            if pos + tlv_len > data.len() {
                break;
            }

            let tlv_data = &data[pos..pos + tlv_len];
            let tlv = Self::parse_tlv(LldpTlvType::from_u8(tlv_type), tlv_data);

            let is_end = matches!(tlv, LldpTlv::EndOfLldpdu);
            tlvs.push(tlv);
            pos += tlv_len;

            if is_end {
                break;
            }
        }

        Some(Self { tlvs })
    }

    fn parse_tlv(tlv_type: LldpTlvType, data: &[u8]) -> LldpTlv {
        match tlv_type {
            LldpTlvType::EndOfLldpdu => LldpTlv::EndOfLldpdu,
            LldpTlvType::ChassisId => {
                if !data.is_empty() {
                    LldpTlv::ChassisId {
                        subtype: data[0],
                        value: data[1..].to_vec(),
                    }
                } else {
                    LldpTlv::Raw {
                        tlv_type: tlv_type.to_u8(),
                        data: data.to_vec(),
                    }
                }
            }
            LldpTlvType::PortId => {
                if !data.is_empty() {
                    LldpTlv::PortId {
                        subtype: data[0],
                        value: data[1..].to_vec(),
                    }
                } else {
                    LldpTlv::Raw {
                        tlv_type: tlv_type.to_u8(),
                        data: data.to_vec(),
                    }
                }
            }
            LldpTlvType::Ttl => {
                if data.len() >= 2 {
                    LldpTlv::Ttl(u16::from_be_bytes([data[0], data[1]]))
                } else {
                    LldpTlv::Raw {
                        tlv_type: tlv_type.to_u8(),
                        data: data.to_vec(),
                    }
                }
            }
            LldpTlvType::PortDescription => {
                LldpTlv::PortDescription(String::from_utf8_lossy(data).to_string())
            }
            LldpTlvType::SystemName => {
                LldpTlv::SystemName(String::from_utf8_lossy(data).to_string())
            }
            LldpTlvType::SystemDescription => {
                LldpTlv::SystemDescription(String::from_utf8_lossy(data).to_string())
            }
            LldpTlvType::SystemCapabilities => {
                if data.len() >= 4 {
                    LldpTlv::SystemCapabilities {
                        capabilities: u16::from_be_bytes([data[0], data[1]]),
                        enabled: u16::from_be_bytes([data[2], data[3]]),
                    }
                } else {
                    LldpTlv::Raw {
                        tlv_type: tlv_type.to_u8(),
                        data: data.to_vec(),
                    }
                }
            }
            LldpTlvType::ManagementAddress => {
                if data.len() >= 2 {
                    let addr_len = data[0] as usize;
                    if data.len() >= 1 + addr_len && addr_len >= 1 {
                        LldpTlv::ManagementAddress {
                            addr_type: data[1],
                            addr: data[2..1 + addr_len].to_vec(),
                        }
                    } else {
                        LldpTlv::Raw {
                            tlv_type: tlv_type.to_u8(),
                            data: data.to_vec(),
                        }
                    }
                } else {
                    LldpTlv::Raw {
                        tlv_type: tlv_type.to_u8(),
                        data: data.to_vec(),
                    }
                }
            }
            LldpTlvType::OrganizationSpecific => {
                if data.len() >= 4 {
                    LldpTlv::OrganizationSpecific {
                        oui: [data[0], data[1], data[2]],
                        subtype: data[3],
                        data: data[4..].to_vec(),
                    }
                } else {
                    LldpTlv::Raw {
                        tlv_type: tlv_type.to_u8(),
                        data: data.to_vec(),
                    }
                }
            }
            _ => LldpTlv::Raw {
                tlv_type: match tlv_type {
                    LldpTlvType::Unknown(v) => v,
                    _ => tlv_type.to_u8(),
                },
                data: data.to_vec(),
            },
        }
    }

    /// Get chassis ID as hex string
    pub fn chassis_id_string(&self) -> Option<String> {
        for tlv in &self.tlvs {
            if let LldpTlv::ChassisId { value, .. } = tlv {
                return Some(hex::encode(value));
            }
        }
        None
    }

    /// Get system name
    pub fn system_name(&self) -> Option<&str> {
        for tlv in &self.tlvs {
            if let LldpTlv::SystemName(name) = tlv {
                return Some(name);
            }
        }
        None
    }
}

// =============================================================================
// Discovery Protocol State Tracker
// =============================================================================

/// Discovery protocol spoofing alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverySpoofAlert {
    pub protocol: String, // "CDP" or "LLDP"
    pub device_id: String,
    pub claimed_ip: Option<String>,
    pub source_mac: String,
    pub reason: String,
    pub timestamp: u64,
}

/// Tracked device state
#[derive(Debug, Clone)]
struct DeviceState {
    device_id: String,
    source_mac: [u8; 6],
    addresses: Vec<IpAddr>,
    capabilities: Option<u32>,
    last_seen: Instant,
    packet_count: u32,
    is_known: bool,
}

/// Discovery protocol state tracker
#[derive(Debug)]
pub struct DiscoveryTracker {
    /// CDP devices (device_id -> state)
    cdp_devices: HashMap<String, DeviceState>,
    /// LLDP devices (chassis_id hex -> state)
    lldp_devices: HashMap<String, DeviceState>,
    /// Known/trusted device IDs
    known_devices: HashMap<String, [u8; 6]>, // device_id -> expected MAC
    /// Alert threshold for new devices
    new_device_alert: bool,
    /// Statistics
    cdp_packets: u64,
    lldp_packets: u64,
}

impl Default for DiscoveryTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryTracker {
    pub fn new() -> Self {
        Self {
            cdp_devices: HashMap::new(),
            lldp_devices: HashMap::new(),
            known_devices: HashMap::new(),
            new_device_alert: true,
            cdp_packets: 0,
            lldp_packets: 0,
        }
    }

    /// Add a known device
    pub fn add_known_device(&mut self, device_id: &str, mac: [u8; 6]) {
        self.known_devices.insert(device_id.to_string(), mac);
    }

    /// Configure new device alerting
    pub fn set_new_device_alert(&mut self, alert: bool) {
        self.new_device_alert = alert;
    }

    /// Process a CDP packet
    pub fn process_cdp(&mut self, packet: &CdpPacket, source_mac: [u8; 6]) -> Vec<DiscoverySpoofAlert> {
        let mut alerts = Vec::new();
        self.cdp_packets += 1;
        let now = Instant::now();

        let device_id = packet.device_id().unwrap_or("unknown").to_string();
        let mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            source_mac[0], source_mac[1], source_mac[2],
            source_mac[3], source_mac[4], source_mac[5]
        );

        // Check for MAC spoofing on known device
        if let Some(expected_mac) = self.known_devices.get(&device_id) {
            if *expected_mac != source_mac {
                alerts.push(DiscoverySpoofAlert {
                    protocol: "CDP".to_string(),
                    device_id: device_id.clone(),
                    claimed_ip: None,
                    source_mac: mac_str.clone(),
                    reason: format!(
                        "Device ID '{}' seen from unexpected MAC (expected {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
                        device_id,
                        expected_mac[0], expected_mac[1], expected_mac[2],
                        expected_mac[3], expected_mac[4], expected_mac[5]
                    ),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                });
            }
        }

        // Check for capability/address changes
        if let Some(state) = self.cdp_devices.get(&device_id) {
            // Check for capability change
            if let Some(caps) = packet.capabilities() {
                if let Some(old_caps) = state.capabilities {
                    if caps != old_caps {
                        alerts.push(DiscoverySpoofAlert {
                            protocol: "CDP".to_string(),
                            device_id: device_id.clone(),
                            claimed_ip: None,
                            source_mac: mac_str.clone(),
                            reason: format!(
                                "Capabilities changed from 0x{:08x} to 0x{:08x}",
                                old_caps, caps
                            ),
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0),
                        });
                    }
                }
            }
        } else if self.new_device_alert && !self.known_devices.contains_key(&device_id) {
            // New unknown device
            alerts.push(DiscoverySpoofAlert {
                protocol: "CDP".to_string(),
                device_id: device_id.clone(),
                claimed_ip: None,
                source_mac: mac_str,
                reason: "New device discovered".to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            });
        }

        // Update state
        let addresses = packet.tlvs.iter().filter_map(|tlv| {
            if let CdpTlv::Addresses(addrs) | CdpTlv::ManagementAddress(addrs) = tlv {
                Some(addrs.clone())
            } else {
                None
            }
        }).flatten().collect();

        // Get packet count before inserting
        let packet_count = self.cdp_devices.get(&device_id)
            .map(|s| s.packet_count + 1)
            .unwrap_or(1);
        let is_known = self.known_devices.contains_key(&device_id);

        self.cdp_devices.insert(
            device_id.clone(),
            DeviceState {
                device_id,
                source_mac,
                addresses,
                capabilities: packet.capabilities(),
                last_seen: now,
                packet_count,
                is_known,
            },
        );

        alerts
    }

    /// Process an LLDP packet
    pub fn process_lldp(&mut self, packet: &LldpPacket, source_mac: [u8; 6]) -> Vec<DiscoverySpoofAlert> {
        let mut alerts = Vec::new();
        self.lldp_packets += 1;
        let now = Instant::now();

        let chassis_id = packet.chassis_id_string().unwrap_or_else(|| "unknown".to_string());
        let system_name = packet.system_name().unwrap_or("unknown").to_string();
        let mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            source_mac[0], source_mac[1], source_mac[2],
            source_mac[3], source_mac[4], source_mac[5]
        );

        // Check for MAC spoofing on known device
        if let Some(expected_mac) = self.known_devices.get(&system_name) {
            if *expected_mac != source_mac {
                alerts.push(DiscoverySpoofAlert {
                    protocol: "LLDP".to_string(),
                    device_id: system_name.clone(),
                    claimed_ip: None,
                    source_mac: mac_str.clone(),
                    reason: format!(
                        "System name '{}' seen from unexpected MAC",
                        system_name
                    ),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                });
            }
        }

        // Track new devices
        if !self.lldp_devices.contains_key(&chassis_id) && self.new_device_alert
            && !self.known_devices.contains_key(&system_name)
        {
            alerts.push(DiscoverySpoofAlert {
                protocol: "LLDP".to_string(),
                device_id: system_name.clone(),
                claimed_ip: None,
                source_mac: mac_str,
                reason: format!("New LLDP device discovered (chassis: {})", chassis_id),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
            });
        }

        // Update state
        self.lldp_devices.insert(
            chassis_id.clone(),
            DeviceState {
                device_id: system_name,
                source_mac,
                addresses: Vec::new(),
                capabilities: None,
                last_seen: now,
                packet_count: self.lldp_devices.get(&chassis_id)
                    .map(|s| s.packet_count + 1)
                    .unwrap_or(1),
                is_known: false,
            },
        );

        alerts
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, usize, usize) {
        (
            self.cdp_packets,
            self.lldp_packets,
            self.cdp_devices.len(),
            self.lldp_devices.len(),
        )
    }

    /// Cleanup old entries
    pub fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.cdp_devices.retain(|_, state| {
            state.is_known || now.duration_since(state.last_seen) < max_age
        });
        self.lldp_devices.retain(|_, state| {
            state.is_known || now.duration_since(state.last_seen) < max_age
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cdp_parse() {
        // Minimal CDP packet
        let data = [
            0x02,       // Version
            0x1e,       // TTL (30 seconds)
            0x00, 0x00, // Checksum (placeholder)
            // Device ID TLV
            0x00, 0x01, // Type
            0x00, 0x08, // Length (including header)
            0x54, 0x65, 0x73, 0x74, // "Test"
        ];

        let packet = CdpPacket::parse(&data).unwrap();
        assert_eq!(packet.version, 2);
        assert_eq!(packet.ttl, 30);
        assert_eq!(packet.device_id(), Some("Test"));
    }

    #[test]
    fn test_lldp_parse() {
        // Minimal LLDP packet
        let data = [
            // Chassis ID TLV (type 1, len 7)
            0x02, 0x07, // header: type=1, len=7
            0x04, // subtype: MAC address
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // MAC
            // Port ID TLV (type 2, len 4)
            0x04, 0x04, // header: type=2, len=4
            0x05, // subtype: interface name
            0x65, 0x74, 0x68, // "eth"
            // TTL TLV (type 3, len 2)
            0x06, 0x02, // header: type=3, len=2
            0x00, 0x78, // 120 seconds
            // End TLV
            0x00, 0x00,
        ];

        let packet = LldpPacket::parse(&data).unwrap();
        assert_eq!(packet.tlvs.len(), 4);
        assert!(matches!(packet.tlvs[0], LldpTlv::ChassisId { .. }));
    }

    #[test]
    fn test_discovery_spoof_detection() {
        let mut tracker = DiscoveryTracker::new();
        tracker.add_known_device("switch1", [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // Spoofed packet from wrong MAC
        let packet = CdpPacket {
            version: 2,
            ttl: 30,
            checksum: 0,
            tlvs: vec![CdpTlv::DeviceId("switch1".to_string())],
        };

        let alerts = tracker.process_cdp(&packet, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert!(!alerts.is_empty());
        assert!(alerts[0].reason.contains("unexpected MAC"));
    }
}
