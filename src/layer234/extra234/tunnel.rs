//! GRE and VXLAN Tunnel Detection
//!
//! Detects unauthorized tunnel traffic:
//! - GRE tunnels (IP protocol 47)
//! - VXLAN overlays (UDP port 4789)
//! - VNI enumeration attempts
//! - Tunnels to external/unauthorized endpoints

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

// =============================================================================
// GRE (Generic Routing Encapsulation) - IP Protocol 47
// =============================================================================

/// GRE protocol types (inner protocol)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GreProtocol {
    Ipv4,
    Ipv6,
    Erspan,     // ERSPAN Type II
    ErspanIii,  // ERSPAN Type III
    Ppp,        // PPP (PPTP)
    Mpls,
    Ethernet,   // Transparent Ethernet Bridging
    Unknown(u16),
}

impl GreProtocol {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x0800 => Self::Ipv4,
            0x86DD => Self::Ipv6,
            0x88BE => Self::Erspan,
            0x22EB => Self::ErspanIii,
            0x880B => Self::Ppp,
            0x8847 => Self::Mpls,
            0x6558 => Self::Ethernet,
            _ => Self::Unknown(v),
        }
    }
}

/// Parsed GRE header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreHeader {
    pub checksum_present: bool,
    pub key_present: bool,
    pub sequence_present: bool,
    pub version: u8,
    pub protocol_type: GreProtocol,
    pub checksum: Option<u16>,
    pub key: Option<u32>,
    pub sequence: Option<u32>,
    pub header_len: usize,
}

impl GreHeader {
    /// Parse GRE header from raw IP payload (protocol 47)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let flags = u16::from_be_bytes([data[0], data[1]]);
        let checksum_present = (flags & 0x8000) != 0;
        let key_present = (flags & 0x2000) != 0;
        let sequence_present = (flags & 0x1000) != 0;
        let version = (flags & 0x0007) as u8;

        let protocol_type = GreProtocol::from_u16(u16::from_be_bytes([data[2], data[3]]));

        let mut offset = 4;
        let mut checksum = None;
        let mut key = None;
        let mut sequence = None;

        // Checksum and Reserved (4 bytes if C bit set)
        if checksum_present {
            if data.len() < offset + 4 {
                return None;
            }
            checksum = Some(u16::from_be_bytes([data[offset], data[offset + 1]]));
            offset += 4;
        }

        // Key (4 bytes if K bit set)
        if key_present {
            if data.len() < offset + 4 {
                return None;
            }
            key = Some(u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]));
            offset += 4;
        }

        // Sequence (4 bytes if S bit set)
        if sequence_present {
            if data.len() < offset + 4 {
                return None;
            }
            sequence = Some(u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]));
            offset += 4;
        }

        Some(Self {
            checksum_present,
            key_present,
            sequence_present,
            version,
            protocol_type,
            checksum,
            key,
            sequence,
            header_len: offset,
        })
    }
}

// =============================================================================
// VXLAN (Virtual Extensible LAN) - UDP 4789
// =============================================================================

/// Parsed VXLAN header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VxlanHeader {
    pub flags: u8,
    pub vni: u32,      // 24-bit Virtual Network Identifier
    pub reserved1: u32, // 24 bits + 8 bits
    pub reserved2: u8,
}

impl VxlanHeader {
    /// Parse VXLAN header from UDP payload (port 4789)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let flags = data[0];
        // Check I bit (bit 3, 0x08) - must be set for valid VXLAN
        if (flags & 0x08) == 0 {
            return None;
        }

        let reserved1 = u32::from_be_bytes([0, data[1], data[2], data[3]]);
        let vni = u32::from_be_bytes([0, data[4], data[5], data[6]]);
        let reserved2 = data[7];

        Some(Self {
            flags,
            vni,
            reserved1,
            reserved2,
        })
    }
}

// =============================================================================
// Tunnel Attack Detection
// =============================================================================

/// Tunnel detection alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelAlert {
    pub tunnel_type: TunnelType,
    pub src_ip: String,
    pub dst_ip: String,
    pub inner_protocol: Option<String>,
    pub key_or_vni: Option<u32>,
    pub reason: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TunnelType {
    Gre,
    Vxlan,
    Geneve,      // Future: UDP 6081
    IpInIp,      // Future: IP protocol 4
}

/// Tracked tunnel endpoint
#[derive(Debug, Clone)]
struct TunnelEndpoint {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    tunnel_type: TunnelType,
    keys_or_vnis: HashSet<u32>,
    last_seen: Instant,
    packet_count: u64,
    byte_count: u64,
    is_authorized: bool,
}

/// Tunnel traffic tracker
#[derive(Debug)]
pub struct TunnelTracker {
    /// Active tunnel endpoints (src_ip:dst_ip -> state)
    tunnels: HashMap<(IpAddr, IpAddr), TunnelEndpoint>,
    /// Authorized tunnel endpoints (external IPs)
    authorized_endpoints: HashSet<IpAddr>,
    /// Authorized VNIs (for VXLAN)
    authorized_vnis: HashSet<u32>,
    /// Authorized GRE keys
    authorized_keys: HashSet<u32>,
    /// Internal networks (tunnels to external are suspicious)
    internal_networks: Vec<(IpAddr, u8)>, // (network, prefix_len)
    /// VNI enumeration threshold
    vni_enum_threshold: usize,
    /// Statistics
    gre_packets: u64,
    vxlan_packets: u64,
}

impl Default for TunnelTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelTracker {
    pub fn new() -> Self {
        Self {
            tunnels: HashMap::new(),
            authorized_endpoints: HashSet::new(),
            authorized_vnis: HashSet::new(),
            authorized_keys: HashSet::new(),
            internal_networks: Vec::new(),
            vni_enum_threshold: 10,
            gre_packets: 0,
            vxlan_packets: 0,
        }
    }

    /// Add an authorized tunnel endpoint
    pub fn add_authorized_endpoint(&mut self, ip: IpAddr) {
        self.authorized_endpoints.insert(ip);
    }

    /// Add an authorized VNI
    pub fn add_authorized_vni(&mut self, vni: u32) {
        self.authorized_vnis.insert(vni);
    }

    /// Add an authorized GRE key
    pub fn add_authorized_key(&mut self, key: u32) {
        self.authorized_keys.insert(key);
    }

    /// Add an internal network (for detecting external tunnels)
    pub fn add_internal_network(&mut self, network: IpAddr, prefix_len: u8) {
        self.internal_networks.push((network, prefix_len));
    }

    /// Check if an IP is internal
    fn is_internal(&self, ip: &IpAddr) -> bool {
        if self.internal_networks.is_empty() {
            return true; // If no networks defined, assume all internal
        }

        for (network, prefix_len) in &self.internal_networks {
            match (network, ip) {
                (IpAddr::V4(net), IpAddr::V4(addr)) => {
                    let net_bits = u32::from_be_bytes(net.octets());
                    let addr_bits = u32::from_be_bytes(addr.octets());
                    let mask = !0u32 << (32 - prefix_len);
                    if (net_bits & mask) == (addr_bits & mask) {
                        return true;
                    }
                }
                (IpAddr::V6(net), IpAddr::V6(addr)) => {
                    let net_bits = u128::from_be_bytes(net.octets());
                    let addr_bits = u128::from_be_bytes(addr.octets());
                    let mask = !0u128 << (128 - prefix_len);
                    if (net_bits & mask) == (addr_bits & mask) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Process a GRE packet
    pub fn process_gre(
        &mut self,
        header: &GreHeader,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        packet_len: usize,
    ) -> Vec<TunnelAlert> {
        let mut alerts = Vec::new();
        self.gre_packets += 1;
        let now = Instant::now();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let key = (src_ip, dst_ip);
        let gre_key = header.key;

        // Check for unauthorized endpoint
        if !self.authorized_endpoints.is_empty()
            && !self.authorized_endpoints.contains(&dst_ip)
            && !self.is_internal(&dst_ip)
        {
            alerts.push(TunnelAlert {
                tunnel_type: TunnelType::Gre,
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                inner_protocol: Some(format!("{:?}", header.protocol_type)),
                key_or_vni: gre_key,
                reason: "GRE tunnel to unauthorized external endpoint".to_string(),
                timestamp,
            });
        }

        // Check for unauthorized GRE key
        if let Some(k) = gre_key {
            if !self.authorized_keys.is_empty() && !self.authorized_keys.contains(&k) {
                alerts.push(TunnelAlert {
                    tunnel_type: TunnelType::Gre,
                    src_ip: src_ip.to_string(),
                    dst_ip: dst_ip.to_string(),
                    inner_protocol: Some(format!("{:?}", header.protocol_type)),
                    key_or_vni: Some(k),
                    reason: format!("Unauthorized GRE key: 0x{:08x}", k),
                    timestamp,
                });
            }
        }

        // Update tunnel state
        if let Some(state) = self.tunnels.get_mut(&key) {
            state.last_seen = now;
            state.packet_count += 1;
            state.byte_count += packet_len as u64;
            if let Some(k) = gre_key {
                state.keys_or_vnis.insert(k);
            }
        } else {
            let mut keys = HashSet::new();
            if let Some(k) = gre_key {
                keys.insert(k);
            }
            self.tunnels.insert(
                key,
                TunnelEndpoint {
                    src_ip,
                    dst_ip,
                    tunnel_type: TunnelType::Gre,
                    keys_or_vnis: keys,
                    last_seen: now,
                    packet_count: 1,
                    byte_count: packet_len as u64,
                    is_authorized: self.authorized_endpoints.contains(&dst_ip),
                },
            );
        }

        alerts
    }

    /// Process a VXLAN packet
    pub fn process_vxlan(
        &mut self,
        header: &VxlanHeader,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        packet_len: usize,
    ) -> Vec<TunnelAlert> {
        let mut alerts = Vec::new();
        self.vxlan_packets += 1;
        let now = Instant::now();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let key = (src_ip, dst_ip);
        let vni = header.vni;

        // Check for unauthorized VNI
        if !self.authorized_vnis.is_empty() && !self.authorized_vnis.contains(&vni) {
            alerts.push(TunnelAlert {
                tunnel_type: TunnelType::Vxlan,
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                inner_protocol: None,
                key_or_vni: Some(vni),
                reason: format!("Unauthorized VNI: {}", vni),
                timestamp,
            });
        }

        // Check for unauthorized endpoint
        if !self.authorized_endpoints.is_empty()
            && !self.authorized_endpoints.contains(&dst_ip)
            && !self.is_internal(&dst_ip)
        {
            alerts.push(TunnelAlert {
                tunnel_type: TunnelType::Vxlan,
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                inner_protocol: None,
                key_or_vni: Some(vni),
                reason: "VXLAN tunnel to unauthorized external endpoint".to_string(),
                timestamp,
            });
        }

        // Update tunnel state
        if let Some(state) = self.tunnels.get_mut(&key) {
            state.last_seen = now;
            state.packet_count += 1;
            state.byte_count += packet_len as u64;
            state.keys_or_vnis.insert(vni);
        } else {
            let mut vnis = HashSet::new();
            vnis.insert(vni);
            self.tunnels.insert(
                key,
                TunnelEndpoint {
                    src_ip,
                    dst_ip,
                    tunnel_type: TunnelType::Vxlan,
                    keys_or_vnis: vnis,
                    last_seen: now,
                    packet_count: 1,
                    byte_count: packet_len as u64,
                    is_authorized: self.authorized_endpoints.contains(&dst_ip),
                },
            );
        }

        alerts
    }

    /// Check for VNI enumeration attempts
    pub fn check_vni_enumeration(&self) -> Vec<TunnelAlert> {
        let mut alerts = Vec::new();

        for ((src, dst), state) in &self.tunnels {
            if matches!(state.tunnel_type, TunnelType::Vxlan)
                && state.keys_or_vnis.len() > self.vni_enum_threshold
            {
                alerts.push(TunnelAlert {
                    tunnel_type: TunnelType::Vxlan,
                    src_ip: src.to_string(),
                    dst_ip: dst.to_string(),
                    inner_protocol: None,
                    key_or_vni: None,
                    reason: format!(
                        "VNI enumeration detected: {} unique VNIs",
                        state.keys_or_vnis.len()
                    ),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                });
            }
        }

        alerts
    }

    /// Get all active tunnels
    pub fn active_tunnels(&self) -> Vec<((IpAddr, IpAddr), TunnelType, u64)> {
        self.tunnels
            .iter()
            .map(|(k, v)| (*k, v.tunnel_type.clone(), v.packet_count))
            .collect()
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, usize) {
        (self.gre_packets, self.vxlan_packets, self.tunnels.len())
    }

    /// Cleanup old tunnel entries
    pub fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.tunnels.retain(|_, state| {
            state.is_authorized || now.duration_since(state.last_seen) < max_age
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gre_parse() {
        // Simple GRE header with IPv4 payload
        let data = [
            0x00, 0x00, // Flags (no C, K, S)
            0x08, 0x00, // Protocol = IPv4
        ];

        let header = GreHeader::parse(&data).unwrap();
        assert!(!header.checksum_present);
        assert!(!header.key_present);
        assert!(!header.sequence_present);
        assert_eq!(header.protocol_type, GreProtocol::Ipv4);
        assert_eq!(header.header_len, 4);
    }

    #[test]
    fn test_gre_with_key() {
        // GRE header with key
        let data = [
            0x20, 0x00, // Flags (K bit set)
            0x08, 0x00, // Protocol = IPv4
            0x00, 0x00, 0x01, 0x23, // Key = 0x123
        ];

        let header = GreHeader::parse(&data).unwrap();
        assert!(header.key_present);
        assert_eq!(header.key, Some(0x123));
        assert_eq!(header.header_len, 8);
    }

    #[test]
    fn test_vxlan_parse() {
        let data = [
            0x08,             // Flags (I bit set)
            0x00, 0x00, 0x00, // Reserved
            0x00, 0x12, 0x34, // VNI = 0x1234
            0x00,             // Reserved
        ];

        let header = VxlanHeader::parse(&data).unwrap();
        assert_eq!(header.vni, 0x1234);
    }

    #[test]
    fn test_unauthorized_tunnel_detection() {
        let mut tracker = TunnelTracker::new();
        tracker.add_authorized_endpoint(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
        tracker.add_internal_network(
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 0)),
            8,
        );

        // GRE to external unauthorized endpoint
        let header = GreHeader {
            checksum_present: false,
            key_present: false,
            sequence_present: false,
            version: 0,
            protocol_type: GreProtocol::Ipv4,
            checksum: None,
            key: None,
            sequence: None,
            header_len: 4,
        };

        let alerts = tracker.process_gre(
            &header,
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 100)),
            IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), // External!
            100,
        );

        assert!(!alerts.is_empty());
        assert!(alerts[0].reason.contains("unauthorized"));
    }

    #[test]
    fn test_vni_enumeration_detection() {
        let mut tracker = TunnelTracker::new();
        tracker.vni_enum_threshold = 5;

        let src = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

        // Send packets with many different VNIs
        for vni in 0..10 {
            let header = VxlanHeader {
                flags: 0x08,
                vni,
                reserved1: 0,
                reserved2: 0,
            };
            tracker.process_vxlan(&header, src, dst, 100);
        }

        let alerts = tracker.check_vni_enumeration();
        assert!(!alerts.is_empty());
        assert!(alerts[0].reason.contains("enumeration"));
    }
}
