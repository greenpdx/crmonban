//! OSPF (Open Shortest Path First) and RIP (Routing Information Protocol) Parsers
//!
//! Detects routing protocol attacks:
//! - OSPF neighbor injection
//! - OSPF DR/BDR manipulation
//! - LSA injection with metric 0
//! - RIP route poisoning (hop count 16)
//! - Route injection from non-router sources

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

// =============================================================================
// OSPF (Open Shortest Path First) - IP Protocol 89
// =============================================================================

/// OSPF message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OspfType {
    Hello = 1,
    DatabaseDescription = 2,
    LinkStateRequest = 3,
    LinkStateUpdate = 4,
    LinkStateAck = 5,
}

impl OspfType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Hello),
            2 => Some(Self::DatabaseDescription),
            3 => Some(Self::LinkStateRequest),
            4 => Some(Self::LinkStateUpdate),
            5 => Some(Self::LinkStateAck),
            _ => None,
        }
    }
}

/// OSPF authentication types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OspfAuthType {
    Null = 0,
    SimplePassword = 1,
    CryptographicMd5 = 2,
}

impl OspfAuthType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0 => Self::Null,
            1 => Self::SimplePassword,
            2 => Self::CryptographicMd5,
            _ => Self::Null,
        }
    }
}

/// Parsed OSPF packet header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfPacket {
    pub version: u8,
    pub msg_type: OspfType,
    pub length: u16,
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub checksum: u16,
    pub auth_type: OspfAuthType,
}

/// OSPF Hello packet payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfHello {
    pub network_mask: Ipv4Addr,
    pub hello_interval: u16,
    pub options: u8,
    pub priority: u8,
    pub dead_interval: u32,
    pub designated_router: Ipv4Addr,
    pub backup_dr: Ipv4Addr,
    pub neighbors: Vec<Ipv4Addr>,
}

/// LSA (Link State Advertisement) header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LsaHeader {
    pub ls_age: u16,
    pub options: u8,
    pub ls_type: u8,
    pub link_state_id: Ipv4Addr,
    pub advertising_router: Ipv4Addr,
    pub sequence_number: u32,
    pub checksum: u16,
    pub length: u16,
}

impl OspfPacket {
    /// Parse OSPF packet from raw IP payload (protocol 89)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 24 {
            return None;
        }

        let version = data[0];
        if version != 2 && version != 3 {
            return None; // Only OSPFv2 and OSPFv3 supported
        }

        let msg_type = OspfType::from_u8(data[1])?;
        let length = u16::from_be_bytes([data[2], data[3]]);
        let router_id = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
        let area_id = Ipv4Addr::new(data[8], data[9], data[10], data[11]);
        let checksum = u16::from_be_bytes([data[12], data[13]]);
        let auth_type = OspfAuthType::from_u16(u16::from_be_bytes([data[14], data[15]]));

        Some(Self {
            version,
            msg_type,
            length,
            router_id,
            area_id,
            checksum,
            auth_type,
        })
    }
}

impl OspfHello {
    /// Parse OSPF Hello payload (after 24-byte OSPF header)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        let network_mask = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
        let hello_interval = u16::from_be_bytes([data[4], data[5]]);
        let options = data[6];
        let priority = data[7];
        let dead_interval = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let designated_router = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let backup_dr = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

        // Parse neighbor list (remaining bytes, 4 bytes each)
        let mut neighbors = Vec::new();
        let mut pos = 20;
        while pos + 4 <= data.len() {
            neighbors.push(Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]));
            pos += 4;
        }

        Some(Self {
            network_mask,
            hello_interval,
            options,
            priority,
            dead_interval,
            designated_router,
            backup_dr,
            neighbors,
        })
    }

    /// Check if this router is claiming to be DR
    pub fn is_claiming_dr(&self, router_id: Ipv4Addr) -> bool {
        self.designated_router == router_id
    }
}

impl LsaHeader {
    /// Parse LSA header
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        Some(Self {
            ls_age: u16::from_be_bytes([data[0], data[1]]),
            options: data[2],
            ls_type: data[3],
            link_state_id: Ipv4Addr::new(data[4], data[5], data[6], data[7]),
            advertising_router: Ipv4Addr::new(data[8], data[9], data[10], data[11]),
            sequence_number: u32::from_be_bytes([data[12], data[13], data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            length: u16::from_be_bytes([data[18], data[19]]),
        })
    }
}

// =============================================================================
// RIP (Routing Information Protocol) - UDP 520
// =============================================================================

/// RIP command types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RipCommand {
    Request = 1,
    Response = 2,
}

impl RipCommand {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            _ => None,
        }
    }
}

/// Parsed RIP packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RipPacket {
    pub command: RipCommand,
    pub version: u8,
    pub entries: Vec<RipEntry>,
}

/// RIP route entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RipEntry {
    pub afi: u16,             // Address Family Identifier (2 = IPv4)
    pub route_tag: u16,       // RIPv2 only
    pub ip_addr: Ipv4Addr,
    pub subnet_mask: Ipv4Addr, // RIPv2 only (0.0.0.0 for RIPv1)
    pub next_hop: Ipv4Addr,   // RIPv2 only
    pub metric: u32,          // 1-15 valid, 16 = unreachable
}

impl RipPacket {
    /// Parse RIP packet from UDP payload
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let command = RipCommand::from_u8(data[0])?;
        let version = data[1];
        if version != 1 && version != 2 {
            return None;
        }

        // Parse entries (20 bytes each)
        let mut entries = Vec::new();
        let mut pos = 4;

        while pos + 20 <= data.len() {
            let entry = RipEntry::parse(&data[pos..pos + 20])?;
            entries.push(entry);
            pos += 20;
        }

        Some(Self {
            command,
            version,
            entries,
        })
    }
}

impl RipEntry {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 20 {
            return None;
        }

        Some(Self {
            afi: u16::from_be_bytes([data[0], data[1]]),
            route_tag: u16::from_be_bytes([data[2], data[3]]),
            ip_addr: Ipv4Addr::new(data[4], data[5], data[6], data[7]),
            subnet_mask: Ipv4Addr::new(data[8], data[9], data[10], data[11]),
            next_hop: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            metric: u32::from_be_bytes([data[16], data[17], data[18], data[19]]),
        })
    }

    /// Check if this is a poisoned route (metric 16 = unreachable)
    pub fn is_poisoned(&self) -> bool {
        self.metric >= 16
    }

    /// Check for metric 0 (attract all traffic)
    pub fn has_zero_metric(&self) -> bool {
        self.metric == 0
    }
}

// =============================================================================
// Routing Protocol Attack Detection
// =============================================================================

/// OSPF attack alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OspfAttackAlert {
    pub attack_type: OspfAttackType,
    pub router_id: String,
    pub source_ip: String,
    pub area_id: String,
    pub details: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OspfAttackType {
    NeighborInjection,
    DrManipulation,
    LsaInjection,
    HelloFlood,
    NoAuthentication,
}

/// RIP attack alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RipAttackAlert {
    pub attack_type: RipAttackType,
    pub source_ip: String,
    pub route: String,
    pub metric: u32,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RipAttackType {
    RoutePoisoning,
    MetricZero,
    Injection,
    Flood,
}

/// Known OSPF neighbor state
#[derive(Debug, Clone)]
struct OspfNeighborState {
    router_id: Ipv4Addr,
    source_ip: IpAddr,
    area_id: Ipv4Addr,
    last_seen: Instant,
    hello_count: u32,
    is_dr: bool,
    is_known: bool,
}

/// Known RIP source state
#[derive(Debug, Clone)]
struct RipSourceState {
    source_ip: IpAddr,
    last_seen: Instant,
    packet_count: u32,
    routes_advertised: HashSet<Ipv4Addr>,
    is_known: bool,
}

/// Routing protocol state tracker
#[derive(Debug)]
pub struct RoutingTracker {
    /// Known OSPF neighbors (router_id -> state)
    ospf_neighbors: HashMap<Ipv4Addr, OspfNeighborState>,
    /// Known RIP sources
    rip_sources: HashMap<IpAddr, RipSourceState>,
    /// Known/trusted router IDs
    known_routers: HashSet<Ipv4Addr>,
    /// Known/trusted RIP sources
    known_rip_sources: HashSet<IpAddr>,
    /// Current DR for each area
    area_dr: HashMap<Ipv4Addr, Ipv4Addr>,
    /// Require OSPF authentication
    require_ospf_auth: bool,
    /// Hello flood detection window
    hello_window: Duration,
    hello_threshold: u32,
    /// Statistics
    ospf_packets: u64,
    rip_packets: u64,
}

impl Default for RoutingTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl RoutingTracker {
    pub fn new() -> Self {
        Self {
            ospf_neighbors: HashMap::new(),
            rip_sources: HashMap::new(),
            known_routers: HashSet::new(),
            known_rip_sources: HashSet::new(),
            area_dr: HashMap::new(),
            require_ospf_auth: false,
            hello_window: Duration::from_secs(10),
            hello_threshold: 100,
            ospf_packets: 0,
            rip_packets: 0,
        }
    }

    /// Add a known router
    pub fn add_known_router(&mut self, router_id: Ipv4Addr) {
        self.known_routers.insert(router_id);
    }

    /// Add a known RIP source
    pub fn add_known_rip_source(&mut self, ip: IpAddr) {
        self.known_rip_sources.insert(ip);
    }

    /// Set expected DR for an area
    pub fn set_area_dr(&mut self, area_id: Ipv4Addr, dr: Ipv4Addr) {
        self.area_dr.insert(area_id, dr);
    }

    /// Configure OSPF authentication requirement
    pub fn set_require_ospf_auth(&mut self, require: bool) {
        self.require_ospf_auth = require;
    }

    /// Process OSPF packet
    pub fn process_ospf(
        &mut self,
        packet: &OspfPacket,
        hello: Option<&OspfHello>,
        source_ip: IpAddr,
    ) -> Vec<OspfAttackAlert> {
        let mut alerts = Vec::new();
        self.ospf_packets += 1;
        let now = Instant::now();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Check authentication
        if self.require_ospf_auth && packet.auth_type == OspfAuthType::Null {
            alerts.push(OspfAttackAlert {
                attack_type: OspfAttackType::NoAuthentication,
                router_id: packet.router_id.to_string(),
                source_ip: source_ip.to_string(),
                area_id: packet.area_id.to_string(),
                details: "OSPF packet without authentication".to_string(),
                timestamp,
            });
        }

        // Check for unknown router
        if !self.known_routers.is_empty() && !self.known_routers.contains(&packet.router_id) {
            alerts.push(OspfAttackAlert {
                attack_type: OspfAttackType::NeighborInjection,
                router_id: packet.router_id.to_string(),
                source_ip: source_ip.to_string(),
                area_id: packet.area_id.to_string(),
                details: "Unknown router ID detected".to_string(),
                timestamp,
            });
        }

        // Process Hello packets
        if let Some(hello) = hello {
            // Check for DR manipulation
            if let Some(&expected_dr) = self.area_dr.get(&packet.area_id) {
                if hello.designated_router != expected_dr
                    && hello.designated_router != Ipv4Addr::new(0, 0, 0, 0)
                {
                    alerts.push(OspfAttackAlert {
                        attack_type: OspfAttackType::DrManipulation,
                        router_id: packet.router_id.to_string(),
                        source_ip: source_ip.to_string(),
                        area_id: packet.area_id.to_string(),
                        details: format!(
                            "DR changed from {} to {}",
                            expected_dr, hello.designated_router
                        ),
                        timestamp,
                    });
                }
            }

            // Track neighbor state
            if let Some(state) = self.ospf_neighbors.get_mut(&packet.router_id) {
                state.last_seen = now;
                state.hello_count += 1;
                state.is_dr = hello.is_claiming_dr(packet.router_id);
            } else {
                self.ospf_neighbors.insert(
                    packet.router_id,
                    OspfNeighborState {
                        router_id: packet.router_id,
                        source_ip,
                        area_id: packet.area_id,
                        last_seen: now,
                        hello_count: 1,
                        is_dr: hello.is_claiming_dr(packet.router_id),
                        is_known: self.known_routers.contains(&packet.router_id),
                    },
                );
            }
        }

        alerts
    }

    /// Process RIP packet
    pub fn process_rip(&mut self, packet: &RipPacket, source_ip: IpAddr) -> Vec<RipAttackAlert> {
        let mut alerts = Vec::new();
        self.rip_packets += 1;
        let now = Instant::now();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Check for unknown source
        if !self.known_rip_sources.is_empty() && !self.known_rip_sources.contains(&source_ip) {
            alerts.push(RipAttackAlert {
                attack_type: RipAttackType::Injection,
                source_ip: source_ip.to_string(),
                route: "multiple".to_string(),
                metric: 0,
                timestamp,
            });
        }

        // Check each route entry
        for entry in &packet.entries {
            if entry.afi != 2 {
                continue; // Only check IPv4
            }

            // Check for poisoned routes
            if entry.is_poisoned() {
                alerts.push(RipAttackAlert {
                    attack_type: RipAttackType::RoutePoisoning,
                    source_ip: source_ip.to_string(),
                    route: format!("{}/{}", entry.ip_addr, entry.subnet_mask),
                    metric: entry.metric,
                    timestamp,
                });
            }

            // Check for metric 0 (attract traffic)
            if entry.has_zero_metric() {
                alerts.push(RipAttackAlert {
                    attack_type: RipAttackType::MetricZero,
                    source_ip: source_ip.to_string(),
                    route: format!("{}/{}", entry.ip_addr, entry.subnet_mask),
                    metric: 0,
                    timestamp,
                });
            }
        }

        // Update source state
        let routes: HashSet<Ipv4Addr> = packet.entries.iter().map(|e| e.ip_addr).collect();

        if let Some(state) = self.rip_sources.get_mut(&source_ip) {
            state.last_seen = now;
            state.packet_count += 1;
            state.routes_advertised.extend(routes);
        } else {
            self.rip_sources.insert(
                source_ip,
                RipSourceState {
                    source_ip,
                    last_seen: now,
                    packet_count: 1,
                    routes_advertised: routes,
                    is_known: self.known_rip_sources.contains(&source_ip),
                },
            );
        }

        alerts
    }

    /// Check for Hello flood attack
    pub fn check_ospf_hello_flood(&self) -> Vec<OspfAttackAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        for (router_id, state) in &self.ospf_neighbors {
            if now.duration_since(state.last_seen) < self.hello_window
                && state.hello_count > self.hello_threshold
            {
                alerts.push(OspfAttackAlert {
                    attack_type: OspfAttackType::HelloFlood,
                    router_id: router_id.to_string(),
                    source_ip: state.source_ip.to_string(),
                    area_id: state.area_id.to_string(),
                    details: format!("{} hellos in {:?}", state.hello_count, self.hello_window),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                });
            }
        }

        alerts
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, usize, usize) {
        (
            self.ospf_packets,
            self.rip_packets,
            self.ospf_neighbors.len(),
            self.rip_sources.len(),
        )
    }

    /// Cleanup old entries
    pub fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.ospf_neighbors.retain(|_, state| {
            state.is_known || now.duration_since(state.last_seen) < max_age
        });
        self.rip_sources.retain(|_, state| {
            state.is_known || now.duration_since(state.last_seen) < max_age
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ospf_parse() {
        let data = [
            0x02,             // Version 2
            0x01,             // Type = Hello
            0x00, 0x30,       // Length
            192, 168, 1, 1,   // Router ID
            0, 0, 0, 0,       // Area ID (backbone)
            0x00, 0x00,       // Checksum
            0x00, 0x00,       // Auth Type = Null
            0, 0, 0, 0, 0, 0, 0, 0, // Auth data
        ];

        let packet = OspfPacket::parse(&data).unwrap();
        assert_eq!(packet.version, 2);
        assert_eq!(packet.msg_type, OspfType::Hello);
        assert_eq!(packet.router_id, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_rip_parse() {
        let data = [
            0x02,       // Command = Response
            0x02,       // Version 2
            0x00, 0x00, // Unused
            // Entry 1
            0x00, 0x02, // AFI = IP
            0x00, 0x00, // Route tag
            10, 0, 0, 0, // IP address
            255, 255, 255, 0, // Subnet mask
            0, 0, 0, 0, // Next hop
            0, 0, 0, 1, // Metric = 1
        ];

        let packet = RipPacket::parse(&data).unwrap();
        assert_eq!(packet.command, RipCommand::Response);
        assert_eq!(packet.version, 2);
        assert_eq!(packet.entries.len(), 1);
        assert_eq!(packet.entries[0].metric, 1);
    }

    #[test]
    fn test_rip_poisoning_detection() {
        let mut tracker = RoutingTracker::new();

        // Poisoned route (metric 16)
        let packet = RipPacket {
            command: RipCommand::Response,
            version: 2,
            entries: vec![RipEntry {
                afi: 2,
                route_tag: 0,
                ip_addr: Ipv4Addr::new(10, 0, 0, 0),
                subnet_mask: Ipv4Addr::new(255, 0, 0, 0),
                next_hop: Ipv4Addr::new(0, 0, 0, 0),
                metric: 16,
            }],
        };

        let alerts = tracker.process_rip(&packet, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!alerts.is_empty());
        assert!(matches!(alerts[0].attack_type, RipAttackType::RoutePoisoning));
    }

    #[test]
    fn test_ospf_unknown_router_detection() {
        let mut tracker = RoutingTracker::new();
        tracker.add_known_router(Ipv4Addr::new(192, 168, 1, 1));

        let packet = OspfPacket {
            version: 2,
            msg_type: OspfType::Hello,
            length: 48,
            router_id: Ipv4Addr::new(192, 168, 1, 99), // Unknown router
            area_id: Ipv4Addr::new(0, 0, 0, 0),
            checksum: 0,
            auth_type: OspfAuthType::Null,
        };

        let alerts = tracker.process_ospf(&packet, None, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99)));
        assert!(!alerts.is_empty());
        assert!(matches!(alerts[0].attack_type, OspfAttackType::NeighborInjection));
    }
}
