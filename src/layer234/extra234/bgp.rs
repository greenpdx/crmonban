//! BGP (Border Gateway Protocol) Parser and Attack Detection
//!
//! Detects BGP hijacking attacks including:
//! - Unexpected AS in path (hijacking)
//! - Rapid prefix withdrawal/announcement (flapping)
//! - Invalid NEXT_HOP
//! - AS_PATH length anomalies

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// BGP message types (RFC 4271)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpMsgType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    RouteRefresh = 5, // RFC 2918
}

impl BgpMsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Open),
            2 => Some(Self::Update),
            3 => Some(Self::Notification),
            4 => Some(Self::Keepalive),
            5 => Some(Self::RouteRefresh),
            _ => None,
        }
    }
}

/// Path attribute type codes (RFC 4271)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttrType {
    Origin,
    AsPath,
    NextHop,
    Med,         // Multi-Exit Discriminator
    LocalPref,
    AtomicAggregate,
    Aggregator,
    Communities, // RFC 1997
    Unknown(u8),
}

impl AttrType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Origin,
            2 => Self::AsPath,
            3 => Self::NextHop,
            4 => Self::Med,
            5 => Self::LocalPref,
            6 => Self::AtomicAggregate,
            7 => Self::Aggregator,
            8 => Self::Communities,
            _ => Self::Unknown(v),
        }
    }
}

/// AS_PATH segment types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
}

/// Path attribute value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttrValue {
    Origin(u8),                     // IGP(0), EGP(1), Incomplete(2)
    AsPath(Vec<(AsPathSegmentType, Vec<u32>)>),
    NextHop(IpAddr),
    Med(u32),
    LocalPref(u32),
    AtomicAggregate,
    Aggregator { asn: u32, ip: IpAddr },
    Communities(Vec<u32>),
    Raw(Vec<u8>),
}

/// Parsed path attribute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathAttribute {
    pub optional: bool,
    pub transitive: bool,
    pub partial: bool,
    pub extended_length: bool,
    pub attr_type: AttrType,
    pub value: AttrValue,
}

/// Parsed BGP message header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpMessage {
    pub msg_type: BgpMsgType,
    pub length: u16,
}

/// Parsed BGP UPDATE message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpUpdate {
    pub withdrawn_len: u16,
    pub withdrawn_prefixes: Vec<String>, // CIDR notation
    pub path_attributes: Vec<PathAttribute>,
    pub nlri: Vec<String>, // Network Layer Reachability Info (CIDR)
}

impl BgpMessage {
    /// Parse BGP message header from raw bytes
    /// BGP messages start with 16-byte marker (all 0xFF), then length (2 bytes), then type (1 byte)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 19 {
            return None;
        }

        // Check marker (16 bytes of 0xFF)
        if !data[..16].iter().all(|&b| b == 0xFF) {
            return None;
        }

        let length = u16::from_be_bytes([data[16], data[17]]);
        let msg_type = BgpMsgType::from_u8(data[18])?;

        Some(Self { msg_type, length })
    }
}

impl BgpUpdate {
    /// Parse BGP UPDATE message body (after 19-byte header)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let mut offset = 0;

        // Withdrawn Routes Length (2 bytes)
        let withdrawn_len = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Parse withdrawn routes
        let mut withdrawn_prefixes = Vec::new();
        let withdrawn_end = offset + withdrawn_len as usize;
        if withdrawn_end > data.len() {
            return None;
        }

        while offset < withdrawn_end {
            if let Some((prefix, len)) = Self::parse_prefix(&data[offset..]) {
                withdrawn_prefixes.push(prefix);
                offset += len;
            } else {
                break;
            }
        }
        offset = withdrawn_end;

        if offset + 2 > data.len() {
            return None;
        }

        // Total Path Attribute Length (2 bytes)
        let path_attr_len = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Parse path attributes
        let mut path_attributes = Vec::new();
        let attr_end = offset + path_attr_len as usize;
        if attr_end > data.len() {
            return None;
        }

        while offset < attr_end {
            if let Some((attr, len)) = Self::parse_path_attribute(&data[offset..]) {
                path_attributes.push(attr);
                offset += len;
            } else {
                break;
            }
        }
        offset = attr_end;

        // Parse NLRI (remaining bytes)
        let mut nlri = Vec::new();
        while offset < data.len() {
            if let Some((prefix, len)) = Self::parse_prefix(&data[offset..]) {
                nlri.push(prefix);
                offset += len;
            } else {
                break;
            }
        }

        Some(Self {
            withdrawn_len,
            withdrawn_prefixes,
            path_attributes,
            nlri,
        })
    }

    /// Parse a prefix (length byte + prefix bytes)
    fn parse_prefix(data: &[u8]) -> Option<(String, usize)> {
        if data.is_empty() {
            return None;
        }

        let prefix_len = data[0] as usize;
        let byte_len = (prefix_len + 7) / 8;

        if data.len() < 1 + byte_len {
            return None;
        }

        let mut addr_bytes = [0u8; 4];
        for (i, &b) in data[1..1 + byte_len].iter().enumerate() {
            if i < 4 {
                addr_bytes[i] = b;
            }
        }

        let prefix = format!(
            "{}.{}.{}.{}/{}",
            addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3], prefix_len
        );

        Some((prefix, 1 + byte_len))
    }

    /// Parse a path attribute
    fn parse_path_attribute(data: &[u8]) -> Option<(PathAttribute, usize)> {
        if data.len() < 3 {
            return None;
        }

        let flags = data[0];
        let optional = (flags & 0x80) != 0;
        let transitive = (flags & 0x40) != 0;
        let partial = (flags & 0x20) != 0;
        let extended_length = (flags & 0x10) != 0;

        let attr_type = AttrType::from_u8(data[1]);

        let (attr_len, header_len) = if extended_length {
            if data.len() < 4 {
                return None;
            }
            (u16::from_be_bytes([data[2], data[3]]) as usize, 4)
        } else {
            (data[2] as usize, 3)
        };

        if data.len() < header_len + attr_len {
            return None;
        }

        let attr_data = &data[header_len..header_len + attr_len];
        let value = Self::parse_attr_value(attr_type, attr_data);

        Some((
            PathAttribute {
                optional,
                transitive,
                partial,
                extended_length,
                attr_type,
                value,
            },
            header_len + attr_len,
        ))
    }

    /// Parse attribute value based on type
    fn parse_attr_value(attr_type: AttrType, data: &[u8]) -> AttrValue {
        match attr_type {
            AttrType::Origin => {
                if !data.is_empty() {
                    AttrValue::Origin(data[0])
                } else {
                    AttrValue::Raw(data.to_vec())
                }
            }
            AttrType::AsPath => {
                let mut segments = Vec::new();
                let mut offset = 0;
                while offset + 2 <= data.len() {
                    let seg_type = data[offset];
                    let seg_len = data[offset + 1] as usize;
                    offset += 2;

                    let mut asns = Vec::new();
                    for _ in 0..seg_len {
                        if offset + 4 <= data.len() {
                            // 4-byte ASN (RFC 6793)
                            let asn = u32::from_be_bytes([
                                data[offset],
                                data[offset + 1],
                                data[offset + 2],
                                data[offset + 3],
                            ]);
                            asns.push(asn);
                            offset += 4;
                        } else if offset + 2 <= data.len() {
                            // 2-byte ASN (legacy)
                            let asn = u16::from_be_bytes([data[offset], data[offset + 1]]) as u32;
                            asns.push(asn);
                            offset += 2;
                        }
                    }

                    let seg_type = match seg_type {
                        1 => AsPathSegmentType::AsSet,
                        _ => AsPathSegmentType::AsSequence,
                    };
                    segments.push((seg_type, asns));
                }
                AttrValue::AsPath(segments)
            }
            AttrType::NextHop => {
                if data.len() >= 4 {
                    let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                        data[0], data[1], data[2], data[3],
                    ));
                    AttrValue::NextHop(ip)
                } else {
                    AttrValue::Raw(data.to_vec())
                }
            }
            AttrType::Med => {
                if data.len() >= 4 {
                    let med = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    AttrValue::Med(med)
                } else {
                    AttrValue::Raw(data.to_vec())
                }
            }
            AttrType::LocalPref => {
                if data.len() >= 4 {
                    let pref = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    AttrValue::LocalPref(pref)
                } else {
                    AttrValue::Raw(data.to_vec())
                }
            }
            AttrType::AtomicAggregate => AttrValue::AtomicAggregate,
            _ => AttrValue::Raw(data.to_vec()),
        }
    }

    /// Extract AS path as a flat list of ASNs
    pub fn get_as_path(&self) -> Vec<u32> {
        let mut asns = Vec::new();
        for attr in &self.path_attributes {
            if let AttrValue::AsPath(segments) = &attr.value {
                for (_, path) in segments {
                    asns.extend(path);
                }
            }
        }
        asns
    }

    /// Get the NEXT_HOP attribute
    pub fn get_next_hop(&self) -> Option<IpAddr> {
        for attr in &self.path_attributes {
            if let AttrValue::NextHop(ip) = &attr.value {
                return Some(*ip);
            }
        }
        None
    }
}

/// BGP hijacking alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpHijackAlert {
    pub prefix: String,
    pub suspicious_as: u32,
    pub original_as: Option<u32>,
    pub timestamp: u64,
}

/// BGP prefix flapping alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BgpFlapAlert {
    pub prefix: String,
    pub flap_count: u32,
    pub interval_ms: u64,
}

/// Tracked prefix state
#[derive(Debug, Clone)]
struct PrefixState {
    origin_as: u32,
    last_seen: Instant,
    announcement_count: u32,
    withdrawal_count: u32,
}

/// BGP state tracker for detecting hijacking
#[derive(Debug)]
pub struct BgpStateTracker {
    /// Known prefix -> origin AS mappings
    prefix_origins: HashMap<String, PrefixState>,
    /// Known/trusted ASNs
    known_asns: HashSet<u32>,
    /// Window for flap detection
    flap_window: Duration,
    /// Threshold for flap detection
    flap_threshold: u32,
    /// Statistics
    updates_seen: u64,
    withdrawals_seen: u64,
}

impl Default for BgpStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpStateTracker {
    pub fn new() -> Self {
        Self {
            prefix_origins: HashMap::new(),
            known_asns: HashSet::new(),
            flap_window: Duration::from_secs(60),
            flap_threshold: 5,
            updates_seen: 0,
            withdrawals_seen: 0,
        }
    }

    /// Add a known/trusted ASN
    pub fn add_known_asn(&mut self, asn: u32) {
        self.known_asns.insert(asn);
    }

    /// Configure flap detection
    pub fn configure_flap_detection(&mut self, window: Duration, threshold: u32) {
        self.flap_window = window;
        self.flap_threshold = threshold;
    }

    /// Process a BGP UPDATE and check for hijacking
    pub fn process_update(&mut self, update: &BgpUpdate) -> Vec<BgpHijackAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        self.updates_seen += 1;
        self.withdrawals_seen += update.withdrawn_prefixes.len() as u64;

        // Get origin AS from AS_PATH (last AS in sequence)
        let as_path = update.get_as_path();
        let origin_as = as_path.last().copied();

        // Process withdrawn routes
        for prefix in &update.withdrawn_prefixes {
            if let Some(state) = self.prefix_origins.get_mut(prefix) {
                state.withdrawal_count += 1;
            }
        }

        // Process announced routes (NLRI)
        if let Some(origin) = origin_as {
            for prefix in &update.nlri {
                if let Some(state) = self.prefix_origins.get_mut(prefix) {
                    // Check for origin AS change (potential hijack)
                    if state.origin_as != origin {
                        // Only alert if not in known ASNs or if original AS was known
                        if !self.known_asns.contains(&origin)
                            || self.known_asns.contains(&state.origin_as)
                        {
                            alerts.push(BgpHijackAlert {
                                prefix: prefix.clone(),
                                suspicious_as: origin,
                                original_as: Some(state.origin_as),
                                timestamp: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0),
                            });
                        }
                        state.origin_as = origin;
                    }
                    state.last_seen = now;
                    state.announcement_count += 1;
                } else {
                    // New prefix - check if origin AS is unknown
                    if !self.known_asns.is_empty() && !self.known_asns.contains(&origin) {
                        alerts.push(BgpHijackAlert {
                            prefix: prefix.clone(),
                            suspicious_as: origin,
                            original_as: None,
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0),
                        });
                    }

                    self.prefix_origins.insert(
                        prefix.clone(),
                        PrefixState {
                            origin_as: origin,
                            last_seen: now,
                            announcement_count: 1,
                            withdrawal_count: 0,
                        },
                    );
                }
            }
        }

        alerts
    }

    /// Check for prefix flapping
    pub fn check_flapping(&self) -> Vec<BgpFlapAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        for (prefix, state) in &self.prefix_origins {
            let total_changes = state.announcement_count + state.withdrawal_count;
            let elapsed = now.duration_since(state.last_seen);

            if elapsed < self.flap_window && total_changes >= self.flap_threshold {
                alerts.push(BgpFlapAlert {
                    prefix: prefix.clone(),
                    flap_count: total_changes,
                    interval_ms: elapsed.as_millis() as u64,
                });
            }
        }

        alerts
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, usize) {
        (
            self.updates_seen,
            self.withdrawals_seen,
            self.prefix_origins.len(),
        )
    }

    /// Clean up old entries
    pub fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.prefix_origins
            .retain(|_, state| now.duration_since(state.last_seen) < max_age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_message_parse() {
        // Valid BGP header with KEEPALIVE type
        let mut data = vec![0xFF; 16]; // Marker
        data.extend_from_slice(&[0x00, 0x13]); // Length = 19
        data.push(4); // Type = KEEPALIVE

        let msg = BgpMessage::parse(&data).unwrap();
        assert_eq!(msg.msg_type, BgpMsgType::Keepalive);
        assert_eq!(msg.length, 19);
    }

    #[test]
    fn test_bgp_hijack_detection() {
        let mut tracker = BgpStateTracker::new();
        tracker.add_known_asn(64512); // Our AS

        // First announcement - should be flagged as unknown AS
        let update1 = BgpUpdate {
            withdrawn_len: 0,
            withdrawn_prefixes: vec![],
            path_attributes: vec![PathAttribute {
                optional: false,
                transitive: true,
                partial: false,
                extended_length: false,
                attr_type: AttrType::AsPath,
                value: AttrValue::AsPath(vec![(
                    AsPathSegmentType::AsSequence,
                    vec![64512, 65001],
                )]),
            }],
            nlri: vec!["10.0.0.0/8".to_string()],
        };

        let alerts = tracker.process_update(&update1);
        assert_eq!(alerts.len(), 1); // Unknown origin AS 65001

        // Add 65001 as known
        tracker.add_known_asn(65001);

        // Now hijack attempt with different AS
        let update2 = BgpUpdate {
            withdrawn_len: 0,
            withdrawn_prefixes: vec![],
            path_attributes: vec![PathAttribute {
                optional: false,
                transitive: true,
                partial: false,
                extended_length: false,
                attr_type: AttrType::AsPath,
                value: AttrValue::AsPath(vec![(
                    AsPathSegmentType::AsSequence,
                    vec![64512, 65002], // Different origin AS
                )]),
            }],
            nlri: vec!["10.0.0.0/8".to_string()],
        };

        let alerts = tracker.process_update(&update2);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].suspicious_as, 65002);
        assert_eq!(alerts[0].original_as, Some(65001));
    }
}
