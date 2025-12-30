//! STP (Spanning Tree Protocol) / RSTP / MSTP Parser and Attack Detection
//!
//! Detects STP attacks including:
//! - Root bridge manipulation (priority 0 attack)
//! - Topology Change (TC) floods
//! - BPDU injection from unknown sources
//! - Root bridge flapping

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// BPDU type codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BpduType {
    Config = 0x00,        // Configuration BPDU (STP/RSTP)
    Tcn = 0x80,           // Topology Change Notification
    RstConfig = 0x02,     // RST/MST Configuration BPDU
}

impl BpduType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Config),
            0x80 => Some(Self::Tcn),
            0x02 => Some(Self::RstConfig),
            _ => None,
        }
    }
}

/// Bridge ID (priority + MAC address)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BridgeId {
    pub priority: u16,
    pub mac: [u8; 6],
}

impl BridgeId {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let priority = u16::from_be_bytes([data[0], data[1]]);
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&data[2..8]);

        Some(Self { priority, mac })
    }

    /// Convert MAC to hex string
    pub fn mac_string(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]
        )
    }

    /// Check if this is a superior bridge (lower priority wins)
    pub fn is_superior_to(&self, other: &BridgeId) -> bool {
        if self.priority != other.priority {
            self.priority < other.priority
        } else {
            self.mac < other.mac
        }
    }
}

/// Parsed BPDU packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BpduPacket {
    pub protocol_id: u16,      // 0x0000 for STP
    pub version: u8,           // 0=STP, 2=RSTP, 3=MSTP
    pub bpdu_type: BpduType,
    pub flags: u8,
    pub root_id: BridgeId,
    pub root_path_cost: u32,
    pub bridge_id: BridgeId,
    pub port_id: u16,
    pub message_age: u16,      // In 1/256 second units
    pub max_age: u16,
    pub hello_time: u16,
    pub forward_delay: u16,
}

impl BpduPacket {
    /// Parse BPDU from raw bytes (after LLC header)
    /// LLC header: DSAP=0x42, SSAP=0x42, Control=0x03
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Check LLC header if present
        let offset = if data.len() >= 3 && data[0] == 0x42 && data[1] == 0x42 && data[2] == 0x03 {
            3
        } else {
            0
        };

        let data = &data[offset..];

        // Minimum BPDU size is 35 bytes for Configuration BPDU
        if data.len() < 4 {
            return None;
        }

        let protocol_id = u16::from_be_bytes([data[0], data[1]]);
        if protocol_id != 0x0000 {
            return None; // Not STP
        }

        let version = data[2];
        let bpdu_type = BpduType::from_u8(data[3])?;

        // TCN BPDUs are only 4 bytes
        if bpdu_type == BpduType::Tcn {
            return Some(Self {
                protocol_id,
                version,
                bpdu_type,
                flags: 0,
                root_id: BridgeId {
                    priority: 0,
                    mac: [0; 6],
                },
                root_path_cost: 0,
                bridge_id: BridgeId {
                    priority: 0,
                    mac: [0; 6],
                },
                port_id: 0,
                message_age: 0,
                max_age: 0,
                hello_time: 0,
                forward_delay: 0,
            });
        }

        // Configuration BPDU - need at least 35 bytes
        if data.len() < 35 {
            return None;
        }

        let flags = data[4];
        let root_id = BridgeId::parse(&data[5..13])?;
        let root_path_cost = u32::from_be_bytes([data[13], data[14], data[15], data[16]]);
        let bridge_id = BridgeId::parse(&data[17..25])?;
        let port_id = u16::from_be_bytes([data[25], data[26]]);
        let message_age = u16::from_be_bytes([data[27], data[28]]);
        let max_age = u16::from_be_bytes([data[29], data[30]]);
        let hello_time = u16::from_be_bytes([data[31], data[32]]);
        let forward_delay = u16::from_be_bytes([data[33], data[34]]);

        Some(Self {
            protocol_id,
            version,
            bpdu_type,
            flags,
            root_id,
            root_path_cost,
            bridge_id,
            port_id,
            message_age,
            max_age,
            hello_time,
            forward_delay,
        })
    }

    /// Check if Topology Change flag is set
    pub fn has_tc_flag(&self) -> bool {
        (self.flags & 0x01) != 0
    }

    /// Check if TC Acknowledgment flag is set
    pub fn has_tca_flag(&self) -> bool {
        (self.flags & 0x80) != 0
    }

    /// Check if this is claiming to be root (priority 0)
    pub fn is_claiming_root_with_zero_priority(&self) -> bool {
        self.root_id.priority == 0 || self.bridge_id.priority == 0
    }
}

/// STP root attack alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StpRootAttackAlert {
    pub attacker_mac: String,
    pub claimed_priority: u16,
    pub current_root_mac: String,
    pub current_root_priority: u16,
    pub timestamp: u64,
}

/// STP TC flood alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StpTcFloodAlert {
    pub tc_count: u32,
    pub interval_ms: u64,
    pub source_macs: Vec<String>,
}

/// Tracked bridge state
#[derive(Debug, Clone)]
struct BridgeState {
    bridge_id: BridgeId,
    last_seen: Instant,
    bpdu_count: u32,
    tc_count: u32,
    is_known: bool,
}

/// STP state tracker for attack detection
#[derive(Debug)]
pub struct StpTracker {
    /// Current root bridge
    current_root: Option<BridgeId>,
    /// Known bridges
    bridges: HashMap<[u8; 6], BridgeState>,
    /// TC flood detection window
    tc_window: Duration,
    /// TC count threshold for flood detection
    tc_threshold: u32,
    /// Root change threshold (for flapping)
    root_change_threshold: u32,
    /// Root changes in current window
    root_changes: u32,
    /// Last root change time
    last_root_change: Option<Instant>,
    /// Statistics
    bpdus_seen: u64,
    tc_bpdus_seen: u64,
}

impl Default for StpTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl StpTracker {
    pub fn new() -> Self {
        Self {
            current_root: None,
            bridges: HashMap::new(),
            tc_window: Duration::from_secs(10),
            tc_threshold: 50,
            root_change_threshold: 3,
            root_changes: 0,
            last_root_change: None,
            bpdus_seen: 0,
            tc_bpdus_seen: 0,
        }
    }

    /// Configure detection thresholds
    pub fn configure(&mut self, tc_window: Duration, tc_threshold: u32, root_change_threshold: u32) {
        self.tc_window = tc_window;
        self.tc_threshold = tc_threshold;
        self.root_change_threshold = root_change_threshold;
    }

    /// Add a known/trusted bridge
    pub fn add_known_bridge(&mut self, mac: [u8; 6]) {
        self.bridges.insert(
            mac,
            BridgeState {
                bridge_id: BridgeId { priority: 32768, mac },
                last_seen: Instant::now(),
                bpdu_count: 0,
                tc_count: 0,
                is_known: true,
            },
        );
    }

    /// Process a BPDU and check for attacks
    pub fn process_bpdu(&mut self, bpdu: &BpduPacket) -> Vec<StpRootAttackAlert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        self.bpdus_seen += 1;
        if bpdu.bpdu_type == BpduType::Tcn {
            self.tc_bpdus_seen += 1;
        }

        // Track the sending bridge
        let bridge_mac = bpdu.bridge_id.mac;
        if let Some(state) = self.bridges.get_mut(&bridge_mac) {
            state.last_seen = now;
            state.bpdu_count += 1;
            if bpdu.has_tc_flag() {
                state.tc_count += 1;
            }
            state.bridge_id = bpdu.bridge_id.clone();
        } else {
            self.bridges.insert(
                bridge_mac,
                BridgeState {
                    bridge_id: bpdu.bridge_id.clone(),
                    last_seen: now,
                    bpdu_count: 1,
                    tc_count: if bpdu.has_tc_flag() { 1 } else { 0 },
                    is_known: false,
                },
            );
        }

        // Check for root bridge attack (priority 0 or superior claim)
        if bpdu.is_claiming_root_with_zero_priority() {
            // Priority 0 is always suspicious
            if let Some(ref current_root) = self.current_root {
                if bpdu.bridge_id.mac != current_root.mac {
                    alerts.push(StpRootAttackAlert {
                        attacker_mac: bpdu.bridge_id.mac_string(),
                        claimed_priority: bpdu.bridge_id.priority,
                        current_root_mac: current_root.mac_string(),
                        current_root_priority: current_root.priority,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    });
                }
            }
        }

        // Check for root bridge change
        if let Some(ref current_root) = self.current_root {
            if bpdu.root_id.is_superior_to(current_root) {
                // New superior root announced
                let is_unknown = !self
                    .bridges
                    .get(&bpdu.root_id.mac)
                    .map(|s| s.is_known)
                    .unwrap_or(false);

                if is_unknown && bpdu.root_id.priority < 4096 {
                    // Unknown bridge claiming very low priority
                    alerts.push(StpRootAttackAlert {
                        attacker_mac: bpdu.root_id.mac_string(),
                        claimed_priority: bpdu.root_id.priority,
                        current_root_mac: current_root.mac_string(),
                        current_root_priority: current_root.priority,
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    });
                }

                self.current_root = Some(bpdu.root_id.clone());
                self.root_changes += 1;
                self.last_root_change = Some(now);
            }
        } else {
            // First root we've seen
            self.current_root = Some(bpdu.root_id.clone());
        }

        alerts
    }

    /// Check for TC flood
    pub fn check_tc_flood(&self) -> Option<StpTcFloodAlert> {
        let now = Instant::now();
        let mut total_tc = 0u32;
        let mut source_macs = Vec::new();

        for (mac, state) in &self.bridges {
            if now.duration_since(state.last_seen) < self.tc_window && state.tc_count > 0 {
                total_tc += state.tc_count;
                if state.tc_count > 5 {
                    source_macs.push(format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                    ));
                }
            }
        }

        if total_tc >= self.tc_threshold {
            Some(StpTcFloodAlert {
                tc_count: total_tc,
                interval_ms: self.tc_window.as_millis() as u64,
                source_macs,
            })
        } else {
            None
        }
    }

    /// Check for root flapping (too many root changes)
    pub fn is_root_flapping(&self) -> bool {
        if let Some(last_change) = self.last_root_change {
            Instant::now().duration_since(last_change) < self.tc_window
                && self.root_changes >= self.root_change_threshold
        } else {
            false
        }
    }

    /// Get current root bridge
    pub fn current_root(&self) -> Option<&BridgeId> {
        self.current_root.as_ref()
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, usize, u32) {
        (
            self.bpdus_seen,
            self.tc_bpdus_seen,
            self.bridges.len(),
            self.root_changes,
        )
    }

    /// Cleanup old bridge entries
    pub fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.bridges.retain(|_, state| {
            state.is_known || now.duration_since(state.last_seen) < max_age
        });

        // Reset TC counters for windowed detection
        for state in self.bridges.values_mut() {
            if now.duration_since(state.last_seen) > self.tc_window {
                state.tc_count = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpdu_parse() {
        // Sample Configuration BPDU (without LLC header)
        let data = [
            0x00, 0x00, // Protocol ID = 0
            0x00,       // Version = STP
            0x00,       // Type = Config
            0x01,       // Flags (TC)
            // Root ID (priority + MAC)
            0x80, 0x00, // Priority = 32768
            0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, // MAC
            // Root Path Cost
            0x00, 0x00, 0x00, 0x00,
            // Bridge ID
            0x80, 0x00, 0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5f,
            // Port ID
            0x80, 0x01,
            // Message Age
            0x00, 0x00,
            // Max Age
            0x14, 0x00,
            // Hello Time
            0x02, 0x00,
            // Forward Delay
            0x0f, 0x00,
        ];

        let bpdu = BpduPacket::parse(&data).unwrap();
        assert_eq!(bpdu.version, 0);
        assert_eq!(bpdu.bpdu_type, BpduType::Config);
        assert!(bpdu.has_tc_flag());
        assert_eq!(bpdu.root_id.priority, 32768);
    }

    #[test]
    fn test_root_attack_detection() {
        let mut tracker = StpTracker::new();

        // Set up known root
        let normal_root = BridgeId {
            priority: 32768,
            mac: [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e],
        };
        tracker.current_root = Some(normal_root.clone());
        tracker.add_known_bridge([0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]);

        // Attacker claims priority 0
        let attack_bpdu = BpduPacket {
            protocol_id: 0,
            version: 0,
            bpdu_type: BpduType::Config,
            flags: 0,
            root_id: BridgeId {
                priority: 0,
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            },
            root_path_cost: 0,
            bridge_id: BridgeId {
                priority: 0,
                mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            },
            port_id: 0x8001,
            message_age: 0,
            max_age: 20,
            hello_time: 2,
            forward_delay: 15,
        };

        let alerts = tracker.process_bpdu(&attack_bpdu);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].claimed_priority, 0);
    }

    #[test]
    fn test_bridge_superiority() {
        let bridge1 = BridgeId {
            priority: 32768,
            mac: [0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        };
        let bridge2 = BridgeId {
            priority: 32768,
            mac: [0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
        };
        let bridge3 = BridgeId {
            priority: 0,
            mac: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        };

        // Same priority - lower MAC wins
        assert!(bridge1.is_superior_to(&bridge2));
        assert!(!bridge2.is_superior_to(&bridge1));

        // Lower priority always wins
        assert!(bridge3.is_superior_to(&bridge1));
    }
}
