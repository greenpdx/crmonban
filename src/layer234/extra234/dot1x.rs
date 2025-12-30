//! 802.1X (EAPoL - Extensible Authentication Protocol over LAN) Detection
//!
//! Detects 802.1X bypass and authentication attacks:
//! - Hub bypass (multiple MACs behind authenticated port)
//! - EAP-Start floods
//! - Rogue authenticator (unauthorized EAP-Success)
//! - MAB (MAC Authentication Bypass) attacks
//! - Identity probing

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// EAPoL packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EapolType {
    EapPacket = 0x00,
    Start = 0x01,
    Logoff = 0x02,
    Key = 0x03,
    EncapsulatedAsfAlert = 0x04,
    Mka = 0x05,  // MACsec Key Agreement
    Announcement = 0x06,
}

impl EapolType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::EapPacket),
            0x01 => Some(Self::Start),
            0x02 => Some(Self::Logoff),
            0x03 => Some(Self::Key),
            0x04 => Some(Self::EncapsulatedAsfAlert),
            0x05 => Some(Self::Mka),
            0x06 => Some(Self::Announcement),
            _ => None,
        }
    }
}

/// EAP codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EapCode {
    Request = 1,
    Response = 2,
    Success = 3,
    Failure = 4,
}

impl EapCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            3 => Some(Self::Success),
            4 => Some(Self::Failure),
            _ => None,
        }
    }
}

/// EAP method types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EapType {
    Identity,
    Notification,
    Nak,
    Md5Challenge,
    Otp,          // One Time Password
    Gtc,          // Generic Token Card
    Tls,
    Leap,
    Sim,
    Ttls,
    Aka,
    Peap,
    MsChapV2,
    Fast,
    Pwd,
    Unknown(u8),
}

impl EapType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Identity,
            2 => Self::Notification,
            3 => Self::Nak,
            4 => Self::Md5Challenge,
            5 => Self::Otp,
            6 => Self::Gtc,
            13 => Self::Tls,
            17 => Self::Leap,
            18 => Self::Sim,
            21 => Self::Ttls,
            23 => Self::Aka,
            25 => Self::Peap,
            26 => Self::MsChapV2,
            43 => Self::Fast,
            52 => Self::Pwd,
            _ => Self::Unknown(v),
        }
    }
}

/// Parsed EAPoL packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EapolPacket {
    pub version: u8,
    pub packet_type: EapolType,
    pub length: u16,
    pub body: Option<EapPacket>,
}

/// Parsed EAP packet (inside EAPoL)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EapPacket {
    pub code: EapCode,
    pub identifier: u8,
    pub length: u16,
    pub eap_type: Option<EapType>,
    pub type_data: Option<Vec<u8>>,
}

impl EapolPacket {
    /// Parse EAPoL packet from raw bytes (after Ethertype 0x888E)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let version = data[0];
        let packet_type = EapolType::from_u8(data[1])?;
        let length = u16::from_be_bytes([data[2], data[3]]);

        let body = if packet_type == EapolType::EapPacket && data.len() >= 4 + length as usize {
            EapPacket::parse(&data[4..4 + length as usize])
        } else {
            None
        };

        Some(Self {
            version,
            packet_type,
            length,
            body,
        })
    }

    /// Check if this is an EAP-Start packet
    pub fn is_start(&self) -> bool {
        self.packet_type == EapolType::Start
    }

    /// Check if this is an EAP-Logoff packet
    pub fn is_logoff(&self) -> bool {
        self.packet_type == EapolType::Logoff
    }
}

impl EapPacket {
    /// Parse EAP packet
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let code = EapCode::from_u8(data[0])?;
        let identifier = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]);

        // Success and Failure packets have no type
        let (eap_type, type_data) = if matches!(code, EapCode::Request | EapCode::Response)
            && data.len() >= 5
        {
            let eap_type = EapType::from_u8(data[4]);
            let type_data = if data.len() > 5 {
                Some(data[5..].to_vec())
            } else {
                None
            };
            (Some(eap_type), type_data)
        } else {
            (None, None)
        };

        Some(Self {
            code,
            identifier,
            length,
            eap_type,
            type_data,
        })
    }

    /// Check if this is an Identity request/response
    pub fn is_identity(&self) -> bool {
        matches!(self.eap_type, Some(EapType::Identity))
    }

    /// Get identity string (if Identity response)
    pub fn get_identity(&self) -> Option<String> {
        if self.code == EapCode::Response && self.is_identity() {
            self.type_data
                .as_ref()
                .map(|d| String::from_utf8_lossy(d).to_string())
        } else {
            None
        }
    }
}

// =============================================================================
// 802.1X Attack Detection
// =============================================================================

/// 802.1X attack alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dot1xAlert {
    pub attack_type: Dot1xAttackType,
    pub source_mac: String,
    pub port_or_interface: Option<String>,
    pub details: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Dot1xAttackType {
    HubBypass,           // Multiple MACs behind authenticated port
    EapStartFlood,       // Too many EAP-Start packets
    RogueAuthenticator,  // Unauthorized EAP-Success
    IdentityProbing,     // Many identity requests
    MabBypass,           // MAC Authentication Bypass attempt
}

/// Port/interface state
#[derive(Debug, Clone)]
struct PortState {
    authenticated_mac: Option<[u8; 6]>,
    seen_macs: HashSet<[u8; 6]>,
    eap_start_count: u32,
    identity_request_count: u32,
    last_activity: Instant,
    is_authenticator: bool,
}

/// 802.1X state tracker
#[derive(Debug)]
pub struct Dot1xTracker {
    /// Port states (port_id/interface -> state)
    ports: HashMap<String, PortState>,
    /// Known authenticators (MACs that can send EAP-Success)
    known_authenticators: HashSet<[u8; 6]>,
    /// Hub bypass threshold (MACs per port)
    hub_bypass_threshold: usize,
    /// EAP-Start flood threshold (per window)
    eap_start_threshold: u32,
    /// Identity probe threshold
    identity_probe_threshold: u32,
    /// Detection window
    window: Duration,
    /// Statistics
    eapol_packets: u64,
    eap_starts: u64,
    eap_successes: u64,
}

impl Default for Dot1xTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Dot1xTracker {
    pub fn new() -> Self {
        Self {
            ports: HashMap::new(),
            known_authenticators: HashSet::new(),
            hub_bypass_threshold: 2,
            eap_start_threshold: 20,
            identity_probe_threshold: 10,
            window: Duration::from_secs(60),
            eapol_packets: 0,
            eap_starts: 0,
            eap_successes: 0,
        }
    }

    /// Add a known authenticator MAC
    pub fn add_known_authenticator(&mut self, mac: [u8; 6]) {
        self.known_authenticators.insert(mac);
    }

    /// Configure detection thresholds
    pub fn configure(
        &mut self,
        hub_bypass_threshold: usize,
        eap_start_threshold: u32,
        identity_probe_threshold: u32,
        window: Duration,
    ) {
        self.hub_bypass_threshold = hub_bypass_threshold;
        self.eap_start_threshold = eap_start_threshold;
        self.identity_probe_threshold = identity_probe_threshold;
        self.window = window;
    }

    /// Process an EAPoL packet
    pub fn process_eapol(
        &mut self,
        packet: &EapolPacket,
        source_mac: [u8; 6],
        port_id: &str,
    ) -> Vec<Dot1xAlert> {
        let mut alerts = Vec::new();
        self.eapol_packets += 1;
        let now = Instant::now();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            source_mac[0], source_mac[1], source_mac[2],
            source_mac[3], source_mac[4], source_mac[5]
        );

        // Get or create port state
        let port_state = self.ports.entry(port_id.to_string()).or_insert(PortState {
            authenticated_mac: None,
            seen_macs: HashSet::new(),
            eap_start_count: 0,
            identity_request_count: 0,
            last_activity: now,
            is_authenticator: false,
        });

        // Track MACs seen on this port
        port_state.seen_macs.insert(source_mac);
        port_state.last_activity = now;

        // Check for hub bypass (multiple MACs)
        if port_state.authenticated_mac.is_some()
            && port_state.seen_macs.len() > self.hub_bypass_threshold
        {
            alerts.push(Dot1xAlert {
                attack_type: Dot1xAttackType::HubBypass,
                source_mac: mac_str.clone(),
                port_or_interface: Some(port_id.to_string()),
                details: format!(
                    "Multiple MACs ({}) detected behind authenticated port",
                    port_state.seen_macs.len()
                ),
                timestamp,
            });
        }

        // Process by packet type
        match packet.packet_type {
            EapolType::Start => {
                self.eap_starts += 1;
                port_state.eap_start_count += 1;

                // Check for EAP-Start flood
                if port_state.eap_start_count > self.eap_start_threshold {
                    alerts.push(Dot1xAlert {
                        attack_type: Dot1xAttackType::EapStartFlood,
                        source_mac: mac_str.clone(),
                        port_or_interface: Some(port_id.to_string()),
                        details: format!(
                            "EAP-Start flood: {} packets in window",
                            port_state.eap_start_count
                        ),
                        timestamp,
                    });
                }
            }
            EapolType::EapPacket => {
                if let Some(eap) = &packet.body {
                    match eap.code {
                        EapCode::Success => {
                            self.eap_successes += 1;

                            // Check for rogue authenticator
                            if !self.known_authenticators.is_empty()
                                && !self.known_authenticators.contains(&source_mac)
                            {
                                alerts.push(Dot1xAlert {
                                    attack_type: Dot1xAttackType::RogueAuthenticator,
                                    source_mac: mac_str.clone(),
                                    port_or_interface: Some(port_id.to_string()),
                                    details: "EAP-Success from unknown authenticator".to_string(),
                                    timestamp,
                                });
                            } else {
                                // Mark port as authenticated
                                port_state.authenticated_mac = Some(source_mac);
                                port_state.is_authenticator = true;
                            }
                        }
                        EapCode::Request => {
                            if eap.is_identity() {
                                port_state.identity_request_count += 1;

                                // Check for identity probing
                                if port_state.identity_request_count > self.identity_probe_threshold
                                {
                                    alerts.push(Dot1xAlert {
                                        attack_type: Dot1xAttackType::IdentityProbing,
                                        source_mac: mac_str.clone(),
                                        port_or_interface: Some(port_id.to_string()),
                                        details: format!(
                                            "Identity probing: {} requests",
                                            port_state.identity_request_count
                                        ),
                                        timestamp,
                                    });
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        alerts
    }

    /// Set a port as authenticated with a specific MAC
    pub fn set_authenticated(&mut self, port_id: &str, mac: [u8; 6]) {
        if let Some(state) = self.ports.get_mut(port_id) {
            state.authenticated_mac = Some(mac);
            state.seen_macs.clear();
            state.seen_macs.insert(mac);
        }
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, u64, usize) {
        (
            self.eapol_packets,
            self.eap_starts,
            self.eap_successes,
            self.ports.len(),
        )
    }

    /// Cleanup old port entries and reset counters
    pub fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();

        self.ports.retain(|_, state| {
            now.duration_since(state.last_activity) < max_age
        });

        // Reset windowed counters
        for state in self.ports.values_mut() {
            if now.duration_since(state.last_activity) > self.window {
                state.eap_start_count = 0;
                state.identity_request_count = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eapol_start_parse() {
        let data = [
            0x01,       // Version 1
            0x01,       // Type = Start
            0x00, 0x00, // Length = 0
        ];

        let packet = EapolPacket::parse(&data).unwrap();
        assert_eq!(packet.version, 1);
        assert!(packet.is_start());
        assert!(packet.body.is_none());
    }

    #[test]
    fn test_eap_identity_parse() {
        let data = [
            0x01,       // Version 1
            0x00,       // Type = EAP Packet
            0x00, 0x09, // Length = 9
            // EAP packet
            0x02,       // Code = Response
            0x01,       // Identifier
            0x00, 0x09, // Length = 9
            0x01,       // Type = Identity
            0x75, 0x73, 0x65, 0x72, // "user"
        ];

        let packet = EapolPacket::parse(&data).unwrap();
        assert_eq!(packet.packet_type, EapolType::EapPacket);

        let eap = packet.body.unwrap();
        assert_eq!(eap.code, EapCode::Response);
        assert!(eap.is_identity());
        assert_eq!(eap.get_identity(), Some("user".to_string()));
    }

    #[test]
    fn test_hub_bypass_detection() {
        let mut tracker = Dot1xTracker::new();
        tracker.hub_bypass_threshold = 2;

        // Set port as authenticated
        let auth_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        tracker.set_authenticated("eth0", auth_mac);

        // Send packet from different MAC
        let packet = EapolPacket {
            version: 1,
            packet_type: EapolType::Start,
            length: 0,
            body: None,
        };

        let alerts = tracker.process_eapol(
            &packet,
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            "eth0",
        );

        // First additional MAC shouldn't trigger (threshold is 2)
        assert!(alerts.is_empty());

        // Third MAC should trigger
        let alerts = tracker.process_eapol(
            &packet,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            "eth0",
        );

        assert!(!alerts.is_empty());
        assert!(matches!(alerts[0].attack_type, Dot1xAttackType::HubBypass));
    }

    #[test]
    fn test_rogue_authenticator_detection() {
        let mut tracker = Dot1xTracker::new();
        tracker.add_known_authenticator([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

        // EAP-Success from unknown MAC
        let packet = EapolPacket {
            version: 1,
            packet_type: EapolType::EapPacket,
            length: 4,
            body: Some(EapPacket {
                code: EapCode::Success,
                identifier: 1,
                length: 4,
                eap_type: None,
                type_data: None,
            }),
        };

        let alerts = tracker.process_eapol(
            &packet,
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], // Unknown MAC
            "eth0",
        );

        assert!(!alerts.is_empty());
        assert!(matches!(
            alerts[0].attack_type,
            Dot1xAttackType::RogueAuthenticator
        ));
    }

    #[test]
    fn test_eap_start_flood_detection() {
        let mut tracker = Dot1xTracker::new();
        tracker.eap_start_threshold = 5;

        let packet = EapolPacket {
            version: 1,
            packet_type: EapolType::Start,
            length: 0,
            body: None,
        };

        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        // Send more than threshold
        for i in 0..10 {
            let alerts = tracker.process_eapol(&packet, mac, "eth0");
            if i >= 5 {
                assert!(
                    !alerts.is_empty(),
                    "Expected flood alert after {} packets",
                    i + 1
                );
            }
        }
    }
}
