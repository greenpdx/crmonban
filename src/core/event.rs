//! Detection events
//!
//! Unified detection event format used by all analyzers.

use std::collections::HashMap;
use std::net::IpAddr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Detection severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Default for Severity {
    fn default() -> Self {
        Severity::Medium
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl From<u8> for Severity {
    fn from(val: u8) -> Self {
        match val {
            0 => Severity::Info,
            1 => Severity::Low,
            2 => Severity::Medium,
            3 => Severity::High,
            4 => Severity::Critical,
            _ => Severity::Medium,
        }
    }
}

/// Detection type categories
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionType {
    // Signature-based
    SignatureMatch,

    // Protocol anomalies
    ProtocolAnomaly,
    MalformedPacket,

    // Network anomalies
    PortScan,
    NetworkScan,
    DoS,
    BruteForce,
    DataExfiltration,
    Beaconing,
    LateralMovement,

    // Threat intelligence
    ThreatIntelMatch,
    MaliciousIp,
    MaliciousDomain,
    MaliciousUrl,
    MaliciousHash,
    MaliciousJa3,

    // ML/Anomaly
    AnomalyDetection,
    BehaviorAnomaly,
    TrafficAnomaly,

    // Policy violations
    PolicyViolation,
    UnauthorizedAccess,

    // Exploits
    ExploitAttempt,
    Shellcode,
    Overflow,

    // Malware
    MalwareDownload,
    MalwareCallback,
    CnC,

    // Other
    Custom(String),
}

impl Default for DetectionType {
    fn default() -> Self {
        DetectionType::SignatureMatch
    }
}

impl std::fmt::Display for DetectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionType::SignatureMatch => write!(f, "signature_match"),
            DetectionType::ProtocolAnomaly => write!(f, "protocol_anomaly"),
            DetectionType::MalformedPacket => write!(f, "malformed_packet"),
            DetectionType::PortScan => write!(f, "port_scan"),
            DetectionType::NetworkScan => write!(f, "network_scan"),
            DetectionType::DoS => write!(f, "dos"),
            DetectionType::BruteForce => write!(f, "brute_force"),
            DetectionType::DataExfiltration => write!(f, "data_exfiltration"),
            DetectionType::Beaconing => write!(f, "beaconing"),
            DetectionType::LateralMovement => write!(f, "lateral_movement"),
            DetectionType::ThreatIntelMatch => write!(f, "threat_intel_match"),
            DetectionType::MaliciousIp => write!(f, "malicious_ip"),
            DetectionType::MaliciousDomain => write!(f, "malicious_domain"),
            DetectionType::MaliciousUrl => write!(f, "malicious_url"),
            DetectionType::MaliciousHash => write!(f, "malicious_hash"),
            DetectionType::MaliciousJa3 => write!(f, "malicious_ja3"),
            DetectionType::AnomalyDetection => write!(f, "anomaly_detection"),
            DetectionType::BehaviorAnomaly => write!(f, "behavior_anomaly"),
            DetectionType::TrafficAnomaly => write!(f, "traffic_anomaly"),
            DetectionType::PolicyViolation => write!(f, "policy_violation"),
            DetectionType::UnauthorizedAccess => write!(f, "unauthorized_access"),
            DetectionType::ExploitAttempt => write!(f, "exploit_attempt"),
            DetectionType::Shellcode => write!(f, "shellcode"),
            DetectionType::Overflow => write!(f, "overflow"),
            DetectionType::MalwareDownload => write!(f, "malware_download"),
            DetectionType::MalwareCallback => write!(f, "malware_callback"),
            DetectionType::CnC => write!(f, "cnc"),
            DetectionType::Custom(s) => write!(f, "custom:{}", s),
        }
    }
}

/// Action taken in response to detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionAction {
    /// Log only
    Log,
    /// Generate alert
    Alert,
    /// Drop packet
    Drop,
    /// Reject with RST/ICMP
    Reject,
    /// Ban source IP
    Ban,
    /// Rate limit
    RateLimit,
    /// Allow (for pass rules)
    Allow,
}

impl Default for DetectionAction {
    fn default() -> Self {
        DetectionAction::Alert
    }
}

impl std::fmt::Display for DetectionAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionAction::Log => write!(f, "log"),
            DetectionAction::Alert => write!(f, "alert"),
            DetectionAction::Drop => write!(f, "drop"),
            DetectionAction::Reject => write!(f, "reject"),
            DetectionAction::Ban => write!(f, "ban"),
            DetectionAction::RateLimit => write!(f, "rate_limit"),
            DetectionAction::Allow => write!(f, "allow"),
        }
    }
}

/// Unified detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    /// Unique event ID
    pub id: Uuid,
    /// Event timestamp
    pub timestamp: DateTime<Utc>,

    // Classification
    /// Detection type
    pub event_type: DetectionType,
    /// Severity
    pub severity: Severity,
    /// Confidence (0.0 - 1.0)
    pub confidence: f32,

    // Source info
    /// Detector name (signature, anomaly, protocol, etc.)
    pub detector: String,
    /// Rule/signature ID if applicable
    pub rule_id: Option<u32>,
    /// Rule name
    pub rule_name: Option<String>,
    /// Classification type
    pub classtype: Option<String>,

    // Network context
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: Option<u16>,
    /// Destination port
    pub dst_port: Option<u16>,
    /// Protocol
    pub protocol: Option<String>,

    // Flow context
    /// Associated flow ID
    pub flow_id: Option<u64>,

    // Message and details
    /// Alert message
    pub message: String,
    /// Additional details
    pub details: HashMap<String, serde_json::Value>,

    // Threat intelligence
    /// MITRE ATT&CK techniques
    pub mitre_attack: Vec<String>,
    /// CVE if applicable
    pub cve: Option<String>,
    /// Threat intel match info
    pub threat_intel: Option<ThreatIntelInfo>,

    // Action
    /// Action taken
    pub action: DetectionAction,

    // References
    /// External references
    pub references: Vec<String>,
}

impl DetectionEvent {
    /// Create a new detection event
    pub fn new(
        event_type: DetectionType,
        severity: Severity,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        message: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            severity,
            confidence: 1.0,
            detector: "unknown".to_string(),
            rule_id: None,
            rule_name: None,
            classtype: None,
            src_ip,
            dst_ip,
            src_port: None,
            dst_port: None,
            protocol: None,
            flow_id: None,
            message,
            details: HashMap::new(),
            mitre_attack: Vec::new(),
            cve: None,
            threat_intel: None,
            action: DetectionAction::Alert,
            references: Vec::new(),
        }
    }

    /// Set detector name
    pub fn with_detector(mut self, detector: &str) -> Self {
        self.detector = detector.to_string();
        self
    }

    /// Set rule info
    pub fn with_rule(mut self, id: u32, name: Option<&str>) -> Self {
        self.rule_id = Some(id);
        self.rule_name = name.map(|s| s.to_string());
        self
    }

    /// Set ports
    pub fn with_ports(mut self, src_port: u16, dst_port: u16) -> Self {
        self.src_port = Some(src_port);
        self.dst_port = Some(dst_port);
        self
    }

    /// Set protocol
    pub fn with_protocol(mut self, protocol: &str) -> Self {
        self.protocol = Some(protocol.to_string());
        self
    }

    /// Set flow ID
    pub fn with_flow(mut self, flow_id: u64) -> Self {
        self.flow_id = Some(flow_id);
        self
    }

    /// Add detail
    pub fn with_detail(mut self, key: &str, value: serde_json::Value) -> Self {
        self.details.insert(key.to_string(), value);
        self
    }

    /// Set action
    pub fn with_action(mut self, action: DetectionAction) -> Self {
        self.action = action;
        self
    }

    /// Add MITRE ATT&CK technique
    pub fn with_mitre(mut self, technique: &str) -> Self {
        self.mitre_attack.push(technique.to_string());
        self
    }

    /// Set confidence
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
}

/// Threat intelligence match information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelInfo {
    /// IOC type (ip, domain, hash, etc.)
    pub ioc_type: String,
    /// IOC value
    pub ioc_value: String,
    /// Source feed
    pub source: String,
    /// Threat category
    pub category: String,
    /// First seen
    pub first_seen: Option<DateTime<Utc>>,
    /// Last seen
    pub last_seen: Option<DateTime<Utc>>,
    /// Tags
    pub tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_detection_event_creation() {
        let event = DetectionEvent::new(
            DetectionType::SignatureMatch,
            Severity::High,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "SQL Injection attempt".to_string(),
        )
        .with_detector("signatures")
        .with_rule(2001234, Some("ET WEB_SERVER SQL Injection"))
        .with_ports(54321, 80)
        .with_protocol("tcp");

        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.rule_id, Some(2001234));
        assert_eq!(event.dst_port, Some(80));
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
