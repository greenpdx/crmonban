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

impl Severity {
    /// Returns an elevated severity level (one step higher)
    pub fn elevated(&self) -> Severity {
        match self {
            Severity::Info => Severity::Low,
            Severity::Low => Severity::Medium,
            Severity::Medium => Severity::High,
            Severity::High => Severity::Critical,
            Severity::Critical => Severity::Critical,
        }
    }
}

/// Detection type categories
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionType {
    // Signature-based
    SignatureMatch,
    Signature,

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
    ThreatIntel,
    MaliciousIp,
    MaliciousDomain,
    MaliciousUrl,
    MaliciousHash,
    MaliciousJa3,
    C2,
    Phishing,
    Spam,
    TorTraffic,
    VpnTraffic,
    ProxyTraffic,

    // ML/Anomaly
    AnomalyDetection,
    BehaviorAnomaly,
    TrafficAnomaly,

    // Policy violations
    PolicyViolation,
    UnauthorizedAccess,

    // Exploits
    ExploitAttempt,
    Intrusion,
    WebAttack,
    Shellcode,
    Overflow,

    // Web attacks (HTTP)
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    LdapInjection,
    XxeInjection,
    SsrfAttack,
    CsrfAttack,

    // DNS attacks
    DnsTunneling,
    DnsAmplification,
    DnsDga,
    DnsRebinding,
    DnsSpoofing,

    // TLS attacks
    TlsDowngrade,
    TlsHeartbleed,
    TlsWeakCipher,
    TlsSelfSigned,
    TlsExpiredCert,
    TlsKnownMalwareJa3,

    // SSH attacks
    SshBruteForce,
    SshVersionVulnerable,
    SshWeakKeyExchange,
    SshWeakCipher,
    SshWeakMac,
    SshKnownMalwareHashsh,
    SshRootLogin,
    SshInvalidUser,

    // SMTP/Email attacks
    SmtpSpam,
    SmtpPhishing,
    SmtpSpoofing,
    SmtpOpenRelay,
    SmtpAuthBruteForce,
    SmtpMalwareAttachment,
    SmtpSuspiciousSender,
    SmtpMassMailer,
    SmtpHeaderAnomaly,

    // Malware
    Malware,
    MalwareDownload,
    MalwareCallback,
    CnC,

    // Correlation
    CorrelatedThreat,

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
            DetectionType::Signature => write!(f, "signature"),
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
            DetectionType::ThreatIntel => write!(f, "threat_intel"),
            DetectionType::MaliciousIp => write!(f, "malicious_ip"),
            DetectionType::MaliciousDomain => write!(f, "malicious_domain"),
            DetectionType::MaliciousUrl => write!(f, "malicious_url"),
            DetectionType::MaliciousHash => write!(f, "malicious_hash"),
            DetectionType::MaliciousJa3 => write!(f, "malicious_ja3"),
            DetectionType::C2 => write!(f, "c2"),
            DetectionType::Phishing => write!(f, "phishing"),
            DetectionType::Spam => write!(f, "spam"),
            DetectionType::TorTraffic => write!(f, "tor_traffic"),
            DetectionType::VpnTraffic => write!(f, "vpn_traffic"),
            DetectionType::ProxyTraffic => write!(f, "proxy_traffic"),
            DetectionType::AnomalyDetection => write!(f, "anomaly_detection"),
            DetectionType::BehaviorAnomaly => write!(f, "behavior_anomaly"),
            DetectionType::TrafficAnomaly => write!(f, "traffic_anomaly"),
            DetectionType::PolicyViolation => write!(f, "policy_violation"),
            DetectionType::UnauthorizedAccess => write!(f, "unauthorized_access"),
            DetectionType::ExploitAttempt => write!(f, "exploit_attempt"),
            DetectionType::Intrusion => write!(f, "intrusion"),
            DetectionType::WebAttack => write!(f, "web_attack"),
            DetectionType::Shellcode => write!(f, "shellcode"),
            DetectionType::Overflow => write!(f, "overflow"),
            DetectionType::SqlInjection => write!(f, "sql_injection"),
            DetectionType::Xss => write!(f, "xss"),
            DetectionType::PathTraversal => write!(f, "path_traversal"),
            DetectionType::CommandInjection => write!(f, "command_injection"),
            DetectionType::LdapInjection => write!(f, "ldap_injection"),
            DetectionType::XxeInjection => write!(f, "xxe_injection"),
            DetectionType::SsrfAttack => write!(f, "ssrf_attack"),
            DetectionType::CsrfAttack => write!(f, "csrf_attack"),
            // DNS attacks
            DetectionType::DnsTunneling => write!(f, "dns_tunneling"),
            DetectionType::DnsAmplification => write!(f, "dns_amplification"),
            DetectionType::DnsDga => write!(f, "dns_dga"),
            DetectionType::DnsRebinding => write!(f, "dns_rebinding"),
            DetectionType::DnsSpoofing => write!(f, "dns_spoofing"),
            // TLS attacks
            DetectionType::TlsDowngrade => write!(f, "tls_downgrade"),
            DetectionType::TlsHeartbleed => write!(f, "tls_heartbleed"),
            DetectionType::TlsWeakCipher => write!(f, "tls_weak_cipher"),
            DetectionType::TlsSelfSigned => write!(f, "tls_self_signed"),
            DetectionType::TlsExpiredCert => write!(f, "tls_expired_cert"),
            DetectionType::TlsKnownMalwareJa3 => write!(f, "tls_known_malware_ja3"),
            // SSH attacks
            DetectionType::SshBruteForce => write!(f, "ssh_brute_force"),
            DetectionType::SshVersionVulnerable => write!(f, "ssh_version_vulnerable"),
            DetectionType::SshWeakKeyExchange => write!(f, "ssh_weak_kex"),
            DetectionType::SshWeakCipher => write!(f, "ssh_weak_cipher"),
            DetectionType::SshWeakMac => write!(f, "ssh_weak_mac"),
            DetectionType::SshKnownMalwareHashsh => write!(f, "ssh_known_malware_hassh"),
            DetectionType::SshRootLogin => write!(f, "ssh_root_login"),
            DetectionType::SshInvalidUser => write!(f, "ssh_invalid_user"),
            // SMTP attacks
            DetectionType::SmtpSpam => write!(f, "smtp_spam"),
            DetectionType::SmtpPhishing => write!(f, "smtp_phishing"),
            DetectionType::SmtpSpoofing => write!(f, "smtp_spoofing"),
            DetectionType::SmtpOpenRelay => write!(f, "smtp_open_relay"),
            DetectionType::SmtpAuthBruteForce => write!(f, "smtp_auth_brute_force"),
            DetectionType::SmtpMalwareAttachment => write!(f, "smtp_malware_attachment"),
            DetectionType::SmtpSuspiciousSender => write!(f, "smtp_suspicious_sender"),
            DetectionType::SmtpMassMailer => write!(f, "smtp_mass_mailer"),
            DetectionType::SmtpHeaderAnomaly => write!(f, "smtp_header_anomaly"),
            DetectionType::Malware => write!(f, "malware"),
            DetectionType::MalwareDownload => write!(f, "malware_download"),
            DetectionType::MalwareCallback => write!(f, "malware_callback"),
            DetectionType::CnC => write!(f, "cnc"),
            DetectionType::CorrelatedThreat => write!(f, "correlated_threat"),
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

// ============================================================================
// Detection Sub-Types
// ============================================================================

/// Macro to define sub-type enums for each detection type.
/// Automatically includes an `Unknown(String)` variant for extensibility.
#[macro_export]
macro_rules! define_subtype {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )*
            /// Unknown or unrecognized sub-type
            Unknown(String),
        }

        impl Default for $name {
            fn default() -> Self {
                Self::Unknown(String::new())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(Self::$variant => write!(f, "{}", stringify!($variant).to_lowercase()),)*
                    Self::Unknown(s) if s.is_empty() => write!(f, "unknown"),
                    Self::Unknown(s) => write!(f, "unknown:{}", s),
                }
            }
        }
    };
}

define_subtype! {
    /// Sub-types for scan detection
    pub enum ScanSubType {
        /// TCP SYN scan
        SynScan,
        /// TCP ACK scan
        AckScan,
        /// UDP scan
        UdpScan,
        /// TCP FIN scan
        FinScan,
        /// TCP XMAS scan (FIN+PSH+URG)
        XmasScan,
        /// TCP NULL scan
        NullScan,
        /// Slow/stealthy scan
        SlowScan,
        /// Service version scan
        VersionScan,
        /// OS fingerprinting
        OsScan,
        /// Host discovery / ping sweep
        PingSweep,
    }
}

define_subtype! {
    /// Sub-types for malware detection
    pub enum MalwareSubType {
        /// Trojan horse
        Trojan,
        /// Ransomware
        Ransomware,
        /// Self-replicating worm
        Worm,
        /// Rootkit
        Rootkit,
        /// Spyware
        Spyware,
        /// Malware dropper
        Dropper,
        /// Adware
        Adware,
        /// Cryptominer
        Cryptominer,
        /// Botnet client
        Bot,
        /// Keylogger
        Keylogger,
    }
}

define_subtype! {
    /// Sub-types for exploit detection
    pub enum ExploitSubType {
        /// Buffer overflow
        BufferOverflow,
        /// SQL injection
        SqlInjection,
        /// Cross-site scripting
        Xss,
        /// Remote code execution
        Rce,
        /// Local file inclusion
        Lfi,
        /// Remote file inclusion
        Rfi,
        /// Command injection
        CommandInjection,
        /// Path traversal
        PathTraversal,
        /// Deserialization attack
        Deserialization,
        /// SSRF
        Ssrf,
        /// XXE injection
        Xxe,
    }
}

define_subtype! {
    /// Sub-types for DoS/DDoS detection
    pub enum DosSubType {
        /// SYN flood
        SynFlood,
        /// UDP flood
        UdpFlood,
        /// ICMP flood
        IcmpFlood,
        /// HTTP flood
        HttpFlood,
        /// Slowloris attack
        Slowloris,
        /// DNS amplification
        DnsAmplification,
        /// NTP amplification
        NtpAmplification,
        /// SSDP amplification
        SsdpAmplification,
        /// Connection exhaustion
        ConnectionExhaustion,
    }
}

define_subtype! {
    /// Sub-types for protocol anomalies
    pub enum ProtocolSubType {
        /// Malformed header
        MalformedHeader,
        /// Invalid flags
        InvalidFlags,
        /// Invalid sequence
        InvalidSequence,
        /// Fragmentation anomaly
        FragmentAnomaly,
        /// Checksum error
        ChecksumError,
        /// Protocol violation
        ProtocolViolation,
        /// Unexpected option
        UnexpectedOption,
    }
}

define_subtype! {
    /// Sub-types for C2/beaconing detection
    pub enum C2SubType {
        /// HTTP-based C2
        HttpC2,
        /// DNS-based C2
        DnsC2,
        /// HTTPS/TLS C2
        TlsC2,
        /// Custom protocol C2
        CustomProtocol,
        /// Domain generation algorithm
        Dga,
        /// Periodic beaconing
        Beacon,
        /// Data exfiltration channel
        Exfil,
    }
}

define_subtype! {
    /// Sub-types for anomaly/behavioral detection
    pub enum AnomalySubType {
        /// Traffic volume anomaly
        VolumeAnomaly,
        /// Timing anomaly
        TimingAnomaly,
        /// Geographic anomaly
        GeoAnomaly,
        /// Protocol usage anomaly
        ProtocolAnomaly,
        /// Connection pattern anomaly
        ConnectionAnomaly,
        /// Data transfer anomaly
        DataAnomaly,
        /// User behavior anomaly
        BehaviorAnomaly,
    }
}

define_subtype! {
    /// Sub-types for threat intelligence matches
    pub enum ThreatIntelSubType {
        /// Known malicious IP
        MaliciousIp,
        /// Known malicious domain
        MaliciousDomain,
        /// Known malicious URL
        MaliciousUrl,
        /// Known malicious file hash
        MaliciousHash,
        /// Known malicious JA3 fingerprint
        MaliciousJa3,
        /// Known malicious SSL cert
        MaliciousCert,
        /// Blocklisted ASN
        BlocklistedAsn,
    }
}

/// Custom sub-type info for stage-defined attack types.
/// Allows stages to define their own sub-types without modifying core enums.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomSubType {
    /// Category grouping (e.g., "protocol_analyzer", "ml_detector")
    pub category: String,
    /// Sub-type identifier (e.g., "tls_downgrade", "anomalous_beacon")
    pub subtype: String,
    /// Human-readable name
    pub name: String,
    /// Description of the attack/detection
    pub description: String,
    /// Suggested severity for this sub-type
    pub severity: Severity,
    /// Suggested action for this sub-type
    pub action: Option<DetectionAction>,
}

impl CustomSubType {
    /// Create a new custom sub-type
    pub fn new(
        category: impl Into<String>,
        subtype: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            category: category.into(),
            subtype: subtype.into(),
            name: name.into(),
            description: description.into(),
            severity,
            action: None,
        }
    }

    /// Set the suggested action
    pub async fn with_action(mut self, action: DetectionAction) -> Self {
        self.action = Some(action);
        self
    }
}

impl std::fmt::Display for CustomSubType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.category, self.subtype)
    }
}

/// Wrapper enum for all detection sub-types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "category", content = "subtype")]
pub enum DetectionSubType {
    /// Scan sub-types (port scan, network scan)
    Scan(ScanSubType),
    /// Malware sub-types
    Malware(MalwareSubType),
    /// Exploit sub-types
    Exploit(ExploitSubType),
    /// DoS/DDoS sub-types
    Dos(DosSubType),
    /// Protocol anomaly sub-types
    Protocol(ProtocolSubType),
    /// C2/beaconing sub-types
    C2(C2SubType),
    /// Anomaly/behavioral sub-types
    Anomaly(AnomalySubType),
    /// Threat intelligence sub-types
    ThreatIntel(ThreatIntelSubType),
    /// Custom stage-defined sub-type
    Custom(CustomSubType),
    /// No sub-type specified
    None,
}

impl Default for DetectionSubType {
    fn default() -> Self {
        Self::None
    }
}

impl std::fmt::Display for DetectionSubType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Scan(s) => write!(f, "scan:{}", s),
            Self::Malware(s) => write!(f, "malware:{}", s),
            Self::Exploit(s) => write!(f, "exploit:{}", s),
            Self::Dos(s) => write!(f, "dos:{}", s),
            Self::Protocol(s) => write!(f, "protocol:{}", s),
            Self::C2(s) => write!(f, "c2:{}", s),
            Self::Anomaly(s) => write!(f, "anomaly:{}", s),
            Self::ThreatIntel(s) => write!(f, "threat_intel:{}", s),
            Self::Custom(c) => write!(f, "custom:{}", c),
            Self::None => write!(f, "none"),
        }
    }
}

impl From<CustomSubType> for DetectionSubType {
    fn from(custom: CustomSubType) -> Self {
        Self::Custom(custom)
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
    /// Detection sub-type (more specific classification)
    pub subtype: DetectionSubType,
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
    /// Destination IP (primary target)
    pub dst_ip: IpAddr,
    /// Additional target IPs (for scans/sweeps targeting multiple hosts)
    pub target_ips: Vec<IpAddr>,
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

    // ML/Vector-based detection
    /// Feature vector used for ML-based detection (enables baseline comparison, clustering, explainability)
    pub feature_vector: Option<Vec<f32>>,

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
            subtype: DetectionSubType::None,
            severity,
            confidence: 1.0,
            detector: "unknown".to_string(),
            rule_id: None,
            rule_name: None,
            classtype: None,
            src_ip,
            dst_ip,
            target_ips: Vec::new(),
            src_port: None,
            dst_port: None,
            protocol: None,
            flow_id: None,
            message,
            details: HashMap::new(),
            feature_vector: None,
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

    /// Set detection sub-type
    pub fn with_subtype(mut self, subtype: DetectionSubType) -> Self {
        self.subtype = subtype;
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

    /// Set target IPs (for scans/sweeps targeting multiple hosts)
    pub fn with_target_ips(mut self, target_ips: Vec<IpAddr>) -> Self {
        self.target_ips = target_ips;
        self
    }

    /// Add a target IP
    pub fn add_target_ip(mut self, ip: IpAddr) -> Self {
        self.target_ips.push(ip);
        self
    }

    /// Set feature vector (for ML-based detection)
    pub fn with_feature_vector(mut self, vector: Vec<f32>) -> Self {
        self.feature_vector = Some(vector);
        self
    }

    /// Set feature vector from fixed-size array
    pub fn with_feature_array<const N: usize>(mut self, array: [f32; N]) -> Self {
        self.feature_vector = Some(array.to_vec());
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

    #[test]
    fn test_detection_subtype() {
        let event = DetectionEvent::new(
            DetectionType::PortScan,
            Severity::Medium,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "SYN scan detected".to_string(),
        )
        .with_subtype(DetectionSubType::Scan(ScanSubType::SynScan));

        assert_eq!(event.subtype, DetectionSubType::Scan(ScanSubType::SynScan));
        assert_eq!(event.subtype.to_string(), "scan:synscan");
    }

    #[test]
    fn test_subtype_unknown_variant() {
        let subtype = ScanSubType::Unknown("custom_scan".to_string());
        assert_eq!(subtype.to_string(), "unknown:custom_scan");

        let empty_unknown = ScanSubType::Unknown(String::new());
        assert_eq!(empty_unknown.to_string(), "unknown");
    }

    #[tokio::test]
    async fn test_custom_subtype() {
        // Stage defines a custom sub-type
        let custom = CustomSubType::new(
            "protocol_analyzer",
            "tls_downgrade",
            "TLS Downgrade Attack",
            "Detected attempt to downgrade TLS version",
            Severity::High,
        )
        .with_action(DetectionAction::Alert)
        .await;

        assert_eq!(custom.category, "protocol_analyzer");
        assert_eq!(custom.subtype, "tls_downgrade");
        assert_eq!(custom.severity, Severity::High);
        assert_eq!(custom.action, Some(DetectionAction::Alert));
        assert_eq!(custom.to_string(), "protocol_analyzer:tls_downgrade");

        // Use in DetectionEvent
        let event = DetectionEvent::new(
            DetectionType::Custom("tls_attack".to_string()),
            Severity::High,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "TLS downgrade detected".to_string(),
        )
        .with_subtype(DetectionSubType::Custom(custom.clone()));

        assert_eq!(
            event.subtype,
            DetectionSubType::Custom(custom.clone())
        );
        assert_eq!(
            event.subtype.to_string(),
            "custom:protocol_analyzer:tls_downgrade"
        );
    }

    #[test]
    fn test_custom_subtype_from_impl() {
        let custom = CustomSubType::new(
            "ml_detector",
            "anomalous_pattern",
            "Anomalous Pattern",
            "ML model detected anomalous traffic pattern",
            Severity::Medium,
        );

        // Test From<CustomSubType> for DetectionSubType
        let subtype: DetectionSubType = custom.into();
        assert!(matches!(subtype, DetectionSubType::Custom(_)));
    }
}
