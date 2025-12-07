use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Represents a banned IP address
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ban {
    pub id: Option<i64>,
    pub ip: IpAddr,
    pub reason: String,
    pub source: BanSource,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub ban_count: u32,
}

impl Ban {
    pub fn new(ip: IpAddr, reason: String, source: BanSource, duration_secs: Option<i64>) -> Self {
        let now = Utc::now();
        let expires_at = duration_secs.map(|d| now + chrono::Duration::seconds(d));

        Self {
            id: None,
            ip,
            reason,
            source,
            created_at: now,
            expires_at,
            ban_count: 1,
        }
    }

    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires) => Utc::now() > expires,
            None => false, // Permanent ban
        }
    }
}

/// Source of the ban
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BanSource {
    Manual,
    Monitor(String), // Service name (ssh, nginx, etc.)
    Import,
}

impl std::fmt::Display for BanSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BanSource::Manual => write!(f, "manual"),
            BanSource::Monitor(service) => write!(f, "monitor:{}", service),
            BanSource::Import => write!(f, "import"),
        }
    }
}

impl std::str::FromStr for BanSource {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "manual" {
            Ok(BanSource::Manual)
        } else if s == "import" {
            Ok(BanSource::Import)
        } else if s.starts_with("monitor:") {
            Ok(BanSource::Monitor(s[8..].to_string()))
        } else {
            Err(format!("Unknown ban source: {}", s))
        }
    }
}

/// Intelligence gathered about an attacker
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackerIntel {
    pub ip: String,
    pub gathered_at: Option<DateTime<Utc>>,

    // GeoIP
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,

    // Network
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    pub isp: Option<String>,
    pub reverse_dns: Option<String>,

    // WHOIS
    pub whois_org: Option<String>,
    pub whois_registrar: Option<String>,
    pub whois_abuse_contact: Option<String>,
    pub whois_raw: Option<String>,

    // Reputation
    pub is_tor_exit: Option<bool>,
    pub is_vpn: Option<bool>,
    pub is_proxy: Option<bool>,
    pub is_hosting: Option<bool>,
    pub threat_score: Option<u32>,

    // Shodan (optional)
    pub open_ports: Option<Vec<u16>>,
    pub hostnames: Option<Vec<String>>,
    pub shodan_tags: Option<Vec<String>>,
}

impl AttackerIntel {
    pub fn new(ip: String) -> Self {
        Self {
            ip,
            gathered_at: Some(Utc::now()),
            ..Default::default()
        }
    }
}

/// A failed authentication attempt or attack event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEvent {
    pub id: Option<i64>,
    pub ip: IpAddr,
    pub timestamp: DateTime<Utc>,
    pub service: String,
    pub event_type: AttackEventType,
    pub details: Option<String>,
    pub log_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AttackEventType {
    FailedAuth,
    InvalidUser,
    BruteForce,
    PortScan,
    Exploit,
    RateLimit,
    SignatureMatch,
    Anomaly,
    ThreatIntel,
    Other(String),
}

impl std::fmt::Display for AttackEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackEventType::FailedAuth => write!(f, "failed_auth"),
            AttackEventType::InvalidUser => write!(f, "invalid_user"),
            AttackEventType::BruteForce => write!(f, "brute_force"),
            AttackEventType::PortScan => write!(f, "port_scan"),
            AttackEventType::Exploit => write!(f, "exploit"),
            AttackEventType::RateLimit => write!(f, "rate_limit"),
            AttackEventType::SignatureMatch => write!(f, "signature_match"),
            AttackEventType::Anomaly => write!(f, "anomaly"),
            AttackEventType::ThreatIntel => write!(f, "threat_intel"),
            AttackEventType::Other(s) => write!(f, "other:{}", s),
        }
    }
}

/// Whitelist entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistEntry {
    pub id: Option<i64>,
    pub ip: IpAddr,
    pub comment: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl WhitelistEntry {
    pub fn new(ip: IpAddr, comment: Option<String>) -> Self {
        Self {
            id: None,
            ip,
            comment,
            created_at: Utc::now(),
        }
    }
}

/// Statistics about attacks
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AttackStats {
    pub total_bans: u64,
    pub active_bans: u64,
    pub total_events: u64,
    pub events_today: u64,
    pub events_this_hour: u64,
    pub top_countries: Vec<(String, u64)>,
    pub top_asns: Vec<(String, u64)>,
    pub events_by_service: Vec<(String, u64)>,
    pub events_by_type: Vec<(String, u64)>,
}

/// Log entry for activity tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityLog {
    pub id: Option<i64>,
    pub timestamp: DateTime<Utc>,
    pub action: ActivityAction,
    pub ip: Option<IpAddr>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivityAction {
    Ban,
    Unban,
    Whitelist,
    UnWhitelist,
    IntelGathered,
    DaemonStart,
    DaemonStop,
    ConfigReload,
}

impl std::fmt::Display for ActivityAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ActivityAction::Ban => write!(f, "BAN"),
            ActivityAction::Unban => write!(f, "UNBAN"),
            ActivityAction::Whitelist => write!(f, "WHITELIST"),
            ActivityAction::UnWhitelist => write!(f, "UNWHITELIST"),
            ActivityAction::IntelGathered => write!(f, "INTEL"),
            ActivityAction::DaemonStart => write!(f, "START"),
            ActivityAction::DaemonStop => write!(f, "STOP"),
            ActivityAction::ConfigReload => write!(f, "RELOAD"),
        }
    }
}

/// Daemon status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub uptime_secs: Option<u64>,
    pub active_bans: u64,
    pub events_processed: u64,
    pub monitored_files: Vec<String>,
}
