//! Indicator of Compromise (IOC) types
//!
//! Defines the core types for threat intelligence indicators.

use std::net::IpAddr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Type of Indicator of Compromise
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IocType {
    /// IPv4 address
    Ipv4,
    /// IPv6 address
    Ipv6,
    /// IP CIDR block
    IpCidr,
    /// Domain name
    Domain,
    /// Full URL
    Url,
    /// MD5 hash
    Md5,
    /// SHA1 hash
    Sha1,
    /// SHA256 hash
    Sha256,
    /// JA3 TLS fingerprint
    Ja3,
    /// JA3S TLS server fingerprint
    Ja3s,
    /// SSL certificate SHA1
    SslCertSha1,
}

impl IocType {
    pub fn as_str(&self) -> &'static str {
        match self {
            IocType::Ipv4 => "ipv4",
            IocType::Ipv6 => "ipv6",
            IocType::IpCidr => "ip_cidr",
            IocType::Domain => "domain",
            IocType::Url => "url",
            IocType::Md5 => "md5",
            IocType::Sha1 => "sha1",
            IocType::Sha256 => "sha256",
            IocType::Ja3 => "ja3",
            IocType::Ja3s => "ja3s",
            IocType::SslCertSha1 => "ssl_cert_sha1",
        }
    }
}

/// Threat category classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    /// Generic malware
    Malware,
    /// Command and Control server
    C2,
    /// Phishing site/infrastructure
    Phishing,
    /// Spam source
    Spam,
    /// Network scanner/reconnaissance
    Scanner,
    /// Botnet infrastructure
    Botnet,
    /// Ransomware
    Ransomware,
    /// Advanced Persistent Threat
    Apt,
    /// Tor exit node
    TorExit,
    /// Anonymous proxy/VPN
    Proxy,
    /// Cryptocurrency miner
    Cryptominer,
    /// Exploit kit
    ExploitKit,
    /// DDoS infrastructure
    DDoS,
    /// Unknown/unclassified
    Unknown,
}

impl ThreatCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatCategory::Malware => "malware",
            ThreatCategory::C2 => "c2",
            ThreatCategory::Phishing => "phishing",
            ThreatCategory::Spam => "spam",
            ThreatCategory::Scanner => "scanner",
            ThreatCategory::Botnet => "botnet",
            ThreatCategory::Ransomware => "ransomware",
            ThreatCategory::Apt => "apt",
            ThreatCategory::TorExit => "tor_exit",
            ThreatCategory::Proxy => "proxy",
            ThreatCategory::Cryptominer => "cryptominer",
            ThreatCategory::ExploitKit => "exploit_kit",
            ThreatCategory::DDoS => "ddos",
            ThreatCategory::Unknown => "unknown",
        }
    }

    /// Get default severity for this category
    pub fn default_severity(&self) -> Severity {
        match self {
            ThreatCategory::Ransomware | ThreatCategory::Apt => Severity::Critical,
            ThreatCategory::C2 | ThreatCategory::ExploitKit => Severity::High,
            ThreatCategory::Malware | ThreatCategory::Botnet | ThreatCategory::Phishing => Severity::High,
            ThreatCategory::DDoS | ThreatCategory::Cryptominer => Severity::Medium,
            ThreatCategory::Scanner | ThreatCategory::Spam => Severity::Low,
            ThreatCategory::TorExit | ThreatCategory::Proxy => Severity::Info,
            ThreatCategory::Unknown => Severity::Low,
        }
    }
}

/// Severity level for threat indicators
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// An Indicator of Compromise with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    /// Type of indicator
    pub ioc_type: IocType,
    /// The indicator value (IP, domain, hash, etc.)
    pub value: String,
    /// Source feed name
    pub source: String,
    /// Threat category
    pub category: ThreatCategory,
    /// Severity level
    pub severity: Severity,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// When first seen in feed
    pub first_seen: DateTime<Utc>,
    /// When last updated
    pub last_updated: DateTime<Utc>,
    /// Optional expiration time
    pub expires_at: Option<DateTime<Utc>>,
    /// Associated tags
    pub tags: Vec<String>,
    /// MITRE ATT&CK technique IDs
    pub mitre_attack: Vec<String>,
    /// Reference URLs
    pub references: Vec<String>,
    /// Optional malware family name
    pub malware_family: Option<String>,
    /// Optional description
    pub description: Option<String>,
}

impl Ioc {
    /// Create a new IOC with minimal required fields
    pub fn new(ioc_type: IocType, value: String, source: String, category: ThreatCategory) -> Self {
        let now = Utc::now();
        Self {
            ioc_type,
            value,
            source,
            category,
            severity: category.default_severity(),
            confidence: 0.8,
            first_seen: now,
            last_updated: now,
            expires_at: None,
            tags: Vec::new(),
            mitre_attack: Vec::new(),
            references: Vec::new(),
            malware_family: None,
            description: None,
        }
    }

    /// Create an IP IOC
    pub fn ip(ip: IpAddr, source: &str, category: ThreatCategory) -> Self {
        let ioc_type = match ip {
            IpAddr::V4(_) => IocType::Ipv4,
            IpAddr::V6(_) => IocType::Ipv6,
        };
        Self::new(ioc_type, ip.to_string(), source.to_string(), category)
    }

    /// Create a domain IOC
    pub fn domain(domain: &str, source: &str, category: ThreatCategory) -> Self {
        Self::new(IocType::Domain, domain.to_lowercase(), source.to_string(), category)
    }

    /// Create a URL IOC
    pub fn url(url: &str, source: &str, category: ThreatCategory) -> Self {
        Self::new(IocType::Url, url.to_string(), source.to_string(), category)
    }

    /// Create a hash IOC (auto-detects type by length)
    pub fn hash(hash: &str, source: &str, category: ThreatCategory) -> Self {
        let hash_lower = hash.to_lowercase();
        let ioc_type = match hash_lower.len() {
            32 => IocType::Md5,
            40 => IocType::Sha1,
            64 => IocType::Sha256,
            _ => IocType::Sha256, // Default
        };
        Self::new(ioc_type, hash_lower, source.to_string(), category)
    }

    /// Create a JA3 IOC
    pub fn ja3(hash: &str, source: &str, category: ThreatCategory) -> Self {
        Self::new(IocType::Ja3, hash.to_lowercase(), source.to_string(), category)
    }

    /// Check if the IOC has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Utc::now() > expires
        } else {
            false
        }
    }

    /// Set expiration
    pub fn with_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set severity
    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Set confidence
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }

    /// Add MITRE ATT&CK reference
    pub fn with_mitre(mut self, technique: &str) -> Self {
        self.mitre_attack.push(technique.to_string());
        self
    }

    /// Set malware family
    pub fn with_malware_family(mut self, family: &str) -> Self {
        self.malware_family = Some(family.to_string());
        self
    }

    /// Set description
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }
}

/// Result of a threat intelligence match
#[derive(Debug, Clone, Serialize)]
pub struct ThreatMatch {
    /// The matched IOC
    pub ioc: Ioc,
    /// The actual value that matched (may differ in case, etc.)
    pub matched_value: String,
    /// Context about where the match occurred
    pub context: MatchContext,
}

/// Context about where a match occurred
#[derive(Debug, Clone, Serialize)]
pub enum MatchContext {
    /// Source IP of a packet/flow
    SourceIp,
    /// Destination IP of a packet/flow
    DestinationIp,
    /// DNS query domain
    DnsQuery,
    /// HTTP host header
    HttpHost,
    /// HTTP URL
    HttpUrl,
    /// TLS SNI
    TlsSni,
    /// TLS JA3 fingerprint
    TlsJa3,
    /// TLS JA3S fingerprint
    TlsJa3s,
    /// File hash
    FileHash,
    /// SSL certificate
    SslCert,
    /// Generic/other
    Other(String),
}

impl MatchContext {
    pub fn as_str(&self) -> &str {
        match self {
            MatchContext::SourceIp => "source_ip",
            MatchContext::DestinationIp => "destination_ip",
            MatchContext::DnsQuery => "dns_query",
            MatchContext::HttpHost => "http_host",
            MatchContext::HttpUrl => "http_url",
            MatchContext::TlsSni => "tls_sni",
            MatchContext::TlsJa3 => "tls_ja3",
            MatchContext::TlsJa3s => "tls_ja3s",
            MatchContext::FileHash => "file_hash",
            MatchContext::SslCert => "ssl_cert",
            MatchContext::Other(s) => s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ioc_creation() {
        let ioc = Ioc::ip(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            "test_feed",
            ThreatCategory::C2,
        );

        assert_eq!(ioc.ioc_type, IocType::Ipv4);
        assert_eq!(ioc.value, "192.168.1.1");
        assert_eq!(ioc.source, "test_feed");
        assert_eq!(ioc.category, ThreatCategory::C2);
        assert_eq!(ioc.severity, Severity::High);
    }

    #[test]
    fn test_hash_type_detection() {
        let md5 = Ioc::hash("d41d8cd98f00b204e9800998ecf8427e", "test", ThreatCategory::Malware);
        assert_eq!(md5.ioc_type, IocType::Md5);

        let sha1 = Ioc::hash("da39a3ee5e6b4b0d3255bfef95601890afd80709", "test", ThreatCategory::Malware);
        assert_eq!(sha1.ioc_type, IocType::Sha1);

        let sha256 = Ioc::hash(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "test",
            ThreatCategory::Malware,
        );
        assert_eq!(sha256.ioc_type, IocType::Sha256);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
