//! Abuse.ch feed implementations
//!
//! Parsers for SSL blacklist, URLhaus, and Feodo tracker feeds.

use std::time::Duration;
use async_trait::async_trait;

use super::{ThreatFeed, FeedType};
use crate::threat_intel::ioc::{Ioc, IocType, ThreatCategory, Severity};

/// Abuse.ch SSL Blacklist feed
pub struct AbuseChSslFeed {
    url: String,
}

impl AbuseChSslFeed {
    pub fn new() -> Self {
        Self {
            url: "https://sslbl.abuse.ch/blacklist/sslblacklist.csv".to_string(),
        }
    }

    fn parse_line(&self, line: &str) -> Option<Ioc> {
        let line = line.trim();

        // Skip comments and header
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        // CSV format: Listingdate,SHA1,Listingreason
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() < 3 {
            return None;
        }

        let sha1 = parts[1].trim();
        let reason = parts[2].trim();

        // Validate SHA1 format (40 hex chars)
        if sha1.len() != 40 || !sha1.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }

        let category = if reason.to_lowercase().contains("c2") || reason.to_lowercase().contains("c&c") {
            ThreatCategory::C2
        } else if reason.to_lowercase().contains("botnet") {
            ThreatCategory::Botnet
        } else {
            ThreatCategory::Malware
        };

        let mut ioc = Ioc::new(
            IocType::SslCertSha1,
            sha1.to_lowercase(),
            "abuse.ch SSLBL".to_string(),
            category,
        );

        ioc = ioc.with_description(reason);

        // Extract malware family if present
        if let Some(family) = extract_malware_family(reason) {
            ioc = ioc.with_malware_family(&family);
        }

        Some(ioc)
    }
}

impl Default for AbuseChSslFeed {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ThreatFeed for AbuseChSslFeed {
    fn name(&self) -> &str {
        "Abuse.ch SSL Blacklist"
    }

    fn feed_type(&self) -> FeedType {
        FeedType::AbuseChSsl
    }

    fn update_interval(&self) -> Duration {
        Duration::from_secs(6 * 60 * 60) // 6 hours
    }

    async fn fetch(&self, client: &reqwest::Client) -> anyhow::Result<Vec<Ioc>> {
        let response = client
            .get(&self.url)
            .send()
            .await?
            .error_for_status()?;

        let text = response.text().await?;
        let iocs: Vec<Ioc> = text
            .lines()
            .filter_map(|line| self.parse_line(line))
            .collect();

        Ok(iocs)
    }

    fn url(&self) -> &str {
        &self.url
    }
}

/// Abuse.ch URLhaus feed
pub struct AbuseChUrlhausFeed {
    url: String,
}

impl AbuseChUrlhausFeed {
    pub fn new() -> Self {
        Self {
            url: "https://urlhaus.abuse.ch/downloads/csv_online/".to_string(),
        }
    }

    fn parse_line(&self, line: &str) -> Option<Ioc> {
        let line = line.trim();

        // Skip comments and header
        if line.is_empty() || line.starts_with('#') || line.starts_with('"') && line.contains("id") {
            return None;
        }

        // CSV format: "id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"
        // Simple parsing - URLs may contain commas so we need to handle quoted fields
        let fields = parse_csv_line(line);
        if fields.len() < 6 {
            return None;
        }

        let url = &fields[2];
        let threat = &fields[5];

        if url.is_empty() {
            return None;
        }

        let category = match threat.to_lowercase().as_str() {
            "malware_download" => ThreatCategory::Malware,
            "phishing" => ThreatCategory::Phishing,
            _ => ThreatCategory::Malware,
        };

        let mut ioc = Ioc::new(
            IocType::Url,
            url.clone(),
            "abuse.ch URLhaus".to_string(),
            category,
        );

        // Tags field
        if fields.len() > 6 && !fields[6].is_empty() {
            for tag in fields[6].split(',') {
                let tag = tag.trim();
                if !tag.is_empty() {
                    ioc = ioc.with_tag(tag);
                    // Check for malware family
                    if let Some(family) = extract_malware_family(tag) {
                        ioc = ioc.with_malware_family(&family);
                    }
                }
            }
        }

        Some(ioc)
    }
}

impl Default for AbuseChUrlhausFeed {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ThreatFeed for AbuseChUrlhausFeed {
    fn name(&self) -> &str {
        "Abuse.ch URLhaus"
    }

    fn feed_type(&self) -> FeedType {
        FeedType::AbuseChUrlhaus
    }

    fn update_interval(&self) -> Duration {
        Duration::from_secs(5 * 60) // 5 minutes - URLhaus updates frequently
    }

    async fn fetch(&self, client: &reqwest::Client) -> anyhow::Result<Vec<Ioc>> {
        let response = client
            .get(&self.url)
            .send()
            .await?
            .error_for_status()?;

        let text = response.text().await?;
        let iocs: Vec<Ioc> = text
            .lines()
            .filter_map(|line| self.parse_line(line))
            .collect();

        Ok(iocs)
    }

    fn url(&self) -> &str {
        &self.url
    }
}

/// Abuse.ch Feodo Tracker feed (banking trojans)
pub struct AbuseChFeodoFeed {
    url: String,
}

impl AbuseChFeodoFeed {
    pub fn new() -> Self {
        Self {
            url: "https://feodotracker.abuse.ch/downloads/ipblocklist.csv".to_string(),
        }
    }

    fn parse_line(&self, line: &str) -> Option<Ioc> {
        let line = line.trim();

        // Skip comments and header
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        // CSV format: first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() < 6 {
            return None;
        }

        let ip = parts[1].trim();
        let port = parts[2].trim();
        let malware = parts[5].trim();

        // Validate IP format
        if ip.parse::<std::net::IpAddr>().is_err() {
            return None;
        }

        let ioc_type = if ip.contains(':') {
            IocType::Ipv6
        } else {
            IocType::Ipv4
        };

        let mut ioc = Ioc::new(
            ioc_type,
            ip.to_string(),
            "abuse.ch Feodo".to_string(),
            ThreatCategory::Botnet,
        );

        ioc = ioc.with_severity(Severity::High);
        ioc = ioc.with_tag(&format!("port:{}", port));

        if !malware.is_empty() {
            ioc = ioc.with_malware_family(malware);
            ioc = ioc.with_tag(malware);
        }

        ioc = ioc.with_description("Banking trojan C2 server");

        Some(ioc)
    }
}

impl Default for AbuseChFeodoFeed {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ThreatFeed for AbuseChFeodoFeed {
    fn name(&self) -> &str {
        "Abuse.ch Feodo Tracker"
    }

    fn feed_type(&self) -> FeedType {
        FeedType::AbuseChFeodo
    }

    fn update_interval(&self) -> Duration {
        Duration::from_secs(30 * 60) // 30 minutes
    }

    async fn fetch(&self, client: &reqwest::Client) -> anyhow::Result<Vec<Ioc>> {
        let response = client
            .get(&self.url)
            .send()
            .await?
            .error_for_status()?;

        let text = response.text().await?;
        let iocs: Vec<Ioc> = text
            .lines()
            .filter_map(|line| self.parse_line(line))
            .collect();

        Ok(iocs)
    }

    fn url(&self) -> &str {
        &self.url
    }
}

/// Simple CSV line parser that handles quoted fields
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in line.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
            }
            ',' if !in_quotes => {
                fields.push(current.clone());
                current.clear();
            }
            _ => {
                current.push(ch);
            }
        }
    }
    fields.push(current);
    fields
}

/// Extract malware family from description/tag
fn extract_malware_family(text: &str) -> Option<String> {
    let text_lower = text.to_lowercase();

    let known_families = [
        "emotet", "trickbot", "dridex", "qakbot", "qbot", "icedid", "bazarloader",
        "cobalt strike", "cobaltstrike", "raccoon", "redline", "vidar", "lokibot",
        "formbook", "agenttesla", "remcos", "njrat", "asyncrat", "nanocore",
        "darkcomet", "netwire", "bitrat", "dcrat", "warzone", "orcus",
    ];

    for family in known_families {
        if text_lower.contains(family) {
            return Some(family.replace(' ', "_"));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssl_feed_parse() {
        let feed = AbuseChSslFeed::new();

        // Valid line
        let ioc = feed.parse_line("2024-01-01,0123456789abcdef0123456789abcdef01234567,Emotet C2").unwrap();
        assert_eq!(ioc.ioc_type, IocType::SslCertSha1);
        assert_eq!(ioc.category, ThreatCategory::C2);
        assert_eq!(ioc.malware_family, Some("emotet".to_string()));

        // Comment
        assert!(feed.parse_line("# comment").is_none());

        // Invalid SHA1
        assert!(feed.parse_line("2024-01-01,invalid,test").is_none());
    }

    #[test]
    fn test_feodo_feed_parse() {
        let feed = AbuseChFeodoFeed::new();

        // Valid line
        let ioc = feed.parse_line("2024-01-01 00:00:00,192.168.1.1,443,online,2024-01-01,Emotet").unwrap();
        assert_eq!(ioc.value, "192.168.1.1");
        assert_eq!(ioc.ioc_type, IocType::Ipv4);
        assert_eq!(ioc.category, ThreatCategory::Botnet);
        assert!(ioc.tags.contains(&"port:443".to_string()));
        assert!(ioc.tags.contains(&"Emotet".to_string()));

        // Comment
        assert!(feed.parse_line("# comment").is_none());
    }

    #[test]
    fn test_csv_parser() {
        let line = r#""1","2024-01-01","http://evil.com/malware","online","2024-01-01","malware_download","emotet","link","reporter""#;
        let fields = parse_csv_line(line);
        assert_eq!(fields.len(), 9);
        assert_eq!(fields[2], "http://evil.com/malware");
        assert_eq!(fields[5], "malware_download");
    }

    #[test]
    fn test_malware_family_extraction() {
        assert_eq!(extract_malware_family("Emotet C2"), Some("emotet".to_string()));
        assert_eq!(extract_malware_family("TrickBot loader"), Some("trickbot".to_string()));
        assert_eq!(extract_malware_family("Cobalt Strike beacon"), Some("cobalt_strike".to_string()));
        assert_eq!(extract_malware_family("unknown malware"), None);
    }
}
