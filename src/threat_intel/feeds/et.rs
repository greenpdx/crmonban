//! Emerging Threats feed implementation
//!
//! Parses the ET compromised IPs list.

use std::time::Duration;
use async_trait::async_trait;

use super::{ThreatFeed, FeedType};
use crate::threat_intel::ioc::{Ioc, IocType, ThreatCategory};

/// Emerging Threats Compromised IPs feed
pub struct EmergingThreatsFeed {
    url: String,
}

impl EmergingThreatsFeed {
    pub fn new() -> Self {
        Self {
            url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt".to_string(),
        }
    }

    fn parse_line(&self, line: &str) -> Option<Ioc> {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            return None;
        }

        // Format: just an IP per line
        let ip = line.split_whitespace().next()?;

        // Validate IP format
        if ip.parse::<std::net::IpAddr>().is_err() {
            return None;
        }

        let ioc_type = if ip.contains(':') {
            IocType::Ipv6
        } else {
            IocType::Ipv4
        };

        let ioc = Ioc::new(
            ioc_type,
            ip.to_string(),
            "EmergingThreats".to_string(),
            ThreatCategory::Botnet,
        )
        .with_description("Known compromised host");

        Some(ioc)
    }
}

impl Default for EmergingThreatsFeed {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ThreatFeed for EmergingThreatsFeed {
    fn name(&self) -> &str {
        "Emerging Threats Compromised"
    }

    fn feed_type(&self) -> FeedType {
        FeedType::EmergingThreatsCompromised
    }

    fn update_interval(&self) -> Duration {
        Duration::from_secs(24 * 60 * 60) // Daily
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ip() {
        let feed = EmergingThreatsFeed::new();

        // Valid IPv4
        let ioc = feed.parse_line("192.168.1.1").unwrap();
        assert_eq!(ioc.value, "192.168.1.1");
        assert_eq!(ioc.ioc_type, IocType::Ipv4);
        assert_eq!(ioc.category, ThreatCategory::Botnet);

        // Valid IPv6
        let ioc = feed.parse_line("2001:db8::1").unwrap();
        assert_eq!(ioc.ioc_type, IocType::Ipv6);

        // Comment
        assert!(feed.parse_line("# comment").is_none());

        // Empty
        assert!(feed.parse_line("").is_none());

        // Invalid
        assert!(feed.parse_line("not.an.ip").is_none());
    }

    #[test]
    fn test_feed_metadata() {
        let feed = EmergingThreatsFeed::new();
        assert_eq!(feed.name(), "Emerging Threats Compromised");
        assert_eq!(feed.feed_type(), FeedType::EmergingThreatsCompromised);
        assert!(feed.url().contains("compromised-ips"));
    }
}
