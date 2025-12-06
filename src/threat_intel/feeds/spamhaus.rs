//! Spamhaus DROP/EDROP feed implementation
//!
//! Parses Spamhaus block lists for known bad IP ranges.

use std::time::Duration;
use async_trait::async_trait;

use super::{ThreatFeed, FeedType};
use crate::threat_intel::ioc::{Ioc, IocType, ThreatCategory};

/// Spamhaus DROP (Don't Route Or Peer) feed
pub struct SpamhausFeed {
    name: String,
    url: String,
    feed_type: FeedType,
}

impl SpamhausFeed {
    /// Create DROP feed (hijacked netblocks)
    pub fn drop() -> Self {
        Self {
            name: "Spamhaus DROP".to_string(),
            url: "https://www.spamhaus.org/drop/drop.txt".to_string(),
            feed_type: FeedType::SpamhausDrop,
        }
    }

    /// Create EDROP feed (extended DROP)
    pub fn edrop() -> Self {
        Self {
            name: "Spamhaus EDROP".to_string(),
            url: "https://www.spamhaus.org/drop/edrop.txt".to_string(),
            feed_type: FeedType::SpamhausEdrop,
        }
    }

    /// Parse a DROP/EDROP line
    fn parse_line(&self, line: &str) -> Option<Ioc> {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with(';') {
            return None;
        }

        // Format: "cidr ; SBLnnnnn"
        let parts: Vec<&str> = line.split(';').collect();
        if parts.is_empty() {
            return None;
        }

        let cidr = parts[0].trim();

        // Validate CIDR format
        if !cidr.contains('/') {
            return None;
        }

        let sbl_ref = parts.get(1).map(|s| s.trim()).unwrap_or("");

        let mut ioc = Ioc::new(
            IocType::IpCidr,
            cidr.to_string(),
            self.name.clone(),
            ThreatCategory::Spam,
        );

        if !sbl_ref.is_empty() {
            ioc = ioc.with_tag(sbl_ref);
            ioc.references.push(format!("https://www.spamhaus.org/sbl/query/{}", sbl_ref));
        }

        ioc = ioc.with_description("Spamhaus DROP/EDROP - hijacked/leased netblock");

        Some(ioc)
    }
}

#[async_trait]
impl ThreatFeed for SpamhausFeed {
    fn name(&self) -> &str {
        &self.name
    }

    fn feed_type(&self) -> FeedType {
        self.feed_type
    }

    fn update_interval(&self) -> Duration {
        // Spamhaus recommends checking every 12-24 hours
        Duration::from_secs(12 * 60 * 60)
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
    fn test_parse_drop_line() {
        let feed = SpamhausFeed::drop();

        // Valid line
        let ioc = feed.parse_line("1.2.3.0/24 ; SBL123456").unwrap();
        assert_eq!(ioc.value, "1.2.3.0/24");
        assert_eq!(ioc.ioc_type, IocType::IpCidr);
        assert!(ioc.tags.contains(&"SBL123456".to_string()));

        // Comment line
        assert!(feed.parse_line("; This is a comment").is_none());

        // Empty line
        assert!(feed.parse_line("").is_none());

        // Invalid format
        assert!(feed.parse_line("not a cidr").is_none());
    }

    #[test]
    fn test_feed_metadata() {
        let drop = SpamhausFeed::drop();
        assert_eq!(drop.name(), "Spamhaus DROP");
        assert_eq!(drop.feed_type(), FeedType::SpamhausDrop);
        assert!(drop.url().contains("drop.txt"));

        let edrop = SpamhausFeed::edrop();
        assert_eq!(edrop.name(), "Spamhaus EDROP");
        assert_eq!(edrop.feed_type(), FeedType::SpamhausEdrop);
        assert!(edrop.url().contains("edrop.txt"));
    }
}
