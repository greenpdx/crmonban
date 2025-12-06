//! Threat intelligence feed management
//!
//! Provides infrastructure for fetching and parsing threat feeds.

pub mod spamhaus;
pub mod abuse_ch;
pub mod et;

use std::time::Duration;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::ioc::Ioc;

pub use spamhaus::SpamhausFeed;
pub use abuse_ch::{AbuseChSslFeed, AbuseChUrlhausFeed, AbuseChFeodoFeed};
pub use et::EmergingThreatsFeed;

/// Feed type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeedType {
    SpamhausDrop,
    SpamhausEdrop,
    AbuseChSsl,
    AbuseChUrlhaus,
    AbuseChFeodo,
    EmergingThreatsCompromised,
    AlienVaultOtx,
    Custom,
}

impl FeedType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FeedType::SpamhausDrop => "spamhaus_drop",
            FeedType::SpamhausEdrop => "spamhaus_edrop",
            FeedType::AbuseChSsl => "abuse_ch_ssl",
            FeedType::AbuseChUrlhaus => "abuse_ch_urlhaus",
            FeedType::AbuseChFeodo => "abuse_ch_feodo",
            FeedType::EmergingThreatsCompromised => "et_compromised",
            FeedType::AlienVaultOtx => "otx",
            FeedType::Custom => "custom",
        }
    }
}

/// Trait for threat intelligence feeds
#[async_trait]
pub trait ThreatFeed: Send + Sync {
    /// Human-readable name of the feed
    fn name(&self) -> &str;

    /// Feed type identifier
    fn feed_type(&self) -> FeedType;

    /// Recommended update interval
    fn update_interval(&self) -> Duration;

    /// Fetch and parse the feed, returning IOCs
    async fn fetch(&self, client: &reqwest::Client) -> anyhow::Result<Vec<Ioc>>;

    /// URL for the feed (for display/logging)
    fn url(&self) -> &str;
}

/// Status of a feed
#[derive(Debug, Clone, Serialize)]
pub struct FeedStatus {
    pub name: String,
    pub feed_type: FeedType,
    pub enabled: bool,
    pub last_update: Option<DateTime<Utc>>,
    pub last_success: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub ioc_count: usize,
    pub update_interval: Duration,
}

/// Statistics from a feed update
#[derive(Debug, Clone, Default)]
pub struct UpdateStats {
    pub feeds_updated: usize,
    pub feeds_failed: usize,
    pub iocs_added: usize,
    pub iocs_removed: usize,
    pub duration_ms: u64,
}

/// Feed configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    pub name: String,
    pub feed_type: String,
    pub enabled: bool,
    pub url: Option<String>,
    pub api_key: Option<String>,
    pub update_interval_hours: Option<u64>,
}

impl FeedConfig {
    /// Parse feed type from string
    pub fn parse_feed_type(&self) -> Option<FeedType> {
        match self.feed_type.as_str() {
            "spamhaus_drop" => Some(FeedType::SpamhausDrop),
            "spamhaus_edrop" => Some(FeedType::SpamhausEdrop),
            "abuse_ch_ssl" => Some(FeedType::AbuseChSsl),
            "abuse_ch_urlhaus" => Some(FeedType::AbuseChUrlhaus),
            "abuse_ch_feodo" => Some(FeedType::AbuseChFeodo),
            "et_compromised" => Some(FeedType::EmergingThreatsCompromised),
            "otx" => Some(FeedType::AlienVaultOtx),
            "custom" => Some(FeedType::Custom),
            _ => None,
        }
    }
}

/// Feed manager for coordinating multiple feeds
pub struct FeedManager {
    feeds: Vec<Box<dyn ThreatFeed>>,
    statuses: Vec<FeedStatus>,
    client: reqwest::Client,
}

impl FeedManager {
    /// Create a new feed manager
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .user_agent("crmonban/0.1")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            feeds: Vec::new(),
            statuses: Vec::new(),
            client,
        }
    }

    /// Add a feed to the manager
    pub fn add_feed(&mut self, feed: Box<dyn ThreatFeed>) {
        let status = FeedStatus {
            name: feed.name().to_string(),
            feed_type: feed.feed_type(),
            enabled: true,
            last_update: None,
            last_success: None,
            last_error: None,
            ioc_count: 0,
            update_interval: feed.update_interval(),
        };
        self.statuses.push(status);
        self.feeds.push(feed);
    }

    /// Create default feeds from configuration
    pub fn from_configs(configs: &[FeedConfig]) -> Self {
        let mut manager = Self::new();

        for config in configs {
            if !config.enabled {
                continue;
            }

            if let Some(feed_type) = config.parse_feed_type() {
                match feed_type {
                    FeedType::SpamhausDrop => {
                        manager.add_feed(Box::new(SpamhausFeed::drop()));
                    }
                    FeedType::SpamhausEdrop => {
                        manager.add_feed(Box::new(SpamhausFeed::edrop()));
                    }
                    FeedType::AbuseChSsl => {
                        manager.add_feed(Box::new(AbuseChSslFeed::new()));
                    }
                    FeedType::AbuseChUrlhaus => {
                        manager.add_feed(Box::new(AbuseChUrlhausFeed::new()));
                    }
                    FeedType::AbuseChFeodo => {
                        manager.add_feed(Box::new(AbuseChFeodoFeed::new()));
                    }
                    FeedType::EmergingThreatsCompromised => {
                        manager.add_feed(Box::new(EmergingThreatsFeed::new()));
                    }
                    FeedType::AlienVaultOtx | FeedType::Custom => {
                        // These require additional configuration
                        tracing::debug!("Skipping feed {} - requires additional setup", config.name);
                    }
                }
            }
        }

        manager
    }

    /// Get the number of feeds
    pub fn feed_count(&self) -> usize {
        self.feeds.len()
    }

    /// Fetch a single feed and return IOCs
    pub async fn fetch_feed(&mut self, index: usize) -> anyhow::Result<Vec<Ioc>> {
        if index >= self.feeds.len() {
            anyhow::bail!("Feed index out of bounds");
        }

        let feed = &self.feeds[index];
        let status = &mut self.statuses[index];

        status.last_update = Some(Utc::now());

        match feed.fetch(&self.client).await {
            Ok(iocs) => {
                status.last_success = Some(Utc::now());
                status.last_error = None;
                status.ioc_count = iocs.len();
                tracing::info!(
                    "Fetched {} IOCs from {}",
                    iocs.len(),
                    feed.name()
                );
                Ok(iocs)
            }
            Err(e) => {
                status.last_error = Some(e.to_string());
                tracing::warn!("Failed to fetch {}: {}", feed.name(), e);
                Err(e)
            }
        }
    }

    /// Fetch all feeds and return combined IOCs
    pub async fn fetch_all(&mut self) -> (Vec<Ioc>, UpdateStats) {
        let start = std::time::Instant::now();
        let mut all_iocs = Vec::new();
        let mut stats = UpdateStats::default();

        for i in 0..self.feeds.len() {
            match self.fetch_feed(i).await {
                Ok(iocs) => {
                    stats.iocs_added += iocs.len();
                    stats.feeds_updated += 1;
                    all_iocs.extend(iocs);
                }
                Err(_) => {
                    stats.feeds_failed += 1;
                }
            }
        }

        stats.duration_ms = start.elapsed().as_millis() as u64;
        (all_iocs, stats)
    }

    /// Get status of all feeds
    pub fn get_statuses(&self) -> &[FeedStatus] {
        &self.statuses
    }

    /// Check if any feed needs updating
    pub fn needs_update(&self) -> bool {
        let now = Utc::now();
        for status in &self.statuses {
            if !status.enabled {
                continue;
            }
            match status.last_success {
                None => return true,
                Some(last) => {
                    let elapsed = now.signed_duration_since(last);
                    if elapsed.to_std().unwrap_or(Duration::MAX) > status.update_interval {
                        return true;
                    }
                }
            }
        }
        false
    }
}

impl Default for FeedManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feed_manager_creation() {
        let manager = FeedManager::new();
        assert_eq!(manager.feed_count(), 0);
    }

    #[test]
    fn test_feed_type_parsing() {
        let config = FeedConfig {
            name: "Test".to_string(),
            feed_type: "spamhaus_drop".to_string(),
            enabled: true,
            url: None,
            api_key: None,
            update_interval_hours: None,
        };

        assert_eq!(config.parse_feed_type(), Some(FeedType::SpamhausDrop));
    }
}
