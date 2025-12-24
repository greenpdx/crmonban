//! Threat Intelligence Engine
//!
//! Proactive threat detection using external threat feeds.
//!
//! This module provides:
//! - IOC (Indicator of Compromise) types and caching
//! - Feed management for multiple threat intelligence sources
//! - Integration with packet/flow processing for real-time detection

pub mod ioc;
pub mod cache;
pub mod feeds;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::sync::{mpsc, RwLock as TokioRwLock};
use tracing::{debug, info, warn, error};

pub use ioc::{Ioc, IocType, ThreatCategory, Severity, ThreatMatch, MatchContext};
pub use cache::{IocCache, CacheStats};
pub use feeds::{ThreatFeed, FeedType, FeedManager, FeedConfig, FeedStatus, UpdateStats};

/// Threat intelligence engine
pub struct IntelEngine {
    /// IOC cache for fast lookups
    cache: Arc<RwLock<IocCache>>,
    /// Feed manager (uses tokio RwLock for async compatibility)
    feed_manager: Arc<TokioRwLock<FeedManager>>,
    /// Path for cache persistence
    cache_path: Option<std::path::PathBuf>,
    /// Update task handle
    update_handle: Option<tokio::task::JoinHandle<()>>,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl IntelEngine {
    /// Create a new threat intelligence engine
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(IocCache::new())),
            feed_manager: Arc::new(TokioRwLock::new(FeedManager::new())),
            cache_path: None,
            update_handle: None,
            shutdown_tx: None,
        }
    }

    /// Create from feed configurations
    pub fn from_configs(configs: &[FeedConfig]) -> Self {
        let manager = FeedManager::from_configs(configs);
        Self {
            cache: Arc::new(RwLock::new(IocCache::new())),
            feed_manager: Arc::new(TokioRwLock::new(manager)),
            cache_path: None,
            update_handle: None,
            shutdown_tx: None,
        }
    }

    /// Set cache persistence path
    pub fn with_cache_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.cache_path = Some(path.into());
        self
    }

    /// Add a threat feed
    pub async fn add_feed(&self, feed: Box<dyn ThreatFeed>) {
        self.feed_manager.write().await.add_feed(feed);
    }

    /// Load cache from disk if available
    pub fn load_cache(&self) -> anyhow::Result<()> {
        if let Some(path) = &self.cache_path {
            if path.exists() {
                match IocCache::load_from_disk(path) {
                    Ok(loaded_cache) => {
                        *self.cache.write() = loaded_cache;
                        info!("Loaded IOC cache from disk");
                    }
                    Err(e) => {
                        warn!("Failed to load cache from disk: {}", e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Save cache to disk
    pub fn save_cache(&self) -> anyhow::Result<()> {
        if let Some(path) = &self.cache_path {
            self.cache.read().save_to_disk(path)?;
        }
        Ok(())
    }

    /// Fetch all feeds and update cache
    pub async fn update_feeds(&self) -> UpdateStats {
        let (iocs, stats) = {
            let mut manager = self.feed_manager.write().await;
            manager.fetch_all().await
        };

        // Update cache with new IOCs
        {
            let mut cache = self.cache.write();
            cache.insert_many(iocs);
            cache.cleanup_expired();
        }

        // Save to disk if configured
        if let Err(e) = self.save_cache() {
            warn!("Failed to save cache: {}", e);
        }

        info!(
            "Feed update complete: {} feeds updated, {} failed, {} IOCs added in {}ms",
            stats.feeds_updated, stats.feeds_failed, stats.iocs_added, stats.duration_ms
        );

        stats
    }

    /// Start background update task
    pub fn start_background_updates(&mut self, interval: Duration) {
        let cache = self.cache.clone();
        let feed_manager = self.feed_manager.clone();
        let cache_path = self.cache_path.clone();
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        self.shutdown_tx = Some(shutdown_tx);

        let handle = tokio::spawn(async move {
            let mut update_interval = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = update_interval.tick() => {
                        debug!("Running scheduled feed update");

                        // Perform the async fetch
                        let (iocs, stats) = {
                            let mut manager = feed_manager.write().await;
                            manager.fetch_all().await
                        };

                        {
                            let mut c = cache.write();
                            c.insert_many(iocs);
                            c.cleanup_expired();
                        }

                        if let Some(ref path) = cache_path {
                            if let Err(e) = cache.read().save_to_disk(path) {
                                warn!("Failed to save cache: {}", e);
                            }
                        }

                        info!(
                            "Background update: {} feeds, {} IOCs in {}ms",
                            stats.feeds_updated, stats.iocs_added, stats.duration_ms
                        );
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Stopping background feed updates");
                        break;
                    }
                }
            }
        });

        self.update_handle = Some(handle);
    }

    /// Stop background updates
    pub async fn stop_background_updates(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
        if let Some(handle) = self.update_handle.take() {
            let _ = handle.await;
        }
    }

    /// Check an IP address against threat intelligence
    pub fn check_ip(&self, ip: &IpAddr) -> Option<ThreatMatch> {
        self.cache.read().check_ip(ip)
    }

    /// Check a domain against threat intelligence
    pub fn check_domain(&self, domain: &str) -> Option<ThreatMatch> {
        self.cache.read().check_domain(domain)
    }

    /// Check a URL against threat intelligence
    pub fn check_url(&self, url: &str) -> Option<ThreatMatch> {
        self.cache.read().check_url(url)
    }

    /// Check a hash against threat intelligence
    pub fn check_hash(&self, hash: &str) -> Option<ThreatMatch> {
        self.cache.read().check_hash(hash)
    }

    /// Check a JA3/JA3S fingerprint
    pub fn check_ja3(&self, ja3: &str) -> Option<ThreatMatch> {
        self.cache.read().check_ja3(ja3)
    }

    /// Check SSL certificate hash
    pub fn check_ssl_cert(&self, cert_hash: &str) -> Option<ThreatMatch> {
        self.cache.read().check_ssl_cert(cert_hash)
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> CacheStats {
        self.cache.read().stats()
    }

    /// Get feed statuses
    pub async fn feed_statuses(&self) -> Vec<FeedStatus> {
        self.feed_manager.read().await.get_statuses().to_vec()
    }

    /// Get total IOC count
    pub fn ioc_count(&self) -> usize {
        self.cache.read().total_count()
    }

    /// Check if feeds need updating
    pub async fn needs_update(&self) -> bool {
        self.feed_manager.read().await.needs_update()
    }

    /// Insert an IOC directly (for testing)
    #[cfg(test)]
    pub fn insert_ioc(&self, ioc: Ioc) {
        self.cache.write().insert(ioc);
    }

    /// Insert an IOC directly (public for integration tests)
    pub fn add_ioc(&self, ioc: Ioc) {
        self.cache.write().insert(ioc);
    }

    /// Get all IP-based IOCs (IPv4, IPv6, and CIDR)
    ///
    /// Useful for loading threat intel data into external filters (e.g., ipfilter)
    pub fn get_ip_iocs(&self) -> Vec<Ioc> {
        self.cache.read().get_ip_iocs()
    }
}

// Note: IntelEngine is no longer a pipeline stage. Its IOCs are loaded into
// ipfilter at startup via WorkerThread::load_threat_intel(). This allows
// threat intel data to be used in the fast path of the IpFilter stage.

impl Default for IntelEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for IntelEngine {
    fn drop(&mut self) {
        // Try to save cache on shutdown
        if let Err(e) = self.save_cache() {
            error!("Failed to save cache on shutdown: {}", e);
        }
    }
}

/// Builder for IntelEngine with default feeds
pub struct IntelEngineBuilder {
    feeds: Vec<FeedConfig>,
    cache_path: Option<std::path::PathBuf>,
    auto_update: bool,
    update_interval: Duration,
}

impl IntelEngineBuilder {
    pub fn new() -> Self {
        Self {
            feeds: Vec::new(),
            cache_path: None,
            auto_update: false,
            update_interval: Duration::from_secs(6 * 60 * 60), // 6 hours
        }
    }

    /// Add default public feeds
    pub fn with_default_feeds(mut self) -> Self {
        self.feeds.extend([
            FeedConfig {
                name: "Spamhaus DROP".to_string(),
                feed_type: "spamhaus_drop".to_string(),
                enabled: true,
                url: None,
                api_key: None,
                update_interval_hours: Some(12),
            },
            FeedConfig {
                name: "Spamhaus EDROP".to_string(),
                feed_type: "spamhaus_edrop".to_string(),
                enabled: true,
                url: None,
                api_key: None,
                update_interval_hours: Some(12),
            },
            FeedConfig {
                name: "Abuse.ch Feodo".to_string(),
                feed_type: "abuse_ch_feodo".to_string(),
                enabled: true,
                url: None,
                api_key: None,
                update_interval_hours: Some(1),
            },
            FeedConfig {
                name: "Emerging Threats".to_string(),
                feed_type: "et_compromised".to_string(),
                enabled: true,
                url: None,
                api_key: None,
                update_interval_hours: Some(24),
            },
        ]);
        self
    }

    /// Add a feed configuration
    pub fn with_feed(mut self, config: FeedConfig) -> Self {
        self.feeds.push(config);
        self
    }

    /// Set cache path
    pub fn with_cache_path(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.cache_path = Some(path.into());
        self
    }

    /// Enable auto-update
    pub fn with_auto_update(mut self, interval: Duration) -> Self {
        self.auto_update = true;
        self.update_interval = interval;
        self
    }

    /// Build the engine
    pub fn build(self) -> IntelEngine {
        let mut engine = IntelEngine::from_configs(&self.feeds);

        if let Some(path) = self.cache_path {
            engine = engine.with_cache_path(path);
        }

        engine
    }
}

impl Default for IntelEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_engine_creation() {
        let engine = IntelEngine::new();
        assert_eq!(engine.ioc_count(), 0);
    }

    #[test]
    fn test_manual_ioc_insert() {
        let engine = IntelEngine::new();

        {
            let mut cache = engine.cache.write();
            let ioc = Ioc::ip(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                "test",
                ThreatCategory::C2,
            );
            cache.insert(ioc);
        }

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let result = engine.check_ip(&ip);
        assert!(result.is_some());
        assert_eq!(result.unwrap().ioc.category, ThreatCategory::C2);
    }

    #[tokio::test]
    async fn test_builder() {
        let engine = IntelEngineBuilder::new()
            .with_default_feeds()
            .build();

        // Should have feeds configured
        let statuses = engine.feed_statuses().await;
        assert!(!statuses.is_empty());
    }

    #[test]
    fn test_domain_check() {
        let engine = IntelEngine::new();

        {
            let mut cache = engine.cache.write();
            let ioc = Ioc::domain("evil.com", "test", ThreatCategory::Phishing);
            cache.insert(ioc);
        }

        // Exact match
        assert!(engine.check_domain("evil.com").is_some());

        // Subdomain match
        assert!(engine.check_domain("www.evil.com").is_some());

        // No match
        assert!(engine.check_domain("good.com").is_none());
    }
}
