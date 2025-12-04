//! Shared whitelist support
//!
//! Allows crmonban to read whitelist entries from multiple sources:
//! - Local SQLite database (crmonban's own whitelist)
//! - Zone-based implicit whitelists
//! - External whitelist files
//! - D-Bus queries to other services (requires `crrouter` feature)
//!
//! This enables a unified whitelist across the system.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::zones::ZoneManager;

/// Whitelist source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum WhitelistSource {
    /// Local database (default crmonban whitelist)
    Database,

    /// Zone-based whitelist (from ZoneManager)
    Zones,

    /// External file (one IP per line, supports comments with #)
    File {
        path: PathBuf,
        /// Watch for changes
        #[serde(default)]
        watch: bool,
    },

    /// IP networks (CIDR notation)
    Networks {
        networks: Vec<String>,
    },

    /// Query external firewall daemon via D-Bus (requires `crrouter` feature)
    #[cfg(feature = "crrouter")]
    ExternalFirewall,
}

/// Shared whitelist configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SharedWhitelistConfig {
    /// Enable shared whitelist
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Whitelist sources
    #[serde(default)]
    pub sources: Vec<WhitelistSource>,

    /// Cache TTL in seconds (how often to refresh external sources)
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
}

fn default_true() -> bool {
    true
}

fn default_cache_ttl() -> u64 {
    300 // 5 minutes
}

/// Cached whitelist entry
#[derive(Debug, Clone)]
struct CachedEntry {
    ip: IpAddr,
    source: String,
    expires_at: std::time::Instant,
}

/// Shared whitelist manager
pub struct SharedWhitelist {
    config: SharedWhitelistConfig,
    zone_manager: Option<Arc<RwLock<ZoneManager>>>,
    /// Cached IPs from external sources
    cache: Arc<RwLock<HashSet<IpAddr>>>,
    /// Network prefixes for fast matching
    networks: Vec<ipnetwork::IpNetwork>,
    /// Last cache refresh time
    last_refresh: Arc<RwLock<std::time::Instant>>,
}

impl SharedWhitelist {
    /// Create a new shared whitelist manager
    pub fn new(config: SharedWhitelistConfig) -> Self {
        let mut networks = Vec::new();

        // Parse network sources
        for source in &config.sources {
            if let WhitelistSource::Networks { networks: nets } = source {
                for net in nets {
                    if let Ok(network) = net.parse::<ipnetwork::IpNetwork>() {
                        networks.push(network);
                    } else {
                        warn!("Invalid network in whitelist: {}", net);
                    }
                }
            }
        }

        Self {
            config,
            zone_manager: None,
            cache: Arc::new(RwLock::new(HashSet::new())),
            networks,
            last_refresh: Arc::new(RwLock::new(std::time::Instant::now())),
        }
    }

    /// Set the zone manager for zone-based whitelisting
    pub fn set_zone_manager(&mut self, manager: Arc<RwLock<ZoneManager>>) {
        self.zone_manager = Some(manager);
    }

    /// Check if an IP is whitelisted (any source)
    pub async fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Check network prefixes first (fastest)
        for network in &self.networks {
            if network.contains(*ip) {
                debug!("IP {} whitelisted via network {}", ip, network);
                return true;
            }
        }

        // Check zone-based whitelist
        if let Some(ref zone_manager) = self.zone_manager {
            let manager = zone_manager.read().await;
            if manager.is_trusted(ip) {
                debug!("IP {} whitelisted via zone", ip);
                return true;
            }
        }

        // Check cache
        {
            let cache = self.cache.read().await;
            if cache.contains(ip) {
                debug!("IP {} whitelisted via cache", ip);
                return true;
            }
        }

        false
    }

    /// Refresh the whitelist cache from external sources
    pub async fn refresh(&self) -> anyhow::Result<()> {
        let now = std::time::Instant::now();

        {
            let last = self.last_refresh.read().await;
            if now.duration_since(*last).as_secs() < self.config.cache_ttl_secs {
                return Ok(());
            }
        }

        info!("Refreshing shared whitelist cache");

        let mut new_cache = HashSet::new();

        for source in &self.config.sources {
            match source {
                WhitelistSource::File { path, .. } => {
                    if let Ok(ips) = self.load_from_file(path).await {
                        for ip in ips {
                            new_cache.insert(ip);
                        }
                    }
                }
                #[cfg(feature = "crrouter")]
                WhitelistSource::ExternalFirewall => {
                    if let Ok(ips) = self.query_external_firewall().await {
                        for ip in ips {
                            new_cache.insert(ip);
                        }
                    }
                }
                _ => {}
            }
        }

        {
            let mut cache = self.cache.write().await;
            *cache = new_cache;
        }

        {
            let mut last = self.last_refresh.write().await;
            *last = now;
        }

        info!("Whitelist cache refreshed with {} entries", self.cache.read().await.len());

        Ok(())
    }

    /// Load IPs from a file
    async fn load_from_file(&self, path: &PathBuf) -> anyhow::Result<Vec<IpAddr>> {
        let content = tokio::fs::read_to_string(path).await?;
        let mut ips = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Try to parse as IP address
            if let Ok(ip) = line.parse::<IpAddr>() {
                ips.push(ip);
            } else if let Ok(network) = line.parse::<ipnetwork::IpNetwork>() {
                // For networks, we can't enumerate all IPs, but we can handle /32 and /128
                if (network.is_ipv4() && network.prefix() == 32)
                    || (network.is_ipv6() && network.prefix() == 128)
                {
                    ips.push(network.ip());
                }
            } else {
                debug!("Skipping invalid line in whitelist file: {}", line);
            }
        }

        info!("Loaded {} IPs from {}", ips.len(), path.display());
        Ok(ips)
    }

    /// Query external firewall daemon for trusted IPs via D-Bus (requires `crrouter` feature)
    #[cfg(feature = "crrouter")]
    async fn query_external_firewall(&self) -> anyhow::Result<Vec<IpAddr>> {
        use tokio::process::Command;

        // Query external firewall daemon for trusted zones
        let output = Command::new("busctl")
            .args([
                "--system",
                "--json=short",
                "call",
                "org.crrouter.Daemon",
                "/org/crrouter/Daemon",
                "org.crrouter.Firewall",
                "GetTrustedNetworks",
            ])
            .output()
            .await?;

        if !output.status.success() {
            // External daemon might not be running, that's okay
            debug!("External firewall D-Bus query failed (service may not be running)");
            return Ok(vec![]);
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let json_val: serde_json::Value = serde_json::from_str(&stdout)?;

        let mut ips = Vec::new();

        // Parse the response
        if let Some(data) = json_val.get("data").and_then(|d| d.as_array()) {
            if let Some(networks) = data.first().and_then(|a| a.as_array()) {
                for net in networks {
                    if let Some(s) = net.as_str() {
                        if let Ok(ip) = s.parse::<IpAddr>() {
                            ips.push(ip);
                        }
                    }
                }
            }
        }

        info!("Loaded {} trusted IPs from external firewall", ips.len());
        Ok(ips)
    }

    /// Add an IP to the local cache (temporary whitelist)
    pub async fn add_to_cache(&self, ip: IpAddr) {
        let mut cache = self.cache.write().await;
        cache.insert(ip);
        debug!("Added {} to whitelist cache", ip);
    }

    /// Remove an IP from the local cache
    pub async fn remove_from_cache(&self, ip: &IpAddr) {
        let mut cache = self.cache.write().await;
        cache.remove(ip);
        debug!("Removed {} from whitelist cache", ip);
    }

    /// Get all cached whitelist entries
    pub async fn get_cached(&self) -> Vec<IpAddr> {
        self.cache.read().await.iter().cloned().collect()
    }

    /// Check if a network contains the IP (for network-based whitelist)
    pub fn is_in_whitelisted_network(&self, ip: &IpAddr) -> bool {
        for network in &self.networks {
            if network.contains(*ip) {
                return true;
            }
        }
        false
    }
}

/// Watch a whitelist file for changes
pub async fn watch_whitelist_file(
    path: PathBuf,
    whitelist: Arc<RwLock<SharedWhitelist>>,
) -> anyhow::Result<()> {
    use notify::{RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel();

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.send(res);
        },
        notify::Config::default(),
    )?;

    watcher.watch(&path, RecursiveMode::NonRecursive)?;

    info!("Watching whitelist file: {}", path.display());

    loop {
        match rx.recv() {
            Ok(Ok(_event)) => {
                info!("Whitelist file changed, refreshing...");
                let wl = whitelist.read().await;
                if let Err(e) = wl.refresh().await {
                    error!("Failed to refresh whitelist: {}", e);
                }
            }
            Ok(Err(e)) => {
                error!("Watch error: {}", e);
            }
            Err(e) => {
                error!("Channel error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_whitelist() {
        let config = SharedWhitelistConfig {
            enabled: true,
            sources: vec![WhitelistSource::Networks {
                networks: vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()],
            }],
            ..Default::default()
        };

        let whitelist = SharedWhitelist::new(config);

        assert!(whitelist.is_whitelisted(&"10.1.2.3".parse().unwrap()).await);
        assert!(whitelist.is_whitelisted(&"192.168.1.1".parse().unwrap()).await);
        assert!(!whitelist.is_whitelisted(&"8.8.8.8".parse().unwrap()).await);
    }

    #[tokio::test]
    async fn test_cache_whitelist() {
        let config = SharedWhitelistConfig {
            enabled: true,
            sources: vec![],
            ..Default::default()
        };

        let whitelist = SharedWhitelist::new(config);

        let ip: IpAddr = "1.2.3.4".parse().unwrap();

        assert!(!whitelist.is_whitelisted(&ip).await);

        whitelist.add_to_cache(ip).await;
        assert!(whitelist.is_whitelisted(&ip).await);

        whitelist.remove_from_cache(&ip).await;
        assert!(!whitelist.is_whitelisted(&ip).await);
    }
}
