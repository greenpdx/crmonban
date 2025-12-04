//! eBPF integration for fast-path blocking
//!
//! Provides line-rate IP blocking by updating eBPF maps directly,
//! bypassing the nftables slow path for sub-microsecond blocking.
//!
//! Integration methods:
//! 1. D-Bus: Call external eBPF manager via D-Bus (requires `crrouter` feature)
//! 2. BPF maps: Direct map manipulation (requires CAP_BPF)
//! 3. Disabled: Track locally only, no kernel integration

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// eBPF integration method
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EbpfMethod {
    /// Call external eBPF manager via D-Bus (requires `crrouter` feature)
    #[cfg(feature = "crrouter")]
    Dbus,

    /// Direct BPF map file manipulation
    MapFile {
        /// Path to the pinned BPF map
        path: PathBuf,
    },

    /// Disabled (default)
    #[default]
    Disabled,
}

/// eBPF configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EbpfConfig {
    /// Enable eBPF integration
    #[serde(default)]
    pub enabled: bool,

    /// Integration method
    #[serde(default)]
    pub method: EbpfMethod,

    /// Sync interval in seconds (how often to sync with nftables)
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,

    /// Maximum entries in eBPF blacklist
    #[serde(default = "default_max_entries")]
    pub max_entries: u32,
}

fn default_sync_interval() -> u64 {
    60
}

fn default_max_entries() -> u32 {
    10000
}

/// eBPF blacklist manager
pub struct EbpfManager {
    config: EbpfConfig,
    /// Cached blacklist entries (for sync tracking)
    blacklist: Arc<RwLock<HashSet<IpAddr>>>,
    /// Last sync time
    last_sync: Arc<RwLock<std::time::Instant>>,
}

impl EbpfManager {
    /// Create a new eBPF manager
    pub fn new(config: EbpfConfig) -> Self {
        Self {
            config,
            blacklist: Arc::new(RwLock::new(HashSet::new())),
            last_sync: Arc::new(RwLock::new(std::time::Instant::now())),
        }
    }

    /// Check if eBPF integration is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !matches!(self.config.method, EbpfMethod::Disabled)
    }

    /// Add an IP to the eBPF blacklist
    pub async fn add_to_blacklist(&self, ip: IpAddr) -> anyhow::Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        match &self.config.method {
            #[cfg(feature = "crrouter")]
            EbpfMethod::Dbus => self.dbus_add(ip).await?,
            EbpfMethod::MapFile { path } => self.map_add(path, ip).await?,
            EbpfMethod::Disabled => {}
        }

        // Update local cache
        self.blacklist.write().await.insert(ip);
        debug!("Added {} to eBPF blacklist", ip);

        Ok(())
    }

    /// Remove an IP from the eBPF blacklist
    pub async fn remove_from_blacklist(&self, ip: &IpAddr) -> anyhow::Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        match &self.config.method {
            #[cfg(feature = "crrouter")]
            EbpfMethod::Dbus => self.dbus_remove(*ip).await?,
            EbpfMethod::MapFile { path } => self.map_remove(path, *ip).await?,
            EbpfMethod::Disabled => {}
        }

        // Update local cache
        self.blacklist.write().await.remove(ip);
        debug!("Removed {} from eBPF blacklist", ip);

        Ok(())
    }

    /// Sync the blacklist with nftables bans
    pub async fn sync_with_bans(&self, banned_ips: &[IpAddr]) -> anyhow::Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        let now = std::time::Instant::now();

        // Check sync interval
        {
            let last = self.last_sync.read().await;
            if now.duration_since(*last).as_secs() < self.config.sync_interval_secs {
                return Ok(());
            }
        }

        info!("Syncing eBPF blacklist with {} bans", banned_ips.len());

        let current: HashSet<IpAddr> = self.blacklist.read().await.clone();
        let target: HashSet<IpAddr> = banned_ips.iter().cloned().collect();

        // Add new bans
        for ip in target.difference(&current) {
            if let Err(e) = self.add_to_blacklist(*ip).await {
                warn!("Failed to add {} to eBPF blacklist: {}", ip, e);
            }
        }

        // Remove expired bans
        for ip in current.difference(&target) {
            if let Err(e) = self.remove_from_blacklist(ip).await {
                warn!("Failed to remove {} from eBPF blacklist: {}", ip, e);
            }
        }

        // Update sync time
        *self.last_sync.write().await = now;

        info!(
            "eBPF blacklist synced: {} entries",
            self.blacklist.read().await.len()
        );

        Ok(())
    }

    /// Clear the entire blacklist
    pub async fn clear(&self) -> anyhow::Result<()> {
        if !self.is_enabled() {
            return Ok(());
        }

        let ips: Vec<IpAddr> = self.blacklist.read().await.iter().cloned().collect();

        for ip in ips {
            if let Err(e) = self.remove_from_blacklist(&ip).await {
                warn!("Failed to remove {} during clear: {}", ip, e);
            }
        }

        info!("eBPF blacklist cleared");
        Ok(())
    }

    /// Get current blacklist entries
    pub async fn get_blacklist(&self) -> Vec<IpAddr> {
        self.blacklist.read().await.iter().cloned().collect()
    }

    /// Get blacklist count
    pub async fn count(&self) -> usize {
        self.blacklist.read().await.len()
    }

    // D-Bus methods (requires crrouter feature)

    #[cfg(feature = "crrouter")]
    async fn dbus_add(&self, ip: IpAddr) -> anyhow::Result<()> {
        use tokio::process::Command;

        let output = Command::new("busctl")
            .args([
                "--system",
                "call",
                "org.crrouter.Daemon",
                "/org/crrouter/Daemon",
                "org.crrouter.Ebpf",
                "AddToBlacklist",
                "s",
                &ip.to_string(),
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Don't fail if crrouter_web isn't running
            if stderr.contains("not found") || stderr.contains("No such") {
                debug!("crrouter_web eBPF service not available");
                return Ok(());
            }
            anyhow::bail!("D-Bus call failed: {}", stderr);
        }

        Ok(())
    }

    #[cfg(feature = "crrouter")]
    async fn dbus_remove(&self, ip: IpAddr) -> anyhow::Result<()> {
        use tokio::process::Command;

        let output = Command::new("busctl")
            .args([
                "--system",
                "call",
                "org.crrouter.Daemon",
                "/org/crrouter/Daemon",
                "org.crrouter.Ebpf",
                "RemoveFromBlacklist",
                "s",
                &ip.to_string(),
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") || stderr.contains("No such") {
                debug!("crrouter_web eBPF service not available");
                return Ok(());
            }
            anyhow::bail!("D-Bus call failed: {}", stderr);
        }

        Ok(())
    }

    // BPF map file methods

    async fn map_add(&self, path: &PathBuf, ip: IpAddr) -> anyhow::Result<()> {
        // This requires bpftool or direct map manipulation
        // For now, use bpftool if available
        use tokio::process::Command;

        let key = match ip {
            IpAddr::V4(v4) => format!("{:02x} {:02x} {:02x} {:02x}",
                v4.octets()[0], v4.octets()[1], v4.octets()[2], v4.octets()[3]),
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                octets.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
            }
        };

        let output = Command::new("bpftool")
            .args([
                "map",
                "update",
                "pinned",
                path.to_str().unwrap_or(""),
                "key",
                &key,
                "value",
                "01", // 1 = blocked
            ])
            .output()
            .await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("bpftool failed: {}", stderr);
        }

        Ok(())
    }

    async fn map_remove(&self, path: &PathBuf, ip: IpAddr) -> anyhow::Result<()> {
        use tokio::process::Command;

        let key = match ip {
            IpAddr::V4(v4) => format!("{:02x} {:02x} {:02x} {:02x}",
                v4.octets()[0], v4.octets()[1], v4.octets()[2], v4.octets()[3]),
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                octets.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
            }
        };

        let output = Command::new("bpftool")
            .args([
                "map",
                "delete",
                "pinned",
                path.to_str().unwrap_or(""),
                "key",
                &key,
            ])
            .output()
            .await?;

        if !output.status.success() {
            // Key might not exist, that's okay
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("No such") && !stderr.contains("not found") {
                anyhow::bail!("bpftool failed: {}", stderr);
            }
        }

        Ok(())
    }
}

/// Statistics for eBPF blacklist
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EbpfStats {
    pub enabled: bool,
    pub method: String,
    pub blacklist_count: usize,
    pub last_sync_secs_ago: u64,
}

impl EbpfManager {
    /// Get statistics
    pub async fn stats(&self) -> EbpfStats {
        let method = match &self.config.method {
            #[cfg(feature = "crrouter")]
            EbpfMethod::Dbus => "dbus".to_string(),
            EbpfMethod::MapFile { path } => format!("map:{}", path.display()),
            EbpfMethod::Disabled => "disabled".to_string(),
        };

        let last_sync_secs_ago = self.last_sync.read().await.elapsed().as_secs();

        EbpfStats {
            enabled: self.is_enabled(),
            method,
            blacklist_count: self.blacklist.read().await.len(),
            last_sync_secs_ago,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_disabled_manager() {
        let config = EbpfConfig {
            enabled: false,
            ..Default::default()
        };

        let manager = EbpfManager::new(config);
        assert!(!manager.is_enabled());

        // Should not error when disabled
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(manager.add_to_blacklist(ip).await.is_ok());
    }

    #[tokio::test]
    async fn test_local_cache() {
        let config = EbpfConfig {
            enabled: true,
            method: EbpfMethod::Disabled, // Use disabled to skip actual calls
            ..Default::default()
        };

        let manager = EbpfManager::new(config);

        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Local cache should still work
        manager.blacklist.write().await.insert(ip);
        assert_eq!(manager.count().await, 1);

        let list = manager.get_blacklist().await;
        assert!(list.contains(&ip));
    }
}
