pub mod config;
pub mod database;
pub mod dbus;
pub mod dpi;
pub mod ebpf;
pub mod firewall;
pub mod intel;
pub mod models;
pub mod monitor;
pub mod port_scan_monitor;
pub mod shared_whitelist;
pub mod siem;
pub mod zones;

use anyhow::Result;
use chrono::Utc;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use config::Config;
use database::Database;
use dbus::DbusServer;
use firewall::Firewall;
use intel::IntelGatherer;
use models::{ActivityAction, Ban, BanSource, DaemonStatus, WhitelistEntry};
use monitor::{start_monitoring, MonitorEvent};

/// Core crmonban instance
pub struct Crmonban {
    config: Config,
    db: Database,
    firewall: Firewall,
    intel: IntelGatherer,
}

impl Crmonban {
    /// Create a new crmonban instance
    pub fn new(config: Config) -> Result<Self> {
        let db = Database::open(config.db_path())?;
        let port_scan = if config.port_scan.enabled {
            Some(config.port_scan.clone())
        } else {
            None
        };
        let dpi = if config.dpi.enabled {
            Some(config.dpi.clone())
        } else {
            None
        };
        let firewall = Firewall::with_features(config.nftables.clone(), port_scan, dpi);
        let intel = IntelGatherer::new(config.intel.clone())?;

        Ok(Self {
            config,
            db,
            firewall,
            intel,
        })
    }

    /// Create instance with custom database path
    pub fn with_db_path<P: AsRef<Path>>(config: Config, db_path: P) -> Result<Self> {
        let db = Database::open(db_path)?;
        let port_scan = if config.port_scan.enabled {
            Some(config.port_scan.clone())
        } else {
            None
        };
        let dpi = if config.dpi.enabled {
            Some(config.dpi.clone())
        } else {
            None
        };
        let firewall = Firewall::with_features(config.nftables.clone(), port_scan, dpi);
        let intel = IntelGatherer::new(config.intel.clone())?;

        Ok(Self {
            config,
            db,
            firewall,
            intel,
        })
    }

    /// Initialize the firewall (create table, chains, sets)
    pub fn init_firewall(&self) -> Result<()> {
        self.firewall.init()
    }

    /// Sync database bans to nftables
    pub fn sync_bans(&self) -> Result<()> {
        let bans = self.db.get_active_bans()?;

        let ban_data: Vec<(IpAddr, Option<u64>)> = bans
            .iter()
            .map(|b| {
                let timeout = b.expires_at.map(|exp| {
                    let remaining = (exp - Utc::now()).num_seconds();
                    if remaining > 0 {
                        remaining as u64
                    } else {
                        0
                    }
                });
                (b.ip, timeout)
            })
            .collect();

        self.firewall.sync_from_db(&ban_data)
    }

    /// Ban an IP address
    pub fn ban(
        &self,
        ip: IpAddr,
        reason: String,
        source: BanSource,
        duration_secs: Option<i64>,
    ) -> Result<()> {
        // Check whitelist
        if self.db.is_whitelisted(&ip)? {
            warn!("IP {} is whitelisted, not banning", ip);
            return Ok(());
        }

        // Add to database
        let ban = Ban::new(ip, reason.clone(), source, duration_secs);
        self.db.add_ban(&ban)?;

        // Add to firewall
        self.firewall.ban(&ip, duration_secs.map(|d| d as u64))?;

        // Log activity
        self.db
            .log_activity(ActivityAction::Ban, Some(&ip), &reason)?;

        info!("Banned IP: {} (reason: {})", ip, reason);
        Ok(())
    }

    /// Ban with automatic intel gathering
    pub async fn ban_with_intel(
        &self,
        ip: IpAddr,
        reason: String,
        source: BanSource,
        duration_secs: Option<i64>,
    ) -> Result<()> {
        self.ban(ip, reason, source, duration_secs)?;

        // Gather intel in background if enabled
        if self.config.general.auto_intel {
            if let Err(e) = self.gather_and_save_intel(&ip.to_string()).await {
                warn!("Failed to gather intel for {}: {}", ip, e);
            }
        }

        Ok(())
    }

    /// Unban an IP address
    pub fn unban(&self, ip: &IpAddr) -> Result<bool> {
        let removed = self.db.remove_ban(ip)?;

        if removed {
            if let Err(e) = self.firewall.unban(ip) {
                warn!("Failed to remove {} from firewall: {}", ip, e);
            }

            self.db
                .log_activity(ActivityAction::Unban, Some(ip), "Manual unban")?;

            info!("Unbanned IP: {}", ip);
        }

        Ok(removed)
    }

    /// Get list of active bans
    pub fn list_bans(&self) -> Result<Vec<Ban>> {
        self.db.get_active_bans()
    }

    /// Get ban for specific IP
    pub fn get_ban(&self, ip: &IpAddr) -> Result<Option<Ban>> {
        self.db.get_ban(ip)
    }

    /// Add IP to whitelist
    pub fn whitelist_add(&self, ip: IpAddr, comment: Option<String>) -> Result<()> {
        // Remove any existing ban
        if self.db.get_ban(&ip)?.is_some() {
            self.unban(&ip)?;
        }

        let entry = WhitelistEntry::new(ip, comment.clone());
        self.db.add_whitelist(&entry)?;

        self.db.log_activity(
            ActivityAction::Whitelist,
            Some(&ip),
            &comment.unwrap_or_else(|| "Added to whitelist".to_string()),
        )?;

        info!("Added {} to whitelist", ip);
        Ok(())
    }

    /// Remove IP from whitelist
    pub fn whitelist_remove(&self, ip: &IpAddr) -> Result<bool> {
        let removed = self.db.remove_whitelist(ip)?;

        if removed {
            self.db
                .log_activity(ActivityAction::UnWhitelist, Some(ip), "Removed from whitelist")?;

            info!("Removed {} from whitelist", ip);
        }

        Ok(removed)
    }

    /// Get whitelist
    pub fn whitelist_list(&self) -> Result<Vec<WhitelistEntry>> {
        self.db.get_whitelist()
    }

    /// Gather intelligence for an IP
    pub async fn gather_intel(&self, ip: &str) -> Result<models::AttackerIntel> {
        self.intel.gather(ip).await
    }

    /// Gather and save intelligence
    pub async fn gather_and_save_intel(&self, ip: &str) -> Result<models::AttackerIntel> {
        let intel = self.intel.gather(ip).await?;
        self.db.save_intel(&intel)?;

        self.db.log_activity(
            ActivityAction::IntelGathered,
            ip.parse().ok().as_ref(),
            &format!("Gathered intel for {}", ip),
        )?;

        Ok(intel)
    }

    /// Get cached intelligence
    pub fn get_cached_intel(&self, ip: &str) -> Result<Option<models::AttackerIntel>> {
        self.db.get_intel(ip)
    }

    /// Get recent activity logs
    pub fn get_activity(&self, limit: u32) -> Result<Vec<models::ActivityLog>> {
        self.db.get_recent_activity(limit)
    }

    /// Get attack statistics
    pub fn get_stats(&self) -> Result<models::AttackStats> {
        self.db.get_stats()
    }

    /// Clean up expired bans
    pub fn cleanup_expired(&self) -> Result<u32> {
        let expired = self.db.get_expired_bans()?;
        let count = expired.len() as u32;

        for ban in expired {
            if let Err(e) = self.db.remove_ban(&ban.ip) {
                warn!("Failed to remove expired ban for {}: {}", ban.ip, e);
            }
        }

        if count > 0 {
            info!("Cleaned up {} expired bans", count);
        }

        Ok(count)
    }

    /// Flush all bans (dangerous!)
    pub fn flush_all(&self) -> Result<()> {
        self.firewall.flush()?;

        for ban in self.db.get_active_bans()? {
            self.db.remove_ban(&ban.ip)?;
        }

        info!("Flushed all bans");
        Ok(())
    }

    /// Get configuration reference
    pub fn config(&self) -> &Config {
        &self.config
    }
}

/// Daemon runner for monitoring and auto-banning
pub struct Daemon {
    crmonban: Arc<RwLock<Crmonban>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    events_processed: Arc<RwLock<u64>>,
    dbus_server: Option<DbusServer>,
}

impl Daemon {
    /// Create a new daemon
    pub fn new(crmonban: Crmonban) -> Self {
        Self {
            crmonban: Arc::new(RwLock::new(crmonban)),
            shutdown_tx: None,
            events_processed: Arc::new(RwLock::new(0)),
            dbus_server: None,
        }
    }

    /// Run the daemon
    pub async fn run(&mut self) -> Result<()> {
        let crmonban = self.crmonban.read().await;

        // Initialize firewall
        crmonban.init_firewall()?;

        // Sync existing bans
        crmonban.sync_bans()?;

        // Log daemon start
        crmonban
            .db
            .log_activity(ActivityAction::DaemonStart, None, "Daemon started")?;

        let services = crmonban.config.services.clone();
        let dbus_enabled = crmonban.config.dbus.enabled;
        let port_scan_config = crmonban.config.port_scan.clone();
        let dpi_config = crmonban.config.dpi.clone();
        drop(crmonban);

        // Start D-Bus server if enabled
        if dbus_enabled {
            match DbusServer::start(self.crmonban.clone(), self.events_processed.clone()).await {
                Ok(server) => {
                    if let Err(e) = server.emit_daemon_started().await {
                        warn!("Failed to emit D-Bus daemon_started signal: {}", e);
                    }
                    self.dbus_server = Some(server);
                    info!("D-Bus interface enabled");
                }
                Err(e) => {
                    warn!("Failed to start D-Bus server: {}. Continuing without D-Bus.", e);
                }
            }
        }

        // Create channels
        let (event_tx, mut event_rx) = mpsc::channel::<MonitorEvent>(100);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn log monitoring task
        let event_tx_log = event_tx.clone();
        let monitor_handle = tokio::spawn(async move {
            if let Err(e) = start_monitoring(services, event_tx_log).await {
                error!("Monitor error: {}", e);
            }
        });

        // Spawn port scan monitoring task if enabled
        let port_scan_handle = if port_scan_config.enabled {
            let event_tx_portscan = event_tx.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = port_scan_monitor::start_port_scan_monitoring(
                    port_scan_config,
                    event_tx_portscan,
                )
                .await
                {
                    error!("Port scan monitor error: {}", e);
                }
            }))
        } else {
            info!("Port scan detection is disabled");
            None
        };

        // Spawn DPI task if enabled
        let dpi_handle = if dpi_config.enabled {
            let event_tx_dpi = event_tx.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = dpi::start_dpi(dpi_config, event_tx_dpi).await {
                    error!("DPI error: {}", e);
                }
            }))
        } else {
            info!("Deep packet inspection is disabled");
            None
        };

        // Spawn cleanup task (runs every minute)
        let cleanup_crmonban = self.crmonban.clone();
        let cleanup_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let crmonban = cleanup_crmonban.read().await;
                if let Err(e) = crmonban.cleanup_expired() {
                    warn!("Cleanup error: {}", e);
                }
            }
        });

        info!("Daemon started, monitoring logs...");

        // Main event loop
        loop {
            tokio::select! {
                Some(event) = event_rx.recv() => {
                    // Increment events counter
                    {
                        let mut count = self.events_processed.write().await;
                        *count += 1;
                    }

                    match event {
                        MonitorEvent::Attack(attack_event) => {
                            let crmonban = self.crmonban.read().await;
                            if let Err(e) = crmonban.db.add_event(&attack_event) {
                                error!("Failed to record event: {}", e);
                            }

                            // Emit D-Bus signal
                            if let Some(ref dbus) = self.dbus_server {
                                let _ = dbus.emit_attack_detected(
                                    &attack_event.ip.to_string(),
                                    &attack_event.service,
                                    &attack_event.event_type.to_string(),
                                ).await;
                            }
                        }
                        MonitorEvent::Ban { ip, service, reason, duration_secs } => {
                            let crmonban = self.crmonban.read().await;

                            // Check whitelist
                            match crmonban.db.is_whitelisted(&ip) {
                                Ok(true) => {
                                    info!("Skipping ban for whitelisted IP: {}", ip);
                                    continue;
                                }
                                Ok(false) => {}
                                Err(e) => {
                                    error!("Failed to check whitelist: {}", e);
                                    continue;
                                }
                            }

                            let duration = if duration_secs > 0 {
                                Some(duration_secs)
                            } else {
                                None
                            };

                            let ban_reason = reason.clone();
                            let ban_service = service.clone();
                            let duration_for_signal = duration_secs;
                            if let Err(e) = crmonban.ban(
                                ip,
                                reason,
                                BanSource::Monitor(service),
                                duration,
                            ) {
                                error!("Failed to ban {}: {}", ip, e);
                            } else {
                                // Emit D-Bus signal
                                if let Some(ref dbus) = self.dbus_server {
                                    let _ = dbus.emit_ban_added(
                                        &ip.to_string(),
                                        &ban_reason,
                                        &format!("monitor:{}", ban_service),
                                        duration_for_signal as u32,
                                    ).await;
                                }
                            }

                            // Gather intel asynchronously
                            if crmonban.config.general.auto_intel {
                                let ip_str = ip.to_string();
                                let crmonban_clone = self.crmonban.clone();
                                tokio::spawn(async move {
                                    let crmonban = crmonban_clone.read().await;
                                    if let Err(e) = crmonban.gather_and_save_intel(&ip_str).await {
                                        warn!("Failed to gather intel for {}: {}", ip_str, e);
                                    }
                                });
                            }
                        }
                        MonitorEvent::Error(msg) => {
                            error!("Monitor error: {}", msg);
                        }
                    }
                }

                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }

        // Emit D-Bus stopping signal
        if let Some(ref dbus) = self.dbus_server {
            let _ = dbus.emit_daemon_stopping().await;
        }

        // Cleanup
        monitor_handle.abort();
        if let Some(handle) = port_scan_handle {
            handle.abort();
        }
        if let Some(handle) = dpi_handle {
            handle.abort();
        }
        cleanup_handle.abort();

        let crmonban = self.crmonban.read().await;
        crmonban
            .db
            .log_activity(ActivityAction::DaemonStop, None, "Daemon stopped")?;

        info!("Daemon stopped");
        Ok(())
    }

    /// Signal shutdown
    pub async fn shutdown(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(()).await;
        }
    }

    /// Get status
    pub async fn status(&self) -> Result<DaemonStatus> {
        let crmonban = self.crmonban.read().await;
        let active_bans = crmonban.db.get_active_bans()?.len() as u64;
        let monitored_files: Vec<String> = crmonban
            .config
            .services
            .values()
            .filter(|s| s.enabled)
            .map(|s| s.log_path.clone())
            .collect();

        Ok(DaemonStatus {
            running: true,
            pid: Some(std::process::id()),
            uptime_secs: None, // Would need to track start time
            active_bans,
            events_processed: 0, // Would need counter
            monitored_files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crmonban_creation() {
        let config = Config::default();
        // Note: This would fail without proper permissions, but tests the structure
        assert_eq!(config.nftables.table_name, "crmonban");
    }
}
