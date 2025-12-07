pub mod brute_force;
pub mod config;
pub mod database;
#[cfg(feature = "dbus")]
pub mod dbus;
pub mod dpi;
pub mod ebpf;
pub mod firewall;
pub mod intel;
pub mod ipc;
pub mod malware_detect;
pub mod models;
pub mod monitor;
pub mod port_scan_monitor;
pub mod scan_detect;
pub mod shared_whitelist;
pub mod siem;
#[cfg(feature = "signatures")]
pub mod signatures;
pub mod tls_proxy;
pub mod zones;

// NIDS Stage 2 & 3: Flow tracking and protocol analysis
#[cfg(feature = "flow-tracking")]
pub mod core;
#[cfg(feature = "flow-tracking")]
pub mod flow;
#[cfg(feature = "protocols")]
pub mod protocols;

// NIDS Stage 5: Threat intelligence feeds
#[cfg(feature = "threat-intel")]
pub mod threat_intel;

// NIDS Stage 6: ML/Anomaly detection
#[cfg(feature = "ml-detection")]
pub mod ml;

// NIDS Stage 7: Alert Correlation
#[cfg(feature = "correlation")]
pub mod correlation;

// NIDS Stage 8: Packet Engine
#[cfg(feature = "packet-engine")]
pub mod engine;

// Parallel processing
#[cfg(feature = "parallel")]
pub mod parallel;

// Network Scanning (Free: Nmap, Ettercap, Metasploit, Burp)
#[cfg(feature = "scan")]
pub mod network;

use anyhow::Result;
use chrono::Utc;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use config::Config;
use database::Database;
#[cfg(feature = "dbus")]
use dbus::DbusServer;
use firewall::Firewall;
use intel::IntelGatherer;
use ipc::{
    ActionResponse, ActionType, BanEvent, BanInfo, BansResponse, ConfigResponse,
    DisplayProcess, ErrorResponse, EventInfo, EventsResponse, GeoInfo, GetBansRequest,
    GetEventsRequest, GetIntelRequest, IntelResponse, IpcMessage, IpcRequest, IpcServer,
    SecurityEvent, ServiceSummary, StatsResponse, StatusResponse, SystemEvent, WhoisInfo,
};
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
        let tls_proxy = if config.tls_proxy.enabled {
            Some(config.tls_proxy.clone())
        } else {
            None
        };
        let port_rules = if config.port_rules.enabled {
            Some(config.port_rules.clone())
        } else {
            None
        };
        let firewall = Firewall::with_features(config.nftables.clone(), port_scan, dpi, tls_proxy, port_rules);
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
        let tls_proxy = if config.tls_proxy.enabled {
            Some(config.tls_proxy.clone())
        } else {
            None
        };
        let port_rules = if config.port_rules.enabled {
            Some(config.port_rules.clone())
        } else {
            None
        };
        let firewall = Firewall::with_features(config.nftables.clone(), port_scan, dpi, tls_proxy, port_rules);
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

    /// Add a port rule to the firewall
    pub fn add_port_rule(&self, rule: &config::PortRule) -> Result<()> {
        self.firewall.add_port_rule(rule)
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
    #[cfg(feature = "dbus")]
    dbus_server: Option<DbusServer>,
    ipc_server: Option<Arc<IpcServer>>,
    display_process: Option<DisplayProcess>,
}

impl Daemon {
    /// Create a new daemon
    pub fn new(crmonban: Crmonban) -> Self {
        Self {
            crmonban: Arc::new(RwLock::new(crmonban)),
            shutdown_tx: None,
            events_processed: Arc::new(RwLock::new(0)),
            #[cfg(feature = "dbus")]
            dbus_server: None,
            ipc_server: None,
            display_process: None,
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
        #[cfg(feature = "dbus")]
        let dbus_enabled = crmonban.config.dbus.enabled;
        let port_scan_config = crmonban.config.port_scan.clone();
        let dpi_config = crmonban.config.dpi.clone();
        let display_config = crmonban.config.display.clone();
        let db_path = crmonban.config.db_path().to_string_lossy().to_string();
        drop(crmonban);

        // Start IPC server for display communication
        if display_config.enabled {
            let socket_path = display_config.socket_path.clone()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(ipc::DEFAULT_SOCKET_PATH));

            let mut ipc_server = IpcServer::new(Some(socket_path.as_path()));
            // Take request receiver BEFORE starting (and wrapping in Arc)
            let request_rx = ipc_server.take_request_receiver();

            match ipc_server.start().await {
                Ok(()) => {
                    let server = Arc::new(ipc_server);
                    self.ipc_server = Some(server.clone());
                    info!("IPC server started");

                    // Spawn request handler task
                    if let Some(rx) = request_rx {
                        let crmonban_for_requests = self.crmonban.clone();
                        let events_for_requests = self.events_processed.clone();
                        tokio::spawn(async move {
                            handle_ipc_requests(rx, crmonban_for_requests, events_for_requests).await;
                        });
                        info!("IPC request handler started");
                    }

                    // Start display subprocess
                    let display_binary = display_config.binary_path.clone()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| {
                            DisplayProcess::find_binary()
                                .unwrap_or_else(|| PathBuf::from("crmonban-display"))
                        });

                    let mut display_proc = DisplayProcess::new(
                        display_binary,
                        socket_path.clone(),
                        PathBuf::from(&db_path),
                        display_config.port,
                    );

                    match display_proc.spawn().await {
                        Ok(()) => {
                            info!("Display server started on port {}", display_config.port);
                            self.display_process = Some(display_proc);
                        }
                        Err(e) => {
                            warn!("Failed to start display server: {}. Dashboard will not be available.", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to start IPC server: {}. Display server will not be available.", e);
                }
            }
        }

        // Start D-Bus server if enabled
        #[cfg(feature = "dbus")]
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
                            #[cfg(feature = "dbus")]
                            if let Some(ref dbus) = self.dbus_server {
                                let _ = dbus.emit_attack_detected(
                                    &attack_event.ip.to_string(),
                                    &attack_event.service,
                                    &attack_event.event_type.to_string(),
                                ).await;
                            }

                            // Broadcast to display via IPC
                            if let Some(ref ipc) = self.ipc_server {
                                let ipc_event = SecurityEvent {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    timestamp: Utc::now().timestamp_millis(),
                                    src_ip: attack_event.ip,
                                    dst_port: None,
                                    service: attack_event.service.clone(),
                                    event_type: attack_event.event_type.to_string(),
                                    severity: 5, // Default severity
                                    description: format!("Attack detected from {}", attack_event.ip),
                                    banned: false,
                                };
                                ipc.broadcast(IpcMessage::Event(ipc_event));
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
                                #[cfg(feature = "dbus")]
                                if let Some(ref dbus) = self.dbus_server {
                                    let _ = dbus.emit_ban_added(
                                        &ip.to_string(),
                                        &ban_reason,
                                        &format!("monitor:{}", ban_service),
                                        duration_for_signal as u32,
                                    ).await;
                                }

                                // Broadcast to display via IPC
                                if let Some(ref ipc) = self.ipc_server {
                                    let ban_event = BanEvent {
                                        action: "add".to_string(),
                                        ip,
                                        reason: Some(ban_reason.clone()),
                                        source: Some(format!("monitor:{}", ban_service)),
                                        duration_secs: if duration_for_signal > 0 {
                                            Some(duration_for_signal as u32)
                                        } else {
                                            None
                                        },
                                        timestamp: Utc::now().timestamp_millis(),
                                    };
                                    ipc.broadcast(IpcMessage::Ban(ban_event));
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
        #[cfg(feature = "dbus")]
        if let Some(ref dbus) = self.dbus_server {
            let _ = dbus.emit_daemon_stopping().await;
        }

        // Broadcast shutdown via IPC
        if let Some(ref ipc) = self.ipc_server {
            let system_event = SystemEvent {
                event_type: "stopping".to_string(),
                details: Some("Daemon shutting down".to_string()),
                timestamp: Utc::now().timestamp_millis(),
            };
            ipc.broadcast(IpcMessage::System(system_event));
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

        // Stop display subprocess
        if let Some(ref mut display) = self.display_process {
            if let Err(e) = display.stop().await {
                warn!("Failed to stop display server: {}", e);
            }
        }

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

/// Handle IPC requests from display clients
async fn handle_ipc_requests(
    mut rx: mpsc::Receiver<IpcRequest>,
    crmonban: Arc<RwLock<Crmonban>>,
    events_processed: Arc<RwLock<u64>>,
) {
    use std::time::Instant;

    let start_time = Instant::now();

    while let Some(request) = rx.recv().await {
        let response = match request.message {
            IpcMessage::GetBans(req) => handle_get_bans(&crmonban, req).await,
            IpcMessage::GetStats => handle_get_stats(&crmonban).await,
            IpcMessage::GetIntel(req) => handle_get_intel(&crmonban, req).await,
            IpcMessage::GetEvents(req) => handle_get_events(&crmonban, req).await,
            IpcMessage::GetStatus => {
                handle_get_status(&crmonban, &events_processed, start_time).await
            }
            IpcMessage::GetConfig => handle_get_config(&crmonban).await,
            IpcMessage::Action(req) => handle_action(&crmonban, req).await,
            _ => IpcMessage::Error(ErrorResponse {
                request_id: None,
                code: "INVALID_REQUEST".to_string(),
                message: "Unknown request type".to_string(),
            }),
        };

        // Send response back to client (ignore errors if client disconnected)
        let _ = request.response_tx.send(response);
    }
}

async fn handle_get_bans(crmonban: &Arc<RwLock<Crmonban>>, req: GetBansRequest) -> IpcMessage {
    let crmonban = crmonban.read().await;

    match crmonban.list_bans() {
        Ok(bans) => {
            let mut ban_infos: Vec<BanInfo> = bans
                .iter()
                .filter(|b| {
                    // Apply IP filter if specified
                    if let Some(ref filter) = req.ip_filter {
                        b.ip.to_string().contains(filter)
                    } else {
                        true
                    }
                })
                .map(|b| {
                    // Get cached intel for country/ASN
                    let (country, asn) = crmonban
                        .get_cached_intel(&b.ip.to_string())
                        .ok()
                        .flatten()
                        .map(|intel| {
                            (
                                intel.country.clone(),
                                intel.asn.map(|a| a.to_string()),
                            )
                        })
                        .unwrap_or((None, None));

                    BanInfo {
                        ip: b.ip,
                        reason: b.reason.clone(),
                        source: b.source.to_string(),
                        created_at: b.created_at.timestamp_millis(),
                        expires_at: b.expires_at.map(|e| e.timestamp_millis()),
                        ban_count: b.ban_count,
                        country,
                        asn,
                    }
                })
                .collect();

            let total = ban_infos.len() as u64;

            // Apply limit
            if let Some(limit) = req.limit {
                ban_infos.truncate(limit as usize);
            }

            IpcMessage::BansResponse(BansResponse {
                request_id: req.request_id,
                bans: ban_infos,
                total,
            })
        }
        Err(e) => IpcMessage::Error(ErrorResponse {
            request_id: Some(req.request_id),
            code: "DATABASE_ERROR".to_string(),
            message: format!("Failed to get bans: {}", e),
        }),
    }
}

async fn handle_get_stats(crmonban: &Arc<RwLock<Crmonban>>) -> IpcMessage {
    let crmonban = crmonban.read().await;

    match crmonban.get_stats() {
        Ok(stats) => IpcMessage::StatsResponse(StatsResponse {
            request_id: None,
            total_bans: stats.total_bans,
            active_bans: stats.active_bans,
            total_events: stats.total_events,
            events_today: stats.events_today,
            events_this_hour: stats.events_this_hour,
            events_by_service: stats.events_by_service,
            top_countries: stats.top_countries,
            top_asns: stats.top_asns,
        }),
        Err(e) => IpcMessage::Error(ErrorResponse {
            request_id: None,
            code: "DATABASE_ERROR".to_string(),
            message: format!("Failed to get stats: {}", e),
        }),
    }
}

async fn handle_get_intel(crmonban: &Arc<RwLock<Crmonban>>, req: GetIntelRequest) -> IpcMessage {
    let crmonban = crmonban.read().await;

    // Try cached intel first
    let intel_result = if req.refresh {
        // Force refresh - gather new intel
        crmonban.gather_and_save_intel(&req.ip).await
    } else {
        // Try cache first
        match crmonban.get_cached_intel(&req.ip) {
            Ok(Some(cached)) => Ok(cached),
            Ok(None) => {
                // No cache, gather fresh
                crmonban.gather_and_save_intel(&req.ip).await
            }
            Err(e) => Err(e),
        }
    };

    match intel_result {
        Ok(intel) => {
            // Build GeoInfo if any geo fields are present
            let geo = if intel.country.is_some()
                || intel.city.is_some()
                || intel.latitude.is_some()
            {
                Some(GeoInfo {
                    country: intel.country.clone(),
                    country_code: intel.country_code.clone(),
                    region: intel.region.clone(),
                    city: intel.city.clone(),
                    latitude: intel.latitude,
                    longitude: intel.longitude,
                    timezone: intel.timezone.clone(),
                })
            } else {
                None
            };

            // Build WhoisInfo if any whois fields are present
            let whois = if intel.asn.is_some() || intel.as_org.is_some() || intel.isp.is_some() {
                Some(WhoisInfo {
                    asn: intel.asn.map(|a| a.to_string()),
                    org: intel.as_org.clone(),
                    isp: intel.isp.clone(),
                    cidr: None, // Not in AttackerIntel
                    abuse_email: intel.whois_abuse_contact.clone(),
                })
            } else {
                None
            };

            IpcMessage::IntelResponse(IntelResponse {
                request_id: req.request_id,
                ip: req.ip,
                geo,
                whois,
                rdns: intel.reverse_dns.clone(),
                threat_score: intel.threat_score.map(|s| s as u8),
                abuse_reports: None, // Not in AttackerIntel
                open_ports: intel.open_ports.clone().unwrap_or_default(),
                tags: intel.shodan_tags.clone().unwrap_or_default(),
                last_updated: intel.gathered_at.map(|t| t.timestamp_millis()),
            })
        }
        Err(e) => IpcMessage::Error(ErrorResponse {
            request_id: Some(req.request_id),
            code: "INTEL_ERROR".to_string(),
            message: format!("Failed to get intel: {}", e),
        }),
    }
}

async fn handle_get_events(crmonban: &Arc<RwLock<Crmonban>>, req: GetEventsRequest) -> IpcMessage {
    let crmonban = crmonban.read().await;

    // Get recent activity (events are stored as activity logs)
    match crmonban.get_activity(req.limit + req.offset) {
        Ok(activities) => {
            let events: Vec<EventInfo> = activities
                .into_iter()
                .skip(req.offset as usize)
                .take(req.limit as usize)
                .filter_map(|a| {
                    // Filter by service if specified
                    if let Some(ref service) = req.service {
                        if !a.details.contains(service) {
                            return None;
                        }
                    }
                    // Filter by IP if specified
                    if let Some(ref ip_filter) = req.ip {
                        if let Some(ref ip) = a.ip {
                            if !ip.to_string().contains(ip_filter) {
                                return None;
                            }
                        } else {
                            return None;
                        }
                    }
                    // Filter by since timestamp
                    if let Some(since) = req.since {
                        if a.timestamp.timestamp_millis() < since {
                            return None;
                        }
                    }

                    Some(EventInfo {
                        id: a.id.map(|i| i.to_string()).unwrap_or_else(|| "0".to_string()),
                        timestamp: a.timestamp.timestamp_millis(),
                        ip: a.ip.unwrap_or_else(|| "0.0.0.0".parse().unwrap()),
                        service: "system".to_string(),
                        event_type: a.action.to_string(),
                        details: Some(a.details),
                        banned: matches!(a.action, ActivityAction::Ban),
                    })
                })
                .collect();

            let total = events.len() as u64;
            let has_more = (req.offset + req.limit) < total as u32;

            IpcMessage::EventsResponse(EventsResponse {
                request_id: req.request_id,
                events,
                total,
                has_more,
            })
        }
        Err(e) => IpcMessage::Error(ErrorResponse {
            request_id: Some(req.request_id),
            code: "DATABASE_ERROR".to_string(),
            message: format!("Failed to get events: {}", e),
        }),
    }
}

async fn handle_get_status(
    crmonban: &Arc<RwLock<Crmonban>>,
    events_processed: &Arc<RwLock<u64>>,
    start_time: std::time::Instant,
) -> IpcMessage {
    let crmonban = crmonban.read().await;
    let events = *events_processed.read().await;

    let active_bans = crmonban.list_bans().map(|b| b.len() as u64).unwrap_or(0);

    let monitored_services: Vec<String> = crmonban
        .config
        .services
        .iter()
        .filter(|(_, s)| s.enabled)
        .map(|(name, _)| name.clone())
        .collect();

    // Get system resource usage
    let memory_bytes = {
        #[cfg(target_os = "linux")]
        {
            std::fs::read_to_string("/proc/self/statm")
                .ok()
                .and_then(|s| s.split_whitespace().nth(1)?.parse::<u64>().ok())
                .map(|pages| pages * 4096) // Page size is typically 4KB
                .unwrap_or(0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            0
        }
    };

    IpcMessage::StatusResponse(StatusResponse {
        request_id: None,
        running: true,
        pid: std::process::id(),
        uptime_secs: start_time.elapsed().as_secs(),
        active_bans,
        events_processed: events,
        monitored_services,
        ipc_clients: 0, // Would need access to IpcServer to get this
        memory_bytes,
        cpu_usage: 0.0, // Would need to track CPU usage
    })
}

async fn handle_get_config(crmonban: &Arc<RwLock<Crmonban>>) -> IpcMessage {
    let crmonban = crmonban.read().await;
    let config = crmonban.config();

    let services: Vec<ServiceSummary> = config
        .services
        .iter()
        .map(|(name, s)| ServiceSummary {
            name: name.clone(),
            enabled: s.enabled,
            log_path: s.log_path.clone(),
            max_failures: s.max_failures,
            find_time: s.find_time,
            ban_time: s.ban_time,
        })
        .collect();

    IpcMessage::ConfigResponse(ConfigResponse {
        request_id: None,
        services,
        port_scan_enabled: config.port_scan.enabled,
        dpi_enabled: config.dpi.enabled,
        dbus_enabled: config.dbus.enabled,
        default_ban_duration: config.general.default_ban_duration,
        auto_intel: config.general.auto_intel,
    })
}

async fn handle_action(
    crmonban: &Arc<RwLock<Crmonban>>,
    req: ipc::ActionRequest,
) -> IpcMessage {
    let result = match req.action {
        ActionType::Ban {
            ip,
            reason,
            duration_secs,
        } => {
            let guard = crmonban.read().await;
            guard.ban(ip, reason, BanSource::Manual, duration_secs)
        }
        ActionType::Unban { ip } => {
            let guard = crmonban.read().await;
            guard.unban(&ip).map(|_| ())
        }
        ActionType::Whitelist { ip, comment } => {
            let guard = crmonban.read().await;
            guard.whitelist_add(ip, comment)
        }
        ActionType::UnWhitelist { ip } => {
            let guard = crmonban.read().await;
            guard.whitelist_remove(&ip).map(|_| ())
        }
        ActionType::RefreshIntel { ip } => {
            let guard = crmonban.read().await;
            guard.gather_and_save_intel(&ip).await.map(|_| ())
        }
    };

    match result {
        Ok(()) => IpcMessage::ActionResponse(ActionResponse {
            request_id: req.request_id,
            success: true,
            message: "Action completed successfully".to_string(),
        }),
        Err(e) => IpcMessage::ActionResponse(ActionResponse {
            request_id: req.request_id,
            success: false,
            message: format!("Action failed: {}", e),
        }),
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
