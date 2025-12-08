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
use tracing::{debug, error, info, warn};

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
        let firewall = Firewall::with_all(
            config.nftables.clone(),
            config.deployment.clone(),
            port_scan,
            dpi,
            tls_proxy,
            port_rules,
        );
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
        let firewall = Firewall::with_all(
            config.nftables.clone(),
            config.deployment.clone(),
            port_scan,
            dpi,
            tls_proxy,
            port_rules,
        );
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
        let packet_engine_config = crmonban.config.packet_engine.clone();
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

        // Spawn packet engine task if enabled
        #[cfg(feature = "packet-engine")]
        let packet_engine_handle = if packet_engine_config.enabled {
            let event_tx_engine = event_tx.clone();
            let crmonban_for_engine = self.crmonban.clone();
            Some(tokio::spawn(async move {
                if let Err(e) = start_packet_engine(packet_engine_config, event_tx_engine, crmonban_for_engine).await {
                    error!("Packet engine error: {}", e);
                }
            }))
        } else {
            info!("Packet engine is disabled");
            None
        };
        #[cfg(not(feature = "packet-engine"))]
        let packet_engine_handle: Option<tokio::task::JoinHandle<()>> = {
            if packet_engine_config.enabled {
                warn!("Packet engine requested but not compiled in (missing packet-engine feature)");
            }
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
        if let Some(handle) = packet_engine_handle {
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

/// Start the packet engine for live packet capture and NIDS processing
#[cfg(feature = "packet-engine")]
async fn start_packet_engine(
    config: config::PacketEngineConfig,
    event_tx: mpsc::Sender<MonitorEvent>,
    _crmonban: Arc<RwLock<Crmonban>>,
) -> Result<()> {
    use engine::capture::{CaptureConfig, CaptureMethod, create_capture};
    use core::packet::IpProtocol;

    info!("Starting packet engine on interface: {:?}", config.interface);

    // Convert config to capture config
    let capture_method = match config.capture_method.as_str() {
        "af_packet" | "afpacket" => CaptureMethod::AfPacket,
        "nfqueue" => CaptureMethod::Nfqueue,
        "pcap" => CaptureMethod::Pcap,
        _ => CaptureMethod::AfPacket,
    };

    let capture_config = CaptureConfig {
        method: capture_method,
        nfqueue_num: config.nfqueue_num,
        interface: config.interface.clone(),
        pcap_file: None,
        snaplen: config.snaplen,
        timeout_ms: config.timeout_ms,
        buffer_size: 65536,
        promiscuous: config.promiscuous,
    };

    // Create capture
    let mut capture = create_capture(&capture_config)?;

    // Load signatures if enabled
    #[cfg(feature = "signatures")]
    let signature_engine = if config.signatures_enabled {
        info!("Loading signatures...");
        let mut sig_config = signatures::SignatureConfig::default();

        // Override rules_dir from packet engine config
        if let Some(ref rules_dir) = config.rules_dir {
            sig_config.rule_dirs = vec![std::path::PathBuf::from(rules_dir)];
        }

        let mut engine = signatures::SignatureEngine::new(sig_config.clone());

        // Load rules using RuleLoader
        let mut loader = signatures::RuleLoader::new(sig_config.clone());

        // Load classification.config for priority mapping
        if let Some(ref rules_dir) = config.rules_dir {
            let classification_path = std::path::Path::new(rules_dir).join("classification.config");
            if classification_path.exists() {
                if let Err(e) = loader.load_classifications(&classification_path) {
                    warn!("Failed to load classification.config: {}", e);
                }
            }
        }

        match loader.load_all() {
            Ok(ruleset) => {
                info!("Loaded {} rules ({} enabled, {} with content patterns)",
                    ruleset.stats.total_rules,
                    ruleset.stats.total_rules - ruleset.stats.disabled,
                    ruleset.stats.with_content);
                // Add rules to engine
                for (_, rule) in ruleset.rules {
                    engine.add_rule(rule);
                }
                engine.rebuild_prefilter();
                info!("Prefilter patterns: {}", engine.prefilter_pattern_count());
            }
            Err(e) => {
                warn!("Failed to load rules: {}", e);
            }
        }
        Some(engine)
    } else {
        None
    };
    #[cfg(not(feature = "signatures"))]
    let signature_engine: Option<()> = None;

    // Create flow tracker if enabled
    #[cfg(feature = "flow-tracking")]
    let mut flow_tracker = if config.flow_tracking {
        info!("Flow tracking enabled");
        Some(flow::FlowTracker::new(flow::FlowConfig::default()))
    } else {
        None
    };

    // Create ML engine if enabled
    #[cfg(feature = "ml-detection")]
    let mut ml_engine = if config.ml_detection {
        info!("ML anomaly detection enabled");
        let mut engine = ml::MLEngine::default();
        // Try to load existing model
        if let Err(e) = engine.load_model() {
            debug!("No existing ML model: {}", e);
        }
        Some(engine)
    } else {
        None
    };

    // Create threat intel engine if enabled
    #[cfg(feature = "threat-intel")]
    let intel_engine = if config.threat_intel {
        info!("Threat intelligence enabled");
        let engine = threat_intel::IntelEngineBuilder::new()
            .with_default_feeds()
            .build();
        // Initial cache load
        let _ = engine.load_cache();
        Some(engine)
    } else {
        None
    };

    info!("Packet engine started, listening for packets...");

    let mut packet_count: u64 = 0;
    let mut alert_count: u64 = 0;

    // Timing statistics (in microseconds)
    let mut timing_capture_us: u64 = 0;
    let mut timing_context_us: u64 = 0;
    let mut timing_match_us: u64 = 0;
    let mut timing_flow_us: u64 = 0;
    let mut timing_ml_us: u64 = 0;
    let mut timing_intel_us: u64 = 0;
    let mut timing_event_us: u64 = 0;
    let mut timing_total_us: u64 = 0;
    let mut timing_samples: u64 = 0;

    // Statistics counters
    let mut ml_anomaly_count: u64 = 0;
    let mut threat_intel_hits: u64 = 0;
    let mut flows_tracked: u64 = 0;

    // Main capture loop
    loop {
        let loop_start = std::time::Instant::now();

        // Stage 1: Capture (includes parsing in AfPacketCapture)
        let capture_start = std::time::Instant::now();
        match capture.next_packet() {
            Ok(Some(packet)) => {
                let capture_elapsed = capture_start.elapsed().as_micros() as u64;
                timing_capture_us += capture_elapsed;

                packet_count += 1;
                timing_samples += 1;

                // Log timing stats periodically
                if packet_count % 10000 == 0 {
                    let avg_capture = timing_capture_us / timing_samples.max(1);
                    let avg_context = timing_context_us / timing_samples.max(1);
                    let avg_match = timing_match_us / timing_samples.max(1);
                    let avg_flow = timing_flow_us / timing_samples.max(1);
                    let avg_ml = timing_ml_us / timing_samples.max(1);
                    let avg_intel = timing_intel_us / timing_samples.max(1);
                    let avg_event = timing_event_us / timing_samples.max(1);
                    let avg_total = timing_total_us / timing_samples.max(1);
                    info!(
                        "Packets: {} | alerts: {} ml: {} intel: {} flows: {} | Timing (us): cap={} ctx={} sig={} flow={} ml={} intel={} evt={} tot={}",
                        packet_count, alert_count, ml_anomaly_count, threat_intel_hits, flows_tracked,
                        avg_capture, avg_context, avg_match, avg_flow, avg_ml, avg_intel, avg_event, avg_total
                    );
                }

                // Check signatures
                #[cfg(feature = "signatures")]
                if let Some(ref engine) = signature_engine {
                    use signatures::matcher::PacketContext;
                    use signatures::ast::Protocol;

                    // Stage 2: Build context
                    let context_start = std::time::Instant::now();
                    let ctx = PacketContext {
                        src_ip: Some(packet.src_ip),
                        dst_ip: Some(packet.dst_ip),
                        src_port: Some(packet.src_port),
                        dst_port: Some(packet.dst_port),
                        protocol: match packet.protocol {
                            IpProtocol::Tcp => Protocol::Tcp,
                            IpProtocol::Udp => Protocol::Udp,
                            IpProtocol::Icmp | IpProtocol::Icmpv6 => Protocol::Icmp,
                            _ => Protocol::Ip,
                        },
                        tcp_flags: packet.tcp_flags.as_ref().map(|f| {
                            let mut flags = 0u8;
                            if f.syn { flags |= 0x02; }
                            if f.ack { flags |= 0x10; }
                            if f.fin { flags |= 0x01; }
                            if f.rst { flags |= 0x04; }
                            if f.psh { flags |= 0x08; }
                            if f.urg { flags |= 0x20; }
                            flags
                        }).unwrap_or(0),
                        ttl: 64,
                        payload: packet.payload.clone(),
                        established: false,
                        to_server: true,
                        http_uri: None,
                        http_method: None,
                        http_headers: None,
                        http_host: None,
                        http_user_agent: None,
                        dns_query: None,
                        tls_sni: None,
                        ja3_hash: None,
                    };
                    let context_elapsed = context_start.elapsed().as_micros() as u64;
                    timing_context_us += context_elapsed;

                    // Stage 3: Signature matching
                    let match_start = std::time::Instant::now();
                    let matches = engine.match_packet(&ctx);
                    let match_elapsed = match_start.elapsed().as_micros() as u64;
                    timing_match_us += match_elapsed;

                    // Stage 4: Event processing
                    let event_start = std::time::Instant::now();
                    for m in matches {
                        alert_count += 1;
                        let priority = m.priority;
                        info!(
                            "Signature match: [{}:{}] {} -> {}:{} - {}",
                            m.sid, priority,
                            packet.src_ip, packet.dst_ip, packet.dst_port,
                            m.msg
                        );

                        // Send alert event
                        let attack_event = models::AttackEvent {
                            id: None,
                            timestamp: chrono::Utc::now(),
                            ip: packet.src_ip,
                            service: format!("nids:{}", m.classtype.as_deref().unwrap_or("unknown")),
                            event_type: models::AttackEventType::SignatureMatch,
                            details: Some(format!("[{}] {}", m.sid, m.msg)),
                            log_line: String::new(),
                        };

                        if let Err(e) = event_tx.send(MonitorEvent::Attack(attack_event)).await {
                            warn!("Failed to send attack event: {}", e);
                        }

                        // Auto-ban if configured (priority 1-2 are high severity)
                        if config.auto_ban && priority <= 2 {
                            let ban_reason = format!("NIDS signature match: [{}] {}", m.sid, m.msg);
                            if let Err(e) = event_tx.send(MonitorEvent::Ban {
                                ip: packet.src_ip,
                                service: "nids".to_string(),
                                reason: ban_reason,
                                duration_secs: config.ban_duration,
                            }).await {
                                warn!("Failed to send ban event: {}", e);
                            }
                        }
                    }
                    let event_elapsed = event_start.elapsed().as_micros() as u64;
                    timing_event_us += event_elapsed;
                }

                // Flow Tracking - process packet through flow tracker
                #[cfg(feature = "flow-tracking")]
                let current_flow = if let Some(ref mut tracker) = flow_tracker {
                    let flow_start = std::time::Instant::now();
                    let mut pkt = packet.clone();
                    let (flow, _direction) = tracker.process(&mut pkt);
                    let flow_clone = flow.clone();
                    let flow_elapsed = flow_start.elapsed().as_micros() as u64;
                    timing_flow_us += flow_elapsed;
                    flows_tracked = tracker.stats().active_flows as u64;
                    Some(flow_clone)
                } else {
                    None
                };

                // ML Anomaly Detection - process flow through ML engine
                #[cfg(feature = "ml-detection")]
                if let Some(ref mut engine) = ml_engine {
                    let ml_start = std::time::Instant::now();
                    #[cfg(feature = "flow-tracking")]
                    if let Some(ref flow) = current_flow {
                        if let Some(anomaly_score) = engine.process_flow(flow) {
                            ml_anomaly_count += 1;
                            warn!(
                                "ML Anomaly detected: {} -> {} score={:.3} category={:?} - {}",
                                packet.src_ip, packet.dst_ip,
                                anomaly_score.score,
                                anomaly_score.category,
                                anomaly_score.explanation.as_deref().unwrap_or("unknown")
                            );

                            // Send ML anomaly event
                            let attack_event = models::AttackEvent {
                                id: None,
                                timestamp: chrono::Utc::now(),
                                ip: packet.src_ip,
                                service: "ml".to_string(),
                                event_type: models::AttackEventType::Anomaly,
                                details: Some(format!(
                                    "Anomaly score: {:.3}, Category: {:?}",
                                    anomaly_score.score,
                                    anomaly_score.category
                                )),
                                log_line: String::new(),
                            };

                            if let Err(e) = event_tx.send(MonitorEvent::Attack(attack_event)).await {
                                warn!("Failed to send ML anomaly event: {}", e);
                            }

                            // Auto-ban on high-confidence anomalies
                            if config.auto_ban && anomaly_score.score > 0.9 {
                                if let Err(e) = event_tx.send(MonitorEvent::Ban {
                                    ip: packet.src_ip,
                                    service: "ml".to_string(),
                                    reason: format!("ML anomaly: score={:.3}", anomaly_score.score),
                                    duration_secs: config.ban_duration,
                                }).await {
                                    warn!("Failed to send ML ban event: {}", e);
                                }
                            }
                        }
                    }
                    let ml_elapsed = ml_start.elapsed().as_micros() as u64;
                    timing_ml_us += ml_elapsed;
                }

                // Threat Intelligence - check source IP against threat feeds
                #[cfg(feature = "threat-intel")]
                if let Some(ref engine) = intel_engine {
                    let intel_start = std::time::Instant::now();
                    if let Some(threat_match) = engine.check_ip(&packet.src_ip) {
                        threat_intel_hits += 1;
                        alert_count += 1;
                        warn!(
                            "Threat Intel match: {} - {} (category: {:?}, severity: {:?}, feed: {})",
                            packet.src_ip,
                            threat_match.ioc.value,
                            threat_match.ioc.category,
                            threat_match.ioc.severity,
                            threat_match.ioc.source
                        );

                        // Send threat intel event
                        let attack_event = models::AttackEvent {
                            id: None,
                            timestamp: chrono::Utc::now(),
                            ip: packet.src_ip,
                            service: "threat_intel".to_string(),
                            event_type: models::AttackEventType::ThreatIntel,
                            details: Some(format!(
                                "Threat: {:?} from {} - {}",
                                threat_match.ioc.category,
                                threat_match.ioc.source,
                                threat_match.ioc.description.as_deref().unwrap_or("known malicious")
                            )),
                            log_line: String::new(),
                        };

                        if let Err(e) = event_tx.send(MonitorEvent::Attack(attack_event)).await {
                            warn!("Failed to send threat intel event: {}", e);
                        }

                        // Auto-ban critical/high severity threats
                        if config.auto_ban {
                            use threat_intel::Severity;
                            if matches!(threat_match.ioc.severity, Severity::Critical | Severity::High) {
                                if let Err(e) = event_tx.send(MonitorEvent::Ban {
                                    ip: packet.src_ip,
                                    service: "threat_intel".to_string(),
                                    reason: format!("Threat intel: {:?} - {}", threat_match.ioc.category, threat_match.ioc.source),
                                    duration_secs: config.ban_duration,
                                }).await {
                                    warn!("Failed to send threat intel ban event: {}", e);
                                }
                            }
                        }
                    }
                    let intel_elapsed = intel_start.elapsed().as_micros() as u64;
                    timing_intel_us += intel_elapsed;
                }

                let total_elapsed = loop_start.elapsed().as_micros() as u64;
                timing_total_us += total_elapsed;
            }
            Ok(None) => {
                // No packet available (timeout)
                tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
            }
            Err(e) => {
                error!("Capture error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
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
