// Core types - re-exported at crate root for external use
pub mod types;
pub use types::*;

pub mod cloudflare;
pub mod cloudflare_api;
pub mod config;
pub mod database;
pub mod feedback;
#[cfg(feature = "dbus")]
pub mod dbus;
pub mod dpi;
pub mod ebpf;
pub mod firewall;
pub mod http_detect;
pub mod intel;
pub mod ipfilter;
pub mod ipc;
pub mod malware_detect;
pub mod models;
pub mod monitor;
pub mod journald_monitor;
pub mod layer234;
pub mod l2_monitor;
#[cfg(feature = "wireless")]
pub mod wireless;
pub mod port_scan_monitor;
pub mod shared_whitelist;
pub mod siem;
#[cfg(feature = "signatures")]
pub mod signatures;
pub mod testing;
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

// LLM Integration (optional)
#[cfg(feature = "llm")]
pub mod llm;

// NIDS Stage 7: Alert Correlation
#[cfg(feature = "correlation")]
pub mod correlation;

// NIDS Stage 7b: WASM Plugin Processing
#[cfg(feature = "packet-engine")]
pub mod wasm;

// NIDS Stage 8: Packet Engine
#[cfg(feature = "packet-engine")]
pub mod engine;

// Audit logging for offline analysis
#[cfg(feature = "packet-engine")]
pub mod audit;

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

/// Check rules freshness and warn if they are outdated
#[cfg(feature = "signatures")]
fn check_rules_freshness(rules_dir: &str) {
    use std::time::SystemTime;

    let rules_path = Path::new(rules_dir);
    if !rules_path.exists() {
        warn!("Rules directory does not exist: {}", rules_dir);
        warn!("To download rules, run: crmonban rules update");
        return;
    }

    // Check for any .rules files
    let mut rules_found = false;
    let mut newest_mtime: Option<SystemTime> = None;

    if let Ok(entries) = std::fs::read_dir(rules_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| e == "rules") {
                rules_found = true;
                if let Ok(metadata) = path.metadata() {
                    if let Ok(mtime) = metadata.modified() {
                        if newest_mtime.is_none() || mtime > newest_mtime.unwrap() {
                            newest_mtime = Some(mtime);
                        }
                    }
                }
            }
        }
    }

    if !rules_found {
        warn!("No .rules files found in {}", rules_dir);
        warn!("To download rules, run: crmonban rules update");
        return;
    }

    // Check age of newest rules file
    if let Some(mtime) = newest_mtime {
        if let Ok(age) = SystemTime::now().duration_since(mtime) {
            let days = age.as_secs() / 86400;
            if days > 30 {
                warn!("Rules are {} days old - consider updating", days);
                warn!("To update rules, run: crmonban rules update");
            } else if days > 7 {
                info!("Rules are {} days old", days);
            } else {
                info!("Rules are up to date ({} days old)", days);
            }
        }
    }
}

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
        // Enable the DPI nft queue rules when DPI is configured OR the packet
        // engine runs in NFQUEUE mode — otherwise the engine binds a queue the
        // kernel never feeds. Align the rule's queue number with the one the
        // engine binds, so queued packets actually reach the listener.
        let nfqueue_mode =
            config.packet_engine.enabled && config.packet_engine.capture_method == "nfqueue";
        let dpi = if config.dpi.enabled || nfqueue_mode {
            let mut d = config.dpi.clone();
            d.enabled = true;
            if nfqueue_mode {
                d.queue_num = config.packet_engine.nfqueue_num;
                d.queue_until_decided = config.packet_engine.queue_until_decided;
            }
            Some(d)
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
        // Enable the DPI nft queue rules when DPI is configured OR the packet
        // engine runs in NFQUEUE mode — otherwise the engine binds a queue the
        // kernel never feeds. Align the rule's queue number with the one the
        // engine binds, so queued packets actually reach the listener.
        let nfqueue_mode =
            config.packet_engine.enabled && config.packet_engine.capture_method == "nfqueue";
        let dpi = if config.dpi.enabled || nfqueue_mode {
            let mut d = config.dpi.clone();
            d.enabled = true;
            if nfqueue_mode {
                d.queue_num = config.packet_engine.nfqueue_num;
                d.queue_until_decided = config.packet_engine.queue_until_decided;
            }
            Some(d)
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
        self.firewall.init()?;
        // Populate the inline-DPI allow set so whitelisted AND Cloudflare sources
        // are accepted before the NFQUEUE and never inline-dropped by the engine.
        // NOTE: Firewall::init() early-returns when the table already exists, so
        // these rules only materialize on a FRESH table — an already-initialized
        // host needs a `cleanup` before the M2.2 queue/allow rules appear.
        let mut entries: Vec<String> = self
            .db
            .get_whitelist()?
            .into_iter()
            .map(|e| e.ip.to_string())
            .collect();
        entries.extend(
            crate::cloudflare::CLOUDFLARE_IPV4_RANGES
                .iter()
                .map(|s| s.to_string()),
        );
        entries.extend(
            crate::cloudflare::CLOUDFLARE_IPV6_RANGES
                .iter()
                .map(|s| s.to_string()),
        );
        self.firewall.sync_dpi_allow(&entries)?;
        Ok(())
    }

    /// Add a port rule to the firewall
    pub fn add_port_rule(&self, rule: &config::PortRule) -> Result<()> {
        self.firewall.add_port_rule(rule)
    }

    /// Sync database bans to nftables
    pub fn sync_bans(&self) -> Result<()> {
        // Observe-only: never push DB bans to the firewall. Record what we WOULD
        // sync and return, so the eval stays truly non-enforcing even across a
        // restart (the startup sync is the one ban path that doesn't funnel
        // through ban()/the enforce guard).
        if !self.config.general.enforce {
            let n = self.db.get_active_bans().map(|b| b.len()).unwrap_or(0);
            info!(
                "Observe-only: skipping firewall sync of {} active DB ban(s)",
                n
            );
            return Ok(());
        }
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
        // Single infrastructure guard for EVERY ban producer (journald, DPI,
        // TLS proxy, port scanner, IPC, D-Bus). Refuse to ban our own
        // infrastructure / reserved ranges (RFC1918, loopback, link-local,
        // multicast, broadcast, unspecified). Centralizing it here means no
        // producer can bypass it, and a forged/log-injected reserved IP can
        // never be pushed into the firewall. (Security audit A2/A16.)
        if crate::monitor::is_internal_ip(ip) {
            warn!(
                "Refusing to ban internal/reserved IP {} (infrastructure guard)",
                ip
            );
            return Ok(());
        }

        // Check whitelist
        if self.db.is_whitelisted(&ip)? {
            warn!("IP {} is whitelisted, not banning", ip);
            return Ok(());
        }

        let source_str = format!("{:?}", source);

        // OBSERVE-ONLY (general.enforce = false): record exactly what we WOULD
        // have banned — with full context — but never touch the firewall or the
        // ban table. This is the evaluation instrument: it yields the real
        // false-positive rate on live traffic without affecting a single user.
        if !self.config.general.enforce {
            self.log_event_json("would_ban", &ip, &reason, &source_str, duration_secs);
            self.db.log_activity(
                ActivityAction::Ban,
                Some(&ip),
                &format!("WOULD_BAN (observe-only): {}", reason),
            )?;
            info!("WOULD_BAN (observe-only) {} (reason: {})", ip, reason);
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

        self.log_event_json("ban", &ip, &reason, &source_str, duration_secs);
        info!("Banned IP: {} (reason: {})", ip, reason);
        Ok(())
    }

    /// Append one JSON line to the configured events log (the observe/eval
    /// record). No-op when general.events_log is unset. Best-effort: a write
    /// failure is logged, never fatal.
    fn log_event_json(
        &self,
        kind: &str,
        ip: &IpAddr,
        reason: &str,
        source: &str,
        duration_secs: Option<i64>,
    ) {
        let Some(ref path) = self.config.general.events_log else {
            return;
        };
        let line = serde_json::json!({
            "ts": Utc::now().to_rfc3339(),
            "type": kind,
            "ip": ip.to_string(),
            "source": source,
            "duration_secs": duration_secs,
            "enforced": self.config.general.enforce,
            "reason": reason,
        })
        .to_string();
        use std::io::Write;
        match std::fs::OpenOptions::new().create(true).append(true).open(path) {
            Ok(mut f) => {
                if let Err(e) = writeln!(f, "{}", line) {
                    warn!("events_log write to {} failed: {}", path, e);
                }
            }
            Err(e) => warn!("events_log open {} failed: {}", path, e),
        }
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

        // Keep the inline-DPI allow set in sync so the new whitelist entry takes
        // effect immediately, not only after a restart.
        if let Err(e) = self.firewall.sync_dpi_allow(&[ip.to_string()]) {
            warn!("Failed to add {} to inline-DPI allow set: {}", ip, e);
        }

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

        // Optional passive Layer-2 detection plane (ARP spoofing) on a raw-frame
        // capture — the inline nfqueue/IP path can't see ARP (NFQUEUE delivers IP
        // payloads with no Ethernet frame, and the core parser drops non-IP
        // frames). Runs as a dedicated monitor feeding the same event sink, so it
        // converges on the shared ban/alert store, not at the wire.
        //
        // The inline path now supersedes this: when the engine itself captures
        // full frames (af_packet) with L2 detection on, it taps ARP/DHCP/RA off
        // its own capture and the sidecar would only duplicate alerts on the same
        // wire. So run the standalone sidecar ONLY when the engine can't see L2
        // (non-af_packet mode) or it is pointed at a different interface.
        #[cfg(feature = "packet-engine")]
        let engine_inline_l2 = packet_engine_config.enabled
            && packet_engine_config.l2_detection
            && matches!(
                packet_engine_config.capture_method.as_str(),
                "af_packet" | "afpacket"
            );
        #[cfg(feature = "packet-engine")]
        let l2_iface: Option<String> = if packet_engine_config.enabled {
            match packet_engine_config.l2_af_packet_interface.clone() {
                Some(iface)
                    if engine_inline_l2
                        && packet_engine_config.interface.as_deref() == Some(iface.as_str()) =>
                {
                    info!(
                        "L2 sidecar on {} skipped: inline engine L2 detection already covers it",
                        iface
                    );
                    None
                }
                other => other,
            }
        } else {
            None
        };

        // Spawn packet engine task if enabled
        #[cfg(feature = "packet-engine")]
        let (packet_engine_handle, engine_shutdown_tx) = if packet_engine_config.enabled {
            let event_tx_engine = event_tx.clone();
            let crmonban_for_engine = self.crmonban.clone();
            let (eng_sd_tx, eng_sd_rx) = tokio::sync::oneshot::channel::<()>();
            let handle = tokio::spawn(async move {
                if let Err(e) = start_packet_engine(packet_engine_config, event_tx_engine, crmonban_for_engine, eng_sd_rx).await {
                    error!("Packet engine error: {}", e);
                }
            });
            (Some(handle), Some(eng_sd_tx))
        } else {
            info!("Packet engine is disabled");
            (None, None)
        };
        #[cfg(not(feature = "packet-engine"))]
        let (packet_engine_handle, engine_shutdown_tx): (
            Option<tokio::task::JoinHandle<()>>,
            Option<tokio::sync::oneshot::Sender<()>>,
        ) = {
            if packet_engine_config.enabled {
                warn!("Packet engine requested but not compiled in (missing packet-engine feature)");
            }
            (None, None)
        };

        // Spawn the L2 monitor (if configured) — passive raw-frame ARP detection,
        // same event sink as every other detector.
        #[cfg(feature = "packet-engine")]
        let l2_monitor_handle: Option<tokio::task::JoinHandle<()>> = if let Some(iface) = l2_iface {
            let event_tx_l2 = event_tx.clone();
            let handle = tokio::spawn(async move {
                let cfg = l2_monitor::L2MonitorConfig {
                    interface: iface,
                    ..Default::default()
                };
                if let Err(e) = l2_monitor::start_l2_monitor(cfg, event_tx_l2).await {
                    error!("L2 monitor error: {}", e);
                }
            });
            Some(handle)
        } else {
            None
        };
        #[cfg(not(feature = "packet-engine"))]
        let l2_monitor_handle: Option<tokio::task::JoinHandle<()>> = None;

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

        // CF push-on-ban kick: the ban hotpath signals here so a freshly-banned IP
        // is mirrored to the Cloudflare edge within ~1s, instead of riding the
        // periodic reconcile lag — which is the ONLY thing that blocks CF-proxied
        // attacks (the origin never sees their real client IP, so nft/conntrack are
        // both inert there).
        let (cf_kick_tx, cf_kick_rx) = tokio::sync::mpsc::channel::<()>(64);
        // Spawn Cloudflare-edge reconciler (M1): make the CF IP list equal the
        // active-ban set — on a ban-kick (debounced) AND a periodic backstop sweep.
        // Observe-safe — it only pushes when enforce=true.
        {
            let cf_enabled = self.crmonban.read().await.config.cloudflare.enabled;
            if cf_enabled {
                let cf_crmonban = self.crmonban.clone();
                tokio::spawn(async move {
                    let mut cf_kick_rx = cf_kick_rx;
                    let secs = cf_crmonban
                        .read()
                        .await
                        .config
                        .cloudflare
                        .reconcile_interval_secs
                        .max(10);
                    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(secs));
                    // A push-on-ban kick can land between ticks; without this the
                    // next periodic tick fires immediately to "catch up" (tokio's
                    // default Burst), doubling the reconcile. Skip missed ticks so
                    // the periodic sweep stays exactly one-per-interval regardless
                    // of kicks.
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        // Reconcile on the periodic tick OR the moment a ban kicks us
                        // (debounced ~750ms to coalesce a ban burst into one push).
                        tokio::select! {
                            _ = interval.tick() => {}
                            _ = cf_kick_rx.recv() => {
                                tokio::time::sleep(tokio::time::Duration::from_millis(750)).await;
                                while cf_kick_rx.try_recv().is_ok() {}
                            }
                        }
                        // Snapshot config + active bans under the lock, then release it
                        // BEFORE the network round-trip (never hold the lock across I/O).
                        let snapshot = {
                            let c = cf_crmonban.read().await;
                            if !c.config.general.enforce {
                                None // observe-only: never touch the CF account
                            } else {
                                let active = c
                                    .db
                                    .get_active_bans()
                                    .map(|b| b.iter().map(|x| x.ip).collect::<Vec<_>>())
                                    .unwrap_or_default();
                                Some((c.config.cloudflare.clone(), active))
                            }
                        };
                        if let Some((cfg, active)) = snapshot {
                            if let Err(e) = crate::cloudflare_api::reconcile_once(&cfg, &active).await
                            {
                                warn!("cloudflare reconcile error: {}", e);
                            }
                        }
                    }
                });
                info!("Cloudflare-edge reconciler started (push-on-ban + periodic backstop)");
            }
        }

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
                                // push-on-ban: nudge the CF reconciler to mirror this
                                // ban to the edge now (the only block that stops a
                                // CF-proxied attacker). Best-effort; the periodic
                                // sweep is the backstop.
                                let _ = cf_kick_tx.try_send(());

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
        if let Some(tx) = engine_shutdown_tx {
            let _ = tx.send(());
        }
        if let Some(handle) = l2_monitor_handle {
            // The L2 monitor blocks in libpcap; abort the task (the blocking
            // thread is reclaimed on process exit).
            handle.abort();
        }
        if let Some(handle) = packet_engine_handle {
            // Let the engine stop gracefully (drain in-flight verdicts + unbind
            // NFQUEUE), bounded so a stuck engine cannot hang shutdown.
            match tokio::time::timeout(std::time::Duration::from_secs(8), handle).await {
                Ok(_) => {}
                Err(_) => warn!("Packet engine did not stop within 8s"),
            }
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
            IpcMessage::Action(req) => handle_action(&crmonban, req, request.peer_uid).await,
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

/// Authorize a mutating IPC action.
///
/// Mutating actions (Ban/Unban/Whitelist/UnWhitelist/RefreshIntel) are
/// privileged: on the local Unix socket they require the caller to be root or
/// the daemon's own effective UID (SO_PEERCRED); TCP callers (`peer_uid = None`)
/// are already authenticated by mTLS because the TCP listener refuses to start
/// without `require_client_cert`. This stops any local group member (the socket
/// is group-readable, 0o660) from banning infrastructure or whitelisting
/// themselves. (Security audit A4.)
fn action_authorized(peer_uid: Option<u32>) -> bool {
    match peer_uid {
        // TCP client — authenticated via mTLS client certificate.
        None => true,
        // Local peer: allow root or a process running as the daemon's own UID.
        Some(uid) => {
            let self_uid = unsafe { libc::geteuid() };
            uid == 0 || uid == self_uid
        }
    }
}

async fn handle_action(
    crmonban: &Arc<RwLock<Crmonban>>,
    req: ipc::ActionRequest,
    peer_uid: Option<u32>,
) -> IpcMessage {
    if !action_authorized(peer_uid) {
        warn!(
            "Rejected unauthorized IPC action from uid {:?} (mutating actions require root or the daemon UID)",
            peer_uid
        );
        return IpcMessage::ActionResponse(ActionResponse {
            request_id: req.request_id,
            success: false,
            message: "Not authorized: mutating actions require root or mTLS".to_string(),
        });
    }

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
    engine_shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
    use crate::core::{DetectionAction, DetectionEvent};
    use crate::models::{AttackEvent, AttackEventType};
    use engine::capture::{CaptureConfig, CaptureMethod};
    use engine::{PacketEngine, PacketEngineConfig as EngineConfig, PipelineConfig, WorkerConfig};

    info!("Starting packet engine on interface: {:?}", config.interface);

    // Rules freshness check (carried over from the previous engine).
    if let Some(ref rules_dir) = config.rules_dir {
        check_rules_freshness(rules_dir);
    }

    let capture_method = match config.capture_method.as_str() {
        "af_packet" | "afpacket" => CaptureMethod::AfPacket,
        "nfqueue" => CaptureMethod::Nfqueue,
        "pcap" => CaptureMethod::Pcap,
        _ => CaptureMethod::AfPacket,
    };
    // Good-flow bypass (queue-until-decided) only applies inline: it stops queueing
    // a proven-good flow. In passive modes (af_packet/pcap) there is no queue and
    // no kernel bypass, so enabling it would only make the monitor skip a "good"
    // flow's later packets — blinding it. Force full inspection off-queue.
    let is_nfqueue = matches!(capture_method, CaptureMethod::Nfqueue);

    // Inline Layer-2 detection: only af_packet captures see full Ethernet frames,
    // so ARP/DHCP/RA can ride the engine's own capture seam there. In nfqueue/IP
    // mode the frame is gone before userspace, so L2 stays the standalone
    // sidecar's job. Gate on the config toggle (default on).
    let l2_inline_cfg = if matches!(capture_method, CaptureMethod::AfPacket) && config.l2_detection {
        info!("Inline L2 detection (ARP/DHCP/RA) active on the af_packet engine capture");
        Some(crate::layer234::L2InspectConfig::default())
    } else {
        None
    };

    // Map the daemon's packet-engine config onto the engine's config.
    let engine_config = EngineConfig {
        enabled: true,
        capture: CaptureConfig {
            method: capture_method,
            nfqueue_num: config.nfqueue_num,
            interface: config.interface.clone(),
            pcap_file: None,
            snaplen: config.snaplen,
            timeout_ms: config.timeout_ms,
            buffer_size: 65536,
            promiscuous: config.promiscuous,
            l2_detection: l2_inline_cfg,
        },
        pipeline: PipelineConfig {
            enable_flows: true,
            enable_layer234: true,
            // Protocol analysis runs the HTTP/DNS/TLS analyzers and the web-attack
            // heuristic (SQLi/XSS/traversal/Log4Shell, DNS tunneling). It was
            // off-by-default, so none of that ran inline — enable it so the
            // protocol layer actually detects.
            enable_protocols: true,
            enable_signatures: config.signatures_enabled,
            enable_ml: config.ml_detection,
            enable_correlation: false,
            // Queue-until-decided: mark proven-good flows so the kernel bypasses
            // them in-kernel and keep inspecting undecided ones (paired with the
            // nft ct-mark queue rule). Gated to nfqueue inline mode (see
            // is_nfqueue above) so af_packet/observe stays full-inspection.
            // Gated on the explicit opt-in flag (default false). The in-kernel
            // good-flow bypass is direction-blind and lets a keep-alive/HTTP-2/
            // persistent-TLS connection carry an exploit uninspected once marked
            // good, so the default inline deployment now keeps inspecting every
            // packet. (Security audit B1.)
            bypass_good_flows: config.bypass_good_flows && config.queue_until_decided && is_nfqueue,
            // Per-packet, per-stage instrumentation toggle. Off by default (one
            // line per stage per packet is far too chatty for production); set
            // CRMONBAN_TRACE_PACKETS=1 to emit the `[trace] pkt N STAGE [gates]:
            // +Nev verdict=X` lines to stderr for live pipeline debugging.
            trace_packets: std::env::var("CRMONBAN_TRACE_PACKETS").is_ok(),
            // How often the engine emits its PERF keep-up line (default 60s).
            perf_interval_secs: config.perf_interval_secs,
            ..Default::default()
        },
        worker: WorkerConfig {
            // Wire the configured worker count through. 0 = auto-detect
            // (num_cpus); any positive value pins the pool size. Previously this
            // field was dropped on the floor (always auto), so config.workers was
            // a no-op — honour it now.
            num_workers: config.workers,
            rules_dir: config.rules_dir.clone().map(std::path::PathBuf::from),
            ssl_log: config.ssl_log.clone().map(std::path::PathBuf::from),
            ..Default::default()
        },
        action: Default::default(),
    };

    // The engine emits DetectionEvents; bridge them to the daemon's existing
    // MonitorEvent consumer so the packet engine shares the SAME ban+audit path as
    // the log monitors: record the event, and on a blocking detection call
    // crmonban.ban -> firewall @blocked + DB audit + whitelist check.
    let (det_tx, mut det_rx) = mpsc::channel::<DetectionEvent>(1024);
    let bridge_tx = event_tx.clone();
    tokio::spawn(async move {
        // Default ban length for packet-engine detections (seconds).
        const PACKET_ENGINE_BAN_SECS: i64 = 3600;
        // Suppress duplicate bans for the same source within this window (bounds
        // re-bans from a non-cacheable flood, e.g. ICMP).
        const BAN_DEDUPE_SECS: u64 = 60;
        let mut recently_banned: std::collections::HashMap<std::net::IpAddr, std::time::Instant> =
            std::collections::HashMap::new();
        while let Some(ev) = det_rx.recv().await {
            // Audit: record every detection as an attack event.
            let attack = AttackEvent {
                id: None,
                ip: ev.src_ip,
                timestamp: Utc::now(),
                service: "packet-engine".to_string(),
                event_type: AttackEventType::Other(format!("{:?}", ev.event_type)),
                details: Some(ev.message.clone()),
                log_line: ev.message.clone(),
            };
            if bridge_tx.send(MonitorEvent::Attack(attack)).await.is_err() {
                break;
            }

            // Resolution: a blocking verdict (the pipeline rewrites event.action
            // to Ban only when it actually enforces a block) escalates to banning
            // the source so its future traffic is dropped in-kernel (@blocked) and
            // never re-queued.
            if matches!(
                ev.action,
                DetectionAction::Drop | DetectionAction::Reject | DetectionAction::Ban
            ) {
                let now = std::time::Instant::now();
                let recent = recently_banned
                    .get(&ev.src_ip)
                    .map(|t| now.duration_since(*t) < std::time::Duration::from_secs(BAN_DEDUPE_SECS))
                    .unwrap_or(false);
                if !recent {
                    if recently_banned.len() > 100_000 {
                        recently_banned.clear();
                    }
                    recently_banned.insert(ev.src_ip, now);
                    let ban = MonitorEvent::Ban {
                        ip: ev.src_ip,
                        service: "packet-engine".to_string(),
                        reason: ev.message.clone(),
                        duration_secs: PACKET_ENGINE_BAN_SECS,
                    };
                    if bridge_tx.send(ban).await.is_err() {
                        break;
                    }
                }
            }
        }
        debug!("Packet-engine event bridge exiting");
    });

    // Build, wire, and run the engine. PacketEngine carries the 8-stage pipeline,
    // inline NFQUEUE verdict feedback, and the per-flow verdict cache.
    let mut engine = PacketEngine::new(engine_config);
    engine.set_event_channel(det_tx);
    engine.start().await?;

    info!("Packet engine started (PacketEngine): inline verdicts + flow cache + ban resolution active");

    // Run until the daemon signals shutdown, then stop the engine GRACEFULLY:
    // stop() flips state to Stopping, joins the capture thread (draining in-flight
    // verdicts within its 5s deadline) and unbinds the NFQUEUE — rather than being
    // aborted mid-flight, which would leak the capture thread and the queue bind.
    let _ = engine_shutdown_rx.await;
    info!("Packet engine: shutdown signal received, stopping...");
    if let Err(e) = engine.stop().await {
        warn!("Error stopping packet engine: {}", e);
    }
    Ok(())
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
