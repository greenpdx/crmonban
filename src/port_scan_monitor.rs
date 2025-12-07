use anyhow::{Context, Result};
use chrono::Utc;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::PortScanConfig;
use crate::monitor::MonitorEvent;

/// Port access record for tracking unique port hits
#[derive(Debug, Clone)]
struct PortAccess {
    ports: HashMap<u16, chrono::DateTime<Utc>>,
}

impl PortAccess {
    fn new() -> Self {
        Self {
            ports: HashMap::new(),
        }
    }

    fn add_port(&mut self, port: u16) {
        self.ports.entry(port).or_insert_with(Utc::now);
    }

    fn unique_port_count(&self) -> usize {
        self.ports.len()
    }

    fn cleanup_old(&mut self, window_secs: u64) {
        let cutoff = Utc::now() - chrono::Duration::seconds(window_secs as i64);
        self.ports.retain(|_, time| *time > cutoff);
    }
}

/// Scan type detected
#[derive(Debug, Clone, PartialEq)]
pub enum ScanType {
    /// TCP SYN scan (half-open)
    Syn,
    /// TCP NULL scan (no flags)
    Null,
    /// TCP XMAS scan (FIN+PSH+URG)
    Xmas,
    /// TCP FIN scan (only FIN)
    Fin,
    /// UDP scan
    Udp,
    /// Generic port scan (multiple ports accessed)
    Generic,
}

impl std::fmt::Display for ScanType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanType::Syn => write!(f, "SYN scan"),
            ScanType::Null => write!(f, "NULL scan"),
            ScanType::Xmas => write!(f, "XMAS scan"),
            ScanType::Fin => write!(f, "FIN scan"),
            ScanType::Udp => write!(f, "UDP scan"),
            ScanType::Generic => write!(f, "port scan"),
        }
    }
}

/// Port scan monitor that tracks port access via nftables logging
pub struct PortScanMonitor {
    config: PortScanConfig,
    log_path: PathBuf,
    file_position: u64,
    /// Track port accesses per IP
    ip_port_access: HashMap<IpAddr, PortAccess>,
    /// Compiled regex patterns for log parsing
    patterns: PortScanPatterns,
}

/// Compiled regex patterns for different log formats
struct PortScanPatterns {
    /// Standard kernel log format (iptables/nftables LOG target)
    kernel_log: Regex,
    /// nflog format via ulogd
    nflog: Regex,
}

impl PortScanPatterns {
    fn new() -> Result<Self> {
        // Matches nftables/iptables LOG target output in kernel log
        // Example: Dec  6 10:00:00 host kernel: [crmonban-portscan] IN=eth0 ... SRC=192.168.1.100 ... DPT=22 ...
        let kernel_log = Regex::new(
            r"\[crmonban-portscan(?:-(?P<scan_type>syn|null|xmas|fin|udp))?\].*SRC=(?P<ip>[\d.:a-fA-F]+).*DPT=(?P<port>\d+)"
        ).context("Failed to compile kernel log regex")?;

        // nflog format (JSON output from ulogd2)
        let nflog = Regex::new(
            r#""src":\s*"(?P<ip>[\d.:a-fA-F]+)".*"dport":\s*(?P<port>\d+)"#
        ).context("Failed to compile nflog regex")?;

        Ok(Self { kernel_log, nflog })
    }
}

impl PortScanMonitor {
    /// Create a new port scan monitor
    pub fn new(config: PortScanConfig) -> Result<Self> {
        let patterns = PortScanPatterns::new()?;

        Ok(Self {
            log_path: PathBuf::from(&config.log_path),
            config,
            file_position: 0,
            ip_port_access: HashMap::new(),
            patterns,
        })
    }

    /// Check if a port should be monitored
    fn should_monitor_port(&self, port: u16) -> bool {
        // If excluded, skip
        if self.config.excluded_ports.contains(&port) {
            return false;
        }

        // If monitored_ports is empty, monitor all (except excluded)
        // If monitored_ports has values, only monitor those
        if self.config.monitored_ports.is_empty() {
            true
        } else {
            self.config.monitored_ports.contains(&port)
        }
    }

    /// Parse a log line and extract port scan information
    fn parse_log_line(&self, line: &str) -> Option<(IpAddr, u16, Option<ScanType>)> {
        // Try kernel log format first
        if let Some(captures) = self.patterns.kernel_log.captures(line) {
            let ip_str = captures.name("ip")?.as_str();
            let port_str = captures.name("port")?.as_str();

            let ip: IpAddr = ip_str.parse().ok()?;
            let port: u16 = port_str.parse().ok()?;

            let scan_type = captures.name("scan_type").map(|m| match m.as_str() {
                "syn" => ScanType::Syn,
                "null" => ScanType::Null,
                "xmas" => ScanType::Xmas,
                "fin" => ScanType::Fin,
                "udp" => ScanType::Udp,
                _ => ScanType::Generic,
            });

            return Some((ip, port, scan_type));
        }

        // Try nflog format
        if let Some(captures) = self.patterns.nflog.captures(line) {
            let ip_str = captures.name("ip")?.as_str();
            let port_str = captures.name("port")?.as_str();

            let ip: IpAddr = ip_str.parse().ok()?;
            let port: u16 = port_str.parse().ok()?;

            return Some((ip, port, None));
        }

        None
    }

    /// Process new lines from the log file
    pub fn process_new_lines(&mut self) -> Result<Vec<MonitorEvent>> {
        let mut events = Vec::new();

        if !self.log_path.exists() {
            debug!("Port scan log file does not exist: {}", self.log_path.display());
            return Ok(events);
        }

        let file = File::open(&self.log_path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        // Handle log rotation
        if file_size < self.file_position {
            info!(
                "Port scan log file {} appears rotated, starting from beginning",
                self.log_path.display()
            );
            self.file_position = 0;
        }

        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(self.file_position))?;

        let mut line = String::new();
        while reader.read_line(&mut line)? > 0 {
            if let Some((ip, port, scan_type)) = self.parse_log_line(&line) {
                if self.should_monitor_port(port) {
                    if let Some(event) = self.record_port_access(ip, port, scan_type, &line) {
                        events.push(event);
                    }
                }
            }
            line.clear();
        }

        self.file_position = reader.stream_position()?;

        // Periodic cleanup of old entries
        self.cleanup_old_entries();

        Ok(events)
    }

    /// Record a port access and check if threshold is exceeded
    fn record_port_access(
        &mut self,
        ip: IpAddr,
        port: u16,
        scan_type: Option<ScanType>,
        _log_line: &str,
    ) -> Option<MonitorEvent> {
        let access = self.ip_port_access.entry(ip).or_insert_with(PortAccess::new);
        access.add_port(port);

        // Clean old entries for this IP
        access.cleanup_old(self.config.window_secs);

        let port_count = access.unique_port_count();

        debug!(
            "Port access from {}: port {} (total unique ports: {})",
            ip, port, port_count
        );

        // Check if threshold exceeded
        if port_count >= self.config.threshold as usize {
            let scan_type_str = scan_type
                .as_ref()
                .map(|st| st.to_string())
                .unwrap_or_else(|| "port scan".to_string());

            info!(
                "Port scan detected from {}: {} unique ports in {} seconds ({})",
                ip, port_count, self.config.window_secs, scan_type_str
            );

            // Clear the counter for this IP (they'll be banned)
            self.ip_port_access.remove(&ip);

            // Return ban event
            return Some(MonitorEvent::Ban {
                ip,
                service: "port_scan".to_string(),
                reason: format!(
                    "{} detected: {} unique ports in {} seconds",
                    scan_type_str, port_count, self.config.window_secs
                ),
                duration_secs: self.config.ban_time,
            });
        }

        None
    }

    /// Clean up old entries from all IPs
    fn cleanup_old_entries(&mut self) {
        let window_secs = self.config.window_secs;

        self.ip_port_access.retain(|ip, access| {
            access.cleanup_old(window_secs);
            let keep = !access.ports.is_empty();
            if !keep {
                debug!("Cleaned up port scan tracking for {}", ip);
            }
            keep
        });
    }

    /// Get monitoring status
    pub fn status(&self) -> PortScanMonitorStatus {
        PortScanMonitorStatus {
            enabled: self.config.enabled,
            tracked_ips: self.ip_port_access.len(),
            threshold: self.config.threshold,
            window_secs: self.config.window_secs,
            log_path: self.log_path.to_string_lossy().to_string(),
        }
    }
}

/// Status of the port scan monitor
#[derive(Debug, Clone)]
pub struct PortScanMonitorStatus {
    pub enabled: bool,
    pub tracked_ips: usize,
    pub threshold: u32,
    pub window_secs: u64,
    pub log_path: String,
}

/// Start port scan monitoring
pub async fn start_port_scan_monitoring(
    config: PortScanConfig,
    event_tx: mpsc::Sender<MonitorEvent>,
) -> Result<()> {
    if !config.enabled {
        info!("Port scan detection is disabled");
        return Ok(());
    }

    let mut monitor = PortScanMonitor::new(config.clone())?;

    let log_path = PathBuf::from(&config.log_path);
    if !log_path.exists() {
        warn!(
            "Port scan log file does not exist: {}. Will wait for it to appear.",
            log_path.display()
        );
    }

    // Create file watcher
    let (watcher_tx, mut watcher_rx) = mpsc::channel::<Result<Event, notify::Error>>(100);

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = watcher_tx.blocking_send(res);
        },
        Config::default(),
    )?;

    // Watch the parent directory
    if let Some(parent) = log_path.parent() {
        if parent.exists() {
            watcher.watch(parent, RecursiveMode::NonRecursive)?;
            info!("Watching directory for port scan logs: {}", parent.display());
        }
    }

    // Initial poll
    for event in monitor.process_new_lines()? {
        event_tx.send(event).await?;
    }

    info!(
        "Port scan monitoring started (threshold: {} ports in {} seconds)",
        config.threshold, config.window_secs
    );

    // Main monitoring loop
    loop {
        tokio::select! {
            Some(res) = watcher_rx.recv() => {
                match res {
                    Ok(event) => {
                        let dominated = event.paths.iter().any(|p| {
                            p.ends_with(log_path.file_name().unwrap_or_default())
                        });

                        if dominated {
                            match monitor.process_new_lines() {
                                Ok(events) => {
                                    for event in events {
                                        if event_tx.send(event).await.is_err() {
                                            return Ok(());
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Error processing port scan log: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Port scan file watcher error: {}", e);
                    }
                }
            }

            // Poll periodically
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(2)) => {
                match monitor.process_new_lines() {
                    Ok(events) => {
                        for event in events {
                            if event_tx.send(event).await.is_err() {
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error processing port scan log: {}", e);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_log_parsing() {
        let config = PortScanConfig::default();
        let monitor = PortScanMonitor::new(config).unwrap();

        let line = "Dec  6 10:00:00 server kernel: [crmonban-portscan-syn] IN=eth0 OUT= MAC=... SRC=192.168.1.100 DST=192.168.1.1 LEN=44 TOS=0x00 PREC=0x00 TTL=64 ID=12345 DF PROTO=TCP SPT=54321 DPT=22 WINDOW=1024 RES=0x00 SYN URGP=0";

        let result = monitor.parse_log_line(line);
        assert!(result.is_some());

        let (ip, port, scan_type) = result.unwrap();
        assert_eq!(ip.to_string(), "192.168.1.100");
        assert_eq!(port, 22);
        assert_eq!(scan_type, Some(ScanType::Syn));
    }

    #[test]
    fn test_generic_port_scan_parsing() {
        let config = PortScanConfig::default();
        let monitor = PortScanMonitor::new(config).unwrap();

        let line = "Dec  6 10:00:00 server kernel: [crmonban-portscan] IN=eth0 OUT= SRC=10.0.0.50 DST=10.0.0.1 PROTO=TCP DPT=8080";

        let result = monitor.parse_log_line(line);
        assert!(result.is_some());

        let (ip, port, scan_type) = result.unwrap();
        assert_eq!(ip.to_string(), "10.0.0.50");
        assert_eq!(port, 8080);
        assert!(scan_type.is_none());
    }

    #[test]
    fn test_port_exclusion() {
        let mut config = PortScanConfig::default();
        config.excluded_ports = vec![22, 80, 443];
        config.monitored_ports = vec![];

        let monitor = PortScanMonitor::new(config).unwrap();

        assert!(!monitor.should_monitor_port(22));
        assert!(!monitor.should_monitor_port(80));
        assert!(monitor.should_monitor_port(8080));
    }

    #[test]
    fn test_monitored_ports() {
        let mut config = PortScanConfig::default();
        config.excluded_ports = vec![];
        config.monitored_ports = vec![22, 80, 443];

        let monitor = PortScanMonitor::new(config).unwrap();

        assert!(monitor.should_monitor_port(22));
        assert!(monitor.should_monitor_port(80));
        assert!(!monitor.should_monitor_port(8080));
    }
}
