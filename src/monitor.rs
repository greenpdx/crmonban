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

use crate::cloudflare::CloudflareChecker;
use crate::config::ServiceConfig;
use crate::models::{AttackEvent, AttackEventType};

/// Compiled pattern for matching log lines
struct CompiledPattern {
    name: String,
    regex: Regex,
    event_type: AttackEventType,
}

/// Monitor for a single log file
struct LogMonitor {
    service: String,
    path: PathBuf,
    patterns: Vec<CompiledPattern>,
    max_failures: u32,
    find_time: u64,
    ban_time: i64,
    file_position: u64,
}

impl LogMonitor {
    fn new(service: String, config: &ServiceConfig) -> Result<Self> {
        let patterns = config
            .patterns
            .iter()
            .map(|p| {
                let regex = Regex::new(&p.regex)
                    .with_context(|| format!("Invalid regex pattern: {}", p.regex))?;

                let event_type = match p.event_type.as_str() {
                    "failed_auth" => AttackEventType::FailedAuth,
                    "invalid_user" => AttackEventType::InvalidUser,
                    "brute_force" => AttackEventType::BruteForce,
                    "port_scan" => AttackEventType::PortScan,
                    "exploit" => AttackEventType::Exploit,
                    "rate_limit" => AttackEventType::RateLimit,
                    other => AttackEventType::Other(other.to_string()),
                };

                Ok(CompiledPattern {
                    name: p.name.clone(),
                    regex,
                    event_type,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            service,
            path: PathBuf::from(&config.log_path),
            patterns,
            max_failures: config.max_failures,
            find_time: config.find_time,
            ban_time: config.ban_time,
            file_position: 0,
        })
    }

    /// Process new lines from the log file
    fn process_new_lines(&mut self) -> Result<Vec<AttackEvent>> {
        let mut events = Vec::new();

        if !self.path.exists() {
            debug!("Log file does not exist: {}", self.path.display());
            return Ok(events);
        }

        let file = File::open(&self.path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        // Handle log rotation (file got smaller)
        if file_size < self.file_position {
            info!(
                "Log file {} appears to have been rotated, starting from beginning",
                self.path.display()
            );
            self.file_position = 0;
        }

        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(self.file_position))?;

        let mut line = String::new();
        while reader.read_line(&mut line)? > 0 {
            if let Some(event) = self.match_line(&line) {
                events.push(event);
            }
            line.clear();
        }

        self.file_position = reader.stream_position()?;
        Ok(events)
    }

    /// Match a line against all patterns
    fn match_line(&self, line: &str) -> Option<AttackEvent> {
        for pattern in &self.patterns {
            if let Some(captures) = pattern.regex.captures(line) {
                if let Some(ip_match) = captures.name("ip") {
                    let ip_str = ip_match.as_str();
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        debug!(
                            "Matched pattern '{}' for IP {} in service {}",
                            pattern.name, ip, self.service
                        );

                        return Some(AttackEvent {
                            id: None,
                            ip,
                            timestamp: Utc::now(),
                            service: self.service.clone(),
                            event_type: pattern.event_type.clone(),
                            details: Some(pattern.name.clone()),
                            log_line: line.trim().to_string(),
                        });
                    }
                }
            }
        }
        None
    }
}

/// Event sent from the monitor to the main loop
#[derive(Debug)]
pub enum MonitorEvent {
    /// An attack event was detected
    Attack(AttackEvent),
    /// An IP should be banned
    Ban {
        ip: IpAddr,
        service: String,
        reason: String,
        duration_secs: i64,
    },
    /// An error occurred
    Error(String),
}

/// Log file monitor manager
pub struct LogMonitorManager {
    monitors: HashMap<String, LogMonitor>,
    event_counts: HashMap<(IpAddr, String), Vec<chrono::DateTime<Utc>>>,
    cloudflare_checker: CloudflareChecker,
    skip_cloudflare_ips: bool,
}

impl LogMonitorManager {
    /// Create a new monitor manager
    pub fn new() -> Self {
        Self {
            monitors: HashMap::new(),
            event_counts: HashMap::new(),
            cloudflare_checker: CloudflareChecker::new(),
            skip_cloudflare_ips: true, // Don't ban Cloudflare proxy IPs by default
        }
    }

    /// Create a new monitor manager with Cloudflare IP filtering option
    pub fn with_cloudflare_filter(skip_cloudflare: bool) -> Self {
        Self {
            monitors: HashMap::new(),
            event_counts: HashMap::new(),
            cloudflare_checker: CloudflareChecker::new(),
            skip_cloudflare_ips: skip_cloudflare,
        }
    }

    /// Add a service to monitor
    pub fn add_service(&mut self, name: String, config: &ServiceConfig) -> Result<()> {
        if !config.enabled {
            debug!("Service {} is disabled, skipping", name);
            return Ok(());
        }

        let monitor = LogMonitor::new(name.clone(), config)?;
        info!(
            "Added monitor for service '{}' watching {}",
            name,
            monitor.path.display()
        );
        self.monitors.insert(name, monitor);
        Ok(())
    }

    /// Get list of monitored file paths
    pub fn get_monitored_paths(&self) -> Vec<PathBuf> {
        self.monitors.values().map(|m| m.path.clone()).collect()
    }

    /// Process all monitors and return events
    pub fn poll(&mut self) -> Vec<MonitorEvent> {
        let mut output_events = Vec::new();

        for (service, monitor) in &mut self.monitors {
            match monitor.process_new_lines() {
                Ok(events) => {
                    for event in events {
                        let ip = event.ip;

                        // Check if this is a Cloudflare proxy IP
                        let is_cloudflare = self.cloudflare_checker.is_cloudflare_ip(ip);
                        if is_cloudflare && self.skip_cloudflare_ips {
                            debug!(
                                "Skipping Cloudflare proxy IP {} for service {} (attack logged but won't ban)",
                                ip, service
                            );
                            // Still record the attack event, but don't trigger ban
                            output_events.push(MonitorEvent::Attack(event));
                            continue;
                        }

                        // Record the event
                        output_events.push(MonitorEvent::Attack(event));

                        // Check if we should ban
                        let key = (ip, service.clone());
                        let now = Utc::now();
                        let window_start =
                            now - chrono::Duration::seconds(monitor.find_time as i64);

                        // Clean old events and add new one
                        let timestamps = self.event_counts.entry(key.clone()).or_default();
                        timestamps.retain(|t| *t > window_start);
                        timestamps.push(now);

                        // Check threshold
                        if timestamps.len() >= monitor.max_failures as usize {
                            info!(
                                "IP {} exceeded threshold ({}/{}) for service {}, triggering ban",
                                ip,
                                timestamps.len(),
                                monitor.max_failures,
                                service
                            );

                            output_events.push(MonitorEvent::Ban {
                                ip,
                                service: service.clone(),
                                reason: format!(
                                    "{} failures in {} seconds for {}",
                                    timestamps.len(),
                                    monitor.find_time,
                                    service
                                ),
                                duration_secs: monitor.ban_time,
                            });

                            // Clear the count after ban
                            timestamps.clear();
                        }
                    }
                }
                Err(e) => {
                    error!("Error processing log for service {}: {}", service, e);
                    output_events.push(MonitorEvent::Error(format!(
                        "Error monitoring {}: {}",
                        service, e
                    )));
                }
            }
        }

        output_events
    }

    /// Reset event counts for an IP (e.g., after successful auth)
    pub fn reset_counts(&mut self, ip: &IpAddr) {
        self.event_counts.retain(|(k_ip, _), _| k_ip != ip);
    }
}

impl Default for LogMonitorManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Start the file watcher and monitor loop
pub async fn start_monitoring(
    services: HashMap<String, ServiceConfig>,
    event_tx: mpsc::Sender<MonitorEvent>,
) -> Result<()> {
    let mut manager = LogMonitorManager::new();

    // Add all enabled services
    for (name, config) in &services {
        if let Err(e) = manager.add_service(name.clone(), config) {
            warn!("Failed to add monitor for service {}: {}", name, e);
        }
    }

    let paths = manager.get_monitored_paths();
    if paths.is_empty() {
        warn!("No log files to monitor");
        return Ok(());
    }

    // Create file watcher
    let (watcher_tx, mut watcher_rx) = mpsc::channel::<Result<Event, notify::Error>>(100);

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = watcher_tx.blocking_send(res);
        },
        Config::default(),
    )?;

    // Watch parent directories of log files
    let mut watched_dirs = std::collections::HashSet::new();
    for path in &paths {
        if let Some(parent) = path.parent() {
            if watched_dirs.insert(parent.to_path_buf()) {
                if parent.exists() {
                    watcher.watch(parent, RecursiveMode::NonRecursive)?;
                    info!("Watching directory: {}", parent.display());
                }
            }
        }
    }

    // Also do an initial poll
    for event in manager.poll() {
        event_tx.send(event).await?;
    }

    info!("Log monitoring started for {} services", manager.monitors.len());

    // Main monitoring loop
    loop {
        tokio::select! {
            Some(res) = watcher_rx.recv() => {
                match res {
                    Ok(event) => {
                        // Check if any of our monitored files changed
                        let dominated = event.paths.iter().any(|p| {
                            paths.iter().any(|mp| p.ends_with(mp.file_name().unwrap_or_default()))
                        });

                        if dominated {
                            for monitor_event in manager.poll() {
                                if event_tx.send(monitor_event).await.is_err() {
                                    return Ok(());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("File watcher error: {}", e);
                    }
                }
            }

            // Also poll periodically in case we miss file events
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(5)) => {
                for monitor_event in manager.poll() {
                    if event_tx.send(monitor_event).await.is_err() {
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PatternConfig;

    #[test]
    fn test_pattern_matching() {
        let config = ServiceConfig {
            enabled: true,
            log_path: "/var/log/auth.log".to_string(),
            patterns: vec![PatternConfig {
                name: "failed_password".to_string(),
                regex: r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
                event_type: "failed_auth".to_string(),
            }],
            max_failures: 5,
            find_time: 600,
            ban_time: 3600,
        };

        let monitor = LogMonitor::new("ssh".to_string(), &config).unwrap();

        let line = "Dec  4 10:00:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2";
        let event = monitor.match_line(line);

        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.ip.to_string(), "192.168.1.100");
        assert_eq!(event.service, "ssh");
    }
}
