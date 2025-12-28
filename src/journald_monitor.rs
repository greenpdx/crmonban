//! Journald log monitor
//!
//! Monitors systemd journal for attack patterns on systems without traditional
//! syslog files. Uses `journalctl` for log access.

use anyhow::{Context, Result};
use chrono::Utc;
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::models::{AttackEvent, AttackEventType};
use crate::monitor::MonitorEvent;

/// Compiled pattern for matching journal entries
struct JournalPattern {
    name: String,
    regex: Regex,
    event_type: AttackEventType,
}

/// Journal monitor configuration
#[derive(Debug, Clone)]
pub struct JournalConfig {
    pub enabled: bool,
    pub units: Vec<String>,
    pub max_failures: u32,
    pub find_time: u64,
    pub ban_time: i64,
    pub patterns: Vec<JournalPatternConfig>,
}

#[derive(Debug, Clone)]
pub struct JournalPatternConfig {
    pub name: String,
    pub regex: String,
    pub event_type: String,
}

impl Default for JournalConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            units: vec!["sshd".to_string(), "ssh".to_string()],
            max_failures: 5,
            find_time: 600,
            ban_time: 3600,
            patterns: default_ssh_patterns(),
        }
    }
}

fn default_ssh_patterns() -> Vec<JournalPatternConfig> {
    vec![
        JournalPatternConfig {
            name: "failed_password".to_string(),
            regex: r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
            event_type: "failed_auth".to_string(),
        },
        JournalPatternConfig {
            name: "invalid_user".to_string(),
            regex: r"Invalid user .* from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
            event_type: "invalid_user".to_string(),
        },
        JournalPatternConfig {
            name: "connection_closed_preauth".to_string(),
            regex: r"Connection closed by (?P<ip>\d+\.\d+\.\d+\.\d+) port \d+ \[preauth\]".to_string(),
            event_type: "failed_auth".to_string(),
        },
        JournalPatternConfig {
            name: "too_many_auth_failures".to_string(),
            regex: r"Disconnecting authenticating user .* (?P<ip>\d+\.\d+\.\d+\.\d+) .* Too many authentication failures".to_string(),
            event_type: "brute_force".to_string(),
        },
        JournalPatternConfig {
            name: "maximum_auth_attempts".to_string(),
            regex: r"error: maximum authentication attempts exceeded for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
            event_type: "brute_force".to_string(),
        },
        JournalPatternConfig {
            name: "did_not_receive_identification".to_string(),
            regex: r"Did not receive identification string from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
            event_type: "exploit".to_string(),
        },
        JournalPatternConfig {
            name: "bad_protocol".to_string(),
            regex: r"Bad protocol version identification.*from (?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
            event_type: "exploit".to_string(),
        },
        JournalPatternConfig {
            name: "pam_auth_failure".to_string(),
            regex: r"pam_unix\(sshd:auth\): authentication failure.*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)".to_string(),
            event_type: "failed_auth".to_string(),
        },
    ]
}

/// Journald log monitor
pub struct JournaldMonitor {
    config: JournalConfig,
    patterns: Vec<JournalPattern>,
    event_counts: HashMap<(IpAddr, String), Vec<chrono::DateTime<Utc>>>,
}

impl JournaldMonitor {
    pub fn new(config: JournalConfig) -> Result<Self> {
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

                Ok(JournalPattern {
                    name: p.name.clone(),
                    regex,
                    event_type,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            config,
            patterns,
            event_counts: HashMap::new(),
        })
    }

    /// Check if journalctl is available
    pub async fn is_available() -> bool {
        Command::new("journalctl")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Match a line against all patterns
    fn match_line(&self, line: &str, service: &str) -> Option<AttackEvent> {
        for pattern in &self.patterns {
            if let Some(captures) = pattern.regex.captures(line) {
                if let Some(ip_match) = captures.name("ip") {
                    let ip_str = ip_match.as_str();
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        debug!(
                            "Matched pattern '{}' for IP {} in service {}",
                            pattern.name, ip, service
                        );

                        return Some(AttackEvent {
                            id: None,
                            ip,
                            timestamp: Utc::now(),
                            service: service.to_string(),
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

    /// Process an event and check if ban threshold is reached
    fn process_event(&mut self, event: AttackEvent) -> Vec<MonitorEvent> {
        let mut output_events = Vec::new();
        let ip = event.ip;
        let service = event.service.clone();

        output_events.push(MonitorEvent::Attack(event));

        // Check if we should ban
        let key = (ip, service.clone());
        let now = Utc::now();
        let window_start = now - chrono::Duration::seconds(self.config.find_time as i64);

        // Clean old events and add new one
        let timestamps = self.event_counts.entry(key.clone()).or_default();
        timestamps.retain(|t| *t > window_start);
        timestamps.push(now);

        // Check threshold
        if timestamps.len() >= self.config.max_failures as usize {
            info!(
                "IP {} exceeded threshold ({}/{}) for service {}, triggering ban",
                ip,
                timestamps.len(),
                self.config.max_failures,
                service
            );

            output_events.push(MonitorEvent::Ban {
                ip,
                service: service.clone(),
                reason: format!(
                    "{} failures in {} seconds for {}",
                    timestamps.len(),
                    self.config.find_time,
                    service
                ),
                duration_secs: self.config.ban_time,
            });

            // Clear the count after ban
            timestamps.clear();
        }

        output_events
    }
}

/// Start monitoring journald for attack patterns
pub async fn start_journald_monitoring(
    config: JournalConfig,
    event_tx: mpsc::Sender<MonitorEvent>,
) -> Result<()> {
    if !config.enabled {
        debug!("Journald monitoring is disabled");
        return Ok(());
    }

    if !JournaldMonitor::is_available().await {
        warn!("journalctl not available, skipping journald monitoring");
        return Ok(());
    }

    let mut monitor = JournaldMonitor::new(config.clone())?;

    // Build journalctl command for following logs
    let mut cmd = Command::new("journalctl");
    cmd.arg("--follow")
        .arg("--no-pager")
        .arg("--output=short")
        .arg("--since=now");

    // Add unit filters
    for unit in &config.units {
        cmd.arg("-u").arg(unit);
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::null());

    info!(
        "Starting journald monitoring for units: {:?}",
        config.units
    );

    let mut child = cmd.spawn().context("Failed to start journalctl")?;
    let stdout = child
        .stdout
        .take()
        .context("Failed to get journalctl stdout")?;

    let mut reader = BufReader::new(stdout).lines();

    while let Ok(Some(line)) = reader.next_line().await {
        // Determine which service this log is from
        let service = config
            .units
            .iter()
            .find(|u| line.contains(u.as_str()))
            .cloned()
            .unwrap_or_else(|| "journald".to_string());

        if let Some(event) = monitor.match_line(&line, &service) {
            for monitor_event in monitor.process_event(event) {
                if event_tx.send(monitor_event).await.is_err() {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

/// Query journald for historical entries (for validation/testing)
pub async fn query_journal_history(
    units: &[String],
    since: &str,
    patterns: &[JournalPatternConfig],
) -> Result<Vec<AttackEvent>> {
    let mut events = Vec::new();

    // Compile patterns
    let compiled: Vec<(String, Regex, AttackEventType)> = patterns
        .iter()
        .filter_map(|p| {
            let regex = Regex::new(&p.regex).ok()?;
            let event_type = match p.event_type.as_str() {
                "failed_auth" => AttackEventType::FailedAuth,
                "invalid_user" => AttackEventType::InvalidUser,
                "brute_force" => AttackEventType::BruteForce,
                "port_scan" => AttackEventType::PortScan,
                "exploit" => AttackEventType::Exploit,
                "rate_limit" => AttackEventType::RateLimit,
                other => AttackEventType::Other(other.to_string()),
            };
            Some((p.name.clone(), regex, event_type))
        })
        .collect();

    // Build query command
    let mut cmd = Command::new("journalctl");
    cmd.arg("--no-pager")
        .arg("--output=short")
        .arg(format!("--since={}", since));

    for unit in units {
        cmd.arg("-u").arg(unit);
    }

    cmd.stdout(Stdio::piped()).stderr(Stdio::null());

    let output = cmd.output().await.context("Failed to run journalctl")?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        for (name, regex, event_type) in &compiled {
            if let Some(captures) = regex.captures(line) {
                if let Some(ip_match) = captures.name("ip") {
                    if let Ok(ip) = ip_match.as_str().parse::<IpAddr>() {
                        let service = units
                            .iter()
                            .find(|u| line.contains(u.as_str()))
                            .cloned()
                            .unwrap_or_else(|| "journald".to_string());

                        events.push(AttackEvent {
                            id: None,
                            ip,
                            timestamp: Utc::now(),
                            service,
                            event_type: event_type.clone(),
                            details: Some(name.clone()),
                            log_line: line.trim().to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_matching() {
        let config = JournalConfig::default();
        let monitor = JournaldMonitor::new(config).unwrap();

        let test_lines = vec![
            ("Failed password for root from 192.168.1.100 port 22 ssh2", true),
            ("Invalid user admin from 10.0.0.50 port 54321", true),
            ("Connection closed by 172.16.0.1 port 12345 [preauth]", true),
            ("Accepted password for user from 192.168.1.1", false),
            ("Normal log message", false),
        ];

        for (line, should_match) in test_lines {
            let result = monitor.match_line(line, "sshd");
            assert_eq!(
                result.is_some(),
                should_match,
                "Line '{}' should {}match",
                line,
                if should_match { "" } else { "not " }
            );
        }
    }

    #[test]
    fn test_ip_extraction() {
        let config = JournalConfig::default();
        let monitor = JournaldMonitor::new(config).unwrap();

        let line = "Failed password for root from 192.168.1.100 port 22 ssh2";
        let event = monitor.match_line(line, "sshd").unwrap();

        assert_eq!(event.ip.to_string(), "192.168.1.100");
    }
}
