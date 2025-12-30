use anyhow::{Context, Result};
use etherparse::SlicedPacket;
use nfq::{Queue, Verdict};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::{DpiConfig, DpiPattern};
use crate::monitor::MonitorEvent;

/// Connection tracking key
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ConnKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
}

/// Connection state for packet counting
#[derive(Debug)]
struct ConnState {
    packets_seen: u8,
    created_at: std::time::Instant,
}

/// Threat detection result
#[derive(Debug, Clone)]
pub struct ThreatMatch {
    pub rule_name: String,
    pub severity: ThreatSeverity,
    pub description: String,
    pub matched_data: String,
}

/// Threat severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ThreatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatSeverity::Low => write!(f, "low"),
            ThreatSeverity::Medium => write!(f, "medium"),
            ThreatSeverity::High => write!(f, "high"),
            ThreatSeverity::Critical => write!(f, "critical"),
        }
    }
}

impl From<&str> for ThreatSeverity {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "low" => ThreatSeverity::Low,
            "medium" => ThreatSeverity::Medium,
            "high" => ThreatSeverity::High,
            "critical" => ThreatSeverity::Critical,
            _ => ThreatSeverity::Medium,
        }
    }
}

/// Compiled detection rule
struct CompiledRule {
    name: String,
    pattern: Regex,
    severity: ThreatSeverity,
    description: String,
}

/// Rule categories loaded from external file
#[derive(Debug, Default, Deserialize)]
pub struct DpiRulesFile {
    #[serde(default)]
    pub sqli: Vec<DpiPattern>,
    #[serde(default)]
    pub xss: Vec<DpiPattern>,
    #[serde(default)]
    pub cmdi: Vec<DpiPattern>,
    #[serde(default)]
    pub path_traversal: Vec<DpiPattern>,
    #[serde(default)]
    pub shellcode: Vec<DpiPattern>,
    #[serde(default)]
    pub protocol_anomaly: Vec<DpiPattern>,
    #[serde(default)]
    pub tls_anomaly: Vec<DpiPattern>,
}

/// Deep Packet Inspector
pub struct DpiEngine {
    config: DpiConfig,
    rules: Vec<CompiledRule>,
    conn_tracker: HashMap<ConnKey, ConnState>,
}

impl DpiEngine {
    /// Create a new DPI engine
    pub fn new(config: DpiConfig) -> Result<Self> {
        // Load rules from file or embedded defaults
        let rules_file = Self::load_rules(&config)?;

        let mut rules = Vec::new();

        // SQL Injection patterns
        if config.detect_sqli {
            rules.extend(Self::compile_dpi_patterns(&rules_file.sqli)?);
        }

        // XSS patterns
        if config.detect_xss {
            rules.extend(Self::compile_dpi_patterns(&rules_file.xss)?);
        }

        // Command injection patterns
        if config.detect_cmdi {
            rules.extend(Self::compile_dpi_patterns(&rules_file.cmdi)?);
        }

        // Path traversal patterns
        if config.detect_path_traversal {
            rules.extend(Self::compile_dpi_patterns(&rules_file.path_traversal)?);
        }

        // Shellcode patterns
        if config.detect_shellcode {
            rules.extend(Self::compile_dpi_patterns(&rules_file.shellcode)?);
        }

        // Protocol anomaly patterns
        if config.detect_protocol_anomaly {
            rules.extend(Self::compile_dpi_patterns(&rules_file.protocol_anomaly)?);
            rules.extend(Self::compile_dpi_patterns(&rules_file.tls_anomaly)?);
        }

        // Custom patterns from config (additional patterns on top of rules file)
        rules.extend(Self::compile_dpi_patterns(&config.custom_patterns)?);

        info!("DPI engine initialized with {} rules", rules.len());

        Ok(Self {
            config,
            rules,
            conn_tracker: HashMap::new(),
        })
    }

    /// Load rules from external file or embedded defaults
    fn load_rules(config: &DpiConfig) -> Result<DpiRulesFile> {
        if let Some(path) = &config.rules_file {
            // Load from specified external file
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read DPI rules file: {}", path.display()))?;
            toml::from_str(&content)
                .with_context(|| format!("Failed to parse DPI rules file: {}", path.display()))
        } else {
            // Use embedded default rules
            Ok(Self::default_rules())
        }
    }

    /// Embedded default rules (compiled into binary)
    fn default_rules() -> DpiRulesFile {
        toml::from_str(include_str!("../data/dpi_rules.toml"))
            .expect("Default DPI rules must be valid TOML")
    }

    /// Compile DpiPattern slice into CompiledRules
    fn compile_dpi_patterns(patterns: &[DpiPattern]) -> Result<Vec<CompiledRule>> {
        patterns
            .iter()
            .filter_map(|p| {
                match Regex::new(&p.pattern) {
                    Ok(regex) => Some(Ok(CompiledRule {
                        name: p.name.clone(),
                        pattern: regex,
                        severity: ThreatSeverity::from(p.severity.as_str()),
                        description: p.description.clone(),
                    })),
                    Err(e) => {
                        warn!("Failed to compile DPI pattern '{}': {}", p.name, e);
                        None
                    }
                }
            })
            .collect()
    }

    /// Check if a port should be inspected
    fn should_inspect_port(&self, port: u16) -> bool {
        if self.config.excluded_ports.contains(&port) {
            return false;
        }

        if self.config.inspected_ports.is_empty() {
            true
        } else {
            self.config.inspected_ports.contains(&port)
        }
    }

    /// Inspect a packet payload for threats
    pub fn inspect_payload(&self, payload: &[u8]) -> Vec<ThreatMatch> {
        let mut matches = Vec::new();

        // Limit payload size
        let inspect_data = if payload.len() > self.config.max_payload_bytes {
            &payload[..self.config.max_payload_bytes]
        } else {
            payload
        };

        // Convert to string for regex matching (lossy for binary data)
        let payload_str = String::from_utf8_lossy(inspect_data);

        for rule in &self.rules {
            if let Some(m) = rule.pattern.find(&payload_str) {
                matches.push(ThreatMatch {
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    description: rule.description.clone(),
                    matched_data: m.as_str().chars().take(100).collect(),
                });
            }
        }

        matches
    }

    /// Process a packet from NFQUEUE
    pub fn process_packet(&mut self, data: &[u8]) -> (Verdict, Option<(IpAddr, Vec<ThreatMatch>)>) {
        // Parse the packet
        let packet = match SlicedPacket::from_ip(data) {
            Ok(p) => p,
            Err(e) => {
                debug!("Failed to parse packet: {}", e);
                return (Verdict::Accept, None);
            }
        };

        // Extract IP addresses using the new etherparse API
        let (src_ip, dst_ip) = match &packet.net {
            Some(net) => {
                use etherparse::InternetSlice;
                match net {
                    InternetSlice::Ipv4(ipv4) => (
                        IpAddr::V4(ipv4.header().source().into()),
                        IpAddr::V4(ipv4.header().destination().into()),
                    ),
                    InternetSlice::Ipv6(ipv6) => (
                        IpAddr::V6(ipv6.header().source().into()),
                        IpAddr::V6(ipv6.header().destination().into()),
                    ),
                    _ => return (Verdict::Accept, None), // ARP or other
                }
            }
            None => return (Verdict::Accept, None),
        };

        // Extract ports from TCP header
        let (src_port, dst_port) = match &packet.transport {
            Some(transport) => {
                use etherparse::TransportSlice;
                match transport {
                    TransportSlice::Tcp(tcp) => (tcp.source_port(), tcp.destination_port()),
                    _ => return (Verdict::Accept, None),
                }
            }
            None => return (Verdict::Accept, None),
        };

        // Check if we should inspect this port
        if !self.should_inspect_port(dst_port) {
            return (Verdict::Accept, None);
        }

        // Connection tracking
        let conn_key = ConnKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        };

        let conn_state = self.conn_tracker.entry(conn_key.clone()).or_insert(ConnState {
            packets_seen: 0,
            created_at: std::time::Instant::now(),
        });

        conn_state.packets_seen += 1;

        // Only inspect first N packets
        if conn_state.packets_seen > self.config.packets_per_conn {
            // Clean up old connections periodically
            if conn_state.created_at.elapsed().as_secs() > 300 {
                self.conn_tracker.remove(&conn_key);
            }
            return (Verdict::Accept, None);
        }

        // Get payload from transport layer
        let payload = match &packet.transport {
            Some(transport) => {
                use etherparse::TransportSlice;
                match transport {
                    TransportSlice::Tcp(tcp) => tcp.payload(),
                    _ => return (Verdict::Accept, None),
                }
            }
            None => return (Verdict::Accept, None),
        };

        if payload.is_empty() {
            return (Verdict::Accept, None);
        }

        // Inspect the payload
        let threats = self.inspect_payload(payload);

        if threats.is_empty() {
            (Verdict::Accept, None)
        } else {
            let max_severity = threats
                .iter()
                .map(|t| t.severity)
                .max_by_key(|s| match s {
                    ThreatSeverity::Low => 0,
                    ThreatSeverity::Medium => 1,
                    ThreatSeverity::High => 2,
                    ThreatSeverity::Critical => 3,
                })
                .unwrap_or(ThreatSeverity::Low);

            // Determine verdict based on action and severity
            let verdict = match self.config.action.as_str() {
                "drop" => Verdict::Drop,
                "ban" => {
                    if max_severity as u8 >= ThreatSeverity::Medium as u8 {
                        Verdict::Drop
                    } else {
                        Verdict::Accept
                    }
                }
                _ => Verdict::Accept, // "log" - accept but return threats
            };

            info!(
                "DPI threat detected from {}: {:?}",
                src_ip,
                threats.iter().map(|t| &t.rule_name).collect::<Vec<_>>()
            );

            (verdict, Some((src_ip, threats)))
        }
    }

    /// Clean up old connection tracking entries
    pub fn cleanup_connections(&mut self) {
        let now = std::time::Instant::now();
        self.conn_tracker
            .retain(|_, state| now.duration_since(state.created_at).as_secs() < 300);
    }
}

/// Start DPI processing loop
pub async fn start_dpi(config: DpiConfig, event_tx: mpsc::Sender<MonitorEvent>) -> Result<()> {
    if !config.enabled {
        info!("DPI is disabled");
        return Ok(());
    }

    let queue_num = config.queue_num;
    let ban_time = config.ban_time;
    let action = config.action.clone();

    let engine = Arc::new(std::sync::Mutex::new(DpiEngine::new(config)?));

    info!("Starting DPI on NFQUEUE {}", queue_num);

    // Run NFQUEUE processing in a blocking thread
    let engine_clone = engine.clone();
    let event_tx_clone = event_tx.clone();

    tokio::task::spawn_blocking(move || {
        let mut queue = match Queue::open() {
            Ok(q) => q,
            Err(e) => {
                error!("Failed to open NFQUEUE: {}", e);
                return;
            }
        };

        if let Err(e) = queue.bind(queue_num) {
            error!("Failed to bind to NFQUEUE {}: {}", queue_num, e);
            return;
        }

        info!("DPI bound to NFQUEUE {}", queue_num);

        loop {
            match queue.recv() {
                Ok(mut msg) => {
                    let data = msg.get_payload();

                    let (verdict, threat_info) = {
                        match engine_clone.lock() {
                            Ok(mut engine) => engine.process_packet(data),
                            Err(poisoned) => {
                                // Recover from poisoned mutex
                                let mut engine = poisoned.into_inner();
                                engine.process_packet(data)
                            }
                        }
                    };

                    // Handle detected threats
                    if let Some((src_ip, threats)) = threat_info {
                        if action == "ban" {
                            let threat_names: Vec<_> =
                                threats.iter().map(|t| t.rule_name.as_str()).collect();
                            let reason = format!("DPI: {}", threat_names.join(", "));

                            // Send ban event
                            let _ = event_tx_clone.blocking_send(MonitorEvent::Ban {
                                ip: src_ip,
                                service: "dpi".to_string(),
                                reason,
                                duration_secs: ban_time,
                            });
                        }
                    }

                    msg.set_verdict(verdict);
                    if let Err(e) = queue.verdict(msg) {
                        error!("Failed to send verdict: {}", e);
                    }
                }
                Err(e) => {
                    error!("NFQUEUE recv error: {}", e);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        }
    });

    // Cleanup task
    let engine_cleanup = engine;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            match engine_cleanup.lock() {
                Ok(mut engine) => engine.cleanup_connections(),
                Err(poisoned) => {
                    // Recover from poisoned mutex
                    let mut engine = poisoned.into_inner();
                    engine.cleanup_connections();
                }
            }
        }
    });

    Ok(())
}

/// DPI status information
#[derive(Debug, Clone)]
pub struct DpiStatus {
    pub enabled: bool,
    pub queue_num: u16,
    pub rules_loaded: usize,
    pub connections_tracked: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqli_detection() {
        let config = DpiConfig {
            enabled: true,
            detect_sqli: true,
            ..Default::default()
        };

        let engine = DpiEngine::new(config).unwrap();

        // SQL injection attempts
        let payloads = vec![
            "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin",
            "admin'-- ",
            "1' OR '1'='1",
            "; DROP TABLE users;",
            "SLEEP(5)",
        ];

        for payload in payloads {
            let matches = engine.inspect_payload(payload.as_bytes());
            assert!(
                !matches.is_empty(),
                "Should detect SQLi in: {}",
                payload
            );
        }
    }

    #[test]
    fn test_xss_detection() {
        let config = DpiConfig {
            enabled: true,
            detect_xss: true,
            ..Default::default()
        };

        let engine = DpiEngine::new(config).unwrap();

        let payloads = vec![
            "<script>alert('xss')</script>",
            "<img onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
        ];

        for payload in payloads {
            let matches = engine.inspect_payload(payload.as_bytes());
            assert!(!matches.is_empty(), "Should detect XSS in: {}", payload);
        }
    }

    #[test]
    fn test_cmdi_detection() {
        let config = DpiConfig {
            enabled: true,
            detect_cmdi: true,
            ..Default::default()
        };

        let engine = DpiEngine::new(config).unwrap();

        let payloads = vec![
            "; cat /etc/passwd",
            "| whoami",
            "$(id)",
            "`ls -la`",
        ];

        for payload in payloads {
            let matches = engine.inspect_payload(payload.as_bytes());
            assert!(
                !matches.is_empty(),
                "Should detect command injection in: {}",
                payload
            );
        }
    }

    #[test]
    fn test_path_traversal_detection() {
        let config = DpiConfig {
            enabled: true,
            detect_path_traversal: true,
            ..Default::default()
        };

        let engine = DpiEngine::new(config).unwrap();

        let payloads = vec![
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "%2e%2e/%2e%2e/etc/passwd",
        ];

        for payload in payloads {
            let matches = engine.inspect_payload(payload.as_bytes());
            assert!(
                !matches.is_empty(),
                "Should detect path traversal in: {}",
                payload
            );
        }
    }

    #[test]
    fn test_clean_payload() {
        let config = DpiConfig::default();
        let engine = DpiEngine::new(config).unwrap();

        let clean = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let matches = engine.inspect_payload(clean.as_bytes());
        assert!(matches.is_empty(), "Should not detect threats in clean request");
    }

    #[test]
    fn test_port_filtering() {
        let mut config = DpiConfig::default();
        config.excluded_ports = vec![443, 22];
        config.inspected_ports = vec![];

        let engine = DpiEngine::new(config).unwrap();

        assert!(!engine.should_inspect_port(443));
        assert!(!engine.should_inspect_port(22));
        assert!(engine.should_inspect_port(80));
        assert!(engine.should_inspect_port(8080));
    }
}
