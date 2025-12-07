use anyhow::{Context, Result};
use etherparse::SlicedPacket;
use nfq::{Queue, Verdict};
use regex::Regex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::config::DpiConfig;
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

/// Deep Packet Inspector
pub struct DpiEngine {
    config: DpiConfig,
    rules: Vec<CompiledRule>,
    conn_tracker: HashMap<ConnKey, ConnState>,
}

impl DpiEngine {
    /// Create a new DPI engine
    pub fn new(config: DpiConfig) -> Result<Self> {
        let mut rules = Vec::new();

        // SQL Injection patterns
        if config.detect_sqli {
            rules.extend(Self::compile_sqli_rules()?);
        }

        // XSS patterns
        if config.detect_xss {
            rules.extend(Self::compile_xss_rules()?);
        }

        // Command injection patterns
        if config.detect_cmdi {
            rules.extend(Self::compile_cmdi_rules()?);
        }

        // Path traversal patterns
        if config.detect_path_traversal {
            rules.extend(Self::compile_path_traversal_rules()?);
        }

        // Shellcode patterns
        if config.detect_shellcode {
            rules.extend(Self::compile_shellcode_rules()?);
        }

        // Protocol anomaly patterns
        if config.detect_protocol_anomaly {
            rules.extend(Self::compile_protocol_anomaly_rules()?);
            rules.extend(Self::compile_tls_anomaly_rules()?);
        }

        // Custom patterns
        for custom in &config.custom_patterns {
            if let Ok(regex) = Regex::new(&custom.pattern) {
                rules.push(CompiledRule {
                    name: custom.name.clone(),
                    pattern: regex,
                    severity: ThreatSeverity::from(custom.severity.as_str()),
                    description: custom.description.clone(),
                });
            } else {
                warn!("Failed to compile custom DPI pattern: {}", custom.name);
            }
        }

        info!("DPI engine initialized with {} rules", rules.len());

        Ok(Self {
            config,
            rules,
            conn_tracker: HashMap::new(),
        })
    }

    /// Compile SQL injection detection rules
    fn compile_sqli_rules() -> Result<Vec<CompiledRule>> {
        let patterns = vec![
            (
                "sqli_union",
                r"(?i)(\bunion\b.*\bselect\b|\bselect\b.*\bunion\b)",
                ThreatSeverity::High,
                "SQL UNION injection attempt",
            ),
            (
                "sqli_comment",
                r#"('|")\s*(--|#|/\*)"#,
                ThreatSeverity::Medium,
                "SQL comment injection",
            ),
            (
                "sqli_or_bypass",
                r"(?i)'\s*(or|and)\s*'",
                ThreatSeverity::High,
                "SQL OR/AND bypass attempt",
            ),
            (
                "sqli_stacked",
                r"(?i);\s*(drop|delete|insert|update|truncate|alter)\s",
                ThreatSeverity::Critical,
                "SQL stacked query injection",
            ),
            (
                "sqli_sleep",
                r"(?i)(sleep|benchmark|waitfor|delay)\s*\(",
                ThreatSeverity::High,
                "SQL time-based injection",
            ),
            (
                "sqli_information_schema",
                r"(?i)information_schema\.(tables|columns|schemata)",
                ThreatSeverity::High,
                "SQL information schema access",
            ),
            (
                "sqli_hex_encode",
                r"(?i)(0x[0-9a-f]{16,}|char\s*\(\s*\d+\s*(,\s*\d+\s*)+\))",
                ThreatSeverity::Medium,
                "SQL hex/char encoding",
            ),
        ];

        Self::compile_patterns(patterns)
    }

    /// Compile XSS detection rules
    fn compile_xss_rules() -> Result<Vec<CompiledRule>> {
        let patterns = vec![
            (
                "xss_script_tag",
                r"(?i)<script[^>]*>",
                ThreatSeverity::High,
                "XSS script tag injection",
            ),
            (
                "xss_event_handler",
                r"(?i)\bon(error|load|click|mouse|key|focus|blur|change|submit)\s*=",
                ThreatSeverity::High,
                "XSS event handler injection",
            ),
            (
                "xss_javascript_uri",
                r"(?i)javascript\s*:",
                ThreatSeverity::High,
                "XSS javascript URI",
            ),
            (
                "xss_data_uri",
                r"(?i)data\s*:\s*(text/html|application/javascript)",
                ThreatSeverity::Medium,
                "XSS data URI injection",
            ),
            (
                "xss_svg_onload",
                r"(?i)<svg[^>]*\bonload\s*=",
                ThreatSeverity::High,
                "XSS SVG onload injection",
            ),
            (
                "xss_iframe",
                r"(?i)<iframe[^>]*\bsrc\s*=",
                ThreatSeverity::Medium,
                "XSS iframe injection",
            ),
            (
                "xss_expression",
                r"(?i)(expression|behavior)\s*\(",
                ThreatSeverity::Medium,
                "XSS CSS expression",
            ),
        ];

        Self::compile_patterns(patterns)
    }

    /// Compile command injection detection rules
    fn compile_cmdi_rules() -> Result<Vec<CompiledRule>> {
        let patterns = vec![
            (
                "cmdi_pipe",
                r"[|;&`]\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|python|perl|ruby|php)\b",
                ThreatSeverity::Critical,
                "Command injection via pipe/chain",
            ),
            (
                "cmdi_subshell",
                r"\$\([^)]*\)|\$\{[^}]*\}|`[^`]*`",
                ThreatSeverity::High,
                "Command injection via subshell",
            ),
            (
                "cmdi_reverse_shell",
                r"(?i)(nc|ncat|netcat|bash|sh|python|perl|ruby|php).*(-e|exec|system|popen)",
                ThreatSeverity::Critical,
                "Potential reverse shell attempt",
            ),
            (
                "cmdi_etc_passwd",
                r"/etc/(passwd|shadow|group)",
                ThreatSeverity::High,
                "Sensitive file access attempt",
            ),
            (
                "cmdi_proc_self",
                r"/proc/self/(environ|cmdline|fd)",
                ThreatSeverity::High,
                "Process info disclosure attempt",
            ),
        ];

        Self::compile_patterns(patterns)
    }

    /// Compile path traversal detection rules
    fn compile_path_traversal_rules() -> Result<Vec<CompiledRule>> {
        let patterns = vec![
            (
                "path_traversal_dotdot",
                r"(\.\.[\\/]){2,}",
                ThreatSeverity::High,
                "Path traversal via ../",
            ),
            (
                "path_traversal_encoded",
                r"(%2e%2e[\\/]|%252e%252e[\\/]|\.\.%2f|\.\.%5c)",
                ThreatSeverity::High,
                "Encoded path traversal",
            ),
            (
                "path_traversal_null",
                r"%00|\\x00",
                ThreatSeverity::High,
                "Null byte injection",
            ),
            (
                "path_absolute_unix",
                r"^/(etc|var|usr|tmp|root|home)/",
                ThreatSeverity::Medium,
                "Absolute Unix path access",
            ),
            (
                "path_absolute_windows",
                r"[a-zA-Z]:\\\\(windows|winnt|system32)",
                ThreatSeverity::Medium,
                "Absolute Windows path access",
            ),
        ];

        Self::compile_patterns(patterns)
    }

    /// Compile shellcode detection rules
    fn compile_shellcode_rules() -> Result<Vec<CompiledRule>> {
        let patterns = vec![
            (
                "shellcode_nop_sled",
                r"(\x90{10,}|%90{10,})",
                ThreatSeverity::Critical,
                "NOP sled detected",
            ),
            (
                "shellcode_x86_common",
                r"(\xcd\x80|\x0f\x05|\xff\xe4)",
                ThreatSeverity::Critical,
                "x86 syscall/jmp esp shellcode",
            ),
            (
                "shellcode_format_string",
                r"%[0-9]*\$[nsx]|%[0-9]*n",
                ThreatSeverity::High,
                "Format string vulnerability",
            ),
        ];

        Self::compile_patterns(patterns)
    }

    /// Compile protocol anomaly detection rules
    fn compile_protocol_anomaly_rules() -> Result<Vec<CompiledRule>> {
        let patterns = vec![
            (
                "http_method_invalid",
                r"^(CONNECT|TRACE|TRACK|DEBUG)\s+",
                ThreatSeverity::Medium,
                "Suspicious HTTP method",
            ),
            (
                "http_smuggling",
                r"(?i)(transfer-encoding\s*:\s*chunked.*content-length|content-length.*transfer-encoding\s*:\s*chunked)",
                ThreatSeverity::High,
                "HTTP request smuggling attempt",
            ),
            (
                "http_crlf_injection",
                r"%0d%0a|%0D%0A",
                ThreatSeverity::High,
                "HTTP CRLF injection",
            ),
            (
                "http_host_injection",
                r"(?i)^host\s*:.*@",
                ThreatSeverity::Medium,
                "HTTP Host header injection",
            ),
        ];

        Self::compile_patterns(patterns)
    }

    /// Compile TLS/SSL anomaly detection rules
    fn compile_tls_anomaly_rules() -> Result<Vec<CompiledRule>> {
        // TLS record types and handshake detection via byte patterns
        // TLS records start with: ContentType (1 byte) | Version (2 bytes) | Length (2 bytes)
        // ContentType: 0x14=ChangeCipherSpec, 0x15=Alert, 0x16=Handshake, 0x17=Application
        // Version: 0x0301=TLS1.0, 0x0302=TLS1.1, 0x0303=TLS1.2, 0x0304=TLS1.3
        let patterns = vec![
            (
                "tls_sslv2_client_hello",
                // SSLv2 ClientHello - deprecated and insecure
                r"^\x80[\x20-\xff]\x01\x00\x02",
                ThreatSeverity::High,
                "SSLv2 ClientHello detected - deprecated protocol",
            ),
            (
                "tls_sslv3_handshake",
                // SSLv3 - deprecated and vulnerable (POODLE)
                r"^\x16\x03\x00",
                ThreatSeverity::Medium,
                "SSLv3 detected - vulnerable to POODLE",
            ),
            (
                "tls_heartbleed_probe",
                // Heartbeat request with suspicious length
                r"^\x18\x03[\x00-\x03]",
                ThreatSeverity::Critical,
                "Potential Heartbleed probe",
            ),
            (
                "tls_export_cipher",
                // EXPORT cipher suites in ClientHello - weak crypto
                r"\x00\x03|\x00\x06|\x00\x08|\x00\x0b|\x00\x0e|\x00\x11|\x00\x14|\x00\x17|\x00\x19|\x00\x26",
                ThreatSeverity::High,
                "EXPORT cipher suite offered - weak cryptography",
            ),
            (
                "tls_null_cipher",
                // NULL cipher suites - no encryption
                r"\x00\x00|\x00\x01|\x00\x02|\x00\x2c|\x00\x2d|\x00\x2e|\x00\x3b",
                ThreatSeverity::Critical,
                "NULL cipher suite - no encryption",
            ),
            (
                "tls_anonymous_dh",
                // Anonymous DH - no authentication
                r"\x00\x18|\x00\x1b|\x00\x34|\x00\x3a|\x00\x46|\x00\x6c",
                ThreatSeverity::High,
                "Anonymous DH cipher suite - no authentication",
            ),
            (
                "tls_rc4_cipher",
                // RC4 cipher suites - broken
                r"\x00\x04|\x00\x05|\x00\x24|\x00\x28|\x00\x8a|\x00\x8e|\x00\x92|\xc0\x02|\xc0\x07|\xc0\x0c|\xc0\x11",
                ThreatSeverity::Medium,
                "RC4 cipher suite - broken encryption",
            ),
            (
                "tls_des_cipher",
                // DES/3DES cipher suites - weak
                r"\x00\x09|\x00\x0c|\x00\x0f|\x00\x12|\x00\x15|\x00\x1a|\x00\x1d|\x00\x21",
                ThreatSeverity::Medium,
                "DES/3DES cipher suite - weak encryption",
            ),
            (
                "tls_renegotiation_attack",
                // Empty renegotiation_info in handshake without SCSV
                r"\xff\x01\x00\x01\x00",
                ThreatSeverity::Medium,
                "Potential TLS renegotiation attack",
            ),
        ];

        Self::compile_patterns(patterns)
    }

    /// Helper to compile pattern tuples into CompiledRules
    fn compile_patterns(
        patterns: Vec<(&str, &str, ThreatSeverity, &str)>,
    ) -> Result<Vec<CompiledRule>> {
        patterns
            .into_iter()
            .map(|(name, pattern, severity, desc)| {
                let regex = Regex::new(pattern)
                    .with_context(|| format!("Failed to compile pattern: {}", name))?;
                Ok(CompiledRule {
                    name: name.to_string(),
                    pattern: regex,
                    severity,
                    description: desc.to_string(),
                })
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
