//! SSH protocol analyzer
//!
//! Analyzes SSH traffic for security events including:
//! - Brute force detection (per-IP tracking)
//! - Vulnerable version detection (CVE database)
//! - HASSH fingerprint matching (malware detection)
//! - Weak algorithm detection
//! - Root login attempts

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crmonban_types::{DetectionType, Flow, Packet, ProtocolEvent};
use crmonban_types::protocols::{
    SshEvent, SshAuthMethod, SshVersionInfo, HasshFingerprint,
};
use tracing::{debug, info, warn};

use crate::protocols::ProtocolAnalyzer;
use super::cve::{SshCveDatabase, CveSeverity, SemVer};
use super::hassh::{HasshDatabase, HasshCategory};
use super::parser::{SshParser, WEAK_KEX_ALGORITHMS, WEAK_CIPHERS, WEAK_MACS, has_weak_algorithms};

/// SSH analyzer configuration
#[derive(Debug, Clone)]
pub struct SshAnalyzerConfig {
    /// Enable SSH analysis
    pub enabled: bool,
    /// SSH ports to analyze
    pub ports: Vec<u16>,
    /// Enable brute force detection
    pub detect_brute_force: bool,
    /// Auth failures before triggering brute force alert
    pub brute_force_threshold: u32,
    /// Time window for brute force detection (seconds)
    pub brute_force_window_secs: u64,
    /// Enable version vulnerability detection
    pub detect_vulnerable_versions: bool,
    /// Block SSH-1 protocol
    pub block_ssh1: bool,
    /// Enable HASSH fingerprinting
    pub hassh_enabled: bool,
    /// Enable weak algorithm detection
    pub detect_weak_algorithms: bool,
    /// Alert on root login attempts
    pub alert_root_login: bool,
    /// Path to CVE database file (optional)
    pub cve_database_path: Option<String>,
    /// Path to HASSH database file (optional)
    pub hassh_database_path: Option<String>,
}

impl Default for SshAnalyzerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![22, 2222, 22222],
            detect_brute_force: true,
            brute_force_threshold: 5,
            brute_force_window_secs: 60,
            detect_vulnerable_versions: true,
            block_ssh1: true,
            hassh_enabled: true,
            detect_weak_algorithms: true,
            alert_root_login: true,
            cve_database_path: None,
            hassh_database_path: None,
        }
    }
}

/// Per-IP authentication tracking
#[derive(Debug, Default)]
struct AuthTracker {
    /// Failed attempts in current window
    failures: u32,
    /// Successful attempts
    successes: u32,
    /// Last attempt timestamp
    last_attempt: Option<Instant>,
    /// Window start time
    window_start: Option<Instant>,
    /// Usernames attempted
    usernames: Vec<String>,
    /// Already alerted for brute force
    alerted: bool,
}

impl AuthTracker {
    fn reset_window(&mut self, now: Instant) {
        self.failures = 0;
        self.window_start = Some(now);
        self.usernames.clear();
        self.alerted = false;
    }

    fn record_failure(&mut self, username: &str, now: Instant, window_secs: u64) {
        // Check if we need to reset the window
        if let Some(start) = self.window_start {
            if now.duration_since(start) > Duration::from_secs(window_secs) {
                self.reset_window(now);
            }
        } else {
            self.window_start = Some(now);
        }

        self.failures += 1;
        self.last_attempt = Some(now);
        if !self.usernames.contains(&username.to_string()) {
            self.usernames.push(username.to_string());
        }
    }

    fn record_success(&mut self) {
        self.successes += 1;
    }
}

/// SSH protocol analyzer
pub struct SshAnalyzer {
    /// Configuration
    config: SshAnalyzerConfig,
    /// CVE database
    cve_db: SshCveDatabase,
    /// HASSH database
    hassh_db: HasshDatabase,
    /// Per-IP auth tracking
    auth_trackers: HashMap<IpAddr, AuthTracker>,
    /// Parser instances per flow
    parsers: HashMap<u64, (SshParser, SshParser)>, // (client, server)
    /// Version info per flow
    version_info: HashMap<u64, (Option<SshVersionInfo>, Option<SshVersionInfo>)>,
    /// Statistics
    stats: SshAnalyzerStats,
}

/// SSH analyzer statistics
#[derive(Debug, Default)]
pub struct SshAnalyzerStats {
    /// Total SSH packets analyzed
    pub packets_analyzed: u64,
    /// Version exchanges seen
    pub version_exchanges: u64,
    /// Key exchanges seen
    pub key_exchanges: u64,
    /// Auth attempts seen
    pub auth_attempts: u64,
    /// Successful auths
    pub auth_successes: u64,
    /// Failed auths
    pub auth_failures: u64,
    /// Brute force detections
    pub brute_force_detections: u64,
    /// Vulnerable versions detected
    pub vulnerable_versions: u64,
    /// Malicious HASSH detected
    pub malicious_hassh: u64,
    /// Weak algorithm detections
    pub weak_algorithm_detections: u64,
    /// Root login attempts
    pub root_login_attempts: u64,
    /// SSH-1 detections
    pub ssh1_detections: u64,
}

/// Detection result from SSH analysis
#[derive(Debug, Clone)]
pub struct SshDetection {
    /// Detection type
    pub detection_type: DetectionType,
    /// Severity (0.0 - 1.0)
    pub severity: f32,
    /// Description
    pub description: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl SshAnalyzer {
    /// Create new SSH analyzer
    pub fn new(config: SshAnalyzerConfig) -> Self {
        // Load CVE database
        let cve_db = if let Some(ref path) = config.cve_database_path {
            SshCveDatabase::load_from_file(path).unwrap_or_else(|e| {
                warn!("Failed to load CVE database from {}: {}", path, e);
                SshCveDatabase::load_embedded()
            })
        } else {
            SshCveDatabase::load_embedded()
        };

        // Load HASSH database
        let hassh_db = if let Some(ref path) = config.hassh_database_path {
            HasshDatabase::load_from_file(path).unwrap_or_else(|e| {
                warn!("Failed to load HASSH database from {}: {}", path, e);
                HasshDatabase::load_embedded()
            })
        } else {
            HasshDatabase::load_embedded()
        };

        info!(
            cve_entries = cve_db.stats().total_entries,
            hassh_entries = hassh_db.stats().total_entries,
            "SSH analyzer initialized"
        );

        Self {
            config,
            cve_db,
            hassh_db,
            auth_trackers: HashMap::new(),
            parsers: HashMap::new(),
            version_info: HashMap::new(),
            stats: SshAnalyzerStats::default(),
        }
    }

    /// Analyze SSH event and return detections
    pub fn analyze(&mut self, event: &SshEvent, src_ip: IpAddr, flow_id: u64) -> Vec<SshDetection> {
        let mut detections = Vec::new();
        self.stats.packets_analyzed += 1;

        match event {
            SshEvent::VersionExchange { client_version, server_version, protocol_version } => {
                self.stats.version_exchanges += 1;
                detections.extend(self.analyze_version(
                    client_version,
                    server_version.as_deref(),
                    *protocol_version,
                    src_ip,
                    flow_id,
                ));
            }

            SshEvent::KeyExchangeInit {
                hassh,
                kex_algorithms,
                encryption_c2s,
                mac_c2s,
                ..
            } => {
                self.stats.key_exchanges += 1;
                detections.extend(self.analyze_kex(
                    hassh,
                    kex_algorithms,
                    encryption_c2s,
                    mac_c2s,
                    src_ip,
                ));
            }

            SshEvent::ServerKexInit { hassh_server, .. } => {
                // Analyze server HASSH too
                if self.config.hassh_enabled {
                    detections.extend(self.analyze_hassh(&hassh_server.hash, src_ip, true));
                }
            }

            SshEvent::AuthAttempt { username, method, success, .. } => {
                self.stats.auth_attempts += 1;
                if *success {
                    self.stats.auth_successes += 1;
                } else {
                    self.stats.auth_failures += 1;
                }
                detections.extend(self.analyze_auth(username, method, *success, src_ip));
            }

            SshEvent::ChannelOpen { channel_type, .. } => {
                debug!(channel_type = %channel_type, "SSH channel opened");
            }

            SshEvent::ChannelRequest { request_type, command, subsystem } => {
                debug!(
                    request_type = %request_type,
                    command = ?command,
                    subsystem = ?subsystem,
                    "SSH channel request"
                );
            }
        }

        detections
    }

    /// Analyze SSH version exchange
    fn analyze_version(
        &mut self,
        client_version: &str,
        server_version: Option<&str>,
        protocol_version: u8,
        src_ip: IpAddr,
        flow_id: u64,
    ) -> Vec<SshDetection> {
        let mut detections = Vec::new();

        // Check for SSH-1 protocol
        if self.config.block_ssh1 && protocol_version == 1 {
            self.stats.ssh1_detections += 1;
            detections.push(SshDetection {
                detection_type: DetectionType::SshVersionVulnerable,
                severity: 1.0,
                description: "SSH-1 protocol detected - deprecated and cryptographically broken".into(),
                metadata: [
                    ("version".into(), client_version.into()),
                    ("protocol_version".into(), "1".into()),
                ].into_iter().collect(),
            });
        }

        // Parse and check client version
        if let Some(info) = SshVersionInfo::parse(client_version) {
            if self.config.detect_vulnerable_versions {
                if let Some(version) = SemVer::from_software(&info.software) {
                    if let Some(result) = self.cve_db.lookup(&info.software, Some(&version)) {
                        self.stats.vulnerable_versions += 1;

                        let severity = match result.max_severity {
                            CveSeverity::Critical => 1.0,
                            CveSeverity::High => 0.8,
                            CveSeverity::Medium => 0.5,
                            CveSeverity::Low => 0.3,
                        };

                        let cve_list: Vec<_> = result.cves.iter().map(|c| c.cve_id.clone()).collect();
                        detections.push(SshDetection {
                            detection_type: DetectionType::SshVersionVulnerable,
                            severity,
                            description: format!(
                                "Vulnerable SSH version detected: {} (CVEs: {})",
                                info.software,
                                cve_list.join(", ")
                            ),
                            metadata: [
                                ("software".into(), info.software.clone()),
                                ("version".into(), version.to_string()),
                                ("cves".into(), cve_list.join(",")),
                                ("max_cvss".into(), result.max_cvss.to_string()),
                            ].into_iter().collect(),
                        });
                    }
                }
            }

            // Store version info for flow
            let entry = self.version_info.entry(flow_id).or_insert((None, None));
            entry.0 = Some(info);
        }

        // Check server version if present
        if let Some(sv) = server_version {
            if let Some(info) = SshVersionInfo::parse(sv) {
                if self.config.detect_vulnerable_versions {
                    if let Some(version) = SemVer::from_software(&info.software) {
                        if let Some(result) = self.cve_db.lookup(&info.software, Some(&version)) {
                            let severity = match result.max_severity {
                                CveSeverity::Critical => 1.0,
                                CveSeverity::High => 0.8,
                                CveSeverity::Medium => 0.5,
                                CveSeverity::Low => 0.3,
                            };

                            let cve_list: Vec<_> = result.cves.iter().map(|c| c.cve_id.clone()).collect();
                            detections.push(SshDetection {
                                detection_type: DetectionType::SshVersionVulnerable,
                                severity,
                                description: format!(
                                    "Vulnerable SSH server: {} (CVEs: {})",
                                    info.software,
                                    cve_list.join(", ")
                                ),
                                metadata: [
                                    ("software".into(), info.software.clone()),
                                    ("version".into(), version.to_string()),
                                    ("cves".into(), cve_list.join(",")),
                                    ("is_server".into(), "true".into()),
                                ].into_iter().collect(),
                            });
                        }
                    }
                }

                let entry = self.version_info.entry(flow_id).or_insert((None, None));
                entry.1 = Some(info);
            }
        }

        detections
    }

    /// Analyze key exchange initialization
    fn analyze_kex(
        &mut self,
        hassh: &HasshFingerprint,
        kex_algorithms: &[String],
        encryption: &[String],
        mac: &[String],
        src_ip: IpAddr,
    ) -> Vec<SshDetection> {
        let mut detections = Vec::new();

        // Check HASSH fingerprint
        if self.config.hassh_enabled {
            detections.extend(self.analyze_hassh(&hassh.hash, src_ip, false));
        }

        // Check for weak algorithms
        if self.config.detect_weak_algorithms {
            let weak_kex = has_weak_algorithms(kex_algorithms, WEAK_KEX_ALGORITHMS);
            let weak_enc = has_weak_algorithms(encryption, WEAK_CIPHERS);
            let weak_mac = has_weak_algorithms(mac, WEAK_MACS);

            if !weak_kex.is_empty() {
                self.stats.weak_algorithm_detections += 1;
                detections.push(SshDetection {
                    detection_type: DetectionType::SshWeakKeyExchange,
                    severity: 0.6,
                    description: format!("Weak key exchange algorithms offered: {}", weak_kex.join(", ")),
                    metadata: [
                        ("weak_algorithms".into(), weak_kex.join(",")),
                        ("algorithm_type".into(), "kex".into()),
                    ].into_iter().collect(),
                });
            }

            if !weak_enc.is_empty() {
                self.stats.weak_algorithm_detections += 1;
                detections.push(SshDetection {
                    detection_type: DetectionType::SshWeakCipher,
                    severity: 0.7,
                    description: format!("Weak ciphers offered: {}", weak_enc.join(", ")),
                    metadata: [
                        ("weak_algorithms".into(), weak_enc.join(",")),
                        ("algorithm_type".into(), "cipher".into()),
                    ].into_iter().collect(),
                });
            }

            if !weak_mac.is_empty() {
                self.stats.weak_algorithm_detections += 1;
                detections.push(SshDetection {
                    detection_type: DetectionType::SshWeakMac,
                    severity: 0.5,
                    description: format!("Weak MAC algorithms offered: {}", weak_mac.join(", ")),
                    metadata: [
                        ("weak_algorithms".into(), weak_mac.join(",")),
                        ("algorithm_type".into(), "mac".into()),
                    ].into_iter().collect(),
                });
            }
        }

        detections
    }

    /// Analyze HASSH fingerprint
    fn analyze_hassh(&mut self, hash: &str, src_ip: IpAddr, is_server: bool) -> Vec<SshDetection> {
        let mut detections = Vec::new();

        let result = self.hassh_db.lookup(hash);

        if result.is_malicious {
            self.stats.malicious_hassh += 1;
            let malware = result.malware.as_ref();
            detections.push(SshDetection {
                detection_type: DetectionType::SshKnownMalwareHashsh,
                severity: result.confidence,
                description: format!(
                    "Known malicious SSH {} fingerprint: {} ({})",
                    if is_server { "server" } else { "client" },
                    hash,
                    malware.map(|m| m.family.as_str()).unwrap_or("unknown")
                ),
                metadata: [
                    ("hassh".into(), hash.into()),
                    ("is_server".into(), is_server.to_string()),
                    ("family".into(), malware.map(|m| m.family.clone()).unwrap_or_default()),
                    ("confidence".into(), result.confidence.to_string()),
                ].into_iter().collect(),
            });
        } else if let Some(entry) = result.entry {
            // Log interesting fingerprints (offensive tools, bots)
            match entry.category {
                HasshCategory::OffensiveTool => {
                    debug!(
                        hassh = %hash,
                        software = ?entry.software,
                        "Offensive tool SSH fingerprint detected"
                    );
                }
                HasshCategory::Bot => {
                    debug!(
                        hassh = %hash,
                        software = ?entry.software,
                        "Bot/scanner SSH fingerprint detected"
                    );
                }
                _ => {}
            }
        }

        detections
    }

    /// Analyze authentication attempt
    fn analyze_auth(
        &mut self,
        username: &str,
        method: &SshAuthMethod,
        success: bool,
        src_ip: IpAddr,
    ) -> Vec<SshDetection> {
        let mut detections = Vec::new();
        let now = Instant::now();

        // Get or create tracker for this IP
        let tracker = self.auth_trackers.entry(src_ip).or_default();

        if success {
            tracker.record_success();
        } else {
            tracker.record_failure(username, now, self.config.brute_force_window_secs);

            // Check for brute force
            if self.config.detect_brute_force
                && tracker.failures >= self.config.brute_force_threshold
                && !tracker.alerted
            {
                self.stats.brute_force_detections += 1;
                tracker.alerted = true;

                detections.push(SshDetection {
                    detection_type: DetectionType::SshBruteForce,
                    severity: 0.8,
                    description: format!(
                        "SSH brute force attack: {} failures from {} in {} seconds",
                        tracker.failures,
                        src_ip,
                        self.config.brute_force_window_secs
                    ),
                    metadata: [
                        ("failures".into(), tracker.failures.to_string()),
                        ("src_ip".into(), src_ip.to_string()),
                        ("usernames".into(), tracker.usernames.join(",")),
                        ("window_secs".into(), self.config.brute_force_window_secs.to_string()),
                    ].into_iter().collect(),
                });
            }
        }

        // Check for root login attempt
        if self.config.alert_root_login && (username == "root" || username == "admin" || username == "administrator") {
            self.stats.root_login_attempts += 1;
            detections.push(SshDetection {
                detection_type: DetectionType::SshRootLogin,
                severity: if success { 0.9 } else { 0.5 },
                description: format!(
                    "SSH {} login attempt for privileged user '{}'",
                    if success { "successful" } else { "failed" },
                    username
                ),
                metadata: [
                    ("username".into(), username.into()),
                    ("method".into(), format!("{}", method)),
                    ("success".into(), success.to_string()),
                ].into_iter().collect(),
            });
        }

        // Check for invalid/suspicious usernames
        if is_invalid_username(username) {
            detections.push(SshDetection {
                detection_type: DetectionType::SshInvalidUser,
                severity: 0.4,
                description: format!("SSH login attempt with invalid/suspicious username: {}", username),
                metadata: [
                    ("username".into(), username.into()),
                ].into_iter().collect(),
            });
        }

        detections
    }

    /// Get analyzer statistics
    pub fn stats(&self) -> &SshAnalyzerStats {
        &self.stats
    }

    /// Clean up old tracking data
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.brute_force_window_secs * 2);

        // Remove old auth trackers
        self.auth_trackers.retain(|_, tracker| {
            tracker.last_attempt
                .map(|t| now.duration_since(t) < window)
                .unwrap_or(false)
        });

        // Could also clean up old flow data
    }
}

impl ProtocolAnalyzer for SshAnalyzer {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn detect(&self, payload: &[u8], port: u16) -> bool {
        self.config.ports.contains(&port) || SshParser::is_ssh(payload)
    }

    fn parse(&self, packet: &Packet, flow: &mut Flow) -> Option<ProtocolEvent> {
        let payload = packet.payload();
        if payload.is_empty() {
            return None;
        }

        // Check for version string first
        if let Some(event) = SshParser::parse_version(payload) {
            return Some(ProtocolEvent::Ssh(event));
        }

        // Try parsing as binary SSH packet
        let mut parser = SshParser::new(true);
        if let Some(event) = parser.parse_packet(payload) {
            return Some(ProtocolEvent::Ssh(event));
        }

        None
    }
}

/// Check if username is invalid/suspicious
fn is_invalid_username(username: &str) -> bool {
    // Empty or whitespace
    if username.trim().is_empty() {
        return true;
    }

    // Too long
    if username.len() > 32 {
        return true;
    }

    // Contains suspicious characters
    if username.contains(|c: char| c.is_control() || c == '\'' || c == '"' || c == ';' || c == '|') {
        return true;
    }

    // Common invalid/default usernames used in attacks
    let suspicious = [
        "test", "guest", "user", "default", "support", "admin1", "administrator",
        "backup", "oracle", "mysql", "postgres", "ftp", "www", "apache", "nginx",
        "ubuntu", "centos", "debian", "pi", "raspberrypi",
    ];

    suspicious.contains(&username.to_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_creation() {
        let config = SshAnalyzerConfig::default();
        let analyzer = SshAnalyzer::new(config);
        assert!(analyzer.stats.packets_analyzed == 0);
    }

    #[test]
    fn test_invalid_username() {
        assert!(is_invalid_username(""));
        assert!(is_invalid_username("test"));
        assert!(is_invalid_username("root'; DROP TABLE users;--"));
        assert!(!is_invalid_username("john.doe"));
        assert!(!is_invalid_username("valid_user123"));
    }

    #[test]
    fn test_brute_force_detection() {
        let config = SshAnalyzerConfig {
            brute_force_threshold: 3,
            brute_force_window_secs: 60,
            ..Default::default()
        };
        let mut analyzer = SshAnalyzer::new(config);
        let src_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // First 2 failures - no alert
        for i in 0..2 {
            let detections = analyzer.analyze_auth(
                &format!("user{}", i),
                &SshAuthMethod::Password,
                false,
                src_ip,
            );
            assert!(detections.iter().all(|d| d.detection_type != DetectionType::SshBruteForce));
        }

        // Third failure - should trigger alert
        let detections = analyzer.analyze_auth("user3", &SshAuthMethod::Password, false, src_ip);
        assert!(detections.iter().any(|d| d.detection_type == DetectionType::SshBruteForce));
    }

    #[test]
    fn test_root_login_detection() {
        let config = SshAnalyzerConfig::default();
        let mut analyzer = SshAnalyzer::new(config);
        let src_ip: IpAddr = "192.168.1.100".parse().unwrap();

        let detections = analyzer.analyze_auth("root", &SshAuthMethod::Password, false, src_ip);
        assert!(detections.iter().any(|d| d.detection_type == DetectionType::SshRootLogin));
    }
}
