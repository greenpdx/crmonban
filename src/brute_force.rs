//! Brute Force Attack Detection Module
//!
//! Detects brute force login attempts by analyzing session patterns:
//! - Many short sessions to authentication services (SSH, FTP, RDP, etc.)
//! - Small packet counts per session (typical of failed logins)
//! - Rapid connection attempts from same source
//!
//! # Example
//! ```ignore
//! use crmonban::brute_force::{BruteForceTracker, SessionEvent};
//!
//! let mut tracker = BruteForceTracker::new();
//!
//! // Track session start
//! tracker.session_start(src_ip, dst_ip, dst_port);
//!
//! // Track packets in session
//! tracker.session_packet(src_ip, dst_ip, dst_port, payload_len);
//!
//! // Track session end and check for brute force
//! if let Some(alert) = tracker.session_end(src_ip, dst_ip, dst_port, was_reset) {
//!     println!("Brute force detected: {} attempts from {}", alert.attempt_count, alert.src_ip);
//! }
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::core::{PacketAnalysis, DetectionEvent, DetectionType, Severity};
use crate::engine::pipeline::{PipelineConfig, PipelineStage, StageProcessor};

/// Configuration for brute force detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceConfig {
    /// Minimum failed attempts to trigger alert
    pub attempt_threshold: usize,
    /// Time window for counting attempts
    pub window_duration: Duration,
    /// Maximum packets in a session to consider it a "failed attempt"
    /// (successful logins typically have more packets)
    pub max_packets_for_failure: usize,
    /// Maximum session duration to consider it a "failed attempt"
    pub max_duration_for_failure: Duration,
    /// Maximum bytes in session to consider it a "failed attempt"
    pub max_bytes_for_failure: usize,
}

impl Default for BruteForceConfig {
    fn default() -> Self {
        Self {
            attempt_threshold: 5,
            window_duration: Duration::from_secs(60),
            max_packets_for_failure: 20,
            max_duration_for_failure: Duration::from_secs(10),
            max_bytes_for_failure: 2000,
        }
    }
}

/// Target key: (source IP, destination IP, destination port)
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
struct TargetKey {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
}

/// Active session being tracked
#[derive(Debug, Clone)]
struct ActiveSession {
    start_time: Instant,
    packet_count: usize,
    total_bytes: usize,
}

impl ActiveSession {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            packet_count: 0,
            total_bytes: 0,
        }
    }
}

/// Record of failed attempts to a target
#[derive(Debug, Clone)]
struct FailedAttempts {
    /// Timestamps of failed attempts
    attempts: Vec<Instant>,
    /// Whether alert has been triggered
    alerted: bool,
}

impl FailedAttempts {
    fn new() -> Self {
        Self {
            attempts: Vec::new(),
            alerted: false,
        }
    }

    /// Add a failed attempt and clean old ones outside window
    fn add_attempt(&mut self, window: Duration) {
        let now = Instant::now();
        // Remove attempts outside window
        self.attempts.retain(|t| now.duration_since(*t) <= window);
        self.attempts.push(now);
    }

    /// Get count of attempts within window
    fn count_in_window(&self, window: Duration) -> usize {
        let now = Instant::now();
        self.attempts
            .iter()
            .filter(|t| now.duration_since(**t) <= window)
            .count()
    }
}

/// Brute force attack tracker
#[derive(Debug)]
pub struct BruteForceTracker {
    /// Configuration
    config: BruteForceConfig,
    /// Active sessions: key -> session data
    active_sessions: HashMap<TargetKey, ActiveSession>,
    /// Failed attempt history per target
    failed_attempts: HashMap<TargetKey, FailedAttempts>,
    /// Ports that are authentication services
    auth_ports: HashMap<u16, &'static str>,
    /// Total alerts triggered
    total_alerts: usize,
}

impl BruteForceTracker {
    /// Create new tracker with default config
    pub fn new() -> Self {
        Self::with_config(BruteForceConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: BruteForceConfig) -> Self {
        // Common authentication service ports
        let mut auth_ports = HashMap::new();
        auth_ports.insert(21, "FTP");
        auth_ports.insert(22, "SSH");
        auth_ports.insert(23, "Telnet");
        auth_ports.insert(25, "SMTP");
        auth_ports.insert(110, "POP3");
        auth_ports.insert(143, "IMAP");
        auth_ports.insert(389, "LDAP");
        auth_ports.insert(443, "HTTPS");
        auth_ports.insert(445, "SMB");
        auth_ports.insert(465, "SMTPS");
        auth_ports.insert(587, "SMTP-Sub");
        auth_ports.insert(636, "LDAPS");
        auth_ports.insert(993, "IMAPS");
        auth_ports.insert(995, "POP3S");
        auth_ports.insert(1433, "MSSQL");
        auth_ports.insert(1521, "Oracle");
        auth_ports.insert(3306, "MySQL");
        auth_ports.insert(3389, "RDP");
        auth_ports.insert(5432, "PostgreSQL");
        auth_ports.insert(5900, "VNC");
        auth_ports.insert(6379, "Redis");
        auth_ports.insert(8080, "HTTP-Alt");
        auth_ports.insert(27017, "MongoDB");

        Self {
            config,
            active_sessions: HashMap::new(),
            failed_attempts: HashMap::new(),
            auth_ports,
            total_alerts: 0,
        }
    }

    /// Check if port is an authentication service
    pub fn is_auth_port(&self, port: u16) -> bool {
        self.auth_ports.contains_key(&port)
    }

    /// Get service name for port
    pub fn get_service_name(&self, port: u16) -> Option<&'static str> {
        self.auth_ports.get(&port).copied()
    }

    /// Track start of a new session (SYN packet)
    pub fn session_start(&mut self, src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16) {
        // Only track auth service ports
        if !self.is_auth_port(dst_port) {
            return;
        }

        let key = TargetKey { src_ip, dst_ip, dst_port };
        self.active_sessions.insert(key, ActiveSession::new());
    }

    /// Track a packet in an active session
    pub fn session_packet(&mut self, src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16, payload_len: usize) {
        let key = TargetKey { src_ip, dst_ip, dst_port };

        if let Some(session) = self.active_sessions.get_mut(&key) {
            session.packet_count += 1;
            session.total_bytes += payload_len;
        }
    }

    /// Track end of a session and check for brute force pattern
    /// Returns alert if brute force threshold exceeded
    pub fn session_end(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        was_reset: bool,
    ) -> Option<BruteForceAlert> {
        let key = TargetKey { src_ip, dst_ip, dst_port };

        let session = self.active_sessions.remove(&key)?;
        let duration = session.start_time.elapsed();

        // Check if this looks like a failed login attempt
        let is_failed_attempt = self.is_failed_attempt(&session, duration, was_reset);

        if is_failed_attempt {
            // Record the failed attempt
            let attempts = self.failed_attempts
                .entry(key)
                .or_insert_with(FailedAttempts::new);

            attempts.add_attempt(self.config.window_duration);

            // Check if threshold exceeded
            let count = attempts.count_in_window(self.config.window_duration);

            if count >= self.config.attempt_threshold && !attempts.alerted {
                attempts.alerted = true;
                self.total_alerts += 1;

                return Some(BruteForceAlert {
                    src_ip,
                    dst_ip,
                    dst_port,
                    service: self.get_service_name(dst_port).unwrap_or("Unknown"),
                    attempt_count: count,
                    window_seconds: self.config.window_duration.as_secs(),
                    last_session_packets: session.packet_count,
                    last_session_bytes: session.total_bytes,
                    last_session_duration_ms: duration.as_millis() as u64,
                });
            }
        }

        None
    }

    /// Determine if a session looks like a failed login attempt
    fn is_failed_attempt(&self, session: &ActiveSession, duration: Duration, was_reset: bool) -> bool {
        // RST after short session is very suspicious
        if was_reset && session.packet_count <= 10 {
            return true;
        }

        // Check all failure criteria
        let short_duration = duration <= self.config.max_duration_for_failure;
        let few_packets = session.packet_count <= self.config.max_packets_for_failure;
        let small_transfer = session.total_bytes <= self.config.max_bytes_for_failure;

        // Must meet at least 2 of 3 criteria
        let criteria_met = [short_duration, few_packets, small_transfer]
            .iter()
            .filter(|&&x| x)
            .count();

        criteria_met >= 2
    }

    /// Track a complete session at once (for flow-based analysis)
    pub fn track_session(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        packet_count: usize,
        total_bytes: usize,
        duration_ms: u64,
        had_rst: bool,
    ) -> Option<BruteForceAlert> {
        // Only track auth service ports
        if !self.is_auth_port(dst_port) {
            return None;
        }

        let key = TargetKey { src_ip, dst_ip, dst_port };

        // Create synthetic session for analysis
        let session = ActiveSession {
            start_time: Instant::now(), // Not used for duration check
            packet_count,
            total_bytes,
        };

        let duration = Duration::from_millis(duration_ms);
        let is_failed = self.is_failed_attempt(&session, duration, had_rst);

        if is_failed {
            let attempts = self.failed_attempts
                .entry(key)
                .or_insert_with(FailedAttempts::new);

            attempts.add_attempt(self.config.window_duration);

            let count = attempts.count_in_window(self.config.window_duration);

            if count >= self.config.attempt_threshold && !attempts.alerted {
                attempts.alerted = true;
                self.total_alerts += 1;

                return Some(BruteForceAlert {
                    src_ip,
                    dst_ip,
                    dst_port,
                    service: self.get_service_name(dst_port).unwrap_or("Unknown"),
                    attempt_count: count,
                    window_seconds: self.config.window_duration.as_secs(),
                    last_session_packets: packet_count,
                    last_session_bytes: total_bytes,
                    last_session_duration_ms: duration_ms,
                });
            }
        }

        None
    }

    /// Get total alerts triggered
    pub fn total_alerts(&self) -> usize {
        self.total_alerts
    }

    /// Get number of targets being tracked
    pub fn tracked_targets(&self) -> usize {
        self.failed_attempts.len()
    }

    /// Get top targets by attempt count
    pub fn top_targets(&self, limit: usize) -> Vec<(IpAddr, IpAddr, u16, usize)> {
        let mut targets: Vec<_> = self.failed_attempts
            .iter()
            .map(|(k, v)| (k.src_ip, k.dst_ip, k.dst_port, v.count_in_window(self.config.window_duration)))
            .collect();

        targets.sort_by(|a, b| b.3.cmp(&a.3));
        targets.truncate(limit);
        targets
    }

    /// Clear all tracking data
    pub fn clear(&mut self) {
        self.active_sessions.clear();
        self.failed_attempts.clear();
        self.total_alerts = 0;
    }

    /// Cleanup expired entries
    pub fn cleanup_expired(&mut self) {
        let window = self.config.window_duration;

        // Remove failed attempt records with no recent attempts
        self.failed_attempts.retain(|_, v| {
            v.count_in_window(window) > 0
        });

        // Remove stale active sessions (should have ended but didn't)
        let stale_threshold = Duration::from_secs(300); // 5 minutes
        self.active_sessions.retain(|_, v| {
            v.start_time.elapsed() <= stale_threshold
        });
    }
}

impl Default for BruteForceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl BruteForceTracker {
    /// Process a packet and detect brute force patterns
    ///
    /// This method examines TCP flags to track session lifecycle:
    /// - SYN: Start a new session
    /// - FIN/RST: End a session and check for brute force pattern
    /// - Other: Update packet count for active session
    pub fn process_packet(&mut self, packet: &crate::core::Packet) -> Option<BruteForceAlert> {
        // Only process TCP packets
        let flags = packet.tcp_flags()?;
        let src_ip = packet.src_ip();
        let dst_ip = packet.dst_ip();
        let dst_port = packet.dst_port();
        let payload_len = packet.payload().len();

        // SYN without ACK = new connection
        if flags.syn && !flags.ack {
            self.session_start(src_ip, dst_ip, dst_port);
            return None;
        }

        // FIN or RST = session end
        if flags.fin || flags.rst {
            return self.session_end(src_ip, dst_ip, dst_port, flags.rst);
        }

        // Other packets = update session
        self.session_packet(src_ip, dst_ip, dst_port, payload_len);
        None
    }

    /// Convert an alert to a DetectionEvent
    pub fn alert_to_event(&self, alert: &BruteForceAlert) -> DetectionEvent {
        let severity = match alert.severity() {
            s if s >= 8 => Severity::Critical,
            s if s >= 6 => Severity::High,
            s if s >= 4 => Severity::Medium,
            _ => Severity::Low,
        };

        DetectionEvent::new(
            DetectionType::BruteForce,
            severity,
            alert.src_ip,
            alert.dst_ip,
            format!(
                "{} brute force: {} attempts in {}s on port {} ({})",
                alert.service,
                alert.attempt_count,
                alert.window_seconds,
                alert.dst_port,
                alert.service,
            ),
        )
        .with_detector("brute_force")
        .with_ports(0, alert.dst_port)
    }
}

impl StageProcessor<PipelineConfig, PipelineStage> for BruteForceTracker {
    async fn process(&mut self, mut analysis: PacketAnalysis, _config: &PipelineConfig) -> PacketAnalysis {
        if let Some(alert) = self.process_packet(&analysis.packet) {
            let event = self.alert_to_event(&alert);
            analysis.add_event(event);
        }
        analysis
    }

    async fn stage(&self) -> PipelineStage {
        PipelineStage::BruteForceDetection
    }
}

/// Brute force attack alert
#[derive(Debug, Clone)]
pub struct BruteForceAlert {
    /// Source IP performing the attack
    pub src_ip: IpAddr,
    /// Destination IP being attacked
    pub dst_ip: IpAddr,
    /// Destination port being attacked
    pub dst_port: u16,
    /// Service name (SSH, FTP, etc.)
    pub service: &'static str,
    /// Number of failed attempts detected
    pub attempt_count: usize,
    /// Time window in seconds
    pub window_seconds: u64,
    /// Packets in last session
    pub last_session_packets: usize,
    /// Bytes in last session
    pub last_session_bytes: usize,
    /// Duration of last session in ms
    pub last_session_duration_ms: u64,
}

impl BruteForceAlert {
    /// Get severity level (1-10)
    pub fn severity(&self) -> u8 {
        let mut severity = 4u8; // Base severity

        // More attempts = higher severity
        if self.attempt_count >= 50 {
            severity += 4;
        } else if self.attempt_count >= 20 {
            severity += 3;
        } else if self.attempt_count >= 10 {
            severity += 2;
        } else {
            severity += 1;
        }

        // Critical services bump severity
        match self.service {
            "SSH" | "RDP" | "SMB" => severity += 1,
            "MySQL" | "PostgreSQL" | "MSSQL" | "MongoDB" | "Redis" => severity += 1,
            _ => {}
        }

        severity.min(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_brute_force_basic() {
        let mut config = BruteForceConfig::default();
        config.attempt_threshold = 3;

        let mut tracker = BruteForceTracker::with_config(config);
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Simulate 3 failed SSH login attempts
        for i in 0..3 {
            tracker.session_start(src, dst, 22);
            tracker.session_packet(src, dst, 22, 100);
            tracker.session_packet(src, dst, 22, 50);

            let alert = tracker.session_end(src, dst, 22, i == 2);

            if i < 2 {
                assert!(alert.is_none());
            } else {
                assert!(alert.is_some());
                let alert = alert.unwrap();
                assert_eq!(alert.service, "SSH");
                assert_eq!(alert.attempt_count, 3);
            }
        }
    }

    #[test]
    fn test_track_session() {
        let mut config = BruteForceConfig::default();
        config.attempt_threshold = 3;

        let mut tracker = BruteForceTracker::with_config(config);
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50));
        let dst = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // 3 failed RDP attempts
        for i in 0..3 {
            let alert = tracker.track_session(
                src, dst, 3389,
                5,      // packets
                500,    // bytes
                2000,   // 2 seconds
                true,   // had RST
            );

            if i < 2 {
                assert!(alert.is_none());
            } else {
                assert!(alert.is_some());
                let a = alert.unwrap();
                assert_eq!(a.service, "RDP");
            }
        }
    }

    #[test]
    fn test_non_auth_port_ignored() {
        let mut tracker = BruteForceTracker::new();
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Port 12345 is not an auth port
        for _ in 0..10 {
            tracker.session_start(src, dst, 12345);
            let alert = tracker.session_end(src, dst, 12345, true);
            assert!(alert.is_none());
        }

        assert_eq!(tracker.total_alerts(), 0);
    }

    #[test]
    fn test_successful_login_not_flagged() {
        let mut config = BruteForceConfig::default();
        config.attempt_threshold = 3;

        let mut tracker = BruteForceTracker::with_config(config);
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Simulate successful SSH sessions (many packets, large transfer)
        for _ in 0..10 {
            tracker.session_start(src, dst, 22);
            for _ in 0..100 {
                tracker.session_packet(src, dst, 22, 500);
            }
            let alert = tracker.session_end(src, dst, 22, false);
            assert!(alert.is_none());
        }

        assert_eq!(tracker.total_alerts(), 0);
    }

    #[test]
    fn test_is_auth_port() {
        let tracker = BruteForceTracker::new();
        assert!(tracker.is_auth_port(22));  // SSH
        assert!(tracker.is_auth_port(3389)); // RDP
        assert!(tracker.is_auth_port(3306)); // MySQL
        assert!(!tracker.is_auth_port(80));  // HTTP (not auth-focused)
        assert!(!tracker.is_auth_port(12345)); // Random
    }

    #[test]
    fn test_severity() {
        let alert = BruteForceAlert {
            src_ip: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            dst_port: 22,
            service: "SSH",
            attempt_count: 50,
            window_seconds: 60,
            last_session_packets: 5,
            last_session_bytes: 200,
            last_session_duration_ms: 1000,
        };

        // 50+ attempts on SSH should be high severity
        assert!(alert.severity() >= 8);
    }
}
