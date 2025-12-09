//! Per-IP behavior tracking for probabilistic scan detection

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Flow key for tracking individual connections
/// Uses the full 4-tuple: (src_port, dst_ip, dst_port)
/// Note: src_ip is already the key for SourceBehavior
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl FlowKey {
    pub fn new(src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Self {
        Self { src_port, dst_ip, dst_port }
    }
}

/// Connection state for a specific port
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// SYN sent, waiting for SYN-ACK
    HalfOpen,
    /// SYN-ACK received, waiting for ACK
    SynReceived,
    /// Full handshake completed
    Established,
    /// Data has been exchanged
    Active,
    /// Connection was reset
    Reset,
    /// Connection timed out (half-open expired)
    Expired,
}

/// Classification of source IP behavior
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Classification {
    /// Score < suspicious threshold
    Normal,
    /// Score >= suspicious threshold
    Suspicious,
    /// Score >= probable_scan threshold
    ProbableScan,
    /// Score >= likely_attack threshold
    LikelyAttack,
    /// Score >= confirmed_scan threshold
    ConfirmedScan,
    /// Network issue detected (not attack)
    NetworkIssue,
    /// Could not verify (scanner blocking probes)
    Unverifiable,
}

impl Classification {
    /// Get severity level (0-10)
    pub fn severity(&self) -> u8 {
        match self {
            Classification::Normal => 0,
            Classification::Suspicious => 3,
            Classification::ProbableScan => 5,
            Classification::LikelyAttack => 7,
            Classification::ConfirmedScan => 9,
            Classification::NetworkIssue => 2,
            Classification::Unverifiable => 4,
        }
    }

    /// Should this trigger an alert?
    pub fn should_alert(&self) -> bool {
        matches!(
            self,
            Classification::ProbableScan
                | Classification::LikelyAttack
                | Classification::ConfirmedScan
        )
    }

    /// Should this trigger a ban?
    pub fn should_ban(&self) -> bool {
        matches!(
            self,
            Classification::LikelyAttack | Classification::ConfirmedScan
        )
    }
}

/// Score history entry for audit trail
#[derive(Debug, Clone)]
pub struct ScoreEntry {
    /// When this score was applied
    pub timestamp: Instant,
    /// Rule ID that generated this score
    pub rule_id: String,
    /// Score delta (positive or negative)
    pub delta: f32,
    /// Running total after this entry
    pub total: f32,
    /// Evidence/reason
    pub evidence: String,
}

/// Per-port connection tracking
#[derive(Debug, Clone)]
pub struct PortConnection {
    /// Current state
    pub state: ConnectionState,
    /// When SYN was first seen
    pub syn_time: Instant,
    /// When handshake completed (if any)
    pub established_time: Option<Instant>,
    /// Bytes transferred (if established)
    pub bytes_transferred: u64,
    /// Protocol detected (http, tls, ssh, etc.)
    pub protocol: Option<String>,
}

impl PortConnection {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::HalfOpen,
            syn_time: Instant::now(),
            established_time: None,
            bytes_transferred: 0,
            protocol: None,
        }
    }

    /// Check if connection is expired (half-open timeout)
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.state == ConnectionState::HalfOpen && self.syn_time.elapsed() > timeout
    }

    /// Mark as established
    pub fn establish(&mut self) {
        self.state = ConnectionState::Established;
        self.established_time = Some(Instant::now());
    }

    /// Add bytes transferred
    pub fn add_bytes(&mut self, bytes: u64) {
        self.bytes_transferred += bytes;
        if self.state == ConnectionState::Established {
            self.state = ConnectionState::Active;
        }
    }
}

impl Default for PortConnection {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-source IP behavior tracking
#[derive(Debug)]
pub struct SourceBehavior {
    /// Source IP address
    pub src_ip: IpAddr,

    /// Per-flow connection tracking (full 4-tuple)
    pub connections: HashMap<FlowKey, PortConnection>,

    /// Flow keys that had half-open connections that expired
    pub expired_half_opens: HashSet<FlowKey>,

    /// Flow keys with completed handshakes
    pub completed_flows: HashSet<FlowKey>,

    /// Unique destination ports touched (for scan detection)
    pub touched_ports: HashSet<u16>,

    /// Current score
    pub score: f32,

    /// Score history (audit trail)
    pub score_history: VecDeque<ScoreEntry>,

    /// Current classification
    pub classification: Classification,

    /// When first seen
    pub first_seen: Instant,

    /// When last seen
    pub last_seen: Instant,

    /// SYN timestamps for rate detection
    pub syn_timestamps: VecDeque<Instant>,

    /// Port sequence for sequential scan detection
    pub port_sequence: Vec<u16>,

    /// Whether verification has been attempted
    pub verified: bool,

    /// Verification result
    pub verification_result: Option<VerificationResult>,

    /// Tags applied by rules
    pub tags: HashSet<String>,

    /// Stealth scan type counts (null, fin, xmas, maimon, ack_only)
    pub stealth_scan_counts: HashMap<String, u32>,
}

/// Result of active verification (nmap probe)
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// When verification was performed
    pub timestamp: Instant,
    /// Whether probe succeeded
    pub probe_success: bool,
    /// Method used
    pub method: String,
    /// Details
    pub details: String,
}

impl SourceBehavior {
    /// Create new behavior tracker for an IP
    pub fn new(src_ip: IpAddr) -> Self {
        let now = Instant::now();
        Self {
            src_ip,
            connections: HashMap::new(),
            expired_half_opens: HashSet::new(),
            completed_flows: HashSet::new(),
            touched_ports: HashSet::new(),
            score: 0.0,
            score_history: VecDeque::with_capacity(100),
            classification: Classification::Normal,
            first_seen: now,
            last_seen: now,
            syn_timestamps: VecDeque::with_capacity(100),
            port_sequence: Vec::new(),
            verified: false,
            verification_result: None,
            tags: HashSet::new(),
            stealth_scan_counts: HashMap::new(),
        }
    }

    /// Record a stealth scan packet type
    pub fn record_stealth_scan(&mut self, scan_type: &str) {
        *self.stealth_scan_counts.entry(scan_type.to_string()).or_insert(0) += 1;
    }

    /// Record a SYN packet with full flow key
    pub fn record_syn(&mut self, flow_key: FlowKey) {
        let now = Instant::now();
        self.last_seen = now;
        self.syn_timestamps.push_back(now);
        self.port_sequence.push(flow_key.dst_port);
        self.touched_ports.insert(flow_key.dst_port);

        // Only create if not already tracking this flow
        self.connections.entry(flow_key).or_insert_with(PortConnection::new);
    }

    /// Record handshake completion (SYN-ACK + ACK received)
    pub fn record_established(&mut self, flow_key: FlowKey) {
        self.last_seen = Instant::now();
        if let Some(conn) = self.connections.get_mut(&flow_key) {
            conn.establish();
            self.completed_flows.insert(flow_key);
        }
    }

    /// Record data transfer
    pub fn record_data(&mut self, flow_key: FlowKey, bytes: u64) {
        self.last_seen = Instant::now();
        if let Some(conn) = self.connections.get_mut(&flow_key) {
            conn.add_bytes(bytes);
        }
    }

    /// Record protocol detection
    pub fn record_protocol(&mut self, flow_key: FlowKey, protocol: &str) {
        if let Some(conn) = self.connections.get_mut(&flow_key) {
            conn.protocol = Some(protocol.to_string());
        }
    }

    /// Record RST received (closed port or connection reset)
    pub fn record_rst(&mut self, flow_key: FlowKey) {
        self.last_seen = Instant::now();
        if let Some(conn) = self.connections.get_mut(&flow_key) {
            conn.state = ConnectionState::Reset;
        }
    }

    /// Check if a flow exists (for rule lookups)
    pub fn get_connection(&self, flow_key: &FlowKey) -> Option<&PortConnection> {
        self.connections.get(flow_key)
    }

    /// Check if flow is completed
    pub fn is_flow_completed(&self, flow_key: &FlowKey) -> bool {
        self.completed_flows.contains(flow_key)
    }

    /// Apply a score delta
    pub fn apply_score(&mut self, rule_id: &str, delta: f32, evidence: &str) {
        self.score += delta;

        // Keep history bounded
        if self.score_history.len() >= 100 {
            self.score_history.pop_front();
        }

        self.score_history.push_back(ScoreEntry {
            timestamp: Instant::now(),
            rule_id: rule_id.to_string(),
            delta,
            total: self.score,
            evidence: evidence.to_string(),
        });
    }

    /// Update classification based on thresholds
    pub fn update_classification(&mut self, thresholds: &super::config::ScoreThresholds) {
        self.classification = if self.score >= thresholds.confirmed_scan {
            Classification::ConfirmedScan
        } else if self.score >= thresholds.likely_attack {
            Classification::LikelyAttack
        } else if self.score >= thresholds.probable_scan {
            Classification::ProbableScan
        } else if self.score >= thresholds.suspicious {
            Classification::Suspicious
        } else {
            Classification::Normal
        };
    }

    /// Clean up expired half-open connections
    pub fn cleanup_expired(&mut self, timeout: Duration) {
        let expired: Vec<FlowKey> = self
            .connections
            .iter()
            .filter(|(_, conn)| conn.is_expired(timeout))
            .map(|(flow_key, _)| *flow_key)
            .collect();

        for flow_key in expired {
            if let Some(conn) = self.connections.get_mut(&flow_key) {
                conn.state = ConnectionState::Expired;
            }
            self.expired_half_opens.insert(flow_key);
        }

        // Clean up old SYN timestamps
        let cutoff = Instant::now() - timeout;
        while let Some(ts) = self.syn_timestamps.front() {
            if *ts < cutoff {
                self.syn_timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    /// Count currently half-open connections
    pub fn half_open_count(&self) -> usize {
        self.connections
            .values()
            .filter(|c| c.state == ConnectionState::HalfOpen)
            .count()
    }

    /// Count completed handshakes
    pub fn completed_count(&self) -> usize {
        self.completed_flows.len()
    }

    /// Count expired half-opens (never completed)
    pub fn expired_count(&self) -> usize {
        self.expired_half_opens.len()
    }

    /// Get unique destination ports touched
    pub fn unique_ports(&self) -> &HashSet<u16> {
        &self.touched_ports
    }

    /// Calculate SYN rate (SYNs per second in recent window)
    pub fn syn_rate(&self, window: Duration) -> f32 {
        let cutoff = Instant::now() - window;
        let count = self
            .syn_timestamps
            .iter()
            .filter(|ts| **ts >= cutoff)
            .count();
        count as f32 / window.as_secs_f32()
    }

    /// Check for sequential port scanning pattern
    pub fn has_sequential_pattern(&self, min_sequence: usize) -> bool {
        if self.port_sequence.len() < min_sequence {
            return false;
        }

        // Check last N ports for sequential pattern
        let recent: Vec<u16> = self
            .port_sequence
            .iter()
            .rev()
            .take(min_sequence)
            .copied()
            .collect();

        // Check if ports are sequential (N, N+1, N+2, ...)
        let mut sorted = recent.clone();
        sorted.sort();

        for i in 1..sorted.len() {
            if sorted[i] != sorted[i - 1] + 1 {
                return false;
            }
        }

        true
    }

    /// Add a tag
    pub fn add_tag(&mut self, tag: &str) {
        self.tags.insert(tag.to_string());
    }

    /// Check if has tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }

    /// Get duration since first seen
    pub fn duration(&self) -> Duration {
        self.first_seen.elapsed()
    }

    /// Check if window has expired (should reset tracking)
    pub fn is_window_expired(&self, window: Duration) -> bool {
        self.last_seen.elapsed() > window
    }

    /// Reset for new window
    pub fn reset(&mut self) {
        self.connections.clear();
        self.expired_half_opens.clear();
        self.completed_flows.clear();
        self.touched_ports.clear();
        self.score = 0.0;
        self.score_history.clear();
        self.classification = Classification::Normal;
        self.first_seen = Instant::now();
        self.last_seen = Instant::now();
        self.syn_timestamps.clear();
        self.port_sequence.clear();
        self.tags.clear();
        // Keep verification state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_flow_key(src_port: u16, dst_ip: IpAddr, dst_port: u16) -> FlowKey {
        FlowKey::new(src_port, dst_ip, dst_port)
    }

    #[test]
    fn test_source_behavior_new() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let behavior = SourceBehavior::new(ip);

        assert_eq!(behavior.src_ip, ip);
        assert_eq!(behavior.score, 0.0);
        assert_eq!(behavior.classification, Classification::Normal);
        assert_eq!(behavior.half_open_count(), 0);
    }

    #[test]
    fn test_record_syn() {
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut behavior = SourceBehavior::new(src_ip);

        behavior.record_syn(make_flow_key(50000, dst_ip, 22));
        behavior.record_syn(make_flow_key(50001, dst_ip, 80));
        behavior.record_syn(make_flow_key(50002, dst_ip, 443));

        assert_eq!(behavior.half_open_count(), 3);
        assert_eq!(behavior.unique_ports().len(), 3);
    }

    #[test]
    fn test_record_established() {
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut behavior = SourceBehavior::new(src_ip);

        let flow_80 = make_flow_key(50000, dst_ip, 80);
        let flow_443 = make_flow_key(50001, dst_ip, 443);

        behavior.record_syn(flow_80);
        behavior.record_syn(flow_443);
        behavior.record_established(flow_80);

        assert_eq!(behavior.half_open_count(), 1);
        assert_eq!(behavior.completed_count(), 1);
        assert!(behavior.completed_flows.contains(&flow_80));
    }

    #[test]
    fn test_apply_score() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let mut behavior = SourceBehavior::new(ip);

        behavior.apply_score("R1", 1.0, "Half-open SYN");
        behavior.apply_score("R2", 0.5, "Targeted port");
        behavior.apply_score("R10", -2.0, "Completed handshake");

        assert_eq!(behavior.score, -0.5);
        assert_eq!(behavior.score_history.len(), 3);
    }

    #[test]
    fn test_sequential_pattern() {
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut behavior = SourceBehavior::new(src_ip);

        // Sequential: 80, 81, 82, 83, 84
        for port in 80..=84 {
            behavior.record_syn(make_flow_key(50000 + port, dst_ip, port));
        }

        assert!(behavior.has_sequential_pattern(5));
        assert!(behavior.has_sequential_pattern(3));
        assert!(!behavior.has_sequential_pattern(6));
    }

    #[test]
    fn test_classification() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let mut behavior = SourceBehavior::new(ip);
        let thresholds = super::super::config::ScoreThresholds::default();

        behavior.score = 2.0;
        behavior.update_classification(&thresholds);
        assert_eq!(behavior.classification, Classification::Normal);

        behavior.score = 4.0;
        behavior.update_classification(&thresholds);
        assert_eq!(behavior.classification, Classification::Suspicious);

        behavior.score = 6.0;
        behavior.update_classification(&thresholds);
        assert_eq!(behavior.classification, Classification::ProbableScan);

        behavior.score = 10.0;
        behavior.update_classification(&thresholds);
        assert_eq!(behavior.classification, Classification::LikelyAttack);

        behavior.score = 15.0;
        behavior.update_classification(&thresholds);
        assert_eq!(behavior.classification, Classification::ConfirmedScan);
    }
}
