//! SYN Flood Detection
//!
//! Detects SYN flood attacks through volume-based analysis:
//! - Absolute SYN rate thresholds (>1000/sec = critical)
//! - Half-open connection saturation
//! - Single-port concentration attacks
//! - Sustained high-rate detection
//! - Spoofed source detection (TTL uniformity, port entropy)
//!
//! Unlike port scan detection (behavioral), this focuses on throughput metrics.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::core::Packet;

/// SYN flood detector configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynFloodConfig {
    /// Enable SYN flood detection
    pub enabled: bool,
    /// Critical SYN rate threshold (per source IP, per second)
    pub critical_rate_per_sec: u32,
    /// High SYN rate threshold (per source IP, per second)
    pub high_rate_per_sec: u32,
    /// Maximum half-open connections per source IP
    pub max_half_open_per_ip: usize,
    /// Global half-open connection limit
    pub max_half_open_global: usize,
    /// Seconds of sustained high rate before alert
    pub sustained_threshold_secs: u64,
    /// Time window for rate calculation (seconds)
    pub rate_window_secs: u64,
    /// Cleanup interval for stale entries (seconds)
    pub cleanup_interval_secs: u64,
    /// Single-port concentration threshold (rate to single port)
    pub single_port_rate_threshold: u32,
    /// Source port entropy threshold (0.0 = sequential, 1.0 = random)
    /// Low entropy suggests spoofed sources
    pub port_entropy_threshold: f32,
    /// TTL uniformity threshold (fraction of packets with same TTL)
    /// High uniformity suggests spoofed sources
    pub ttl_uniformity_threshold: f32,
}

impl Default for SynFloodConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            critical_rate_per_sec: 1000,
            high_rate_per_sec: 100,
            max_half_open_per_ip: 10_000,
            max_half_open_global: 100_000,
            sustained_threshold_secs: 5,
            rate_window_secs: 10,
            cleanup_interval_secs: 60,
            single_port_rate_threshold: 100,
            port_entropy_threshold: 0.3,
            ttl_uniformity_threshold: 0.95,
        }
    }
}

/// Flood attack type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FloodType {
    /// Standard SYN flood from single source
    SynFlood,
    /// High-rate attack targeting single port
    SinglePortFlood,
    /// Sustained attack over extended period
    SustainedFlood,
    /// Likely spoofed source IPs (uniform TTL, sequential ports)
    SpoofedFlood,
    /// Multiple sources attacking same target
    DistributedFlood,
    /// Half-open connection exhaustion
    HalfOpenSaturation,
}

/// Flood alert severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FloodSeverity {
    /// Elevated traffic, monitor closely
    Warning,
    /// High traffic, possible attack
    High,
    /// Critical attack in progress
    Critical,
}

/// Alert generated when flood is detected
#[derive(Debug, Clone)]
pub struct SynFloodAlert {
    /// Type of flood attack
    pub flood_type: FloodType,
    /// Severity level
    pub severity: FloodSeverity,
    /// Source IP address
    pub source_ip: IpAddr,
    /// Target port (if single-port attack)
    pub target_port: Option<u16>,
    /// Current SYN packets per second
    pub packets_per_sec: u32,
    /// Duration of sustained attack (seconds)
    pub duration_secs: u64,
    /// Current half-open connection count
    pub half_open_count: usize,
    /// Unique destination ports targeted
    pub unique_ports: usize,
    /// Detection confidence (0.0-1.0)
    pub confidence: f32,
    /// Human-readable description
    pub description: String,
    /// Timestamp of alert
    pub timestamp: Instant,
}

/// Per-source IP flood metrics
#[derive(Debug, Clone)]
pub struct FloodMetrics {
    /// SYN packet timestamps in current window
    syn_timestamps: VecDeque<Instant>,
    /// Half-open connections (dst_port -> timestamp)
    half_open: HashMap<u16, Instant>,
    /// Target ports hit
    target_ports: HashSet<u16>,
    /// Source ports used (for entropy calculation)
    source_ports: Vec<u16>,
    /// TTL values seen (for uniformity check)
    ttl_values: Vec<u8>,
    /// First high-rate timestamp (for sustained detection)
    high_rate_start: Option<Instant>,
    /// Last activity timestamp
    last_seen: Instant,
    /// Alert cooldown (don't spam alerts)
    last_alert: Option<Instant>,
}

impl FloodMetrics {
    fn new() -> Self {
        Self {
            syn_timestamps: VecDeque::new(),
            half_open: HashMap::new(),
            target_ports: HashSet::new(),
            source_ports: Vec::new(),
            ttl_values: Vec::new(),
            high_rate_start: None,
            last_seen: Instant::now(),
            last_alert: None,
        }
    }

    /// Record a SYN packet
    fn record_syn(&mut self, src_port: u16, dst_port: u16, ttl: u8) {
        let now = Instant::now();
        self.syn_timestamps.push_back(now);
        self.target_ports.insert(dst_port);
        self.source_ports.push(src_port);
        self.ttl_values.push(ttl);
        self.last_seen = now;

        // Track half-open
        self.half_open.insert(dst_port, now);

        // Limit memory usage
        if self.source_ports.len() > 10_000 {
            self.source_ports.drain(0..5_000);
        }
        if self.ttl_values.len() > 10_000 {
            self.ttl_values.drain(0..5_000);
        }
    }

    /// Record SYN-ACK (connection completing)
    fn record_syn_ack(&mut self, dst_port: u16) {
        self.half_open.remove(&dst_port);
    }

    /// Record RST (connection reset)
    fn record_rst(&mut self, dst_port: u16) {
        self.half_open.remove(&dst_port);
    }

    /// Prune old entries outside the window
    fn prune(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;

        // Prune SYN timestamps
        while let Some(front) = self.syn_timestamps.front() {
            if *front < cutoff {
                self.syn_timestamps.pop_front();
            } else {
                break;
            }
        }

        // Prune stale half-open connections (5 second timeout)
        let half_open_cutoff = Instant::now() - Duration::from_secs(5);
        self.half_open.retain(|_, ts| *ts > half_open_cutoff);
    }

    /// Calculate SYN rate (packets per second) over the window
    fn syn_rate(&self, window: Duration) -> f64 {
        let cutoff = Instant::now() - window;
        let count = self.syn_timestamps.iter().filter(|ts| **ts > cutoff).count();
        count as f64 / window.as_secs_f64()
    }

    /// Get half-open connection count
    fn half_open_count(&self) -> usize {
        self.half_open.len()
    }

    /// Calculate source port entropy (0.0 = all same, 1.0 = all unique)
    fn source_port_entropy(&self) -> f32 {
        if self.source_ports.len() < 10 {
            return 1.0; // Not enough data, assume legitimate
        }

        let unique: HashSet<_> = self.source_ports.iter().collect();
        let uniqueness = unique.len() as f32 / self.source_ports.len() as f32;

        // Also check for sequential patterns
        let mut sequential_count = 0;
        for window in self.source_ports.windows(2) {
            if window[1] == window[0].wrapping_add(1) {
                sequential_count += 1;
            }
        }
        let sequential_ratio = sequential_count as f32 / (self.source_ports.len() - 1).max(1) as f32;

        // Low uniqueness or high sequential = low entropy
        uniqueness * (1.0 - sequential_ratio * 0.5)
    }

    /// Calculate TTL uniformity (fraction with most common TTL)
    fn ttl_uniformity(&self) -> f32 {
        if self.ttl_values.is_empty() {
            return 0.0;
        }

        let mut counts: HashMap<u8, usize> = HashMap::new();
        for &ttl in &self.ttl_values {
            *counts.entry(ttl).or_default() += 1;
        }

        let max_count = counts.values().max().copied().unwrap_or(0);
        max_count as f32 / self.ttl_values.len() as f32
    }

    /// Check if we should alert (cooldown)
    fn should_alert(&self) -> bool {
        match self.last_alert {
            None => true,
            Some(last) => last.elapsed() > Duration::from_secs(10),
        }
    }

    /// Mark that we alerted
    fn mark_alerted(&mut self) {
        self.last_alert = Some(Instant::now());
    }
}

/// SYN flood detector
pub struct SynFloodDetector {
    config: SynFloodConfig,
    /// Per-source IP metrics
    source_metrics: HashMap<IpAddr, FloodMetrics>,
    /// Per-target (dst_ip, dst_port) SYN counts for distributed detection
    target_counts: HashMap<(IpAddr, u16), VecDeque<Instant>>,
    /// Global half-open count
    global_half_open: usize,
    /// Last cleanup time
    last_cleanup: Instant,
}

impl SynFloodDetector {
    /// Create a new SYN flood detector
    pub fn new(config: SynFloodConfig) -> Self {
        Self {
            config,
            source_metrics: HashMap::new(),
            target_counts: HashMap::new(),
            global_half_open: 0,
            last_cleanup: Instant::now(),
        }
    }

    /// Process a packet and check for SYN flood
    pub fn process(&mut self, packet: &Packet) -> Option<SynFloodAlert> {
        if !self.config.enabled {
            return None;
        }

        // Only process TCP packets
        let flags = packet.tcp_flags()?;

        let src_ip = packet.src_ip();
        let dst_ip = packet.dst_ip();
        let src_port = packet.src_port();
        let dst_port = packet.dst_port();
        let ttl = packet.ttl();

        // Periodic cleanup
        if self.last_cleanup.elapsed() > Duration::from_secs(self.config.cleanup_interval_secs) {
            self.cleanup();
        }

        // Get or create metrics for this source
        let metrics = self.source_metrics
            .entry(src_ip)
            .or_insert_with(FloodMetrics::new);

        // Process based on TCP flags
        let is_syn = flags.syn && !flags.ack;
        let is_syn_ack = flags.syn && flags.ack;
        let is_rst = flags.rst;

        if is_syn {
            metrics.record_syn(src_port, dst_port, ttl);

            // Track target for distributed detection
            let target_key = (dst_ip, dst_port);
            let target_queue = self.target_counts.entry(target_key).or_default();
            target_queue.push_back(Instant::now());

            // Update global half-open
            self.global_half_open = self.source_metrics
                .values()
                .map(|m| m.half_open_count())
                .sum();

            // Check for flood conditions
            return self.check_flood(src_ip, dst_ip, dst_port);
        } else if is_syn_ack {
            metrics.record_syn_ack(dst_port);
        } else if is_rst {
            metrics.record_rst(dst_port);
        }

        None
    }

    /// Check for flood conditions and generate alert
    fn check_flood(&mut self, src_ip: IpAddr, _dst_ip: IpAddr, dst_port: u16) -> Option<SynFloodAlert> {
        // First pass: extract data from metrics with mutable borrow
        let (rate_per_sec, half_open, unique_ports, port_entropy, ttl_uniformity, sustained_secs, should_alert) = {
            let metrics = self.source_metrics.get_mut(&src_ip)?;

            // Prune old data
            let window = Duration::from_secs(self.config.rate_window_secs);
            metrics.prune(window);

            // Calculate current rate
            let rate = metrics.syn_rate(Duration::from_secs(1));
            let rate_per_sec = rate as u32;

            // Skip if rate is low
            if rate_per_sec < self.config.high_rate_per_sec {
                metrics.high_rate_start = None;
                return None;
            }

            // Check alert cooldown
            if !metrics.should_alert() {
                return None;
            }

            // Track sustained high rate
            let sustained_secs = match metrics.high_rate_start {
                None => {
                    metrics.high_rate_start = Some(Instant::now());
                    0
                }
                Some(start) => start.elapsed().as_secs(),
            };

            let half_open = metrics.half_open_count();
            let unique_ports = metrics.target_ports.len();
            let port_entropy = metrics.source_port_entropy();
            let ttl_uniformity = metrics.ttl_uniformity();

            (rate_per_sec, half_open, unique_ports, port_entropy, ttl_uniformity, sustained_secs, true)
        };

        if !should_alert {
            return None;
        }

        // Second pass: classify (only needs &self.config, not metrics)
        let (flood_type, severity, confidence, description) = self.classify_flood(
            rate_per_sec,
            half_open,
            unique_ports,
            sustained_secs,
            port_entropy,
            ttl_uniformity,
            dst_port,
        );

        // Third pass: mark alerted
        if let Some(metrics) = self.source_metrics.get_mut(&src_ip) {
            metrics.mark_alerted();
        }

        Some(SynFloodAlert {
            flood_type,
            severity,
            source_ip: src_ip,
            target_port: if unique_ports == 1 { Some(dst_port) } else { None },
            packets_per_sec: rate_per_sec,
            duration_secs: sustained_secs,
            half_open_count: half_open,
            unique_ports,
            confidence,
            description,
            timestamp: Instant::now(),
        })
    }

    /// Classify the flood type and severity
    fn classify_flood(
        &self,
        rate: u32,
        half_open: usize,
        unique_ports: usize,
        sustained_secs: u64,
        port_entropy: f32,
        ttl_uniformity: f32,
        dst_port: u16,
    ) -> (FloodType, FloodSeverity, f32, String) {
        let mut confidence = 0.0f32;
        let mut reasons = Vec::new();

        // Check for spoofed source indicators
        let likely_spoofed = port_entropy < self.config.port_entropy_threshold
            && ttl_uniformity > self.config.ttl_uniformity_threshold;

        // Critical rate
        if rate >= self.config.critical_rate_per_sec {
            confidence += 0.4;
            reasons.push(format!("critical rate {}pps", rate));
        } else if rate >= self.config.high_rate_per_sec {
            confidence += 0.2;
            reasons.push(format!("high rate {}pps", rate));
        }

        // Half-open saturation
        if half_open >= self.config.max_half_open_per_ip {
            confidence += 0.3;
            reasons.push(format!("{} half-open connections", half_open));
        } else if half_open >= self.config.max_half_open_per_ip / 2 {
            confidence += 0.15;
            reasons.push(format!("{} half-open connections", half_open));
        }

        // Sustained attack
        if sustained_secs >= self.config.sustained_threshold_secs {
            confidence += 0.2;
            reasons.push(format!("sustained {}s", sustained_secs));
        }

        // Single port concentration
        let single_port = unique_ports == 1 && rate >= self.config.single_port_rate_threshold;
        if single_port {
            confidence += 0.2;
            reasons.push(format!("single port {}", dst_port));
        }

        // Spoofing indicators
        if likely_spoofed {
            confidence += 0.1;
            reasons.push("likely spoofed source".to_string());
        }

        confidence = confidence.min(1.0);

        // Determine flood type
        let flood_type = if likely_spoofed {
            FloodType::SpoofedFlood
        } else if half_open >= self.config.max_half_open_per_ip {
            FloodType::HalfOpenSaturation
        } else if sustained_secs >= self.config.sustained_threshold_secs * 2 {
            FloodType::SustainedFlood
        } else if single_port {
            FloodType::SinglePortFlood
        } else {
            FloodType::SynFlood
        };

        // Determine severity
        let severity = if rate >= self.config.critical_rate_per_sec
            || half_open >= self.config.max_half_open_per_ip
        {
            FloodSeverity::Critical
        } else if sustained_secs >= self.config.sustained_threshold_secs
            || rate >= self.config.high_rate_per_sec * 5
        {
            FloodSeverity::High
        } else {
            FloodSeverity::Warning
        };

        let description = format!("SYN flood: {}", reasons.join(", "));

        (flood_type, severity, confidence, description)
    }

    /// Cleanup stale entries
    fn cleanup(&mut self) {
        let cutoff = Instant::now() - Duration::from_secs(self.config.rate_window_secs * 2);

        // Remove inactive sources
        self.source_metrics.retain(|_, metrics| {
            metrics.last_seen > cutoff
        });

        // Prune target counts
        for queue in self.target_counts.values_mut() {
            while let Some(front) = queue.front() {
                if *front < cutoff {
                    queue.pop_front();
                } else {
                    break;
                }
            }
        }
        self.target_counts.retain(|_, queue| !queue.is_empty());

        self.last_cleanup = Instant::now();
    }

    /// Get global half-open connection count
    pub fn global_half_open(&self) -> usize {
        self.global_half_open
    }

    /// Get metrics for a specific source IP
    pub fn get_source_metrics(&self, ip: &IpAddr) -> Option<&FloodMetrics> {
        self.source_metrics.get(ip)
    }

    /// Get number of tracked sources
    pub fn tracked_sources(&self) -> usize {
        self.source_metrics.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use crate::core::{IpProtocol, TcpFlags};

    fn make_syn_packet(src_ip: Ipv4Addr, dst_port: u16, src_port: u16) -> Packet {
        let mut pkt = Packet::new(
            0,
            IpAddr::V4(src_ip),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpProtocol::Tcp,
            "lo",
        );
        if let Some(tcp) = pkt.tcp_mut() {
            tcp.src_port = src_port;
            tcp.dst_port = dst_port;
            tcp.flags = TcpFlags { syn: true, ..Default::default() };
        }
        pkt
    }

    #[test]
    fn test_flood_detector_new() {
        let detector = SynFloodDetector::new(SynFloodConfig::default());
        assert_eq!(detector.tracked_sources(), 0);
        assert_eq!(detector.global_half_open(), 0);
    }

    #[test]
    fn test_low_rate_no_alert() {
        let mut detector = SynFloodDetector::new(SynFloodConfig::default());
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);

        // Send a few SYN packets (below threshold)
        for i in 0..10 {
            let pkt = make_syn_packet(src_ip, 80, 50000 + i);
            let alert = detector.process(&pkt);
            assert!(alert.is_none(), "Should not alert on low rate");
        }
    }

    #[test]
    fn test_high_rate_alert() {
        let config = SynFloodConfig {
            high_rate_per_sec: 10, // Low threshold for testing
            critical_rate_per_sec: 50,
            ..Default::default()
        };
        let mut detector = SynFloodDetector::new(config);
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);

        // Send many SYN packets quickly
        let mut alert_generated = false;
        for i in 0..100 {
            let pkt = make_syn_packet(src_ip, 80, 50000 + i);
            if detector.process(&pkt).is_some() {
                alert_generated = true;
                break;
            }
        }

        assert!(alert_generated, "Should generate alert on high rate");
    }

    #[test]
    fn test_flood_metrics_entropy() {
        let mut metrics = FloodMetrics::new();

        // Sequential source ports = low entropy
        for i in 0..100 {
            metrics.record_syn(50000 + i, 80, 64);
        }

        let entropy = metrics.source_port_entropy();
        assert!(entropy <= 0.5, "Sequential ports should have low entropy: {}", entropy);
    }

    #[test]
    fn test_flood_metrics_ttl_uniformity() {
        let mut metrics = FloodMetrics::new();

        // All same TTL
        for _ in 0..100 {
            metrics.record_syn(50000, 80, 64);
        }

        let uniformity = metrics.ttl_uniformity();
        assert!(uniformity > 0.99, "Same TTL should have high uniformity: {}", uniformity);
    }

    #[test]
    fn test_half_open_tracking() {
        let mut metrics = FloodMetrics::new();

        // Record SYNs to different ports
        metrics.record_syn(50000, 80, 64);
        metrics.record_syn(50001, 443, 64);
        metrics.record_syn(50002, 22, 64);

        assert_eq!(metrics.half_open_count(), 3);

        // SYN-ACK completes one
        metrics.record_syn_ack(80);
        assert_eq!(metrics.half_open_count(), 2);

        // RST closes another
        metrics.record_rst(443);
        assert_eq!(metrics.half_open_count(), 1);
    }

    #[test]
    fn test_flood_type_classification() {
        let detector = SynFloodDetector::new(SynFloodConfig::default());

        // Critical rate = SynFlood + Critical severity
        let (flood_type, severity, _, _) = detector.classify_flood(
            2000, 100, 50, 3, 0.8, 0.5, 80,
        );
        assert_eq!(severity, FloodSeverity::Critical);
        assert_eq!(flood_type, FloodType::SynFlood);

        // Single port concentration
        let (flood_type, _, _, _) = detector.classify_flood(
            200, 100, 1, 3, 0.8, 0.5, 80,
        );
        assert_eq!(flood_type, FloodType::SinglePortFlood);

        // Spoofed (low entropy, high TTL uniformity)
        let (flood_type, _, _, _) = detector.classify_flood(
            500, 100, 10, 3, 0.1, 0.99, 80,
        );
        assert_eq!(flood_type, FloodType::SpoofedFlood);

        // Half-open saturation
        let (flood_type, _, _, _) = detector.classify_flood(
            500, 15000, 10, 3, 0.8, 0.5, 80,
        );
        assert_eq!(flood_type, FloodType::HalfOpenSaturation);
    }
}
