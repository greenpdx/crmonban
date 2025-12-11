//! Scan detection engine - main orchestrator

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use crate::core::packet::Packet;
use super::behavior::{Classification, FlowKey, SourceBehavior};
use super::config::ScanDetectConfig;
use super::rules::{EvaluationContext, RuleRegistry};

/// Type of scan alert
#[derive(Debug, Clone)]
pub enum AlertType {
    /// Score exceeded suspicious threshold
    Suspicious {
        score: f32,
    },
    /// Score exceeded probable_scan threshold
    ProbableScan {
        score: f32,
        half_open_ports: Vec<u16>,
        completed_ports: Vec<u16>,
    },
    /// Score exceeded likely_attack threshold
    LikelyAttack {
        score: f32,
        recommendation: String,
    },
    /// Score exceeded confirmed_scan threshold
    ConfirmedScan {
        score: f32,
        action: String,
    },
    /// Verified attack via active probe
    VerifiedAttack {
        score: f32,
        verification_method: String,
    },
    /// Network issue detected
    NetworkIssue {
        affected_sources: usize,
        details: String,
    },
}

/// Scan detection alert
#[derive(Debug, Clone)]
pub struct ScanAlert {
    /// Source IP
    pub src_ip: IpAddr,
    /// Alert type
    pub alert_type: AlertType,
    /// Classification
    pub classification: Classification,
    /// Unique ports touched
    pub unique_ports: usize,
    /// Top contributing rules
    pub top_rules: Vec<(String, f32)>,
    /// Tags
    pub tags: Vec<String>,
    /// Timestamp
    pub timestamp: Instant,
}

impl ScanAlert {
    /// Get severity (0-10)
    pub fn severity(&self) -> u8 {
        self.classification.severity()
    }

    /// Should this alert trigger a ban?
    pub fn should_ban(&self) -> bool {
        self.classification.should_ban()
    }
}

/// Network health status
#[derive(Debug, Clone)]
pub struct NetworkHealth {
    /// Total sources being tracked
    pub total_sources: usize,
    /// Sources with half-open connections
    pub sources_with_half_open: usize,
    /// Sources with completed connections
    pub sources_with_completed: usize,
    /// Global half-open ratio
    pub half_open_ratio: f32,
    /// Is network health suspect?
    pub is_suspect: bool,
    /// Last check time
    pub last_check: Instant,
}

impl Default for NetworkHealth {
    fn default() -> Self {
        Self {
            total_sources: 0,
            sources_with_half_open: 0,
            sources_with_completed: 0,
            half_open_ratio: 0.0,
            is_suspect: false,
            last_check: Instant::now(),
        }
    }
}

/// Main scan detection engine
pub struct ScanDetectEngine {
    /// Configuration
    config: ScanDetectConfig,
    /// Per-IP behavior tracking
    behaviors: HashMap<IpAddr, SourceBehavior>,
    /// Rule registry
    rules: RuleRegistry,
    /// Network health status
    network_health: NetworkHealth,
    /// Last cleanup time
    last_cleanup: Instant,
    /// Total alerts generated
    total_alerts: u64,
    /// Pending alerts to emit
    #[allow(dead_code)]
    pending_alerts: Vec<ScanAlert>,
}

impl ScanDetectEngine {
    /// Create a new scan detection engine
    pub fn new(config: ScanDetectConfig) -> Self {
        info!(
            "Initializing probabilistic scan detection (window={}s, thresholds: suspicious={}, probable={}, likely={}, confirmed={})",
            config.window_secs,
            config.thresholds.suspicious,
            config.thresholds.probable_scan,
            config.thresholds.likely_attack,
            config.thresholds.confirmed_scan,
        );

        Self {
            config,
            behaviors: HashMap::new(),
            rules: RuleRegistry::with_builtins(),
            network_health: NetworkHealth::default(),
            last_cleanup: Instant::now(),
            total_alerts: 0,
            pending_alerts: Vec::new(),
        }
    }

    /// Process a packet for scan detection
    ///
    /// This is the main entry point - extracts all needed info from the Packet.
    /// Only processes TCP packets; returns None for non-TCP.
    pub fn process(&mut self, packet: &Packet) -> Option<ScanAlert> {
        // Only process TCP packets for scan detection
        let flags = packet.tcp_flags()?;

        let is_syn = flags.syn && !flags.ack;
        let is_syn_ack = flags.syn && flags.ack;
        let is_ack = flags.ack && !flags.syn;
        let is_rst = flags.rst;
        let is_fin = flags.fin;
        let is_psh = flags.psh;
        let is_urg = flags.urg;

        self.process_internal(
            packet.src_ip(),
            packet.src_port(),
            packet.dst_ip(),
            packet.dst_port(),
            is_syn,
            is_syn_ack,
            is_ack,
            is_rst,
            is_fin,
            is_psh,
            is_urg,
            packet.payload().len(),
            Some(packet.ttl()),
        )
    }

    /// Internal implementation with all TCP flags for stealth scan detection
    fn process_internal(
        &mut self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        is_syn: bool,
        is_syn_ack: bool,
        is_ack: bool,
        is_rst: bool,
        is_fin: bool,
        is_psh: bool,
        is_urg: bool,
        payload_size: usize,
        ttl: Option<u8>,
    ) -> Option<ScanAlert> {
        if !self.config.enabled {
            return None;
        }

        // Create flow key for this connection
        let flow_key = FlowKey::new(src_port, dst_ip, dst_port);

        // Get or create behavior tracker for this IP
        let behavior = self.behaviors.entry(src_ip).or_insert_with(|| {
            debug!("New source tracked: {}", src_ip);
            SourceBehavior::new(src_ip)
        });

        // Check if window expired
        if behavior.is_window_expired(self.config.window_duration()) {
            behavior.reset();
        }

        // Detect stealth scan types
        let is_null = !is_syn && !is_ack && !is_fin && !is_rst && !is_psh && !is_urg;
        let is_fin_only = !is_syn && !is_ack && is_fin && !is_rst && !is_psh && !is_urg;
        let is_xmas = !is_syn && !is_ack && is_fin && !is_rst && is_psh && is_urg;
        let is_maimon = !is_syn && is_ack && is_fin && !is_rst && !is_psh && !is_urg;
        let is_ack_only = !is_syn && is_ack && !is_fin && !is_rst && !is_psh && !is_urg;

        // Record stealth scan types
        if is_null {
            behavior.record_stealth_scan("null");
        } else if is_xmas {
            behavior.record_stealth_scan("xmas");
        } else if is_fin_only {
            behavior.record_stealth_scan("fin");
        } else if is_maimon {
            behavior.record_stealth_scan("maimon");
        } else if is_ack_only && behavior.get_connection(&flow_key).is_none() {
            // ACK without prior connection for this flow
            behavior.record_stealth_scan("ack_only");
        }

        // Update behavior based on packet type using full flow key
        if is_syn {
            behavior.record_syn(flow_key);
        } else if is_ack && !is_syn_ack && !is_fin {
            behavior.record_established(flow_key);
            if payload_size > 0 {
                behavior.record_data(flow_key, payload_size as u64);
            }
        } else if is_rst {
            behavior.record_rst(flow_key);
        }

        // Cleanup expired half-opens
        behavior.cleanup_expired(self.config.syn_timeout());

        // Build evaluation context with full tuple info
        let ctx = EvaluationContext::new(src_ip, behavior, &self.config)
            .with_src_port(src_port)
            .with_dst_ip(dst_ip)
            .with_port(dst_port);

        let ctx = if is_syn { ctx.with_syn() } else { ctx };
        let ctx = if is_syn_ack { ctx.with_syn_ack() } else { ctx };
        let ctx = if is_ack { ctx.with_ack() } else { ctx };
        let ctx = if is_rst { ctx.with_rst() } else { ctx };
        let ctx = if is_fin { ctx.with_fin() } else { ctx };
        let ctx = if is_psh { ctx.with_psh() } else { ctx };
        let ctx = if is_urg { ctx.with_urg() } else { ctx };
        let ctx = ctx.with_payload(payload_size);
        let ctx = if let Some(t) = ttl { ctx.with_ttl(t) } else { ctx };

        // Evaluate all rules
        let results = self.rules.evaluate_all(&ctx);

        // Apply results to behavior
        {
            let behavior = self.behaviors.get_mut(&src_ip).unwrap();
            for result in &results {
                let adjusted_delta = result.score_delta * result.confidence;
                behavior.apply_score(&result.rule_id, adjusted_delta, &result.evidence);

                for tag in &result.tags {
                    behavior.add_tag(tag);
                }
            }

            // Update classification
            behavior.update_classification(&self.config.thresholds);
        }

        // Check if we should generate an alert (reborrow after block ends)
        let should_alert = self.behaviors.get(&src_ip)
            .map(|b| b.classification.should_alert())
            .unwrap_or(false);

        if should_alert {
            return self.generate_alert(src_ip);
        }

        // Periodic cleanup
        self.maybe_cleanup();

        None
    }

    /// Mark a connection as having a specific protocol detected
    pub fn mark_protocol(&mut self, src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port: u16, protocol: &str) {
        let flow_key = FlowKey::new(src_port, dst_ip, dst_port);
        if let Some(behavior) = self.behaviors.get_mut(&src_ip) {
            behavior.record_protocol(flow_key, protocol);
        }
    }

    /// Generate an alert for a source IP
    fn generate_alert(
        &mut self,
        src_ip: IpAddr,
    ) -> Option<ScanAlert> {
        // Extract all data from behavior first to avoid borrow conflicts
        let alert = {
            let behavior = self.behaviors.get(&src_ip)?;
            let classification = behavior.classification;
            let score = behavior.score;

            // Get top contributing rules from score history
            let mut rule_scores: HashMap<String, f32> = HashMap::new();
            for entry in behavior.score_history.iter() {
                *rule_scores.entry(entry.rule_id.clone()).or_insert(0.0) += entry.delta;
            }
            let mut top_rules: Vec<_> = rule_scores.into_iter().collect();
            top_rules.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
            top_rules.truncate(5);

            let alert_type = match classification {
                Classification::Suspicious => AlertType::Suspicious { score },
                Classification::ProbableScan => AlertType::ProbableScan {
                    score,
                    half_open_ports: behavior.connections
                        .iter()
                        .filter(|(_, c)| c.state == super::behavior::ConnectionState::HalfOpen)
                        .map(|(fk, _)| fk.dst_port)
                        .collect(),
                    completed_ports: behavior.completed_flows.iter().map(|fk| fk.dst_port).collect(),
                },
                Classification::LikelyAttack => AlertType::LikelyAttack {
                    score,
                    recommendation: "Consider banning source IP".to_string(),
                },
                Classification::ConfirmedScan => AlertType::ConfirmedScan {
                    score,
                    action: "Automatic ban recommended".to_string(),
                },
                _ => return None,
            };

            let unique_ports_count = behavior.unique_ports().len();
            let tags: Vec<String> = behavior.tags.iter().cloned().collect();

            info!(
                "Scan alert: {} (score={:.1}, ports={}, classification={:?})",
                src_ip, score, unique_ports_count, classification
            );

            ScanAlert {
                src_ip,
                alert_type,
                classification,
                unique_ports: unique_ports_count,
                top_rules,
                tags,
                timestamp: Instant::now(),
            }
        };

        self.total_alerts += 1;
        Some(alert)
    }

    /// Run periodic cleanup
    fn maybe_cleanup(&mut self) {
        let cleanup_interval = Duration::from_secs(self.config.cleanup_interval_secs);
        if self.last_cleanup.elapsed() < cleanup_interval {
            return;
        }

        self.last_cleanup = Instant::now();
        let window = self.config.window_duration();

        // Remove expired behaviors
        let before = self.behaviors.len();
        self.behaviors.retain(|_, b| !b.is_window_expired(window));
        let removed = before - self.behaviors.len();

        if removed > 0 {
            debug!("Cleaned up {} expired source behaviors", removed);
        }

        // Update network health
        self.update_network_health();
    }

    /// Update network health metrics
    fn update_network_health(&mut self) {
        let total = self.behaviors.len();
        let with_half_open = self.behaviors.values()
            .filter(|b| b.half_open_count() > 0)
            .count();
        let with_completed = self.behaviors.values()
            .filter(|b| b.completed_count() > 0)
            .count();

        let ratio = if total > 0 {
            with_half_open as f32 / total as f32
        } else {
            0.0
        };

        // Network is suspect if >80% of sources have only half-open connections
        let is_suspect = total > 10 && ratio > 0.8 && with_completed < total / 5;

        if is_suspect && !self.network_health.is_suspect {
            warn!(
                "Network health suspect: {}% of sources have half-open only ({}/{})",
                (ratio * 100.0) as u32, with_half_open, total
            );
        }

        self.network_health = NetworkHealth {
            total_sources: total,
            sources_with_half_open: with_half_open,
            sources_with_completed: with_completed,
            half_open_ratio: ratio,
            is_suspect,
            last_check: Instant::now(),
        };
    }

    /// Get behavior for an IP
    pub fn get_behavior(&self, ip: &IpAddr) -> Option<&SourceBehavior> {
        self.behaviors.get(ip)
    }

    /// Get network health status
    pub fn network_health(&self) -> &NetworkHealth {
        &self.network_health
    }

    /// Get total tracked sources
    pub fn tracked_sources(&self) -> usize {
        self.behaviors.len()
    }

    /// Get total alerts generated
    pub fn total_alerts(&self) -> u64 {
        self.total_alerts
    }

    /// Get top scanners by score
    pub fn top_scanners(&self, limit: usize) -> Vec<(IpAddr, f32, Classification)> {
        let mut scanners: Vec<_> = self.behaviors
            .iter()
            .map(|(ip, b)| (*ip, b.score, b.classification))
            .collect();
        scanners.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        scanners.truncate(limit);
        scanners
    }

    /// Clear all tracking data
    pub fn clear(&mut self) {
        self.behaviors.clear();
        self.total_alerts = 0;
        self.network_health = NetworkHealth::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use crate::core::packet::{IpProtocol, TcpFlags};

    /// Create a TCP SYN packet for testing
    fn make_syn_packet(src_ip: Ipv4Addr, dst_port: u16) -> Packet {
        let mut pkt = Packet::new(
            0,
            IpAddr::V4(src_ip),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpProtocol::Tcp,
            "lo",
        );
        if let Some(tcp) = pkt.tcp_mut() {
            tcp.src_port = 54321;
            tcp.dst_port = dst_port;
            tcp.flags = TcpFlags { syn: true, ..Default::default() };
        }
        pkt
    }

    /// Create a TCP ACK packet for testing
    fn make_ack_packet(src_ip: Ipv4Addr, dst_port: u16) -> Packet {
        let mut pkt = Packet::new(
            0,
            IpAddr::V4(src_ip),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpProtocol::Tcp,
            "lo",
        );
        if let Some(tcp) = pkt.tcp_mut() {
            tcp.src_port = 54321;
            tcp.dst_port = dst_port;
            tcp.flags = TcpFlags { ack: true, ..Default::default() };
        }
        pkt
    }

    #[test]
    fn test_engine_new() {
        let config = ScanDetectConfig::default();
        let engine = ScanDetectEngine::new(config);
        assert_eq!(engine.tracked_sources(), 0);
        assert_eq!(engine.total_alerts(), 0);
    }

    #[test]
    fn test_process_syn() {
        let config = ScanDetectConfig::default();
        let mut engine = ScanDetectEngine::new(config);

        let src_ip = Ipv4Addr::new(192, 168, 1, 100);

        // Process multiple SYNs to different ports
        for port in 1..=5 {
            let pkt = make_syn_packet(src_ip, port);
            engine.process(&pkt);
        }

        assert_eq!(engine.tracked_sources(), 1);

        let ip = IpAddr::V4(src_ip);
        let behavior = engine.get_behavior(&ip).unwrap();
        assert_eq!(behavior.half_open_count(), 5);
    }

    #[test]
    fn test_process_completed_handshake() {
        let config = ScanDetectConfig::default();
        let mut engine = ScanDetectEngine::new(config);

        let src_ip = Ipv4Addr::new(192, 168, 1, 100);

        // SYN
        let syn_pkt = make_syn_packet(src_ip, 80);
        engine.process(&syn_pkt);
        // ACK (handshake complete)
        let ack_pkt = make_ack_packet(src_ip, 80);
        engine.process(&ack_pkt);

        let ip = IpAddr::V4(src_ip);
        let behavior = engine.get_behavior(&ip).unwrap();
        // Score should be reduced due to completed handshake
        assert!(behavior.score < 0.0 || behavior.completed_count() > 0);
    }

    #[test]
    fn test_scan_detection() {
        let mut config = ScanDetectConfig::default();
        config.thresholds.probable_scan = 3.0; // Lower threshold for testing

        let mut engine = ScanDetectEngine::new(config);

        let src_ip = Ipv4Addr::new(10, 0, 0, 1);

        // Process many SYNs to targeted ports without completing handshakes
        for port in [22, 23, 80, 443, 3389] {
            let pkt = make_syn_packet(src_ip, port);
            engine.process(&pkt);
        }

        let ip = IpAddr::V4(src_ip);
        let behavior = engine.get_behavior(&ip).unwrap();
        assert!(behavior.score > 0.0);
        // Should be classified as at least suspicious
        assert!(behavior.classification != Classification::Normal);
    }

    #[test]
    fn test_network_health() {
        let config = ScanDetectConfig::default();
        let mut engine = ScanDetectEngine::new(config);

        // Simulate many sources with half-open connections
        for i in 0..20 {
            let src_ip = Ipv4Addr::new(192, 168, 1, i as u8);
            let pkt = make_syn_packet(src_ip, 80);
            engine.process(&pkt);
        }

        engine.update_network_health();

        let health = engine.network_health();
        assert_eq!(health.total_sources, 20);
        assert_eq!(health.sources_with_half_open, 20);
    }
}
