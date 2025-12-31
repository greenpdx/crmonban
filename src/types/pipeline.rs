//! Pipeline processing types
//!
//! Contains the StageProcessor trait for detection stages and
//! the AlertAnalyzer for deciding block/continue actions.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::analysis::{PacketAnalysis, PacketVerdict};
use super::event::{DetectionAction, Severity};

/// Trait for pipeline stage processors
///
/// Each detection stage implements this trait with a uniform interface:
/// - Receives `PacketAnalysis` containing packet, flow, events, and control flags
/// - Returns the modified `PacketAnalysis` for the next stage
///
/// This enables a clean functional pipeline: stage1 -> stage2 -> ... -> stageN
///
/// Type parameters:
/// - `Config`: Configuration type (typically `PipelineConfig` from crmonban)
/// - `Stage`: Pipeline stage enum type (typically `PipelineStage` from crmonban)
pub trait StageProcessor<Config, Stage> {
    /// Process the packet analysis through this stage
    ///
    /// The stage may:
    /// - Add detection events via `analysis.add_event()`
    /// - Update flow state via `analysis.flow_mut()`
    /// - Set control flags (stop_processing, suppress_events)
    /// - Mark the packet as suspicious
    async fn process(&mut self, analysis: PacketAnalysis, config: &Config) -> PacketAnalysis;

    /// Get the pipeline stage type this processor handles
    async fn stage(&self) -> Stage;
}

/// Decision from alert analyzer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalyzerDecision {
    /// RemoveFlow: confirmed threat
    /// - Alert already created inside analyzer
    /// - Caller removes packet from flow tracking
    /// - Caller stops further stage processing
    RemoveFlow,

    /// Continue: need more analysis or no action needed
    /// - Caller continues to next detection stage
    Continue,
}

/// Blocking policy for a severity level
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockPolicy {
    /// Alert only, never block packets of this severity
    AlertOnly,
    /// Block after N events from same source within window
    BlockAfterThreshold {
        /// Number of events before blocking
        count: u32,
        /// Time window in seconds
        window_secs: u64,
    },
    /// Block immediately on first detection
    BlockImmediately,
}

impl Default for BlockPolicy {
    fn default() -> Self {
        BlockPolicy::AlertOnly
    }
}

/// Per-severity blocking policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityPolicy {
    /// Policy for Info severity events
    pub info: BlockPolicy,
    /// Policy for Low severity events
    pub low: BlockPolicy,
    /// Policy for Medium severity events
    pub medium: BlockPolicy,
    /// Policy for High severity events
    pub high: BlockPolicy,
    /// Policy for Critical severity events
    pub critical: BlockPolicy,
}

impl Default for SeverityPolicy {
    fn default() -> Self {
        Self {
            info: BlockPolicy::AlertOnly,
            low: BlockPolicy::AlertOnly,
            medium: BlockPolicy::AlertOnly,
            high: BlockPolicy::BlockAfterThreshold {
                count: 5,
                window_secs: 60,
            },
            critical: BlockPolicy::BlockImmediately,
        }
    }
}

impl SeverityPolicy {
    /// Get the policy for a given severity level
    pub fn get(&self, severity: Severity) -> &BlockPolicy {
        match severity {
            Severity::Info => &self.info,
            Severity::Low => &self.low,
            Severity::Medium => &self.medium,
            Severity::High => &self.high,
            Severity::Critical => &self.critical,
        }
    }
}

/// Alert analyzer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertAnalyzerConfig {
    /// Enable alert analyzer
    pub enabled: bool,
    /// Severity-based blocking policy
    pub severity_policy: SeverityPolicy,
    /// Minimum confidence threshold to apply blocking (0.0-1.0)
    pub confidence_threshold: f32,
    /// Always generate alerts regardless of verdict (for visibility)
    pub always_alert: bool,
}

impl Default for AlertAnalyzerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            severity_policy: SeverityPolicy::default(),
            confidence_threshold: 0.5,
            always_alert: true,
        }
    }
}

/// Tracks event counts per source IP for threshold-based blocking
#[derive(Debug)]
struct ThresholdTracker {
    /// Events per source IP: (count, first_event_time)
    counts: HashMap<IpAddr, (u32, Instant)>,
}

impl ThresholdTracker {
    fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    /// Record an event and check if threshold is exceeded
    fn record_and_check(&mut self, src_ip: IpAddr, threshold: u32, window: Duration) -> bool {
        let now = Instant::now();

        let entry = self.counts.entry(src_ip).or_insert((0, now));

        // Check if window expired, reset if so
        if now.duration_since(entry.1) > window {
            *entry = (1, now);
            return false;
        }

        // Increment count
        entry.0 += 1;

        // Check threshold
        entry.0 >= threshold
    }

    /// Clean up expired entries (call periodically)
    fn cleanup(&mut self, max_window: Duration) {
        let now = Instant::now();
        self.counts.retain(|_, (_, first_seen)| {
            now.duration_since(*first_seen) <= max_window
        });
    }
}

/// Alert analyzer - analyzes PacketAnalysis with events and decides action
///
/// Called only when detection stages have added events to analysis.
/// Applies severity-based blocking policy to determine verdict.
pub struct AlertAnalyzer {
    config: AlertAnalyzerConfig,
    /// Threshold tracker for BlockAfterThreshold policy
    threshold_tracker: ThresholdTracker,
    /// Last cleanup time
    last_cleanup: Instant,
}

impl AlertAnalyzer {
    /// Create a new alert analyzer with the given configuration
    pub fn new(config: AlertAnalyzerConfig) -> Self {
        Self {
            config,
            threshold_tracker: ThresholdTracker::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Analyze packet with detection events and decide action
    ///
    /// Called only when detection stages have added events to analysis.
    /// Sets verdict on analysis based on severity policy.
    ///
    /// # Arguments
    /// * `analysis` - PacketAnalysis with DetectionEvents already filled in
    ///
    /// # Returns
    /// * `RemoveFlow` - Remove from flow, stop processing (blocked)
    /// * `Continue` - Continue to next stage (allowed)
    pub async fn analyze(&mut self, analysis: &mut PacketAnalysis) -> AnalyzerDecision {
        if !self.config.enabled || analysis.events.is_empty() {
            return AnalyzerDecision::Continue;
        }

        // Periodic cleanup (every 60 seconds)
        if self.last_cleanup.elapsed() > Duration::from_secs(60) {
            self.threshold_tracker.cleanup(Duration::from_secs(300));
            self.last_cleanup = Instant::now();
        }

        // Find highest severity and determine suggested verdict
        let mut highest_severity = Severity::Info;
        let mut suggested_verdict = PacketVerdict::Accept;
        let mut has_blocking_action = false;

        for event in &analysis.events {
            // Track highest severity
            if event.severity > highest_severity {
                highest_severity = event.severity;
            }

            // Check if event's action suggests blocking
            match event.action {
                DetectionAction::Drop => {
                    suggested_verdict = PacketVerdict::Drop;
                    has_blocking_action = true;
                }
                DetectionAction::Reject => {
                    suggested_verdict = PacketVerdict::Reject;
                    has_blocking_action = true;
                }
                DetectionAction::Ban => {
                    suggested_verdict = PacketVerdict::Drop;
                    has_blocking_action = true;
                }
                _ => {}
            }

            // Check confidence threshold
            if event.confidence < self.config.confidence_threshold {
                // Low confidence - don't let this event trigger blocking
                continue;
            }
        }

        // Set suggested verdict for logging/visibility
        analysis.set_suggested_verdict(suggested_verdict);

        // If no blocking action suggested, always accept
        if !has_blocking_action {
            analysis.set_verdict(PacketVerdict::Accept);
            return AnalyzerDecision::Continue;
        }

        // Get policy for highest severity
        let policy = self.config.severity_policy.get(highest_severity);

        // Apply policy to determine actual verdict
        let actual_verdict = match policy {
            BlockPolicy::AlertOnly => {
                // Alert only - never block
                PacketVerdict::Accept
            }
            BlockPolicy::BlockImmediately => {
                // Block immediately on first detection
                suggested_verdict
            }
            BlockPolicy::BlockAfterThreshold { count, window_secs } => {
                // Check if threshold exceeded
                let src_ip = analysis.packet.src_ip();
                let window = Duration::from_secs(*window_secs);

                if self.threshold_tracker.record_and_check(src_ip, *count, window) {
                    suggested_verdict
                } else {
                    PacketVerdict::Accept
                }
            }
        };

        // Set actual verdict
        analysis.set_verdict(actual_verdict);

        // Return decision based on verdict
        if actual_verdict.is_blocking() {
            AnalyzerDecision::RemoveFlow
        } else {
            AnalyzerDecision::Continue
        }
    }

    /// Check if the analyzer is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get configuration reference
    pub fn config(&self) -> &AlertAnalyzerConfig {
        &self.config
    }

    /// Get mutable configuration reference
    pub fn config_mut(&mut self) -> &mut AlertAnalyzerConfig {
        &mut self.config
    }

    /// Get statistics about tracked thresholds
    pub fn tracked_sources(&self) -> usize {
        self.threshold_tracker.counts.len()
    }
}

impl Default for AlertAnalyzer {
    fn default() -> Self {
        Self::new(AlertAnalyzerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::event::{DetectionEvent, DetectionType};
    use super::super::packet::{Packet, IpProtocol};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_test_packet() -> Packet {
        Packet::new(
            0,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpProtocol::Tcp,
            "lo",
        )
    }

    fn make_event(severity: Severity, action: DetectionAction) -> DetectionEvent {
        DetectionEvent::new(
            DetectionType::PortScan,
            severity,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "Test event".to_string(),
        ).with_action(action)
    }

    #[test]
    fn test_alert_analyzer_default() {
        let analyzer = AlertAnalyzer::default();
        assert!(analyzer.is_enabled());
    }

    #[test]
    fn test_severity_policy_default() {
        let policy = SeverityPolicy::default();
        assert!(matches!(policy.info, BlockPolicy::AlertOnly));
        assert!(matches!(policy.low, BlockPolicy::AlertOnly));
        assert!(matches!(policy.medium, BlockPolicy::AlertOnly));
        assert!(matches!(policy.high, BlockPolicy::BlockAfterThreshold { .. }));
        assert!(matches!(policy.critical, BlockPolicy::BlockImmediately));
    }

    #[tokio::test]
    async fn test_analyze_empty_events_returns_continue() {
        let mut analyzer = AlertAnalyzer::default();
        let packet = make_test_packet();
        let mut analysis = PacketAnalysis::new(packet);

        let decision = analyzer.analyze(&mut analysis).await;
        assert_eq!(decision, AnalyzerDecision::Continue);
        assert_eq!(analysis.verdict(), PacketVerdict::Accept);
    }

    #[tokio::test]
    async fn test_analyze_critical_blocks_immediately() {
        let mut analyzer = AlertAnalyzer::default();
        let packet = make_test_packet();
        let mut analysis = PacketAnalysis::new(packet);

        // Add critical event with Drop action
        analysis.add_event(make_event(Severity::Critical, DetectionAction::Drop));

        let decision = analyzer.analyze(&mut analysis).await;
        assert_eq!(decision, AnalyzerDecision::RemoveFlow);
        assert_eq!(analysis.verdict(), PacketVerdict::Drop);
        assert_eq!(analysis.suggested_verdict(), PacketVerdict::Drop);
    }

    #[tokio::test]
    async fn test_analyze_medium_alert_only() {
        let mut analyzer = AlertAnalyzer::default();
        let packet = make_test_packet();
        let mut analysis = PacketAnalysis::new(packet);

        // Add medium event with Drop action
        analysis.add_event(make_event(Severity::Medium, DetectionAction::Drop));

        let decision = analyzer.analyze(&mut analysis).await;
        // Medium severity = AlertOnly, so should continue
        assert_eq!(decision, AnalyzerDecision::Continue);
        assert_eq!(analysis.verdict(), PacketVerdict::Accept);
        // But suggested verdict should show what would have happened
        assert_eq!(analysis.suggested_verdict(), PacketVerdict::Drop);
        assert!(analysis.would_block());
    }

    #[tokio::test]
    async fn test_analyze_high_threshold() {
        let mut analyzer = AlertAnalyzer::default();

        // First 4 events should not block (threshold is 5)
        for i in 0..4 {
            let packet = make_test_packet();
            let mut analysis = PacketAnalysis::new(packet);
            analysis.add_event(make_event(Severity::High, DetectionAction::Drop));

            let decision = analyzer.analyze(&mut analysis).await;
            assert_eq!(decision, AnalyzerDecision::Continue, "Event {} should not block", i);
        }

        // 5th event should block
        let packet = make_test_packet();
        let mut analysis = PacketAnalysis::new(packet);
        analysis.add_event(make_event(Severity::High, DetectionAction::Drop));

        let decision = analyzer.analyze(&mut analysis).await;
        assert_eq!(decision, AnalyzerDecision::RemoveFlow);
        assert_eq!(analysis.verdict(), PacketVerdict::Drop);
    }

    #[tokio::test]
    async fn test_analyze_alert_action_no_block() {
        let mut analyzer = AlertAnalyzer::default();
        let packet = make_test_packet();
        let mut analysis = PacketAnalysis::new(packet);

        // Add critical event but with Alert action (not Drop)
        analysis.add_event(make_event(Severity::Critical, DetectionAction::Alert));

        let decision = analyzer.analyze(&mut analysis).await;
        // Alert action doesn't suggest blocking
        assert_eq!(decision, AnalyzerDecision::Continue);
        assert_eq!(analysis.verdict(), PacketVerdict::Accept);
    }
}
