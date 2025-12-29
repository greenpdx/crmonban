//! Pipeline processing types
//!
//! Contains the StageProcessor trait for detection stages and
//! the AlertAnalyzer for deciding block/continue actions.

use super::analysis::PacketAnalysis;

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

/// Alert analyzer configuration
#[derive(Debug, Clone)]
pub struct AlertAnalyzerConfig {
    /// Enable alert analyzer
    pub enabled: bool,
    // Additional configuration fields to be added when implementing real logic
}

impl Default for AlertAnalyzerConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Alert analyzer - analyzes PacketAnalysis with events and decides action
///
/// Called only when detection stages have added events to analysis.
/// Creates alerts internally if needed.
///
/// Implementation is a black box for now - details to be added later.
pub struct AlertAnalyzer {
    config: AlertAnalyzerConfig,
}

impl AlertAnalyzer {
    /// Create a new alert analyzer with the given configuration
    pub fn new(config: AlertAnalyzerConfig) -> Self {
        Self { config }
    }

    /// Analyze packet with detection events and decide action
    ///
    /// Called only when detection stages have added events to analysis.
    /// Creates alerts internally if needed.
    ///
    /// # Arguments
    /// * `analysis` - PacketAnalysis with DetectionEvents already filled in
    ///
    /// # Returns
    /// * `RemoveFlow` - Remove from flow, stop processing
    /// * `Continue` - Continue to next stage
    pub async fn analyze(&mut self, _analysis: &mut PacketAnalysis) -> AnalyzerDecision {
        // TODO: Black box - implementation details to be added later
        //
        // Future implementation will:
        // 1. Analyze detection events in analysis.events
        // 2. Decide if this is a confirmed threat (RemoveFlow) or needs more analysis (Continue)
        // 3. Create alerts internally when appropriate
        //
        // For now: always continue (no blocking)
        AnalyzerDecision::Continue
    }

    /// Check if the analyzer is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get configuration reference
    pub fn config(&self) -> &AlertAnalyzerConfig {
        &self.config
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

    #[test]
    fn test_alert_analyzer_default() {
        let analyzer = AlertAnalyzer::default();
        assert!(analyzer.is_enabled());
    }

    #[test]
    fn test_alert_analyzer_config() {
        let config = AlertAnalyzerConfig { enabled: false };
        let analyzer = AlertAnalyzer::new(config);
        assert!(!analyzer.is_enabled());
    }

    #[tokio::test]
    async fn test_analyze_returns_continue() {
        let mut analyzer = AlertAnalyzer::default();
        let packet = make_test_packet();
        let mut analysis = PacketAnalysis::new(packet);

        let decision = analyzer.analyze(&mut analysis).await;
        assert_eq!(decision, AnalyzerDecision::Continue);
    }
}
