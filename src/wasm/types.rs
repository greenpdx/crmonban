//! Types for WASM plugin interface
//!
//! Provides stage-aware context and result types for WASM/Rust plugins.

use serde::{Deserialize, Serialize};

use crate::core::DetectionType;
use crate::engine::pipeline::PipelineStage;

/// Stage-specific context populated by earlier pipeline stages
///
/// This allows WASM plugins to access results from all stages that
/// have already processed the packet.
#[derive(Debug, Clone, Default)]
pub struct StageContext {
    /// Which stage is calling the plugin
    pub calling_stage: Option<PipelineStage>,

    /// Flow tracking info (from FlowTracker stage)
    pub flow: Option<FlowInfo>,

    /// Scan detection results (from ScanDetection stage)
    pub scan: Option<ScanInfo>,

    /// DoS detection results (from DoSDetection stage)
    pub dos: Option<DoSInfo>,

    /// Brute force detection results (from BruteForceDetection stage)
    pub brute_force: Option<BruteForceInfo>,

    /// Signature matches (from SignatureMatching stage)
    pub signatures: Vec<SignatureInfo>,

    /// Threat intel hits (from ThreatIntel stage)
    pub intel: Vec<IntelInfo>,

    /// Protocol analysis results (from ProtocolAnalysis stage)
    pub protocols: Option<ProtocolInfo>,
}

impl StageContext {
    /// Create a new empty context
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the calling stage
    pub fn with_stage(mut self, stage: PipelineStage) -> Self {
        self.calling_stage = Some(stage);
        self
    }

    /// Add flow info
    pub fn with_flow(mut self, flow: FlowInfo) -> Self {
        self.flow = Some(flow);
        self
    }

    /// Add scan detection result
    pub fn with_scan(mut self, scan: ScanInfo) -> Self {
        self.scan = Some(scan);
        self
    }

    /// Add DoS detection result
    pub fn with_dos(mut self, dos: DoSInfo) -> Self {
        self.dos = Some(dos);
        self
    }

    /// Add brute force detection result
    pub fn with_brute_force(mut self, bf: BruteForceInfo) -> Self {
        self.brute_force = Some(bf);
        self
    }

    /// Add signature matches
    pub fn with_signatures(mut self, sigs: Vec<SignatureInfo>) -> Self {
        self.signatures = sigs;
        self
    }

    /// Add threat intel hits
    pub fn with_intel(mut self, intel: Vec<IntelInfo>) -> Self {
        self.intel = intel;
        self
    }

    /// Add protocol analysis
    pub fn with_protocols(mut self, protocols: ProtocolInfo) -> Self {
        self.protocols = Some(protocols);
        self
    }

    /// Check if any detection has fired
    pub fn has_detections(&self) -> bool {
        self.scan.is_some()
            || self.dos.is_some()
            || self.brute_force.is_some()
            || !self.signatures.is_empty()
            || !self.intel.is_empty()
    }
}

/// Flow tracking information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowInfo {
    /// Flow ID
    pub flow_id: u64,
    /// Packets in flow (client to server)
    pub packets_to_server: u64,
    /// Packets in flow (server to client)
    pub packets_to_client: u64,
    /// Bytes to server
    pub bytes_to_server: u64,
    /// Bytes to client
    pub bytes_to_client: u64,
    /// Flow state (e.g., "established", "syn_sent", "closed")
    pub state: String,
    /// Flow duration in milliseconds
    pub duration_ms: u64,
    /// Is this direction to server?
    pub to_server: bool,
}

/// Scan detection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanInfo {
    /// Scan type detected
    pub scan_type: String,
    /// Confidence score (0.0-1.0)
    pub confidence: f32,
    /// Number of ports scanned
    pub ports_scanned: u32,
    /// Half-open connections
    pub half_open: u32,
    /// Sequential port pattern detected
    pub sequential_pattern: bool,
}

/// DoS detection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoSInfo {
    /// DoS type (e.g., "syn_flood", "udp_flood")
    pub dos_type: String,
    /// Severity level
    pub severity: String,
    /// Packets per second
    pub pps: u64,
    /// Half-open connections
    pub half_open: u32,
    /// Confidence score
    pub confidence: f32,
}

/// Brute force detection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceInfo {
    /// Target service
    pub service: String,
    /// Failed attempts
    pub failed_attempts: u32,
    /// Time window (seconds)
    pub window_secs: u32,
    /// Different usernames tried
    pub unique_usernames: u32,
}

/// Signature match information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// Signature ID
    pub sid: u32,
    /// Signature message
    pub msg: String,
    /// Priority (1=high, 4=low)
    pub priority: u8,
    /// Classification type
    pub classtype: Option<String>,
    /// MITRE ATT&CK IDs
    pub mitre: Vec<String>,
}

/// Threat intelligence match information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelInfo {
    /// IOC type (ip, domain, hash, etc.)
    pub ioc_type: String,
    /// IOC value that matched
    pub ioc_value: String,
    /// Source feed name
    pub source: String,
    /// Threat category
    pub category: String,
    /// Severity level
    pub severity: String,
}

/// Protocol analysis information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolInfo {
    /// Detected protocol
    pub protocol: String,
    /// HTTP request info
    pub http: Option<HttpInfo>,
    /// DNS query info
    pub dns: Option<DnsInfo>,
    /// TLS info
    pub tls: Option<TlsInfo>,
}

/// HTTP protocol info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInfo {
    pub method: Option<String>,
    pub uri: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub status_code: Option<u16>,
}

/// DNS protocol info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    pub query_name: Option<String>,
    pub query_type: Option<String>,
    pub response_code: Option<u16>,
}

/// TLS protocol info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub sni: Option<String>,
    pub ja3_hash: Option<String>,
    pub version: Option<String>,
}

/// Result from a WASM/Rust plugin evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmResult {
    /// Plugin/rule ID
    pub plugin_id: String,
    /// Score delta (positive = more suspicious)
    pub score_delta: f32,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Evidence/explanation
    pub evidence: String,
    /// Tags to apply
    pub tags: Vec<String>,
    /// Detection type (if this should generate an event)
    pub detection_type: Option<DetectionType>,
}

impl WasmResult {
    /// Create a new WASM result
    pub fn new(plugin_id: &str, score_delta: f32, evidence: &str) -> Self {
        Self {
            plugin_id: plugin_id.to_string(),
            score_delta,
            confidence: 1.0,
            evidence: evidence.to_string(),
            tags: Vec::new(),
            detection_type: None,
        }
    }

    /// Set confidence
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Set tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Set detection type
    pub fn with_detection_type(mut self, dt: DetectionType) -> Self {
        self.detection_type = Some(dt);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stage_context() {
        let ctx = StageContext::new()
            .with_stage(PipelineStage::WasmPlugins)
            .with_scan(ScanInfo {
                scan_type: "syn_scan".to_string(),
                confidence: 0.9,
                ports_scanned: 100,
                half_open: 50,
                sequential_pattern: true,
            });

        assert!(ctx.has_detections());
        assert_eq!(ctx.calling_stage, Some(PipelineStage::WasmPlugins));
    }

    #[test]
    fn test_wasm_result() {
        let result = WasmResult::new("TEST_PLUGIN", 5.0, "Detected something suspicious")
            .with_confidence(0.85)
            .with_tags(vec!["scan".to_string(), "recon".to_string()]);

        assert_eq!(result.plugin_id, "TEST_PLUGIN");
        assert_eq!(result.score_delta, 5.0);
        assert_eq!(result.confidence, 0.85);
        assert_eq!(result.tags.len(), 2);
    }
}
