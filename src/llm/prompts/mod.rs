//! LLM Prompt Templates
//!
//! Provides structured prompts for security analysis tasks.

pub mod alert_triage;
pub mod threat_explain;
pub mod attack_chain;
pub mod mitre_map;

pub use alert_triage::AlertTriagePrompt;
pub use threat_explain::ThreatExplainPrompt;
pub use attack_chain::AttackChainPrompt;
pub use mitre_map::MitreMapPrompt;

use serde::{Deserialize, Serialize};

use crate::llm::config::AnalysisType;

/// Base prompt template
pub trait PromptTemplate {
    /// Get the analysis type
    fn analysis_type(&self) -> AnalysisType;

    /// Get the system prompt
    fn system_prompt(&self) -> &str;

    /// Build the user prompt with context
    fn build_prompt(&self, context: &PromptContext) -> String;

    /// Get expected output format
    fn output_format(&self) -> OutputFormat;

    /// Get maximum tokens for response
    fn max_tokens(&self) -> usize {
        2048
    }
}

/// Output format for LLM responses
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Plain text response
    Text,
    /// JSON response
    Json,
    /// Markdown response
    Markdown,
}

/// Context for prompt building
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptContext {
    /// Alert/incident summary
    pub alert_summary: String,
    /// Source IP (may be sanitized)
    pub source_ip: Option<String>,
    /// Destination IP (may be sanitized)
    pub dest_ip: Option<String>,
    /// Source port
    pub source_port: Option<u16>,
    /// Destination port
    pub dest_port: Option<u16>,
    /// Protocol
    pub protocol: Option<String>,
    /// Detection type
    pub detection_type: String,
    /// Severity level
    pub severity: String,
    /// Confidence score (0-1)
    pub confidence: Option<f32>,
    /// Detection module
    pub detector: Option<String>,
    /// Timestamp
    pub timestamp: String,
    /// Related events (for attack chain)
    pub related_events: Vec<RelatedEvent>,
    /// Additional context
    pub additional_context: Option<String>,
    /// RAG context (retrieved documents)
    pub rag_context: Option<String>,
}

impl PromptContext {
    /// Create a new prompt context from alert data
    pub fn new(detection_type: &str, severity: &str, summary: &str) -> Self {
        Self {
            alert_summary: summary.to_string(),
            source_ip: None,
            dest_ip: None,
            source_port: None,
            dest_port: None,
            protocol: None,
            detection_type: detection_type.to_string(),
            severity: severity.to_string(),
            confidence: None,
            detector: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            related_events: Vec::new(),
            additional_context: None,
            rag_context: None,
        }
    }

    /// Add network information
    pub fn with_network(
        mut self,
        src_ip: Option<&str>,
        dst_ip: Option<&str>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: Option<&str>,
    ) -> Self {
        self.source_ip = src_ip.map(String::from);
        self.dest_ip = dst_ip.map(String::from);
        self.source_port = src_port;
        self.dest_port = dst_port;
        self.protocol = protocol.map(String::from);
        self
    }

    /// Add detection metadata
    pub fn with_detection(mut self, detector: &str, confidence: f32) -> Self {
        self.detector = Some(detector.to_string());
        self.confidence = Some(confidence);
        self
    }

    /// Add related events
    pub fn with_related_events(mut self, events: Vec<RelatedEvent>) -> Self {
        self.related_events = events;
        self
    }

    /// Add RAG context
    pub fn with_rag_context(mut self, context: &str) -> Self {
        self.rag_context = Some(context.to_string());
        self
    }

    /// Format as compact summary for prompt
    pub fn format_summary(&self) -> String {
        let mut parts = Vec::new();

        parts.push(format!("Type: {}", self.detection_type));
        parts.push(format!("Severity: {}", self.severity));

        if let Some(src) = &self.source_ip {
            let port = self.source_port.map(|p| format!(":{}", p)).unwrap_or_default();
            parts.push(format!("Source: {}{}", src, port));
        }

        if let Some(dst) = &self.dest_ip {
            let port = self.dest_port.map(|p| format!(":{}", p)).unwrap_or_default();
            parts.push(format!("Destination: {}{}", dst, port));
        }

        if let Some(proto) = &self.protocol {
            parts.push(format!("Protocol: {}", proto));
        }

        if let Some(conf) = self.confidence {
            parts.push(format!("Confidence: {:.0}%", conf * 100.0));
        }

        if let Some(detector) = &self.detector {
            parts.push(format!("Detector: {}", detector));
        }

        parts.push(format!("Time: {}", self.timestamp));

        if !self.alert_summary.is_empty() {
            parts.push(format!("Details: {}", self.alert_summary));
        }

        parts.join("\n")
    }
}

/// Related event for attack chain analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedEvent {
    /// Event timestamp
    pub timestamp: String,
    /// Event type
    pub event_type: String,
    /// Brief description
    pub description: String,
    /// Severity
    pub severity: String,
}

impl RelatedEvent {
    /// Create a new related event
    pub fn new(timestamp: &str, event_type: &str, description: &str, severity: &str) -> Self {
        Self {
            timestamp: timestamp.to_string(),
            event_type: event_type.to_string(),
            description: description.to_string(),
            severity: severity.to_string(),
        }
    }
}

/// Create a prompt template for the given analysis type
pub fn create_prompt(analysis_type: AnalysisType) -> Box<dyn PromptTemplate + Send + Sync> {
    match analysis_type {
        AnalysisType::Triage => Box::new(AlertTriagePrompt::new()),
        AnalysisType::Explain => Box::new(ThreatExplainPrompt::new()),
        AnalysisType::AttackChain => Box::new(AttackChainPrompt::new()),
        AnalysisType::MitreMapping => Box::new(MitreMapPrompt::new()),
        AnalysisType::ThreatHunt => Box::new(ThreatExplainPrompt::new()), // Reuse for now
        AnalysisType::Full => Box::new(ThreatExplainPrompt::new()), // Full handled differently
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompt_context() {
        let ctx = PromptContext::new("PortScan", "High", "Port scan detected")
            .with_network(
                Some("192.168.1.100"),
                Some("10.0.0.1"),
                Some(54321),
                Some(22),
                Some("TCP"),
            )
            .with_detection("layer234", 0.85);

        let summary = ctx.format_summary();
        assert!(summary.contains("PortScan"));
        assert!(summary.contains("High"));
        assert!(summary.contains("192.168.1.100"));
    }

    #[test]
    fn test_create_prompt() {
        let prompt = create_prompt(AnalysisType::Triage);
        assert_eq!(prompt.analysis_type(), AnalysisType::Triage);
    }
}
