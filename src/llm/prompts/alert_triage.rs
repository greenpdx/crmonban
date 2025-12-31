//! Alert Triage Prompt
//!
//! Prompts for prioritizing security alerts.

use super::{OutputFormat, PromptContext, PromptTemplate};
use crate::llm::config::AnalysisType;

/// Alert triage prompt template
pub struct AlertTriagePrompt {
    system: String,
}

impl AlertTriagePrompt {
    /// Create a new alert triage prompt
    pub fn new() -> Self {
        Self {
            system: TRIAGE_SYSTEM_PROMPT.to_string(),
        }
    }
}

impl Default for AlertTriagePrompt {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptTemplate for AlertTriagePrompt {
    fn analysis_type(&self) -> AnalysisType {
        AnalysisType::Triage
    }

    fn system_prompt(&self) -> &str {
        &self.system
    }

    fn build_prompt(&self, context: &PromptContext) -> String {
        let mut prompt = String::new();

        prompt.push_str("Analyze this security alert and provide triage:\n\n");
        prompt.push_str("## Alert Details\n");
        prompt.push_str(&context.format_summary());
        prompt.push_str("\n\n");

        if let Some(rag) = &context.rag_context {
            prompt.push_str("## Threat Intelligence Context\n");
            prompt.push_str(rag);
            prompt.push_str("\n\n");
        }

        prompt.push_str("Provide your analysis in JSON format with these fields:\n");
        prompt.push_str("- priority: P1, P2, P3, or P4\n");
        prompt.push_str("- confidence: your confidence in this assessment (0.0-1.0)\n");
        prompt.push_str("- reasoning: brief explanation for the priority\n");
        prompt.push_str("- recommended_action: what should be done\n");
        prompt.push_str("- false_positive_likelihood: low, medium, or high\n");

        prompt
    }

    fn output_format(&self) -> OutputFormat {
        OutputFormat::Json
    }

    fn max_tokens(&self) -> usize {
        512
    }
}

const TRIAGE_SYSTEM_PROMPT: &str = r#"You are an expert security analyst specializing in alert triage for a network intrusion detection system.

Your task is to analyze security alerts and assign priority levels:
- P1 (Critical): Active exploitation, data exfiltration, or imminent threat requiring immediate response
- P2 (High): Likely attack or significant security event requiring response within hours
- P3 (Medium): Potential security concern requiring investigation within 24 hours
- P4 (Low): Informational or likely false positive, can be reviewed when convenient

Consider these factors:
1. Attack sophistication and intent
2. Target sensitivity (internal servers, databases, critical infrastructure)
3. Historical context (known attacker, repeat behavior)
4. Confidence of detection
5. Potential business impact

Respond only with valid JSON. Be concise and actionable."#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_triage_prompt() {
        let prompt = AlertTriagePrompt::new();
        let context = PromptContext::new("PortScan", "High", "Sequential port scan detected");

        let built = prompt.build_prompt(&context);
        assert!(built.contains("PortScan"));
        assert!(built.contains("priority"));
    }

    #[test]
    fn test_output_format() {
        let prompt = AlertTriagePrompt::new();
        assert_eq!(prompt.output_format(), OutputFormat::Json);
    }
}
