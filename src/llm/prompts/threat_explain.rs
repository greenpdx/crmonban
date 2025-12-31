//! Threat Explanation Prompt
//!
//! Prompts for generating human-readable threat descriptions.

use super::{OutputFormat, PromptContext, PromptTemplate};
use crate::llm::config::AnalysisType;

/// Threat explanation prompt template
pub struct ThreatExplainPrompt {
    system: String,
}

impl ThreatExplainPrompt {
    /// Create a new threat explanation prompt
    pub fn new() -> Self {
        Self {
            system: EXPLAIN_SYSTEM_PROMPT.to_string(),
        }
    }
}

impl Default for ThreatExplainPrompt {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptTemplate for ThreatExplainPrompt {
    fn analysis_type(&self) -> AnalysisType {
        AnalysisType::Explain
    }

    fn system_prompt(&self) -> &str {
        &self.system
    }

    fn build_prompt(&self, context: &PromptContext) -> String {
        let mut prompt = String::new();

        prompt.push_str("Explain this security event for a technical audience:\n\n");
        prompt.push_str("## Detection Details\n");
        prompt.push_str(&context.format_summary());
        prompt.push_str("\n\n");

        if let Some(rag) = &context.rag_context {
            prompt.push_str("## Related Threat Intelligence\n");
            prompt.push_str(rag);
            prompt.push_str("\n\n");
        }

        if let Some(additional) = &context.additional_context {
            prompt.push_str("## Additional Context\n");
            prompt.push_str(additional);
            prompt.push_str("\n\n");
        }

        prompt.push_str("Provide:\n");
        prompt.push_str("1. What happened (in plain language)\n");
        prompt.push_str("2. Why this matters (potential impact)\n");
        prompt.push_str("3. What the attacker might be trying to do\n");
        prompt.push_str("4. Recommended investigation steps\n");

        prompt
    }

    fn output_format(&self) -> OutputFormat {
        OutputFormat::Markdown
    }

    fn max_tokens(&self) -> usize {
        1024
    }
}

const EXPLAIN_SYSTEM_PROMPT: &str = r#"You are a senior security analyst creating incident reports for your SOC team.

Your explanations should be:
- Clear and concise, using proper security terminology
- Focused on actionable information
- Contextual, explaining why this matters
- Balanced, acknowledging uncertainty where appropriate

Structure your response as a brief incident summary that helps analysts understand:
1. The nature of the threat
2. The attacker's likely objectives
3. The potential business impact
4. Recommended next steps

Keep responses focused and avoid speculation beyond the evidence. If something is uncertain, say so."#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explain_prompt() {
        let prompt = ThreatExplainPrompt::new();
        let context = PromptContext::new("SQLInjection", "Critical", "SQL injection attempt detected");

        let built = prompt.build_prompt(&context);
        assert!(built.contains("SQLInjection"));
        assert!(built.contains("What happened"));
    }

    #[test]
    fn test_output_format() {
        let prompt = ThreatExplainPrompt::new();
        assert_eq!(prompt.output_format(), OutputFormat::Markdown);
    }
}
