//! Attack Chain Narrative Prompt
//!
//! Prompts for generating attack chain narratives from correlated events.

use super::{OutputFormat, PromptContext, PromptTemplate};
use crate::llm::config::AnalysisType;

/// Attack chain narrative prompt template
pub struct AttackChainPrompt {
    system: String,
}

impl AttackChainPrompt {
    /// Create a new attack chain prompt
    pub fn new() -> Self {
        Self {
            system: CHAIN_SYSTEM_PROMPT.to_string(),
        }
    }
}

impl Default for AttackChainPrompt {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptTemplate for AttackChainPrompt {
    fn analysis_type(&self) -> AnalysisType {
        AnalysisType::AttackChain
    }

    fn system_prompt(&self) -> &str {
        &self.system
    }

    fn build_prompt(&self, context: &PromptContext) -> String {
        let mut prompt = String::new();

        prompt.push_str("Analyze this sequence of events and construct an attack narrative:\n\n");

        prompt.push_str("## Primary Event\n");
        prompt.push_str(&context.format_summary());
        prompt.push_str("\n\n");

        if !context.related_events.is_empty() {
            prompt.push_str("## Related Events (chronological)\n");
            for (i, event) in context.related_events.iter().enumerate() {
                prompt.push_str(&format!(
                    "{}. [{}] {} - {} ({})\n",
                    i + 1,
                    event.timestamp,
                    event.event_type,
                    event.description,
                    event.severity
                ));
            }
            prompt.push_str("\n");
        }

        if let Some(rag) = &context.rag_context {
            prompt.push_str("## Threat Intelligence\n");
            prompt.push_str(rag);
            prompt.push_str("\n\n");
        }

        prompt.push_str("Construct an attack narrative that explains:\n");
        prompt.push_str("1. The likely attack progression (what happened first, second, etc.)\n");
        prompt.push_str("2. The attacker's probable objectives\n");
        prompt.push_str("3. Current attack phase (recon, initial access, lateral movement, etc.)\n");
        prompt.push_str("4. Predicted next steps if not mitigated\n");
        prompt.push_str("5. Recommended containment actions\n");

        prompt
    }

    fn output_format(&self) -> OutputFormat {
        OutputFormat::Markdown
    }

    fn max_tokens(&self) -> usize {
        2048
    }
}

const CHAIN_SYSTEM_PROMPT: &str = r#"You are a threat intelligence analyst specializing in attack chain reconstruction.

Your task is to analyze sequences of security events and reconstruct the attacker's campaign. Consider:

1. **Kill Chain Phases**: Map events to Lockheed Martin Cyber Kill Chain phases
   - Reconnaissance → Weaponization → Delivery → Exploitation → Installation → C2 → Actions

2. **Attack Patterns**: Recognize common attack patterns
   - Brute force followed by successful login → credential compromise
   - Port scan → vulnerability scan → exploit attempt → attack chain
   - DNS queries → C2 beaconing pattern

3. **Temporal Analysis**: Consider timing between events
   - Rapid succession suggests automation/scripts
   - Regular intervals suggest beaconing
   - Long gaps may indicate human operator

4. **Lateral Movement Indicators**:
   - Internal reconnaissance after initial compromise
   - Credential harvesting attempts
   - Pivoting through internal hosts

Provide a coherent narrative that connects the events and explains the attack progression. Be specific about confidence levels and alternative interpretations where appropriate."#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::prompts::RelatedEvent;

    #[test]
    fn test_attack_chain_prompt() {
        let prompt = AttackChainPrompt::new();
        let mut context = PromptContext::new("BruteForce", "High", "Brute force attack detected");

        context.related_events = vec![
            RelatedEvent::new("2024-01-01T10:00:00Z", "PortScan", "Port scan on target", "Medium"),
            RelatedEvent::new("2024-01-01T10:05:00Z", "BruteForce", "SSH brute force", "High"),
            RelatedEvent::new("2024-01-01T10:10:00Z", "AuthSuccess", "Login after brute force", "Critical"),
        ];

        let built = prompt.build_prompt(&context);
        assert!(built.contains("Related Events"));
        assert!(built.contains("PortScan"));
        assert!(built.contains("attack progression"));
    }
}
