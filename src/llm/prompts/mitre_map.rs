//! MITRE ATT&CK Mapping Prompt
//!
//! Prompts for mapping security events to MITRE ATT&CK framework.

use super::{OutputFormat, PromptContext, PromptTemplate};
use crate::llm::config::AnalysisType;

/// MITRE ATT&CK mapping prompt template
pub struct MitreMapPrompt {
    system: String,
}

impl MitreMapPrompt {
    /// Create a new MITRE mapping prompt
    pub fn new() -> Self {
        Self {
            system: MITRE_SYSTEM_PROMPT.to_string(),
        }
    }
}

impl Default for MitreMapPrompt {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptTemplate for MitreMapPrompt {
    fn analysis_type(&self) -> AnalysisType {
        AnalysisType::MitreMapping
    }

    fn system_prompt(&self) -> &str {
        &self.system
    }

    fn build_prompt(&self, context: &PromptContext) -> String {
        let mut prompt = String::new();

        prompt.push_str("Map this security event to MITRE ATT&CK techniques:\n\n");
        prompt.push_str("## Event Details\n");
        prompt.push_str(&context.format_summary());
        prompt.push_str("\n\n");

        if !context.related_events.is_empty() {
            prompt.push_str("## Related Events\n");
            for event in &context.related_events {
                prompt.push_str(&format!(
                    "- {} ({}): {}\n",
                    event.event_type, event.severity, event.description
                ));
            }
            prompt.push_str("\n");
        }

        if let Some(rag) = &context.rag_context {
            prompt.push_str("## Reference Information\n");
            prompt.push_str(rag);
            prompt.push_str("\n\n");
        }

        prompt.push_str("Provide MITRE ATT&CK mapping in JSON format with:\n");
        prompt.push_str("- techniques: array of mapped techniques with:\n");
        prompt.push_str("  - id: technique ID (e.g., T1595)\n");
        prompt.push_str("  - name: technique name\n");
        prompt.push_str("  - tactic: primary tactic\n");
        prompt.push_str("  - confidence: mapping confidence (0.0-1.0)\n");
        prompt.push_str("  - evidence: brief evidence from the event\n");
        prompt.push_str("- subtechniques: array of specific sub-techniques if applicable\n");

        prompt
    }

    fn output_format(&self) -> OutputFormat {
        OutputFormat::Json
    }

    fn max_tokens(&self) -> usize {
        1024
    }
}

const MITRE_SYSTEM_PROMPT: &str = r#"You are a threat intelligence analyst expert in MITRE ATT&CK framework mapping.

Map security events to ATT&CK techniques using Enterprise ATT&CK matrix. Key mappings:

## Reconnaissance (TA0043)
- Port scans → T1595 Active Scanning
- DNS queries → T1596 Search Open Websites/Domains
- Banner grabbing → T1592 Gather Victim Host Information

## Initial Access (TA0001)
- Brute force → T1110 Brute Force
- Phishing → T1566 Phishing
- Exploit public apps → T1190 Exploit Public-Facing Application

## Execution (TA0002)
- Command injection → T1059 Command and Scripting Interpreter
- SQL injection → T1059.004 (if leading to code execution)

## Credential Access (TA0006)
- Password spraying → T1110.003 Password Spraying
- Credential stuffing → T1110.004 Credential Stuffing
- MITM → T1557 Adversary-in-the-Middle

## Lateral Movement (TA0008)
- SMB → T1021.002 SMB/Windows Admin Shares
- SSH → T1021.004 SSH
- RDP → T1021.001 Remote Desktop Protocol

## Impact (TA0040)
- DoS → T1498/T1499 Network/Endpoint Denial of Service
- Data destruction → T1485 Data Destruction

Provide only techniques that are clearly evidenced. Include confidence levels.
Respond with valid JSON only."#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mitre_prompt() {
        let prompt = MitreMapPrompt::new();
        let context = PromptContext::new("PortScan", "Medium", "Sequential port scan from external IP");

        let built = prompt.build_prompt(&context);
        assert!(built.contains("MITRE ATT&CK"));
        assert!(built.contains("techniques"));
    }

    #[test]
    fn test_output_format() {
        let prompt = MitreMapPrompt::new();
        assert_eq!(prompt.output_format(), OutputFormat::Json);
    }
}
