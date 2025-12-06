//! Correlation rules definition
//!
//! Defines rules for correlating detection events into incidents.

use serde::{Deserialize, Serialize};

/// A correlation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationRule {
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: Option<String>,
    /// Rule type (count or sequence)
    pub rule_type: RuleType,
    /// Time window in seconds
    pub window_seconds: u64,
    /// Whether to elevate severity when matched
    pub elevate_severity: bool,
    /// MITRE ATT&CK tactics
    pub mitre_tactics: Vec<String>,
    /// Tags to apply to incidents
    pub tags: Vec<String>,
}

/// Type of correlation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleType {
    /// Count-based rule (threshold of events)
    Count {
        /// Event types to match
        event_types: Vec<String>,
        /// Threshold count
        threshold: usize,
        /// Field to group by
        group_by: Option<String>,
    },
    /// Sequence-based rule (ordered events)
    Sequence {
        /// Stages in the sequence
        stages: Vec<String>,
        /// Maximum gap between stages in seconds
        max_gap_seconds: u64,
    },
}

/// Result of checking a rule
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// The rule that matched
    pub rule_name: String,
    /// Matched event IDs
    pub event_ids: Vec<uuid::Uuid>,
    /// Match confidence (0.0-1.0)
    pub confidence: f32,
}

impl CorrelationRule {
    /// Create a count-based rule
    pub fn count(
        name: &str,
        event_types: Vec<&str>,
        threshold: usize,
        window_seconds: u64,
    ) -> Self {
        Self {
            name: name.to_string(),
            description: None,
            rule_type: RuleType::Count {
                event_types: event_types.into_iter().map(|s| s.to_string()).collect(),
                threshold,
                group_by: Some("src_ip".to_string()),
            },
            window_seconds,
            elevate_severity: false,
            mitre_tactics: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Create a sequence-based rule
    pub fn sequence(name: &str, stages: Vec<&str>, max_gap_seconds: u64) -> Self {
        let stage_count = stages.len();
        Self {
            name: name.to_string(),
            description: None,
            rule_type: RuleType::Sequence {
                stages: stages.into_iter().map(|s| s.to_string()).collect(),
                max_gap_seconds,
            },
            window_seconds: max_gap_seconds * stage_count as u64,
            elevate_severity: true,
            mitre_tactics: Vec::new(),
            tags: vec!["attack_chain".to_string()],
        }
    }

    /// Set description
    pub fn with_description(mut self, desc: &str) -> Self {
        self.description = Some(desc.to_string());
        self
    }

    /// Set MITRE tactics
    pub fn with_mitre_tactics(mut self, tactics: Vec<&str>) -> Self {
        self.mitre_tactics = tactics.into_iter().map(|s| s.to_string()).collect();
        self
    }

    /// Set tags
    pub fn with_tags(mut self, tags: Vec<&str>) -> Self {
        self.tags = tags.into_iter().map(|s| s.to_string()).collect();
        self
    }

    /// Enable severity elevation
    pub fn elevate(mut self) -> Self {
        self.elevate_severity = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_rule_creation() {
        let rule = CorrelationRule::count(
            "test_rule",
            vec!["PortScan", "Probe"],
            5,
            60,
        );

        assert_eq!(rule.name, "test_rule");
        assert_eq!(rule.window_seconds, 60);

        match rule.rule_type {
            RuleType::Count { threshold, .. } => assert_eq!(threshold, 5),
            _ => panic!("Expected Count rule"),
        }
    }

    #[test]
    fn test_sequence_rule_creation() {
        let rule = CorrelationRule::sequence(
            "attack_chain",
            vec!["Scan", "Exploit", "Persistence"],
            3600,
        );

        assert_eq!(rule.name, "attack_chain");
        assert!(rule.elevate_severity);

        match rule.rule_type {
            RuleType::Sequence { stages, .. } => assert_eq!(stages.len(), 3),
            _ => panic!("Expected Sequence rule"),
        }
    }

    #[test]
    fn test_rule_builder() {
        let rule = CorrelationRule::count("brute_force", vec!["FailedAuth"], 10, 60)
            .with_description("Brute force detection")
            .with_mitre_tactics(vec!["TA0006"])
            .with_tags(vec!["ssh", "auth"])
            .elevate();

        assert!(rule.description.is_some());
        assert_eq!(rule.mitre_tactics.len(), 1);
        assert_eq!(rule.tags.len(), 2);
        assert!(rule.elevate_severity);
    }
}
