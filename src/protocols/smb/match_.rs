//! SMB rule matching
//!
//! Matches Suricata rules against parsed SMB protocol data.

use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet, MatchInfo};
use crate::protocols::alerts::priority_to_severity;
use crate::signatures::ast::{Rule, RuleOption, ContentMatch};
use crmonban_types::DetectionType;
use super::state::SmbState;
use super::types::*;

/// SMB rule matcher
pub struct SmbMatcher;

impl SmbMatcher {
    /// Create new SMB matcher
    pub fn new() -> Self {
        Self
    }

    /// Match Suricata rules against SMB state
    pub fn match_rules(
        &self,
        state: &ProtocolState,
        rules: &ProtocolRuleSet<'_>,
    ) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();

        // Get SMB-specific state
        let smb_state = state.get_inner::<SmbState>();

        // Generate protocol-level alerts first
        alerts.extend(self.check_protocol_alerts(state, smb_state));

        // Match against Suricata rules
        for rule in rules.iter() {
            if let Some(alert) = self.match_rule(state, rule) {
                alerts.push(alert);
            }
        }

        alerts
    }

    /// Check for protocol-level security issues
    fn check_protocol_alerts(
        &self,
        state: &ProtocolState,
        smb_state: Option<&SmbState>,
    ) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();

        let Some(smb) = smb_state else {
            return alerts;
        };

        // SMB1 usage alert
        if smb.is_smb1() {
            alerts.push(ProtocolAlert::new(
                "SMB1 protocol detected - legacy and vulnerable",
                DetectionType::ProtocolAnomaly,
                Severity::Medium,
            ).with_classtype("policy-violation")
             .with_metadata("protocol_version", "SMB1"));
        }

        // Authentication brute force
        if smb.auth_failures >= 5 {
            alerts.push(ProtocolAlert::new(
                format!("SMB authentication brute force detected - {} failures", smb.auth_failures),
                DetectionType::BruteForce,
                Severity::High,
            ).with_classtype("attempted-user")
             .with_metadata("failure_count", smb.auth_failures.to_string()));
        }

        // Lateral movement indicators
        if smb.check_lateral_movement() {
            let mut alert = ProtocolAlert::new(
                "Potential lateral movement via SMB detected",
                DetectionType::LateralMovement,
                Severity::High,
            ).with_classtype("trojan-activity");

            // Add share info if available
            if let Some(share) = smb.current_share() {
                alert = alert.with_metadata("share", share.to_string());
            }

            // Add pipe info
            for pipe in smb.pipes.values() {
                alert = alert.with_metadata("named_pipe", pipe.name.clone());
                break; // Just first one for now
            }

            alerts.push(alert);
        }

        // Ransomware indicators
        if smb.check_ransomware_indicators() {
            alerts.push(ProtocolAlert::new(
                format!("Potential ransomware activity - {} suspicious files accessed",
                    smb.suspicious_files.len()),
                DetectionType::Malware,
                Severity::Critical,
            ).with_classtype("trojan-activity")
             .with_metadata("suspicious_file_count", smb.suspicious_files.len().to_string())
             .with_metadata("threat_type", "ransomware"));
        }

        // Admin share access
        for tree in smb.trees.values() {
            let share_lower = tree.share_name.to_lowercase();
            if share_lower.ends_with("$") {
                if share_lower.contains("admin$") {
                    alerts.push(ProtocolAlert::new(
                        format!("Admin share access: {}", tree.share_name),
                        DetectionType::UnauthorizedAccess,
                        Severity::High,
                    ).with_classtype("policy-violation")
                     .with_metadata("share", tree.share_name.clone())
                     .with_metadata("access_type", "admin_share"));
                } else if share_lower.contains("c$") || share_lower.contains("d$") {
                    alerts.push(ProtocolAlert::new(
                        format!("Hidden drive share access: {}", tree.share_name),
                        DetectionType::UnauthorizedAccess,
                        Severity::Medium,
                    ).with_classtype("policy-violation")
                     .with_metadata("share", tree.share_name.clone())
                     .with_metadata("access_type", "hidden_share"));
                }
            }
        }

        // Suspicious named pipe access
        for pipe in smb.pipes.values() {
            let pipe_lower = pipe.name.to_lowercase();
            for suspicious in SUSPICIOUS_PIPES {
                if pipe_lower.contains(&suspicious.to_lowercase()) {
                    alerts.push(ProtocolAlert::new(
                        format!("Suspicious named pipe access: {}", pipe.name),
                        DetectionType::LateralMovement,
                        Severity::Medium,
                    ).with_classtype("attempted-admin")
                     .with_metadata("pipe_name", pipe.name.clone())
                     .with_metadata("access_type", "suspicious_pipe"));
                    break;
                }
            }
        }

        alerts
    }

    /// Match a single rule against SMB state
    fn match_rule(&self, state: &ProtocolState, rule: &Rule) -> Option<ProtocolAlert> {
        // Check SMB-specific keywords first
        for option in &rule.options {
            match option {
                // Check smb.share
                RuleOption::Raw { keyword, value } if keyword == "smb.share" => {
                    let share = state.get_buffer("smb.share")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(share, pattern.as_bytes(), false) {
                            return None;
                        }
                    }
                }

                // Check smb.named_pipe
                RuleOption::Raw { keyword, value } if keyword == "smb.named_pipe" => {
                    let pipe = state.get_buffer("smb.named_pipe")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(pipe, pattern.as_bytes(), false) {
                            return None;
                        }
                    }
                }

                // Content matches on any buffer
                RuleOption::Content(cm) => {
                    if !self.check_content_match(state, cm) {
                        return None;
                    }
                }

                _ => {}
            }
        }

        // All conditions matched
        Some(ProtocolAlert::from_rule(
            rule.sid,
            &rule.msg,
            self.rule_to_detection_type(rule),
            priority_to_severity(rule.priority),
            rule.classtype.clone(),
        ))
    }

    /// Check content match against SMB buffers
    fn check_content_match(&self, state: &ProtocolState, cm: &ContentMatch) -> bool {
        // Try each SMB buffer
        let buffers = [
            "smb.share",
            "smb.named_pipe",
            "smb.filename",
            "smb.ntlmssp_user",
            "smb.ntlmssp_domain",
        ];

        for buf_name in buffers {
            if let Some(buf) = state.get_buffer(buf_name) {
                let matched = self.content_matches(buf, &cm.pattern, cm.nocase);
                if cm.negated {
                    if matched {
                        return false;
                    }
                } else if matched {
                    return true;
                }
            }
        }

        // Negated content that wasn't found is a match
        cm.negated
    }

    /// Check if content matches pattern
    fn content_matches(&self, haystack: &[u8], needle: &[u8], nocase: bool) -> bool {
        if needle.is_empty() {
            return true;
        }
        if haystack.len() < needle.len() {
            return false;
        }

        if nocase {
            let haystack_lower: Vec<u8> = haystack.iter().map(|b| b.to_ascii_lowercase()).collect();
            let needle_lower: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
            haystack_lower.windows(needle_lower.len()).any(|w| w == needle_lower.as_slice())
        } else {
            haystack.windows(needle.len()).any(|w| w == needle)
        }
    }

    /// Determine detection type from rule
    fn rule_to_detection_type(&self, rule: &Rule) -> DetectionType {
        // Check classtype first
        if let Some(ref classtype) = rule.classtype {
            match classtype.as_str() {
                "trojan-activity" => return DetectionType::Malware,
                "attempted-admin" => return DetectionType::UnauthorizedAccess,
                "attempted-user" => return DetectionType::BruteForce,
                "policy-violation" => return DetectionType::PolicyViolation,
                "bad-unknown" => return DetectionType::ProtocolAnomaly,
                _ => {}
            }
        }

        // Check rule message for hints
        let msg_lower = rule.msg.to_lowercase();

        if msg_lower.contains("ransomware") {
            DetectionType::Malware
        } else if msg_lower.contains("lateral") || msg_lower.contains("psexec") {
            DetectionType::LateralMovement
        } else if msg_lower.contains("brute") || msg_lower.contains("auth") {
            DetectionType::BruteForce
        } else if msg_lower.contains("exploit") || msg_lower.contains("overflow") {
            DetectionType::ExploitAttempt
        } else if msg_lower.contains("admin") || msg_lower.contains("privilege") {
            DetectionType::UnauthorizedAccess
        } else {
            DetectionType::SignatureMatch
        }
    }
}

impl Default for SmbMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_matches() {
        let matcher = SmbMatcher::new();

        assert!(matcher.content_matches(b"hello world", b"world", false));
        assert!(!matcher.content_matches(b"hello world", b"WORLD", false));
        assert!(matcher.content_matches(b"hello world", b"WORLD", true));
        assert!(!matcher.content_matches(b"hello", b"hello world", false));
    }

    #[test]
    fn test_smb1_detection() {
        let matcher = SmbMatcher::new();
        let state = ProtocolState::new();

        let mut smb_state = SmbState::new();
        smb_state.set_version(SmbVersion::Smb1);

        let alerts = matcher.check_protocol_alerts(&state, Some(&smb_state));
        assert!(alerts.iter().any(|a| a.msg.contains("SMB1")));
    }

    #[test]
    fn test_brute_force_detection() {
        let matcher = SmbMatcher::new();
        let state = ProtocolState::new();

        let mut smb_state = SmbState::new();
        for _ in 0..10 {
            smb_state.record_auth_failure();
        }

        let alerts = matcher.check_protocol_alerts(&state, Some(&smb_state));
        assert!(alerts.iter().any(|a| a.detection_type == DetectionType::BruteForce));
    }

    #[test]
    fn test_admin_share_detection() {
        let matcher = SmbMatcher::new();
        let state = ProtocolState::new();

        let mut smb_state = SmbState::new();
        smb_state.add_tree(1, "\\\\server\\ADMIN$".to_string(), ShareType::Disk);

        let alerts = matcher.check_protocol_alerts(&state, Some(&smb_state));
        assert!(alerts.iter().any(|a| a.msg.contains("Admin share")));
        assert!(alerts.iter().any(|a| a.detection_type == DetectionType::UnauthorizedAccess));
    }
}
