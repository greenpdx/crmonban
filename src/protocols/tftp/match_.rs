//! TFTP rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::types::DetectionType;
use super::state::TftpState;

pub struct TftpMatcher;
impl TftpMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(tftp) = state.get_inner::<TftpState>() {
            if tftp.suspicious_file {
                alerts.push(ProtocolAlert::new("TFTP transfer of suspicious file type", DetectionType::BehaviorAnomaly, Severity::High).with_classtype("suspicious-filename-detect"));
            }
            if tftp.is_write {
                alerts.push(ProtocolAlert::new("TFTP write request detected", DetectionType::PolicyViolation, Severity::Medium).with_classtype("policy-violation"));
            }
        }
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for TftpMatcher { fn default() -> Self { Self::new() } }
