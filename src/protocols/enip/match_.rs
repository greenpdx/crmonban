//! EtherNet/IP rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crmonban_types::DetectionType;
use super::state::EnipState;

pub struct EnipMatcher;
impl EnipMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(enip) = state.get_inner::<EnipState>() {
            if enip.control_detected {
                alerts.push(ProtocolAlert::new("EtherNet/IP control operation detected", DetectionType::PolicyViolation, Severity::High).with_classtype("policy-violation"));
            }
        }
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for EnipMatcher { fn default() -> Self { Self::new() } }
