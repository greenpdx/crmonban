//! SIP rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::types::DetectionType;
use super::state::SipState;

pub struct SipMatcher;
impl SipMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(sip) = state.get_inner::<SipState>() {
            if sip.toll_fraud { alerts.push(ProtocolAlert::new("SIP toll fraud attempt", DetectionType::PolicyViolation, Severity::High).with_classtype("attempted-dos")); }
        }
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for SipMatcher { fn default() -> Self { Self::new() } }
