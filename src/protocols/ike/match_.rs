//! IKE/IPsec rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crmonban_types::DetectionType;
use super::state::IkeState;

pub struct IkeMatcher;
impl IkeMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(ike) = state.get_inner::<IkeState>() {
            if ike.aggressive_mode {
                alerts.push(ProtocolAlert::new("IKE aggressive mode detected (potential credential exposure)", DetectionType::PolicyViolation, Severity::Medium).with_classtype("policy-violation"));
            }
            if ike.version == 1 {
                alerts.push(ProtocolAlert::new("IKEv1 detected (deprecated protocol)", DetectionType::PolicyViolation, Severity::Low).with_classtype("policy-violation"));
            }
        }
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for IkeMatcher { fn default() -> Self { Self::new() } }
