//! RFB/VNC rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crmonban_types::DetectionType;
use super::state::RfbState;

pub struct RfbMatcher;
impl RfbMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(rfb) = state.get_inner::<RfbState>() {
            if rfb.weak_auth {
                alerts.push(ProtocolAlert::new("VNC no authentication configured", DetectionType::PolicyViolation, Severity::High).with_classtype("policy-violation"));
            }
        }
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for RfbMatcher { fn default() -> Self { Self::new() } }
