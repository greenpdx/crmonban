//! DNP3 rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::types::DetectionType;
use super::state::Dnp3State;

pub struct Dnp3Matcher;
impl Dnp3Matcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(dnp3) = state.get_inner::<Dnp3State>() {
            if dnp3.restart_detected {
                alerts.push(ProtocolAlert::new("DNP3 restart command detected", DetectionType::ExploitAttempt, Severity::Critical).with_classtype("attempted-admin"));
            }
            if dnp3.control_detected {
                alerts.push(ProtocolAlert::new("DNP3 control operation detected", DetectionType::PolicyViolation, Severity::High).with_classtype("policy-violation"));
            }
        }
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for Dnp3Matcher { fn default() -> Self { Self::new() } }
