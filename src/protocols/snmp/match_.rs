//! SNMP rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::types::DetectionType;
use super::state::SnmpState;

pub struct SnmpMatcher;
impl SnmpMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(snmp) = state.get_inner::<SnmpState>() {
            if snmp.default_community { alerts.push(ProtocolAlert::new("Default SNMP community string", DetectionType::PolicyViolation, Severity::High).with_classtype("policy-violation")); }
        }
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for SnmpMatcher { fn default() -> Self { Self::new() } }
