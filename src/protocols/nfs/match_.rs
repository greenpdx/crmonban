//! NFS rule matching
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::types::DetectionType;

pub struct NfsMatcher;
impl NfsMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, _state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for NfsMatcher { fn default() -> Self { Self::new() } }
