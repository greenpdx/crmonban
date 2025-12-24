//! RDP rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::signatures::ast::Rule;
use crmonban_types::DetectionType;
use super::state::RdpState;

pub struct RdpMatcher;
impl RdpMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(rdp) = state.get_inner::<RdpState>() {
            if rdp.auth_failures >= 3 { alerts.push(ProtocolAlert::new("RDP brute force", DetectionType::BruteForce, Severity::High).with_classtype("attempted-admin")); }
            if rdp.bluekeep_probe { alerts.push(ProtocolAlert::new("BlueKeep probe detected", DetectionType::ExploitAttempt, Severity::Critical).with_classtype("attempted-admin")); }
        }
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for RdpMatcher { fn default() -> Self { Self::new() } }
