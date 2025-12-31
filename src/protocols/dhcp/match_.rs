//! DHCP rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::types::DetectionType;
use super::state::DhcpState;

pub struct DhcpMatcher;
impl DhcpMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(dhcp) = state.get_inner::<DhcpState>() {
            if dhcp.rogue_server { alerts.push(ProtocolAlert::new("Rogue DHCP server detected", DetectionType::TrafficAnomaly, Severity::High).with_classtype("network-event")); }
        }
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for DhcpMatcher { fn default() -> Self { Self::new() } }
