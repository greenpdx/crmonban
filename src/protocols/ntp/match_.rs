//! NTP rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crmonban_types::DetectionType;
use super::state::NtpState;

pub struct NtpMatcher;
impl NtpMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(ntp) = state.get_inner::<NtpState>() {
            if ntp.monlist_detected {
                alerts.push(ProtocolAlert::new("NTP monlist amplification attempt", DetectionType::DoS, Severity::High).with_classtype("attempted-dos"));
            }
            if ntp.private_mode {
                alerts.push(ProtocolAlert::new("NTP private mode request", DetectionType::BehaviorAnomaly, Severity::Medium).with_classtype("misc-activity"));
            }
        }
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for NtpMatcher { fn default() -> Self { Self::new() } }
