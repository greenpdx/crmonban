//! MQTT rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crmonban_types::DetectionType;
use super::state::MqttState;

pub struct MqttMatcher;
impl MqttMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(mqtt) = state.get_inner::<MqttState>() {
            if mqtt.wildcard_subscribe { alerts.push(ProtocolAlert::new("MQTT wildcard subscription (#/+)", DetectionType::PolicyViolation, Severity::Medium).with_classtype("policy-violation")); }
            if mqtt.sys_topic_access { alerts.push(ProtocolAlert::new("MQTT $SYS topic access attempt", DetectionType::NetworkScan, Severity::Medium).with_classtype("attempted-recon")); }
        }
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for MqttMatcher { fn default() -> Self { Self::new() } }
