//! Modbus rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crmonban_types::DetectionType;
use super::state::ModbusState;
use super::types::DANGEROUS_FUNCTIONS;

pub struct ModbusMatcher;
impl ModbusMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(modbus) = state.get_inner::<ModbusState>() {
            if modbus.write_detected {
                alerts.push(ProtocolAlert::new("Modbus write operation detected", DetectionType::PolicyViolation, Severity::Medium).with_classtype("policy-violation"));
            }
            if modbus.diagnostic_detected {
                alerts.push(ProtocolAlert::new("Modbus diagnostic/identification request", DetectionType::NetworkScan, Severity::Low).with_classtype("attempted-recon"));
            }
            if DANGEROUS_FUNCTIONS.contains(&modbus.function_code) && modbus.unit_id == 0 {
                alerts.push(ProtocolAlert::new("Modbus broadcast write command", DetectionType::ExploitAttempt, Severity::High).with_classtype("attempted-admin"));
            }
        }
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for ModbusMatcher { fn default() -> Self { Self::new() } }
