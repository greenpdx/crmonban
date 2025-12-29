//! DCE/RPC rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::signatures::ast::{Rule, RuleOption, ContentMatch};
use crate::types::DetectionType;
use super::state::DceRpcState;

pub struct DceRpcMatcher;

impl DceRpcMatcher {
    pub fn new() -> Self { Self }

    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(dce) = state.get_inner::<DceRpcState>() {
            if dce.suspicious_interface {
                alerts.push(ProtocolAlert::new(
                    "Suspicious DCE/RPC interface detected",
                    DetectionType::LateralMovement, Severity::High,
                ).with_classtype("attempted-admin"));
            }
        }
        for rule in rules.iter() {
            if let Some(alert) = self.match_rule(state, rule) { alerts.push(alert); }
        }
        alerts
    }

    fn match_rule(&self, state: &ProtocolState, rule: &Rule) -> Option<ProtocolAlert> {
        for opt in &rule.options {
            match opt {
                RuleOption::Raw { keyword, value } if keyword == "dcerpc.iface" || keyword == "dce_iface" => {
                    let iface = state.get_buffer("dcerpc.iface")?;
                    if let Some(p) = value { if !iface.windows(p.len()).any(|w| w == p.as_bytes()) { return None; } }
                }
                RuleOption::Content(cm) => { if !self.check_content(state, cm) { return None; } }
                _ => {}
            }
        }
        Some(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone()))
    }

    fn check_content(&self, state: &ProtocolState, cm: &ContentMatch) -> bool {
        for buf in ["dcerpc.iface", "dcerpc.stub_data"] {
            if let Some(data) = state.get_buffer(buf) {
                if data.windows(cm.pattern.len()).any(|w| w == cm.pattern.as_slice()) { return !cm.negated; }
            }
        }
        cm.negated
    }
}

impl Default for DceRpcMatcher { fn default() -> Self { Self::new() } }
