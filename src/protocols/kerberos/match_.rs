//! Kerberos rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::signatures::ast::Rule;
use crate::types::DetectionType;
use super::state::KerberosState;

pub struct KerberosMatcher;
impl KerberosMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(krb) = state.get_inner::<KerberosState>() {
            if krb.weak_encryption { alerts.push(ProtocolAlert::new("Weak Kerberos encryption", DetectionType::PolicyViolation, Severity::Medium).with_classtype("policy-violation")); }
            if krb.kerberoasting { alerts.push(ProtocolAlert::new("Kerberoasting detected", DetectionType::UnauthorizedAccess, Severity::High).with_classtype("attempted-admin")); }
        }
        for rule in rules.iter() { alerts.push(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone())); }
        alerts
    }
}
impl Default for KerberosMatcher { fn default() -> Self { Self::new() } }
