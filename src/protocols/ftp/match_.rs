//! FTP rule matching
use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::signatures::ast::{Rule, RuleOption};
use crate::types::DetectionType;
use super::state::FtpState;

pub struct FtpMatcher;
impl FtpMatcher {
    pub fn new() -> Self { Self }
    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        if let Some(ftp) = state.get_inner::<FtpState>() {
            if ftp.auth_failures >= 3 {
                alerts.push(ProtocolAlert::new("FTP brute force detected", DetectionType::BruteForce, Severity::High).with_classtype("attempted-admin"));
            }
            if ftp.bounce_attack {
                alerts.push(ProtocolAlert::new("FTP bounce attack detected", DetectionType::NetworkScan, Severity::High).with_classtype("attempted-recon"));
            }
        }
        for rule in rules.iter() { if let Some(a) = self.match_rule(state, rule) { alerts.push(a); } }
        alerts
    }
    fn match_rule(&self, state: &ProtocolState, rule: &Rule) -> Option<ProtocolAlert> {
        for opt in &rule.options {
            if let RuleOption::Raw { keyword, value } = opt {
                if keyword == "ftp.command" {
                    let cmd = state.get_buffer("ftp.command")?;
                    if let Some(p) = value { if !cmd.windows(p.len()).any(|w| w.eq_ignore_ascii_case(p.as_bytes())) { return None; } }
                }
            }
        }
        Some(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone()))
    }
}
impl Default for FtpMatcher { fn default() -> Self { Self::new() } }
