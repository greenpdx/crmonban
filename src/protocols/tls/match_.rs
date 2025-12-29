//! TLS rule matching

use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::signatures::ast::{Rule, RuleOption, ContentMatch};
use crate::types::DetectionType;
use super::state::TlsState;
use super::types::*;

pub struct TlsMatcher;

impl TlsMatcher {
    pub fn new() -> Self { Self }

    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        let tls_state = state.get_inner::<TlsState>();
        alerts.extend(self.check_protocol_alerts(state, tls_state));
        for rule in rules.iter() {
            if let Some(alert) = self.match_rule(state, rule) {
                alerts.push(alert);
            }
        }
        alerts
    }

    fn check_protocol_alerts(&self, _state: &ProtocolState, tls_state: Option<&TlsState>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        let Some(tls) = tls_state else { return alerts; };

        if tls.suspicious_ja3 {
            if let Some(ref hash) = tls.ja3_hash {
                alerts.push(ProtocolAlert::new(
                    format!("Suspicious JA3 fingerprint detected: {}", hash),
                    DetectionType::Malware,
                    Severity::High,
                ).with_classtype("trojan-activity")
                 .with_metadata("ja3_hash", hash.clone()));
            }
        }

        if let Some(ref version) = tls.version {
            if version.0 < 0x0303 { // Older than TLS 1.2
                alerts.push(ProtocolAlert::new(
                    format!("Deprecated TLS version: {}", version),
                    DetectionType::PolicyViolation,
                    Severity::Medium,
                ).with_classtype("policy-violation"));
            }
        }

        alerts
    }

    fn match_rule(&self, state: &ProtocolState, rule: &Rule) -> Option<ProtocolAlert> {
        for option in &rule.options {
            match option {
                RuleOption::Raw { keyword, value } if keyword == "tls.sni" => {
                    let sni = state.get_buffer("tls.sni")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(sni, pattern.as_bytes(), true) { return None; }
                    }
                }
                RuleOption::Raw { keyword, value } if keyword == "ja3.hash" => {
                    let ja3 = state.get_buffer("ja3.hash")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(ja3, pattern.as_bytes(), false) { return None; }
                    }
                }
                RuleOption::Content(cm) => {
                    if !self.check_content_match(state, cm) { return None; }
                }
                _ => {}
            }
        }

        Some(ProtocolAlert::from_rule(rule.sid, &rule.msg, DetectionType::SignatureMatch, priority_to_severity(rule.priority), rule.classtype.clone()))
    }

    fn check_content_match(&self, state: &ProtocolState, cm: &ContentMatch) -> bool {
        for buf in ["tls.sni", "ja3.hash", "ja3.string"] {
            if let Some(buf_data) = state.get_buffer(buf) {
                let matched = self.content_matches(buf_data, &cm.pattern, cm.nocase);
                if cm.negated { if matched { return false; } } else if matched { return true; }
            }
        }
        cm.negated
    }

    fn content_matches(&self, haystack: &[u8], needle: &[u8], nocase: bool) -> bool {
        if needle.is_empty() { return true; }
        if haystack.len() < needle.len() { return false; }
        if nocase {
            let h: Vec<u8> = haystack.iter().map(|b| b.to_ascii_lowercase()).collect();
            let n: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
            h.windows(n.len()).any(|w| w == n.as_slice())
        } else {
            haystack.windows(needle.len()).any(|w| w == needle)
        }
    }
}

impl Default for TlsMatcher { fn default() -> Self { Self::new() } }
