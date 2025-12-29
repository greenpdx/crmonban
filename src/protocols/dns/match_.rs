//! DNS rule matching
//!
//! Matches Suricata rules against parsed DNS protocol data.

use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::signatures::ast::{Rule, RuleOption, ContentMatch};
use crate::types::DetectionType;
use super::state::DnsState;
use super::types::*;

/// DNS rule matcher
pub struct DnsMatcher;

impl DnsMatcher {
    /// Create new DNS matcher
    pub fn new() -> Self {
        Self
    }

    /// Match Suricata rules against DNS state
    pub fn match_rules(
        &self,
        state: &ProtocolState,
        rules: &ProtocolRuleSet<'_>,
    ) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();

        // Get DNS-specific state
        let dns_state = state.get_inner::<DnsState>();

        // Generate protocol-level alerts first
        alerts.extend(self.check_protocol_alerts(state, dns_state));

        // Match against Suricata rules
        for rule in rules.iter() {
            if let Some(alert) = self.match_rule(state, rule) {
                alerts.push(alert);
            }
        }

        alerts
    }

    /// Check for protocol-level security issues
    fn check_protocol_alerts(
        &self,
        state: &ProtocolState,
        dns_state: Option<&DnsState>,
    ) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();

        let Some(dns) = dns_state else {
            return alerts;
        };

        // DNS tunneling detected
        if dns.tunneling_detected {
            alerts.push(ProtocolAlert::new(
                "DNS tunneling detected - potential data exfiltration",
                DetectionType::DataExfiltration,
                Severity::High,
            ).with_classtype("attempted-exfiltration")
             .with_metadata("detection", "tunneling"));
        }

        // DGA indicators (high NXDOMAIN ratio)
        if dns.check_dga_indicators() {
            alerts.push(ProtocolAlert::new(
                format!("Potential DGA activity - {} NXDOMAIN out of {} queries",
                    dns.nxdomain_count, dns.query_count),
                DetectionType::Malware,
                Severity::High,
            ).with_classtype("trojan-activity")
             .with_metadata("nxdomain_count", dns.nxdomain_count.to_string())
             .with_metadata("query_count", dns.query_count.to_string()));
        }

        // Suspicious TLD domains
        for domain in &dns.suspicious_domains {
            alerts.push(ProtocolAlert::new(
                format!("Query to suspicious TLD: {}", domain),
                DetectionType::MaliciousDomain,
                Severity::Medium,
            ).with_classtype("bad-unknown")
             .with_metadata("domain", domain.clone()));
        }

        // High query rate (potential DoS or enumeration)
        if dns.query_count > 100 {
            alerts.push(ProtocolAlert::new(
                format!("High DNS query rate: {} queries", dns.query_count),
                DetectionType::DoS,
                Severity::Low,
            ).with_classtype("attempted-dos")
             .with_metadata("query_count", dns.query_count.to_string()));
        }

        alerts
    }

    /// Match a single rule against DNS state
    fn match_rule(&self, state: &ProtocolState, rule: &Rule) -> Option<ProtocolAlert> {
        // Check DNS-specific keywords
        for option in &rule.options {
            match option {
                // Check dns.query
                RuleOption::Raw { keyword, value } if keyword == "dns.query" => {
                    let query = state.get_buffer("dns.query")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(query, pattern.as_bytes(), true) {
                            return None;
                        }
                    }
                }

                // Check dns.opcode
                RuleOption::Raw { keyword, value } if keyword == "dns.opcode" => {
                    let opcode = state.get_buffer("dns.opcode")?;
                    if let Some(pattern) = value {
                        if let Ok(expected) = pattern.parse::<u8>() {
                            if opcode.first() != Some(&expected) {
                                return None;
                            }
                        }
                    }
                }

                // Check dns.rcode
                RuleOption::Raw { keyword, value } if keyword == "dns.rcode" => {
                    let rcode = state.get_buffer("dns.rcode")?;
                    if let Some(pattern) = value {
                        if let Ok(expected) = pattern.parse::<u8>() {
                            if rcode.first() != Some(&expected) {
                                return None;
                            }
                        }
                    }
                }

                // Content matches on any buffer
                RuleOption::Content(cm) => {
                    if !self.check_content_match(state, cm) {
                        return None;
                    }
                }

                _ => {}
            }
        }

        // All conditions matched
        Some(ProtocolAlert::from_rule(
            rule.sid,
            &rule.msg,
            self.rule_to_detection_type(rule),
            priority_to_severity(rule.priority),
            rule.classtype.clone(),
        ))
    }

    /// Check content match against DNS buffers
    fn check_content_match(&self, state: &ProtocolState, cm: &ContentMatch) -> bool {
        let buffers = [
            "dns.query",
            "dns.rrname",
            "dns.rrtype",
        ];

        for buf_name in buffers {
            if let Some(buf) = state.get_buffer(buf_name) {
                let matched = self.content_matches(buf, &cm.pattern, cm.nocase);
                if cm.negated {
                    if matched {
                        return false;
                    }
                } else if matched {
                    return true;
                }
            }
        }

        cm.negated
    }

    /// Check if content matches pattern
    fn content_matches(&self, haystack: &[u8], needle: &[u8], nocase: bool) -> bool {
        if needle.is_empty() {
            return true;
        }
        if haystack.len() < needle.len() {
            return false;
        }

        if nocase {
            let haystack_lower: Vec<u8> = haystack.iter().map(|b| b.to_ascii_lowercase()).collect();
            let needle_lower: Vec<u8> = needle.iter().map(|b| b.to_ascii_lowercase()).collect();
            haystack_lower.windows(needle_lower.len()).any(|w| w == needle_lower.as_slice())
        } else {
            haystack.windows(needle.len()).any(|w| w == needle)
        }
    }

    /// Determine detection type from rule
    fn rule_to_detection_type(&self, rule: &Rule) -> DetectionType {
        if let Some(ref classtype) = rule.classtype {
            match classtype.as_str() {
                "trojan-activity" => return DetectionType::Malware,
                "attempted-recon" => return DetectionType::NetworkScan,
                "bad-unknown" => return DetectionType::ProtocolAnomaly,
                "policy-violation" => return DetectionType::PolicyViolation,
                _ => {}
            }
        }

        let msg_lower = rule.msg.to_lowercase();

        if msg_lower.contains("tunneling") || msg_lower.contains("tunnel") {
            DetectionType::DataExfiltration
        } else if msg_lower.contains("dga") || msg_lower.contains("malware") {
            DetectionType::Malware
        } else if msg_lower.contains("c2") || msg_lower.contains("command") {
            DetectionType::C2
        } else if msg_lower.contains("exfil") {
            DetectionType::DataExfiltration
        } else {
            DetectionType::SignatureMatch
        }
    }
}

impl Default for DnsMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_matches() {
        let matcher = DnsMatcher::new();

        assert!(matcher.content_matches(b"example.com", b"example", false));
        assert!(matcher.content_matches(b"EXAMPLE.COM", b"example", true));
        assert!(!matcher.content_matches(b"example.com", b"EXAMPLE", false));
    }

    #[test]
    fn test_dga_detection() {
        let matcher = DnsMatcher::new();
        let state = ProtocolState::new();

        let mut dns_state = DnsState::new();
        dns_state.query_count = 20;
        dns_state.nxdomain_count = 15; // 75% NXDOMAIN

        let alerts = matcher.check_protocol_alerts(&state, Some(&dns_state));
        assert!(alerts.iter().any(|a| a.msg.contains("DGA")));
    }

    #[test]
    fn test_tunneling_detection() {
        let matcher = DnsMatcher::new();
        let state = ProtocolState::new();

        let mut dns_state = DnsState::new();
        dns_state.tunneling_detected = true;

        let alerts = matcher.check_protocol_alerts(&state, Some(&dns_state));
        assert!(alerts.iter().any(|a| a.msg.contains("tunneling")));
    }
}
