//! HTTP rule matching
//!
//! Matches Suricata rules against parsed HTTP protocol data.

use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::signatures::ast::{Rule, RuleOption, ContentMatch};
use crate::types::DetectionType;
use super::state::HttpState;

/// HTTP rule matcher
pub struct HttpMatcher;

impl HttpMatcher {
    /// Create new HTTP matcher
    pub fn new() -> Self {
        Self
    }

    /// Match Suricata rules against HTTP state
    pub fn match_rules(
        &self,
        state: &ProtocolState,
        rules: &ProtocolRuleSet<'_>,
    ) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();

        // Get HTTP-specific state
        let http_state = state.get_inner::<HttpState>();

        // Generate protocol-level alerts first
        alerts.extend(self.check_protocol_alerts(state, http_state));

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
        _state: &ProtocolState,
        http_state: Option<&HttpState>,
    ) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();

        let Some(http) = http_state else {
            return alerts;
        };

        // Path traversal detection
        if http.path_traversal {
            alerts.push(ProtocolAlert::new(
                "HTTP path traversal attempt detected",
                DetectionType::ExploitAttempt,
                Severity::High,
            ).with_classtype("web-application-attack")
             .with_metadata("attack_type", "path_traversal"));
        }

        // SQL injection detection
        if http.sql_injection {
            alerts.push(ProtocolAlert::new(
                "HTTP SQL injection attempt detected",
                DetectionType::ExploitAttempt,
                Severity::High,
            ).with_classtype("web-application-attack")
             .with_metadata("attack_type", "sql_injection"));
        }

        // XSS detection
        if http.xss_detected {
            alerts.push(ProtocolAlert::new(
                "HTTP XSS attempt detected",
                DetectionType::ExploitAttempt,
                Severity::High,
            ).with_classtype("web-application-attack")
             .with_metadata("attack_type", "xss"));
        }

        // Suspicious user agent
        if http.suspicious_ua {
            if let Some(ref ua) = http.last_user_agent {
                alerts.push(ProtocolAlert::new(
                    format!("Suspicious HTTP User-Agent detected: {}", ua),
                    DetectionType::NetworkScan,
                    Severity::Medium,
                ).with_classtype("attempted-recon")
                 .with_metadata("user_agent", ua.clone()));
            }
        }

        // Error rate anomaly (many 4xx/5xx responses)
        if http.error_count > 10 && http.response_count > 0 {
            let error_rate = (http.error_count as f64 / http.response_count as f64) * 100.0;
            if error_rate > 50.0 {
                alerts.push(ProtocolAlert::new(
                    format!("High HTTP error rate: {:.1}%", error_rate),
                    DetectionType::ProtocolAnomaly,
                    Severity::Low,
                ).with_classtype("misc-activity")
                 .with_metadata("error_rate", format!("{:.1}%", error_rate))
                 .with_metadata("error_count", http.error_count.to_string()));
            }
        }

        alerts
    }

    /// Match a single rule against HTTP state
    fn match_rule(&self, state: &ProtocolState, rule: &Rule) -> Option<ProtocolAlert> {
        // Check HTTP-specific keywords
        for option in &rule.options {
            match option {
                // Check http.uri
                RuleOption::Raw { keyword, value } if keyword == "http.uri" => {
                    let uri = state.get_buffer("http.uri")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(uri, pattern.as_bytes(), false) {
                            return None;
                        }
                    }
                }

                // Check http.method
                RuleOption::Raw { keyword, value } if keyword == "http.method" => {
                    let method = state.get_buffer("http.method")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(method, pattern.as_bytes(), true) {
                            return None;
                        }
                    }
                }

                // Check http.host
                RuleOption::Raw { keyword, value } if keyword == "http.host" => {
                    let host = state.get_buffer("http.host")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(host, pattern.as_bytes(), true) {
                            return None;
                        }
                    }
                }

                // Check http.user_agent
                RuleOption::Raw { keyword, value } if keyword == "http.user_agent" => {
                    let ua = state.get_buffer("http.user_agent")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(ua, pattern.as_bytes(), true) {
                            return None;
                        }
                    }
                }

                // Check http.stat_code
                RuleOption::Raw { keyword, value } if keyword == "http.stat_code" => {
                    let status = state.get_buffer("http.stat_code")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(status, pattern.as_bytes(), false) {
                            return None;
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

    /// Check content match against HTTP buffers
    fn check_content_match(&self, state: &ProtocolState, cm: &ContentMatch) -> bool {
        // Try each HTTP buffer
        let buffers = [
            "http.uri",
            "http.uri.raw",
            "http.method",
            "http.host",
            "http.user_agent",
            "http.cookie",
            "http.request_body",
            "http.response_body",
            "http.server",
            "http.content_type",
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

        // Negated content that wasn't found is a match
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
        // Check classtype first
        if let Some(ref classtype) = rule.classtype {
            match classtype.as_str() {
                "web-application-attack" => return DetectionType::WebAttack,
                "web-application-activity" => return DetectionType::SignatureMatch,
                "attempted-recon" => return DetectionType::NetworkScan,
                "trojan-activity" => return DetectionType::Malware,
                "bad-unknown" => return DetectionType::ProtocolAnomaly,
                _ => {}
            }
        }

        // Check rule message for hints
        let msg_lower = rule.msg.to_lowercase();

        if msg_lower.contains("sql injection") || msg_lower.contains("sqli") {
            DetectionType::SqlInjection
        } else if msg_lower.contains("xss") || msg_lower.contains("script") {
            DetectionType::Xss
        } else if msg_lower.contains("traversal") || msg_lower.contains("lfi") {
            DetectionType::PathTraversal
        } else if msg_lower.contains("scanner") || msg_lower.contains("recon") {
            DetectionType::NetworkScan
        } else if msg_lower.contains("malware") || msg_lower.contains("trojan") {
            DetectionType::Malware
        } else if msg_lower.contains("bot") || msg_lower.contains("c2") {
            DetectionType::C2
        } else {
            DetectionType::SignatureMatch
        }
    }
}

impl Default for HttpMatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_matches() {
        let matcher = HttpMatcher::new();

        assert!(matcher.content_matches(b"hello world", b"world", false));
        assert!(!matcher.content_matches(b"hello world", b"WORLD", false));
        assert!(matcher.content_matches(b"hello world", b"WORLD", true));
        assert!(!matcher.content_matches(b"hello", b"hello world", false));
    }

    #[test]
    fn test_path_traversal_detection() {
        let matcher = HttpMatcher::new();
        let state = ProtocolState::new();

        let mut http_state = HttpState::new();
        http_state.path_traversal = true;

        let alerts = matcher.check_protocol_alerts(&state, Some(&http_state));
        assert!(alerts.iter().any(|a| a.msg.contains("path traversal")));
    }

    #[test]
    fn test_sql_injection_detection() {
        let matcher = HttpMatcher::new();
        let state = ProtocolState::new();

        let mut http_state = HttpState::new();
        http_state.sql_injection = true;

        let alerts = matcher.check_protocol_alerts(&state, Some(&http_state));
        assert!(alerts.iter().any(|a| a.msg.contains("SQL injection")));
    }
}
