//! SMTP rule matching

use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::signatures::ast::{Rule, RuleOption, ContentMatch};
use crate::types::DetectionType;
use super::state::SmtpState;

pub struct SmtpMatcher;

impl SmtpMatcher {
    pub fn new() -> Self { Self }

    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        let smtp_state = state.get_inner::<SmtpState>();

        // Protocol-level alerts
        alerts.extend(self.check_protocol_alerts(state, smtp_state));

        // Rule matching
        for rule in rules.iter() {
            if let Some(alert) = self.match_rule(state, rule) {
                alerts.push(alert);
            }
        }

        alerts
    }

    fn check_protocol_alerts(&self, _state: &ProtocolState, smtp_state: Option<&SmtpState>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        let Some(smtp) = smtp_state else { return alerts; };

        // Dangerous attachments
        if !smtp.dangerous_attachments.is_empty() {
            alerts.push(ProtocolAlert::new(
                format!("Dangerous email attachment: {}", smtp.dangerous_attachments.join(", ")),
                DetectionType::SmtpMalwareAttachment,
                Severity::High,
            ).with_classtype("trojan-activity")
             .with_metadata("attachments", smtp.dangerous_attachments.join(",")));
        }

        // Spam indicators
        if !smtp.spam_indicators.is_empty() {
            alerts.push(ProtocolAlert::new(
                format!("Spam indicators detected: {}", smtp.spam_indicators.join(", ")),
                DetectionType::SmtpSpam,
                Severity::Medium,
            ).with_classtype("policy-violation")
             .with_metadata("indicators", smtp.spam_indicators.join(",")));
        }

        // Phishing indicators
        if !smtp.phishing_indicators.is_empty() {
            alerts.push(ProtocolAlert::new(
                format!("Phishing indicators detected: {}", smtp.phishing_indicators.join(", ")),
                DetectionType::SmtpPhishing,
                Severity::High,
            ).with_classtype("attempted-user")
             .with_metadata("indicators", smtp.phishing_indicators.join(",")));
        }

        // Spoofing
        if smtp.spoofing_detected {
            alerts.push(ProtocolAlert::new(
                "Email spoofing detected (SPF/DKIM/DMARC failure)".to_string(),
                DetectionType::SmtpSpoofing,
                Severity::High,
            ).with_classtype("attempted-user"));
        }

        // Auth brute force
        if smtp.auth_failures >= 3 {
            alerts.push(ProtocolAlert::new(
                format!("SMTP authentication brute force: {} failures", smtp.auth_failures),
                DetectionType::SmtpAuthBruteForce,
                Severity::High,
            ).with_classtype("attempted-admin")
             .with_metadata("failures", smtp.auth_failures.to_string())
             .with_metadata("username", smtp.auth_username.clone().unwrap_or_default()));
        }

        // Mass mailer detection (within single flow)
        if smtp.transaction_count >= 10 || smtp.total_recipients >= 50 {
            alerts.push(ProtocolAlert::new(
                format!("Mass mailer detected: {} transactions, {} recipients",
                       smtp.transaction_count, smtp.total_recipients),
                DetectionType::SmtpMassMailer,
                Severity::Medium,
            ).with_classtype("policy-violation")
             .with_metadata("transactions", smtp.transaction_count.to_string())
             .with_metadata("recipients", smtp.total_recipients.to_string()));
        }

        // No TLS when credentials were sent
        if smtp.auth_username.is_some() && !smtp.using_tls {
            alerts.push(ProtocolAlert::new(
                "SMTP authentication without TLS - credentials may be exposed".to_string(),
                DetectionType::PolicyViolation,
                Severity::Medium,
            ).with_classtype("policy-violation"));
        }

        alerts
    }

    fn match_rule(&self, state: &ProtocolState, rule: &Rule) -> Option<ProtocolAlert> {
        for option in &rule.options {
            match option {
                RuleOption::Raw { keyword, value } if keyword == "smtp.mail_from" => {
                    let mail_from = state.get_buffer("smtp.mail_from")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(mail_from, pattern.as_bytes(), true) { return None; }
                    }
                }
                RuleOption::Raw { keyword, value } if keyword == "smtp.rcpt_to" => {
                    let rcpt_to = state.get_buffer("smtp.rcpt_to")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(rcpt_to, pattern.as_bytes(), true) { return None; }
                    }
                }
                RuleOption::Raw { keyword, value } if keyword == "smtp.helo" => {
                    let helo = state.get_buffer("smtp.helo")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(helo, pattern.as_bytes(), true) { return None; }
                    }
                }
                RuleOption::Raw { keyword, value } if keyword == "smtp.from" => {
                    let from = state.get_buffer("smtp.from")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(from, pattern.as_bytes(), true) { return None; }
                    }
                }
                RuleOption::Raw { keyword, value } if keyword == "smtp.to" => {
                    let to = state.get_buffer("smtp.to")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(to, pattern.as_bytes(), true) { return None; }
                    }
                }
                RuleOption::Raw { keyword, value } if keyword == "smtp.subject" => {
                    let subject = state.get_buffer("smtp.subject")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(subject, pattern.as_bytes(), true) { return None; }
                    }
                }
                RuleOption::Raw { keyword, value } if keyword == "file.name" => {
                    let filename = state.get_buffer("file.name")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(filename, pattern.as_bytes(), true) { return None; }
                    }
                }
                RuleOption::Content(cm) => {
                    if !self.check_content_match(state, cm) { return None; }
                }
                _ => {}
            }
        }

        Some(ProtocolAlert::from_rule(
            rule.sid,
            &rule.msg,
            DetectionType::SignatureMatch,
            priority_to_severity(rule.priority),
            rule.classtype.clone()
        ))
    }

    fn check_content_match(&self, state: &ProtocolState, cm: &ContentMatch) -> bool {
        // Check all SMTP buffers for content match
        for buf in ["smtp.mail_from", "smtp.rcpt_to", "smtp.from", "smtp.to", "smtp.subject", "smtp.body", "file.name", "file.data"] {
            if let Some(buf_data) = state.get_buffer(buf) {
                let matched = self.content_matches(buf_data, &cm.pattern, cm.nocase);
                if cm.negated {
                    if matched { return false; }
                } else if matched {
                    return true;
                }
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

impl Default for SmtpMatcher {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_matching() {
        let matcher = SmtpMatcher::new();
        assert!(matcher.content_matches(b"sender@example.com", b"example.com", true));
        assert!(matcher.content_matches(b"SENDER@EXAMPLE.COM", b"example.com", true));
        assert!(!matcher.content_matches(b"SENDER@EXAMPLE.COM", b"example.com", false));
    }

    #[test]
    fn test_protocol_alerts() {
        use crate::signatures::ast::Protocol;

        let matcher = SmtpMatcher::new();
        let mut state = ProtocolState::new();

        let mut smtp = SmtpState::new();
        smtp.dangerous_attachments.push("malware.exe".to_string());
        state.set_inner(smtp);

        let rules = ProtocolRuleSet::new(Protocol::Smtp, vec![]);
        let alerts = matcher.match_rules(&state, &rules);

        assert!(alerts.iter().any(|a| a.msg.contains("Dangerous")));
    }
}
