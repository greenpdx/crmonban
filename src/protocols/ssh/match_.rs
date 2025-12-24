//! SSH rule matching

use crate::core::Severity;
use crate::protocols::{ProtocolState, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::alerts::priority_to_severity;
use crate::signatures::ast::{Rule, RuleOption, ContentMatch};
use crmonban_types::DetectionType;
use super::state::SshState;
use super::types::*;

pub struct SshMatcher;

impl SshMatcher {
    pub fn new() -> Self { Self }

    pub fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        let ssh_state = state.get_inner::<SshState>();

        // Protocol-level alerts
        alerts.extend(self.check_protocol_alerts(state, ssh_state));

        // Rule matching
        for rule in rules.iter() {
            if let Some(alert) = self.match_rule(state, rule) {
                alerts.push(alert);
            }
        }

        alerts
    }

    fn check_protocol_alerts(&self, _state: &ProtocolState, ssh_state: Option<&SshState>) -> Vec<ProtocolAlert> {
        let mut alerts = Vec::new();
        let Some(ssh) = ssh_state else { return alerts; };

        // SSH-1 protocol detection
        if ssh.ssh1_detected {
            alerts.push(ProtocolAlert::new(
                "Deprecated SSH-1 protocol detected".to_string(),
                DetectionType::SshVersionVulnerable,
                Severity::Critical,
            ).with_classtype("protocol-command-decode")
             .with_metadata("protocol_version", "1".to_string()));
        }

        // Suspicious HASSH fingerprint
        if ssh.suspicious_hassh {
            let hash = ssh.client_hassh.as_ref()
                .or(ssh.server_hassh.as_ref())
                .cloned()
                .unwrap_or_default();
            alerts.push(ProtocolAlert::new(
                format!("Suspicious SSH HASSH fingerprint: {}", hash),
                DetectionType::SshKnownMalwareHashsh,
                Severity::High,
            ).with_classtype("trojan-activity")
             .with_metadata("hassh", hash));
        }

        // Suspicious software
        if ssh.suspicious_software {
            let software = ssh.client_version.as_ref()
                .map(|v| v.software.clone())
                .unwrap_or_default();
            alerts.push(ProtocolAlert::new(
                format!("Suspicious SSH client software: {}", software),
                DetectionType::NetworkScan,
                Severity::Medium,
            ).with_classtype("attempted-recon")
             .with_metadata("software", software));
        }

        // Weak algorithms
        if !ssh.weak_algorithms.is_empty() {
            alerts.push(ProtocolAlert::new(
                format!("Weak SSH algorithms detected: {}", ssh.weak_algorithms.join(", ")),
                DetectionType::PolicyViolation,
                Severity::Medium,
            ).with_classtype("policy-violation")
             .with_metadata("algorithms", ssh.weak_algorithms.join(",")));
        }

        // Vulnerable version
        if ssh.vulnerable_version && !ssh.cves.is_empty() {
            let version = ssh.client_version.as_ref()
                .or(ssh.server_version.as_ref())
                .map(|v| v.software.clone())
                .unwrap_or_default();
            alerts.push(ProtocolAlert::new(
                format!("Vulnerable SSH version: {} (CVEs: {})", version, ssh.cves.join(", ")),
                DetectionType::SshVersionVulnerable,
                Severity::High,
            ).with_classtype("attempted-admin")
             .with_metadata("cves", ssh.cves.join(","))
             .with_metadata("version", version));
        }

        // Brute force attempt (within single flow)
        if ssh.auth_failures >= 3 {
            alerts.push(ProtocolAlert::new(
                format!("SSH brute force attempt: {} failures", ssh.auth_failures),
                DetectionType::SshBruteForce,
                Severity::High,
            ).with_classtype("attempted-admin")
             .with_metadata("failures", ssh.auth_failures.to_string())
             .with_metadata("username", ssh.current_username.clone().unwrap_or_default()));
        }

        // Root/admin login attempt
        if let Some(ref username) = ssh.current_username {
            if COMMON_BRUTE_USERNAMES.iter().take(3).any(|u| u == username) { // root, admin, administrator
                alerts.push(ProtocolAlert::new(
                    format!("SSH privileged account login attempt: {}", username),
                    DetectionType::SshRootLogin,
                    Severity::Medium,
                ).with_classtype("attempted-admin")
                 .with_metadata("username", username.clone()));
            }
        }

        alerts
    }

    fn match_rule(&self, state: &ProtocolState, rule: &Rule) -> Option<ProtocolAlert> {
        for option in &rule.options {
            match option {
                RuleOption::Raw { keyword, value } if keyword == "ssh.proto" || keyword == "ssh.protoversion" => {
                    let proto = state.get_buffer("ssh.proto")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(proto, pattern.as_bytes(), false) { return None; }
                    }
                }
                RuleOption::Raw { keyword, value } if keyword == "ssh.software" || keyword == "ssh.softwareversion" => {
                    let software = state.get_buffer("ssh.software")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(software, pattern.as_bytes(), true) { return None; }
                    }
                }
                RuleOption::Raw { keyword, value } if keyword == "ssh.hassh" => {
                    let hassh = state.get_buffer("ssh.hassh")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(hassh, pattern.as_bytes(), false) { return None; }
                    }
                }
                RuleOption::Raw { keyword, value } if keyword == "ssh.hassh.server" => {
                    let hassh = state.get_buffer("ssh.hassh.server")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(hassh, pattern.as_bytes(), false) { return None; }
                    }
                }
                RuleOption::Raw { keyword, value } if keyword == "ssh.hassh.string" => {
                    let hassh_str = state.get_buffer("ssh.hassh.string")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(hassh_str, pattern.as_bytes(), true) { return None; }
                    }
                }
                RuleOption::Raw { keyword, value } if keyword == "ssh.hassh.server.string" => {
                    let hassh_str = state.get_buffer("ssh.hassh.server.string")?;
                    if let Some(pattern) = value {
                        if !self.content_matches(hassh_str, pattern.as_bytes(), true) { return None; }
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
        // Check all SSH buffers for content match
        for buf in ["ssh.software", "ssh.hassh", "ssh.hassh.string", "ssh.hassh.server", "ssh.hassh.server.string"] {
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

impl Default for SshMatcher {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_matching() {
        let matcher = SshMatcher::new();
        assert!(matcher.content_matches(b"OpenSSH_8.9p1", b"OpenSSH", true));
        assert!(matcher.content_matches(b"OpenSSH_8.9p1", b"openssh", true));
        assert!(!matcher.content_matches(b"OpenSSH_8.9p1", b"openssh", false));
    }

    #[test]
    fn test_protocol_alerts() {
        let matcher = SshMatcher::new();
        let mut state = ProtocolState::new();

        let mut ssh = SshState::new();
        ssh.ssh1_detected = true;
        state.set_inner(ssh);

        let rules = ProtocolRuleSet::empty();
        let alerts = matcher.match_rules(&state, &rules);

        assert!(alerts.iter().any(|a| a.description.contains("SSH-1")));
    }
}
