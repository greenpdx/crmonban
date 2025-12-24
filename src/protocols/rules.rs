//! Protocol-specific rule sets with Aho-Corasick pre-filtering
//!
//! Provides efficient rule matching by pre-filtering candidate rules
//! using Aho-Corasick multi-pattern matching.

use std::collections::HashMap;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use crate::signatures::ast::{Protocol, Rule, RuleOption, ContentMatch};

/// Pre-indexed rules for a specific protocol
///
/// Uses Aho-Corasick for fast content pre-filtering and provides
/// keyword-based rule lookup for protocol-specific matching.
pub struct ProtocolRuleSet<'a> {
    /// Protocol these rules apply to
    pub protocol: Protocol,

    /// All rules for this protocol
    rules: Vec<&'a Rule>,

    /// Aho-Corasick automaton for content pre-filtering
    content_matcher: Option<AhoCorasick>,

    /// Pattern index → Rule indices mapping
    /// Each pattern may appear in multiple rules
    pattern_to_rules: Vec<Vec<usize>>,

    /// Rules indexed by SID for fast lookup
    by_sid: HashMap<u32, usize>,

    /// Rules grouped by keyword used
    /// e.g., "smb.share" → [rule indices that use smb.share]
    by_keyword: HashMap<&'static str, Vec<usize>>,

    /// Rules without content patterns (must always be checked)
    no_content_rules: Vec<usize>,
}

impl<'a> ProtocolRuleSet<'a> {
    /// Build rule set from filtered rules for a specific protocol
    pub fn new(protocol: Protocol, rules: Vec<&'a Rule>) -> Self {
        let mut by_sid = HashMap::new();
        let mut by_keyword: HashMap<&'static str, Vec<usize>> = HashMap::new();
        let mut no_content_rules = Vec::new();

        // Collect all unique content patterns for Aho-Corasick
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut pattern_to_rules: Vec<Vec<usize>> = Vec::new();
        let mut pattern_map: HashMap<Vec<u8>, usize> = HashMap::new();

        for (rule_idx, rule) in rules.iter().enumerate() {
            // Index by SID
            by_sid.insert(rule.sid, rule_idx);

            // Index by keywords
            for option in &rule.options {
                let keyword = option_to_keyword(option);
                if let Some(kw) = keyword {
                    by_keyword
                        .entry(kw)
                        .or_insert_with(Vec::new)
                        .push(rule_idx);
                }
            }

            // Collect content patterns
            let content_patterns: Vec<&ContentMatch> = rule.content_patterns();

            if content_patterns.is_empty() {
                // Rule has no content patterns, must always be checked
                no_content_rules.push(rule_idx);
            } else {
                // Add patterns to Aho-Corasick
                for cm in content_patterns {
                    if cm.negated {
                        // Negated patterns don't help with pre-filtering
                        continue;
                    }

                    let pattern = if cm.nocase {
                        // Lowercase for case-insensitive matching
                        cm.pattern.to_ascii_lowercase()
                    } else {
                        cm.pattern.clone()
                    };

                    if let Some(&pat_idx) = pattern_map.get(&pattern) {
                        // Pattern already exists, add rule to its list
                        pattern_to_rules[pat_idx].push(rule_idx);
                    } else {
                        // New pattern
                        let pat_idx = patterns.len();
                        pattern_map.insert(pattern.clone(), pat_idx);
                        patterns.push(pattern);
                        pattern_to_rules.push(vec![rule_idx]);
                    }
                }
            }
        }

        // Build Aho-Corasick automaton
        let content_matcher = if patterns.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostFirst)
                    .build(&patterns)
                    .expect("Failed to build Aho-Corasick automaton")
            )
        };

        Self {
            protocol,
            rules,
            content_matcher,
            pattern_to_rules,
            by_sid,
            by_keyword,
            no_content_rules,
        }
    }

    /// Get candidate rules based on content pre-filtering
    ///
    /// Uses Aho-Corasick to quickly find rules that might match,
    /// then returns those rules for full verification.
    pub fn candidates_for_content(&self, content: &[u8]) -> Vec<&'a Rule> {
        let mut candidate_indices: std::collections::HashSet<usize> = std::collections::HashSet::new();

        // Always include rules without content patterns
        for &idx in &self.no_content_rules {
            candidate_indices.insert(idx);
        }

        // Use Aho-Corasick to find matching patterns
        if let Some(ref matcher) = self.content_matcher {
            // Also try lowercase for case-insensitive matching
            let content_lower = content.to_ascii_lowercase();

            for mat in matcher.find_iter(content) {
                for &rule_idx in &self.pattern_to_rules[mat.pattern().as_usize()] {
                    candidate_indices.insert(rule_idx);
                }
            }

            // Also search lowercase version
            for mat in matcher.find_iter(&content_lower) {
                for &rule_idx in &self.pattern_to_rules[mat.pattern().as_usize()] {
                    candidate_indices.insert(rule_idx);
                }
            }
        }

        candidate_indices
            .into_iter()
            .map(|idx| self.rules[idx])
            .collect()
    }

    /// Get rules that use a specific keyword
    ///
    /// Useful for targeted matching when a specific buffer is parsed
    /// e.g., only check rules with "smb.share" when share name is parsed
    pub fn rules_with_keyword(&self, keyword: &str) -> impl Iterator<Item = &'a Rule> {
        self.by_keyword
            .get(keyword)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
            .iter()
            .map(|&idx| self.rules[idx])
    }

    /// Get rule by SID
    pub fn get_by_sid(&self, sid: u32) -> Option<&'a Rule> {
        self.by_sid.get(&sid).map(|&idx| self.rules[idx])
    }

    /// Iterate all rules in this set
    pub fn iter(&self) -> impl Iterator<Item = &'a Rule> {
        self.rules.iter().copied()
    }

    /// Number of rules in this set
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Get rules without content patterns (must always check)
    pub fn no_content_rules(&self) -> impl Iterator<Item = &'a Rule> {
        self.no_content_rules.iter().map(|&idx| self.rules[idx])
    }

    /// Get all keywords used in this rule set
    pub fn used_keywords(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.by_keyword.keys().copied()
    }
}

/// Map RuleOption to keyword string for indexing
fn option_to_keyword(option: &RuleOption) -> Option<&'static str> {
    match option {
        // HTTP keywords
        RuleOption::HttpUri => Some("http.uri"),
        RuleOption::HttpRawUri => Some("http.raw_uri"),
        RuleOption::HttpMethod => Some("http.method"),
        RuleOption::HttpHeader => Some("http.header"),
        RuleOption::HttpRawHeader => Some("http.raw_header"),
        RuleOption::HttpCookie => Some("http.cookie"),
        RuleOption::HttpUserAgent => Some("http.user_agent"),
        RuleOption::HttpHost => Some("http.host"),
        RuleOption::HttpRawHost => Some("http.raw_host"),
        RuleOption::HttpClientBody => Some("http.request_body"),
        RuleOption::HttpServerBody => Some("http.response_body"),
        RuleOption::HttpStatCode => Some("http.stat_code"),
        RuleOption::HttpStatMsg => Some("http.stat_msg"),

        // DNS keywords
        RuleOption::DnsQuery => Some("dns.query"),
        RuleOption::DnsAnswer => Some("dns.answer"),

        // TLS keywords
        RuleOption::TlsSni => Some("tls.sni"),
        RuleOption::TlsCertSubject => Some("tls.cert_subject"),
        RuleOption::TlsCertIssuer => Some("tls.cert_issuer"),
        RuleOption::Ja3Hash => Some("ja3.hash"),
        RuleOption::Ja3sHash => Some("ja3s.hash"),

        // SSH keywords
        RuleOption::SshProto => Some("ssh.proto"),
        RuleOption::SshSoftware => Some("ssh.software"),
        RuleOption::SshHassh => Some("ssh.hassh"),
        RuleOption::SshHasshServer => Some("ssh.hassh.server"),

        // File keywords
        RuleOption::FileData => Some("file.data"),
        RuleOption::Filename => Some("file.name"),
        RuleOption::Filemagic => Some("file.magic"),
        RuleOption::FileMd5 => Some("file.md5"),
        RuleOption::FileSha256 => Some("file.sha256"),

        // Other keywords don't map to sticky buffers
        _ => None,
    }
}

/// Builder for creating ProtocolRuleSet from all rules
pub struct RuleSetBuilder<'a> {
    rules: &'a [Rule],
}

impl<'a> RuleSetBuilder<'a> {
    /// Create builder from all rules
    pub fn new(rules: &'a [Rule]) -> Self {
        Self { rules }
    }

    /// Build rule set for a specific protocol
    pub fn build_for_protocol(&self, protocol: Protocol) -> ProtocolRuleSet<'a> {
        let filtered: Vec<&Rule> = self.rules
            .iter()
            .filter(|r| r.protocol == protocol || r.protocol == Protocol::Any)
            .filter(|r| r.enabled)
            .collect();

        ProtocolRuleSet::new(protocol, filtered)
    }

    /// Build rule sets for all protocols
    pub fn build_all(&self) -> HashMap<Protocol, ProtocolRuleSet<'a>> {
        let protocols = [
            Protocol::Http,
            Protocol::Dns,
            Protocol::Tls,
            Protocol::Ssh,
            Protocol::Smtp,
            Protocol::Smb,
            Protocol::Ftp,
            Protocol::Dcerpc,
            Protocol::Dhcp,
            Protocol::Ntp,
        ];

        protocols
            .into_iter()
            .map(|proto| (proto, self.build_for_protocol(proto)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::ast::{Rule, RuleOption, ContentMatch, Action, IpSpec, PortSpec, Direction};

    fn make_test_rule(sid: u32, content: &[u8], protocol: Protocol) -> Rule {
        Rule {
            id: sid,
            enabled: true,
            action: Action::Alert,
            protocol,
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            direction: Direction::ToServer,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            options: vec![
                RuleOption::Sid(sid),
                RuleOption::Msg(format!("Test rule {}", sid)),
                RuleOption::Content(ContentMatch {
                    pattern: content.to_vec(),
                    negated: false,
                    nocase: false,
                    ..Default::default()
                }),
            ],
            sid,
            rev: 1,
            msg: format!("Test rule {}", sid),
            classtype: None,
            priority: 3,
            references: vec![],
            source_file: None,
            source_line: None,
        }
    }

    #[test]
    fn test_rule_set_creation() {
        let rules = vec![
            make_test_rule(1, b"test", Protocol::Http),
            make_test_rule(2, b"example", Protocol::Http),
        ];

        let refs: Vec<&Rule> = rules.iter().collect();
        let rule_set = ProtocolRuleSet::new(Protocol::Http, refs);

        assert_eq!(rule_set.len(), 2);
        assert!(!rule_set.is_empty());
    }

    #[test]
    fn test_content_filtering() {
        let rules = vec![
            make_test_rule(1, b"malware", Protocol::Http),
            make_test_rule(2, b"attack", Protocol::Http),
            make_test_rule(3, b"benign", Protocol::Http),
        ];

        let refs: Vec<&Rule> = rules.iter().collect();
        let rule_set = ProtocolRuleSet::new(Protocol::Http, refs);

        // Content with "malware" should return rule 1
        let candidates = rule_set.candidates_for_content(b"this contains malware in it");
        assert!(candidates.iter().any(|r| r.sid == 1));

        // Content with "attack" should return rule 2
        let candidates = rule_set.candidates_for_content(b"attack detected");
        assert!(candidates.iter().any(|r| r.sid == 2));
    }

    #[test]
    fn test_sid_lookup() {
        let rules = vec![
            make_test_rule(1001, b"test", Protocol::Http),
            make_test_rule(1002, b"test2", Protocol::Http),
        ];

        let refs: Vec<&Rule> = rules.iter().collect();
        let rule_set = ProtocolRuleSet::new(Protocol::Http, refs);

        assert!(rule_set.get_by_sid(1001).is_some());
        assert!(rule_set.get_by_sid(1002).is_some());
        assert!(rule_set.get_by_sid(9999).is_none());
    }

    #[test]
    fn test_builder() {
        let rules = vec![
            make_test_rule(1, b"test", Protocol::Http),
            make_test_rule(2, b"dns", Protocol::Dns),
            make_test_rule(3, b"any", Protocol::Any),
        ];

        let builder = RuleSetBuilder::new(&rules);

        let http_rules = builder.build_for_protocol(Protocol::Http);
        // Should include HTTP rule and Any rule
        assert_eq!(http_rules.len(), 2);

        let dns_rules = builder.build_for_protocol(Protocol::Dns);
        // Should include DNS rule and Any rule
        assert_eq!(dns_rules.len(), 2);
    }
}
