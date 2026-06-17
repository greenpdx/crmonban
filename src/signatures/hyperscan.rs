//! Hyperscan-accelerated signature matching
//!
//! Uses Intel Hyperscan library for high-performance multi-pattern matching.
//! Provides 10-50x speedup over Aho-Corasick for large rulesets.
//!
//! # Requirements
//!
//! Install libhyperscan-dev:
//! ```bash
//! # Debian/Ubuntu
//! apt install libhyperscan-dev
//!
//! # Fedora/RHEL
//! dnf install hyperscan-devel
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use hyperscan::prelude::*;
use hyperscan::PatternFlags as Flags;
use tracing::{info, warn};

use super::ast::{Rule, ContentMatch, RuleOption, Action, Reference};
use super::matcher::{FlowState, ProtocolContext, MatchResult};
use crate::types::Packet;

/// Pattern info stored alongside the Hyperscan database
#[derive(Debug, Clone)]
struct PatternInfo {
    /// Original rule ID (sid)
    rule_id: u32,
    /// Pattern index within the rule
    pattern_index: usize,
    /// Is this the "fast pattern" for prefiltering?
    is_fast_pattern: bool,
    /// Pattern is negated (must NOT match)
    negated: bool,
}

/// Substring search for `pattern` in `payload`, optionally case-insensitive.
fn payload_contains(payload: &[u8], pattern: &[u8], nocase: bool) -> bool {
    if pattern.is_empty() {
        return true;
    }
    if pattern.len() > payload.len() {
        return false;
    }
    if nocase {
        payload
            .windows(pattern.len())
            .any(|w| w.eq_ignore_ascii_case(pattern))
    } else {
        payload.windows(pattern.len()).any(|w| w == pattern)
    }
}

/// Minimum length of the content compiled into the hyperscan prefilter as a
/// rule's trigger. Short, common content (GET, Host, 200, ...) matches nearly
/// every packet and would nominate thousands of rules per packet; rules whose
/// most-specific content is shorter than this fall back to the always-check set.
const MIN_TRIGGER_LEN: usize = 2;

/// Hyperscan-accelerated matcher. The database holds ONE specific trigger pattern
/// per rule (a prefilter); a scan hit nominates the rule, and `verify_rule`
/// re-scans the payload to confirm ALL of the rule's content patterns. This keeps
/// the per-packet candidate set small even with tens of thousands of rules.
pub struct HyperscanMatcher {
    /// Compiled Hyperscan database (block mode)
    database: BlockDatabase,
    /// Scratch space for matching (per-thread in production)
    scratch: Scratch,
    /// Map from Hyperscan pattern ID to pattern info
    pattern_map: Vec<PatternInfo>,
    /// Map from rule ID to rule
    rules: HashMap<u32, Arc<Rule>>,
    /// Number of patterns compiled
    pattern_count: usize,
    /// Rules with no content long enough to be a trigger — verified every packet.
    always_check: Vec<u32>,
}

impl HyperscanMatcher {
    /// Create a new Hyperscan matcher from rules
    pub fn new(rules: &[Rule]) -> Result<Self, String> {
        let mut patterns: Vec<Pattern> = Vec::new();
        let mut pattern_map: Vec<PatternInfo> = Vec::new();
        let mut rule_map: HashMap<u32, Arc<Rule>> = HashMap::new();

        info!("Building Hyperscan database from {} rules", rules.len());

        let mut always_check: Vec<u32> = Vec::new();
        for rule in rules {
            if !rule.enabled {
                continue;
            }

            let rule_id = rule.sid;
            rule_map.insert(rule_id, Arc::new(rule.clone()));

            // Trigger = the longest POSITIVE content pattern. A rule with no
            // positive content can't be confirmed by this content-only matcher
            // (it needs flags/flow/pcre the hyperscan path doesn't evaluate), so
            // skip it rather than let verify_rule pass it on every packet. A
            // positive content shorter than the trigger minimum can't seed the
            // prefilter, so the rule falls back to always-check.
            let trigger = rule
                .options
                .iter()
                .filter_map(|o| match o {
                    RuleOption::Content(c) if !c.negated => Some(c),
                    _ => None,
                })
                .max_by_key(|c| c.pattern.len());
            let content = match trigger {
                None => continue,
                Some(c) if c.pattern.len() < MIN_TRIGGER_LEN => {
                    always_check.push(rule_id);
                    continue;
                }
                Some(c) => c,
            };

            let pattern_str = Self::content_to_pattern(content);
            if pattern_str.is_empty() {
                always_check.push(rule_id);
                continue;
            }

            let pattern_id = patterns.len();
            let mut flags = Flags::empty();
            if content.nocase {
                flags |= Flags::CASELESS;
            }
            flags |= Flags::SOM_LEFTMOST;

            // A single rule with an un-compilable pattern shouldn't fail the whole
            // database — fall back to always-check.
            let mut pat = match Pattern::new(pattern_str) {
                Ok(p) => p,
                Err(_) => {
                    always_check.push(rule_id);
                    continue;
                }
            };
            pat.flags = flags;
            pat.id = Some(pattern_id);
            patterns.push(pat);
            pattern_map.push(PatternInfo {
                rule_id,
                pattern_index: 0,
                is_fast_pattern: true,
                negated: false,
            });
        }

        if patterns.is_empty() {
            return Err("No patterns to compile".to_string());
        }

        info!("Compiling {} patterns into Hyperscan database", patterns.len());

        // Build the database from patterns
        let patterns_collection: Patterns = patterns.into();
        let database: BlockDatabase = patterns_collection
            .build()
            .map_err(|e| format!("Database build error: {}", e))?;

        // Create scratch space
        let scratch = database
            .alloc_scratch()
            .map_err(|e| format!("Scratch allocation error: {}", e))?;

        let pattern_count = pattern_map.len();
        info!(
            "Hyperscan database built: {} patterns, {} rules",
            pattern_count,
            rule_map.len()
        );

        Ok(Self {
            database,
            scratch,
            pattern_map,
            rules: rule_map,
            pattern_count,
            always_check,
        })
    }

    /// Convert ContentMatch to Hyperscan pattern string
    fn content_to_pattern(content: &ContentMatch) -> String {
        // Escape special regex characters and convert to literal pattern
        let mut pattern = String::new();
        for byte in &content.pattern {
            match *byte {
                // Escape regex metacharacters
                b'.' | b'^' | b'$' | b'*' | b'+' | b'?' | b'{' | b'}' | b'[' | b']'
                | b'\\' | b'|' | b'(' | b')' => {
                    pattern.push('\\');
                    pattern.push(*byte as char);
                }
                // Printable ASCII
                0x20..=0x7E => {
                    pattern.push(*byte as char);
                }
                // Non-printable: use hex escape
                _ => {
                    pattern.push_str(&format!("\\x{:02x}", byte));
                }
            }
        }
        pattern
    }

    /// Match packet payload against all patterns
    pub fn match_packet(
        &self,
        packet: &Packet,
        _proto_ctx: &ProtocolContext,
        _flow_state: &FlowState,
    ) -> Vec<MatchResult> {
        let payload = packet.payload();
        if payload.is_empty() {
            return Vec::new();
        }

        // Prefilter: a scan hit on a rule's trigger nominates that rule.
        let mut triggered: HashSet<u32> = HashSet::new();
        let result = self.database.scan(payload, &self.scratch, |id, _from, _to, _flags| {
            if let Some(info) = self.pattern_map.get(id as usize) {
                triggered.insert(info.rule_id);
            }
            Matching::Continue
        });
        if let Err(e) = result {
            warn!("Hyperscan scan error: {}", e);
            return Vec::new();
        }

        // Rules without a usable trigger are checked on every packet.
        for sid in &self.always_check {
            triggered.insert(*sid);
        }

        // Confirm each nominated rule by independently re-scanning the payload for
        // all of its content patterns.
        let mut results: Vec<MatchResult> = Vec::new();
        for rule_id in triggered {
            if let Some(rule) = self.rules.get(&rule_id) {
                if self.verify_rule(rule, payload) {
                    results.push(MatchResult {
                        rule_id,
                        sid: rule.sid,
                        msg: rule.msg.clone(),
                        classtype: rule.classtype.clone(),
                        priority: rule.priority,
                        action: rule.action,
                        references: rule.references.clone(),
                        timestamp: std::time::Instant::now(),
                        content_matches: Vec::new(),
                    });
                }
            }
        }

        results
    }

    /// Prefilter: return the rule IDs nominated by a payload scan (a trigger
    /// pattern hit) plus the always-check set. No verification — the caller
    /// (SignatureEngine) runs the full per-rule checks on these candidates.
    pub fn prefilter(&self, payload: &[u8]) -> HashSet<u32> {
        let mut triggered: HashSet<u32> = HashSet::new();
        if payload.is_empty() {
            return triggered;
        }
        let _ = self.database.scan(payload, &self.scratch, |id, _from, _to, _flags| {
            if let Some(info) = self.pattern_map.get(id as usize) {
                triggered.insert(info.rule_id);
            }
            Matching::Continue
        });
        for sid in &self.always_check {
            triggered.insert(*sid);
        }
        triggered
    }

    /// Confirm a nominated rule by re-scanning the payload for every content
    /// pattern: all non-negated content must be present and all negated content
    /// absent. Independent of which trigger fired in the prefilter.
    fn verify_rule(&self, rule: &Rule, payload: &[u8]) -> bool {
        for opt in &rule.options {
            if let RuleOption::Content(c) = opt {
                let present = payload_contains(payload, &c.pattern, c.nocase);
                if c.negated {
                    if present {
                        return false;
                    }
                } else if !present {
                    return false;
                }
            }
        }
        // TODO: distance/within and offset/depth constraints (as before, not yet
        // enforced).
        true
    }

    /// Get the number of patterns compiled
    pub fn pattern_count(&self) -> usize {
        self.pattern_count
    }

    /// Get the number of rules loaded
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get database info
    pub fn database_info(&self) -> String {
        format!(
            "Hyperscan database: {} patterns, {} rules",
            self.pattern_count,
            self.rules.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::ast::*;
    use crate::types::{Layer3, Layer4, Ipv4Info, TcpInfo};
    use std::net::Ipv4Addr;

    fn make_test_rule(sid: u32, pattern: &[u8], msg: &str) -> Rule {
        Rule {
            id: sid,
            enabled: true,
            action: Action::Alert,
            protocol: Protocol::Tcp,
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            direction: Direction::ToServer,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            options: vec![RuleOption::Content(ContentMatch {
                pattern: pattern.to_vec(),
                negated: false,
                nocase: false,
                offset: None,
                depth: None,
                distance: None,
                within: None,
                fast_pattern: true,
                rawbytes: false,
            })],
            sid,
            rev: 1,
            msg: msg.to_string(),
            classtype: None,
            priority: 2,
            references: Vec::new(),
            source_file: None,
            source_line: None,
        }
    }

    fn make_test_packet(payload: &[u8]) -> Packet {
        use chrono::Utc;
        use crate::types::Direction as PktDirection;

        let layer3 = Layer3::Ipv4(Ipv4Info {
            src_addr: Ipv4Addr::new(192, 168, 1, 1),
            dst_addr: Ipv4Addr::new(10, 0, 0, 1),
            protocol: 6, // TCP
            ttl: 64,
            ..Default::default()
        });

        let layer4 = Layer4::Tcp(TcpInfo {
            src_port: 12345,
            dst_port: 80,
            payload: payload.to_vec(),
            ..Default::default()
        });

        Packet {
            timestamp: Utc::now(),
            id: 1,
            ttl: 64,
            ethernet: None,
            layer3,
            layer4,
            tls: None,
            flow_id: None,
            direction: PktDirection::Unknown,
            interface: "eth0".to_string(),
            raw_len: payload.len() as u32,
        }
    }

    #[test]
    fn test_hyperscan_basic() {
        let rules = vec![
            make_test_rule(1001, b"malware", "Test malware detection"),
            make_test_rule(1002, b"exploit", "Test exploit detection"),
            make_test_rule(1003, b"GET /admin", "Admin access"),
        ];

        let matcher = HyperscanMatcher::new(&rules).expect("Failed to create matcher");
        assert_eq!(matcher.rule_count(), 3);
        assert_eq!(matcher.pattern_count(), 3);

        // Test matching
        let packet = make_test_packet(b"GET /admin/config HTTP/1.1");
        let proto_ctx = ProtocolContext::default();
        let flow_state = FlowState::default();

        let matches = matcher.match_packet(&packet, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, 1003);
    }

    #[test]
    fn trigger_then_verify_all_content() {
        fn content(p: &[u8], negated: bool) -> RuleOption {
            RuleOption::Content(ContentMatch {
                pattern: p.to_vec(),
                negated,
                nocase: false,
                offset: None,
                depth: None,
                distance: None,
                within: None,
                fast_pattern: false,
                rawbytes: false,
            })
        }
        // Multi-content rule: needs BOTH union and select.
        let mut multi = make_test_rule(2001, b"union", "sqli");
        multi.options = vec![content(b"union", false), content(b"select", false)];
        // Negated: admin present AND "logged" absent.
        let mut negated = make_test_rule(2002, b"admin", "admin-anon");
        negated.options = vec![content(b"admin", false), content(b"logged", true)];
        // Content-less rule must be skipped (else it would match every packet).
        let mut contentless = make_test_rule(2003, b"x", "no-content");
        contentless.options = vec![];

        let m = HyperscanMatcher::new(&[multi, negated, contentless]).unwrap();
        let ctx = ProtocolContext::default();
        let fs = FlowState::default();
        let hits = |p: &[u8]| -> Vec<u32> {
            m.match_packet(&make_test_packet(p), &ctx, &fs).iter().map(|r| r.rule_id).collect()
        };

        // All content present -> match; partial -> no match.
        assert!(hits(b"q=union+x+select+y").contains(&2001));
        assert!(!hits(b"q=union+only").contains(&2001));
        // Negated absent -> match; negated present -> no match.
        assert!(hits(b"path=/admin/x").contains(&2002));
        assert!(!hits(b"/admin logged in").contains(&2002));
        // Content-less rule never fires.
        assert!(!hits(b"anything at all").contains(&2003));
    }

    #[test]
    fn test_hyperscan_no_match() {
        let rules = vec![make_test_rule(1001, b"malware", "Test")];

        let matcher = HyperscanMatcher::new(&rules).expect("Failed to create matcher");

        let packet = make_test_packet(b"normal traffic here");
        let matches = matcher.match_packet(&packet, &ProtocolContext::default(), &FlowState::default());
        assert!(matches.is_empty());
    }

    #[test]
    fn test_hyperscan_multiple_matches() {
        let rules = vec![
            make_test_rule(1001, b"HTTP", "HTTP protocol"),
            make_test_rule(1002, b"GET", "GET method"),
        ];

        let matcher = HyperscanMatcher::new(&rules).expect("Failed to create matcher");

        let packet = make_test_packet(b"GET /index.html HTTP/1.1");
        let matches = matcher.match_packet(&packet, &ProtocolContext::default(), &FlowState::default());
        assert_eq!(matches.len(), 2);
    }
}
