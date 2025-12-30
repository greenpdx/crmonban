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

use std::collections::HashMap;
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

/// Hyperscan-accelerated matcher
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
}

impl HyperscanMatcher {
    /// Create a new Hyperscan matcher from rules
    pub fn new(rules: &[Rule]) -> Result<Self, String> {
        let mut patterns: Vec<Pattern> = Vec::new();
        let mut pattern_map: Vec<PatternInfo> = Vec::new();
        let mut rule_map: HashMap<u32, Arc<Rule>> = HashMap::new();

        info!("Building Hyperscan database from {} rules", rules.len());

        for rule in rules {
            if !rule.enabled {
                continue;
            }

            let rule_id = rule.sid;
            rule_map.insert(rule_id, Arc::new(rule.clone()));

            // Extract content patterns from rule
            for (pattern_index, opt) in rule.options.iter().enumerate() {
                if let RuleOption::Content(content) = opt {
                    // Convert pattern to Hyperscan format
                    let pattern_str = Self::content_to_pattern(content);
                    if pattern_str.is_empty() {
                        continue;
                    }

                    let pattern_id = patterns.len();

                    // Set flags
                    let mut flags = Flags::empty();
                    if content.nocase {
                        flags |= Flags::CASELESS;
                    }
                    // Use SOM_LEFTMOST for offset tracking
                    flags |= Flags::SOM_LEFTMOST;

                    // Create Pattern with id
                    let mut pat = Pattern::new(pattern_str)
                        .map_err(|e| format!("Invalid pattern: {}", e))?;
                    pat.flags = flags;
                    pat.id = Some(pattern_id);

                    patterns.push(pat);

                    pattern_map.push(PatternInfo {
                        rule_id,
                        pattern_index,
                        is_fast_pattern: content.fast_pattern,
                        negated: content.negated,
                    });
                }
            }
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

        // Collect matching pattern IDs
        let mut matched_patterns: Vec<(usize, u64, u64)> = Vec::new();

        // Run Hyperscan scan
        let result = self.database.scan(payload, &self.scratch, |id, from, to, _flags| {
            matched_patterns.push((id as usize, from, to));
            Matching::Continue
        });

        if let Err(e) = result {
            warn!("Hyperscan scan error: {}", e);
            return Vec::new();
        }

        // Group matches by rule ID
        let mut rule_matches: HashMap<u32, Vec<(usize, u64, u64)>> = HashMap::new();
        for (pattern_id, from, to) in matched_patterns {
            if let Some(info) = self.pattern_map.get(pattern_id) {
                if !info.negated {
                    rule_matches
                        .entry(info.rule_id)
                        .or_default()
                        .push((info.pattern_index, from, to));
                }
            }
        }

        // Verify rules and build results
        let mut results: Vec<MatchResult> = Vec::new();
        for (rule_id, matches) in rule_matches {
            if let Some(rule) = self.rules.get(&rule_id) {
                // Check if all required patterns matched
                if self.verify_rule(rule, &matches, payload) {
                    results.push(MatchResult {
                        rule_id,
                        sid: rule.sid,
                        msg: rule.msg.clone(),
                        classtype: rule.classtype.clone(),
                        priority: rule.priority,
                        action: rule.action,
                        references: rule.references.clone(),
                        timestamp: std::time::Instant::now(),
                        content_matches: matches.iter().map(|(_, from, to)| (*from as usize, *to as usize)).collect(),
                    });
                }
            }
        }

        results
    }

    /// Verify that all rule conditions are met
    fn verify_rule(
        &self,
        rule: &Rule,
        matches: &[(usize, u64, u64)],
        payload: &[u8],
    ) -> bool {
        // Count required content patterns
        let required_patterns: Vec<usize> = rule
            .options
            .iter()
            .enumerate()
            .filter_map(|(i, opt)| {
                if let RuleOption::Content(c) = opt {
                    if !c.negated {
                        return Some(i);
                    }
                }
                None
            })
            .collect();

        // Check if all required patterns matched
        let matched_indices: std::collections::HashSet<usize> =
            matches.iter().map(|(idx, _, _)| *idx).collect();

        for required in &required_patterns {
            if !matched_indices.contains(required) {
                return false;
            }
        }

        // Check negated patterns (must NOT match)
        for (_i, opt) in rule.options.iter().enumerate() {
            if let RuleOption::Content(c) = opt {
                if c.negated {
                    // Check if this pattern is in the payload
                    let pattern = &c.pattern;
                    if c.nocase {
                        let pattern_lower: Vec<u8> =
                            pattern.iter().map(|b| b.to_ascii_lowercase()).collect();
                        let payload_lower: Vec<u8> =
                            payload.iter().map(|b| b.to_ascii_lowercase()).collect();
                        if payload_lower
                            .windows(pattern_lower.len())
                            .any(|w| w == pattern_lower.as_slice())
                        {
                            return false; // Negated pattern matched - rule fails
                        }
                    } else if payload
                        .windows(pattern.len())
                        .any(|w| w == pattern.as_slice())
                    {
                        return false; // Negated pattern matched - rule fails
                    }
                }
            }
        }

        // TODO: Verify distance/within constraints
        // TODO: Verify offset/depth constraints

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
            raw_len: payload.len(),
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
