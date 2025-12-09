//! Pattern matching engine
//!
//! Uses Aho-Corasick for fast multi-pattern pre-filtering followed by
//! full rule verification including PCRE, byte tests, and flow checks.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::bytes::Regex;
use parking_lot::RwLock;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

use super::ast::*;
use super::{SignatureConfig, RuleStats};
use crate::core::packet::Packet;

/// Result of a signature match
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// Rule that matched
    pub rule_id: u32,
    /// Signature ID
    pub sid: u32,
    /// Alert message
    pub msg: String,
    /// Classification type
    pub classtype: Option<String>,
    /// Priority (1-4)
    pub priority: u8,
    /// Action to take
    pub action: Action,
    /// References
    pub references: Vec<Reference>,
    /// Match timestamp
    pub timestamp: Instant,
    /// Matched content positions
    pub content_matches: Vec<(usize, usize)>,
}

/// Flow state for signature matching
#[derive(Debug, Clone, Default)]
pub struct FlowState {
    /// Is established connection
    pub established: bool,
    /// Direction to server
    pub to_server: bool,
}

/// HTTP protocol context
#[derive(Debug, Clone, Default)]
pub struct HttpContext {
    /// HTTP URI
    pub uri: Option<Vec<u8>>,
    /// HTTP method
    pub method: Option<Vec<u8>>,
    /// HTTP headers
    pub headers: Option<Vec<u8>>,
    /// HTTP host
    pub host: Option<Vec<u8>>,
    /// HTTP user agent
    pub user_agent: Option<Vec<u8>>,
}

/// DNS protocol context
#[derive(Debug, Clone, Default)]
pub struct DnsContext {
    /// DNS query name
    pub query: Option<Vec<u8>>,
}

/// TLS protocol context
#[derive(Debug, Clone, Default)]
pub struct TlsContext {
    /// TLS SNI (Server Name Indication)
    pub sni: Option<Vec<u8>>,
    /// JA3 fingerprint hash
    pub ja3_hash: Option<String>,
}

/// SSH protocol context
#[derive(Debug, Clone, Default)]
pub struct SshContext {
    /// SSH version string
    pub version: Option<String>,
    /// HASSH fingerprint
    pub hassh: Option<String>,
}

/// SMTP protocol context
#[derive(Debug, Clone, Default)]
pub struct SmtpContext {
    /// MAIL FROM address
    pub mail_from: Option<Vec<u8>>,
    /// RCPT TO addresses
    pub rcpt_to: Option<Vec<Vec<u8>>>,
    /// HELO/EHLO hostname
    pub helo: Option<Vec<u8>>,
}

/// Protocol-specific parsed context for signature matching
#[derive(Debug, Clone)]
pub enum ProtocolContext {
    /// HTTP protocol data
    Http(HttpContext),
    /// DNS protocol data
    Dns(DnsContext),
    /// TLS protocol data
    Tls(TlsContext),
    /// SSH protocol data
    Ssh(SshContext),
    /// SMTP protocol data
    Smtp(SmtpContext),
    /// No protocol-specific data available
    None,
}

impl Default for ProtocolContext {
    fn default() -> Self {
        ProtocolContext::None
    }
}

impl ProtocolContext {
    /// Get HTTP URI if available
    pub fn http_uri(&self) -> Option<&[u8]> {
        match self {
            ProtocolContext::Http(h) => h.uri.as_deref(),
            _ => None,
        }
    }

    /// Get HTTP method if available
    pub fn http_method(&self) -> Option<&[u8]> {
        match self {
            ProtocolContext::Http(h) => h.method.as_deref(),
            _ => None,
        }
    }

    /// Get HTTP headers if available
    pub fn http_headers(&self) -> Option<&[u8]> {
        match self {
            ProtocolContext::Http(h) => h.headers.as_deref(),
            _ => None,
        }
    }

    /// Get HTTP host if available
    pub fn http_host(&self) -> Option<&[u8]> {
        match self {
            ProtocolContext::Http(h) => h.host.as_deref(),
            _ => None,
        }
    }

    /// Get HTTP user agent if available
    pub fn http_user_agent(&self) -> Option<&[u8]> {
        match self {
            ProtocolContext::Http(h) => h.user_agent.as_deref(),
            _ => None,
        }
    }

    /// Get DNS query if available
    pub fn dns_query(&self) -> Option<&[u8]> {
        match self {
            ProtocolContext::Dns(d) => d.query.as_deref(),
            _ => None,
        }
    }

    /// Get TLS SNI if available
    pub fn tls_sni(&self) -> Option<&[u8]> {
        match self {
            ProtocolContext::Tls(t) => t.sni.as_deref(),
            _ => None,
        }
    }

    /// Get JA3 hash if available
    pub fn ja3_hash(&self) -> Option<&str> {
        match self {
            ProtocolContext::Tls(t) => t.ja3_hash.as_deref(),
            _ => None,
        }
    }
}

/// Convert IpProtocol to signature Protocol
fn ip_protocol_to_sig_protocol(ip_proto: crate::core::packet::IpProtocol) -> Protocol {
    use crate::core::packet::IpProtocol;
    match ip_proto {
        IpProtocol::Tcp => Protocol::Tcp,
        IpProtocol::Udp => Protocol::Udp,
        IpProtocol::Icmp | IpProtocol::Icmpv6 => Protocol::Icmp,
        IpProtocol::Other(_) => Protocol::Ip,
    }
}

/// Pre-compiled pattern matcher using Aho-Corasick
pub struct PatternMatcher {
    /// Aho-Corasick automaton
    automaton: AhoCorasick,
    /// Pattern index to rule IDs mapping
    pattern_to_rules: Vec<Vec<u32>>,
    /// Number of patterns
    pattern_count: usize,
}

impl PatternMatcher {
    /// Build pattern matcher from rules
    pub fn build(rules: &[Rule], min_length: usize) -> Option<Self> {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut pattern_to_rules: Vec<Vec<u32>> = Vec::new();
        let mut pattern_map: HashMap<Vec<u8>, usize> = HashMap::new();

        for rule in rules {
            if !rule.enabled {
                continue;
            }

            // Get fast pattern or longest content
            if let Some(fp) = rule.fast_pattern() {
                if fp.pattern.len() >= min_length {
                    let pattern = if fp.nocase {
                        fp.pattern.to_ascii_lowercase()
                    } else {
                        fp.pattern.clone()
                    };

                    if let Some(&idx) = pattern_map.get(&pattern) {
                        pattern_to_rules[idx].push(rule.id);
                    } else {
                        let idx = patterns.len();
                        pattern_map.insert(pattern.clone(), idx);
                        patterns.push(pattern);
                        pattern_to_rules.push(vec![rule.id]);
                    }
                }
            }
        }

        if patterns.is_empty() {
            return None;
        }

        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .ascii_case_insensitive(true)
            .build(&patterns)
            .ok()?;

        Some(Self {
            automaton,
            pattern_to_rules,
            pattern_count: patterns.len(),
        })
    }

    /// Find candidate rules for payload
    pub fn find_candidates(&self, payload: &[u8]) -> HashSet<u32> {
        let mut candidates = HashSet::new();

        for mat in self.automaton.find_iter(payload) {
            if let Some(rule_ids) = self.pattern_to_rules.get(mat.pattern().as_usize()) {
                candidates.extend(rule_ids.iter().copied());
            }
        }

        candidates
    }

    /// Get pattern count
    pub fn pattern_count(&self) -> usize {
        self.pattern_count
    }
}

/// Compiled PCRE pattern cache
struct PcreCache {
    patterns: HashMap<String, Regex>,
}

impl PcreCache {
    fn new() -> Self {
        Self {
            patterns: HashMap::new(),
        }
    }

    /// Check if pattern exists in cache
    #[inline]
    fn get(&self, key: &str) -> Option<&Regex> {
        self.patterns.get(key)
    }

    /// Compile and insert a new pattern
    fn compile_and_insert(&mut self, pattern: &str, flags: &str) -> Option<&Regex> {
        let key = format!("/{}/{}", pattern, flags);

        let mut regex_pattern = String::with_capacity(pattern.len() + 12);

        // Build regex flags prefix
        if flags.contains('i') {
            regex_pattern.push_str("(?i)");
        }
        if flags.contains('s') {
            regex_pattern.push_str("(?s)");
        }
        if flags.contains('m') {
            regex_pattern.push_str("(?m)");
        }

        regex_pattern.push_str(pattern);

        match Regex::new(&regex_pattern) {
            Ok(re) => {
                self.patterns.insert(key.clone(), re);
                self.patterns.get(&key)
            }
            Err(_) => None,
        }
    }

    /// Generate cache key
    #[inline]
    fn make_key(pattern: &str, flags: &str) -> String {
        format!("/{}/{}", pattern, flags)
    }
}

/// Threshold tracking state
struct ThresholdState {
    /// Count by tracker key
    counts: HashMap<String, ThresholdEntry>,
}

struct ThresholdEntry {
    count: u32,
    window_start: Instant,
    last_alert: Option<Instant>,
}

impl ThresholdState {
    fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    fn check_threshold(
        &mut self,
        sid: u32,
        spec: &ThresholdSpec,
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
    ) -> bool {
        let key = match spec.track {
            TrackBy::BySrc => format!("{}:{:?}", sid, src_ip),
            TrackBy::ByDst => format!("{}:{:?}", sid, dst_ip),
            TrackBy::ByRule => format!("{}", sid),
            TrackBy::ByBoth => format!("{}:{:?}:{:?}", sid, src_ip, dst_ip),
        };

        let now = Instant::now();
        let window = Duration::from_secs(spec.seconds as u64);

        let entry = self.counts.entry(key).or_insert_with(|| ThresholdEntry {
            count: 0,
            window_start: now,
            last_alert: None,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start) > window {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;

        match spec.threshold_type {
            ThresholdType::Limit => {
                // Alert on first N
                entry.count <= spec.count
            }
            ThresholdType::Threshold => {
                // Alert once per count
                entry.count >= spec.count && entry.count % spec.count == 0
            }
            ThresholdType::Both => {
                // Alert once when threshold reached
                if entry.count >= spec.count {
                    if entry.last_alert.map(|t| now.duration_since(t) > window).unwrap_or(true) {
                        entry.last_alert = Some(now);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        }
    }

    fn cleanup_expired(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.counts.retain(|_, entry| {
            now.duration_since(entry.window_start) < max_age
        });
    }
}

/// Flowbits state tracking
struct FlowbitsState {
    /// Bits by flow key (using u64 hash for speed)
    bits: HashMap<u64, HashSet<String>>,
}

impl FlowbitsState {
    fn new() -> Self {
        Self {
            bits: HashMap::new(),
        }
    }

    /// Generate flow key from Packet (much faster than String formatting)
    #[inline]
    fn flow_key_from_packet(packet: &Packet) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        packet.src_ip().hash(&mut hasher);
        packet.src_port().hash(&mut hasher);
        packet.dst_ip().hash(&mut hasher);
        packet.dst_port().hash(&mut hasher);
        hasher.finish()
    }

    #[inline]
    fn set_for_packet(&mut self, packet: &Packet, name: &str) {
        let key = Self::flow_key_from_packet(packet);
        self.bits.entry(key).or_default().insert(name.to_string());
    }

    #[inline]
    fn unset_for_packet(&mut self, packet: &Packet, name: &str) {
        let key = Self::flow_key_from_packet(packet);
        if let Some(bits) = self.bits.get_mut(&key) {
            bits.remove(name);
        }
    }

    #[inline]
    fn is_set_for_packet(&self, packet: &Packet, name: &str) -> bool {
        let key = Self::flow_key_from_packet(packet);
        self.bits.get(&key).map(|b| b.contains(name)).unwrap_or(false)
    }

    #[inline]
    fn toggle_for_packet(&mut self, packet: &Packet, name: &str) {
        let key = Self::flow_key_from_packet(packet);
        let bits = self.bits.entry(key).or_default();
        if bits.contains(name) {
            bits.remove(name);
        } else {
            bits.insert(name.to_string());
        }
    }
}

/// Main signature matching engine
pub struct SignatureEngine {
    /// Configuration
    config: SignatureConfig,
    /// Loaded rules by ID
    rules: HashMap<u32, Rule>,
    /// Rules by protocol
    rules_by_protocol: HashMap<Protocol, Vec<u32>>,
    /// Pre-filter pattern matcher
    prefilter: Option<PatternMatcher>,
    /// PCRE pattern cache
    pcre_cache: RwLock<PcreCache>,
    /// Threshold state
    threshold_state: RwLock<ThresholdState>,
    /// Flowbits state
    flowbits_state: RwLock<FlowbitsState>,
    /// Rule statistics
    stats: RuleStats,
    /// Variable substitution map
    variables: HashMap<String, String>,
}

impl SignatureEngine {
    /// Create new signature engine
    pub fn new(config: SignatureConfig) -> Self {
        Self {
            variables: config.variables.clone(),
            config,
            rules: HashMap::new(),
            rules_by_protocol: HashMap::new(),
            prefilter: None,
            pcre_cache: RwLock::new(PcreCache::new()),
            threshold_state: RwLock::new(ThresholdState::new()),
            flowbits_state: RwLock::new(FlowbitsState::new()),
            stats: RuleStats::default(),
        }
    }

    /// Load rules from the default Suricata rules directory
    ///
    /// Returns an initialized SignatureEngine with rules loaded and prefilter built.
    /// Default rules directory: /var/lib/crmonban/data/signatures/suricata/rules
    pub fn load_default_rules() -> Result<Self, String> {
        use super::RuleLoader;
        use std::path::PathBuf;

        let mut config = super::SignatureConfig::default();
        let rules_dir = PathBuf::from("/var/lib/crmonban/data/signatures/suricata/rules");
        if rules_dir.exists() {
            config.rule_dirs = vec![rules_dir];
        }

        let mut engine = Self::new(config.clone());
        let mut loader = RuleLoader::new(config);

        match loader.load_all() {
            Ok(ruleset) => {
                for (_, rule) in ruleset.rules {
                    engine.add_rule(rule);
                }
                engine.rebuild_prefilter();
                Ok(engine)
            }
            Err(e) => Err(format!("Failed to load rules: {}", e)),
        }
    }

    /// Load rules from the default directory, printing status to stdout
    ///
    /// Same as load_default_rules() but with verbose output for CLI/benchmark use.
    pub fn load_default_rules_verbose() -> Result<Self, String> {
        use super::RuleLoader;
        use std::path::PathBuf;

        let mut config = super::SignatureConfig::default();
        let rules_dir = PathBuf::from("/var/lib/crmonban/data/signatures/suricata/rules");
        if rules_dir.exists() {
            config.rule_dirs = vec![rules_dir.clone()];
            println!("Loading rules from: {:?}", rules_dir);
        }

        let mut engine = Self::new(config.clone());
        let mut loader = RuleLoader::new(config);

        match loader.load_all() {
            Ok(ruleset) => {
                println!("Loaded {} rules ({} enabled, {} with content patterns)",
                    ruleset.stats.total_rules,
                    ruleset.stats.total_rules - ruleset.stats.disabled,
                    ruleset.stats.with_content);
                for (_, rule) in ruleset.rules {
                    engine.add_rule(rule);
                }
                engine.rebuild_prefilter();
                println!("Prefilter patterns: {}", engine.prefilter_pattern_count());
                Ok(engine)
            }
            Err(e) => Err(format!("Failed to load rules: {}", e)),
        }
    }

    /// Load rules from a specified directory
    ///
    /// Returns Some(engine) on success, None if directory doesn't exist or loading fails.
    pub fn load_from_dir(rules_dir: &std::path::Path) -> Option<Self> {
        use super::RuleLoader;
        use tracing::{debug, warn};

        if !rules_dir.exists() {
            warn!("Rules directory does not exist: {:?}", rules_dir);
            return None;
        }

        debug!("Loading signatures from {:?}...", rules_dir);

        let mut config = super::SignatureConfig::default();
        config.rule_dirs = vec![rules_dir.to_path_buf()];

        let mut engine = Self::new(config.clone());
        let mut loader = RuleLoader::new(config);

        // Load classification.config for priority mapping
        let classification_path = rules_dir.join("classification.config");
        if classification_path.exists() {
            if let Err(e) = loader.load_classifications(&classification_path) {
                warn!("Failed to load classification.config: {}", e);
            }
        }

        match loader.load_all() {
            Ok(ruleset) => {
                debug!(
                    "Loaded {} rules ({} enabled, {} with content patterns)",
                    ruleset.stats.total_rules,
                    ruleset.stats.total_rules - ruleset.stats.disabled,
                    ruleset.stats.with_content
                );
                for (_, rule) in ruleset.rules {
                    engine.add_rule(rule);
                }
                engine.rebuild_prefilter();
                debug!("Prefilter patterns: {}", engine.prefilter_pattern_count());
                Some(engine)
            }
            Err(e) => {
                warn!("Failed to load rules: {}", e);
                None
            }
        }
    }

    /// Add a rule to the engine
    pub fn add_rule(&mut self, rule: Rule) {
        let id = rule.id;
        let protocol = rule.protocol;

        self.stats.add_rule(&rule);
        self.rules.insert(id, rule);
        self.rules_by_protocol
            .entry(protocol)
            .or_default()
            .push(id);
    }

    /// Rebuild the pre-filter after loading rules
    pub fn rebuild_prefilter(&mut self) {
        if self.config.prefilter_enabled {
            let rules: Vec<_> = self.rules.values().cloned().collect();
            self.prefilter = PatternMatcher::build(&rules, self.config.prefilter_min_length);
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &RuleStats {
        &self.stats
    }

    /// Get rule count
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get prefilter pattern count
    pub fn prefilter_pattern_count(&self) -> usize {
        self.prefilter.as_ref().map(|p| p.pattern_count()).unwrap_or(0)
    }

    /// Match packet against all rules
    ///
    /// # Arguments
    /// * `packet` - The packet to match against
    /// * `proto_ctx` - Protocol-specific context (HTTP, DNS, TLS, etc.)
    /// * `flow_state` - Connection flow state (established, direction)
    #[inline]
    pub fn match_packet(
        &self,
        packet: &Packet,
        proto_ctx: &ProtocolContext,
        flow_state: &FlowState,
    ) -> Vec<MatchResult> {
        self.match_packet_with_stream(packet, proto_ctx, flow_state, None, None)
    }

    /// Match packet against all rules, including stream data
    ///
    /// # Arguments
    /// * `packet` - The packet to match against
    /// * `proto_ctx` - Protocol-specific context (HTTP, DNS, TLS, etc.)
    /// * `flow_state` - Connection flow state (established, direction)
    /// * `fwd_stream` - Optional forward stream data (client to server)
    /// * `bwd_stream` - Optional backward stream data (server to client)
    #[inline]
    pub fn match_packet_with_stream(
        &self,
        packet: &Packet,
        proto_ctx: &ProtocolContext,
        flow_state: &FlowState,
        fwd_stream: Option<&[u8]>,
        bwd_stream: Option<&[u8]>,
    ) -> Vec<MatchResult> {
        use tracing::debug;
        use std::time::Instant;

        let start = Instant::now();
        let mut results = Vec::new();

        // Extract packet info once
        let packet_payload = packet.payload();
        // Use stream data if available and has content, otherwise use packet payload
        let payload = if flow_state.to_server {
            fwd_stream.filter(|s| !s.is_empty()).unwrap_or(packet_payload)
        } else {
            bwd_stream.filter(|s| !s.is_empty()).unwrap_or(packet_payload)
        };
        let protocol = ip_protocol_to_sig_protocol(packet.protocol());
        let src_ip = Some(packet.src_ip());
        let dst_ip = Some(packet.dst_ip());
        let src_port = Some(packet.src_port());
        let dst_port = Some(packet.dst_port());

        // Get candidate rules from prefilter
        let prefilter_start = Instant::now();
        let mut candidates = if let Some(ref prefilter) = self.prefilter {
            let c = prefilter.find_candidates(payload);
            // Debug: log candidate count for non-empty payloads
            if !payload.is_empty() && c.len() > 0 {
                debug!("Prefilter found {} candidates for payload len {} in {:?}",
                    c.len(), payload.len(), prefilter_start.elapsed());
            }
            c
        } else {
            // No prefilter - check all rules for matching protocol
            debug!("No prefilter, checking protocol rules for {:?}", protocol);
            self.get_protocol_rules(protocol)
        };

        // Also include rules that couldn't be in prefilter:
        // - Rules with sticky buffers (HTTP/DNS/TLS context)
        // - Rules with short patterns (< min_length)
        // - Rules with no content patterns
        let non_prefilter_rules = self.get_non_prefilter_rules(protocol, proto_ctx);
        candidates.extend(non_prefilter_rules);

        // Debug: periodically log candidate stats
        static MATCH_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let count = MATCH_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count % 10000 == 0 {
            debug!(
                "match_packet #{}: payload_len={}, candidates={}, proto={:?}",
                count, payload.len(), candidates.len(), protocol
            );
        }

        // Debug: track verification stats
        let mut verified_count = 0u32;
        let mut failed_protocol = 0u32;
        let mut failed_flags = 0u32;
        let mut failed_address = 0u32;
        let mut failed_flow = 0u32;
        let mut failed_flowbits = 0u32;
        let mut failed_content = 0u32;
        let mut failed_pcre = 0u32;
        let mut failed_threshold = 0u32;

        // Get TCP flags once for all rules
        let tcp_flags = packet.tcp_flags();

        // Verify each candidate rule
        let verify_start = Instant::now();
        for rule_id in &candidates {
            if let Some(rule) = self.rules.get(rule_id) {
                // Skip disabled rules
                if !rule.enabled {
                    continue;
                }

                verified_count += 1;

                // Check each stage and count failures
                if !self.check_protocol_direct(rule, protocol) {
                    failed_protocol += 1;
                    continue;
                }
                if !self.check_tcp_flags_direct(rule, tcp_flags) {
                    failed_flags += 1;
                    continue;
                }
                if !self.check_addresses_direct(rule, src_ip, dst_ip, src_port, dst_port, flow_state.to_server) {
                    failed_address += 1;
                    // Log first few address failures for debugging
                    if failed_address <= 3 && count % 10000 == 0 {
                        debug!(
                            "Addr fail SID {}: src_ip={:?} (rule: {:?}), dst_ip={:?} (rule: {:?}), src_port={:?} (rule: {:?}), dst_port={:?} (rule: {:?}), dir={:?}",
                            rule.sid,
                            src_ip, rule.src_ip,
                            dst_ip, rule.dst_ip,
                            src_port, rule.src_port,
                            dst_port, rule.dst_port,
                            rule.direction
                        );
                    }
                    continue;
                }
                if !self.check_flow_direct(rule, flow_state) {
                    failed_flow += 1;
                    continue;
                }
                if !self.check_flowbits_prereqs_direct(rule, packet, flow_state) {
                    failed_flowbits += 1;
                    continue;
                }

                // Match content patterns
                let content_matches = match self.match_contents_direct(rule, payload, proto_ctx) {
                    Some(m) => m,
                    None => {
                        failed_content += 1;
                        // Log first few content failures for debugging
                        if failed_content <= 3 && count % 10000 == 0 {
                            let patterns: Vec<_> = rule.options.iter()
                                .filter_map(|o| match o {
                                    RuleOption::Content(cm) => Some(format!("{:?}", String::from_utf8_lossy(&cm.pattern))),
                                    _ => None,
                                })
                                .collect();
                            debug!(
                                "Content fail SID {}: payload_len={}, patterns={:?}",
                                rule.sid, payload.len(), patterns
                            );
                        }
                        continue;
                    }
                };

                // Match PCRE patterns
                if !self.match_pcre_direct(rule, payload, proto_ctx) {
                    failed_pcre += 1;
                    continue;
                }

                // Check threshold
                if !self.check_threshold_direct(rule, src_ip) {
                    failed_threshold += 1;
                    continue;
                }

                // Update flowbits state
                self.update_flowbits_direct(rule, packet, flow_state);

                // Check for noalert
                if rule.options.iter().any(|o| matches!(o, RuleOption::Noalert)) {
                    continue;
                }

                debug!("Rule {} (SID {}) MATCHED: {}", rule.id, rule.sid, rule.msg);
                results.push(MatchResult {
                    rule_id: rule.id,
                    sid: rule.sid,
                    msg: rule.msg.clone(),
                    classtype: rule.classtype.clone(),
                    priority: rule.priority,
                    action: rule.action,
                    references: rule.references.clone(),
                    timestamp: Instant::now(),
                    content_matches,
                });
            }
        }

        // Log verification stats periodically
        if count % 10000 == 0 && candidates.len() > 0 {
            debug!(
                "Verify stats #{}: checked={}, proto_fail={}, flags_fail={}, addr_fail={}, flow_fail={}, flowbits_fail={}, content_fail={}, pcre_fail={}, thresh_fail={}, matched={}, time={:?}",
                count, verified_count, failed_protocol, failed_flags, failed_address, failed_flow,
                failed_flowbits, failed_content, failed_pcre, failed_threshold,
                results.len(), verify_start.elapsed()
            );
        }

        // Log total time periodically
        if count % 100000 == 0 {
            debug!("match_packet #{}: total_time={:?}", count, start.elapsed());
        }

        results
    }

    /// Get rule IDs for a protocol
    fn get_protocol_rules(&self, protocol: Protocol) -> HashSet<u32> {
        let mut rules = HashSet::new();

        // Add protocol-specific rules
        if let Some(ids) = self.rules_by_protocol.get(&protocol) {
            rules.extend(ids.iter().copied());
        }

        // Add "any" protocol rules
        if let Some(ids) = self.rules_by_protocol.get(&Protocol::Any) {
            rules.extend(ids.iter().copied());
        }

        // Add IP rules for TCP/UDP/ICMP
        if matches!(protocol, Protocol::Tcp | Protocol::Udp | Protocol::Icmp) {
            if let Some(ids) = self.rules_by_protocol.get(&Protocol::Ip) {
                rules.extend(ids.iter().copied());
            }
        }

        rules
    }

    /// Get rules that couldn't be added to prefilter but should be checked
    /// based on protocol context or rule characteristics
    fn get_non_prefilter_rules(&self, protocol: Protocol, proto_ctx: &ProtocolContext) -> HashSet<u32> {
        let mut rules = HashSet::new();
        let min_length = self.config.prefilter_min_length;

        for rule in self.rules.values() {
            if !rule.enabled {
                continue;
            }

            // Skip if protocol doesn't match
            if rule.protocol != Protocol::Any && rule.protocol != protocol {
                continue;
            }

            // Check if rule uses sticky buffers that match the protocol context
            let uses_sticky_buffer = rule.options.iter().any(|opt| {
                matches!(opt,
                    RuleOption::HttpUri |
                    RuleOption::HttpMethod |
                    RuleOption::HttpHeader |
                    RuleOption::HttpHost |
                    RuleOption::HttpUserAgent |
                    RuleOption::DnsQuery |
                    RuleOption::TlsSni
                )
            });

            // Check if rule has only short patterns (below prefilter threshold)
            let has_only_short_patterns = if let Some(fp) = rule.fast_pattern() {
                fp.pattern.len() < min_length
            } else {
                // No fast pattern - check all content patterns
                let content_patterns: Vec<_> = rule.options.iter()
                    .filter_map(|o| match o {
                        RuleOption::Content(cm) => Some(&cm.pattern),
                        _ => None,
                    })
                    .collect();

                if content_patterns.is_empty() {
                    true // No content patterns at all
                } else {
                    content_patterns.iter().all(|p| p.len() < min_length)
                }
            };

            // Include rule if:
            // 1. Uses sticky buffers AND matching context is available
            // 2. Has only short patterns (couldn't be in prefilter)
            // 3. Has no content patterns (protocol-only rule)
            let context_matches = match proto_ctx {
                ProtocolContext::Http(_) => uses_sticky_buffer && rule.options.iter().any(|opt| {
                    matches!(opt,
                        RuleOption::HttpUri |
                        RuleOption::HttpMethod |
                        RuleOption::HttpHeader |
                        RuleOption::HttpHost |
                        RuleOption::HttpUserAgent
                    )
                }),
                ProtocolContext::Dns(_) => uses_sticky_buffer && rule.options.iter().any(|opt| {
                    matches!(opt, RuleOption::DnsQuery)
                }),
                ProtocolContext::Tls(_) => uses_sticky_buffer && rule.options.iter().any(|opt| {
                    matches!(opt, RuleOption::TlsSni)
                }),
                _ => false,
            };

            if context_matches || has_only_short_patterns {
                rules.insert(rule.id);
            }
        }

        rules
    }

    fn ip_matches(&self, spec: &IpSpec, ip: Option<IpAddr>) -> bool {
        match spec {
            IpSpec::Any => true,
            IpSpec::Var(name) => {
                // Resolve variable and check
                if let Some(value) = self.variables.get(name) {
                    if value == "any" {
                        return true;
                    }
                    // TODO: Parse variable value and check
                }
                true // Default to match for unresolved vars
            }
            IpSpec::Single(spec_ip) => ip.map(|i| i == *spec_ip).unwrap_or(false),
            IpSpec::Cidr(net_ip, prefix) => {
                if let Some(check_ip) = ip {
                    match (net_ip, check_ip) {
                        (IpAddr::V4(net), IpAddr::V4(check)) => {
                            let mask = if *prefix >= 32 {
                                u32::MAX
                            } else {
                                u32::MAX << (32 - prefix)
                            };
                            (u32::from(*net) & mask) == (u32::from(check) & mask)
                        }
                        (IpAddr::V6(net), IpAddr::V6(check)) => {
                            let net_bits: u128 = (*net).into();
                            let check_bits: u128 = check.into();
                            let mask = if *prefix >= 128 {
                                u128::MAX
                            } else {
                                u128::MAX << (128 - prefix)
                            };
                            (net_bits & mask) == (check_bits & mask)
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            }
            IpSpec::Range(start, end) => {
                ip.map(|i| i >= *start && i <= *end).unwrap_or(false)
            }
            IpSpec::List(specs) => specs.iter().any(|s| self.ip_matches(s, ip)),
            IpSpec::Negated(inner) => !self.ip_matches(inner, ip),
        }
    }

    fn port_matches(&self, spec: &PortSpec, port: Option<u16>) -> bool {
        match spec {
            PortSpec::Any => true,
            PortSpec::Var(name) => {
                // Resolve variable
                if let Some(value) = self.variables.get(name) {
                    if value == "any" {
                        return true;
                    }
                    // Parse port list from variable
                    if let Some(p) = port {
                        return value.split(',')
                            .any(|v| v.trim().parse::<u16>().map(|vp| vp == p).unwrap_or(false));
                    }
                }
                true
            }
            PortSpec::Single(spec_port) => port.map(|p| p == *spec_port).unwrap_or(false),
            PortSpec::Range(start, end) => {
                port.map(|p| p >= *start && p <= *end).unwrap_or(false)
            }
            PortSpec::List(specs) => specs.iter().any(|s| self.port_matches(s, port)),
            PortSpec::Negated(inner) => !self.port_matches(inner, port),
        }
    }

    /// Match content pattern (optimized - minimal allocations)
    #[inline]
    fn match_content(&self, cm: &ContentMatch, buffer: &[u8], start: usize) -> Option<usize> {
        // Calculate search range
        let search_start = if let Some(offset) = cm.offset {
            offset as usize
        } else if let Some(distance) = cm.distance {
            if distance >= 0 {
                start + distance as usize
            } else {
                start.saturating_sub((-distance) as usize)
            }
        } else {
            start
        };

        let search_end = if let Some(depth) = cm.depth {
            (search_start + depth as usize).min(buffer.len())
        } else if let Some(within) = cm.within {
            (start + within as usize).min(buffer.len())
        } else {
            buffer.len()
        };

        if search_start >= buffer.len() || search_end <= search_start {
            return None;
        }

        let search_range = &buffer[search_start..search_end];
        let pattern = &cm.pattern;

        // Check if pattern can fit in search range
        if pattern.len() > search_range.len() {
            return None;
        }

        // Use optimized search based on case sensitivity
        if cm.nocase {
            // Case-insensitive search without allocation
            self.find_nocase(search_range, pattern).map(|i| search_start + i)
        } else {
            // Case-sensitive search using optimized byte search
            self.find_bytes(search_range, pattern).map(|i| search_start + i)
        }
    }

    /// Fast case-sensitive byte pattern search
    #[inline]
    fn find_bytes(&self, haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        if needle.len() > haystack.len() {
            return None;
        }

        // Use first byte to quickly scan
        let first = needle[0];
        let mut pos = 0;

        while pos <= haystack.len() - needle.len() {
            // Find first byte
            if let Some(offset) = haystack[pos..].iter().position(|&b| b == first) {
                let start = pos + offset;
                if start + needle.len() <= haystack.len() {
                    if &haystack[start..start + needle.len()] == needle {
                        return Some(start);
                    }
                }
                pos = start + 1;
            } else {
                break;
            }
        }
        None
    }

    /// Fast case-insensitive search without allocation
    #[inline]
    fn find_nocase(&self, haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        if needle.len() > haystack.len() {
            return None;
        }

        let first_lower = needle[0].to_ascii_lowercase();
        let first_upper = needle[0].to_ascii_uppercase();
        let mut pos = 0;

        while pos <= haystack.len() - needle.len() {
            // Find first byte (case-insensitive)
            let found = haystack[pos..].iter().position(|&b| {
                b == first_lower || b == first_upper
            });

            if let Some(offset) = found {
                let start = pos + offset;
                if start + needle.len() <= haystack.len() {
                    // Check full pattern
                    let matches = haystack[start..start + needle.len()]
                        .iter()
                        .zip(needle.iter())
                        .all(|(&h, &n)| h.to_ascii_lowercase() == n.to_ascii_lowercase());

                    if matches {
                        return Some(start);
                    }
                }
                pos = start + 1;
            } else {
                break;
            }
        }
        None
    }

    // =========================================================================
    // Direct helper methods using &Packet + &ProtocolContext + &FlowState
    // These replace PacketContext-based methods for the new API
    // TODO: Future optimization - analyze which fields are actually used per rule
    // and skip unused checks
    // =========================================================================

    /// Check protocol match (direct version)
    #[inline]
    fn check_protocol_direct(&self, rule: &Rule, protocol: Protocol) -> bool {
        rule.protocol == Protocol::Any || rule.protocol == protocol
    }

    /// Check TCP flags match (direct version)
    ///
    /// Implements Suricata-style flags matching:
    /// - `flags:S` - SYN flag must be set
    /// - `flags:SA` - SYN and ACK must be set
    /// - `flags:S,12` - Only check SYN and ACK bits (mask), SYN must be set
    /// - `flags:0` - No flags set (NULL scan)
    /// - `flags:+S` - At least SYN must be set (match_all mode)
    /// - `flags:*SA` - At least one of SYN or ACK must be set (match_any mode)
    #[inline]
    fn check_tcp_flags_direct(
        &self,
        rule: &Rule,
        packet_flags: Option<crate::core::packet::TcpFlags>,
    ) -> bool {
        // Find Flags option in rule
        for opt in &rule.options {
            if let RuleOption::Flags(rule_flags) = opt {
                // If packet is not TCP, flags check fails
                let pkt_flags = match packet_flags {
                    Some(f) => f,
                    None => return false,
                };

                // Check each specified flag
                // For each flag in the rule spec, if Some(true) it must be set,
                // if Some(false) it must NOT be set, if None it's not checked

                if rule_flags.match_any {
                    // At least one specified flag must match
                    let mut any_match = false;
                    if rule_flags.syn == Some(true) && pkt_flags.syn { any_match = true; }
                    if rule_flags.ack == Some(true) && pkt_flags.ack { any_match = true; }
                    if rule_flags.fin == Some(true) && pkt_flags.fin { any_match = true; }
                    if rule_flags.rst == Some(true) && pkt_flags.rst { any_match = true; }
                    if rule_flags.psh == Some(true) && pkt_flags.psh { any_match = true; }
                    if rule_flags.urg == Some(true) && pkt_flags.urg { any_match = true; }
                    if rule_flags.ece == Some(true) && pkt_flags.ece { any_match = true; }
                    if rule_flags.cwr == Some(true) && pkt_flags.cwr { any_match = true; }
                    if !any_match {
                        return false;
                    }
                } else {
                    // Default: all specified flags must match exactly
                    // SYN
                    if let Some(expected) = rule_flags.syn {
                        if pkt_flags.syn != expected {
                            return false;
                        }
                    }
                    // ACK
                    if let Some(expected) = rule_flags.ack {
                        if pkt_flags.ack != expected {
                            return false;
                        }
                    }
                    // FIN
                    if let Some(expected) = rule_flags.fin {
                        if pkt_flags.fin != expected {
                            return false;
                        }
                    }
                    // RST
                    if let Some(expected) = rule_flags.rst {
                        if pkt_flags.rst != expected {
                            return false;
                        }
                    }
                    // PSH
                    if let Some(expected) = rule_flags.psh {
                        if pkt_flags.psh != expected {
                            return false;
                        }
                    }
                    // URG
                    if let Some(expected) = rule_flags.urg {
                        if pkt_flags.urg != expected {
                            return false;
                        }
                    }
                    // ECE
                    if let Some(expected) = rule_flags.ece {
                        if pkt_flags.ece != expected {
                            return false;
                        }
                    }
                    // CWR
                    if let Some(expected) = rule_flags.cwr {
                        if pkt_flags.cwr != expected {
                            return false;
                        }
                    }
                }
            }
        }

        // No flags option or all flags matched
        true
    }

    /// Check IP/port addresses (direct version)
    #[inline]
    fn check_addresses_direct(
        &self,
        rule: &Rule,
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        to_server: bool,
    ) -> bool {
        // Check source IP
        if !self.ip_matches(&rule.src_ip, src_ip) {
            return false;
        }

        // Check destination IP
        if !self.ip_matches(&rule.dst_ip, dst_ip) {
            return false;
        }

        // Check source port
        if !self.port_matches(&rule.src_port, src_port) {
            return false;
        }

        // Check destination port
        if !self.port_matches(&rule.dst_port, dst_port) {
            return false;
        }

        // Check direction
        match rule.direction {
            Direction::ToServer => to_server,
            Direction::ToClient => !to_server,
            Direction::Both => true,
        }
    }

    /// Check flow flags (direct version)
    #[inline]
    fn check_flow_direct(&self, rule: &Rule, flow_state: &FlowState) -> bool {
        if let Some(flags) = rule.flow_flags() {
            if flags.established && !flow_state.established {
                return false;
            }
            if flags.not_established && flow_state.established {
                return false;
            }
            if flags.to_server && !flow_state.to_server {
                return false;
            }
            if flags.to_client && flow_state.to_server {
                return false;
            }
        }
        true
    }

    /// Check flowbits prerequisites (direct version)
    #[inline]
    fn check_flowbits_prereqs_direct(&self, rule: &Rule, packet: &Packet, _flow_state: &FlowState) -> bool {
        let state = self.flowbits_state.read();

        for opt in &rule.options {
            if let RuleOption::Flowbits(op) = opt {
                match op {
                    FlowbitsOp::IsSet(name) => {
                        if !state.is_set_for_packet(packet, name) {
                            return false;
                        }
                    }
                    FlowbitsOp::IsNotSet(name) => {
                        if state.is_set_for_packet(packet, name) {
                            return false;
                        }
                    }
                    _ => {}
                }
            }
        }

        true
    }

    /// Match content patterns (direct version)
    #[inline]
    fn match_contents_direct(
        &self,
        rule: &Rule,
        payload: &[u8],
        proto_ctx: &ProtocolContext,
    ) -> Option<Vec<(usize, usize)>> {
        let mut matches = Vec::new();
        let mut last_match_end = 0;

        for opt in &rule.options {
            if let RuleOption::Content(cm) = opt {
                // Select buffer based on sticky buffers
                let buffer = self.select_buffer_direct(rule, payload, proto_ctx, opt);

                if let Some(pos) = self.match_content(cm, buffer, last_match_end) {
                    if cm.negated {
                        return None; // Negated content matched - rule fails
                    }
                    matches.push((pos, pos + cm.pattern.len()));
                    last_match_end = pos + cm.pattern.len();
                } else if !cm.negated {
                    return None; // Required content not found
                }
            }
        }

        Some(matches)
    }

    /// Select buffer for content matching (direct version using ProtocolContext)
    #[inline]
    fn select_buffer_direct<'a>(
        &self,
        rule: &Rule,
        payload: &'a [u8],
        proto_ctx: &'a ProtocolContext,
        current_opt: &RuleOption,
    ) -> &'a [u8] {
        // Find the most recent sticky buffer before this option
        let mut use_buffer: Option<&'a [u8]> = None;
        for opt in &rule.options {
            if std::ptr::eq(opt, current_opt) {
                break;
            }

            use_buffer = match opt {
                RuleOption::HttpUri => proto_ctx.http_uri(),
                RuleOption::HttpMethod => proto_ctx.http_method(),
                RuleOption::HttpHeader => proto_ctx.http_headers(),
                RuleOption::HttpHost => proto_ctx.http_host(),
                RuleOption::HttpUserAgent => proto_ctx.http_user_agent(),
                RuleOption::DnsQuery => proto_ctx.dns_query(),
                RuleOption::TlsSni => proto_ctx.tls_sni(),
                _ => continue,
            };
        }

        use_buffer.unwrap_or(payload)
    }

    /// Match PCRE patterns (direct version)
    #[inline]
    fn match_pcre_direct(&self, rule: &Rule, payload: &[u8], _proto_ctx: &ProtocolContext) -> bool {
        for opt in &rule.options {
            if let RuleOption::Pcre(pcre) = opt {
                let buffer = payload;
                let key = PcreCache::make_key(&pcre.pattern, &pcre.flags);

                // Try read lock first (fast path for cached patterns)
                let matched = {
                    let cache = self.pcre_cache.read();
                    if let Some(re) = cache.get(&key) {
                        Some(re.is_match(buffer))
                    } else {
                        None
                    }
                };

                let matched = match matched {
                    Some(m) => m,
                    None => {
                        // Cache miss - need write lock to compile
                        let mut cache = self.pcre_cache.write();
                        // Double-check after acquiring write lock
                        if let Some(re) = cache.get(&key) {
                            re.is_match(buffer)
                        } else if let Some(re) = cache.compile_and_insert(&pcre.pattern, &pcre.flags) {
                            re.is_match(buffer)
                        } else {
                            continue; // Compilation failed, skip this pattern
                        }
                    }
                };

                if pcre.negated {
                    if matched {
                        return false;
                    }
                } else if !matched {
                    return false;
                }
            }
        }
        true
    }

    /// Check threshold (direct version)
    #[inline]
    fn check_threshold_direct(&self, rule: &Rule, src_ip: Option<IpAddr>) -> bool {
        for opt in &rule.options {
            match opt {
                RuleOption::Threshold(spec) | RuleOption::DetectionFilter(spec) => {
                    let mut state = self.threshold_state.write();
                    // For direct version, we use src_ip for both src and dst tracking
                    // This matches common use case; rules can use track:by_src
                    if !state.check_threshold(rule.sid, spec, src_ip, src_ip) {
                        return false;
                    }
                }
                _ => {}
            }
        }
        true
    }

    /// Update flowbits state (direct version)
    #[inline]
    fn update_flowbits_direct(&self, rule: &Rule, packet: &Packet, _flow_state: &FlowState) {
        let mut state = self.flowbits_state.write();

        for opt in &rule.options {
            if let RuleOption::Flowbits(op) = opt {
                match op {
                    FlowbitsOp::Set(name) => state.set_for_packet(packet, name),
                    FlowbitsOp::Unset(name) => state.unset_for_packet(packet, name),
                    FlowbitsOp::Toggle(name) => state.toggle_for_packet(packet, name),
                    _ => {}
                }
            }
        }
    }

    /// Cleanup expired state
    pub fn cleanup(&self, max_age: Duration) {
        self.threshold_state.write().cleanup_expired(max_age);
    }

    /// Load rules from persistent storage
    pub fn load_from_storage(&mut self) -> std::io::Result<usize> {
        use super::storage::SignatureStorage;

        let mut storage = SignatureStorage::with_path(&self.config.storage_dir);

        // Initialize storage directory if needed
        storage.init()?;

        // Load all enabled signature sets
        let sets = storage.load_all_enabled()?;
        let mut total_loaded = 0;

        for set in sets {
            for rule in set.rules {
                self.add_rule(rule);
                total_loaded += 1;
            }
        }

        if total_loaded > 0 {
            self.rebuild_prefilter();
        }

        Ok(total_loaded)
    }

    /// Save current rules to persistent storage
    pub fn save_to_storage(&self, name: &str) -> std::io::Result<std::path::PathBuf> {
        use super::storage::{SignatureSet, SignatureStorage};

        let mut storage = SignatureStorage::with_path(&self.config.storage_dir);
        storage.init()?;

        let mut set = SignatureSet::new(name, "custom");
        for rule in self.rules.values() {
            set.add_rule(rule.clone());
        }

        storage.save_set(&set)
    }

    /// Get all current rules for export
    pub fn get_all_rules(&self) -> Vec<&Rule> {
        self.rules.values().collect()
    }

    /// Get the storage directory path
    pub fn storage_dir(&self) -> &std::path::Path {
        &self.config.storage_dir
    }

    /// Check if storage loading is enabled
    pub fn storage_enabled(&self) -> bool {
        self.config.load_from_storage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::packet::{Packet, IpProtocol, TcpFlags};
    use crate::core::layers::{Layer3, Layer4, Ipv4Info, TcpInfo, UdpInfo};
    use std::net::{IpAddr, Ipv4Addr};

    // =========================================================================
    // Helper functions for creating synthetic packets
    // =========================================================================

    /// Create a TCP packet with payload
    fn make_tcp_packet(
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Packet {
        let layer3 = Layer3::Ipv4(Ipv4Info {
            src_addr: src_ip.parse().unwrap(),
            dst_addr: dst_ip.parse().unwrap(),
            protocol: 6, // TCP
            ttl: 64,
            ..Default::default()
        });

        let layer4 = Layer4::Tcp(TcpInfo {
            src_port,
            dst_port,
            seq: 1000,
            ack: 0,
            flags: TcpFlags { syn: false, ack: true, ..Default::default() },
            window: 65535,
            payload: payload.to_vec(),
            ..Default::default()
        });

        Packet::from_layers(1, layer3, layer4, "lo".to_string())
    }

    /// Create a UDP packet with payload
    fn make_udp_packet(
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Packet {
        let layer3 = Layer3::Ipv4(Ipv4Info {
            src_addr: src_ip.parse().unwrap(),
            dst_addr: dst_ip.parse().unwrap(),
            protocol: 17, // UDP
            ttl: 64,
            ..Default::default()
        });

        let layer4 = Layer4::Udp(UdpInfo {
            src_port,
            dst_port,
            length: payload.len() as u16 + 8,
            payload: payload.to_vec(),
        });

        Packet::from_layers(1, layer3, layer4, "lo".to_string())
    }

    /// Create a simple rule for testing
    fn make_rule(
        sid: u32,
        protocol: Protocol,
        content: Option<&[u8]>,
        msg: &str,
    ) -> Rule {
        let mut rule = Rule {
            id: sid,
            sid,
            msg: msg.to_string(),
            protocol,
            action: Action::Alert,
            enabled: true,
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            direction: Direction::Both,
            ..Default::default()
        };

        if let Some(pat) = content {
            rule.options.push(RuleOption::Content(ContentMatch {
                pattern: pat.to_vec(),
                ..Default::default()
            }));
        }

        rule
    }

    // =========================================================================
    // Original tests (preserved)
    // =========================================================================

    #[test]
    fn test_content_match() {
        let engine = SignatureEngine::new(SignatureConfig::default());
        let cm = ContentMatch {
            pattern: b"test".to_vec(),
            ..Default::default()
        };

        assert_eq!(engine.match_content(&cm, b"this is a test", 0), Some(10));
        assert_eq!(engine.match_content(&cm, b"no match here", 0), None);
    }

    #[test]
    fn test_content_match_nocase() {
        let engine = SignatureEngine::new(SignatureConfig::default());
        let cm = ContentMatch {
            pattern: b"TEST".to_vec(),
            nocase: true,
            ..Default::default()
        };

        assert!(engine.match_content(&cm, b"this is a test", 0).is_some());
    }

    #[test]
    fn test_content_match_offset() {
        let engine = SignatureEngine::new(SignatureConfig::default());
        let cm = ContentMatch {
            pattern: b"test".to_vec(),
            offset: Some(10),
            ..Default::default()
        };

        // "this is a test" - "test" starts at position 10
        assert!(engine.match_content(&cm, b"this is a test", 0).is_some());
        // "test at start" is only 13 chars, "test" at offset 10 would need 14 chars minimum
        assert!(engine.match_content(&cm, b"test at start", 0).is_none());
        // Buffer too short for offset
        assert!(engine.match_content(&cm, b"short", 0).is_none());
    }

    #[test]
    fn test_ip_match_cidr() {
        let engine = SignatureEngine::new(SignatureConfig::default());
        let spec = IpSpec::Cidr("192.168.1.0".parse().unwrap(), 24);

        assert!(engine.ip_matches(&spec, Some("192.168.1.100".parse().unwrap())));
        assert!(!engine.ip_matches(&spec, Some("192.168.2.1".parse().unwrap())));
    }

    #[test]
    fn test_port_match_range() {
        let engine = SignatureEngine::new(SignatureConfig::default());
        let spec = PortSpec::Range(80, 443);

        assert!(engine.port_matches(&spec, Some(80)));
        assert!(engine.port_matches(&spec, Some(443)));
        assert!(engine.port_matches(&spec, Some(100)));
        assert!(!engine.port_matches(&spec, Some(8080)));
    }

    // =========================================================================
    // New API tests: match_packet with synthetic sessions
    // =========================================================================

    #[test]
    fn test_match_packet_simple_content() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());
        let rule = make_rule(1001, Protocol::Tcp, Some(b"malware"), "Test malware detection");
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"GET /malware.exe HTTP/1.1");
        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState { established: true, to_server: true };

        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].sid, 1001);
    }

    #[test]
    fn test_match_packet_no_match() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());
        let rule = make_rule(1002, Protocol::Tcp, Some(b"malware"), "Test no match");
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"GET /index.html HTTP/1.1");
        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState { established: true, to_server: true };

        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_packet_protocol_filter() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());
        // UDP-only rule
        let rule = make_rule(1003, Protocol::Udp, Some(b"test"), "UDP only rule");
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        // TCP packet should NOT match UDP rule
        let tcp_pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"test data");
        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();

        let matches = engine.match_packet(&tcp_pkt, &proto_ctx, &flow_state);
        assert!(matches.is_empty(), "TCP packet should not match UDP rule");

        // UDP packet SHOULD match
        let udp_pkt = make_udp_packet("10.0.0.1", "192.168.1.1", 12345, 53, b"test data");
        let matches = engine.match_packet(&udp_pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_match_packet_multiple_rules() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        // Add multiple rules that should match
        let rule1 = make_rule(2001, Protocol::Tcp, Some(b"GET"), "HTTP GET");
        let rule2 = make_rule(2002, Protocol::Tcp, Some(b"HTTP"), "HTTP Protocol");
        engine.add_rule(rule1);
        engine.add_rule(rule2);
        engine.rebuild_prefilter();

        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"GET /index.html HTTP/1.1");
        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState { established: true, to_server: true };

        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_match_packet_http_context() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        // Rule that matches on HTTP URI
        let mut rule = Rule {
            id: 3001,
            sid: 3001,
            msg: "SQL injection attempt".to_string(),
            protocol: Protocol::Tcp,
            action: Action::Alert,
            enabled: true,
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            direction: Direction::Both,
            ..Default::default()
        };
        rule.options.push(RuleOption::HttpUri);
        rule.options.push(RuleOption::Content(ContentMatch {
            pattern: b"UNION SELECT".to_vec(),
            nocase: true,
            ..Default::default()
        }));
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"");
        let proto_ctx = ProtocolContext::Http(HttpContext {
            uri: Some(b"/search?q=UNION SELECT * FROM users".to_vec()),
            method: Some(b"GET".to_vec()),
            ..Default::default()
        });
        let flow_state = FlowState { established: true, to_server: true };

        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].msg, "SQL injection attempt");
    }

    #[test]
    fn test_match_packet_dns_context() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let mut rule = Rule {
            id: 3002,
            sid: 3002,
            msg: "Suspicious DNS query".to_string(),
            protocol: Protocol::Udp,
            action: Action::Alert,
            enabled: true,
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            direction: Direction::Both,
            ..Default::default()
        };
        rule.options.push(RuleOption::DnsQuery);
        rule.options.push(RuleOption::Content(ContentMatch {
            pattern: b"malicious.com".to_vec(),
            nocase: true,
            ..Default::default()
        }));
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let pkt = make_udp_packet("10.0.0.1", "8.8.8.8", 12345, 53, b"");
        let proto_ctx = ProtocolContext::Dns(DnsContext {
            query: Some(b"evil.malicious.com".to_vec()),
        });
        let flow_state = FlowState::default();

        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_match_packet_tls_context() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let mut rule = Rule {
            id: 3003,
            sid: 3003,
            msg: "Suspicious TLS SNI".to_string(),
            protocol: Protocol::Tcp,
            action: Action::Alert,
            enabled: true,
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            direction: Direction::Both,
            ..Default::default()
        };
        rule.options.push(RuleOption::TlsSni);
        rule.options.push(RuleOption::Content(ContentMatch {
            pattern: b"bad-site.com".to_vec(),
            nocase: true,
            ..Default::default()
        }));
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 443, b"");
        let proto_ctx = ProtocolContext::Tls(TlsContext {
            sni: Some(b"www.bad-site.com".to_vec()),
            ja3_hash: None,
        });
        let flow_state = FlowState { established: true, to_server: true };

        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_match_packet_flow_state_established() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        // Rule requires established connection
        let mut rule = make_rule(4001, Protocol::Tcp, Some(b"test"), "Established only");
        rule.options.push(RuleOption::Flow(FlowFlags {
            established: true,
            ..Default::default()
        }));
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"test data");
        let proto_ctx = ProtocolContext::None;

        // Not established - should NOT match
        let flow_state = FlowState { established: false, to_server: true };
        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert!(matches.is_empty(), "Should not match when not established");

        // Established - SHOULD match
        let flow_state = FlowState { established: true, to_server: true };
        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_match_packet_flow_direction_to_server() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let mut rule = make_rule(4002, Protocol::Tcp, Some(b"test"), "To server only");
        rule.options.push(RuleOption::Flow(FlowFlags {
            to_server: true,
            ..Default::default()
        }));
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"test data");
        let proto_ctx = ProtocolContext::None;

        // To client - should NOT match
        let flow_state = FlowState { established: true, to_server: false };
        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert!(matches.is_empty());

        // To server - SHOULD match
        let flow_state = FlowState { established: true, to_server: true };
        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_match_packet_content_nocase() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let mut rule = Rule {
            id: 5001,
            sid: 5001,
            msg: "Case insensitive match".to_string(),
            protocol: Protocol::Tcp,
            action: Action::Alert,
            enabled: true,
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            direction: Direction::Both,
            ..Default::default()
        };
        rule.options.push(RuleOption::Content(ContentMatch {
            pattern: b"MALWARE".to_vec(),
            nocase: true,
            ..Default::default()
        }));
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"downloading malware.exe");
        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();

        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_match_packet_content_depth() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let mut rule = Rule {
            id: 5002,
            sid: 5002,
            msg: "Content with depth".to_string(),
            protocol: Protocol::Tcp,
            action: Action::Alert,
            enabled: true,
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            direction: Direction::Both,
            ..Default::default()
        };
        rule.options.push(RuleOption::Content(ContentMatch {
            pattern: b"GET".to_vec(),
            depth: Some(10),
            ..Default::default()
        }));
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        // GET within first 10 bytes - should match
        let pkt1 = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"GET / HTTP/1.1");
        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();
        let matches = engine.match_packet(&pkt1, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);

        // GET beyond first 10 bytes - should NOT match
        let pkt2 = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"XXXXXXXXXX GET /");
        let matches = engine.match_packet(&pkt2, &proto_ctx, &flow_state);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_packet_multiple_content_patterns() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let mut rule = Rule {
            id: 5003,
            sid: 5003,
            msg: "Multiple content patterns".to_string(),
            protocol: Protocol::Tcp,
            action: Action::Alert,
            enabled: true,
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            direction: Direction::Both,
            ..Default::default()
        };
        // Both patterns must match
        rule.options.push(RuleOption::Content(ContentMatch {
            pattern: b"GET".to_vec(),
            ..Default::default()
        }));
        rule.options.push(RuleOption::Content(ContentMatch {
            pattern: b"HTTP".to_vec(),
            ..Default::default()
        }));
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();

        // Both patterns present - should match
        let pkt1 = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"GET /index.html HTTP/1.1");
        let matches = engine.match_packet(&pkt1, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);

        // Only first pattern - should NOT match
        let pkt2 = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"GET /index.html");
        let matches = engine.match_packet(&pkt2, &proto_ctx, &flow_state);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_packet_negated_content() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let mut rule = Rule {
            id: 5004,
            sid: 5004,
            msg: "Negated content".to_string(),
            protocol: Protocol::Tcp,
            action: Action::Alert,
            enabled: true,
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            direction: Direction::Both,
            ..Default::default()
        };
        rule.options.push(RuleOption::Content(ContentMatch {
            pattern: b"GET".to_vec(),
            ..Default::default()
        }));
        rule.options.push(RuleOption::Content(ContentMatch {
            pattern: b"safe".to_vec(),
            negated: true, // Must NOT contain "safe"
            ..Default::default()
        }));
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();

        // Contains "GET" but not "safe" - should match
        let pkt1 = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"GET /malware.exe");
        let matches = engine.match_packet(&pkt1, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);

        // Contains both "GET" and "safe" - should NOT match
        let pkt2 = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"GET /safe/file.txt");
        let matches = engine.match_packet(&pkt2, &proto_ctx, &flow_state);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_packet_ip_address_filter() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let mut rule = make_rule(6001, Protocol::Tcp, Some(b"test"), "Specific source IP");
        rule.src_ip = IpSpec::Cidr("10.0.0.0".parse().unwrap(), 8);
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();

        // Source IP in 10.0.0.0/8 - should match
        let pkt1 = make_tcp_packet("10.1.2.3", "192.168.1.1", 12345, 80, b"test data");
        let matches = engine.match_packet(&pkt1, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);

        // Source IP NOT in 10.0.0.0/8 - should NOT match
        let pkt2 = make_tcp_packet("192.168.1.100", "192.168.1.1", 12345, 80, b"test data");
        let matches = engine.match_packet(&pkt2, &proto_ctx, &flow_state);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_packet_port_filter() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let mut rule = make_rule(6002, Protocol::Tcp, Some(b"test"), "HTTP ports only");
        rule.dst_port = PortSpec::List(vec![
            PortSpec::Single(80),
            PortSpec::Single(8080),
            PortSpec::Single(443),
        ]);
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();

        // Port 80 - should match
        let pkt1 = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"test data");
        let matches = engine.match_packet(&pkt1, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);

        // Port 22 - should NOT match
        let pkt2 = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 22, b"test data");
        let matches = engine.match_packet(&pkt2, &proto_ctx, &flow_state);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_match_packet_empty_payload() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        // Rule without content - should match based on protocol only
        let rule = make_rule(7001, Protocol::Tcp, None, "TCP packet no content");
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"");
        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();

        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_match_packet_large_payload() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let rule = make_rule(7002, Protocol::Tcp, Some(b"END_MARKER"), "Large payload test");
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        // Create large payload with marker at the end
        let mut payload = vec![b'X'; 10000];
        payload.extend_from_slice(b"END_MARKER");

        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, &payload);
        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();

        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_match_packet_binary_content() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        // Binary pattern (shellcode-like)
        let binary_pattern = vec![0x90, 0x90, 0x90, 0x90]; // NOP sled
        let mut rule = Rule {
            id: 7003,
            sid: 7003,
            msg: "NOP sled detected".to_string(),
            protocol: Protocol::Tcp,
            action: Action::Alert,
            enabled: true,
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            direction: Direction::Both,
            ..Default::default()
        };
        rule.options.push(RuleOption::Content(ContentMatch {
            pattern: binary_pattern.clone(),
            ..Default::default()
        }));
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        // Payload with NOP sled
        let payload: Vec<u8> = vec![0x00, 0x01, 0x90, 0x90, 0x90, 0x90, 0xCC];
        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, &payload);
        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();

        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_match_packet_disabled_rule() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let mut rule = make_rule(8001, Protocol::Tcp, Some(b"test"), "Disabled rule");
        rule.enabled = false;
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"test data");
        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();

        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert!(matches.is_empty(), "Disabled rule should not match");
    }

    #[test]
    fn test_match_packet_noalert_rule() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let mut rule = make_rule(8002, Protocol::Tcp, Some(b"test"), "Noalert rule");
        rule.options.push(RuleOption::Noalert);
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"test data");
        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();

        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert!(matches.is_empty(), "Noalert rule should not generate alert");
    }

    #[test]
    fn test_match_packet_protocol_any() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let rule = make_rule(9001, Protocol::Any, Some(b"test"), "Any protocol");
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();

        // TCP should match
        let tcp_pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"test data");
        let matches = engine.match_packet(&tcp_pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);

        // UDP should also match
        let udp_pkt = make_udp_packet("10.0.0.1", "192.168.1.1", 12345, 53, b"test data");
        let matches = engine.match_packet(&udp_pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn test_match_result_fields() {
        let mut engine = SignatureEngine::new(SignatureConfig::default());

        let mut rule = Rule {
            id: 10001,
            sid: 10001,
            msg: "Test alert message".to_string(),
            protocol: Protocol::Tcp,
            action: Action::Alert,
            enabled: true,
            priority: 2,
            classtype: Some("attempted-admin".to_string()),
            src_ip: IpSpec::Any,
            src_port: PortSpec::Any,
            dst_ip: IpSpec::Any,
            dst_port: PortSpec::Any,
            direction: Direction::Both,
            ..Default::default()
        };
        rule.options.push(RuleOption::Content(ContentMatch {
            pattern: b"admin".to_vec(),
            ..Default::default()
        }));
        engine.add_rule(rule);
        engine.rebuild_prefilter();

        let pkt = make_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80, b"GET /admin/login");
        let proto_ctx = ProtocolContext::None;
        let flow_state = FlowState::default();

        let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
        assert_eq!(matches.len(), 1);

        let result = &matches[0];
        assert_eq!(result.sid, 10001);
        assert_eq!(result.msg, "Test alert message");
        assert_eq!(result.priority, 2);
        assert_eq!(result.classtype, Some("attempted-admin".to_string()));
        assert_eq!(result.action, Action::Alert);
    }

    // =========================================================================
    // Rule loading from filesystem tests
    // =========================================================================

    #[test]
    fn test_load_default_rules() {
        use std::path::Path;

        let rules_dir = Path::new("/var/lib/crmonban/data/signatures/suricata/rules");

        // Skip test if rules directory doesn't exist (CI environment)
        if !rules_dir.exists() {
            eprintln!("Skipping test_load_default_rules: rules directory not found");
            return;
        }

        // Load rules from default directory
        let result = SignatureEngine::load_default_rules();
        assert!(result.is_ok(), "Failed to load rules: {:?}", result.err());

        let engine = result.unwrap();

        // Verify rules were loaded
        let stats = engine.stats();
        assert!(stats.total_rules > 0, "No rules loaded from {:?}", rules_dir);

        // Verify prefilter was built
        assert!(engine.prefilter_pattern_count() > 0, "Prefilter not built");

        eprintln!(
            "Loaded {} rules ({} disabled, {} prefilter patterns)",
            stats.total_rules,
            stats.disabled,
            engine.prefilter_pattern_count()
        );
    }

    #[test]
    fn test_load_default_rules_verbose() {
        use std::path::Path;

        let rules_dir = Path::new("/var/lib/crmonban/data/signatures/suricata/rules");

        // Skip test if rules directory doesn't exist
        if !rules_dir.exists() {
            eprintln!("Skipping test_load_default_rules_verbose: rules directory not found");
            return;
        }

        let result = SignatureEngine::load_default_rules_verbose();
        assert!(result.is_ok(), "Failed to load rules: {:?}", result.err());

        let engine = result.unwrap();
        assert!(engine.stats().total_rules > 0, "No rules loaded");
    }

    #[test]
    fn test_load_rules_from_custom_directory() {
        use std::path::PathBuf;
        use crate::signatures::RuleLoader;

        let rules_dir = PathBuf::from("/var/lib/crmonban/data/signatures/suricata/rules");

        // Skip test if rules directory doesn't exist
        if !rules_dir.exists() {
            eprintln!("Skipping test_load_rules_from_custom_directory: rules directory not found");
            return;
        }

        let mut config = SignatureConfig::default();
        config.rule_dirs = vec![rules_dir.clone()];

        let mut loader = RuleLoader::new(config.clone());
        let ruleset = loader.load_all();
        assert!(ruleset.is_ok(), "Failed to load ruleset: {:?}", ruleset.err());

        let ruleset = ruleset.unwrap();
        assert!(ruleset.stats.total_rules > 0, "No rules in ruleset");

        // Build engine from loaded rules
        let mut engine = SignatureEngine::new(config);
        for (_, rule) in ruleset.rules {
            engine.add_rule(rule);
        }
        engine.rebuild_prefilter();

        eprintln!(
            "Custom load: {} rules, {} with content, {} disabled",
            ruleset.stats.total_rules,
            ruleset.stats.with_content,
            ruleset.stats.disabled
        );
    }

    #[test]
    fn test_load_nonexistent_directory() {
        use std::path::PathBuf;
        use crate::signatures::RuleLoader;

        let mut config = SignatureConfig::default();
        config.rule_dirs = vec![PathBuf::from("/nonexistent/rules/directory")];

        let mut loader = RuleLoader::new(config);
        let result = loader.load_all();

        // Should succeed but load no rules (directory doesn't exist)
        assert!(result.is_ok());
        let ruleset = result.unwrap();
        assert_eq!(ruleset.stats.total_rules, 0, "Should load 0 rules from nonexistent dir");
    }
}
