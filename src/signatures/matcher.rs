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

use super::ast::*;
use super::{SignatureConfig, RuleStats};

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

/// Packet context for matching
#[derive(Debug, Clone, Default)]
pub struct PacketContext {
    /// Source IP
    pub src_ip: Option<IpAddr>,
    /// Destination IP
    pub dst_ip: Option<IpAddr>,
    /// Source port
    pub src_port: Option<u16>,
    /// Destination port
    pub dst_port: Option<u16>,
    /// Protocol
    pub protocol: Protocol,
    /// TCP flags
    pub tcp_flags: u8,
    /// TTL
    pub ttl: u8,
    /// Payload data
    pub payload: Vec<u8>,
    /// Is established connection
    pub established: bool,
    /// Direction to server
    pub to_server: bool,
    /// HTTP URI (if HTTP)
    pub http_uri: Option<Vec<u8>>,
    /// HTTP method
    pub http_method: Option<Vec<u8>>,
    /// HTTP headers
    pub http_headers: Option<Vec<u8>>,
    /// HTTP host
    pub http_host: Option<Vec<u8>>,
    /// HTTP user agent
    pub http_user_agent: Option<Vec<u8>>,
    /// DNS query name
    pub dns_query: Option<Vec<u8>>,
    /// TLS SNI
    pub tls_sni: Option<Vec<u8>>,
    /// JA3 fingerprint
    pub ja3_hash: Option<String>,
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

    /// Generate flow key as u64 hash (much faster than String formatting)
    #[inline]
    fn flow_key(ctx: &PacketContext) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        ctx.src_ip.hash(&mut hasher);
        ctx.src_port.hash(&mut hasher);
        ctx.dst_ip.hash(&mut hasher);
        ctx.dst_port.hash(&mut hasher);
        hasher.finish()
    }

    #[inline]
    fn set(&mut self, ctx: &PacketContext, name: &str) {
        let key = Self::flow_key(ctx);
        self.bits.entry(key).or_default().insert(name.to_string());
    }

    #[inline]
    fn unset(&mut self, ctx: &PacketContext, name: &str) {
        let key = Self::flow_key(ctx);
        if let Some(bits) = self.bits.get_mut(&key) {
            bits.remove(name);
        }
    }

    #[inline]
    fn is_set(&self, ctx: &PacketContext, name: &str) -> bool {
        let key = Self::flow_key(ctx);
        self.bits.get(&key).map(|b| b.contains(name)).unwrap_or(false)
    }

    #[inline]
    fn toggle(&mut self, ctx: &PacketContext, name: &str) {
        let key = Self::flow_key(ctx);
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
    #[inline]
    pub fn match_packet(&self, ctx: &PacketContext) -> Vec<MatchResult> {
        let mut results = Vec::new();

        // Get candidate rules from prefilter
        let candidates = if let Some(ref prefilter) = self.prefilter {
            prefilter.find_candidates(&ctx.payload)
        } else {
            // No prefilter - check all rules for matching protocol
            self.get_protocol_rules(ctx.protocol)
        };

        // Verify each candidate rule
        for rule_id in candidates {
            if let Some(rule) = self.rules.get(&rule_id) {
                if let Some(result) = self.verify_rule(rule, ctx) {
                    results.push(result);
                }
            }
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

    /// Fully verify a rule against packet context
    #[inline]
    fn verify_rule(&self, rule: &Rule, ctx: &PacketContext) -> Option<MatchResult> {
        // Check if rule is enabled
        if !rule.enabled {
            return None;
        }

        // Check protocol match
        if !self.check_protocol(rule, ctx) {
            return None;
        }

        // Check IP/port match
        if !self.check_addresses(rule, ctx) {
            return None;
        }

        // Check flow flags
        if !self.check_flow(rule, ctx) {
            return None;
        }

        // Check flowbits prerequisites
        if !self.check_flowbits_prereqs(rule, ctx) {
            return None;
        }

        // Match content patterns
        let content_matches = self.match_contents(rule, ctx)?;

        // Match PCRE patterns
        if !self.match_pcre(rule, ctx) {
            return None;
        }

        // Check threshold/detection_filter
        if !self.check_threshold(rule, ctx) {
            return None;
        }

        // Update flowbits state
        self.update_flowbits(rule, ctx);

        // Check for noalert
        if rule.options.iter().any(|o| matches!(o, RuleOption::Noalert)) {
            return None;
        }

        Some(MatchResult {
            rule_id: rule.id,
            sid: rule.sid,
            msg: rule.msg.clone(),
            classtype: rule.classtype.clone(),
            priority: rule.priority,
            action: rule.action,
            references: rule.references.clone(),
            timestamp: Instant::now(),
            content_matches,
        })
    }

    #[inline]
    fn check_protocol(&self, rule: &Rule, ctx: &PacketContext) -> bool {
        rule.protocol == Protocol::Any || rule.protocol == ctx.protocol
    }

    #[inline]
    fn check_addresses(&self, rule: &Rule, ctx: &PacketContext) -> bool {
        // Check source IP
        if !self.ip_matches(&rule.src_ip, ctx.src_ip) {
            return false;
        }

        // Check destination IP
        if !self.ip_matches(&rule.dst_ip, ctx.dst_ip) {
            return false;
        }

        // Check source port
        if !self.port_matches(&rule.src_port, ctx.src_port) {
            return false;
        }

        // Check destination port
        if !self.port_matches(&rule.dst_port, ctx.dst_port) {
            return false;
        }

        // Check direction
        match rule.direction {
            Direction::ToServer => ctx.to_server,
            Direction::ToClient => !ctx.to_server,
            Direction::Both => true,
        }
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

    fn check_flow(&self, rule: &Rule, ctx: &PacketContext) -> bool {
        if let Some(flags) = rule.flow_flags() {
            if flags.established && !ctx.established {
                return false;
            }
            if flags.not_established && ctx.established {
                return false;
            }
            if flags.to_server && !ctx.to_server {
                return false;
            }
            if flags.to_client && ctx.to_server {
                return false;
            }
        }
        true
    }

    fn check_flowbits_prereqs(&self, rule: &Rule, ctx: &PacketContext) -> bool {
        let state = self.flowbits_state.read();

        for opt in &rule.options {
            if let RuleOption::Flowbits(op) = opt {
                match op {
                    FlowbitsOp::IsSet(name) => {
                        if !state.is_set(ctx, name) {
                            return false;
                        }
                    }
                    FlowbitsOp::IsNotSet(name) => {
                        if state.is_set(ctx, name) {
                            return false;
                        }
                    }
                    _ => {}
                }
            }
        }

        true
    }

    fn update_flowbits(&self, rule: &Rule, ctx: &PacketContext) {
        let mut state = self.flowbits_state.write();

        for opt in &rule.options {
            if let RuleOption::Flowbits(op) = opt {
                match op {
                    FlowbitsOp::Set(name) => state.set(ctx, name),
                    FlowbitsOp::Unset(name) => state.unset(ctx, name),
                    FlowbitsOp::Toggle(name) => state.toggle(ctx, name),
                    _ => {}
                }
            }
        }
    }

    fn match_contents(&self, rule: &Rule, ctx: &PacketContext) -> Option<Vec<(usize, usize)>> {
        let mut matches = Vec::new();
        let mut last_match_end = 0;

        for opt in &rule.options {
            if let RuleOption::Content(cm) = opt {
                // Select buffer based on sticky buffers
                let buffer = self.select_buffer(rule, ctx, opt);

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

    fn select_buffer<'a>(&self, rule: &Rule, ctx: &'a PacketContext, current_opt: &RuleOption) -> &'a [u8] {
        // Find the most recent sticky buffer before this option
        let mut use_buffer = None;
        for opt in &rule.options {
            if std::ptr::eq(opt, current_opt) {
                break;
            }

            use_buffer = match opt {
                RuleOption::HttpUri => ctx.http_uri.as_deref(),
                RuleOption::HttpMethod => ctx.http_method.as_deref(),
                RuleOption::HttpHeader => ctx.http_headers.as_deref(),
                RuleOption::HttpHost => ctx.http_host.as_deref(),
                RuleOption::HttpUserAgent => ctx.http_user_agent.as_deref(),
                RuleOption::DnsQuery => ctx.dns_query.as_deref(),
                RuleOption::TlsSni => ctx.tls_sni.as_deref(),
                _ => continue,
            };
        }

        use_buffer.unwrap_or(&ctx.payload)
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

    fn match_pcre(&self, rule: &Rule, ctx: &PacketContext) -> bool {
        for opt in &rule.options {
            if let RuleOption::Pcre(pcre) = opt {
                let buffer = &ctx.payload;
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

    fn check_threshold(&self, rule: &Rule, ctx: &PacketContext) -> bool {
        for opt in &rule.options {
            match opt {
                RuleOption::Threshold(spec) | RuleOption::DetectionFilter(spec) => {
                    let mut state = self.threshold_state.write();
                    if !state.check_threshold(rule.sid, spec, ctx.src_ip, ctx.dst_ip) {
                        return false;
                    }
                }
                _ => {}
            }
        }
        true
    }

    /// Cleanup expired state
    pub fn cleanup(&self, max_age: Duration) {
        self.threshold_state.write().cleanup_expired(max_age);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
