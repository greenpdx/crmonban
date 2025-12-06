# Implementation Plan: Suricata/Snort Rule Compatibility

## Overview

Add the ability to parse and execute Suricata/Snort rule syntax, giving crmonban instant access to 30,000+ community detection rules from Emerging Threats, Snort Community, and other sources.

## Why This First?

1. **Immediate value**: Thousands of battle-tested detection signatures
2. **Industry standard**: Security teams already know the syntax
3. **Foundation**: Other features (threat intel, protocol detection) build on this
4. **Competitive parity**: Suricata's rule compatibility is a key strength

## Suricata Rule Syntax Overview

```
action protocol src_ip src_port -> dst_ip dst_port (options)
```

### Example Rules

```snort
# Basic signature match
alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; content:"UNION SELECT"; nocase; sid:1000001; rev:1;)

# HTTP-specific with header inspection
alert http any any -> any any (msg:"Malicious User-Agent"; http.user_agent; content:"nikto"; nocase; sid:1000002;)

# TLS/JA3 fingerprint
alert tls any any -> any any (msg:"Cobalt Strike Beacon"; ja3.hash; content:"72a589da586844d7f0818ce684948eea"; sid:1000003;)

# DNS query
alert dns any any -> any any (msg:"Malware C2 Domain"; dns.query; content:".evil.com"; endswith; sid:1000004;)

# PCRE regex
alert tcp any any -> any any (msg:"Shell Command"; content:"|2f 62 69 6e 2f|"; pcre:"/\/(bin|usr\/bin)\/(sh|bash|nc)/i"; sid:1000005;)

# Flow-based
alert tcp any any -> any 22 (msg:"SSH Brute Force"; flow:to_server,established; threshold:type both,track by_src,count 5,seconds 60; sid:1000006;)
```

## Implementation Architecture

```
src/rules/
├── mod.rs           # Module exports
├── parser.rs        # Rule syntax parser (nom-based)
├── ast.rs           # Abstract syntax tree for rules
├── matcher.rs       # Pattern matching engine
├── loader.rs        # Load rules from files/directories
├── compiler.rs      # Compile rules to optimized form
├── variables.rs     # $HOME_NET, $EXTERNAL_NET, etc.
└── builtin/
    ├── mod.rs
    ├── content.rs   # content, nocase, offset, depth
    ├── pcre.rs      # PCRE regex matching
    ├── flow.rs      # flow:to_server, established
    ├── threshold.rs # threshold, detection_filter
    ├── http.rs      # http.uri, http.header, http.method
    ├── dns.rs       # dns.query, dns.answer
    ├── tls.rs       # tls.sni, tls.cert_subject, ja3.hash
    └── meta.rs      # msg, sid, rev, classtype, priority
```

## Detailed Implementation

### Step 1.1: Rule AST Definition (`src/rules/ast.rs`)

```rust
/// Rule action
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Alert,      // Generate alert
    Drop,       // Drop packet (IPS mode)
    Reject,     // Reject with RST/ICMP
    Pass,       // Allow through
    Log,        // Log only
}

/// Protocol
#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Ip,         // Any IP protocol
    Http,       // Application layer
    Dns,
    Tls,
    Ssh,
    Ftp,
    Smtp,
    Smb,
}

/// IP address specification
#[derive(Debug, Clone, PartialEq)]
pub enum IpSpec {
    Any,
    Var(String),                    // $HOME_NET
    Single(IpAddr),                 // 192.168.1.1
    Cidr(IpAddr, u8),              // 192.168.1.0/24
    Range(IpAddr, IpAddr),         // 192.168.1.1-192.168.1.100
    List(Vec<IpSpec>),             // [192.168.1.0/24, 10.0.0.0/8]
    Negated(Box<IpSpec>),          // !192.168.1.1
}

/// Port specification
#[derive(Debug, Clone, PartialEq)]
pub enum PortSpec {
    Any,
    Single(u16),                    // 80
    Range(u16, u16),               // 1024:65535
    List(Vec<PortSpec>),           // [80, 443, 8080]
    Negated(Box<PortSpec>),        // !22
}

/// Direction
#[derive(Debug, Clone, PartialEq)]
pub enum Direction {
    ToServer,    // ->
    ToClient,    // <-
    Both,        // <>
}

/// Rule option
#[derive(Debug, Clone)]
pub enum RuleOption {
    // Metadata
    Msg(String),
    Sid(u32),
    Rev(u32),
    Classtype(String),
    Priority(u8),
    Metadata(Vec<(String, String)>),
    Reference(String, String),

    // Content matching
    Content(ContentMatch),
    Pcre(PcreMatch),
    ByteTest(ByteTest),
    ByteJump(ByteJump),
    ByteExtract(ByteExtract),

    // Flow
    Flow(FlowFlags),
    Flowbits(FlowbitsOp),

    // Thresholds
    Threshold(ThresholdSpec),
    DetectionFilter(DetectionFilter),

    // Protocol-specific
    HttpUri,
    HttpHeader,
    HttpMethod,
    HttpUserAgent,
    HttpHost,
    HttpCookie,
    HttpRequestBody,
    HttpResponseBody,
    HttpStat,

    DnsQuery,
    DnsAnswer,

    TlsSni,
    TlsCertSubject,
    TlsCertIssuer,
    TlsVersion,
    Ja3Hash,
    Ja3sHash,

    // Packet
    Dsize(Comparison),
    Flags(TcpFlags),
    Ttl(Comparison),
    Ipopts(IpOption),

    // Performance
    FastPattern,
    Noalert,
}

/// Content match options
#[derive(Debug, Clone)]
pub struct ContentMatch {
    pub pattern: Vec<u8>,           // Pattern bytes
    pub negated: bool,              // ! prefix
    pub nocase: bool,               // Case insensitive
    pub offset: Option<u32>,        // Start position
    pub depth: Option<u32>,         // Max search depth
    pub distance: Option<i32>,      // Relative to last match
    pub within: Option<u32>,        // Must match within N bytes
    pub fast_pattern: bool,         // Use for fast pre-filter
    pub rawbytes: bool,             // Match raw, not normalized
}

/// PCRE regex match
#[derive(Debug, Clone)]
pub struct PcreMatch {
    pub pattern: String,
    pub flags: String,              // i, s, m, etc.
    pub negated: bool,
    pub relative: bool,             // R flag
}

/// Complete parsed rule
#[derive(Debug, Clone)]
pub struct Rule {
    pub id: u32,                    // Internal ID
    pub enabled: bool,
    pub action: Action,
    pub protocol: Protocol,
    pub src_ip: IpSpec,
    pub src_port: PortSpec,
    pub direction: Direction,
    pub dst_ip: IpSpec,
    pub dst_port: PortSpec,
    pub options: Vec<RuleOption>,

    // Extracted metadata
    pub sid: u32,
    pub rev: u32,
    pub msg: String,
    pub classtype: Option<String>,
    pub priority: u8,
}
```

### Step 1.2: Rule Parser (`src/rules/parser.rs`)

Using `nom` for parsing:

```rust
use nom::{
    IResult,
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_until, take_while1},
    character::complete::{char, digit1, multispace0, multispace1},
    combinator::{map, opt, value},
    multi::{many0, separated_list0},
    sequence::{delimited, preceded, tuple},
};

/// Parse a complete rule
pub fn parse_rule(input: &str) -> IResult<&str, Rule> {
    let (input, _) = multispace0(input)?;
    let (input, action) = parse_action(input)?;
    let (input, _) = multispace1(input)?;
    let (input, protocol) = parse_protocol(input)?;
    let (input, _) = multispace1(input)?;
    let (input, src_ip) = parse_ip_spec(input)?;
    let (input, _) = multispace1(input)?;
    let (input, src_port) = parse_port_spec(input)?;
    let (input, _) = multispace1(input)?;
    let (input, direction) = parse_direction(input)?;
    let (input, _) = multispace1(input)?;
    let (input, dst_ip) = parse_ip_spec(input)?;
    let (input, _) = multispace1(input)?;
    let (input, dst_port) = parse_port_spec(input)?;
    let (input, _) = multispace0(input)?;
    let (input, options) = parse_options(input)?;

    // Extract metadata from options
    let sid = extract_sid(&options).unwrap_or(0);
    let rev = extract_rev(&options).unwrap_or(1);
    let msg = extract_msg(&options).unwrap_or_default();
    let classtype = extract_classtype(&options);
    let priority = extract_priority(&options).unwrap_or(3);

    Ok((input, Rule {
        id: sid,
        enabled: true,
        action,
        protocol,
        src_ip,
        src_port,
        direction,
        dst_ip,
        dst_port,
        options,
        sid,
        rev,
        msg,
        classtype,
        priority,
    }))
}

fn parse_action(input: &str) -> IResult<&str, Action> {
    alt((
        value(Action::Alert, tag_no_case("alert")),
        value(Action::Drop, tag_no_case("drop")),
        value(Action::Reject, tag_no_case("reject")),
        value(Action::Pass, tag_no_case("pass")),
        value(Action::Log, tag_no_case("log")),
    ))(input)
}

fn parse_protocol(input: &str) -> IResult<&str, Protocol> {
    alt((
        value(Protocol::Tcp, tag_no_case("tcp")),
        value(Protocol::Udp, tag_no_case("udp")),
        value(Protocol::Icmp, tag_no_case("icmp")),
        value(Protocol::Http, tag_no_case("http")),
        value(Protocol::Dns, tag_no_case("dns")),
        value(Protocol::Tls, tag_no_case("tls")),
        value(Protocol::Ssh, tag_no_case("ssh")),
        value(Protocol::Ftp, tag_no_case("ftp")),
        value(Protocol::Smtp, tag_no_case("smtp")),
        value(Protocol::Smb, tag_no_case("smb")),
        value(Protocol::Ip, tag_no_case("ip")),
    ))(input)
}

/// Parse content option with all modifiers
fn parse_content(input: &str) -> IResult<&str, RuleOption> {
    let (input, _) = tag_no_case("content")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = char(':')(input)?;
    let (input, _) = multispace0(input)?;

    // Check for negation
    let (input, negated) = opt(char('!'))(input)?;

    // Parse quoted string with hex support
    let (input, pattern) = parse_content_string(input)?;

    Ok((input, RuleOption::Content(ContentMatch {
        pattern,
        negated: negated.is_some(),
        nocase: false,
        offset: None,
        depth: None,
        distance: None,
        within: None,
        fast_pattern: false,
        rawbytes: false,
    })))
}

/// Parse content string including hex escapes like |00 01 02|
fn parse_content_string(input: &str) -> IResult<&str, Vec<u8>> {
    let (input, _) = char('"')(input)?;
    let mut result = Vec::new();
    let mut chars = input.chars().peekable();
    let mut consumed = 0;

    while let Some(c) = chars.next() {
        consumed += c.len_utf8();
        match c {
            '"' => break,
            '|' => {
                // Hex mode
                let mut hex_str = String::new();
                while let Some(&hc) = chars.peek() {
                    if hc == '|' {
                        chars.next();
                        consumed += 1;
                        break;
                    }
                    if !hc.is_whitespace() {
                        hex_str.push(hc);
                    }
                    chars.next();
                    consumed += hc.len_utf8();
                }
                // Parse hex bytes
                for chunk in hex_str.as_bytes().chunks(2) {
                    if chunk.len() == 2 {
                        if let Ok(byte) = u8::from_str_radix(
                            std::str::from_utf8(chunk).unwrap_or(""),
                            16
                        ) {
                            result.push(byte);
                        }
                    }
                }
            }
            '\\' => {
                if let Some(esc) = chars.next() {
                    consumed += esc.len_utf8();
                    match esc {
                        'n' => result.push(b'\n'),
                        'r' => result.push(b'\r'),
                        't' => result.push(b'\t'),
                        '\\' => result.push(b'\\'),
                        '"' => result.push(b'"'),
                        _ => {
                            result.push(b'\\');
                            result.push(esc as u8);
                        }
                    }
                }
            }
            _ => result.push(c as u8),
        }
    }

    Ok((&input[consumed..], result))
}
```

### Step 1.3: Rule Matcher (`src/rules/matcher.rs`)

```rust
use aho_corasick::AhoCorasick;
use regex::bytes::Regex;

/// Compiled rule set for fast matching
pub struct RuleSet {
    rules: Vec<Rule>,

    // Fast pre-filter using Aho-Corasick
    content_matcher: Option<AhoCorasick>,
    content_to_rules: HashMap<usize, Vec<usize>>,

    // Compiled PCRE patterns
    pcre_cache: HashMap<u32, Regex>,
}

impl RuleSet {
    /// Create new ruleset from parsed rules
    pub fn new(rules: Vec<Rule>) -> Self {
        let mut ruleset = Self {
            rules,
            content_matcher: None,
            content_to_rules: HashMap::new(),
            pcre_cache: HashMap::new(),
        };
        ruleset.compile();
        ruleset
    }

    /// Compile rules for fast matching
    fn compile(&mut self) {
        // Extract all content patterns for Aho-Corasick
        let mut patterns = Vec::new();

        for (rule_idx, rule) in self.rules.iter().enumerate() {
            for opt in &rule.options {
                if let RuleOption::Content(cm) = opt {
                    if cm.fast_pattern || patterns.is_empty() {
                        let pattern_idx = patterns.len();
                        patterns.push(cm.pattern.clone());
                        self.content_to_rules
                            .entry(pattern_idx)
                            .or_default()
                            .push(rule_idx);
                    }
                }
            }
        }

        if !patterns.is_empty() {
            self.content_matcher = Some(
                AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(&patterns)
                    .expect("Failed to build Aho-Corasick")
            );
        }

        // Pre-compile PCRE patterns
        for rule in &self.rules {
            for opt in &rule.options {
                if let RuleOption::Pcre(pcre) = opt {
                    let regex_pattern = format!(
                        "(?{}){}",
                        pcre.flags,
                        pcre.pattern
                    );
                    if let Ok(re) = Regex::new(&regex_pattern) {
                        self.pcre_cache.insert(rule.sid, re);
                    }
                }
            }
        }
    }

    /// Match packet against all rules
    pub fn match_packet(&self, packet: &Packet) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        // Phase 1: Fast pre-filter with Aho-Corasick
        let candidate_rules: HashSet<usize> = if let Some(ref ac) = self.content_matcher {
            ac.find_iter(&packet.payload)
                .flat_map(|m| {
                    self.content_to_rules
                        .get(&m.pattern().as_usize())
                        .cloned()
                        .unwrap_or_default()
                })
                .collect()
        } else {
            (0..self.rules.len()).collect()
        };

        // Phase 2: Full rule evaluation for candidates
        for rule_idx in candidate_rules {
            let rule = &self.rules[rule_idx];

            if self.evaluate_rule(rule, packet) {
                matches.push(RuleMatch {
                    rule_id: rule.sid,
                    action: rule.action.clone(),
                    msg: rule.msg.clone(),
                    priority: rule.priority,
                    classtype: rule.classtype.clone(),
                });
            }
        }

        matches
    }

    /// Evaluate a single rule against a packet
    fn evaluate_rule(&self, rule: &Rule, packet: &Packet) -> bool {
        // Check protocol
        if !self.match_protocol(rule.protocol, packet) {
            return false;
        }

        // Check direction and IPs
        if !self.match_addresses(rule, packet) {
            return false;
        }

        // Check ports
        if !self.match_ports(rule, packet) {
            return false;
        }

        // Evaluate all options (AND logic)
        let mut last_match_pos = 0;

        for opt in &rule.options {
            match opt {
                RuleOption::Content(cm) => {
                    if !self.match_content(cm, &packet.payload, &mut last_match_pos) {
                        return false;
                    }
                }
                RuleOption::Pcre(pcre) => {
                    if let Some(re) = self.pcre_cache.get(&rule.sid) {
                        let search_from = if pcre.relative { last_match_pos } else { 0 };
                        if !re.is_match(&packet.payload[search_from..]) {
                            return false;
                        }
                    }
                }
                RuleOption::Dsize(cmp) => {
                    if !cmp.compare(packet.payload.len()) {
                        return false;
                    }
                }
                RuleOption::Flow(flags) => {
                    if !self.match_flow(flags, packet) {
                        return false;
                    }
                }
                // ... other options
                _ => {}
            }
        }

        true
    }

    fn match_content(
        &self,
        cm: &ContentMatch,
        payload: &[u8],
        last_pos: &mut usize
    ) -> bool {
        let search_start = cm.offset.unwrap_or(0) as usize;
        let search_end = cm.depth
            .map(|d| (search_start + d as usize).min(payload.len()))
            .unwrap_or(payload.len());

        if search_start >= payload.len() {
            return cm.negated;
        }

        let search_slice = &payload[search_start..search_end];

        let found = if cm.nocase {
            search_slice
                .windows(cm.pattern.len())
                .any(|w| w.eq_ignore_ascii_case(&cm.pattern))
        } else {
            search_slice
                .windows(cm.pattern.len())
                .any(|w| w == cm.pattern.as_slice())
        };

        if found {
            // Update last match position for relative matches
            if let Some(pos) = search_slice
                .windows(cm.pattern.len())
                .position(|w| {
                    if cm.nocase {
                        w.eq_ignore_ascii_case(&cm.pattern)
                    } else {
                        w == cm.pattern.as_slice()
                    }
                })
            {
                *last_pos = search_start + pos + cm.pattern.len();
            }
        }

        found != cm.negated
    }
}

/// Match result
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: u32,
    pub action: Action,
    pub msg: String,
    pub priority: u8,
    pub classtype: Option<String>,
}
```

### Step 1.4: Rule Loader (`src/rules/loader.rs`)

```rust
use std::path::Path;
use walkdir::WalkDir;

/// Rule loader with variable expansion
pub struct RuleLoader {
    variables: HashMap<String, String>,
    rules: Vec<Rule>,
}

impl RuleLoader {
    pub fn new() -> Self {
        let mut loader = Self {
            variables: HashMap::new(),
            rules: Vec::new(),
        };

        // Default variables
        loader.set_var("HOME_NET", "any");
        loader.set_var("EXTERNAL_NET", "any");
        loader.set_var("HTTP_PORTS", "80,8080,8000,8888");
        loader.set_var("SSH_PORTS", "22");
        loader.set_var("DNS_PORTS", "53");
        loader.set_var("HTTPS_PORTS", "443,8443");

        loader
    }

    pub fn set_var(&mut self, name: &str, value: &str) {
        self.variables.insert(name.to_string(), value.to_string());
    }

    /// Load rules from a file
    pub fn load_file<P: AsRef<Path>>(&mut self, path: P) -> Result<usize> {
        let content = std::fs::read_to_string(&path)?;
        let mut count = 0;

        for line in content.lines() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Variable definition
            if line.starts_with("var ") || line.starts_with("ipvar ") ||
               line.starts_with("portvar ") {
                self.parse_variable(line);
                continue;
            }

            // Expand variables and parse rule
            let expanded = self.expand_variables(line);

            match parse_rule(&expanded) {
                Ok((_, rule)) => {
                    self.rules.push(rule);
                    count += 1;
                }
                Err(e) => {
                    warn!("Failed to parse rule: {}", e);
                }
            }
        }

        Ok(count)
    }

    /// Load all .rules files from a directory
    pub fn load_directory<P: AsRef<Path>>(&mut self, path: P) -> Result<usize> {
        let mut total = 0;

        for entry in WalkDir::new(&path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.extension().map(|e| e == "rules").unwrap_or(false) {
                match self.load_file(path) {
                    Ok(count) => {
                        info!("Loaded {} rules from {}", count, path.display());
                        total += count;
                    }
                    Err(e) => {
                        warn!("Failed to load {}: {}", path.display(), e);
                    }
                }
            }
        }

        Ok(total)
    }

    /// Expand $VARIABLE references
    fn expand_variables(&self, line: &str) -> String {
        let mut result = line.to_string();

        for (name, value) in &self.variables {
            result = result.replace(&format!("${}", name), value);
            result = result.replace(&format!("${{{}}}", name), value);
        }

        result
    }

    /// Build the final ruleset
    pub fn build(self) -> RuleSet {
        RuleSet::new(self.rules)
    }
}
```

### Step 1.5: Configuration (`src/config.rs` additions)

```rust
/// Signature-based detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureConfig {
    /// Enable signature-based detection
    #[serde(default)]
    pub enabled: bool,

    /// Directories containing .rules files
    #[serde(default = "default_rules_dirs")]
    pub rules_dirs: Vec<String>,

    /// Individual rule files to load
    #[serde(default)]
    pub rules_files: Vec<String>,

    /// Download and update rules from these sources
    #[serde(default)]
    pub rule_sources: Vec<RuleSource>,

    /// Variable definitions (HOME_NET, EXTERNAL_NET, etc.)
    #[serde(default)]
    pub variables: HashMap<String, String>,

    /// Disabled rule SIDs
    #[serde(default)]
    pub disabled_sids: Vec<u32>,

    /// Rule update interval in hours (0 = manual only)
    #[serde(default)]
    pub update_interval_hours: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSource {
    pub name: String,
    pub url: String,
    pub enabled: bool,
    /// Optional API key/code for paid rulesets
    pub api_key: Option<String>,
}

fn default_rules_dirs() -> Vec<String> {
    vec![
        "/etc/crmonban/rules".to_string(),
        "/var/lib/crmonban/rules".to_string(),
    ]
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rules_dirs: default_rules_dirs(),
            rules_files: vec![],
            rule_sources: vec![
                RuleSource {
                    name: "Emerging Threats Open".to_string(),
                    url: "https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz".to_string(),
                    enabled: true,
                    api_key: None,
                },
            ],
            variables: HashMap::new(),
            disabled_sids: vec![],
            update_interval_hours: 24,
        }
    }
}
```

### Step 1.6: config.toml additions

```toml
# ============================================================================
# Signature-Based Detection (Suricata/Snort Compatible)
# ============================================================================

[signatures]
# Enable signature-based detection
enabled = false

# Directories containing .rules files
rules_dirs = [
    "/etc/crmonban/rules",
    "/var/lib/crmonban/rules"
]

# Individual rule files
rules_files = []

# Network variables (used in rules)
[signatures.variables]
HOME_NET = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
EXTERNAL_NET = "!$HOME_NET"
HTTP_PORTS = "80,8080,8000,8888"
HTTPS_PORTS = "443,8443"
SSH_PORTS = "22"
DNS_PORTS = "53"
SMTP_PORTS = "25,465,587"
SQL_PORTS = "1433,3306,5432"

# Disabled rule SIDs (false positives, etc.)
disabled_sids = []

# Rule update interval (hours, 0 = manual)
update_interval_hours = 24

# Rule sources
[[signatures.rule_sources]]
name = "Emerging Threats Open"
url = "https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"
enabled = true

[[signatures.rule_sources]]
name = "Abuse.ch SSL Blacklist"
url = "https://sslbl.abuse.ch/blacklist/sslblacklist.rules"
enabled = true

# Uncomment for Emerging Threats Pro (requires subscription)
# [[signatures.rule_sources]]
# name = "Emerging Threats Pro"
# url = "https://rules.emergingthreatspro.com/APIKEY/suricata-6.0/etpro.rules.tar.gz"
# enabled = false
# api_key = "your-api-key"
```

## CLI Commands

```bash
# Download/update rules
crmonban rules update

# List loaded rules
crmonban rules list [--filter "sql injection"]

# Show rule details
crmonban rules show 2001234

# Enable/disable rules
crmonban rules disable 2001234
crmonban rules enable 2001234

# Test rule against sample data
crmonban rules test 2001234 --pcap sample.pcap

# Validate rules file syntax
crmonban rules validate /path/to/rules.rules

# Show rule statistics
crmonban rules stats
```

## Dependencies to Add (Cargo.toml)

```toml
[dependencies]
nom = "7"                    # Parser combinators
aho-corasick = "1"           # Fast multi-pattern matching
regex = "1"                  # PCRE-compatible regex
walkdir = "2"                # Directory traversal
flate2 = "1"                 # Gzip decompression for rule downloads
tar = "0.4"                  # Tar extraction
```

## Testing Strategy

1. **Parser tests**: Parse sample rules, verify AST
2. **Matcher tests**: Match rules against crafted packets
3. **Integration tests**: Load ET Open rules, run against pcap
4. **Performance tests**: Benchmark rule matching throughput

## Files to Create

| File | Lines (est.) | Description |
|------|--------------|-------------|
| `src/rules/mod.rs` | 30 | Module exports |
| `src/rules/ast.rs` | 300 | Rule AST definitions |
| `src/rules/parser.rs` | 600 | Nom-based rule parser |
| `src/rules/matcher.rs` | 400 | Pattern matching engine |
| `src/rules/loader.rs` | 200 | File/directory loading |
| `src/rules/compiler.rs` | 150 | Rule optimization |
| `src/rules/variables.rs` | 100 | Variable handling |
| `src/rules/builtin/*.rs` | 500 | Option implementations |
| **Total** | **~2,300** | |

## Success Criteria

1. Parse 95%+ of Emerging Threats Open rules without errors
2. Match rules at 1Gbps+ throughput on modern hardware
3. Memory usage < 500MB for 30,000 rules
4. False positive rate comparable to Suricata
5. CLI tools for rule management

## Timeline Estimate

- AST + Parser: 2-3 days
- Matcher engine: 2-3 days
- Loader + CLI: 1-2 days
- Testing + tuning: 2-3 days
- **Total: ~8-10 days**
