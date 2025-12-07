# Probabilistic Scan Detection System

## Overview

Replace simple threshold-based detection with a probabilistic scoring system that:
- Tracks connection states (half-open vs completed)
- Weights different behaviors differently
- Detects network issues vs actual attacks
- Actively verifies suspected attackers

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Probabilistic Scan Engine                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │  Connection      │    │  Scoring         │    │  Network Health  │      │
│  │  State Tracker   │───▶│  Engine          │───▶│  Monitor         │      │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘      │
│           │                       │                       │                 │
│           ▼                       ▼                       ▼                 │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐      │
│  │  Per-IP State    │    │  Alert Generator │    │  Active Verifier │      │
│  │  Machine         │    │                  │    │  (nmap probe)    │      │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘      │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Detection Rules

### Rule Categories

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  INCREASE SCAN PROBABILITY                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  R1: Half-open SYN to different port      +1.0 per occurrence               │
│  R2: SYN to targeted/sensitive port       +0.5 bonus (22,23,3389,etc)       │
│  R3: Sequential port scanning             +2.0 (ports N, N+1, N+2...)       │
│  R4: Rapid SYN rate (>10/sec)             +3.0                              │
│  R5: SYN to closed port (RST received)    +0.5                              │
│  R6: Known scanner fingerprint            +5.0 (nmap, masscan patterns)     │
│  R7: Unusual TTL values                   +1.0 (TTL manipulation)           │
│  R8: TCP options fingerprint mismatch     +1.0 (OS spoofing attempt)        │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  DECREASE SCAN PROBABILITY                                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  R10: Completed TCP handshake             -2.0 per completion               │
│  R11: Data exchanged after handshake      -1.0 (legitimate traffic)         │
│  R12: TLS handshake completed             -2.0 (real client behavior)       │
│  R13: HTTP request after connect          -1.5                              │
│  R14: Previously known good IP            -3.0 (from whitelist/history)     │
│  R15: Matching forward/reverse DNS        -1.0                              │
│  R16: Connection to expected services     -0.5 (80, 443 on web server)      │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│  NETWORK ISSUE INDICATORS                                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  N1: >80% of ALL sources show half-open   → NETWORK_SUSPECT flag            │
│  N2: Our outbound connections failing     → NETWORK_SUSPECT flag            │
│  N3: Packet loss on known-good hosts      → NETWORK_SUSPECT flag            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Scoring Thresholds

```
Score Range     │ Classification        │ Action
────────────────┼───────────────────────┼────────────────────────────
< 3.0           │ NORMAL                │ No action
3.0 - 5.0       │ SUSPICIOUS            │ Log, increase monitoring
5.0 - 8.0       │ PROBABLE_SCAN         │ Alert, start verification
8.0 - 12.0      │ LIKELY_ATTACK         │ Alert, prepare ban
> 12.0          │ CONFIRMED_SCAN        │ Immediate ban
────────────────┴───────────────────────┴────────────────────────────
```

## Connection State Machine

```
                    ┌─────────────────────────────────────────┐
                    │           Per-Connection State          │
                    └─────────────────────────────────────────┘

     SYN sent                SYN-ACK received           ACK sent
    ┌───────┐  timeout(5s)  ┌───────────────┐         ┌───────────┐
    │ HALF  │──────────────▶│   EXPIRED     │         │ESTABLISHED│
    │ OPEN  │               │ (+1.0 score)  │         │(-2.0 score)│
    └───┬───┘               └───────────────┘         └─────┬─────┘
        │                                                   │
        │ SYN-ACK                                          │ Data
        ▼                                                   ▼
    ┌───────┐               ┌───────────────┐         ┌───────────┐
    │ SYN   │──────────────▶│  ESTABLISHED  │────────▶│  ACTIVE   │
    │ RCVD  │    ACK        │               │         │(-1.0 more)│
    └───────┘               └───────────────┘         └───────────┘
```

## Per-IP Tracking Structure

```rust
struct SourceBehavior {
    // Connection tracking
    half_open_connections: HashMap<u16, Instant>,  // port -> SYN time
    completed_connections: HashSet<u16>,           // ports with full handshake

    // Scoring
    current_score: f32,
    score_history: VecDeque<(Instant, f32, RuleId)>,  // audit trail

    // Timing analysis
    first_seen: Instant,
    last_seen: Instant,
    syn_timestamps: VecDeque<Instant>,  // for rate detection

    // Pattern detection
    port_sequence: Vec<u16>,  // for sequential scan detection

    // Classification
    classification: Classification,
    verified: bool,
    verification_result: Option<VerificationResult>,
}

enum Classification {
    Normal,
    Suspicious,
    ProbableScan,
    LikelyAttack,
    ConfirmedScan,
    NetworkIssue,
}
```

## Network Health Monitor

```
┌─────────────────────────────────────────────────────────────────┐
│                    Global Network Health                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Metrics:                                                       │
│  ├── total_sources_with_half_open: usize                       │
│  ├── total_sources_with_completed: usize                       │
│  ├── global_half_open_ratio: f32                               │
│  ├── our_outbound_success_rate: f32                            │
│  └── known_good_hosts_reachable: bool                          │
│                                                                 │
│  Decision:                                                      │
│  IF global_half_open_ratio > 0.8 AND our_outbound_failing:     │
│     → Set NETWORK_SUSPECT for all sources                      │
│     → Trigger network diagnostics                              │
│  ELSE:                                                          │
│     → Normal per-IP scoring applies                            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Active Verification Process

```
┌─────────────────────────────────────────────────────────────────┐
│  Verification Flow (when score > 5.0)                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Probe suspected scanner IP:                                 │
│     nmap -sT -p 22,80,443 --max-retries 2 <suspect_ip>         │
│                                                                 │
│  2. Analyze result:                                             │
│     ├── Probe succeeds → IP is reachable, likely ATTACK        │
│     │   → Upgrade classification, prepare ban                  │
│     │                                                           │
│     └── Probe fails → Test network health                      │
│         │                                                       │
│         ├── Probe 3 known-good external IPs                    │
│         │   (8.8.8.8, 1.1.1.1, etc)                            │
│         │                                                       │
│         ├── If known-good also fail → NETWORK_ISSUE            │
│         │   → Alert ops, don't ban                             │
│         │                                                       │
│         └── If known-good succeed → Scanner is blocking us     │
│             → Still suspicious, but can't verify               │
│             → Mark as UNVERIFIABLE, monitor closely            │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

```toml
[scan_detect]
enabled = true

# Scoring thresholds
suspicious_threshold = 3.0
probable_scan_threshold = 5.0
likely_attack_threshold = 8.0
confirmed_scan_threshold = 12.0

# Timing
window_duration_secs = 600        # 10 minute window
syn_completion_timeout_secs = 5   # SYN must complete in 5s
cleanup_interval_secs = 30

# Rule weights (customize scoring)
[scan_detect.weights]
half_open_syn = 1.0
targeted_port_bonus = 0.5
sequential_scan = 2.0
rapid_rate_bonus = 3.0
closed_port_rst = 0.5
scanner_fingerprint = 5.0
unusual_ttl = 1.0
tcp_options_mismatch = 1.0

completed_handshake = -2.0
data_exchanged = -1.0
tls_completed = -2.0
http_request = -1.5
known_good_ip = -3.0
dns_match = -1.0
expected_service = -0.5

# Network health
[scan_detect.network_health]
global_half_open_threshold = 0.8
check_outbound_success = true
known_good_hosts = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

# Verification
[scan_detect.verification]
enabled = true
probe_ports = [22, 80, 443]
probe_timeout_secs = 5
max_retries = 2
```

## Alert Types

```rust
enum ScanAlertType {
    /// Score exceeded threshold, needs attention
    ProbableScan {
        score: f32,
        top_rules: Vec<(RuleId, f32)>,
        half_open_ports: Vec<u16>,
        completed_ports: Vec<u16>,
    },

    /// Verified attack via active probe
    VerifiedAttack {
        score: f32,
        verification_method: String,
        recommendation: Action,
    },

    /// Network issue detected, not an attack
    NetworkIssue {
        affected_sources: usize,
        diagnostic_results: NetworkDiagnostics,
    },

    /// Could not verify, scanner blocking probes
    UnverifiableSuspect {
        score: f32,
        reason: String,
    },
}
```

## Geographic & ASN Rules

```
┌─────────────────────────────────────────────────────────────────┐
│  Geographic/ASN Scoring                                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  G1: Source from high-risk country          +2.0                │
│      (configurable country list)                                │
│                                                                 │
│  G2: Source from known bulletproof ASN      +3.0                │
│      (hosting providers ignoring abuse)                         │
│                                                                 │
│  G3: Source from residential IP range       -0.5                │
│      (less likely to be scanner infra)                          │
│                                                                 │
│  G4: Source from cloud provider ASN         +0.5                │
│      (AWS, GCP, Azure, DigitalOcean, etc)                       │
│                                                                 │
│  G5: Source from Tor exit node              +2.0                │
│                                                                 │
│  G6: Source from VPN provider range         +1.0                │
│                                                                 │
│  G7: Source from same country as server     -0.5                │
│      (more likely legitimate user)                              │
│                                                                 │
│  G8: GeoIP lookup failure (bogon/unrouted)  +1.5                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### GeoIP Configuration

```toml
[scan_detect.geo]
enabled = true
geoip_db_path = "/var/lib/crmonban/GeoLite2-Country.mmdb"
asn_db_path = "/var/lib/crmonban/GeoLite2-ASN.mmdb"

# High-risk countries (ISO 3166-1 alpha-2)
high_risk_countries = ["CN", "RU", "KP", "IR"]
high_risk_weight = 2.0

# Bulletproof hosting ASNs
bulletproof_asns = [
    202425,  # Example
    # Add known bad ASNs
]
bulletproof_weight = 3.0

# Cloud provider ASNs (suspicious for scanners)
cloud_asns = [
    16509,   # Amazon
    15169,   # Google
    8075,    # Microsoft
    14061,   # DigitalOcean
    13335,   # Cloudflare
]
cloud_weight = 0.5

# Tor exit node list (updated periodically)
tor_exit_list_url = "https://check.torproject.org/torbulkexitlist"
tor_weight = 2.0

# Server's own country (for same-country bonus)
server_country = "US"
same_country_bonus = -0.5
```

## Time-Based Rules

```
┌─────────────────────────────────────────────────────────────────┐
│  Time-of-Day / Temporal Patterns                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  T1: Activity during off-hours               +1.0               │
│      (2am-6am server local time)                                │
│                                                                 │
│  T2: Activity during business hours          -0.5               │
│      (9am-6pm server local time)                                │
│                                                                 │
│  T3: Burst after long silence                +1.5               │
│      (no activity for 1hr, then sudden scans)                   │
│                                                                 │
│  T4: Consistent timing pattern               +2.0               │
│      (automated scanner signature)                              │
│                                                                 │
│  T5: Weekend activity on business server     +0.5               │
│                                                                 │
│  T6: Holiday period scanning                 +1.0               │
│      (attackers target holidays)                                │
│                                                                 │
│  T7: Matches known attack campaign timing    +3.0               │
│      (correlate with threat intel)                              │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Time Configuration

```toml
[scan_detect.time]
enabled = true
timezone = "America/New_York"

# Off-hours definition (24h format)
off_hours_start = 2   # 2 AM
off_hours_end = 6     # 6 AM
off_hours_weight = 1.0

# Business hours
business_hours_start = 9
business_hours_end = 18
business_hours_bonus = -0.5

# Silence threshold before burst detection
silence_threshold_secs = 3600  # 1 hour
burst_after_silence_weight = 1.5

# Weekend detection (for business servers)
weekend_penalty = 0.5
server_type = "business"  # or "consumer", "always-on"
```

## Protocol-Specific Rules

```
┌─────────────────────────────────────────────────────────────────┐
│  Protocol-Specific Behaviors                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  HTTP/HTTPS:                                                    │
│  P1: HTTP request with no User-Agent        +1.0                │
│  P2: HTTP request with scanner User-Agent   +3.0                │
│      (nikto, sqlmap, nmap, etc)                                 │
│  P3: Rapid 404 generation                   +2.0                │
│      (directory enumeration)                                    │
│  P4: Valid HTTP request with response       -1.0                │
│  P5: Unusual HTTP methods (TRACE, OPTIONS)  +0.5                │
│                                                                 │
│  SSH:                                                           │
│  P10: SSH banner grab only (no auth)        +1.5                │
│  P11: Multiple failed auth attempts         +2.0                │
│  P12: Successful SSH login                  -3.0                │
│  P13: SSH with known-bad client version     +2.0                │
│                                                                 │
│  DNS:                                                           │
│  P20: DNS zone transfer attempt             +3.0                │
│  P21: High volume DNS queries               +1.5                │
│  P22: DNS query for scanner domains         +2.0                │
│                                                                 │
│  SMTP:                                                          │
│  P30: SMTP VRFY/EXPN commands               +2.0                │
│  P31: SMTP without sending mail             +1.0                │
│  P32: SMTP with invalid HELO                +1.5                │
│                                                                 │
│  Database Ports:                                                │
│  P40: Connection to DB port, no auth        +1.5                │
│  P41: Multiple DB auth failures             +2.5                │
│  P42: Successful DB connection              -2.0                │
│                                                                 │
│  TLS/SSL:                                                       │
│  P50: TLS handshake only, no app data       +0.5                │
│  P51: Invalid/malformed TLS handshake       +1.5                │
│  P52: SSLv2/SSLv3 probing (deprecated)      +2.0                │
│  P53: TLS with known-bad JA3 fingerprint    +3.0                │
│  P54: Valid TLS with app data               -1.5                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Protocol Configuration

```toml
[scan_detect.protocols]
enabled = true

# HTTP scanning signatures
[scan_detect.protocols.http]
scanner_user_agents = [
    "nikto", "sqlmap", "nmap", "masscan", "zgrab",
    "gobuster", "dirbuster", "wfuzz", "ffuf",
    "nuclei", "httpx", "curl/", "python-requests",
]
scanner_ua_weight = 3.0
missing_ua_weight = 1.0
rapid_404_threshold = 10  # 10 404s in window
rapid_404_weight = 2.0

# SSH signatures
[scan_detect.protocols.ssh]
bad_client_versions = [
    "SSH-2.0-libssh",  # Often used by scanners
    "SSH-2.0-paramiko",
]
banner_grab_only_weight = 1.5
auth_failure_weight = 2.0
auth_failure_threshold = 3

# TLS/JA3 fingerprints
[scan_detect.protocols.tls]
bad_ja3_hashes = [
    "e7d705a3286e19ea42f587b344ee6865",  # Example scanner
    # Add known malicious JA3 hashes
]
bad_ja3_weight = 3.0
```

## Reputation Feed Rules

```
┌─────────────────────────────────────────────────────────────────┐
│  Reputation & Threat Intelligence                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  REP1: IP on AbuseIPDB (confidence > 50%)   +3.0                │
│  REP2: IP on AbuseIPDB (confidence > 80%)   +5.0                │
│  REP3: IP on Spamhaus DROP/EDROP            +4.0                │
│  REP4: IP on Emerging Threats blocklist     +3.0                │
│  REP5: IP seen in recent threat reports     +2.0                │
│  REP6: IP reported by honeypot network      +4.0                │
│  REP7: IP in local blocklist history        +2.0                │
│      (previously banned by us)                                  │
│  REP8: IP on whitelist/allowlist            -5.0                │
│  REP9: IP belongs to known partner/vendor   -3.0                │
│  REP10: IP has good reputation score        -2.0                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Reputation Configuration

```toml
[scan_detect.reputation]
enabled = true
cache_ttl_secs = 3600  # Cache lookups for 1 hour

# AbuseIPDB
[scan_detect.reputation.abuseipdb]
enabled = true
api_key = "${ABUSEIPDB_API_KEY}"
confidence_threshold_low = 50
confidence_threshold_high = 80
weight_low = 3.0
weight_high = 5.0

# Spamhaus
[scan_detect.reputation.spamhaus]
enabled = true
drop_list_url = "https://www.spamhaus.org/drop/drop.txt"
edrop_list_url = "https://www.spamhaus.org/drop/edrop.txt"
weight = 4.0

# Emerging Threats
[scan_detect.reputation.emerging_threats]
enabled = true
blocklist_url = "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"
weight = 3.0

# Local history
[scan_detect.reputation.local]
check_ban_history = true
previous_ban_weight = 2.0
previous_ban_lookback_days = 90

# Whitelist
whitelist_path = "/etc/crmonban/whitelist.txt"
whitelist_bonus = -5.0

# Partner/vendor IPs
partner_ranges = [
    "10.0.0.0/8",      # Internal
    "203.0.113.0/24",  # Example partner
]
partner_bonus = -3.0
```

## Custom Behavior Framework

```
┌─────────────────────────────────────────────────────────────────┐
│  Extensible Rule System                                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Custom rules can be defined via:                               │
│  1. TOML configuration (simple patterns)                        │
│  2. Lua scripts (complex logic)                                 │
│  3. External plugins (shared libraries)                         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Custom Rule Types

```rust
/// Trait for custom detection rules
pub trait DetectionRule: Send + Sync {
    /// Unique identifier for this rule
    fn id(&self) -> &str;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Rule category
    fn category(&self) -> RuleCategory;

    /// Evaluate the rule against current state
    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult>;

    /// Can this rule be configured via TOML?
    fn configurable(&self) -> bool { true }

    /// Default weight for this rule
    fn default_weight(&self) -> f32;
}

pub struct EvaluationContext<'a> {
    /// Source IP being evaluated
    pub src_ip: IpAddr,

    /// Current behavior data for this IP
    pub behavior: &'a SourceBehavior,

    /// Current packet/connection (if applicable)
    pub packet: Option<&'a PacketInfo>,

    /// Flow state (if applicable)
    pub flow: Option<&'a FlowState>,

    /// Global network health
    pub network_health: &'a NetworkHealth,

    /// Timestamp
    pub timestamp: Instant,

    /// GeoIP data (if available)
    pub geo: Option<&'a GeoInfo>,

    /// Reputation data (if available)
    pub reputation: Option<&'a ReputationInfo>,

    /// Protocol analysis results (if available)
    pub protocol_info: Option<&'a ProtocolInfo>,
}

pub struct RuleResult {
    /// Score adjustment (positive = more suspicious)
    pub score_delta: f32,

    /// Confidence in this result (0.0 - 1.0)
    pub confidence: f32,

    /// Evidence/reason for this result
    pub evidence: String,

    /// Tags to add to this IP's profile
    pub tags: Vec<String>,
}

pub enum RuleCategory {
    Connection,
    Protocol,
    Geographic,
    Temporal,
    Reputation,
    Behavioral,
    NetworkHealth,
    Custom,
}
```

### TOML-Defined Custom Rules

```toml
# Custom rules defined in config
[[scan_detect.custom_rules]]
id = "custom_rdp_scan"
name = "RDP Scanning Pattern"
category = "protocol"
weight = 2.5
enabled = true

# Condition: multiple RDP connection attempts without success
[scan_detect.custom_rules.condition]
port = 3389
min_attempts = 3
max_success = 0
window_secs = 300

[[scan_detect.custom_rules]]
id = "custom_internal_scan"
name = "Internal Network Scanning"
category = "behavioral"
weight = 4.0
enabled = true

# Condition: scanning RFC1918 ranges from external IP
[scan_detect.custom_rules.condition]
src_external = true
dst_internal = true
min_ports = 5

[[scan_detect.custom_rules]]
id = "custom_api_enumeration"
name = "API Endpoint Enumeration"
category = "protocol"
weight = 2.0
enabled = true

[scan_detect.custom_rules.condition]
protocol = "http"
path_patterns = ["/api/*", "/v1/*", "/v2/*", "/graphql"]
min_unique_paths = 20
window_secs = 60

[[scan_detect.custom_rules]]
id = "custom_legit_monitoring"
name = "Known Monitoring Service"
category = "reputation"
weight = -4.0  # Negative = reduces score
enabled = true

[scan_detect.custom_rules.condition]
user_agent_contains = ["UptimeRobot", "Pingdom", "StatusCake"]
```

### WebAssembly Plugin Rules (Hot-Reloadable)

WASM plugins provide:
- **Sandboxed execution** - isolated from host system
- **Multi-language support** - write rules in Rust, Go, C, AssemblyScript, etc.
- **Hot-reload** - update rules without restarting the daemon
- **Near-native performance** - faster than interpreted languages

```
┌─────────────────────────────────────────────────────────────────┐
│  WASM Plugin Architecture                                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │ Rust Rule   │    │ Go Rule     │    │ C Rule      │         │
│  │ (.rs)       │    │ (.go)       │    │ (.c)        │         │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘         │
│         │                  │                  │                 │
│         ▼                  ▼                  ▼                 │
│  ┌─────────────────────────────────────────────────────┐       │
│  │              Compile to WASM (.wasm)                │       │
│  └─────────────────────────────────────────────────────┘       │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────┐       │
│  │  wasmtime Runtime (sandboxed, hot-reload)           │       │
│  │  ┌─────────────────────────────────────────────┐   │       │
│  │  │  Host Functions (provided by crmonban):     │   │       │
│  │  │  - get_src_ip()                             │   │       │
│  │  │  - get_half_open_count()                    │   │       │
│  │  │  - get_port_list()                          │   │       │
│  │  │  - lookup_geoip()                           │   │       │
│  │  │  - check_reputation()                       │   │       │
│  │  │  - log_debug() / log_info()                 │   │       │
│  │  └─────────────────────────────────────────────┘   │       │
│  └─────────────────────────────────────────────────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

#### WASM Plugin Interface (wit)

```wit
// /etc/crmonban/plugins/rule.wit
package crmonban:rule@0.1.0;

interface types {
    record rule-result {
        score-delta: float32,
        confidence: float32,
        evidence: string,
        tags: list<string>,
    }

    record evaluation-context {
        src-ip: string,
        half-open-count: u32,
        completed-count: u32,
        ports: list<u16>,
        first-seen-secs: u64,
        last-seen-secs: u64,
    }

    record rule-metadata {
        id: string,
        name: string,
        category: string,
        version: string,
        default-weight: float32,
    }
}

interface host {
    use types.{evaluation-context};

    // Host functions available to WASM plugins
    get-context: func() -> evaluation-context;
    get-port-list: func() -> list<u16>;
    lookup-geoip: func(ip: string) -> option<string>;
    lookup-asn: func(ip: string) -> option<u32>;
    check-reputation: func(ip: string) -> option<float32>;
    get-subnet-hits: func(prefix-len: u8) -> u32;
    log-debug: func(msg: string);
    log-info: func(msg: string);
}

interface rule {
    use types.{rule-result, rule-metadata};

    // Required exports from WASM plugin
    get-metadata: func() -> rule-metadata;
    evaluate: func() -> option<rule-result>;
}

world detection-rule {
    import host;
    export rule;
}
```

#### Example WASM Rule (Rust)

```rust
// plugins/distributed_bruteforce/src/lib.rs
// Compile with: cargo build --target wasm32-wasip1 --release

use crmonban_rule_sdk::*;

struct DistributedBruteforce;

impl DetectionRule for DistributedBruteforce {
    fn metadata() -> RuleMetadata {
        RuleMetadata {
            id: "wasm_distributed_bruteforce".into(),
            name: "Distributed Brute-Force Detection".into(),
            category: "behavioral".into(),
            version: "1.0.0".into(),
            default_weight: 3.0,
        }
    }

    fn evaluate() -> Option<RuleResult> {
        let ctx = host::get_context();
        let auth_ports = [22, 23, 3389, 5900];

        // Check how many IPs from same /24 are hitting auth ports
        let subnet_hits = host::get_subnet_hits(24);

        if subnet_hits >= 3 {
            let score = 3.0 + (subnet_hits as f32 * 0.5);
            return Some(RuleResult {
                score_delta: score,
                confidence: 0.8,
                evidence: format!("Distributed attack: {} IPs from same /24", subnet_hits),
                tags: vec!["distributed".into(), "bruteforce".into()],
            });
        }

        None
    }
}

export_rule!(DistributedBruteforce);
```

#### Example WASM Rule (Go)

```go
// plugins/slow_scan/main.go
// Compile with: tinygo build -o slow_scan.wasm -target=wasip1

package main

import (
    "github.com/crmonban/rule-sdk-go"
)

type SlowScanRule struct{}

func (r *SlowScanRule) Metadata() rule.Metadata {
    return rule.Metadata{
        ID:            "wasm_slow_scan",
        Name:          "Slow/Stealth Scan Detection",
        Category:      "behavioral",
        Version:       "1.0.0",
        DefaultWeight: 2.0,
    }
}

func (r *SlowScanRule) Evaluate() *rule.Result {
    ctx := rule.GetContext()

    // Slow scan: many ports over long time (>5min)
    duration := ctx.LastSeenSecs - ctx.FirstSeenSecs
    if duration > 300 && ctx.HalfOpenCount >= 5 {
        rate := float32(ctx.HalfOpenCount) / float32(duration)
        if rate < 0.1 { // Less than 1 port per 10 seconds
            return &rule.Result{
                ScoreDelta: 2.0,
                Confidence: 0.7,
                Evidence:   fmt.Sprintf("Slow scan: %d ports over %ds", ctx.HalfOpenCount, duration),
                Tags:       []string{"slow-scan", "stealth"},
            }
        }
    }
    return nil
}

func main() {
    rule.Export(&SlowScanRule{})
}
```

#### Hot-Reload System

```rust
/// WASM plugin manager with hot-reload support
pub struct WasmPluginManager {
    /// wasmtime engine (shared across all plugins)
    engine: wasmtime::Engine,

    /// Loaded plugins: path -> (module, instance, metadata)
    plugins: HashMap<PathBuf, LoadedPlugin>,

    /// File watcher for hot-reload
    watcher: notify::RecommendedWatcher,

    /// Plugin directory
    plugin_dir: PathBuf,

    /// Reload channel
    reload_tx: mpsc::Sender<PathBuf>,
}

impl WasmPluginManager {
    /// Start watching for plugin changes
    pub fn start_hot_reload(&mut self) -> Result<()> {
        let reload_tx = self.reload_tx.clone();

        self.watcher.watch(&self.plugin_dir, RecursiveMode::NonRecursive)?;

        // Handle file change events
        tokio::spawn(async move {
            // On .wasm file change:
            // 1. Validate new module
            // 2. Instantiate in sandbox
            // 3. Run basic tests
            // 4. Hot-swap old instance
            // 5. Log reload event
        });

        Ok(())
    }

    /// Reload a specific plugin
    pub fn reload_plugin(&mut self, path: &Path) -> Result<()> {
        info!("Hot-reloading plugin: {:?}", path);

        // Load new module
        let wasm_bytes = std::fs::read(path)?;
        let module = wasmtime::Module::new(&self.engine, &wasm_bytes)?;

        // Create new instance with host functions
        let mut store = wasmtime::Store::new(&self.engine, HostState::new());
        let instance = self.instantiate_plugin(&mut store, &module)?;

        // Get metadata from new plugin
        let metadata = self.call_get_metadata(&mut store, &instance)?;

        info!("Loaded plugin: {} v{}", metadata.name, metadata.version);

        // Swap in new plugin (atomic)
        self.plugins.insert(path.to_path_buf(), LoadedPlugin {
            module,
            store,
            instance,
            metadata,
            loaded_at: Instant::now(),
        });

        Ok(())
    }

    /// Evaluate all plugins against context
    pub fn evaluate_all(&mut self, ctx: &EvaluationContext) -> Vec<RuleResult> {
        let mut results = Vec::new();

        for (path, plugin) in &mut self.plugins {
            // Set context in host state
            plugin.store.data_mut().set_context(ctx);

            // Call evaluate function
            match self.call_evaluate(&mut plugin.store, &plugin.instance) {
                Ok(Some(result)) => {
                    results.push(result);
                }
                Ok(None) => {} // Rule didn't match
                Err(e) => {
                    warn!("Plugin {:?} error: {}", path, e);
                    // Don't crash on plugin errors
                }
            }
        }

        results
    }
}
```

#### Plugin Configuration

```toml
[scan_detect.wasm]
enabled = true
plugin_dir = "/etc/crmonban/plugins"
hot_reload = true
hot_reload_debounce_ms = 500

# Resource limits per plugin (sandboxing)
[scan_detect.wasm.limits]
max_memory_bytes = 16_777_216  # 16 MB
max_execution_time_ms = 100    # 100ms per evaluation
max_table_elements = 10000
fuel_limit = 1_000_000         # wasmtime fuel for bounded execution

# Host function permissions (per-plugin)
[[scan_detect.wasm.plugins]]
path = "distributed_bruteforce.wasm"
enabled = true
weight_override = 3.5  # Optional weight override
permissions = [
    "get_context",
    "get_port_list",
    "get_subnet_hits",
    "log_debug",
]

[[scan_detect.wasm.plugins]]
path = "geo_anomaly.wasm"
enabled = true
permissions = [
    "get_context",
    "lookup_geoip",
    "lookup_asn",
    "log_info",
]
```

#### Plugin SDK (for developers)

```toml
# Cargo.toml for plugin development
[package]
name = "my-custom-rule"
version = "0.1.0"

[lib]
crate-type = ["cdylib"]

[dependencies]
crmonban-rule-sdk = "0.1"

[profile.release]
opt-level = "s"      # Optimize for size
lto = true           # Link-time optimization
```

```rust
// crmonban-rule-sdk crate provides:
pub use crmonban_rule_sdk::{
    DetectionRule,
    RuleMetadata,
    RuleResult,
    EvaluationContext,
    export_rule,
    host,  // Host function bindings
};
```

### Rule Configuration

```toml
[scan_detect.rules]
# Enable/disable rule categories
enable_connection_rules = true
enable_protocol_rules = true
enable_geographic_rules = true
enable_temporal_rules = true
enable_reputation_rules = true
enable_custom_rules = true
enable_wasm_plugins = true

# WASM plugin directory (hot-reloaded)
wasm_plugin_dir = "/etc/crmonban/plugins"

# Override individual rule weights
[scan_detect.rules.weights]
half_open_syn = 1.0
completed_handshake = -2.0
# ... override any rule weight

# Disable specific rules
[scan_detect.rules.disabled]
rules = ["T5", "G3"]  # Disable weekend penalty and residential IP bonus
```

## Complete Rule Registry

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  RULE REGISTRY - All Available Rules                                       │
├────────┬───────────────────────────────────────┬─────────┬─────────────────┤
│ ID     │ Description                           │ Weight  │ Category        │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│        │ CONNECTION RULES                      │         │                 │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│ R1     │ Half-open SYN to different port       │ +1.0    │ Connection      │
│ R2     │ SYN to targeted port                  │ +0.5    │ Connection      │
│ R3     │ Sequential port scan                  │ +2.0    │ Connection      │
│ R4     │ Rapid SYN rate (>10/sec)              │ +3.0    │ Connection      │
│ R5     │ SYN to closed port (RST)              │ +0.5    │ Connection      │
│ R6     │ Scanner fingerprint match             │ +5.0    │ Connection      │
│ R7     │ Unusual TTL values                    │ +1.0    │ Connection      │
│ R8     │ TCP options mismatch                  │ +1.0    │ Connection      │
│ R10    │ Completed handshake                   │ -2.0    │ Connection      │
│ R11    │ Data exchanged                        │ -1.0    │ Connection      │
│ R12    │ TLS handshake completed               │ -2.0    │ Connection      │
│ R13    │ HTTP request after connect            │ -1.5    │ Connection      │
│ R14    │ Known good IP                         │ -3.0    │ Connection      │
│ R15    │ DNS forward/reverse match             │ -1.0    │ Connection      │
│ R16    │ Expected service connection           │ -0.5    │ Connection      │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│        │ GEOGRAPHIC RULES                      │         │                 │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│ G1     │ High-risk country                     │ +2.0    │ Geographic      │
│ G2     │ Bulletproof ASN                       │ +3.0    │ Geographic      │
│ G3     │ Residential IP range                  │ -0.5    │ Geographic      │
│ G4     │ Cloud provider ASN                    │ +0.5    │ Geographic      │
│ G5     │ Tor exit node                         │ +2.0    │ Geographic      │
│ G6     │ VPN provider range                    │ +1.0    │ Geographic      │
│ G7     │ Same country as server                │ -0.5    │ Geographic      │
│ G8     │ GeoIP lookup failure                  │ +1.5    │ Geographic      │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│        │ TEMPORAL RULES                        │         │                 │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│ T1     │ Off-hours activity                    │ +1.0    │ Temporal        │
│ T2     │ Business hours activity               │ -0.5    │ Temporal        │
│ T3     │ Burst after silence                   │ +1.5    │ Temporal        │
│ T4     │ Consistent timing pattern             │ +2.0    │ Temporal        │
│ T5     │ Weekend on business server            │ +0.5    │ Temporal        │
│ T6     │ Holiday period                        │ +1.0    │ Temporal        │
│ T7     │ Known campaign timing                 │ +3.0    │ Temporal        │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│        │ PROTOCOL RULES                        │         │                 │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│ P1     │ HTTP no User-Agent                    │ +1.0    │ Protocol        │
│ P2     │ HTTP scanner User-Agent               │ +3.0    │ Protocol        │
│ P3     │ Rapid 404 generation                  │ +2.0    │ Protocol        │
│ P4     │ Valid HTTP request/response           │ -1.0    │ Protocol        │
│ P5     │ Unusual HTTP methods                  │ +0.5    │ Protocol        │
│ P10    │ SSH banner grab only                  │ +1.5    │ Protocol        │
│ P11    │ SSH auth failures                     │ +2.0    │ Protocol        │
│ P12    │ Successful SSH login                  │ -3.0    │ Protocol        │
│ P13    │ SSH bad client version                │ +2.0    │ Protocol        │
│ P20    │ DNS zone transfer attempt             │ +3.0    │ Protocol        │
│ P21    │ High volume DNS queries               │ +1.5    │ Protocol        │
│ P22    │ DNS scanner domain query              │ +2.0    │ Protocol        │
│ P30    │ SMTP VRFY/EXPN                        │ +2.0    │ Protocol        │
│ P31    │ SMTP no mail sent                     │ +1.0    │ Protocol        │
│ P32    │ SMTP invalid HELO                     │ +1.5    │ Protocol        │
│ P40    │ DB port no auth                       │ +1.5    │ Protocol        │
│ P41    │ DB auth failures                      │ +2.5    │ Protocol        │
│ P42    │ Successful DB connection              │ -2.0    │ Protocol        │
│ P50    │ TLS handshake only                    │ +0.5    │ Protocol        │
│ P51    │ Malformed TLS                         │ +1.5    │ Protocol        │
│ P52    │ SSLv2/v3 probing                      │ +2.0    │ Protocol        │
│ P53    │ Bad JA3 fingerprint                   │ +3.0    │ Protocol        │
│ P54    │ Valid TLS with data                   │ -1.5    │ Protocol        │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│        │ REPUTATION RULES                      │         │                 │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│ REP1   │ AbuseIPDB >50% confidence             │ +3.0    │ Reputation      │
│ REP2   │ AbuseIPDB >80% confidence             │ +5.0    │ Reputation      │
│ REP3   │ Spamhaus DROP/EDROP                   │ +4.0    │ Reputation      │
│ REP4   │ Emerging Threats list                 │ +3.0    │ Reputation      │
│ REP5   │ Recent threat reports                 │ +2.0    │ Reputation      │
│ REP6   │ Honeypot network report               │ +4.0    │ Reputation      │
│ REP7   │ Previously banned by us               │ +2.0    │ Reputation      │
│ REP8   │ On whitelist                          │ -5.0    │ Reputation      │
│ REP9   │ Known partner/vendor                  │ -3.0    │ Reputation      │
│ REP10  │ Good reputation score                 │ -2.0    │ Reputation      │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│        │ NETWORK HEALTH RULES                  │         │                 │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│ N1     │ >80% sources half-open                │ FLAG    │ NetworkHealth   │
│ N2     │ Our outbound failing                  │ FLAG    │ NetworkHealth   │
│ N3     │ Known-good hosts unreachable          │ FLAG    │ NetworkHealth   │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│        │ CUSTOM RULES                          │         │                 │
├────────┼───────────────────────────────────────┼─────────┼─────────────────┤
│ C*     │ User-defined via TOML                 │ varies  │ Custom          │
│ WASM*  │ User-defined via WASM plugins         │ varies  │ Custom          │
└────────┴───────────────────────────────────────┴─────────┴─────────────────┘
```

## Implementation Phases

### Phase 1: Core Scoring Engine
- [ ] `DetectionRule` trait and `EvaluationContext` struct
- [ ] `RuleEngine` to load/evaluate rules
- [ ] Connection state tracker (half-open vs completed)
- [ ] Per-IP `SourceBehavior` tracking struct
- [ ] Basic scoring with R1, R10 rules
- [ ] Classification based on score thresholds
- [ ] Score history/audit trail

### Phase 2: Connection Rules (R1-R16)
- [ ] Half-open SYN tracking (R1)
- [ ] Targeted port bonus (R2)
- [ ] Sequential scan detection (R3)
- [ ] Rate-based detection (R4)
- [ ] Closed port RST detection (R5)
- [ ] Scanner fingerprinting (R6)
- [ ] TTL analysis (R7)
- [ ] TCP options fingerprinting (R8)
- [ ] Completed handshake credit (R10-R16)

### Phase 3: Geographic & ASN Rules (G1-G8)
- [ ] MaxMind GeoIP integration
- [ ] ASN database lookup
- [ ] High-risk country scoring (G1)
- [ ] Bulletproof ASN detection (G2)
- [ ] Residential vs cloud IP classification (G3, G4)
- [ ] Tor exit node list integration (G5)
- [ ] VPN provider detection (G6)
- [ ] Same-country bonus (G7)
- [ ] Bogon/unrouted detection (G8)

### Phase 4: Temporal Rules (T1-T7)
- [ ] Timezone-aware time analysis
- [ ] Off-hours detection (T1)
- [ ] Business hours bonus (T2)
- [ ] Burst after silence detection (T3)
- [ ] Timing pattern analysis (T4)
- [ ] Weekend/holiday detection (T5, T6)
- [ ] Campaign timing correlation (T7)

### Phase 5: Protocol Rules (P1-P54)
- [ ] HTTP analysis (P1-P5)
  - [ ] User-Agent inspection
  - [ ] 404 rate tracking
  - [ ] Method analysis
- [ ] SSH analysis (P10-P13)
  - [ ] Banner grab detection
  - [ ] Auth failure tracking
  - [ ] Client version fingerprinting
- [ ] DNS analysis (P20-P22)
- [ ] SMTP analysis (P30-P32)
- [ ] Database port analysis (P40-P42)
- [ ] TLS/JA3 analysis (P50-P54)

### Phase 6: Reputation Rules (REP1-REP10)
- [ ] AbuseIPDB API integration (REP1-REP2)
- [ ] Spamhaus DROP list integration (REP3)
- [ ] Emerging Threats list (REP4)
- [ ] Threat intel correlation (REP5)
- [ ] Honeypot network integration (REP6)
- [ ] Local ban history lookup (REP7)
- [ ] Whitelist/partner handling (REP8-REP10)
- [ ] Reputation cache layer

### Phase 7: Network Health Monitor (N1-N3)
- [ ] Global half-open ratio tracking (N1)
- [ ] Outbound connection health check (N2)
- [ ] Known-good host probing (N3)
- [ ] NETWORK_ISSUE classification
- [ ] Automatic network diagnostics

### Phase 8: Active Verification
- [ ] nmap integration for suspect probing
- [ ] Probe result interpretation
- [ ] Verification state machine
- [ ] Automatic ban on verified attacks
- [ ] Network issue vs attack differentiation

### Phase 9: WASM Plugin Framework
- [ ] wasmtime integration
- [ ] WIT interface definition (rule.wit)
- [ ] Host function implementations
- [ ] WasmPluginManager with hot-reload
- [ ] File watcher for .wasm changes
- [ ] Sandboxing (memory limits, fuel)
- [ ] Per-plugin permissions
- [ ] Plugin SDK crate (crmonban-rule-sdk)

### Phase 10: Tuning & Learning
- [ ] Score calibration tools
- [ ] False positive tracking
- [ ] Rule weight optimization
- [ ] Feedback integration
- [ ] Dashboard/reporting

## File Structure

```
src/
├── scan_detect/
│   ├── mod.rs              # Main module, exports
│   ├── engine.rs           # RuleEngine, scoring logic
│   ├── behavior.rs         # SourceBehavior, per-IP tracking
│   ├── rules/
│   │   ├── mod.rs          # Rule trait, registry
│   │   ├── connection.rs   # R1-R16 rules
│   │   ├── geographic.rs   # G1-G8 rules
│   │   ├── temporal.rs     # T1-T7 rules
│   │   ├── protocol.rs     # P1-P54 rules
│   │   ├── reputation.rs   # REP1-REP10 rules
│   │   └── custom.rs       # TOML custom rule loader
│   ├── wasm/
│   │   ├── mod.rs          # WASM plugin manager
│   │   ├── host.rs         # Host function implementations
│   │   ├── loader.rs       # Plugin loading/hot-reload
│   │   └── sandbox.rs      # Resource limits, permissions
│   ├── network_health.rs   # N1-N3, health monitoring
│   ├── verification.rs     # Active verification (nmap)
│   ├── geoip.rs            # GeoIP/ASN integration
│   └── config.rs           # Configuration structs

# Separate crate for plugin SDK
crates/
└── crmonban-rule-sdk/
    ├── Cargo.toml          # wasm32-wasip1 target
    ├── src/
    │   ├── lib.rs          # SDK exports
    │   ├── types.rs        # RuleResult, RuleMetadata
    │   └── host.rs         # Host function bindings
    └── wit/
        └── rule.wit        # WIT interface definition

# Example plugins
plugins/
├── distributed_bruteforce/
│   ├── Cargo.toml
│   └── src/lib.rs
├── slow_scan/
│   ├── Cargo.toml
│   └── src/lib.rs
└── geo_anomaly/
    ├── Cargo.toml
    └── src/lib.rs
```
