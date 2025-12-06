# Complete NIDS Enhancement Implementation Plan

## Architecture Overview

All features integrate through a unified packet processing pipeline:

```
                                    ┌─────────────────────────────────────────────────────┐
                                    │                   crmonban                          │
                                    └─────────────────────────────────────────────────────┘
                                                          │
                    ┌─────────────────────────────────────┼─────────────────────────────────────┐
                    │                                     │                                     │
                    ▼                                     ▼                                     ▼
           ┌────────────────┐                   ┌────────────────┐                   ┌────────────────┐
           │  Log Monitor   │                   │ Packet Engine  │                   │  Threat Intel  │
           │   (existing)   │                   │    (new)       │                   │   (enhanced)   │
           └───────┬────────┘                   └───────┬────────┘                   └───────┬────────┘
                   │                                    │                                    │
                   │                    ┌───────────────┼───────────────┐                    │
                   │                    │               │               │                    │
                   │                    ▼               ▼               ▼                    │
                   │           ┌──────────────┐ ┌──────────────┐ ┌──────────────┐           │
                   │           │   Flow       │ │  Protocol    │ │  Signature   │           │
                   │           │  Tracker     │ │  Analyzers   │ │   Engine     │           │
                   │           └──────┬───────┘ └──────┬───────┘ └──────┬───────┘           │
                   │                  │                │                │                    │
                   │                  └────────────────┼────────────────┘                    │
                   │                                   │                                     │
                   │                                   ▼                                     │
                   │                          ┌──────────────┐                              │
                   │                          │   ML/Anomaly │                              │
                   │                          │    Engine    │                              │
                   │                          └──────┬───────┘                              │
                   │                                 │                                      │
                   └─────────────────────────────────┼──────────────────────────────────────┘
                                                     │
                                                     ▼
                                            ┌──────────────┐
                                            │  Correlation │
                                            │    Engine    │
                                            └──────┬───────┘
                                                   │
                                    ┌──────────────┼──────────────┐
                                    │              │              │
                                    ▼              ▼              ▼
                           ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
                           │   Alerting   │ │   Firewall   │ │   Logging    │
                           │   (D-Bus)    │ │  (nftables)  │ │ (SIEM/File)  │
                           └──────────────┘ └──────────────┘ └──────────────┘
```

## Shared Data Structures (`src/core/`)

All features share these core types:

```rust
// src/core/mod.rs
pub mod packet;
pub mod flow;
pub mod event;
pub mod connection;

// src/core/packet.rs
/// Unified packet representation used by all analyzers
#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: Instant,
    pub id: u64,

    // Layer 2
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,

    // Layer 3
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: IpProtocol,
    pub ttl: u8,
    pub ip_flags: u8,

    // Layer 4
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: Option<TcpFlags>,
    pub seq: Option<u32>,
    pub ack: Option<u32>,

    // Layer 7
    pub app_protocol: Option<AppProtocol>,
    pub payload: Vec<u8>,

    // Metadata
    pub flow_id: u64,
    pub direction: Direction,
    pub interface: Option<String>,
}

// src/core/flow.rs
/// Connection flow (bidirectional)
#[derive(Debug, Clone)]
pub struct Flow {
    pub id: u64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: IpProtocol,
    pub state: FlowState,

    // Statistics
    pub start_time: Instant,
    pub last_seen: Instant,
    pub packets_to_server: u64,
    pub packets_to_client: u64,
    pub bytes_to_server: u64,
    pub bytes_to_client: u64,

    // Timing
    pub inter_arrival_times: Vec<Duration>,
    pub packet_sizes: Vec<u16>,

    // Application layer
    pub app_protocol: Option<AppProtocol>,
    pub app_data: HashMap<String, Value>,

    // Detection results
    pub alerts: Vec<AlertId>,
    pub risk_score: f32,
    pub tags: HashSet<String>,
}

// src/core/event.rs
/// Unified detection event
#[derive(Debug, Clone, Serialize)]
pub struct DetectionEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: DetectionType,
    pub severity: Severity,
    pub confidence: f32,

    // Source
    pub detector: String,           // "signature", "anomaly", "protocol", etc.
    pub rule_id: Option<u32>,
    pub rule_name: Option<String>,

    // Network context
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,

    // Flow context
    pub flow_id: Option<u64>,

    // Details
    pub message: String,
    pub details: HashMap<String, Value>,

    // Threat intel
    pub mitre_attack: Vec<String>,  // T1190, T1059, etc.
    pub cve: Option<String>,
    pub threat_intel: Option<ThreatIntelMatch>,

    // Action taken
    pub action: DetectionAction,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum DetectionAction {
    Alert,
    Log,
    Drop,
    Reject,
    Ban,
    RateLimit,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}
```

## Feature Flags (Cargo.toml)

```toml
[features]
default = ["log-monitor", "firewall"]

# Core features (existing)
log-monitor = []
firewall = []
dbus-api = ["zbus"]
siem = ["reqwest"]

# New detection features
signatures = ["nom", "aho-corasick"]          # Suricata/Snort rules
flow-tracking = []                             # Connection tracking
protocols = []                                 # Protocol analyzers
ml-detection = ["linfa", "ndarray"]           # Machine learning
threat-intel = ["reqwest"]                    # Threat feed integration

# Advanced features
ja3-fingerprint = ["md5"]                     # TLS fingerprinting
hassh = ["md5"]                               # SSH fingerprinting
eta = []                                       # Encrypted traffic analysis
correlation = []                               # Alert correlation

# UI features
web-ui = ["axum", "tower", "tokio"]           # Web dashboard

# Performance features
xdp = ["aya"]                                  # eBPF/XDP acceleration

# All features
full = [
    "log-monitor", "firewall", "dbus-api", "siem",
    "signatures", "flow-tracking", "protocols", "ml-detection",
    "threat-intel", "ja3-fingerprint", "hassh", "eta",
    "correlation", "web-ui"
]
```

---

## Feature 1: Signature Engine (`signatures`)

### Purpose
Parse and execute Suricata/Snort compatible rules for signature-based detection.

### Files
```
src/signatures/
├── mod.rs              # Module exports, SignatureEngine struct
├── ast.rs              # Rule AST (Action, Protocol, IpSpec, PortSpec, RuleOption)
├── parser.rs           # Nom-based rule parser
├── matcher.rs          # Aho-Corasick + PCRE pattern matching
├── loader.rs           # Load rules from files/URLs
├── updater.rs          # Auto-update rules from feeds
├── options/
│   ├── mod.rs
│   ├── content.rs      # content, nocase, offset, depth, distance, within
│   ├── pcre.rs         # PCRE regex matching
│   ├── flow.rs         # flow:to_server,established
│   ├── threshold.rs    # threshold, detection_filter, rate limiting
│   ├── http.rs         # http.uri, http.header, http.method, http.user_agent
│   ├── dns.rs          # dns.query, dns.answer
│   ├── tls.rs          # tls.sni, tls.cert_subject, ja3.hash
│   └── meta.rs         # msg, sid, rev, classtype, priority, reference
└── tests/
    ├── parser_tests.rs
    └── matcher_tests.rs
```

### Integration Points
```rust
impl SignatureEngine {
    /// Called by PacketEngine for each packet
    pub fn inspect(&self, packet: &Packet, flow: Option<&Flow>) -> Vec<DetectionEvent>;

    /// Called by ProtocolAnalyzers with parsed data
    pub fn inspect_http(&self, http: &HttpTransaction) -> Vec<DetectionEvent>;
    pub fn inspect_dns(&self, dns: &DnsMessage) -> Vec<DetectionEvent>;
    pub fn inspect_tls(&self, tls: &TlsHandshake) -> Vec<DetectionEvent>;
}
```

### Config Section
```toml
[signatures]
enabled = true
rules_dirs = ["/etc/crmonban/rules"]
variables = { HOME_NET = "192.168.0.0/16", EXTERNAL_NET = "!$HOME_NET" }
disabled_sids = [2001234, 2001235]
update_interval_hours = 24

[[signatures.sources]]
name = "ET Open"
url = "https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"
enabled = true
```

---

## Feature 2: Flow Tracking (`flow-tracking`)

### Purpose
Track TCP/UDP connections bidirectionally, compute flow statistics for ML and correlation.

### Files
```
src/flow/
├── mod.rs              # FlowTracker struct, exports
├── tracker.rs          # Connection state machine
├── table.rs            # Flow hash table with timeout
├── stats.rs            # Per-flow statistics computation
├── reassembly.rs       # TCP stream reassembly (optional)
└── export.rs           # Export flows to database/SIEM
```

### Integration Points
```rust
impl FlowTracker {
    /// Called by PacketEngine for each packet
    pub fn process(&mut self, packet: &mut Packet) -> &Flow;

    /// Get flow by ID
    pub fn get_flow(&self, id: u64) -> Option<&Flow>;

    /// Iterate expired flows (for cleanup/export)
    pub fn drain_expired(&mut self) -> impl Iterator<Item = Flow>;

    /// Flow statistics for ML
    pub fn get_stats(&self, flow_id: u64) -> Option<FlowStats>;
}

#[derive(Debug, Clone)]
pub struct FlowStats {
    pub duration_ms: u64,
    pub packets_fwd: u64,
    pub packets_bwd: u64,
    pub bytes_fwd: u64,
    pub bytes_bwd: u64,
    pub mean_pkt_size_fwd: f32,
    pub mean_pkt_size_bwd: f32,
    pub std_pkt_size_fwd: f32,
    pub std_pkt_size_bwd: f32,
    pub mean_iat_fwd: f32,          // Inter-arrival time
    pub mean_iat_bwd: f32,
    pub min_iat: f32,
    pub max_iat: f32,
    pub syn_count: u32,
    pub fin_count: u32,
    pub rst_count: u32,
    pub psh_count: u32,
    pub urg_count: u32,
    pub bytes_per_second: f32,
    pub packets_per_second: f32,
}
```

### Config Section
```toml
[flow_tracking]
enabled = true
table_size = 1000000            # Max concurrent flows
timeout_tcp_established = 3600  # 1 hour
timeout_tcp_idle = 300          # 5 minutes
timeout_udp = 180               # 3 minutes
timeout_icmp = 30
enable_reassembly = false       # TCP reassembly (memory intensive)
export_on_close = true          # Export closed flows to DB
```

---

## Feature 3: Protocol Analyzers (`protocols`)

### Purpose
Deep inspection of application layer protocols to extract fields for signature matching and anomaly detection.

### Files
```
src/protocols/
├── mod.rs              # ProtocolDetector, trait definitions
├── detector.rs         # Automatic protocol detection
├── http/
│   ├── mod.rs
│   ├── parser.rs       # HTTP/1.x parser
│   ├── http2.rs        # HTTP/2 frame parser (optional)
│   └── types.rs        # HttpRequest, HttpResponse, HttpTransaction
├── dns/
│   ├── mod.rs
│   ├── parser.rs       # DNS message parser
│   └── types.rs        # DnsQuery, DnsAnswer, DnsMessage
├── tls/
│   ├── mod.rs
│   ├── parser.rs       # TLS record/handshake parser
│   ├── ja3.rs          # JA3/JA3S fingerprinting
│   └── types.rs        # TlsHandshake, Certificate, etc.
├── ssh/
│   ├── mod.rs
│   ├── parser.rs       # SSH protocol parser
│   ├── hassh.rs        # HASSH fingerprinting
│   └── types.rs
├── smtp/
│   ├── mod.rs
│   └── parser.rs
├── ftp/
│   ├── mod.rs
│   └── parser.rs
├── smb/
│   ├── mod.rs
│   └── parser.rs
└── mysql/
    ├── mod.rs
    └── parser.rs
```

### Integration Points
```rust
pub trait ProtocolAnalyzer: Send + Sync {
    fn name(&self) -> &'static str;
    fn detect(&self, payload: &[u8], port: u16) -> bool;
    fn parse(&self, packet: &Packet, flow: &mut Flow) -> Option<ProtocolEvent>;
}

pub enum ProtocolEvent {
    Http(HttpTransaction),
    Dns(DnsMessage),
    Tls(TlsEvent),
    Ssh(SshEvent),
    Smtp(SmtpEvent),
    // ...
}

impl ProtocolDetector {
    pub fn analyze(&self, packet: &Packet, flow: &mut Flow) -> Vec<ProtocolEvent> {
        // Auto-detect protocol, dispatch to appropriate analyzer
    }
}
```

### Config Section
```toml
[protocols]
enabled = true

[protocols.http]
enabled = true
ports = [80, 8080, 8000, 8888]
max_request_body = 1048576      # 1MB
max_response_body = 10485760    # 10MB
extract_files = false

[protocols.dns]
enabled = true
ports = [53]
log_queries = true
log_answers = true

[protocols.tls]
enabled = true
ports = [443, 8443, 993, 995, 465, 587]
ja3_enabled = true
ja3s_enabled = true
extract_certificates = true
log_sni = true

[protocols.ssh]
enabled = true
ports = [22]
hassh_enabled = true
```

---

## Feature 4: JA3/JA3S Fingerprinting (`ja3-fingerprint`)

### Purpose
Identify TLS clients/servers by their fingerprint, detect malware and malicious tools.

### Files
```
src/protocols/tls/ja3.rs        # JA3 computation
src/signatures/options/tls.rs   # ja3.hash rule option
src/intel/ja3_db.rs             # Known malware JA3 database
```

### Implementation
```rust
/// Compute JA3 hash from TLS ClientHello
pub fn compute_ja3(client_hello: &ClientHello) -> Ja3Fingerprint {
    // JA3 = MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
    let ja3_string = format!(
        "{},{},{},{},{}",
        client_hello.version,
        client_hello.cipher_suites.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-"),
        client_hello.extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-"),
        client_hello.supported_groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("-"),
        client_hello.ec_point_formats.iter().map(|f| f.to_string()).collect::<Vec<_>>().join("-"),
    );

    Ja3Fingerprint {
        string: ja3_string.clone(),
        hash: format!("{:x}", md5::compute(&ja3_string)),
    }
}

/// Known malicious JA3 fingerprints
pub struct Ja3Database {
    malware: HashMap<String, Ja3Entry>,     // JA3 hash -> malware info
    tools: HashMap<String, Ja3Entry>,       // Security tools
    browsers: HashMap<String, Ja3Entry>,    // Legitimate browsers
}

#[derive(Debug, Clone)]
pub struct Ja3Entry {
    pub hash: String,
    pub name: String,
    pub category: Ja3Category,
    pub description: String,
    pub references: Vec<String>,
}

pub enum Ja3Category {
    Malware,
    C2Framework,       // Cobalt Strike, Metasploit, etc.
    Scanner,           // Nmap, Masscan
    Bot,
    Legitimate,
    Unknown,
}
```

### Config Section
```toml
[protocols.tls]
ja3_enabled = true
ja3s_enabled = true
ja3_alert_unknown = false       # Alert on unknown JA3
ja3_database_path = "/var/lib/crmonban/ja3.db"
ja3_auto_update = true
```

---

## Feature 5: Machine Learning Detection (`ml-detection`)

### Purpose
Learn normal traffic patterns and detect anomalies that signatures miss.

### Files
```
src/ml/
├── mod.rs              # MLEngine struct
├── features.rs         # Feature extraction from flows
├── baseline.rs         # Normal behavior baseline
├── classifier.rs       # Random Forest / neural network
├── anomaly.rs          # Anomaly scoring
├── models/
│   ├── mod.rs
│   ├── random_forest.rs
│   ├── isolation_forest.rs
│   └── autoencoder.rs  # Optional neural network
└── training.rs         # Model training utilities
```

### Integration Points
```rust
impl MLEngine {
    /// Extract features from a flow
    pub fn extract_features(&self, flow: &Flow) -> FeatureVector;

    /// Score a flow for anomalies
    pub fn score(&self, flow: &Flow) -> AnomalyScore;

    /// Classify traffic type
    pub fn classify(&self, flow: &Flow) -> Classification;

    /// Update baseline with normal traffic
    pub fn update_baseline(&mut self, flow: &Flow);
}

#[derive(Debug, Clone)]
pub struct FeatureVector {
    pub features: Vec<f32>,
    pub labels: Vec<&'static str>,
}

// Standard features (CICIDS2017-compatible)
pub const FEATURES: &[&str] = &[
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    // ... 41 features total
];

#[derive(Debug, Clone)]
pub struct AnomalyScore {
    pub score: f32,             // 0.0 = normal, 1.0 = highly anomalous
    pub confidence: f32,
    pub contributing_features: Vec<(String, f32)>,
    pub category: Option<AnomalyCategory>,
}

pub enum AnomalyCategory {
    DoS,
    Probe,
    R2L,                // Remote to local
    U2R,                // User to root
    DataExfiltration,
    Beaconing,
    Unknown,
}
```

### Config Section
```toml
[ml]
enabled = true
model_path = "/var/lib/crmonban/ml_model.bin"

[ml.baseline]
enabled = true
learning_period_hours = 168     # 1 week
update_interval_hours = 24

[ml.detection]
anomaly_threshold = 0.7
min_confidence = 0.6
alert_on_unknown = false

[ml.features]
use_timing = true
use_packet_sizes = true
use_tcp_flags = true
use_protocol_stats = true
```

---

## Feature 6: Threat Intelligence (`threat-intel`)

### Purpose
Integrate real-time threat feeds to block known-bad IPs, domains, and hashes.

### Files
```
src/intel/
├── mod.rs              # IntelEngine struct (enhanced)
├── feeds/
│   ├── mod.rs
│   ├── otx.rs          # AlienVault OTX
│   ├── abuse_ch.rs     # Abuse.ch (SSL, URLhaus, etc.)
│   ├── emergingthreats.rs
│   ├── spamhaus.rs
│   └── misp.rs         # MISP integration
├── ioc.rs              # IOC types and matching
├── cache.rs            # Local IOC cache
├── stix.rs             # STIX/TAXII support
└── mitre.rs            # MITRE ATT&CK mapping
```

### Integration Points
```rust
impl IntelEngine {
    /// Check IP against all feeds
    pub fn check_ip(&self, ip: &IpAddr) -> Option<ThreatIntelMatch>;

    /// Check domain
    pub fn check_domain(&self, domain: &str) -> Option<ThreatIntelMatch>;

    /// Check file hash
    pub fn check_hash(&self, hash: &str) -> Option<ThreatIntelMatch>;

    /// Check JA3 fingerprint
    pub fn check_ja3(&self, ja3: &str) -> Option<ThreatIntelMatch>;

    /// Check URL
    pub fn check_url(&self, url: &str) -> Option<ThreatIntelMatch>;

    /// Update all feeds
    pub async fn update_feeds(&mut self) -> Result<UpdateStats>;
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatIntelMatch {
    pub ioc_type: IocType,
    pub ioc_value: String,
    pub source: String,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub confidence: f32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub tags: Vec<String>,
    pub references: Vec<String>,
    pub mitre_attack: Vec<String>,
}

pub enum ThreatCategory {
    Malware,
    C2,
    Phishing,
    Spam,
    Scanner,
    Botnet,
    Ransomware,
    APT,
}
```

### Config Section
```toml
[threat_intel]
enabled = true
cache_path = "/var/lib/crmonban/intel_cache"
update_interval_hours = 4

[[threat_intel.feeds]]
name = "AlienVault OTX"
type = "otx"
enabled = true
api_key = "your-otx-api-key"

[[threat_intel.feeds]]
name = "Abuse.ch SSL"
type = "abuse_ch_ssl"
url = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
enabled = true

[[threat_intel.feeds]]
name = "Abuse.ch URLhaus"
type = "abuse_ch_urlhaus"
url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
enabled = true

[[threat_intel.feeds]]
name = "Spamhaus DROP"
type = "spamhaus_drop"
url = "https://www.spamhaus.org/drop/drop.txt"
enabled = true

[[threat_intel.feeds]]
name = "EmergingThreats Compromised IPs"
type = "et_compromised"
url = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
enabled = true
```

---

## Feature 7: Alert Correlation (`correlation`)

### Purpose
Group related alerts, reduce noise, identify attack chains.

### Files
```
src/correlation/
├── mod.rs              # CorrelationEngine
├── rules.rs            # Correlation rules
├── chains.rs           # Attack chain detection
├── aggregator.rs       # Alert aggregation
├── timeline.rs         # Timeline reconstruction
└── incident.rs         # Incident grouping
```

### Integration Points
```rust
impl CorrelationEngine {
    /// Process new detection event
    pub fn process(&mut self, event: DetectionEvent) -> CorrelationResult;

    /// Get active incidents
    pub fn get_incidents(&self) -> Vec<Incident>;

    /// Get related events
    pub fn get_related(&self, event_id: Uuid) -> Vec<DetectionEvent>;
}

pub enum CorrelationResult {
    NewIncident(Incident),
    UpdatedIncident(Incident),
    Suppressed,             // Duplicate/noise
    Standalone(DetectionEvent),
}

#[derive(Debug, Clone)]
pub struct Incident {
    pub id: Uuid,
    pub severity: Severity,
    pub start_time: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub events: Vec<DetectionEvent>,
    pub affected_hosts: HashSet<IpAddr>,
    pub attack_chain: Option<AttackChain>,
    pub mitre_tactics: Vec<String>,
    pub status: IncidentStatus,
}

#[derive(Debug, Clone)]
pub struct AttackChain {
    pub name: String,
    pub stages: Vec<AttackStage>,
    pub confidence: f32,
}
```

### Config Section
```toml
[correlation]
enabled = true
window_seconds = 300            # 5 minute correlation window
max_incidents = 10000
aggregation_threshold = 5       # Min events to aggregate

[[correlation.rules]]
name = "brute_force"
events = ["failed_auth"]
count_threshold = 5
window_seconds = 60
group_by = ["src_ip", "dst_ip"]

[[correlation.rules]]
name = "port_scan_then_exploit"
sequence = ["port_scan", "exploit_attempt"]
max_gap_seconds = 3600
elevate_severity = true
```

---

## Feature 8: Web Dashboard (`web-ui`)

### Purpose
Real-time visibility into alerts, traffic, and system status.

### Files
```
src/web/
├── mod.rs              # Web server setup
├── routes/
│   ├── mod.rs
│   ├── dashboard.rs    # Main dashboard API
│   ├── alerts.rs       # Alert management
│   ├── flows.rs        # Flow browser
│   ├── rules.rs        # Rule management
│   ├── intel.rs        # Threat intel status
│   ├── stats.rs        # Statistics
│   └── config.rs       # Configuration
├── websocket.rs        # Real-time updates
├── auth.rs             # Authentication
└── static/             # Frontend assets (or separate repo)

web/                    # Frontend (React/HTMX)
├── index.html
├── src/
│   ├── dashboard.js
│   ├── alerts.js
│   ├── flows.js
│   └── charts.js
└── css/
```

### API Endpoints
```
GET  /api/v1/dashboard/summary      # Overview stats
GET  /api/v1/alerts                 # List alerts
GET  /api/v1/alerts/:id             # Alert details
POST /api/v1/alerts/:id/ack         # Acknowledge alert
GET  /api/v1/flows                  # List flows
GET  /api/v1/flows/:id              # Flow details
GET  /api/v1/rules                  # List signature rules
POST /api/v1/rules/:sid/disable     # Disable rule
GET  /api/v1/intel/status           # Threat intel status
POST /api/v1/intel/update           # Trigger feed update
GET  /api/v1/stats/traffic          # Traffic statistics
GET  /api/v1/stats/top-talkers      # Top IPs by traffic
WS   /api/v1/live                   # WebSocket for real-time
```

### Config Section
```toml
[web]
enabled = false
listen_addr = "127.0.0.1"
listen_port = 8080
tls_enabled = false
tls_cert = "/etc/crmonban/web.crt"
tls_key = "/etc/crmonban/web.key"

[web.auth]
enabled = true
type = "basic"                  # basic, ldap, oauth
users_file = "/etc/crmonban/users.htpasswd"
session_timeout_hours = 24
```

---

## Feature 9: Packet Engine (`packet-engine`)

### Purpose
Multi-threaded packet capture and processing pipeline that ties everything together.

### Files
```
src/engine/
├── mod.rs              # PacketEngine struct
├── capture.rs          # Packet capture (NFQUEUE, AF_PACKET)
├── pipeline.rs         # Processing pipeline
├── workers.rs          # Worker thread pool
├── dispatcher.rs       # Dispatch to analyzers
└── actions.rs          # Action execution (drop, reject, ban)
```

### Integration
```rust
pub struct PacketEngine {
    config: PacketEngineConfig,

    // Capture
    capture: Box<dyn PacketCapture>,

    // Processing components
    flow_tracker: Arc<RwLock<FlowTracker>>,
    protocol_detector: Arc<ProtocolDetector>,
    signature_engine: Arc<SignatureEngine>,
    ml_engine: Arc<RwLock<MLEngine>>,
    intel_engine: Arc<IntelEngine>,
    correlation_engine: Arc<RwLock<CorrelationEngine>>,

    // Output
    event_tx: mpsc::Sender<DetectionEvent>,
}

impl PacketEngine {
    pub async fn run(&mut self) -> Result<()> {
        let (packet_tx, packet_rx) = crossbeam_channel::bounded(10000);

        // Spawn capture thread
        let capture = self.capture.clone();
        std::thread::spawn(move || {
            capture.run(packet_tx);
        });

        // Spawn worker threads
        for _ in 0..self.config.worker_threads {
            let rx = packet_rx.clone();
            let flow_tracker = self.flow_tracker.clone();
            let protocol_detector = self.protocol_detector.clone();
            let signature_engine = self.signature_engine.clone();
            let ml_engine = self.ml_engine.clone();
            let intel_engine = self.intel_engine.clone();
            let event_tx = self.event_tx.clone();

            tokio::spawn(async move {
                while let Ok(packet) = rx.recv() {
                    // 1. Flow tracking
                    let flow = flow_tracker.write().await.process(&packet);

                    // 2. Protocol analysis
                    let proto_events = protocol_detector.analyze(&packet, &mut flow);

                    // 3. Threat intel check
                    if let Some(intel) = intel_engine.check_ip(&packet.src_ip) {
                        event_tx.send(intel.into_event(&packet)).await;
                    }

                    // 4. Signature matching
                    for event in signature_engine.inspect(&packet, Some(&flow)) {
                        event_tx.send(event).await;
                    }

                    // 5. ML scoring (on flow completion)
                    if flow.is_complete() {
                        let score = ml_engine.read().await.score(&flow);
                        if score.is_anomalous() {
                            event_tx.send(score.into_event(&flow)).await;
                        }
                    }
                }
            });
        }

        Ok(())
    }
}
```

### Config Section
```toml
[engine]
enabled = true
capture_method = "nfqueue"      # nfqueue, af_packet, pcap
nfqueue_num = 0
worker_threads = 4              # 0 = auto (num_cpus)
packet_buffer_size = 10000
```

---

## Unified Configuration Structure

```toml
# /etc/crmonban/config.toml

[general]
db_path = "/var/lib/crmonban/crmonban.db"
log_level = "info"

[nftables]
table_name = "crmonban"
chain_name = "input"

# ===== NEW FEATURES =====

[engine]
enabled = true
capture_method = "nfqueue"
worker_threads = 4

[flow_tracking]
enabled = true
table_size = 1000000
timeout_tcp_established = 3600

[signatures]
enabled = true
rules_dirs = ["/etc/crmonban/rules"]
# ...

[protocols]
enabled = true
[protocols.http]
enabled = true
# ...

[protocols.tls]
enabled = true
ja3_enabled = true
# ...

[ml]
enabled = true
# ...

[threat_intel]
enabled = true
# ...

[correlation]
enabled = true
# ...

[web]
enabled = false
# ...
```

---

## Implementation Order & Dependencies

```
                    ┌──────────────────┐
                    │  1. Signatures   │ ◄── Foundation, no deps
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │ 2. Flow Tracking │ ◄── Needed for ML, correlation
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼────────┐ ┌───▼───┐ ┌───────▼───────┐
     │ 3. Protocols    │ │4. JA3 │ │ 5. Threat     │
     │   (HTTP,DNS,TLS)│ │       │ │    Intel      │
     └────────┬────────┘ └───┬───┘ └───────┬───────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼─────────┐
                    │  6. ML Engine    │ ◄── Needs flows + protocols
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  7. Correlation  │ ◄── Needs all detection
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  8. Packet       │ ◄── Ties everything together
                    │     Engine       │
                    └────────┬─────────┘
                             │
                    ┌────────▼─────────┐
                    │  9. Web UI       │ ◄── Visualization layer
                    └──────────────────┘
```

---

## Estimated Lines of Code

| Feature | Files | Est. Lines |
|---------|-------|------------|
| Core types | 4 | 500 |
| Signatures | 12 | 2,500 |
| Flow Tracking | 6 | 1,200 |
| Protocols | 20 | 3,000 |
| JA3/HASSH | 4 | 600 |
| ML Engine | 8 | 2,000 |
| Threat Intel | 10 | 1,500 |
| Correlation | 6 | 1,000 |
| Packet Engine | 6 | 800 |
| Web UI (backend) | 10 | 1,500 |
| Web UI (frontend) | 15 | 2,000 |
| **Total** | **101** | **~16,600** |

---

## Testing Strategy

1. **Unit tests**: Each module has `tests/` with parser, matcher tests
2. **Integration tests**: `tests/integration/` with pcap replay
3. **Benchmark tests**: `benches/` for throughput measurement
4. **Real-world testing**: Deploy on honeypot with real attack traffic
