# crmonban Product Tiers

## Overview

One codebase, two product tiers controlled by Cargo features and configuration.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              crmonban                                            │
├─────────────────────────────────┬───────────────────────────────────────────────┤
│                                 │                                               │
│    crmonban-lite                │           crmonban-full                       │
│    (Firewall + Log Monitor)     │           (Security Appliance)                │
│                                 │                                               │
│    • nftables firewall          │    Everything in Lite, plus:                  │
│    • Port-based rules (UFW)     │                                               │
│    • Log monitoring             │    • Signature detection (Snort/Suricata)     │
│    • IP banning                 │    • Flow tracking & analysis                 │
│    • Basic port scan detect     │    • Protocol analyzers (HTTP/DNS/TLS)        │
│    • Whitelist/blacklist        │    • JA3/HASSH fingerprinting                 │
│    • Simple CLI                 │    • Machine learning detection               │
│    • Systemd service            │    • Threat intelligence feeds                │
│                                 │    • Alert correlation                        │
│    Target: Home/Small Server    │    • Active defense (honeypots, OSINT)        │
│    Memory: < 50MB               │    • Web dashboard                            │
│    Dependencies: Minimal        │    • SIEM integration                         │
│                                 │    • D-Bus API                                │
│                                 │                                               │
│                                 │    Target: Enterprise/Security Teams          │
│                                 │    Memory: < 2GB                              │
│                                 │    Dependencies: Full                         │
│                                 │                                               │
└─────────────────────────────────┴───────────────────────────────────────────────┘
```

## Cargo Features Structure

```toml
# Cargo.toml

[package]
name = "crmonban"
version = "0.2.0"
edition = "2021"

[features]
# ═══════════════════════════════════════════════════════════════════════════════
# TIER 1: crmonban-lite (Simple Firewall + Log Monitor)
# ═══════════════════════════════════════════════════════════════════════════════
default = ["lite"]

lite = [
    "firewall",
    "log-monitor",
    "port-rules",
    "whitelist",
    "cli",
]

# Core components (always available)
firewall = []                   # nftables management
log-monitor = []                # Log file watching + regex matching
port-rules = []                 # UFW-style port allow/deny
whitelist = []                  # IP whitelist management
cli = ["clap"]                  # Command-line interface

# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2: crmonban-full (Security Appliance)
# ═══════════════════════════════════════════════════════════════════════════════
full = [
    "lite",
    # Detection
    "signatures",
    "flow-tracking",
    "protocols",
    "fingerprinting",
    "ml-detection",
    "malware-detect",
    # Intelligence
    "threat-intel",
    "correlation",
    # Response
    "active-defense",
    # Integration
    "web-ui",
    "dbus-api",
    "siem",
]

# ─────────────────────────────────────────────────────────────────────────────
# Detection Features
# ─────────────────────────────────────────────────────────────────────────────
signatures = ["nom", "aho-corasick", "regex"]       # Suricata/Snort rules
flow-tracking = []                                   # Connection tracking
protocols = ["httparse"]                             # Protocol analyzers
fingerprinting = ["md5"]                             # JA3/HASSH
ml-detection = ["linfa", "linfa-trees", "ndarray", "rustfft"]  # ML/anomaly
malware-detect = []                                  # eBPF malware detection

# ─────────────────────────────────────────────────────────────────────────────
# Intelligence Features
# ─────────────────────────────────────────────────────────────────────────────
threat-intel = ["reqwest"]                           # Threat feeds
correlation = []                                     # Alert correlation

# ─────────────────────────────────────────────────────────────────────────────
# Response Features
# ─────────────────────────────────────────────────────────────────────────────
active-defense = ["lettre", "tera"]                  # Honeypots, OSINT, playbooks
honeypots = ["active-defense", "axum"]               # Honeypot services
active-recon = ["active-defense"]                    # Active scanning (opt-in)

# ─────────────────────────────────────────────────────────────────────────────
# Integration Features
# ─────────────────────────────────────────────────────────────────────────────
web-ui = ["axum", "tower", "tower-http"]             # Web dashboard
dbus-api = ["zbus"]                                  # D-Bus interface
siem = ["reqwest"]                                   # SIEM export

# ─────────────────────────────────────────────────────────────────────────────
# Performance Features (optional for both tiers)
# ─────────────────────────────────────────────────────────────────────────────
xdp = ["aya"]                                        # eBPF/XDP acceleration
tls-inspect = ["rustls", "rcgen"]                    # TLS MITM proxy

[dependencies]
# Always included
anyhow = "1"
thiserror = "1"
tracing = "0.1"
tracing-subscriber = "0.3"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "fs", "io-util", "net", "sync", "time", "signal"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
chrono = { version = "0.4", features = ["serde"] }
rusqlite = { version = "0.31", features = ["bundled"] }

# nftables (firewall)
nftables = "0.4"

# CLI
clap = { version = "4", features = ["derive"], optional = true }

# Signatures
nom = { version = "7", optional = true }
aho-corasick = { version = "1", optional = true }
regex = { version = "1", optional = true }

# Protocols
httparse = { version = "1", optional = true }

# Fingerprinting
md5 = { version = "0.7", optional = true }

# ML
linfa = { version = "0.7", optional = true }
linfa-trees = { version = "0.7", optional = true }
ndarray = { version = "0.15", optional = true }
rustfft = { version = "6", optional = true }

# Web/HTTP
axum = { version = "0.7", optional = true }
tower = { version = "0.4", optional = true }
tower-http = { version = "0.5", features = ["fs", "cors"], optional = true }
reqwest = { version = "0.12", features = ["json"], optional = true }

# D-Bus
zbus = { version = "4", optional = true }

# Active defense
lettre = { version = "0.11", optional = true }
tera = { version = "1", optional = true }

# TLS
rustls = { version = "0.23", optional = true }
rcgen = { version = "0.13", optional = true }

# XDP
aya = { version = "0.12", optional = true }

[[bin]]
name = "crmonban"
path = "src/main.rs"

# Build lite version by default, full with --features full
# cargo build                    -> lite
# cargo build --features full    -> full
# cargo build --no-default-features --features "firewall,cli"  -> minimal
```

## Directory Structure

```
crmonban/
├── Cargo.toml
├── config.toml                 # Default config (lite)
├── config.full.toml            # Full config template
│
├── src/
│   ├── main.rs                 # Entry point
│   ├── lib.rs                  # Library root with conditional modules
│   │
│   ├── core/                   # Shared core (both tiers)
│   │   ├── mod.rs
│   │   ├── config.rs           # Configuration loading
│   │   ├── database.rs         # SQLite database
│   │   ├── models.rs           # Shared data models
│   │   └── error.rs            # Error types
│   │
│   ├── firewall/               # TIER 1: Firewall (lite)
│   │   ├── mod.rs
│   │   ├── nftables.rs         # nftables management
│   │   ├── port_rules.rs       # UFW-style rules
│   │   └── sets.rs             # IP sets
│   │
│   ├── monitor/                # TIER 1: Log Monitor (lite)
│   │   ├── mod.rs
│   │   ├── watcher.rs          # File watching
│   │   ├── parser.rs           # Log parsing
│   │   └── actions.rs          # Ban/alert actions
│   │
│   ├── cli/                    # TIER 1: CLI (lite)
│   │   ├── mod.rs
│   │   ├── commands.rs         # Command definitions
│   │   └── output.rs           # Formatting
│   │
│   ├── signatures/             # TIER 2: Signature Engine (full)
│   │   ├── mod.rs
│   │   ├── ast.rs
│   │   ├── parser.rs
│   │   ├── matcher.rs
│   │   └── loader.rs
│   │
│   ├── flow/                   # TIER 2: Flow Tracking (full)
│   │   ├── mod.rs
│   │   ├── tracker.rs
│   │   └── stats.rs
│   │
│   ├── protocols/              # TIER 2: Protocol Analyzers (full)
│   │   ├── mod.rs
│   │   ├── http.rs
│   │   ├── dns.rs
│   │   ├── tls.rs
│   │   └── ssh.rs
│   │
│   ├── ml/                     # TIER 2: ML Detection (full)
│   │   ├── mod.rs
│   │   ├── features.rs
│   │   ├── baseline.rs
│   │   ├── classifier.rs
│   │   └── anomaly.rs
│   │
│   ├── intel/                  # TIER 2: Threat Intelligence (full)
│   │   ├── mod.rs
│   │   ├── feeds.rs
│   │   ├── osint.rs
│   │   └── cache.rs
│   │
│   ├── correlation/            # TIER 2: Alert Correlation (full)
│   │   ├── mod.rs
│   │   └── rules.rs
│   │
│   ├── active_defense/         # TIER 2: Active Defense (full)
│   │   ├── mod.rs
│   │   ├── honeypots.rs
│   │   ├── honeytokens.rs
│   │   ├── playbooks.rs
│   │   └── profiler.rs
│   │
│   ├── web/                    # TIER 2: Web UI (full)
│   │   ├── mod.rs
│   │   ├── routes.rs
│   │   └── api.rs
│   │
│   ├── dbus/                   # TIER 2: D-Bus API (full)
│   │   └── mod.rs
│   │
│   └── siem/                   # TIER 2: SIEM Integration (full)
│       └── mod.rs
│
├── web/                        # Web UI frontend (full only)
│   └── ...
│
└── rules/                      # Signature rules (full only)
    └── ...
```

## lib.rs with Conditional Compilation

```rust
// src/lib.rs

// ═══════════════════════════════════════════════════════════════════════════════
// CORE (Always available)
// ═══════════════════════════════════════════════════════════════════════════════
pub mod core;
pub use core::{config, database, models, error};

// ═══════════════════════════════════════════════════════════════════════════════
// TIER 1: LITE (Firewall + Log Monitor)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "firewall")]
pub mod firewall;

#[cfg(feature = "log-monitor")]
pub mod monitor;

#[cfg(feature = "port-rules")]
pub mod port_rules;

#[cfg(feature = "whitelist")]
pub mod whitelist;

#[cfg(feature = "cli")]
pub mod cli;

// ═══════════════════════════════════════════════════════════════════════════════
// TIER 2: FULL (Security Appliance)
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(feature = "signatures")]
pub mod signatures;

#[cfg(feature = "flow-tracking")]
pub mod flow;

#[cfg(feature = "protocols")]
pub mod protocols;

#[cfg(feature = "fingerprinting")]
pub mod fingerprint;

#[cfg(feature = "ml-detection")]
pub mod ml;

#[cfg(feature = "malware-detect")]
pub mod malware_detect;

#[cfg(feature = "threat-intel")]
pub mod intel;

#[cfg(feature = "correlation")]
pub mod correlation;

#[cfg(feature = "active-defense")]
pub mod active_defense;

#[cfg(feature = "web-ui")]
pub mod web;

#[cfg(feature = "dbus-api")]
pub mod dbus;

#[cfg(feature = "siem")]
pub mod siem;

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;

/// crmonban engine - adapts based on enabled features
pub struct Crmonban {
    config: config::Config,
    db: database::Database,

    #[cfg(feature = "firewall")]
    firewall: firewall::Firewall,

    #[cfg(feature = "signatures")]
    signature_engine: Option<signatures::SignatureEngine>,

    #[cfg(feature = "flow-tracking")]
    flow_tracker: Option<Arc<RwLock<flow::FlowTracker>>>,

    #[cfg(feature = "ml-detection")]
    ml_engine: Option<Arc<RwLock<ml::MLEngine>>>,

    #[cfg(feature = "threat-intel")]
    intel_engine: Option<Arc<intel::IntelEngine>>,

    #[cfg(feature = "correlation")]
    correlation_engine: Option<Arc<RwLock<correlation::CorrelationEngine>>>,

    #[cfg(feature = "active-defense")]
    active_defense: Option<Arc<active_defense::ActiveDefenseEngine>>,
}

impl Crmonban {
    pub fn new(config: config::Config) -> Result<Self> {
        let db = database::Database::open(&config.general.db_path)?;

        Ok(Self {
            #[cfg(feature = "firewall")]
            firewall: firewall::Firewall::new(&config.nftables)?,

            #[cfg(feature = "signatures")]
            signature_engine: if config.signatures.enabled {
                Some(signatures::SignatureEngine::new(&config.signatures)?)
            } else {
                None
            },

            #[cfg(feature = "flow-tracking")]
            flow_tracker: if config.flow_tracking.enabled {
                Some(Arc::new(RwLock::new(flow::FlowTracker::new(&config.flow_tracking))))
            } else {
                None
            },

            #[cfg(feature = "ml-detection")]
            ml_engine: if config.ml.enabled {
                Some(Arc::new(RwLock::new(ml::MLEngine::new(&config.ml)?)))
            } else {
                None
            },

            #[cfg(feature = "threat-intel")]
            intel_engine: if config.threat_intel.enabled {
                Some(Arc::new(intel::IntelEngine::new(&config.threat_intel)?))
            } else {
                None
            },

            #[cfg(feature = "correlation")]
            correlation_engine: if config.correlation.enabled {
                Some(Arc::new(RwLock::new(correlation::CorrelationEngine::new(&config.correlation))))
            } else {
                None
            },

            #[cfg(feature = "active-defense")]
            active_defense: if config.active_defense.enabled {
                Some(Arc::new(active_defense::ActiveDefenseEngine::new(&config.active_defense)?))
            } else {
                None
            },

            config,
            db,
        })
    }

    /// Get feature summary for --version output
    pub fn feature_summary() -> &'static str {
        concat!(
            "crmonban ",
            env!("CARGO_PKG_VERSION"),
            "\n",
            "Enabled features:\n",
            #[cfg(feature = "lite")]
            "  [lite] Firewall + Log Monitor\n",
            #[cfg(feature = "firewall")]
            "    • firewall (nftables)\n",
            #[cfg(feature = "log-monitor")]
            "    • log-monitor\n",
            #[cfg(feature = "port-rules")]
            "    • port-rules (UFW-style)\n",
            #[cfg(feature = "whitelist")]
            "    • whitelist\n",
            #[cfg(feature = "signatures")]
            "  [full] Security Appliance\n",
            #[cfg(feature = "signatures")]
            "    • signatures (Suricata/Snort)\n",
            #[cfg(feature = "flow-tracking")]
            "    • flow-tracking\n",
            #[cfg(feature = "protocols")]
            "    • protocols (HTTP/DNS/TLS/SSH)\n",
            #[cfg(feature = "fingerprinting")]
            "    • fingerprinting (JA3/HASSH)\n",
            #[cfg(feature = "ml-detection")]
            "    • ml-detection\n",
            #[cfg(feature = "threat-intel")]
            "    • threat-intel\n",
            #[cfg(feature = "correlation")]
            "    • correlation\n",
            #[cfg(feature = "active-defense")]
            "    • active-defense\n",
            #[cfg(feature = "web-ui")]
            "    • web-ui\n",
            #[cfg(feature = "dbus-api")]
            "    • dbus-api\n",
            #[cfg(feature = "siem")]
            "    • siem\n",
        )
    }
}
```

## Configuration Files

### Lite Config (`config.toml`)

```toml
# crmonban-lite Configuration
# Simple firewall + log monitoring

[general]
db_path = "/var/lib/crmonban/crmonban.db"
pid_file = "/var/run/crmonban.pid"
log_level = "info"
default_ban_duration = 3600     # 1 hour

[nftables]
table_name = "crmonban"
chain_name = "input"
set_v4 = "blocked_v4"
set_v6 = "blocked_v6"
priority = -100

# UFW-style port rules
[port_rules]
enabled = true
default_input_policy = "drop"
default_output_policy = "accept"
allow_established = true
allow_loopback = true
allow_icmp = true

[[port_rules.rules]]
action = "allow"
protocol = "tcp"
port = "22"
comment = "Allow SSH"

# SSH monitoring
[services.ssh]
enabled = true
log_path = "/var/log/auth.log"
max_failures = 5
find_time = 600
ban_time = 3600

[[services.ssh.patterns]]
name = "failed_password"
regex = 'Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'
event_type = "failed_auth"

# ═══════════════════════════════════════════════════════════════════════════════
# FULL FEATURES (disabled in lite)
# ═══════════════════════════════════════════════════════════════════════════════

[signatures]
enabled = false

[flow_tracking]
enabled = false

[protocols]
enabled = false

[ml]
enabled = false

[threat_intel]
enabled = false

[correlation]
enabled = false

[active_defense]
enabled = false

[web]
enabled = false

[dbus]
enabled = false

[siem]
enabled = false
```

### Full Config (`config.full.toml`)

```toml
# crmonban-full Configuration
# Complete security appliance

[general]
db_path = "/var/lib/crmonban/crmonban.db"
pid_file = "/var/run/crmonban.pid"
log_level = "info"
default_ban_duration = 3600

[nftables]
table_name = "crmonban"
chain_name = "input"
set_v4 = "blocked_v4"
set_v6 = "blocked_v6"
priority = -100

[port_rules]
enabled = true
default_input_policy = "drop"
default_output_policy = "accept"
allow_established = true
allow_loopback = true
allow_icmp = true

[[port_rules.rules]]
action = "allow"
protocol = "tcp"
port = "22"
comment = "Allow SSH"

[[port_rules.rules]]
action = "allow"
protocol = "tcp"
port = "80,443"
comment = "Allow HTTP/HTTPS"

[services.ssh]
enabled = true
log_path = "/var/log/auth.log"
max_failures = 5
find_time = 600
ban_time = 3600

[[services.ssh.patterns]]
name = "failed_password"
regex = 'Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'
event_type = "failed_auth"

# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2: SIGNATURE DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

[signatures]
enabled = true
rules_dirs = ["/etc/crmonban/rules", "/var/lib/crmonban/rules"]
update_interval_hours = 24

[signatures.variables]
HOME_NET = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"
EXTERNAL_NET = "!$HOME_NET"
HTTP_PORTS = "80,8080,8000,8888"

[[signatures.sources]]
name = "ET Open"
url = "https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz"
enabled = true

[[signatures.sources]]
name = "Abuse.ch SSL"
url = "https://sslbl.abuse.ch/blacklist/sslblacklist.rules"
enabled = true

# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2: FLOW TRACKING
# ═══════════════════════════════════════════════════════════════════════════════

[flow_tracking]
enabled = true
table_size = 1000000
timeout_tcp_established = 3600
timeout_tcp_idle = 300
timeout_udp = 180
export_on_close = true

# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2: PROTOCOL ANALYZERS
# ═══════════════════════════════════════════════════════════════════════════════

[protocols]
enabled = true

[protocols.http]
enabled = true
ports = [80, 8080, 8000]
max_request_body = 1048576

[protocols.dns]
enabled = true
ports = [53]
log_queries = true

[protocols.tls]
enabled = true
ports = [443, 8443]
ja3_enabled = true
ja3s_enabled = true
extract_certificates = true

[protocols.ssh]
enabled = true
ports = [22]
hassh_enabled = true

# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2: MACHINE LEARNING
# ═══════════════════════════════════════════════════════════════════════════════

[ml]
enabled = true
model_path = "/var/lib/crmonban/ml_model.bin"

[ml.baseline]
enabled = true
learning_period_hours = 168

[ml.classification]
enabled = true
min_confidence = 0.7

[ml.anomaly]
enabled = true
algorithm = "isolation_forest"
threshold = 0.5

[ml.beaconing]
enabled = true
min_connections = 20

# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2: THREAT INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

[threat_intel]
enabled = true
cache_path = "/var/lib/crmonban/intel_cache"
update_interval_hours = 4

[[threat_intel.feeds]]
name = "Spamhaus DROP"
type = "ip_list"
url = "https://www.spamhaus.org/drop/drop.txt"
enabled = true

[[threat_intel.feeds]]
name = "Abuse.ch URLhaus"
type = "url_list"
url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
enabled = true

# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2: ALERT CORRELATION
# ═══════════════════════════════════════════════════════════════════════════════

[correlation]
enabled = true
window_seconds = 300
max_incidents = 10000

# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2: ACTIVE DEFENSE
# ═══════════════════════════════════════════════════════════════════════════════

[active_defense]
enabled = true
legal_consent = false           # Must explicitly enable

[active_defense.profiler]
enabled = true
abuseipdb_key = ""
shodan_key = ""

[active_defense.honeypots]
enabled = false

[[active_defense.honeypots.services]]
type = "ssh"
port = 2222

[active_defense.honeytokens]
enabled = false

[active_defense.playbooks]
enabled = true

# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2: WEB DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

[web]
enabled = true
listen_addr = "127.0.0.1"
listen_port = 8080
tls_enabled = false

[web.auth]
enabled = true
type = "basic"
users_file = "/etc/crmonban/users.htpasswd"

# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2: D-BUS API
# ═══════════════════════════════════════════════════════════════════════════════

[dbus]
enabled = true
system_bus = true

# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2: SIEM INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════════

[siem]
enabled = false

[siem.splunk]
enabled = false
hec_url = ""
hec_token = ""

[siem.elasticsearch]
enabled = false
url = ""
index = "crmonban"
```

## Build Commands

```bash
# ═══════════════════════════════════════════════════════════════════════════════
# BUILD LITE (Default)
# ═══════════════════════════════════════════════════════════════════════════════

# Standard build (lite features)
cargo build --release

# Resulting binary: ~5MB, minimal dependencies
# Features: firewall, log-monitor, port-rules, whitelist, cli

# ═══════════════════════════════════════════════════════════════════════════════
# BUILD FULL
# ═══════════════════════════════════════════════════════════════════════════════

# Full security appliance
cargo build --release --features full

# Resulting binary: ~25MB, all dependencies
# Features: Everything

# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM BUILDS
# ═══════════════════════════════════════════════════════════════════════════════

# Lite + signatures only
cargo build --release --features "lite,signatures"

# Lite + ML detection
cargo build --release --features "lite,flow-tracking,ml-detection"

# Lite + web UI
cargo build --release --features "lite,web-ui"

# Full without active defense
cargo build --release --features "full" --no-default-features

# Minimal (firewall only)
cargo build --release --no-default-features --features "firewall,cli"
```

## CLI Differences

### Lite CLI
```bash
crmonban --help

crmonban - Simple firewall and intrusion prevention

USAGE:
    crmonban <COMMAND>

COMMANDS:
    start       Start the daemon
    stop        Stop the daemon
    status      Show daemon status
    ban         Ban an IP address
    unban       Unban an IP address
    list        List active bans
    whitelist   Manage whitelist
    port        Manage port rules (UFW-style)
    reload      Reload configuration
    help        Show help

PORT COMMANDS:
    crmonban port allow 22/tcp
    crmonban port allow 80,443/tcp
    crmonban port deny 3306/tcp
    crmonban port list
    crmonban port status
```

### Full CLI (Additional Commands)
```bash
crmonban --help

crmonban - Network Security Appliance

USAGE:
    crmonban <COMMAND>

COMMANDS:
    # Lite commands...
    start, stop, status, ban, unban, list, whitelist, port, reload

    # Full commands
    rules       Manage signature rules
    flows       View active flows
    intel       Threat intelligence
    ml          Machine learning controls
    profile     Profile an attacker
    honeypot    Honeypot management
    dashboard   Open web dashboard
    incidents   View security incidents

RULES COMMANDS:
    crmonban rules update
    crmonban rules list
    crmonban rules show SID
    crmonban rules disable SID
    crmonban rules stats

ML COMMANDS:
    crmonban ml status
    crmonban ml baseline reset
    crmonban ml train --dataset PATH

PROFILE COMMANDS:
    crmonban profile 1.2.3.4
    crmonban profile 1.2.3.4 --full

HONEYPOT COMMANDS:
    crmonban honeypot start
    crmonban honeypot interactions
```

## Installation

```bash
# ═══════════════════════════════════════════════════════════════════════════════
# INSTALL LITE
# ═══════════════════════════════════════════════════════════════════════════════

# Build
cargo build --release

# Install
sudo cp target/release/crmonban /usr/local/bin/
sudo cp config.toml /etc/crmonban/config.toml
sudo cp crmonban.service /etc/systemd/system/

# Enable
sudo systemctl enable --now crmonban

# ═══════════════════════════════════════════════════════════════════════════════
# INSTALL FULL
# ═══════════════════════════════════════════════════════════════════════════════

# Build
cargo build --release --features full

# Install
sudo cp target/release/crmonban /usr/local/bin/
sudo cp config.full.toml /etc/crmonban/config.toml
sudo mkdir -p /etc/crmonban/rules
sudo mkdir -p /var/lib/crmonban/{certs,intel_cache}
sudo cp crmonban.service /etc/systemd/system/

# Download initial rules
sudo crmonban rules update

# Enable
sudo systemctl enable --now crmonban

# Optional: Enable web dashboard
sudo crmonban dashboard --generate-password admin
```

## Resource Comparison

| Resource | Lite | Full |
|----------|------|------|
| Binary Size | ~5 MB | ~25 MB |
| RAM (idle) | ~20 MB | ~200 MB |
| RAM (active) | ~50 MB | ~500 MB - 2 GB |
| CPU (idle) | < 1% | < 2% |
| Disk (rules) | 0 | ~100 MB |
| Disk (ML model) | 0 | ~50 MB |
| Disk (intel cache) | 0 | ~200 MB |
| Dependencies | 15 | 45 |

## Summary

| Aspect | Lite | Full |
|--------|------|------|
| **Target User** | Home/Small Server | Enterprise/Security Team |
| **Complexity** | Simple | Advanced |
| **Setup Time** | 5 minutes | 30 minutes |
| **Learning Curve** | Minimal | Moderate |
| **Maintenance** | Low | Regular rule/feed updates |
| **Detection** | Log patterns | Signatures + ML + Behavior |
| **Response** | Ban only | Ban + Honeypot + Playbooks |
| **Visibility** | CLI only | CLI + Web Dashboard |
| **Integration** | None | SIEM + D-Bus |
