# Implementation Plan: Active Defense & Threat Response

## Overview

Active defense goes beyond passive detection to actively engage with attackers, gather intelligence, and potentially neutralize threats. This includes:

1. **Reconnaissance** - Profile attacker systems and infrastructure
2. **Deception** - Honeypots, honeytokens, and decoys
3. **Attribution** - Identify attacker identity and infrastructure
4. **Counter-Intelligence** - Gather intel on attacker TTPs
5. **Active Response** - Automated countermeasures (with legal constraints)

## Legal & Ethical Framework

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        LEGAL BOUNDARIES                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ✅ PERMITTED (Defensive)              ❌ PROHIBITED (Offensive)            │
│  ─────────────────────────             ────────────────────────             │
│  • Passive reconnaissance              • Unauthorized system access         │
│  • Open source intelligence            • DDoS or destructive attacks        │
│  • Honeypots on your network           • Malware deployment                 │
│  • Tracking attacker behavior          • Data theft/exfiltration            │
│  • Threat intelligence gathering       • Hack-back operations               │
│  • Deception/misdirection              • Attacking third-party infra        │
│  • Sinkholing your own traffic         • Vigilante justice                  │
│  • Legal takedown requests             • Unauthorized scanning              │
│                                                                             │
│  ⚠️  GRAY AREA (Consult Legal)                                              │
│  ─────────────────────────────                                              │
│  • Active scanning of attacker IPs (may be legal in some jurisdictions)    │
│  • Beacons/trackers in bait files (check wiretap laws)                     │
│  • Engaging with attacker C2 (passive observation only)                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘

IMPORTANT: This module requires explicit opt-in and legal acknowledgment.
Active features should only be used with proper authorization.
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Active Defense Engine                                │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐          ┌───────────────┐          ┌───────────────┐
│  Threat       │          │   Deception   │          │   Response    │
│  Profiler     │          │   Framework   │          │   Orchestrator│
└───────┬───────┘          └───────┬───────┘          └───────┬───────┘
        │                          │                          │
   ┌────┴────┐               ┌─────┴─────┐              ┌─────┴─────┐
   │         │               │           │              │           │
   ▼         ▼               ▼           ▼              ▼           ▼
┌──────┐ ┌──────┐      ┌─────────┐ ┌─────────┐   ┌──────────┐ ┌──────────┐
│OSINT │ │Recon │      │Honeypot │ │Honey-   │   │Automated │ │Takedown  │
│Engine│ │Module│      │Manager  │ │tokens   │   │Response  │ │Requests  │
└──────┘ └──────┘      └─────────┘ └─────────┘   └──────────┘ └──────────┘
   │         │               │           │              │           │
   └────┬────┘               └─────┬─────┘              └─────┬─────┘
        │                          │                          │
        ▼                          ▼                          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Threat Intelligence Database                        │
│  • Attacker profiles    • Infrastructure maps    • TTP patterns             │
│  • Attribution data     • Campaign tracking      • IOC correlation          │
└─────────────────────────────────────────────────────────────────────────────┘
```

## File Structure

```
src/active_defense/
├── mod.rs                      # ActiveDefenseEngine, feature gate
├── config.rs                   # Configuration with legal acknowledgment
├── profiler/
│   ├── mod.rs                  # ThreatProfiler
│   ├── osint.rs                # Open source intelligence gathering
│   ├── recon.rs                # Passive/active reconnaissance
│   ├── fingerprint.rs          # OS/service fingerprinting
│   ├── infrastructure.rs       # Infrastructure mapping
│   └── attribution.rs          # Attacker attribution
├── deception/
│   ├── mod.rs                  # DeceptionFramework
│   ├── honeypot.rs             # Honeypot services
│   ├── honeytoken.rs           # Honeytokens/canaries
│   ├── tarpit.rs               # Connection tarpits
│   ├── decoy.rs                # Decoy files/services
│   └── breadcrumbs.rs          # False trail generation
├── response/
│   ├── mod.rs                  # ResponseOrchestrator
│   ├── playbooks.rs            # Automated response playbooks
│   ├── escalation.rs           # Escalation procedures
│   ├── takedown.rs             # Abuse report generation
│   └── sinkhole.rs             # Traffic sinkholing
├── intel/
│   ├── mod.rs                  # Intelligence database
│   ├── campaign.rs             # Campaign tracking
│   ├── ttp.rs                  # TTP pattern matching
│   └── correlation.rs          # Cross-attack correlation
└── legal/
    ├── mod.rs                  # Legal compliance checks
    ├── consent.rs              # User consent management
    └── audit.rs                # Audit logging for legal
```

## Feature 1: Threat Profiler

### OSINT Engine

```rust
// src/active_defense/profiler/osint.rs

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Open Source Intelligence gatherer
pub struct OsintEngine {
    config: OsintConfig,
    cache: OsintCache,
    rate_limiter: RateLimiter,
}

/// Complete attacker profile from OSINT
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerProfile {
    pub ip: IpAddr,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub attacks_observed: u32,

    // Network information
    pub network_info: NetworkInfo,

    // Geolocation
    pub geolocation: Option<GeoLocation>,

    // Reputation data
    pub reputation: ReputationData,

    // Infrastructure analysis
    pub infrastructure: InfrastructureAnalysis,

    // Historical activity
    pub history: AttackHistory,

    // Attribution hints
    pub attribution: AttributionData,

    // Risk assessment
    pub risk_score: f64,
    pub threat_level: ThreatLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub asn: Option<u32>,
    pub asn_name: Option<String>,
    pub asn_country: Option<String>,
    pub network_cidr: Option<String>,
    pub network_name: Option<String>,
    pub abuse_contact: Option<String>,
    pub is_hosting: bool,
    pub is_vpn: bool,
    pub is_tor: bool,
    pub is_proxy: bool,
    pub is_datacenter: bool,
    pub is_mobile: bool,
    pub is_crawler: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationData {
    // AbuseIPDB
    pub abuseipdb_score: Option<u8>,
    pub abuseipdb_reports: Option<u32>,
    pub abuseipdb_categories: Vec<String>,

    // VirusTotal
    pub virustotal_malicious: Option<u32>,
    pub virustotal_suspicious: Option<u32>,
    pub virustotal_engines: Option<u32>,

    // Shodan
    pub shodan_ports: Vec<u16>,
    pub shodan_vulns: Vec<String>,
    pub shodan_tags: Vec<String>,

    // Other sources
    pub blocklist_hits: Vec<String>,
    pub threat_feeds_matched: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfrastructureAnalysis {
    // Open ports discovered
    pub open_ports: Vec<PortInfo>,

    // Services detected
    pub services: Vec<ServiceInfo>,

    // SSL/TLS certificates
    pub certificates: Vec<CertificateInfo>,

    // DNS records
    pub dns_records: DnsRecords,

    // Related infrastructure
    pub related_ips: Vec<IpAddr>,
    pub related_domains: Vec<String>,

    // Hosting analysis
    pub hosting_provider: Option<String>,
    pub shared_hosting: bool,
    pub reverse_dns: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub vulnerabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionData {
    // Behavioral patterns
    pub attack_patterns: Vec<String>,       // MITRE ATT&CK
    pub tools_observed: Vec<String>,        // Detected tools
    pub malware_families: Vec<String>,      // Associated malware

    // Temporal patterns
    pub active_hours: Vec<u8>,              // Hours of activity (UTC)
    pub active_days: Vec<u8>,               // Days of week
    pub timezone_estimate: Option<String>,

    // Language hints
    pub language_indicators: Vec<String>,

    // Campaign association
    pub campaigns: Vec<CampaignLink>,

    // Threat actor association
    pub threat_actors: Vec<ThreatActorLink>,

    // Confidence
    pub attribution_confidence: f64,
}

impl OsintEngine {
    pub fn new(config: OsintConfig) -> Self {
        Self {
            config,
            cache: OsintCache::new(),
            rate_limiter: RateLimiter::new(),
        }
    }

    /// Build complete attacker profile
    pub async fn profile_attacker(&self, ip: IpAddr) -> Result<AttackerProfile> {
        // Check cache first
        if let Some(cached) = self.cache.get(&ip) {
            if cached.age() < self.config.cache_ttl {
                return Ok(cached);
            }
        }

        // Gather intelligence in parallel
        let (network, geo, reputation, infra) = tokio::join!(
            self.gather_network_info(ip),
            self.gather_geolocation(ip),
            self.gather_reputation(ip),
            self.analyze_infrastructure(ip),
        );

        let profile = AttackerProfile {
            ip,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            attacks_observed: 1,
            network_info: network?,
            geolocation: geo.ok(),
            reputation: reputation?,
            infrastructure: infra?,
            history: AttackHistory::default(),
            attribution: AttributionData::default(),
            risk_score: 0.0,
            threat_level: ThreatLevel::Unknown,
        };

        // Calculate risk score
        let profile = self.calculate_risk_score(profile);

        // Cache result
        self.cache.insert(ip, profile.clone());

        Ok(profile)
    }

    /// Gather network/ASN information
    async fn gather_network_info(&self, ip: IpAddr) -> Result<NetworkInfo> {
        let mut info = NetworkInfo::default();

        // RDAP/WHOIS lookup
        if let Ok(whois) = self.rdap_lookup(ip).await {
            info.asn = whois.asn;
            info.asn_name = whois.asn_name;
            info.network_cidr = whois.network;
            info.abuse_contact = whois.abuse_contact;
        }

        // Check IP type databases
        info.is_tor = self.check_tor_exit(ip).await;
        info.is_vpn = self.check_vpn_provider(ip).await;
        info.is_datacenter = self.check_datacenter(ip).await;
        info.is_proxy = self.check_proxy(ip).await;

        Ok(info)
    }

    /// Gather reputation from multiple sources
    async fn gather_reputation(&self, ip: IpAddr) -> Result<ReputationData> {
        let mut rep = ReputationData::default();

        // AbuseIPDB (if API key configured)
        if let Some(ref api_key) = self.config.abuseipdb_key {
            if let Ok(abuse) = self.query_abuseipdb(ip, api_key).await {
                rep.abuseipdb_score = Some(abuse.score);
                rep.abuseipdb_reports = Some(abuse.total_reports);
                rep.abuseipdb_categories = abuse.categories;
            }
        }

        // VirusTotal (if API key configured)
        if let Some(ref api_key) = self.config.virustotal_key {
            if let Ok(vt) = self.query_virustotal(ip, api_key).await {
                rep.virustotal_malicious = Some(vt.malicious);
                rep.virustotal_suspicious = Some(vt.suspicious);
            }
        }

        // Shodan (if API key configured)
        if let Some(ref api_key) = self.config.shodan_key {
            if let Ok(shodan) = self.query_shodan(ip, api_key).await {
                rep.shodan_ports = shodan.ports;
                rep.shodan_vulns = shodan.vulns;
                rep.shodan_tags = shodan.tags;
            }
        }

        // Free blocklists
        rep.blocklist_hits = self.check_blocklists(ip).await;

        Ok(rep)
    }

    /// Analyze attacker infrastructure (passive only by default)
    async fn analyze_infrastructure(&self, ip: IpAddr) -> Result<InfrastructureAnalysis> {
        let mut analysis = InfrastructureAnalysis::default();

        // Reverse DNS
        analysis.reverse_dns = self.reverse_dns(ip).await.ok();

        // Certificate transparency logs
        if let Some(ref rdns) = analysis.reverse_dns {
            analysis.certificates = self.query_ct_logs(rdns).await.unwrap_or_default();
        }

        // Passive DNS (from threat intel feeds)
        analysis.dns_records = self.passive_dns(ip).await.unwrap_or_default();

        // Historical port data from Shodan/Censys (passive)
        if self.config.use_shodan_history {
            analysis.open_ports = self.shodan_port_history(ip).await.unwrap_or_default();
        }

        // Find related infrastructure
        analysis.related_ips = self.find_related_ips(ip).await.unwrap_or_default();

        Ok(analysis)
    }

    /// Calculate overall risk score (0.0 - 1.0)
    fn calculate_risk_score(&self, mut profile: AttackerProfile) -> AttackerProfile {
        let mut score = 0.0;
        let mut factors = 0;

        // Reputation score
        if let Some(abuse_score) = profile.reputation.abuseipdb_score {
            score += (abuse_score as f64) / 100.0;
            factors += 1;
        }

        // Blocklist hits
        let blocklist_factor = (profile.reputation.blocklist_hits.len() as f64 / 10.0).min(1.0);
        score += blocklist_factor;
        factors += 1;

        // VPN/Tor/Proxy (higher risk)
        if profile.network_info.is_tor {
            score += 0.8;
            factors += 1;
        } else if profile.network_info.is_vpn || profile.network_info.is_proxy {
            score += 0.5;
            factors += 1;
        }

        // Datacenter IP (often used for attacks)
        if profile.network_info.is_datacenter {
            score += 0.3;
            factors += 1;
        }

        // Known vulnerabilities on attacker system
        let vuln_count = profile.infrastructure.open_ports
            .iter()
            .flat_map(|p| &p.vulnerabilities)
            .count();
        if vuln_count > 0 {
            score += (vuln_count as f64 / 20.0).min(0.5);
            factors += 1;
        }

        // Normalize
        profile.risk_score = if factors > 0 { score / factors as f64 } else { 0.5 };

        // Determine threat level
        profile.threat_level = match profile.risk_score {
            s if s >= 0.8 => ThreatLevel::Critical,
            s if s >= 0.6 => ThreatLevel::High,
            s if s >= 0.4 => ThreatLevel::Medium,
            s if s >= 0.2 => ThreatLevel::Low,
            _ => ThreatLevel::Info,
        };

        profile
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
    Unknown,
}
```

### Active Reconnaissance (Opt-in, requires consent)

```rust
// src/active_defense/profiler/recon.rs

/// Active reconnaissance module (requires explicit authorization)
pub struct ActiveRecon {
    config: ReconConfig,
    consent_verified: bool,
}

impl ActiveRecon {
    /// Requires explicit consent before any active scanning
    pub fn new(config: ReconConfig) -> Result<Self> {
        if !config.legal_consent_given {
            return Err(anyhow!("Active reconnaissance requires legal consent"));
        }

        Ok(Self {
            config,
            consent_verified: true,
        })
    }

    /// Light port scan - only check specific ports
    /// This should only be used against confirmed attackers
    /// with proper authorization
    pub async fn quick_scan(&self, ip: IpAddr) -> Result<Vec<PortInfo>> {
        if !self.consent_verified {
            return Err(anyhow!("Consent not verified"));
        }

        // Only scan common attack infrastructure ports
        let target_ports = [
            21,    // FTP (common C2)
            22,    // SSH
            23,    // Telnet
            80,    // HTTP
            443,   // HTTPS
            445,   // SMB
            1433,  // MSSQL
            3306,  // MySQL
            3389,  // RDP
            4444,  // Metasploit default
            5900,  // VNC
            6667,  // IRC (C2)
            8080,  // HTTP alt
            8443,  // HTTPS alt
            9001,  // Tor
        ];

        let mut results = Vec::new();

        for &port in &target_ports {
            match self.check_port(ip, port).await {
                Ok(info) => results.push(info),
                Err(_) => continue,
            }
        }

        Ok(results)
    }

    /// Check single port with banner grab
    async fn check_port(&self, ip: IpAddr, port: u16) -> Result<PortInfo> {
        let addr = SocketAddr::new(ip, port);
        let timeout = Duration::from_secs(self.config.timeout_secs);

        // TCP connect with timeout
        let stream = tokio::time::timeout(
            timeout,
            TcpStream::connect(addr)
        ).await??;

        // Grab banner if possible
        let banner = self.grab_banner(&stream, port).await.ok();

        // Identify service
        let (service, version) = self.identify_service(port, banner.as_deref());

        Ok(PortInfo {
            port,
            protocol: "tcp".into(),
            service,
            version,
            banner,
            vulnerabilities: vec![],
        })
    }

    /// OS fingerprinting via TCP/IP stack behavior
    pub async fn os_fingerprint(&self, ip: IpAddr) -> Result<OsFingerprint> {
        if !self.consent_verified {
            return Err(anyhow!("Consent not verified"));
        }

        // Analyze TCP characteristics
        let mut hints = Vec::new();

        // TTL analysis (from received packets)
        // - Linux: typically 64
        // - Windows: typically 128
        // - Cisco/Network: typically 255

        // TCP window size
        // TCP options order
        // Response timing

        Ok(OsFingerprint {
            os_family: None,
            os_version: None,
            confidence: 0.0,
            hints,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFingerprint {
    pub os_family: Option<String>,    // Linux, Windows, BSD, etc.
    pub os_version: Option<String>,
    pub confidence: f64,
    pub hints: Vec<String>,
}
```

## Feature 2: Deception Framework

### Honeypot Manager

```rust
// src/active_defense/deception/honeypot.rs

use std::collections::HashMap;
use tokio::net::TcpListener;

/// Honeypot service manager
pub struct HoneypotManager {
    config: HoneypotConfig,
    services: HashMap<u16, HoneypotService>,
    interaction_log: InteractionLog,
}

/// Types of honeypot services
pub enum HoneypotService {
    Ssh(SshHoneypot),
    Http(HttpHoneypot),
    Ftp(FtpHoneypot),
    Telnet(TelnetHoneypot),
    Smb(SmbHoneypot),
    Mysql(MysqlHoneypot),
    Redis(RedisHoneypot),
    Custom(CustomHoneypot),
}

/// SSH honeypot - captures credentials and commands
pub struct SshHoneypot {
    port: u16,
    banner: String,
    fake_hostname: String,
    fake_users: Vec<FakeUser>,
    allow_login: bool,
    capture_commands: bool,
    max_session_time: Duration,
}

impl SshHoneypot {
    pub async fn run(&self, listener: TcpListener, log: InteractionLog) -> Result<()> {
        loop {
            let (stream, addr) = listener.accept().await?;

            let honeypot = self.clone();
            let log = log.clone();

            tokio::spawn(async move {
                if let Err(e) = honeypot.handle_connection(stream, addr, log).await {
                    tracing::debug!("SSH honeypot error: {}", e);
                }
            });
        }
    }

    async fn handle_connection(
        &self,
        stream: TcpStream,
        addr: SocketAddr,
        log: InteractionLog,
    ) -> Result<()> {
        log.record(InteractionEvent {
            timestamp: Utc::now(),
            source_ip: addr.ip(),
            source_port: addr.port(),
            service: "ssh".into(),
            event_type: InteractionType::Connection,
            details: HashMap::new(),
        });

        // Send banner
        stream.write_all(self.banner.as_bytes()).await?;

        // Implement minimal SSH protocol to capture credentials
        // This is a simplified version - real implementation would
        // properly implement SSH handshake

        let mut buffer = [0u8; 4096];

        loop {
            let n = stream.read(&mut buffer).await?;
            if n == 0 {
                break;
            }

            // Log all data received
            log.record(InteractionEvent {
                timestamp: Utc::now(),
                source_ip: addr.ip(),
                source_port: addr.port(),
                service: "ssh".into(),
                event_type: InteractionType::Data,
                details: [
                    ("data".into(), hex::encode(&buffer[..n]).into()),
                    ("length".into(), n.to_string().into()),
                ].into(),
            });

            // Extract credentials if possible
            if let Some((username, password)) = self.extract_credentials(&buffer[..n]) {
                log.record(InteractionEvent {
                    timestamp: Utc::now(),
                    source_ip: addr.ip(),
                    source_port: addr.port(),
                    service: "ssh".into(),
                    event_type: InteractionType::Credential,
                    details: [
                        ("username".into(), username.clone().into()),
                        ("password".into(), password.clone().into()),
                    ].into(),
                });

                // If allow_login, simulate successful auth
                if self.allow_login && self.check_fake_user(&username, &password) {
                    self.run_fake_shell(stream, addr, log).await?;
                    break;
                }
            }
        }

        Ok(())
    }

    async fn run_fake_shell(
        &self,
        mut stream: TcpStream,
        addr: SocketAddr,
        log: InteractionLog,
    ) -> Result<()> {
        // Send fake shell prompt
        let prompt = format!("{}@{}:~$ ", "user", self.fake_hostname);
        stream.write_all(prompt.as_bytes()).await?;

        let mut buffer = [0u8; 4096];

        loop {
            let n = stream.read(&mut buffer).await?;
            if n == 0 {
                break;
            }

            let command = String::from_utf8_lossy(&buffer[..n]).trim().to_string();

            log.record(InteractionEvent {
                timestamp: Utc::now(),
                source_ip: addr.ip(),
                source_port: addr.port(),
                service: "ssh".into(),
                event_type: InteractionType::Command,
                details: [("command".into(), command.clone().into())].into(),
            });

            // Generate fake response
            let response = self.fake_command_response(&command);
            stream.write_all(response.as_bytes()).await?;
            stream.write_all(prompt.as_bytes()).await?;
        }

        Ok(())
    }

    fn fake_command_response(&self, command: &str) -> String {
        let parts: Vec<&str> = command.split_whitespace().collect();
        let cmd = parts.first().map(|s| *s).unwrap_or("");

        match cmd {
            "ls" => "Desktop  Documents  Downloads\n".into(),
            "pwd" => "/home/user\n".into(),
            "whoami" => "user\n".into(),
            "id" => "uid=1000(user) gid=1000(user) groups=1000(user)\n".into(),
            "uname" => "Linux\n".into(),
            "cat" => {
                if parts.get(1).map(|s| s.contains("passwd")).unwrap_or(false) {
                    "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n".into()
                } else {
                    "cat: file not found\n".into()
                }
            }
            "wget" | "curl" => {
                // Log download attempt - critical intel!
                "Connecting...\n".into()
            }
            "exit" | "quit" => "logout\n".into(),
            _ => format!("{}: command not found\n", cmd),
        }
    }
}

/// HTTP honeypot - mimics vulnerable web applications
pub struct HttpHoneypot {
    port: u16,
    server_banner: String,
    fake_cms: FakeCms,
    vulnerable_paths: Vec<VulnerablePath>,
}

#[derive(Clone)]
pub enum FakeCms {
    WordPress { version: String },
    Drupal { version: String },
    Joomla { version: String },
    PhpMyAdmin { version: String },
    Custom { name: String },
}

pub struct VulnerablePath {
    path: String,
    vulnerability: String,
    response: String,
}

impl HttpHoneypot {
    pub async fn run(&self, listener: TcpListener, log: InteractionLog) -> Result<()> {
        let app = Router::new()
            .route("/", get(Self::handle_root))
            .route("/wp-admin/*path", get(Self::handle_wp_admin))
            .route("/wp-login.php", get(Self::handle_wp_login).post(Self::handle_wp_login_post))
            .route("/phpmyadmin/*path", get(Self::handle_phpmyadmin))
            .route("/admin/*path", get(Self::handle_admin))
            .route("/*path", get(Self::handle_any))
            .layer(Extension(log))
            .layer(Extension(self.clone()));

        axum::serve(listener, app).await?;
        Ok(())
    }

    async fn handle_wp_login_post(
        Extension(log): Extension<InteractionLog>,
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
        Form(params): Form<HashMap<String, String>>,
    ) -> impl IntoResponse {
        // Capture credentials
        if let (Some(user), Some(pass)) = (params.get("log"), params.get("pwd")) {
            log.record(InteractionEvent {
                timestamp: Utc::now(),
                source_ip: addr.ip(),
                source_port: addr.port(),
                service: "http".into(),
                event_type: InteractionType::Credential,
                details: [
                    ("username".into(), user.clone().into()),
                    ("password".into(), pass.clone().into()),
                    ("path".into(), "/wp-login.php".into()),
                ].into(),
            });
        }

        // Return fake error page
        Html(r#"
            <html>
            <head><title>WordPress &rsaquo; Error</title></head>
            <body>
            <div id="login_error">
                <strong>Error:</strong> The username or password you entered is incorrect.
            </div>
            </body>
            </html>
        "#)
    }
}

/// Interaction event log
#[derive(Clone)]
pub struct InteractionLog {
    events: Arc<RwLock<Vec<InteractionEvent>>>,
    event_tx: mpsc::Sender<InteractionEvent>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InteractionEvent {
    pub timestamp: DateTime<Utc>,
    pub source_ip: IpAddr,
    pub source_port: u16,
    pub service: String,
    pub event_type: InteractionType,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum InteractionType {
    Connection,
    Credential,
    Command,
    Data,
    Download,
    Upload,
    Exploit,
    Scan,
}
```

### Honeytokens & Canaries

```rust
// src/active_defense/deception/honeytoken.rs

/// Honeytokens - trackable bait credentials/files
pub struct HoneytokenManager {
    tokens: HashMap<String, Honeytoken>,
    alert_tx: mpsc::Sender<HoneytokenAlert>,
}

/// Types of honeytokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Honeytoken {
    /// Fake AWS credentials
    AwsCredential {
        access_key_id: String,
        secret_access_key: String,
        description: String,
    },

    /// Fake API key
    ApiKey {
        service: String,
        key: String,
        description: String,
    },

    /// Fake database credential
    DatabaseCredential {
        host: String,
        username: String,
        password: String,
        database: String,
    },

    /// Canary file (tracks when opened)
    CanaryFile {
        path: PathBuf,
        callback_url: String,
        description: String,
    },

    /// DNS canary (tracks DNS lookups)
    DnsCanary {
        subdomain: String,
        domain: String,
        description: String,
    },

    /// Web beacon (tracking pixel)
    WebBeacon {
        url: String,
        description: String,
    },

    /// Fake SSH key
    SshKey {
        public_key: String,
        description: String,
    },
}

impl HoneytokenManager {
    /// Generate AWS credential honeytoken
    pub fn create_aws_token(&mut self, description: &str) -> Honeytoken {
        // Generate realistic-looking fake AWS credentials
        let access_key_id = format!("AKIA{}", generate_random_string(16));
        let secret_access_key = generate_random_string(40);

        let token = Honeytoken::AwsCredential {
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
            description: description.into(),
        };

        self.tokens.insert(access_key_id, token.clone());

        // Register with canary service (e.g., canarytokens.org API or self-hosted)
        self.register_canary(&token);

        token
    }

    /// Create canary file that calls back when opened
    pub fn create_canary_file(
        &mut self,
        path: &Path,
        file_type: CanaryFileType,
        description: &str,
    ) -> Result<Honeytoken> {
        // Generate unique callback URL
        let token_id = generate_token_id();
        let callback_url = format!(
            "https://canarytokens.your-domain.com/{}",
            token_id
        );

        let content = match file_type {
            CanaryFileType::Word => self.create_word_canary(&callback_url)?,
            CanaryFileType::Excel => self.create_excel_canary(&callback_url)?,
            CanaryFileType::Pdf => self.create_pdf_canary(&callback_url)?,
            CanaryFileType::Exe => self.create_exe_canary(&callback_url)?,
        };

        std::fs::write(path, content)?;

        let token = Honeytoken::CanaryFile {
            path: path.to_path_buf(),
            callback_url,
            description: description.into(),
        };

        self.tokens.insert(token_id, token.clone());
        Ok(token)
    }

    /// Create DNS canary subdomain
    pub fn create_dns_canary(&mut self, base_domain: &str, description: &str) -> Honeytoken {
        let subdomain = generate_random_string(12).to_lowercase();

        let token = Honeytoken::DnsCanary {
            subdomain: subdomain.clone(),
            domain: base_domain.into(),
            description: description.into(),
        };

        // Full hostname to monitor
        let hostname = format!("{}.{}", subdomain, base_domain);

        self.tokens.insert(hostname, token.clone());
        token
    }

    /// Deploy honeytokens to strategic locations
    pub fn deploy_breadcrumbs(&mut self, config: &BreadcrumbConfig) -> Result<Vec<Honeytoken>> {
        let mut deployed = Vec::new();

        // Plant fake AWS credentials in common locations
        if config.aws_credentials {
            let token = self.create_aws_token("Breadcrumb AWS creds");

            // Write to common paths
            for path in &[
                "/home/*/.aws/credentials",
                "/root/.aws/credentials",
                "/var/www/.aws/credentials",
            ] {
                // Expand glob and write
            }

            deployed.push(token);
        }

        // Plant canary documents
        if config.canary_documents {
            for (name, desc) in &[
                ("passwords.xlsx", "Password list canary"),
                ("employee_data.csv", "Employee data canary"),
                ("financial_report.pdf", "Financial report canary"),
                ("admin_credentials.txt", "Admin creds canary"),
            ] {
                let path = config.document_path.join(name);
                if let Ok(token) = self.create_canary_file(
                    &path,
                    CanaryFileType::from_extension(name),
                    desc,
                ) {
                    deployed.push(token);
                }
            }
        }

        Ok(deployed)
    }

    /// Handle honeytoken trigger
    pub async fn on_token_triggered(&self, token_id: &str, context: TriggerContext) {
        if let Some(token) = self.tokens.get(token_id) {
            let alert = HoneytokenAlert {
                timestamp: Utc::now(),
                token: token.clone(),
                context,
                severity: Severity::Critical,
            };

            // Send alert
            let _ = self.alert_tx.send(alert).await;
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HoneytokenAlert {
    pub timestamp: DateTime<Utc>,
    pub token: Honeytoken,
    pub context: TriggerContext,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize)]
pub struct TriggerContext {
    pub source_ip: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub referrer: Option<String>,
    pub additional: HashMap<String, String>,
}
```

### Connection Tarpit

```rust
// src/active_defense/deception/tarpit.rs

/// TCP tarpit - slow down attackers
pub struct Tarpit {
    config: TarpitConfig,
    active_connections: Arc<AtomicUsize>,
}

impl Tarpit {
    /// Run tarpit on specified port
    pub async fn run(&self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, addr) = listener.accept().await?;

            if self.active_connections.load(Ordering::SeqCst) >= self.config.max_connections {
                // Drop connection if too many
                drop(stream);
                continue;
            }

            self.active_connections.fetch_add(1, Ordering::SeqCst);

            let config = self.config.clone();
            let counter = self.active_connections.clone();

            tokio::spawn(async move {
                let _ = Self::tarpit_connection(stream, addr, config).await;
                counter.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }

    async fn tarpit_connection(
        mut stream: TcpStream,
        addr: SocketAddr,
        config: TarpitConfig,
    ) -> Result<()> {
        tracing::info!("Tarpitting connection from {}", addr);

        // Set socket options to minimize resources
        stream.set_nodelay(false)?;

        let start = Instant::now();

        // Send data very slowly
        let response = match config.mode {
            TarpitMode::SlowHeaders => {
                // Send HTTP headers one byte at a time
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            }
            TarpitMode::SlowBody => {
                // Send body one byte at a time
                b"<html><body>Loading..."
            }
            TarpitMode::EndlessData => {
                // Send endless stream of data
                b"X"
            }
            TarpitMode::SlowRead => {
                // Accept data very slowly
                b""
            }
        };

        for byte in response.iter().cycle() {
            // Check timeout
            if start.elapsed() > config.max_duration {
                break;
            }

            // Send one byte
            if stream.write_all(&[*byte]).await.is_err() {
                break;
            }

            // Sleep between bytes
            tokio::time::sleep(config.byte_delay).await;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct TarpitConfig {
    pub mode: TarpitMode,
    pub byte_delay: Duration,
    pub max_duration: Duration,
    pub max_connections: usize,
}

#[derive(Clone, Copy)]
pub enum TarpitMode {
    SlowHeaders,    // Slow HTTP headers
    SlowBody,       // Slow HTTP body
    EndlessData,    // Never-ending response
    SlowRead,       // Slow to receive data
}
```

## Feature 3: Response Orchestrator

### Automated Playbooks

```rust
// src/active_defense/response/playbooks.rs

/// Response playbook engine
pub struct PlaybookEngine {
    playbooks: HashMap<String, Playbook>,
    executor: PlaybookExecutor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Playbook {
    pub name: String,
    pub description: String,
    pub triggers: Vec<PlaybookTrigger>,
    pub conditions: Vec<PlaybookCondition>,
    pub actions: Vec<PlaybookAction>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlaybookTrigger {
    Detection { detection_type: String, min_severity: Severity },
    Threshold { metric: String, value: f64, window_secs: u64 },
    Schedule { cron: String },
    Manual,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlaybookCondition {
    IpNotWhitelisted,
    NotInternalIp,
    AttackCountAbove { count: u32 },
    ThreatLevelAbove { level: ThreatLevel },
    TimeOfDay { start_hour: u8, end_hour: u8 },
    RiskScoreAbove { score: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlaybookAction {
    // Blocking
    Ban { duration_secs: Option<i64> },
    RateLimit { requests_per_minute: u32 },
    Tarpit,

    // Intelligence
    ProfileAttacker,
    GatherOsint,
    EnrichWithThreatIntel,

    // Deception
    RedirectToHoneypot { honeypot_port: u16 },
    ServeDecoyContent,

    // Alerting
    SendAlert { channels: Vec<String> },
    CreateIncident,
    EscalateToSoc,

    // External
    ReportToAbuseContact,
    SubmitToThreatIntel,
    BlockAtUpstream { provider: String },

    // Investigation
    CapturePackets { duration_secs: u64 },
    TakeSnapshot,

    // Custom
    RunScript { script: String },
    WebhookCall { url: String, method: String },
}

impl PlaybookEngine {
    /// Execute playbook for detection event
    pub async fn execute(
        &self,
        event: &DetectionEvent,
        context: &ExecutionContext,
    ) -> Result<PlaybookResult> {
        let mut results = Vec::new();

        for playbook in self.playbooks.values() {
            if !playbook.enabled {
                continue;
            }

            // Check triggers
            if !self.check_triggers(&playbook.triggers, event) {
                continue;
            }

            // Check conditions
            if !self.check_conditions(&playbook.conditions, event, context).await {
                continue;
            }

            // Execute actions
            for action in &playbook.actions {
                match self.execute_action(action, event, context).await {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        tracing::error!("Playbook action failed: {}", e);
                    }
                }
            }
        }

        Ok(PlaybookResult { actions_taken: results })
    }

    async fn execute_action(
        &self,
        action: &PlaybookAction,
        event: &DetectionEvent,
        context: &ExecutionContext,
    ) -> Result<ActionResult> {
        match action {
            PlaybookAction::Ban { duration_secs } => {
                context.firewall.ban(&event.src_ip, *duration_secs)?;
                Ok(ActionResult::Banned { ip: event.src_ip, duration: *duration_secs })
            }

            PlaybookAction::ProfileAttacker => {
                let profile = context.osint.profile_attacker(event.src_ip).await?;
                Ok(ActionResult::Profiled { profile })
            }

            PlaybookAction::RedirectToHoneypot { honeypot_port } => {
                context.firewall.redirect_to_honeypot(&event.src_ip, *honeypot_port)?;
                Ok(ActionResult::Redirected { port: *honeypot_port })
            }

            PlaybookAction::ReportToAbuseContact => {
                let report = self.generate_abuse_report(event, context).await?;
                self.send_abuse_report(&report).await?;
                Ok(ActionResult::Reported { contact: report.contact })
            }

            PlaybookAction::CapturePackets { duration_secs } => {
                let pcap_path = context.packet_capture
                    .start_capture(&event.src_ip, *duration_secs)
                    .await?;
                Ok(ActionResult::Captured { path: pcap_path })
            }

            // ... other actions
            _ => Ok(ActionResult::Skipped),
        }
    }
}

/// Default playbooks
pub fn default_playbooks() -> Vec<Playbook> {
    vec![
        // Brute force response
        Playbook {
            name: "brute_force_response".into(),
            description: "Auto-respond to brute force attacks".into(),
            triggers: vec![
                PlaybookTrigger::Detection {
                    detection_type: "brute_force".into(),
                    min_severity: Severity::Medium,
                },
            ],
            conditions: vec![
                PlaybookCondition::IpNotWhitelisted,
                PlaybookCondition::NotInternalIp,
            ],
            actions: vec![
                PlaybookAction::Ban { duration_secs: Some(3600) },
                PlaybookAction::ProfileAttacker,
                PlaybookAction::SendAlert { channels: vec!["slack".into()] },
            ],
            enabled: true,
        },

        // High-severity threat response
        Playbook {
            name: "critical_threat_response".into(),
            description: "Respond to critical threats".into(),
            triggers: vec![
                PlaybookTrigger::Detection {
                    detection_type: "*".into(),
                    min_severity: Severity::Critical,
                },
            ],
            conditions: vec![
                PlaybookCondition::IpNotWhitelisted,
            ],
            actions: vec![
                PlaybookAction::Ban { duration_secs: None }, // Permanent
                PlaybookAction::ProfileAttacker,
                PlaybookAction::GatherOsint,
                PlaybookAction::CapturePackets { duration_secs: 300 },
                PlaybookAction::CreateIncident,
                PlaybookAction::EscalateToSoc,
                PlaybookAction::ReportToAbuseContact,
            ],
            enabled: true,
        },

        // Scanner/probe response
        Playbook {
            name: "scanner_response".into(),
            description: "Respond to port scanners".into(),
            triggers: vec![
                PlaybookTrigger::Detection {
                    detection_type: "port_scan".into(),
                    min_severity: Severity::Low,
                },
            ],
            conditions: vec![
                PlaybookCondition::IpNotWhitelisted,
                PlaybookCondition::NotInternalIp,
            ],
            actions: vec![
                PlaybookAction::Tarpit,
                PlaybookAction::ProfileAttacker,
            ],
            enabled: true,
        },

        // Honeypot redirect
        Playbook {
            name: "honeypot_redirect".into(),
            description: "Redirect suspicious traffic to honeypot".into(),
            triggers: vec![
                PlaybookTrigger::Threshold {
                    metric: "failed_auth_count".into(),
                    value: 3.0,
                    window_secs: 60,
                },
            ],
            conditions: vec![
                PlaybookCondition::IpNotWhitelisted,
                PlaybookCondition::RiskScoreAbove { score: 0.5 },
            ],
            actions: vec![
                PlaybookAction::RedirectToHoneypot { honeypot_port: 2222 },
                PlaybookAction::ProfileAttacker,
            ],
            enabled: false, // Opt-in
        },
    ]
}
```

### Abuse Report Generator

```rust
// src/active_defense/response/takedown.rs

/// Abuse report generator
pub struct AbuseReporter {
    config: AbuseReportConfig,
    templates: HashMap<String, String>,
}

impl AbuseReporter {
    /// Generate abuse report for an attacker
    pub async fn generate_report(
        &self,
        profile: &AttackerProfile,
        events: &[DetectionEvent],
    ) -> Result<AbuseReport> {
        // Find abuse contact
        let contact = profile.network_info.abuse_contact.clone()
            .or_else(|| self.lookup_abuse_contact(&profile.network_info).await.ok())
            .ok_or_else(|| anyhow!("No abuse contact found"))?;

        // Compile evidence
        let evidence = self.compile_evidence(events);

        // Generate report body
        let body = self.render_template("abuse_report", &json!({
            "ip": profile.ip,
            "asn": profile.network_info.asn,
            "asn_name": profile.network_info.asn_name,
            "attack_count": events.len(),
            "first_attack": events.first().map(|e| e.timestamp),
            "last_attack": events.last().map(|e| e.timestamp),
            "attack_types": events.iter().map(|e| &e.event_type).collect::<HashSet<_>>(),
            "evidence": evidence,
            "reporter": self.config.reporter_info,
        }))?;

        Ok(AbuseReport {
            contact,
            subject: format!("Abuse Report: Malicious activity from {}", profile.ip),
            body,
            evidence,
            attachments: vec![],
        })
    }

    fn compile_evidence(&self, events: &[DetectionEvent]) -> Vec<EvidenceItem> {
        events.iter().map(|e| {
            EvidenceItem {
                timestamp: e.timestamp,
                event_type: e.event_type.to_string(),
                description: e.message.clone(),
                raw_data: e.details.get("raw").cloned(),
            }
        }).collect()
    }

    /// Send abuse report
    pub async fn send_report(&self, report: &AbuseReport) -> Result<()> {
        // Send via email
        let email = Message::builder()
            .from(self.config.from_address.parse()?)
            .to(report.contact.parse()?)
            .subject(&report.subject)
            .body(report.body.clone())?;

        self.mailer.send(&email).await?;

        // Log the report
        tracing::info!("Sent abuse report to {} for IP {}", report.contact, report.ip);

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AbuseReport {
    pub contact: String,
    pub subject: String,
    pub body: String,
    pub evidence: Vec<EvidenceItem>,
    pub attachments: Vec<PathBuf>,
}
```

## Configuration

```toml
# config.toml

[active_defense]
enabled = false                 # Explicit opt-in required

# IMPORTANT: Read and accept before enabling
legal_consent = false           # Must set to true after reading legal notice
legal_notice_accepted = ""      # Must contain hash of legal notice

[active_defense.profiler]
enabled = true

[active_defense.profiler.osint]
enabled = true
cache_ttl_hours = 24
# API keys for enhanced intelligence
abuseipdb_key = ""
virustotal_key = ""
shodan_key = ""
# Rate limiting
max_requests_per_minute = 30

[active_defense.profiler.recon]
# REQUIRES ADDITIONAL CONSENT
enabled = false
active_scanning = false         # Active port scanning
timeout_secs = 5
max_concurrent = 10

[active_defense.deception]
enabled = true

[active_defense.deception.honeypots]
enabled = true
[[active_defense.deception.honeypots.services]]
type = "ssh"
port = 2222
banner = "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2"
allow_login = true
capture_commands = true

[[active_defense.deception.honeypots.services]]
type = "http"
port = 8080
fake_cms = "wordpress"
fake_version = "5.4.2"

[[active_defense.deception.honeypots.services]]
type = "mysql"
port = 3307
fake_version = "5.7.30"

[active_defense.deception.honeytokens]
enabled = true
deploy_aws_creds = true
deploy_canary_docs = true
document_path = "/var/www/shared"
dns_canary_domain = "canary.your-domain.com"

[active_defense.deception.tarpit]
enabled = true
ports = [23, 3389, 5900]
byte_delay_ms = 1000
max_duration_secs = 3600
max_connections = 100

[active_defense.response]
enabled = true

[active_defense.response.playbooks]
enabled = true
playbook_dir = "/etc/crmonban/playbooks"

[active_defense.response.abuse_reports]
enabled = true
auto_report = false             # Manual review by default
from_address = "abuse@your-domain.com"
reporter_name = "Security Team"
reporter_contact = "security@your-domain.com"

[active_defense.response.upstream]
# Integration with upstream providers
cloudflare_enabled = false
cloudflare_api_key = ""
aws_waf_enabled = false
```

## CLI Commands

```bash
# Profile an attacker
crmonban profile 1.2.3.4
crmonban profile 1.2.3.4 --full       # Full OSINT

# Honeypot management
crmonban honeypot start
crmonban honeypot stop
crmonban honeypot status
crmonban honeypot interactions        # View captured data
crmonban honeypot interactions --ip 1.2.3.4

# Honeytoken management
crmonban honeytoken create aws --description "Breadcrumb creds"
crmonban honeytoken create dns --domain canary.example.com
crmonban honeytoken list
crmonban honeytoken alerts

# Playbook management
crmonban playbook list
crmonban playbook show brute_force_response
crmonban playbook enable scanner_response
crmonban playbook run critical_threat_response --ip 1.2.3.4

# Abuse reporting
crmonban report generate 1.2.3.4
crmonban report send 1.2.3.4 --review  # Review before sending

# Tarpit
crmonban tarpit start --ports 23,3389
crmonban tarpit status
crmonban tarpit connections
```

## Dependencies

```toml
[dependencies]
# Async networking
tokio = { version = "1", features = ["full"] }

# HTTP for honeypots
axum = "0.7"

# Email for abuse reports
lettre = "0.11"

# Templates
tera = "1"

# FFT for beaconing (reuse from ML)
rustfft = "6"

[features]
active-defense = ["lettre", "tera"]
honeypots = ["active-defense"]
active-recon = ["active-defense"]  # Separate feature for active scanning
```

## Estimated Effort

| Component | Files | Lines |
|-----------|-------|-------|
| OSINT Engine | 6 | 1,200 |
| Active Recon | 2 | 400 |
| Honeypot Manager | 6 | 1,500 |
| Honeytokens | 2 | 600 |
| Tarpit | 1 | 200 |
| Playbook Engine | 3 | 800 |
| Abuse Reporter | 2 | 400 |
| **Total** | **22** | **~5,100** |

## Security Considerations

1. **Legal compliance** - All active features require explicit consent
2. **Audit logging** - Every action is logged for legal defense
3. **Rate limiting** - Prevent abuse of reconnaissance features
4. **Isolation** - Honeypots run in isolated environments
5. **No hack-back** - System explicitly prevents offensive actions
6. **Review process** - Abuse reports require manual review by default

## Success Criteria

1. Profile attacker within 30 seconds
2. Capture 90%+ of credentials attempted on honeypots
3. Detect honeytoken access within 60 seconds
4. Tarpit holds connections for 10+ minutes
5. Generate legally-compliant abuse reports
6. Zero unauthorized offensive actions
