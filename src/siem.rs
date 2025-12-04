//! SIEM export module
//!
//! Provides multiple output formats for Security Information and Event Management systems:
//! - CEF (Common Event Format)
//! - LEEF (Log Event Extended Format)
//! - Syslog (RFC 5424)
//! - JSON
//!
//! Supports multiple output targets:
//! - File
//! - Syslog
//! - HTTP/HTTPS webhook
//! - Unix socket

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::models::{AttackEvent, AttackEventType, Ban, BanSource};

/// SIEM export format
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SiemFormat {
    /// Common Event Format (ArcSight)
    CEF,
    /// Log Event Extended Format (IBM QRadar)
    LEEF,
    /// RFC 5424 Syslog
    Syslog,
    /// Plain JSON
    #[default]
    JSON,
}

/// SIEM output target
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SiemTarget {
    /// Write to file
    File { path: PathBuf },
    /// Send to syslog
    Syslog {
        #[serde(default = "default_syslog_socket")]
        socket: String,
    },
    /// Send to HTTP webhook
    Webhook {
        url: String,
        #[serde(default)]
        headers: Vec<(String, String)>,
    },
    /// Write to Unix socket
    UnixSocket { path: PathBuf },
    /// Write to stdout (for debugging)
    Stdout,
}

fn default_syslog_socket() -> String {
    "/dev/log".to_string()
}

/// SIEM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    /// Enable SIEM export
    #[serde(default)]
    pub enabled: bool,

    /// Output format
    #[serde(default)]
    pub format: SiemFormat,

    /// Output targets
    #[serde(default)]
    pub targets: Vec<SiemTarget>,

    /// Device vendor (for CEF/LEEF)
    #[serde(default = "default_vendor")]
    pub vendor: String,

    /// Device product (for CEF/LEEF)
    #[serde(default = "default_product")]
    pub product: String,

    /// Device version (for CEF/LEEF)
    #[serde(default = "default_version")]
    pub version: String,

    /// Batch events before sending (0 = no batching)
    #[serde(default)]
    pub batch_size: usize,

    /// Flush interval in seconds (0 = immediate)
    #[serde(default)]
    pub flush_interval_secs: u64,
}

fn default_vendor() -> String {
    "crmonban".to_string()
}

fn default_product() -> String {
    "IPS".to_string()
}

fn default_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            format: SiemFormat::JSON,
            targets: vec![],
            vendor: default_vendor(),
            product: default_product(),
            version: default_version(),
            batch_size: 0,
            flush_interval_secs: 0,
        }
    }
}

/// Severity level for SIEM events
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Debug = 0,
    Info = 1,
    Low = 2,
    Medium = 5,
    High = 7,
    Critical = 10,
}

impl Severity {
    pub fn as_cef(&self) -> u8 {
        match self {
            Severity::Debug => 0,
            Severity::Info => 1,
            Severity::Low => 3,
            Severity::Medium => 5,
            Severity::High => 7,
            Severity::Critical => 10,
        }
    }

    pub fn as_syslog(&self) -> u8 {
        // Syslog severity (0=emergency, 7=debug)
        match self {
            Severity::Critical => 2,  // critical
            Severity::High => 3,      // error
            Severity::Medium => 4,    // warning
            Severity::Low => 5,       // notice
            Severity::Info => 6,      // informational
            Severity::Debug => 7,     // debug
        }
    }
}

/// SIEM event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_class", rename_all = "snake_case")]
pub enum SiemEvent {
    /// IP was banned
    BanAdded {
        ip: IpAddr,
        reason: String,
        source: String,
        duration_secs: Option<i64>,
        zone: Option<String>,
        #[serde(flatten)]
        common: CommonFields,
    },

    /// IP was unbanned
    BanRemoved {
        ip: IpAddr,
        reason: String,
        #[serde(flatten)]
        common: CommonFields,
    },

    /// Attack detected
    AttackDetected {
        ip: IpAddr,
        service: String,
        event_type: String,
        details: Option<String>,
        #[serde(flatten)]
        common: CommonFields,
    },

    /// Daemon started
    DaemonStarted {
        #[serde(flatten)]
        common: CommonFields,
    },

    /// Daemon stopped
    DaemonStopped {
        #[serde(flatten)]
        common: CommonFields,
    },
}

/// Common fields for all SIEM events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonFields {
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub hostname: String,
    pub event_id: String,
}

impl CommonFields {
    pub fn new(severity: Severity) -> Self {
        Self {
            timestamp: Utc::now(),
            severity,
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            event_id: uuid::Uuid::new_v4().to_string(),
        }
    }
}

/// SIEM exporter
pub struct SiemExporter {
    config: SiemConfig,
    event_buffer: Arc<RwLock<Vec<SiemEvent>>>,
    http_client: Option<reqwest::Client>,
}

impl SiemExporter {
    /// Create a new SIEM exporter
    pub fn new(config: SiemConfig) -> Self {
        let http_client = if config.targets.iter().any(|t| matches!(t, SiemTarget::Webhook { .. })) {
            Some(reqwest::Client::new())
        } else {
            None
        };

        Self {
            config,
            event_buffer: Arc::new(RwLock::new(Vec::new())),
            http_client,
        }
    }

    /// Check if SIEM export is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !self.config.targets.is_empty()
    }

    /// Export a ban event
    pub async fn export_ban(&self, ban: &Ban, zone: Option<&str>) {
        if !self.is_enabled() {
            return;
        }

        let event = SiemEvent::BanAdded {
            ip: ban.ip,
            reason: ban.reason.clone(),
            source: ban.source.to_string(),
            duration_secs: ban.expires_at.map(|e| (e - ban.created_at).num_seconds()),
            zone: zone.map(String::from),
            common: CommonFields::new(Severity::High),
        };

        self.export_event(event).await;
    }

    /// Export an unban event
    pub async fn export_unban(&self, ip: IpAddr, reason: &str) {
        if !self.is_enabled() {
            return;
        }

        let event = SiemEvent::BanRemoved {
            ip,
            reason: reason.to_string(),
            common: CommonFields::new(Severity::Info),
        };

        self.export_event(event).await;
    }

    /// Export an attack event
    pub async fn export_attack(&self, attack: &AttackEvent) {
        if !self.is_enabled() {
            return;
        }

        let severity = match attack.event_type {
            AttackEventType::BruteForce | AttackEventType::Exploit => Severity::High,
            AttackEventType::PortScan => Severity::Medium,
            AttackEventType::FailedAuth | AttackEventType::InvalidUser => Severity::Low,
            AttackEventType::RateLimit => Severity::Medium,
            AttackEventType::Other(_) => Severity::Low,
        };

        let event = SiemEvent::AttackDetected {
            ip: attack.ip,
            service: attack.service.clone(),
            event_type: attack.event_type.to_string(),
            details: attack.details.clone(),
            common: CommonFields::new(severity),
        };

        self.export_event(event).await;
    }

    /// Export daemon started event
    pub async fn export_daemon_started(&self) {
        if !self.is_enabled() {
            return;
        }

        let event = SiemEvent::DaemonStarted {
            common: CommonFields::new(Severity::Info),
        };

        self.export_event(event).await;
    }

    /// Export daemon stopped event
    pub async fn export_daemon_stopped(&self) {
        if !self.is_enabled() {
            return;
        }

        let event = SiemEvent::DaemonStopped {
            common: CommonFields::new(Severity::Info),
        };

        self.export_event(event).await;
    }

    /// Export a single event
    async fn export_event(&self, event: SiemEvent) {
        if self.config.batch_size > 0 {
            let mut buffer = self.event_buffer.write().await;
            buffer.push(event);

            if buffer.len() >= self.config.batch_size {
                let events: Vec<_> = buffer.drain(..).collect();
                drop(buffer);
                self.flush_events(&events).await;
            }
        } else {
            self.flush_events(&[event]).await;
        }
    }

    /// Flush buffered events
    pub async fn flush(&self) {
        let mut buffer = self.event_buffer.write().await;
        if buffer.is_empty() {
            return;
        }

        let events: Vec<_> = buffer.drain(..).collect();
        drop(buffer);
        self.flush_events(&events).await;
    }

    /// Send events to all targets
    async fn flush_events(&self, events: &[SiemEvent]) {
        for target in &self.config.targets {
            for event in events {
                let formatted = self.format_event(event);

                match target {
                    SiemTarget::File { path } => {
                        if let Err(e) = self.write_to_file(path, &formatted).await {
                            error!("Failed to write SIEM event to file: {}", e);
                        }
                    }
                    SiemTarget::Syslog { socket } => {
                        if let Err(e) = self.write_to_syslog(socket, event, &formatted).await {
                            error!("Failed to write SIEM event to syslog: {}", e);
                        }
                    }
                    SiemTarget::Webhook { url, headers } => {
                        if let Err(e) = self.send_to_webhook(url, headers, &formatted).await {
                            error!("Failed to send SIEM event to webhook: {}", e);
                        }
                    }
                    SiemTarget::UnixSocket { path } => {
                        if let Err(e) = self.write_to_unix_socket(path, &formatted).await {
                            error!("Failed to write SIEM event to unix socket: {}", e);
                        }
                    }
                    SiemTarget::Stdout => {
                        println!("{}", formatted);
                    }
                }
            }
        }
    }

    /// Format an event according to the configured format
    fn format_event(&self, event: &SiemEvent) -> String {
        match self.config.format {
            SiemFormat::CEF => self.format_cef(event),
            SiemFormat::LEEF => self.format_leef(event),
            SiemFormat::Syslog => self.format_syslog(event),
            SiemFormat::JSON => self.format_json(event),
        }
    }

    /// Format event as CEF
    fn format_cef(&self, event: &SiemEvent) -> String {
        let (name, severity, extension) = match event {
            SiemEvent::BanAdded { ip, reason, source, duration_secs, zone, common } => {
                let ext = format!(
                    "src={} reason={} source={} duration={} zone={} eventId={}",
                    ip,
                    self.cef_escape(reason),
                    source,
                    duration_secs.unwrap_or(0),
                    zone.as_deref().unwrap_or("none"),
                    common.event_id
                );
                ("IP Banned", common.severity.as_cef(), ext)
            }
            SiemEvent::BanRemoved { ip, reason, common } => {
                let ext = format!(
                    "src={} reason={} eventId={}",
                    ip,
                    self.cef_escape(reason),
                    common.event_id
                );
                ("IP Unbanned", common.severity.as_cef(), ext)
            }
            SiemEvent::AttackDetected { ip, service, event_type, details, common } => {
                let ext = format!(
                    "src={} service={} attackType={} details={} eventId={}",
                    ip,
                    service,
                    event_type,
                    self.cef_escape(details.as_deref().unwrap_or("")),
                    common.event_id
                );
                ("Attack Detected", common.severity.as_cef(), ext)
            }
            SiemEvent::DaemonStarted { common } => {
                let ext = format!("eventId={}", common.event_id);
                ("Daemon Started", common.severity.as_cef(), ext)
            }
            SiemEvent::DaemonStopped { common } => {
                let ext = format!("eventId={}", common.event_id);
                ("Daemon Stopped", common.severity.as_cef(), ext)
            }
        };

        format!(
            "CEF:0|{}|{}|{}|100|{}|{}|{}",
            self.config.vendor,
            self.config.product,
            self.config.version,
            name,
            severity,
            extension
        )
    }

    /// Format event as LEEF
    fn format_leef(&self, event: &SiemEvent) -> String {
        let (event_id, attrs) = match event {
            SiemEvent::BanAdded { ip, reason, source, duration_secs, zone, common } => {
                let attrs = format!(
                    "src={}\treason={}\tsource={}\tduration={}\tzone={}\teventId={}",
                    ip,
                    reason,
                    source,
                    duration_secs.unwrap_or(0),
                    zone.as_deref().unwrap_or("none"),
                    common.event_id
                );
                ("BanAdded", attrs)
            }
            SiemEvent::BanRemoved { ip, reason, common } => {
                let attrs = format!("src={}\treason={}\teventId={}", ip, reason, common.event_id);
                ("BanRemoved", attrs)
            }
            SiemEvent::AttackDetected { ip, service, event_type, details, common } => {
                let attrs = format!(
                    "src={}\tservice={}\tattackType={}\tdetails={}\teventId={}",
                    ip,
                    service,
                    event_type,
                    details.as_deref().unwrap_or(""),
                    common.event_id
                );
                ("AttackDetected", attrs)
            }
            SiemEvent::DaemonStarted { common } => {
                ("DaemonStarted", format!("eventId={}", common.event_id))
            }
            SiemEvent::DaemonStopped { common } => {
                ("DaemonStopped", format!("eventId={}", common.event_id))
            }
        };

        format!(
            "LEEF:2.0|{}|{}|{}|{}|{}",
            self.config.vendor, self.config.product, self.config.version, event_id, attrs
        )
    }

    /// Format event as syslog (RFC 5424)
    fn format_syslog(&self, event: &SiemEvent) -> String {
        let common = match event {
            SiemEvent::BanAdded { common, .. }
            | SiemEvent::BanRemoved { common, .. }
            | SiemEvent::AttackDetected { common, .. }
            | SiemEvent::DaemonStarted { common }
            | SiemEvent::DaemonStopped { common } => common,
        };

        let facility = 4; // security/authorization
        let severity = common.severity.as_syslog();
        let pri = facility * 8 + severity;

        let timestamp = common.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ");
        let msg = self.format_json(event);

        format!(
            "<{}>{} {} {} {} {} - - {}",
            pri,
            1, // version
            timestamp,
            common.hostname,
            self.config.product,
            std::process::id(),
            msg
        )
    }

    /// Format event as JSON
    fn format_json(&self, event: &SiemEvent) -> String {
        serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string())
    }

    /// Escape special characters for CEF
    fn cef_escape(&self, s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('=', "\\=")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }

    /// Write to file
    async fn write_to_file(&self, path: &PathBuf, content: &str) -> std::io::Result<()> {
        use tokio::fs::OpenOptions;
        use tokio::io::AsyncWriteExt;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await?;

        file.write_all(content.as_bytes()).await?;
        file.write_all(b"\n").await?;

        Ok(())
    }

    /// Write to syslog
    async fn write_to_syslog(
        &self,
        socket: &str,
        event: &SiemEvent,
        formatted: &str,
    ) -> std::io::Result<()> {
        use tokio::net::UnixDatagram;

        let sock = UnixDatagram::unbound()?;
        sock.send_to(formatted.as_bytes(), socket).await?;

        Ok(())
    }

    /// Send to HTTP webhook
    async fn send_to_webhook(
        &self,
        url: &str,
        headers: &[(String, String)],
        content: &str,
    ) -> anyhow::Result<()> {
        let client = self.http_client.as_ref().ok_or_else(|| {
            anyhow::anyhow!("HTTP client not initialized")
        })?;

        let mut req = client.post(url).body(content.to_string());

        for (key, value) in headers {
            req = req.header(key.as_str(), value.as_str());
        }

        req = req.header("Content-Type", "application/json");

        let resp = req.send().await?;

        if !resp.status().is_success() {
            warn!("Webhook returned non-success status: {}", resp.status());
        }

        Ok(())
    }

    /// Write to Unix socket
    async fn write_to_unix_socket(&self, path: &PathBuf, content: &str) -> std::io::Result<()> {
        use tokio::net::UnixStream;
        use tokio::io::AsyncWriteExt;

        let mut stream = UnixStream::connect(path).await?;
        stream.write_all(content.as_bytes()).await?;
        stream.write_all(b"\n").await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_levels() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert_eq!(Severity::Critical.as_cef(), 10);
        assert_eq!(Severity::Critical.as_syslog(), 2);
    }

    #[test]
    fn test_cef_format() {
        let config = SiemConfig {
            enabled: true,
            format: SiemFormat::CEF,
            targets: vec![],
            ..Default::default()
        };

        let exporter = SiemExporter::new(config);

        let event = SiemEvent::BanAdded {
            ip: "192.168.1.1".parse().unwrap(),
            reason: "Test ban".to_string(),
            source: "manual".to_string(),
            duration_secs: Some(3600),
            zone: Some("external".to_string()),
            common: CommonFields::new(Severity::High),
        };

        let formatted = exporter.format_cef(&event);
        assert!(formatted.starts_with("CEF:0|crmonban|IPS|"));
        assert!(formatted.contains("IP Banned"));
        assert!(formatted.contains("src=192.168.1.1"));
    }

    #[test]
    fn test_json_format() {
        let config = SiemConfig::default();
        let exporter = SiemExporter::new(config);

        let event = SiemEvent::AttackDetected {
            ip: "10.0.0.1".parse().unwrap(),
            service: "ssh".to_string(),
            event_type: "failed_auth".to_string(),
            details: Some("Failed password".to_string()),
            common: CommonFields::new(Severity::Low),
        };

        let formatted = exporter.format_json(&event);
        assert!(formatted.contains("AttackDetected") || formatted.contains("attack_detected"));
        assert!(formatted.contains("10.0.0.1"));
    }
}
