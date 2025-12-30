//! Log parsers for extracting ground truth from service logs
//!
//! Parses logs from sshd, nginx, postfix, and other services to extract
//! attack events that serve as ground truth for detection accuracy measurement.

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Service types supported by log parsers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Service {
    /// SSH daemon (auth.log)
    Sshd,
    /// Nginx access log
    NginxAccess,
    /// Nginx error log
    NginxError,
    /// Postfix mail server
    Postfix,
    /// Dovecot IMAP/POP3
    Dovecot,
    /// Custom service
    Custom,
}

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Service::Sshd => write!(f, "sshd"),
            Service::NginxAccess => write!(f, "nginx_access"),
            Service::NginxError => write!(f, "nginx_error"),
            Service::Postfix => write!(f, "postfix"),
            Service::Dovecot => write!(f, "dovecot"),
            Service::Custom => write!(f, "custom"),
        }
    }
}

/// Types of log events (attacks or normal traffic)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogEventType {
    // === SSH Events ===
    /// Failed password authentication
    FailedPassword { user: String },
    /// Invalid/unknown user
    InvalidUser { user: String },
    /// Connection closed before auth
    ConnectionClosedPreauth,
    /// Maximum authentication attempts exceeded
    MaxAuthAttempts { user: String },
    /// Connection reset during auth
    ConnectionReset,
    /// Bad protocol version
    BadProtocol,
    /// PAM authentication failure
    PamAuthFailure { user: String },
    /// Banner exchange failure (scanner)
    BannerExchange,

    // === HTTP Events ===
    /// SQL injection attempt
    SqlInjection { uri: String },
    /// Path traversal attempt
    PathTraversal { uri: String },
    /// Cross-site scripting attempt
    XssAttempt { uri: String },
    /// Command injection attempt
    CommandInjection { uri: String },
    /// Scanner/tool detected by user agent
    ScannerDetected { user_agent: String },
    /// Sensitive file probe (.env, .git, etc.)
    SensitiveFileProbe { path: String },
    /// Web shell access attempt
    WebShellAccess { path: String },
    /// WordPress/CMS probe
    CmsProbe { path: String },
    /// Rate limit exceeded (many requests)
    RateLimitExceeded { count: u32 },
    /// 4xx error burst
    ErrorBurst { status: u16, count: u32 },

    // === SMTP Events ===
    /// SMTP authentication failure
    SmtpAuthFailure { user: Option<String> },
    /// Relay access denied
    RelayDenied,
    /// Spam detected
    SpamDetected,

    // === Generic ===
    /// Normal/legitimate traffic
    Normal,
    /// Unknown event type
    Unknown { raw: String },
}

impl LogEventType {
    /// Returns true if this event type indicates an attack
    pub fn is_attack(&self) -> bool {
        !matches!(self, LogEventType::Normal | LogEventType::Unknown { .. })
    }

    /// Get the detection type this should map to in crmonban
    pub fn expected_detection_type(&self) -> Option<&'static str> {
        match self {
            // SSH brute force
            LogEventType::FailedPassword { .. }
            | LogEventType::InvalidUser { .. }
            | LogEventType::MaxAuthAttempts { .. }
            | LogEventType::PamAuthFailure { .. } => Some("brute_force"),

            // SSH exploit/scan
            LogEventType::BadProtocol
            | LogEventType::BannerExchange
            | LogEventType::ConnectionClosedPreauth
            | LogEventType::ConnectionReset => Some("scan"),

            // HTTP exploits
            LogEventType::SqlInjection { .. }
            | LogEventType::PathTraversal { .. }
            | LogEventType::XssAttempt { .. }
            | LogEventType::CommandInjection { .. }
            | LogEventType::WebShellAccess { .. } => Some("web_attack"),

            // HTTP scanning
            LogEventType::ScannerDetected { .. }
            | LogEventType::SensitiveFileProbe { .. }
            | LogEventType::CmsProbe { .. } => Some("scan"),

            // Rate limiting
            LogEventType::RateLimitExceeded { .. }
            | LogEventType::ErrorBurst { .. } => Some("dos"),

            // SMTP
            LogEventType::SmtpAuthFailure { .. } => Some("brute_force"),
            LogEventType::RelayDenied | LogEventType::SpamDetected => Some("spam"),

            // Normal/Unknown
            LogEventType::Normal | LogEventType::Unknown { .. } => None,
        }
    }

    /// Get severity score (0-10)
    pub fn severity(&self) -> u8 {
        match self {
            LogEventType::SqlInjection { .. }
            | LogEventType::CommandInjection { .. }
            | LogEventType::WebShellAccess { .. } => 9,

            LogEventType::PathTraversal { .. }
            | LogEventType::XssAttempt { .. } => 8,

            LogEventType::MaxAuthAttempts { .. }
            | LogEventType::RateLimitExceeded { .. } => 7,

            LogEventType::FailedPassword { .. }
            | LogEventType::InvalidUser { .. }
            | LogEventType::SmtpAuthFailure { .. } => 5,

            LogEventType::ScannerDetected { .. }
            | LogEventType::SensitiveFileProbe { .. }
            | LogEventType::CmsProbe { .. }
            | LogEventType::BadProtocol
            | LogEventType::BannerExchange => 4,

            LogEventType::ConnectionClosedPreauth
            | LogEventType::ConnectionReset
            | LogEventType::PamAuthFailure { .. }
            | LogEventType::ErrorBurst { .. } => 3,

            LogEventType::RelayDenied
            | LogEventType::SpamDetected => 2,

            LogEventType::Normal => 0,
            LogEventType::Unknown { .. } => 1,
        }
    }
}

/// A unified log event from any service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    /// Event timestamp
    pub timestamp: DateTime<Utc>,
    /// Source IP address
    pub src_ip: IpAddr,
    /// Service that logged this event
    pub service: Service,
    /// Type of event
    pub event_type: LogEventType,
    /// Additional details
    pub details: HashMap<String, String>,
    /// Raw log line
    pub raw_line: String,
}

impl LogEvent {
    /// Create a new log event
    pub fn new(
        timestamp: DateTime<Utc>,
        src_ip: IpAddr,
        service: Service,
        event_type: LogEventType,
        raw_line: String,
    ) -> Self {
        Self {
            timestamp,
            src_ip,
            service,
            event_type,
            details: HashMap::new(),
            raw_line,
        }
    }

    /// Add a detail key-value pair
    pub fn with_detail(mut self, key: &str, value: &str) -> Self {
        self.details.insert(key.to_string(), value.to_string());
        self
    }
}

/// Trait for log parsers
pub trait LogParser: Send + Sync {
    /// Parse a single log line, returning an event if it matches
    fn parse_line(&self, line: &str) -> Option<LogEvent>;

    /// Get the service type this parser handles
    fn service(&self) -> Service;

    /// Get the name of this parser
    fn name(&self) -> &'static str;
}

// =============================================================================
// SSHD Log Parser
// =============================================================================

/// Parser for sshd logs (typically from /var/log/auth.log)
pub struct SshdLogParser {
    patterns: Vec<SshdPattern>,
    timestamp_regex: Regex,
}

struct SshdPattern {
    name: &'static str,
    regex: Regex,
    event_type_fn: fn(&regex::Captures) -> LogEventType,
}

impl SshdLogParser {
    /// Create a new sshd log parser
    pub fn new() -> Self {
        let patterns = vec![
            SshdPattern {
                name: "failed_password",
                regex: Regex::new(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)").unwrap(),
                event_type_fn: |caps| LogEventType::FailedPassword {
                    user: caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(),
                },
            },
            SshdPattern {
                name: "invalid_user",
                regex: Regex::new(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)").unwrap(),
                event_type_fn: |caps| LogEventType::InvalidUser {
                    user: caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(),
                },
            },
            SshdPattern {
                name: "connection_closed_preauth",
                regex: Regex::new(r"Connection closed by (\d+\.\d+\.\d+\.\d+) port \d+ \[preauth\]").unwrap(),
                event_type_fn: |_| LogEventType::ConnectionClosedPreauth,
            },
            SshdPattern {
                name: "connection_reset",
                regex: Regex::new(r"Connection reset by (\d+\.\d+\.\d+\.\d+) port \d+ \[preauth\]").unwrap(),
                event_type_fn: |_| LogEventType::ConnectionReset,
            },
            SshdPattern {
                name: "max_auth_attempts",
                regex: Regex::new(r"(?:error: )?maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)").unwrap(),
                event_type_fn: |caps| LogEventType::MaxAuthAttempts {
                    user: caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(),
                },
            },
            SshdPattern {
                name: "too_many_auth_failures",
                regex: Regex::new(r"Disconnecting (?:authenticating )?user (\S+) (\d+\.\d+\.\d+\.\d+) .* Too many authentication failures").unwrap(),
                event_type_fn: |caps| LogEventType::MaxAuthAttempts {
                    user: caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(),
                },
            },
            SshdPattern {
                name: "bad_protocol",
                regex: Regex::new(r"Bad protocol version identification.*from (\d+\.\d+\.\d+\.\d+)").unwrap(),
                event_type_fn: |_| LogEventType::BadProtocol,
            },
            SshdPattern {
                name: "banner_exchange",
                regex: Regex::new(r"kex_exchange_identification: (?:banner exchange: )?Connection reset by (\d+\.\d+\.\d+\.\d+)").unwrap(),
                event_type_fn: |_| LogEventType::BannerExchange,
            },
            SshdPattern {
                name: "did_not_receive_ident",
                regex: Regex::new(r"Did not receive identification string from (\d+\.\d+\.\d+\.\d+)").unwrap(),
                event_type_fn: |_| LogEventType::BannerExchange,
            },
            SshdPattern {
                name: "pam_auth_failure",
                regex: Regex::new(r"pam_unix\(sshd:auth\): authentication failure.*ruser=(\S*) .*rhost=(\d+\.\d+\.\d+\.\d+)").unwrap(),
                event_type_fn: |caps| LogEventType::PamAuthFailure {
                    user: caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default(),
                },
            },
        ];

        // Syslog timestamp format: "Dec 30 14:23:45"
        let timestamp_regex = Regex::new(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})").unwrap();

        Self {
            patterns,
            timestamp_regex,
        }
    }

    /// Parse syslog timestamp
    fn parse_timestamp(&self, line: &str) -> Option<DateTime<Utc>> {
        if let Some(caps) = self.timestamp_regex.captures(line) {
            let ts_str = caps.get(1)?.as_str();
            // Add current year since syslog doesn't include it
            let year = Utc::now().year();
            let full_ts = format!("{} {}", year, ts_str);

            if let Ok(naive) = NaiveDateTime::parse_from_str(&full_ts, "%Y %b %d %H:%M:%S") {
                return Some(Utc.from_utc_datetime(&naive));
            }
        }
        None
    }

    /// Extract IP from captures based on pattern
    fn extract_ip(&self, caps: &regex::Captures, pattern_name: &str) -> Option<IpAddr> {
        // Most patterns have IP in capture group 2, some in group 1
        let ip_group = match pattern_name {
            "connection_closed_preauth" | "connection_reset" | "bad_protocol"
            | "banner_exchange" | "did_not_receive_ident" => 1,
            _ => 2,
        };

        caps.get(ip_group)
            .and_then(|m| IpAddr::from_str(m.as_str()).ok())
    }
}

impl Default for SshdLogParser {
    fn default() -> Self {
        Self::new()
    }
}

impl LogParser for SshdLogParser {
    fn parse_line(&self, line: &str) -> Option<LogEvent> {
        // Skip lines that don't contain sshd
        if !line.contains("sshd") {
            return None;
        }

        let timestamp = self.parse_timestamp(line).unwrap_or_else(Utc::now);

        for pattern in &self.patterns {
            if let Some(caps) = pattern.regex.captures(line) {
                if let Some(ip) = self.extract_ip(&caps, pattern.name) {
                    let event_type = (pattern.event_type_fn)(&caps);
                    return Some(LogEvent::new(
                        timestamp,
                        ip,
                        Service::Sshd,
                        event_type,
                        line.to_string(),
                    ).with_detail("pattern", pattern.name));
                }
            }
        }

        None
    }

    fn service(&self) -> Service {
        Service::Sshd
    }

    fn name(&self) -> &'static str {
        "sshd"
    }
}

// =============================================================================
// Nginx Access Log Parser
// =============================================================================

/// Parser for nginx access logs
pub struct NginxAccessParser {
    /// Combined log format regex
    log_regex: Regex,
    /// Attack patterns
    patterns: Vec<NginxPattern>,
}

struct NginxPattern {
    name: &'static str,
    regex: Regex,
    event_type_fn: fn(&str, &regex::Captures) -> LogEventType,
}

impl NginxAccessParser {
    /// Create a new nginx access log parser
    pub fn new() -> Self {
        // Combined log format: IP - user [timestamp] "METHOD URI PROTO" status size "referer" "user_agent"
        let log_regex = Regex::new(
            r#"^(\d+\.\d+\.\d+\.\d+) - \S+ \[([^\]]+)\] "([^"]*)" (\d+) \d+ "[^"]*" "([^"]*)""#
        ).unwrap();

        let patterns = vec![
            // SQL Injection
            NginxPattern {
                name: "sql_injection_union",
                regex: Regex::new(r"(?i)(union\s*(?:all\s*)?select|select\s.*from|insert\s+into|update\s+\S+\s+set|delete\s+from)").unwrap(),
                event_type_fn: |uri, _| LogEventType::SqlInjection { uri: uri.to_string() },
            },
            NginxPattern {
                name: "sql_injection_comment",
                regex: Regex::new(r"(?i)('--|#|/\*|\*/|;--)").unwrap(),
                event_type_fn: |uri, _| LogEventType::SqlInjection { uri: uri.to_string() },
            },
            NginxPattern {
                name: "sql_injection_or",
                regex: Regex::new(r"(?i)(\bor\b\s+\d+\s*=\s*\d+|\bor\b\s+'[^']*'\s*=\s*'[^']*')").unwrap(),
                event_type_fn: |uri, _| LogEventType::SqlInjection { uri: uri.to_string() },
            },
            // Path Traversal
            NginxPattern {
                name: "path_traversal",
                regex: Regex::new(r"(\.\.\/|\.\.%2[fF]|\.\.%252[fF]|%2e%2e%2f)").unwrap(),
                event_type_fn: |uri, _| LogEventType::PathTraversal { uri: uri.to_string() },
            },
            // XSS
            NginxPattern {
                name: "xss_script",
                regex: Regex::new(r"(?i)(<script|%3[cC]script|javascript:|on\w+\s*=)").unwrap(),
                event_type_fn: |uri, _| LogEventType::XssAttempt { uri: uri.to_string() },
            },
            // Command Injection
            NginxPattern {
                name: "cmd_injection",
                regex: Regex::new(r"(;cat\s|%7[cC]cat|`[^`]+`|\$\([^)]+\)|\|\s*\w+)").unwrap(),
                event_type_fn: |uri, _| LogEventType::CommandInjection { uri: uri.to_string() },
            },
            // Sensitive Files
            NginxPattern {
                name: "env_probe",
                regex: Regex::new(r"/\.env").unwrap(),
                event_type_fn: |_, _| LogEventType::SensitiveFileProbe { path: ".env".to_string() },
            },
            NginxPattern {
                name: "git_probe",
                regex: Regex::new(r"/\.git/").unwrap(),
                event_type_fn: |_, _| LogEventType::SensitiveFileProbe { path: ".git".to_string() },
            },
            NginxPattern {
                name: "aws_probe",
                regex: Regex::new(r"(\.aws/credentials|\.ssh/|id_rsa)").unwrap(),
                event_type_fn: |_, caps| LogEventType::SensitiveFileProbe {
                    path: caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default()
                },
            },
            // Web Shells
            NginxPattern {
                name: "shell_access",
                regex: Regex::new(r"(shell\.php|c99\.php|r57\.php|b374k|cmd\.php|eval-stdin\.php)").unwrap(),
                event_type_fn: |_, caps| LogEventType::WebShellAccess {
                    path: caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default()
                },
            },
            // CMS Probes
            NginxPattern {
                name: "wordpress_probe",
                regex: Regex::new(r"(wp-login\.php|xmlrpc\.php|wp-admin|wp-content/uploads)").unwrap(),
                event_type_fn: |_, caps| LogEventType::CmsProbe {
                    path: caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default()
                },
            },
            // Scanner detection by user agent
            NginxPattern {
                name: "scanner_uagent",
                regex: Regex::new(r"(?i)(nikto|sqlmap|nmap|masscan|zgrab|nessus|nuclei|wpscan|acunetix|burp)").unwrap(),
                event_type_fn: |_, caps| LogEventType::ScannerDetected {
                    user_agent: caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default()
                },
            },
            // phpinfo probe
            NginxPattern {
                name: "phpinfo_probe",
                regex: Regex::new(r"phpinfo").unwrap(),
                event_type_fn: |_, _| LogEventType::SensitiveFileProbe { path: "phpinfo".to_string() },
            },
        ];

        Self { log_regex, patterns }
    }

    /// Parse nginx timestamp format: "30/Dec/2024:14:23:45 +0000"
    fn parse_timestamp(&self, ts_str: &str) -> Option<DateTime<Utc>> {
        DateTime::parse_from_str(ts_str, "%d/%b/%Y:%H:%M:%S %z")
            .map(|dt| dt.with_timezone(&Utc))
            .ok()
    }
}

impl Default for NginxAccessParser {
    fn default() -> Self {
        Self::new()
    }
}

impl LogParser for NginxAccessParser {
    fn parse_line(&self, line: &str) -> Option<LogEvent> {
        let caps = self.log_regex.captures(line)?;

        let ip_str = caps.get(1)?.as_str();
        let ip = IpAddr::from_str(ip_str).ok()?;
        let ts_str = caps.get(2)?.as_str();
        let timestamp = self.parse_timestamp(ts_str).unwrap_or_else(Utc::now);
        let request = caps.get(3).map(|m| m.as_str()).unwrap_or("");
        let status: u16 = caps.get(4)?.as_str().parse().ok()?;
        let user_agent = caps.get(5).map(|m| m.as_str()).unwrap_or("");

        // Check each pattern against request and user_agent
        let full_text = format!("{} {}", request, user_agent);

        for pattern in &self.patterns {
            // For scanner detection, only check user_agent
            let text_to_check = if pattern.name == "scanner_uagent" {
                user_agent
            } else {
                &full_text
            };

            if let Some(pcaps) = pattern.regex.captures(text_to_check) {
                let event_type = (pattern.event_type_fn)(request, &pcaps);
                return Some(LogEvent::new(
                    timestamp,
                    ip,
                    Service::NginxAccess,
                    event_type,
                    line.to_string(),
                )
                .with_detail("pattern", pattern.name)
                .with_detail("status", &status.to_string())
                .with_detail("request", request));
            }
        }

        // Return Normal for 2xx/3xx, skip 4xx/5xx without attack patterns
        if status >= 200 && status < 400 {
            return Some(LogEvent::new(
                timestamp,
                ip,
                Service::NginxAccess,
                LogEventType::Normal,
                line.to_string(),
            ));
        }

        None
    }

    fn service(&self) -> Service {
        Service::NginxAccess
    }

    fn name(&self) -> &'static str {
        "nginx_access"
    }
}

// =============================================================================
// Nginx Error Log Parser
// =============================================================================

/// Parser for nginx error logs
pub struct NginxErrorParser {
    timestamp_regex: Regex,
    client_regex: Regex,
}

impl NginxErrorParser {
    /// Create a new nginx error log parser
    pub fn new() -> Self {
        // Error log format: "2024/12/30 14:23:45 [error] ... client: 1.2.3.4, ..."
        let timestamp_regex = Regex::new(r"^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})").unwrap();
        let client_regex = Regex::new(r"client:\s*(\d+\.\d+\.\d+\.\d+)").unwrap();

        Self {
            timestamp_regex,
            client_regex,
        }
    }

    fn parse_timestamp(&self, line: &str) -> Option<DateTime<Utc>> {
        if let Some(caps) = self.timestamp_regex.captures(line) {
            let ts_str = caps.get(1)?.as_str();
            if let Ok(naive) = NaiveDateTime::parse_from_str(ts_str, "%Y/%m/%d %H:%M:%S") {
                return Some(Utc.from_utc_datetime(&naive));
            }
        }
        None
    }
}

impl Default for NginxErrorParser {
    fn default() -> Self {
        Self::new()
    }
}

impl LogParser for NginxErrorParser {
    fn parse_line(&self, line: &str) -> Option<LogEvent> {
        // Extract client IP
        let ip_caps = self.client_regex.captures(line)?;
        let ip_str = ip_caps.get(1)?.as_str();
        let ip = IpAddr::from_str(ip_str).ok()?;

        let timestamp = self.parse_timestamp(line).unwrap_or_else(Utc::now);

        // Categorize based on error content
        let event_type = if line.contains("access forbidden") {
            LogEventType::SensitiveFileProbe { path: "forbidden".to_string() }
        } else if line.contains("directory index") {
            LogEventType::SensitiveFileProbe { path: "directory_listing".to_string() }
        } else {
            LogEventType::Unknown { raw: line.to_string() }
        };

        Some(LogEvent::new(
            timestamp,
            ip,
            Service::NginxError,
            event_type,
            line.to_string(),
        ))
    }

    fn service(&self) -> Service {
        Service::NginxError
    }

    fn name(&self) -> &'static str {
        "nginx_error"
    }
}

// =============================================================================
// Postfix Log Parser
// =============================================================================

/// Parser for Postfix mail logs (typically from /var/log/mail.log)
pub struct PostfixParser {
    timestamp_regex: Regex,
    sasl_auth_failed: Regex,
    relay_denied: Regex,
    client_regex: Regex,
}

impl PostfixParser {
    /// Create a new Postfix log parser
    pub fn new() -> Self {
        let timestamp_regex = Regex::new(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})").unwrap();
        let sasl_auth_failed = Regex::new(r"SASL (?:LOGIN|PLAIN) authentication failed").unwrap();
        let relay_denied = Regex::new(r"Relay access denied").unwrap();
        let client_regex = Regex::new(r"client=\S+\[(\d+\.\d+\.\d+\.\d+)\]").unwrap();

        Self {
            timestamp_regex,
            sasl_auth_failed,
            relay_denied,
            client_regex,
        }
    }

    fn parse_timestamp(&self, line: &str) -> Option<DateTime<Utc>> {
        if let Some(caps) = self.timestamp_regex.captures(line) {
            let ts_str = caps.get(1)?.as_str();
            let year = Utc::now().year();
            let full_ts = format!("{} {}", year, ts_str);

            if let Ok(naive) = NaiveDateTime::parse_from_str(&full_ts, "%Y %b %d %H:%M:%S") {
                return Some(Utc.from_utc_datetime(&naive));
            }
        }
        None
    }
}

impl Default for PostfixParser {
    fn default() -> Self {
        Self::new()
    }
}

impl LogParser for PostfixParser {
    fn parse_line(&self, line: &str) -> Option<LogEvent> {
        // Skip lines without postfix
        if !line.contains("postfix") {
            return None;
        }

        // Extract client IP
        let ip_caps = self.client_regex.captures(line)?;
        let ip_str = ip_caps.get(1)?.as_str();
        let ip = IpAddr::from_str(ip_str).ok()?;

        let timestamp = self.parse_timestamp(line).unwrap_or_else(Utc::now);

        let event_type = if self.sasl_auth_failed.is_match(line) {
            LogEventType::SmtpAuthFailure { user: None }
        } else if self.relay_denied.is_match(line) {
            LogEventType::RelayDenied
        } else {
            return None; // Skip non-attack lines
        };

        Some(LogEvent::new(
            timestamp,
            ip,
            Service::Postfix,
            event_type,
            line.to_string(),
        ))
    }

    fn service(&self) -> Service {
        Service::Postfix
    }

    fn name(&self) -> &'static str {
        "postfix"
    }
}

// =============================================================================
// Helper trait extension for Chrono
// =============================================================================

trait DateTimeExt {
    fn year(&self) -> i32;
}

impl DateTimeExt for DateTime<Utc> {
    fn year(&self) -> i32 {
        chrono::Datelike::year(self)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sshd_failed_password() {
        let parser = SshdLogParser::new();
        let line = "Dec 30 14:23:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2";

        let event = parser.parse_line(line).unwrap();
        assert_eq!(event.service, Service::Sshd);
        assert!(matches!(event.event_type, LogEventType::FailedPassword { user } if user == "root"));
        assert_eq!(event.src_ip.to_string(), "192.168.1.100");
    }

    #[test]
    fn test_sshd_invalid_user() {
        let parser = SshdLogParser::new();
        let line = "Dec 30 14:23:45 server sshd[1234]: Invalid user admin from 10.0.0.1 port 22";

        let event = parser.parse_line(line).unwrap();
        assert!(matches!(event.event_type, LogEventType::InvalidUser { user } if user == "admin"));
    }

    #[test]
    fn test_sshd_max_auth() {
        let parser = SshdLogParser::new();
        let line = "Dec 30 14:23:45 server sshd[1234]: error: maximum authentication attempts exceeded for root from 192.168.1.100 port 22 ssh2";

        let event = parser.parse_line(line).unwrap();
        assert!(matches!(event.event_type, LogEventType::MaxAuthAttempts { user } if user == "root"));
    }

    #[test]
    fn test_nginx_sql_injection() {
        let parser = NginxAccessParser::new();
        let line = r#"192.168.1.100 - - [30/Dec/2024:14:23:45 +0000] "GET /page?id=1 UNION SELECT * FROM users HTTP/1.1" 200 1234 "-" "Mozilla/5.0""#;

        let event = parser.parse_line(line).unwrap();
        assert_eq!(event.service, Service::NginxAccess);
        assert!(matches!(event.event_type, LogEventType::SqlInjection { .. }));
    }

    #[test]
    fn test_nginx_path_traversal() {
        let parser = NginxAccessParser::new();
        let line = r#"10.0.0.1 - - [30/Dec/2024:14:23:45 +0000] "GET /../../etc/passwd HTTP/1.1" 404 123 "-" "curl/7.68.0""#;

        let event = parser.parse_line(line).unwrap();
        assert!(matches!(event.event_type, LogEventType::PathTraversal { .. }));
    }

    #[test]
    fn test_nginx_scanner_detection() {
        let parser = NginxAccessParser::new();
        let line = r#"10.0.0.1 - - [30/Dec/2024:14:23:45 +0000] "GET / HTTP/1.1" 200 1234 "-" "nikto/2.1.6""#;

        let event = parser.parse_line(line).unwrap();
        assert!(matches!(event.event_type, LogEventType::ScannerDetected { user_agent } if user_agent.contains("nikto")));
    }

    #[test]
    fn test_nginx_normal_traffic() {
        let parser = NginxAccessParser::new();
        let line = r#"192.168.1.1 - - [30/Dec/2024:14:23:45 +0000] "GET /index.html HTTP/1.1" 200 5678 "-" "Mozilla/5.0""#;

        let event = parser.parse_line(line).unwrap();
        assert!(matches!(event.event_type, LogEventType::Normal));
    }

    #[test]
    fn test_postfix_auth_failure() {
        let parser = PostfixParser::new();
        let line = "Dec 30 14:23:45 mail postfix/smtpd[1234]: warning: unknown[192.168.1.100]: SASL LOGIN authentication failed: client=mail[192.168.1.100]";

        let event = parser.parse_line(line).unwrap();
        assert_eq!(event.service, Service::Postfix);
        assert!(matches!(event.event_type, LogEventType::SmtpAuthFailure { .. }));
    }

    #[test]
    fn test_event_type_severity() {
        assert_eq!(LogEventType::SqlInjection { uri: String::new() }.severity(), 9);
        assert_eq!(LogEventType::FailedPassword { user: String::new() }.severity(), 5);
        assert_eq!(LogEventType::Normal.severity(), 0);
    }

    #[test]
    fn test_expected_detection_type() {
        assert_eq!(
            LogEventType::FailedPassword { user: "root".to_string() }.expected_detection_type(),
            Some("brute_force")
        );
        assert_eq!(
            LogEventType::SqlInjection { uri: String::new() }.expected_detection_type(),
            Some("web_attack")
        );
        assert_eq!(LogEventType::Normal.expected_detection_type(), None);
    }
}
