//! Protocol type definitions
//!
//! Contains application layer protocol definitions used for protocol detection
//! and parsed protocol events passed between pipeline stages.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::packet::IpProtocol;

/// Application layer protocol (auto-detected or by port)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum AppProtocol {
    #[default]
    Unknown,
    Http,
    Https,
    Dns,
    Ssh,
    Ftp,
    FtpData,
    Smtp,
    Pop3,
    Imap,
    Smb,
    Mysql,
    Postgres,
    Redis,
    Mongodb,
    Ldap,
    Rdp,
    Vnc,
    Telnet,
    Sip,
    Ntp,
    Dhcp,
    Snmp,
}

impl AppProtocol {
    /// Guess protocol from well-known port
    pub fn from_port(port: u16, proto: IpProtocol) -> Self {
        match (proto, port) {
            (IpProtocol::Tcp, 80) => AppProtocol::Http,
            (IpProtocol::Tcp, 443) => AppProtocol::Https,
            (IpProtocol::Tcp, 8080) => AppProtocol::Http,
            (IpProtocol::Tcp, 8443) => AppProtocol::Https,
            (IpProtocol::Udp, 53) | (IpProtocol::Tcp, 53) => AppProtocol::Dns,
            (IpProtocol::Tcp, 22) => AppProtocol::Ssh,
            (IpProtocol::Tcp, 21) => AppProtocol::Ftp,
            (IpProtocol::Tcp, 20) => AppProtocol::FtpData,
            (IpProtocol::Tcp, 25) | (IpProtocol::Tcp, 587) | (IpProtocol::Tcp, 465) => AppProtocol::Smtp,
            (IpProtocol::Tcp, 110) | (IpProtocol::Tcp, 995) => AppProtocol::Pop3,
            (IpProtocol::Tcp, 143) | (IpProtocol::Tcp, 993) => AppProtocol::Imap,
            (IpProtocol::Tcp, 445) | (IpProtocol::Tcp, 139) => AppProtocol::Smb,
            (IpProtocol::Tcp, 3306) => AppProtocol::Mysql,
            (IpProtocol::Tcp, 5432) => AppProtocol::Postgres,
            (IpProtocol::Tcp, 6379) => AppProtocol::Redis,
            (IpProtocol::Tcp, 27017) => AppProtocol::Mongodb,
            (IpProtocol::Tcp, 389) | (IpProtocol::Tcp, 636) => AppProtocol::Ldap,
            (IpProtocol::Tcp, 3389) => AppProtocol::Rdp,
            (IpProtocol::Tcp, 5900..=5909) => AppProtocol::Vnc,
            (IpProtocol::Tcp, 23) => AppProtocol::Telnet,
            (IpProtocol::Udp, 5060) | (IpProtocol::Tcp, 5060) => AppProtocol::Sip,
            (IpProtocol::Udp, 123) => AppProtocol::Ntp,
            (IpProtocol::Udp, 67) | (IpProtocol::Udp, 68) => AppProtocol::Dhcp,
            (IpProtocol::Udp, 161) | (IpProtocol::Udp, 162) => AppProtocol::Snmp,
            _ => AppProtocol::Unknown,
        }
    }
}

impl std::fmt::Display for AppProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppProtocol::Unknown => write!(f, "unknown"),
            AppProtocol::Http => write!(f, "http"),
            AppProtocol::Https => write!(f, "https"),
            AppProtocol::Dns => write!(f, "dns"),
            AppProtocol::Ssh => write!(f, "ssh"),
            AppProtocol::Ftp => write!(f, "ftp"),
            AppProtocol::FtpData => write!(f, "ftp-data"),
            AppProtocol::Smtp => write!(f, "smtp"),
            AppProtocol::Pop3 => write!(f, "pop3"),
            AppProtocol::Imap => write!(f, "imap"),
            AppProtocol::Smb => write!(f, "smb"),
            AppProtocol::Mysql => write!(f, "mysql"),
            AppProtocol::Postgres => write!(f, "postgres"),
            AppProtocol::Redis => write!(f, "redis"),
            AppProtocol::Mongodb => write!(f, "mongodb"),
            AppProtocol::Ldap => write!(f, "ldap"),
            AppProtocol::Rdp => write!(f, "rdp"),
            AppProtocol::Vnc => write!(f, "vnc"),
            AppProtocol::Telnet => write!(f, "telnet"),
            AppProtocol::Sip => write!(f, "sip"),
            AppProtocol::Ntp => write!(f, "ntp"),
            AppProtocol::Dhcp => write!(f, "dhcp"),
            AppProtocol::Snmp => write!(f, "snmp"),
        }
    }
}

// ============================================================================
// Protocol Events - Parsed protocol data passed between pipeline stages
// ============================================================================

/// Events emitted by protocol analyzers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolEvent {
    /// HTTP transaction (request + optional response)
    Http(HttpTransaction),
    /// DNS message (query or response)
    Dns(DnsMessage),
    /// TLS handshake event
    Tls(TlsEvent),
    /// SSH protocol event
    Ssh(SshEvent),
    /// SMTP protocol event
    Smtp(SmtpEvent),
    /// Generic protocol event for extensibility
    Generic {
        protocol: String,
        event_type: String,
        data: serde_json::Value,
    },
}

/// HTTP transaction (request + response)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpTransaction {
    /// HTTP request (if seen)
    pub request: Option<HttpRequest>,
    /// HTTP response (if seen)
    pub response: Option<HttpResponse>,
    /// Request timestamp (millis since epoch)
    pub timestamp_request: Option<u64>,
    /// Response timestamp (millis since epoch)
    pub timestamp_response: Option<u64>,
}

/// HTTP request
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpRequest {
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// Request URI/path
    pub uri: String,
    /// HTTP version (1.0, 1.1, 2)
    pub version: String,
    /// Request headers
    pub headers: HashMap<String, String>,
    /// Host header value
    pub host: Option<String>,
    /// User-Agent header
    pub user_agent: Option<String>,
    /// Content-Type header
    pub content_type: Option<String>,
    /// Content-Length header
    pub content_length: Option<usize>,
    /// Cookie header
    pub cookie: Option<String>,
    /// Request body
    pub body: Vec<u8>,
}

/// HTTP response
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpResponse {
    /// HTTP version
    pub version: String,
    /// HTTP status code
    pub status_code: u16,
    /// Status message
    pub status_msg: String,
    /// Response headers
    pub headers: HashMap<String, String>,
    /// Content-Type header
    pub content_type: Option<String>,
    /// Content-Length header
    pub content_length: Option<usize>,
    /// Server header
    pub server: Option<String>,
    /// Response body
    pub body: Vec<u8>,
}

/// DNS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsRecordType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
    AAAA,
    SRV,
    ANY,
    Other(u16),
}

impl From<u16> for DnsRecordType {
    fn from(val: u16) -> Self {
        match val {
            1 => DnsRecordType::A,
            2 => DnsRecordType::NS,
            5 => DnsRecordType::CNAME,
            6 => DnsRecordType::SOA,
            12 => DnsRecordType::PTR,
            15 => DnsRecordType::MX,
            16 => DnsRecordType::TXT,
            28 => DnsRecordType::AAAA,
            33 => DnsRecordType::SRV,
            255 => DnsRecordType::ANY,
            other => DnsRecordType::Other(other),
        }
    }
}

impl std::fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsRecordType::A => write!(f, "A"),
            DnsRecordType::NS => write!(f, "NS"),
            DnsRecordType::CNAME => write!(f, "CNAME"),
            DnsRecordType::SOA => write!(f, "SOA"),
            DnsRecordType::PTR => write!(f, "PTR"),
            DnsRecordType::MX => write!(f, "MX"),
            DnsRecordType::TXT => write!(f, "TXT"),
            DnsRecordType::AAAA => write!(f, "AAAA"),
            DnsRecordType::SRV => write!(f, "SRV"),
            DnsRecordType::ANY => write!(f, "ANY"),
            DnsRecordType::Other(n) => write!(f, "TYPE{}", n),
        }
    }
}

/// DNS record data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DnsRdata {
    A(std::net::Ipv4Addr),
    AAAA(std::net::Ipv6Addr),
    CNAME(String),
    NS(String),
    PTR(String),
    MX { preference: u16, exchange: String },
    TXT(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Unknown(Vec<u8>),
}

/// DNS query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    /// Query name (domain)
    pub name: String,
    /// Query type
    pub qtype: DnsRecordType,
    /// Query class (usually IN = 1)
    pub qclass: u16,
}

/// DNS answer/resource record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    /// Answer name
    pub name: String,
    /// Record type
    pub rtype: DnsRecordType,
    /// Record class
    pub rclass: u16,
    /// TTL
    pub ttl: u32,
    /// Record data
    pub rdata: DnsRdata,
}

/// DNS message (query or response)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsMessage {
    /// Transaction ID
    pub id: u16,
    /// Is this a response?
    pub is_response: bool,
    /// Operation code
    pub opcode: u8,
    /// Authoritative answer
    pub authoritative: bool,
    /// Truncated
    pub truncated: bool,
    /// Recursion desired
    pub recursion_desired: bool,
    /// Recursion available
    pub recursion_available: bool,
    /// Response code
    pub rcode: u8,
    /// DNS queries
    pub queries: Vec<DnsQuery>,
    /// DNS answers
    pub answers: Vec<DnsAnswer>,
    /// Authority records
    pub authorities: Vec<DnsAnswer>,
    /// Additional records
    pub additionals: Vec<DnsAnswer>,
}

/// TLS-specific events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TlsEvent {
    /// Client Hello parsed
    ClientHello {
        /// Server Name Indication
        sni: Option<String>,
        /// JA3 fingerprint
        ja3: Ja3Fingerprint,
        /// Supported TLS versions
        versions: Vec<u16>,
        /// Offered cipher suites
        cipher_suites: Vec<u16>,
    },
    /// Server Hello parsed
    ServerHello {
        /// JA3S fingerprint
        ja3s: Ja3Fingerprint,
        /// Selected TLS version
        version: u16,
        /// Selected cipher suite
        cipher_suite: u16,
    },
    /// Certificate received
    Certificate {
        /// Certificate subject
        subject: String,
        /// Certificate issuer
        issuer: String,
        /// Serial number
        serial: String,
        /// Not valid before
        not_before: String,
        /// Not valid after
        not_after: String,
        /// SHA256 fingerprint
        fingerprint_sha256: String,
    },
    /// Handshake complete
    HandshakeComplete {
        /// Negotiated TLS version string
        version: String,
        /// Negotiated cipher suite name
        cipher_suite: String,
    },
}

/// JA3/JA3S fingerprint for TLS client/server identification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ja3Fingerprint {
    /// JA3 string (before hashing)
    pub string: String,
    /// MD5 hash of the JA3 string
    pub hash: String,
}

impl Ja3Fingerprint {
    /// Create a new JA3 fingerprint
    pub fn new(string: String, hash: String) -> Self {
        Self { string, hash }
    }
}

// ============================================================================
// SSH Protocol Events
// ============================================================================

/// SSH protocol events for security analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SshEvent {
    /// Version exchange (first phase of SSH handshake)
    VersionExchange {
        /// Client SSH version string (e.g., "SSH-2.0-OpenSSH_8.9p1")
        client_version: String,
        /// Server SSH version string (if seen)
        server_version: Option<String>,
        /// Parsed SSH protocol version (1 or 2)
        protocol_version: u8,
    },
    /// Key exchange initialization (contains HASSH data)
    KeyExchangeInit {
        /// HASSH fingerprint for client identification
        hassh: HasshFingerprint,
        /// Key exchange algorithms offered
        kex_algorithms: Vec<String>,
        /// Host key algorithms
        host_key_algorithms: Vec<String>,
        /// Encryption algorithms (client to server)
        encryption_c2s: Vec<String>,
        /// Encryption algorithms (server to client)
        encryption_s2c: Vec<String>,
        /// MAC algorithms (client to server)
        mac_c2s: Vec<String>,
        /// MAC algorithms (server to client)
        mac_s2c: Vec<String>,
        /// Compression algorithms
        compression: Vec<String>,
    },
    /// Server key exchange init response
    ServerKexInit {
        /// HASSH server fingerprint
        hassh_server: HasshFingerprint,
        /// Selected algorithms after negotiation
        selected_algorithms: Option<SshNegotiatedAlgorithms>,
    },
    /// Authentication attempt
    AuthAttempt {
        /// Username being authenticated
        username: String,
        /// Authentication method used
        method: SshAuthMethod,
        /// Whether this attempt succeeded
        success: bool,
        /// Attempt number for this session
        attempt_number: u32,
    },
    /// New channel opened
    ChannelOpen {
        /// Channel type (session, x11, forwarded-tcpip, etc.)
        channel_type: String,
        /// Channel ID
        channel_id: u32,
    },
    /// Channel request (exec, shell, subsystem, etc.)
    ChannelRequest {
        /// Request type
        request_type: String,
        /// Command if exec
        command: Option<String>,
        /// Subsystem if subsystem request
        subsystem: Option<String>,
    },
}

/// HASSH fingerprint (like JA3 but for SSH)
/// Based on: https://github.com/salesforce/hassh
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HasshFingerprint {
    /// HASSH string (kex;enc;mac;cmp)
    pub string: String,
    /// MD5 hash of the HASSH string
    pub hash: String,
    /// Whether this is client (hassh) or server (hassh-server)
    pub is_server: bool,
}

impl HasshFingerprint {
    /// Create a new HASSH fingerprint
    pub fn new(string: String, hash: String, is_server: bool) -> Self {
        Self { string, hash, is_server }
    }

    /// Compute HASSH from algorithm lists
    pub fn compute(
        kex_algorithms: &[String],
        encryption: &[String],
        mac: &[String],
        compression: &[String],
        is_server: bool,
    ) -> Self {
        let string = format!(
            "{};{};{};{}",
            kex_algorithms.join(","),
            encryption.join(","),
            mac.join(","),
            compression.join(",")
        );
        let hash = format!("{:x}", md5::compute(&string));
        Self { string, hash, is_server }
    }
}

/// Negotiated SSH algorithms after key exchange
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshNegotiatedAlgorithms {
    /// Selected key exchange algorithm
    pub kex: String,
    /// Selected host key algorithm
    pub host_key: String,
    /// Selected encryption algorithm (client to server)
    pub encryption_c2s: String,
    /// Selected encryption algorithm (server to client)
    pub encryption_s2c: String,
    /// Selected MAC algorithm (client to server)
    pub mac_c2s: String,
    /// Selected MAC algorithm (server to client)
    pub mac_s2c: String,
    /// Selected compression algorithm
    pub compression: String,
}

/// SSH authentication methods
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SshAuthMethod {
    /// Password authentication
    Password,
    /// Public key authentication
    PublicKey,
    /// Keyboard-interactive (challenge-response)
    KeyboardInteractive,
    /// Host-based authentication
    HostBased,
    /// GSSAPI (Kerberos)
    GssApi,
    /// No authentication (none)
    None,
    /// Unknown method
    Unknown(String),
}

impl std::fmt::Display for SshAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshAuthMethod::Password => write!(f, "password"),
            SshAuthMethod::PublicKey => write!(f, "publickey"),
            SshAuthMethod::KeyboardInteractive => write!(f, "keyboard-interactive"),
            SshAuthMethod::HostBased => write!(f, "hostbased"),
            SshAuthMethod::GssApi => write!(f, "gssapi"),
            SshAuthMethod::None => write!(f, "none"),
            SshAuthMethod::Unknown(s) => write!(f, "{}", s),
        }
    }
}

/// SSH version information parsed from version string
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshVersionInfo {
    /// Protocol version (1 or 2)
    pub protocol_version: u8,
    /// Software version string (e.g., "OpenSSH_8.9p1")
    pub software: String,
    /// Comments (optional, after software)
    pub comments: Option<String>,
    /// Detected OS/platform from version string
    pub detected_os: Option<String>,
    /// Known vulnerable (from CVE database)
    pub is_vulnerable: bool,
    /// Associated CVEs if vulnerable
    pub cves: Vec<String>,
}

impl SshVersionInfo {
    /// Parse SSH version string (e.g., "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
    pub fn parse(version_string: &str) -> Option<Self> {
        let parts: Vec<&str> = version_string.splitn(3, '-').collect();
        if parts.len() < 3 || parts[0] != "SSH" {
            return None;
        }

        let protocol_version = match parts[1] {
            "1.0" | "1.5" | "1.99" => 1,
            "2.0" => 2,
            _ => return None,
        };

        let remainder = parts[2];
        let (software, comments) = if let Some(idx) = remainder.find(' ') {
            (remainder[..idx].to_string(), Some(remainder[idx+1..].to_string()))
        } else {
            (remainder.to_string(), None)
        };

        // Try to detect OS from comments
        let detected_os = comments.as_ref().and_then(|c| {
            let lower = c.to_lowercase();
            if lower.contains("ubuntu") {
                Some("Ubuntu".to_string())
            } else if lower.contains("debian") {
                Some("Debian".to_string())
            } else if lower.contains("rhel") || lower.contains("redhat") {
                Some("RHEL".to_string())
            } else if lower.contains("centos") {
                Some("CentOS".to_string())
            } else if lower.contains("freebsd") {
                Some("FreeBSD".to_string())
            } else {
                None
            }
        });

        Some(Self {
            protocol_version,
            software,
            comments,
            detected_os,
            is_vulnerable: false,
            cves: Vec::new(),
        })
    }
}

// ============================================================================
// SMTP Protocol Events
// ============================================================================

/// SMTP protocol events for email security analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SmtpEvent {
    /// SMTP connection established (EHLO/HELO)
    Connect {
        /// Client greeting (HELO/EHLO hostname)
        client_hostname: String,
        /// Server greeting response
        server_banner: Option<String>,
        /// Extended SMTP capabilities (EHLO)
        capabilities: Vec<String>,
        /// Is ESMTP (EHLO vs HELO)
        is_esmtp: bool,
    },
    /// Authentication attempt
    Auth {
        /// Authentication mechanism (PLAIN, LOGIN, CRAM-MD5, etc.)
        mechanism: SmtpAuthMechanism,
        /// Username (if extractable)
        username: Option<String>,
        /// Success or failure
        success: bool,
    },
    /// STARTTLS negotiation
    StartTls {
        /// Was STARTTLS successful
        success: bool,
    },
    /// Mail transaction (MAIL FROM + RCPT TO + DATA)
    MailTransaction(SmtpTransaction),
    /// SMTP error/rejection
    Error {
        /// SMTP response code
        code: u16,
        /// Error message
        message: String,
        /// Command that caused error
        command: Option<String>,
    },
}

/// SMTP authentication mechanisms
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SmtpAuthMechanism {
    /// PLAIN authentication (base64 encoded)
    Plain,
    /// LOGIN authentication (separate username/password)
    Login,
    /// CRAM-MD5 challenge-response
    CramMd5,
    /// DIGEST-MD5
    DigestMd5,
    /// NTLM authentication
    Ntlm,
    /// GSSAPI/Kerberos
    GssApi,
    /// OAuth 2.0
    XOAuth2,
    /// Unknown mechanism
    Unknown(String),
}

impl std::fmt::Display for SmtpAuthMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmtpAuthMechanism::Plain => write!(f, "PLAIN"),
            SmtpAuthMechanism::Login => write!(f, "LOGIN"),
            SmtpAuthMechanism::CramMd5 => write!(f, "CRAM-MD5"),
            SmtpAuthMechanism::DigestMd5 => write!(f, "DIGEST-MD5"),
            SmtpAuthMechanism::Ntlm => write!(f, "NTLM"),
            SmtpAuthMechanism::GssApi => write!(f, "GSSAPI"),
            SmtpAuthMechanism::XOAuth2 => write!(f, "XOAUTH2"),
            SmtpAuthMechanism::Unknown(s) => write!(f, "{}", s),
        }
    }
}

/// SMTP mail transaction (envelope + headers)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmtpTransaction {
    /// Envelope sender (MAIL FROM)
    pub mail_from: String,
    /// Envelope recipients (RCPT TO)
    pub rcpt_to: Vec<String>,
    /// Number of recipients
    pub recipient_count: usize,
    /// Parsed email headers
    pub headers: SmtpHeaders,
    /// Message size in bytes
    pub message_size: Option<usize>,
    /// Has attachment(s)
    pub has_attachments: bool,
    /// Attachment info
    pub attachments: Vec<SmtpAttachment>,
    /// SMTP transaction timestamp
    pub timestamp: Option<u64>,
    /// Was rejected by server
    pub rejected: bool,
    /// Rejection reason if rejected
    pub rejection_reason: Option<String>,
}

/// Parsed SMTP email headers
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmtpHeaders {
    /// From header
    pub from: Option<String>,
    /// To header
    pub to: Vec<String>,
    /// Cc header
    pub cc: Vec<String>,
    /// Subject
    pub subject: Option<String>,
    /// Message-ID
    pub message_id: Option<String>,
    /// Date header
    pub date: Option<String>,
    /// Reply-To header
    pub reply_to: Option<String>,
    /// Return-Path
    pub return_path: Option<String>,
    /// X-Mailer or User-Agent
    pub mailer: Option<String>,
    /// Received headers (for hop analysis)
    pub received: Vec<String>,
    /// Content-Type
    pub content_type: Option<String>,
    /// DKIM-Signature present
    pub has_dkim: bool,
    /// SPF result (if visible in headers)
    pub spf_result: Option<String>,
    /// DMARC result (if visible)
    pub dmarc_result: Option<String>,
    /// All headers as key-value pairs
    pub all_headers: HashMap<String, String>,
}

/// Email attachment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpAttachment {
    /// Filename
    pub filename: String,
    /// Content-Type
    pub content_type: String,
    /// Size in bytes
    pub size: usize,
    /// File extension
    pub extension: Option<String>,
    /// Is potentially dangerous extension
    pub is_dangerous: bool,
    /// Content hash (if computed)
    pub hash: Option<String>,
}

impl SmtpAttachment {
    /// Check if the attachment has a dangerous file extension
    pub fn check_dangerous_extension(filename: &str) -> bool {
        let dangerous_extensions = [
            "exe", "bat", "cmd", "com", "pif", "scr", "vbs", "vbe", "js", "jse",
            "ws", "wsf", "wsc", "wsh", "ps1", "psm1", "psd1", "msi", "msp", "mst",
            "jar", "hta", "cpl", "msc", "inf", "reg", "dll", "ocx", "sys", "drv",
            "iso", "img", "vhd", "vhdx",  // Disk images
            "docm", "xlsm", "pptm", "xlam", "ppam", "potm", // Macro-enabled Office
            "lnk", "url", "scf",  // Shortcut files
            "ace", "arj", "cab", "chm", "gadget",
        ];

        if let Some(ext) = filename.rsplit('.').next() {
            dangerous_extensions.contains(&ext.to_lowercase().as_str())
        } else {
            false
        }
    }
}

/// Email address parsing result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAddress {
    /// Display name (if present)
    pub display_name: Option<String>,
    /// Local part (before @)
    pub local_part: String,
    /// Domain part (after @)
    pub domain: String,
    /// Full address
    pub full_address: String,
}

impl EmailAddress {
    /// Parse an email address from a string
    /// Handles formats like: "Name <email@domain.com>" or "email@domain.com"
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();

        // Check for "Display Name <email>" format
        if let Some(start) = s.find('<') {
            if let Some(end) = s.find('>') {
                let display_name = if start > 0 {
                    Some(s[..start].trim().trim_matches('"').to_string())
                } else {
                    None
                };
                let email = &s[start + 1..end];
                return Self::parse_bare_address(email, display_name);
            }
        }

        // Bare email address
        Self::parse_bare_address(s, None)
    }

    fn parse_bare_address(email: &str, display_name: Option<String>) -> Option<Self> {
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return None;
        }

        let local_part = parts[0].to_string();
        let domain = parts[1].to_string();

        if local_part.is_empty() || domain.is_empty() {
            return None;
        }

        Some(Self {
            display_name,
            local_part,
            domain,
            full_address: email.to_string(),
        })
    }

    /// Check if the domain looks suspicious (newly registered, typosquat, etc.)
    pub fn is_suspicious_domain(&self) -> bool {
        let domain = self.domain.to_lowercase();

        // Check for common typosquatting patterns
        let legitimate_domains = [
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
            "icloud.com", "protonmail.com", "mail.com",
        ];

        // Check for similar-looking domains (simple Levenshtein-like check)
        for legit in &legitimate_domains {
            if domain != *legit && Self::is_similar(&domain, legit) {
                return true;
            }
        }

        // Check for suspicious TLDs commonly used in phishing
        let suspicious_tlds = [".xyz", ".top", ".click", ".link", ".work", ".date", ".racing"];
        for tld in &suspicious_tlds {
            if domain.ends_with(tld) {
                return true;
            }
        }

        false
    }

    /// Simple similarity check for typosquatting detection
    fn is_similar(a: &str, b: &str) -> bool {
        if a == b {
            return false;
        }

        let a_chars: Vec<char> = a.chars().collect();
        let b_chars: Vec<char> = b.chars().collect();

        // Length difference of more than 2 = not similar
        if (a_chars.len() as i32 - b_chars.len() as i32).abs() > 2 {
            return false;
        }

        // Count differences
        let mut diffs = 0;
        let min_len = a_chars.len().min(b_chars.len());
        for i in 0..min_len {
            if a_chars[i] != b_chars[i] {
                diffs += 1;
            }
        }
        diffs += (a_chars.len() as i32 - b_chars.len() as i32).unsigned_abs() as usize;

        // Similar if 1-2 character difference
        diffs > 0 && diffs <= 2
    }
}

/// Known spam/phishing patterns
pub mod spam_patterns {
    /// Common spam subject patterns (case-insensitive)
    pub const SPAM_SUBJECT_PATTERNS: &[&str] = &[
        "you have won", "congratulations", "claim your prize",
        "urgent action required", "verify your account",
        "suspended account", "unusual activity",
        "bitcoin", "cryptocurrency", "investment opportunity",
        "make money fast", "work from home",
        "weight loss", "viagra", "cialis",
        "nigerian prince", "inheritance",
        "re: your payment", "invoice attached",
        "click here", "act now", "limited time",
    ];

    /// Phishing subject patterns
    pub const PHISHING_SUBJECT_PATTERNS: &[&str] = &[
        "password reset", "password expir",
        "security alert", "security notice",
        "verify your identity", "confirm your account",
        "unusual sign-in", "suspicious activity",
        "your account has been", "account locked",
        "action required", "immediate action",
        "apple id", "paypal", "amazon order",
        "tax refund", "irs notice",
    ];

    /// Check if subject matches spam patterns
    pub fn is_spam_subject(subject: &str) -> bool {
        let lower = subject.to_lowercase();
        SPAM_SUBJECT_PATTERNS.iter().any(|p| lower.contains(p))
    }

    /// Check if subject matches phishing patterns
    pub fn is_phishing_subject(subject: &str) -> bool {
        let lower = subject.to_lowercase();
        PHISHING_SUBJECT_PATTERNS.iter().any(|p| lower.contains(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_protocol_from_port() {
        assert_eq!(AppProtocol::from_port(80, IpProtocol::Tcp), AppProtocol::Http);
        assert_eq!(AppProtocol::from_port(443, IpProtocol::Tcp), AppProtocol::Https);
        assert_eq!(AppProtocol::from_port(53, IpProtocol::Udp), AppProtocol::Dns);
        assert_eq!(AppProtocol::from_port(22, IpProtocol::Tcp), AppProtocol::Ssh);
        assert_eq!(AppProtocol::from_port(12345, IpProtocol::Tcp), AppProtocol::Unknown);
    }

    #[test]
    fn test_app_protocol_display() {
        assert_eq!(format!("{}", AppProtocol::Http), "http");
        assert_eq!(format!("{}", AppProtocol::Https), "https");
        assert_eq!(format!("{}", AppProtocol::Unknown), "unknown");
    }

    #[test]
    fn test_app_protocol_default() {
        assert_eq!(AppProtocol::default(), AppProtocol::Unknown);
    }

    #[test]
    fn test_ssh_version_parse() {
        let info = SshVersionInfo::parse("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1").unwrap();
        assert_eq!(info.protocol_version, 2);
        assert_eq!(info.software, "OpenSSH_8.9p1");
        assert_eq!(info.detected_os, Some("Ubuntu".to_string()));

        let info = SshVersionInfo::parse("SSH-2.0-dropbear_2022.83").unwrap();
        assert_eq!(info.protocol_version, 2);
        assert_eq!(info.software, "dropbear_2022.83");
        assert!(info.comments.is_none());

        let info = SshVersionInfo::parse("SSH-1.99-OpenSSH_3.9p1");
        assert!(info.is_some());
        assert_eq!(info.unwrap().protocol_version, 1);

        // Invalid formats
        assert!(SshVersionInfo::parse("invalid").is_none());
        assert!(SshVersionInfo::parse("SSH-3.0-test").is_none());
    }

    #[test]
    fn test_hassh_compute() {
        let hassh = HasshFingerprint::compute(
            &["curve25519-sha256".to_string()],
            &["aes256-gcm@openssh.com".to_string()],
            &["hmac-sha2-256".to_string()],
            &["none".to_string()],
            false,
        );
        assert!(!hassh.hash.is_empty());
        assert_eq!(hassh.string, "curve25519-sha256;aes256-gcm@openssh.com;hmac-sha2-256;none");
        assert!(!hassh.is_server);
    }

    #[test]
    fn test_ssh_auth_method_display() {
        assert_eq!(format!("{}", SshAuthMethod::Password), "password");
        assert_eq!(format!("{}", SshAuthMethod::PublicKey), "publickey");
        assert_eq!(format!("{}", SshAuthMethod::Unknown("custom".into())), "custom");
    }

    #[test]
    fn test_email_address_parse() {
        // Simple email
        let addr = EmailAddress::parse("test@example.com").unwrap();
        assert_eq!(addr.local_part, "test");
        assert_eq!(addr.domain, "example.com");
        assert!(addr.display_name.is_none());

        // With display name
        let addr = EmailAddress::parse("John Doe <john@example.com>").unwrap();
        assert_eq!(addr.local_part, "john");
        assert_eq!(addr.domain, "example.com");
        assert_eq!(addr.display_name, Some("John Doe".to_string()));

        // With quoted display name
        let addr = EmailAddress::parse("\"Jane Doe\" <jane@example.com>").unwrap();
        assert_eq!(addr.display_name, Some("Jane Doe".to_string()));

        // Invalid
        assert!(EmailAddress::parse("invalid").is_none());
        assert!(EmailAddress::parse("@nodomain.com").is_none());
    }

    #[test]
    fn test_suspicious_domain() {
        // Typosquatting
        let addr = EmailAddress::parse("user@gmai1.com").unwrap();
        assert!(addr.is_suspicious_domain());

        let addr = EmailAddress::parse("user@gmial.com").unwrap();
        assert!(addr.is_suspicious_domain());

        // Suspicious TLD
        let addr = EmailAddress::parse("user@company.xyz").unwrap();
        assert!(addr.is_suspicious_domain());

        // Legitimate
        let addr = EmailAddress::parse("user@gmail.com").unwrap();
        assert!(!addr.is_suspicious_domain());
    }

    #[test]
    fn test_dangerous_attachment() {
        assert!(SmtpAttachment::check_dangerous_extension("malware.exe"));
        assert!(SmtpAttachment::check_dangerous_extension("script.ps1"));
        assert!(SmtpAttachment::check_dangerous_extension("macro.docm"));
        assert!(!SmtpAttachment::check_dangerous_extension("document.pdf"));
        assert!(!SmtpAttachment::check_dangerous_extension("image.png"));
    }

    #[test]
    fn test_spam_patterns() {
        use spam_patterns::*;

        assert!(is_spam_subject("You have won a prize!"));
        assert!(is_spam_subject("URGENT ACTION REQUIRED"));
        assert!(!is_spam_subject("Meeting tomorrow at 3pm"));

        assert!(is_phishing_subject("Password reset required"));
        assert!(is_phishing_subject("Your Apple ID has been locked"));
        assert!(!is_phishing_subject("Weekly status update"));
    }

    #[test]
    fn test_smtp_auth_mechanism_display() {
        assert_eq!(format!("{}", SmtpAuthMechanism::Plain), "PLAIN");
        assert_eq!(format!("{}", SmtpAuthMechanism::CramMd5), "CRAM-MD5");
        assert_eq!(format!("{}", SmtpAuthMechanism::Unknown("CUSTOM".into())), "CUSTOM");
    }
}
