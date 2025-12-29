//! HTTP protocol types
//!
//! Local types for HTTP parsing and detection. Re-exports common types from crmonban-types.

pub use crate::types::{HttpRequest, HttpResponse, HttpTransaction};

/// HTTP Suricata keywords supported
pub const HTTP_KEYWORDS: &[&str] = &[
    "http.uri",
    "http.uri.raw",
    "http.method",
    "http.request_line",
    "http.request_body",
    "http.header",
    "http.header.raw",
    "http.cookie",
    "http.user_agent",
    "http.host",
    "http.host.raw",
    "http.accept",
    "http.accept_lang",
    "http.accept_enc",
    "http.referer",
    "http.connection",
    "http.content_type",
    "http.content_len",
    "http.protocol",
    "http.start",
    "http.response_line",
    "http.response_body",
    "http.stat_code",
    "http.stat_msg",
    "http.server",
    "http.location",
    "file.data",
];

/// HTTP methods
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
    Connect,
    Trace,
    Unknown,
}

impl From<&str> for HttpMethod {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "PATCH" => Self::Patch,
            "CONNECT" => Self::Connect,
            "TRACE" => Self::Trace,
            _ => Self::Unknown,
        }
    }
}

/// HTTP version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpVersion {
    #[default]
    Http10,
    Http11,
    Http20,
    Http30,
    Unknown,
}

impl From<&str> for HttpVersion {
    fn from(s: &str) -> Self {
        match s {
            "HTTP/1.0" => Self::Http10,
            "HTTP/1.1" => Self::Http11,
            "HTTP/2" | "HTTP/2.0" => Self::Http20,
            "HTTP/3" | "HTTP/3.0" => Self::Http30,
            _ => Self::Unknown,
        }
    }
}

/// Suspicious patterns for HTTP detection
pub const SUSPICIOUS_URI_PATTERNS: &[&str] = &[
    // Path traversal
    "../",
    "..\\",
    // SQL injection indicators
    "' OR",
    "' AND",
    "UNION SELECT",
    "1=1",
    // Command injection
    "; ls",
    "| cat",
    "$(",
    // XXE
    "<!ENTITY",
    // SSRF
    "localhost",
    "127.0.0.1",
    "169.254.",
    // Common exploit paths
    "/wp-admin",
    "/phpmyadmin",
    "/admin",
    "/.env",
    "/.git",
    "/actuator",
    "/solr",
    "/console",
    "/manager",
];

/// Suspicious User-Agent patterns
pub const SUSPICIOUS_UA_PATTERNS: &[&str] = &[
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "burp",
    "curl",
    "wget",
    "python-requests",
    "go-http",
    "scanner",
    "bot",
    "crawl",
];
