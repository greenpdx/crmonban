//! HTTP protocol state
//!
//! Per-flow state tracking for HTTP protocol analysis.

use std::any::Any;
use std::collections::HashMap;

use crate::protocols::ProtocolStateData;
use super::types::*;

/// Per-flow HTTP state
#[derive(Debug, Default)]
pub struct HttpState {
    /// HTTP version detected
    pub version: HttpVersion,

    /// Pending request (waiting for response)
    pub pending_request: Option<HttpRequest>,

    /// Completed transactions
    pub transactions: Vec<HttpTransaction>,

    /// Request count
    pub request_count: u32,

    /// Response count
    pub response_count: u32,

    /// Error count (4xx/5xx responses)
    pub error_count: u32,

    /// Last seen method
    pub last_method: Option<String>,

    /// Last seen URI
    pub last_uri: Option<String>,

    /// Last seen host
    pub last_host: Option<String>,

    /// Last seen user-agent
    pub last_user_agent: Option<String>,

    /// Last seen status code
    pub last_status: Option<u16>,

    /// Suspicious activity flags
    pub suspicious_uri: bool,
    pub suspicious_ua: bool,
    pub path_traversal: bool,
    pub sql_injection: bool,
    pub xss_detected: bool,

    /// Content types seen
    pub content_types: HashMap<String, u32>,

    /// Total bytes received
    pub bytes_received: u64,

    /// Total bytes sent
    pub bytes_sent: u64,
}

impl HttpState {
    /// Create new HTTP state
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a request
    pub fn record_request(&mut self, request: &HttpRequest) {
        self.request_count += 1;
        self.last_method = Some(request.method.clone());
        self.last_uri = Some(request.uri.clone());

        if let Some(ref host) = request.host {
            self.last_host = Some(host.clone());
        }

        if let Some(ref ua) = request.user_agent {
            self.last_user_agent = Some(ua.clone());
            self.check_suspicious_ua(ua);
        }

        // Check for suspicious patterns in URI
        self.check_suspicious_uri(&request.uri);
    }

    /// Record a response
    pub fn record_response(&mut self, response: &HttpResponse) {
        self.response_count += 1;
        self.last_status = Some(response.status_code);

        // Track errors
        if response.status_code >= 400 {
            self.error_count += 1;
        }

        // Track content types
        if let Some(ref ct) = response.content_type {
            *self.content_types.entry(ct.clone()).or_insert(0) += 1;
        }
    }

    /// Check for suspicious URI patterns
    fn check_suspicious_uri(&mut self, uri: &str) {
        let uri_lower = uri.to_lowercase();

        for pattern in SUSPICIOUS_URI_PATTERNS {
            if uri_lower.contains(&pattern.to_lowercase()) {
                self.suspicious_uri = true;

                // Specific attack categorization
                if pattern.contains("..") {
                    self.path_traversal = true;
                }
                if pattern.contains("'") || pattern.contains("UNION") || pattern.contains("1=1") {
                    self.sql_injection = true;
                }
                if pattern.contains("<script") || pattern.contains("javascript:") {
                    self.xss_detected = true;
                }

                break;
            }
        }
    }

    /// Check for suspicious User-Agent
    fn check_suspicious_ua(&mut self, ua: &str) {
        let ua_lower = ua.to_lowercase();

        for pattern in SUSPICIOUS_UA_PATTERNS {
            if ua_lower.contains(&pattern.to_lowercase()) {
                self.suspicious_ua = true;
                break;
            }
        }
    }

    /// Check if any suspicious activity detected
    pub fn has_suspicious_activity(&self) -> bool {
        self.suspicious_uri || self.suspicious_ua ||
        self.path_traversal || self.sql_injection || self.xss_detected
    }

    /// Get transaction count
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
}

impl ProtocolStateData for HttpState {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
