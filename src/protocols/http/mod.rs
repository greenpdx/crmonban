//! HTTP protocol analyzer
//!
//! Parses HTTP/1.x requests and responses.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::core::{Flow, Direction, Packet};
use super::{HttpConfig, ProtocolAnalyzer, ProtocolEvent};

/// HTTP request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
    pub cookie: Option<String>,
    pub body: Vec<u8>,
}

impl Default for HttpRequest {
    fn default() -> Self {
        Self {
            method: String::new(),
            uri: String::new(),
            version: String::new(),
            headers: HashMap::new(),
            host: None,
            user_agent: None,
            content_type: None,
            content_length: None,
            cookie: None,
            body: Vec::new(),
        }
    }
}

/// HTTP response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub status_msg: String,
    pub headers: HashMap<String, String>,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
    pub server: Option<String>,
    pub body: Vec<u8>,
}

impl Default for HttpResponse {
    fn default() -> Self {
        Self {
            version: String::new(),
            status_code: 0,
            status_msg: String::new(),
            headers: HashMap::new(),
            content_type: None,
            content_length: None,
            server: None,
            body: Vec::new(),
        }
    }
}

/// HTTP transaction (request + response)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTransaction {
    pub request: Option<HttpRequest>,
    pub response: Option<HttpResponse>,
    pub timestamp_request: Option<u64>,
    pub timestamp_response: Option<u64>,
}

impl Default for HttpTransaction {
    fn default() -> Self {
        Self {
            request: None,
            response: None,
            timestamp_request: None,
            timestamp_response: None,
        }
    }
}

/// HTTP protocol analyzer
pub struct HttpAnalyzer {
    config: HttpConfig,
}

impl HttpAnalyzer {
    pub fn new(config: HttpConfig) -> Self {
        Self { config }
    }

    /// Parse HTTP request from payload
    pub fn parse_request(&self, payload: &[u8]) -> Option<HttpRequest> {
        let text = std::str::from_utf8(payload).ok()?;
        let mut lines = text.lines();

        // Parse request line
        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_string();
        let uri = parts.next()?.to_string();
        let version = parts.next().unwrap_or("HTTP/1.0").to_string();

        // Validate method
        let valid_methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"];
        if !valid_methods.contains(&method.as_str()) {
            return None;
        }

        let mut request = HttpRequest {
            method,
            uri,
            version,
            ..Default::default()
        };

        // Parse headers
        let mut body_start = None;
        for (i, line) in text.lines().enumerate() {
            if line.is_empty() {
                body_start = Some(i + 1);
                break;
            }

            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim().to_lowercase();
                let value = value.trim().to_string();

                match name.as_str() {
                    "host" => request.host = Some(value.clone()),
                    "user-agent" => request.user_agent = Some(value.clone()),
                    "content-type" => request.content_type = Some(value.clone()),
                    "content-length" => request.content_length = value.parse().ok(),
                    "cookie" => request.cookie = Some(value.clone()),
                    _ => {}
                }

                if self.config.extract_headers {
                    request.headers.insert(name, value);
                }
            }
        }

        // Extract body if present
        if let Some(start) = body_start {
            let body_text: String = text.lines().skip(start).collect::<Vec<_>>().join("\n");
            let max_body = self.config.max_request_body;
            request.body = body_text.as_bytes()[..body_text.len().min(max_body)].to_vec();
        }

        Some(request)
    }

    /// Parse HTTP response from payload
    pub fn parse_response(&self, payload: &[u8]) -> Option<HttpResponse> {
        let text = std::str::from_utf8(payload).ok()?;
        let mut lines = text.lines();

        // Parse status line
        let status_line = lines.next()?;
        let mut parts = status_line.splitn(3, ' ');
        let version = parts.next()?.to_string();
        let status_code: u16 = parts.next()?.parse().ok()?;
        let status_msg = parts.next().unwrap_or("").to_string();

        // Validate version
        if !version.starts_with("HTTP/") {
            return None;
        }

        let mut response = HttpResponse {
            version,
            status_code,
            status_msg,
            ..Default::default()
        };

        // Parse headers
        let mut body_start = None;
        for (i, line) in text.lines().enumerate() {
            if line.is_empty() {
                body_start = Some(i + 1);
                break;
            }

            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim().to_lowercase();
                let value = value.trim().to_string();

                match name.as_str() {
                    "content-type" => response.content_type = Some(value.clone()),
                    "content-length" => response.content_length = value.parse().ok(),
                    "server" => response.server = Some(value.clone()),
                    _ => {}
                }

                response.headers.insert(name, value);
            }
        }

        // Extract body if present
        if let Some(start) = body_start {
            let body_text: String = text.lines().skip(start).collect::<Vec<_>>().join("\n");
            let max_body = self.config.max_response_body;
            response.body = body_text.as_bytes()[..body_text.len().min(max_body)].to_vec();
        }

        Some(response)
    }

    /// Check if payload starts with HTTP request
    fn is_http_request(&self, payload: &[u8]) -> bool {
        if payload.len() < 4 {
            return false;
        }

        let methods = [
            b"GET ".as_slice(),
            b"POST".as_slice(),
            b"PUT ".as_slice(),
            b"DELE".as_slice(),
            b"HEAD".as_slice(),
            b"OPTI".as_slice(),
            b"PATC".as_slice(),
            b"CONN".as_slice(),
            b"TRAC".as_slice(),
        ];

        methods.iter().any(|m| payload.starts_with(m))
    }

    /// Check if payload starts with HTTP response
    fn is_http_response(&self, payload: &[u8]) -> bool {
        payload.starts_with(b"HTTP/")
    }
}

impl ProtocolAnalyzer for HttpAnalyzer {
    fn name(&self) -> &'static str {
        "http"
    }

    fn detect(&self, payload: &[u8], port: u16) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Check by port
        if self.config.ports.contains(&port) {
            return true;
        }

        // Check by content
        self.is_http_request(payload) || self.is_http_response(payload)
    }

    fn parse(&self, packet: &Packet, flow: &mut Flow) -> Option<ProtocolEvent> {
        if !self.config.enabled || packet.payload().is_empty() {
            return None;
        }

        let payload = &packet.payload();

        // Determine if request or response based on direction and content
        let transaction = match packet.direction {
            Direction::ToServer => {
                if self.is_http_request(payload) {
                    if let Some(request) = self.parse_request(payload) {
                        // Store in flow for correlation
                        if let Some(host) = &request.host {
                            flow.set_app_data("http.host", serde_json::json!(host));
                        }
                        if let Some(ua) = &request.user_agent {
                            flow.set_app_data("http.user_agent", serde_json::json!(ua));
                        }
                        flow.set_app_data("http.method", serde_json::json!(&request.method));
                        flow.set_app_data("http.uri", serde_json::json!(&request.uri));

                        HttpTransaction {
                            request: Some(request),
                            response: None,
                            timestamp_request: Some(
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis() as u64
                            ),
                            timestamp_response: None,
                        }
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            Direction::ToClient => {
                if self.is_http_response(payload) {
                    if let Some(response) = self.parse_response(payload) {
                        flow.set_app_data("http.status_code", serde_json::json!(response.status_code));
                        if let Some(server) = &response.server {
                            flow.set_app_data("http.server", serde_json::json!(server));
                        }

                        HttpTransaction {
                            request: None,
                            response: Some(response),
                            timestamp_request: None,
                            timestamp_response: Some(
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_millis() as u64
                            ),
                        }
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
            Direction::Unknown => {
                // Try to auto-detect
                if self.is_http_request(payload) {
                    if let Some(request) = self.parse_request(payload) {
                        HttpTransaction {
                            request: Some(request),
                            ..Default::default()
                        }
                    } else {
                        return None;
                    }
                } else if self.is_http_response(payload) {
                    if let Some(response) = self.parse_response(payload) {
                        HttpTransaction {
                            response: Some(response),
                            ..Default::default()
                        }
                    } else {
                        return None;
                    }
                } else {
                    return None;
                }
            }
        };

        Some(ProtocolEvent::Http(transaction))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request() {
        let config = HttpConfig::default();
        let analyzer = HttpAnalyzer::new(config);

        let request = b"GET /index.html HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        User-Agent: Mozilla/5.0\r\n\
                        \r\n";

        let parsed = analyzer.parse_request(request).unwrap();

        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.uri, "/index.html");
        assert_eq!(parsed.host, Some("example.com".to_string()));
        assert!(parsed.user_agent.is_some());
    }

    #[test]
    fn test_parse_response() {
        let config = HttpConfig::default();
        let analyzer = HttpAnalyzer::new(config);

        let response = b"HTTP/1.1 200 OK\r\n\
                         Content-Type: text/html\r\n\
                         Content-Length: 13\r\n\
                         Server: nginx\r\n\
                         \r\n\
                         Hello, World!";

        let parsed = analyzer.parse_response(response).unwrap();

        assert_eq!(parsed.status_code, 200);
        assert_eq!(parsed.status_msg, "OK");
        assert_eq!(parsed.server, Some("nginx".to_string()));
    }

    #[test]
    fn test_detect_http() {
        let config = HttpConfig::default();
        let analyzer = HttpAnalyzer::new(config);

        assert!(analyzer.detect(b"GET / HTTP/1.1", 80));
        assert!(analyzer.detect(b"POST /api", 8080));
        assert!(analyzer.detect(b"HTTP/1.1 200 OK", 80));
        assert!(!analyzer.detect(b"random data", 12345));
    }
}
