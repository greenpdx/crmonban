//! HTTP protocol parser
//!
//! Parses HTTP/1.x requests and responses.

use async_trait::async_trait;

use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{
    ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction,
    ProtocolRuleSet,
};
use super::types::*;
use super::state::HttpState;
use super::match_::HttpMatcher;

/// HTTP config
#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub extract_headers: bool,
    pub max_request_body: usize,
    pub max_response_body: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![80, 8080, 8000, 8008, 8888, 3000],
            extract_headers: true,
            max_request_body: 65536,
            max_response_body: 65536,
        }
    }
}

/// HTTP Protocol Parser
pub struct HttpParser {
    config: HttpConfig,
    matcher: HttpMatcher,
}

impl HttpParser {
    /// Create new HTTP parser
    pub fn new() -> Self {
        Self {
            config: HttpConfig::default(),
            matcher: HttpMatcher::new(),
        }
    }

    /// Create with config
    pub fn with_config(config: HttpConfig) -> Self {
        Self {
            config,
            matcher: HttpMatcher::new(),
        }
    }

    /// Check if payload starts with HTTP request
    pub fn is_http_request(payload: &[u8]) -> bool {
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
    pub fn is_http_response(payload: &[u8]) -> bool {
        payload.starts_with(b"HTTP/")
    }

    /// Parse HTTP request
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

    /// Parse HTTP response
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
}

impl Default for HttpParser {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProtocolParser for HttpParser {
    fn name(&self) -> &'static str {
        "http"
    }

    fn protocol(&self) -> Protocol {
        Protocol::Http
    }

    fn default_tcp_ports(&self) -> &'static [u16] {
        &[80, 8080, 8000, 8008, 8888, 3000]
    }

    fn default_udp_ports(&self) -> &'static [u16] {
        &[] // HTTP is TCP only (QUIC is separate)
    }

    fn probe(&self, payload: &[u8], _direction: Direction) -> u8 {
        if Self::is_http_request(payload) || Self::is_http_response(payload) {
            100
        } else {
            0
        }
    }

    async fn parse(
        &mut self,
        analysis: &PacketAnalysis,
        pstate: &mut ProtocolState,
    ) -> ParseResult {
        let payload = analysis.packet.payload();

        if payload.is_empty() {
            return ParseResult::Incomplete;
        }

        // Ensure HTTP state exists
        if pstate.get_inner::<HttpState>().is_none() {
            pstate.set_inner(HttpState::new());
        }

        let is_request = matches!(analysis.packet.direction, Direction::ToServer);

        // Parse based on direction
        if is_request && Self::is_http_request(payload) {
            if let Some(request) = self.parse_request(payload) {
                // Set buffers for rule matching
                pstate.set_buffer("http.method", request.method.as_bytes().to_vec());
                pstate.set_buffer("http.uri", request.uri.as_bytes().to_vec());
                pstate.set_buffer("http.uri.raw", request.uri.as_bytes().to_vec());
                pstate.set_buffer("http.protocol", request.version.as_bytes().to_vec());

                if let Some(ref host) = request.host {
                    pstate.set_buffer("http.host", host.as_bytes().to_vec());
                    pstate.set_buffer("http.host.raw", host.as_bytes().to_vec());
                }

                if let Some(ref ua) = request.user_agent {
                    pstate.set_buffer("http.user_agent", ua.as_bytes().to_vec());
                }

                if let Some(ref cookie) = request.cookie {
                    pstate.set_buffer("http.cookie", cookie.as_bytes().to_vec());
                }

                if let Some(ref ct) = request.content_type {
                    pstate.set_buffer("http.content_type", ct.as_bytes().to_vec());
                }

                if !request.body.is_empty() {
                    pstate.set_buffer("http.request_body", request.body.clone());
                }

                // Build request line
                let request_line = format!("{} {} {}", request.method, request.uri, request.version);
                pstate.set_buffer("http.request_line", request_line.into_bytes());

                // Update state
                if let Some(state) = pstate.get_inner_mut::<HttpState>() {
                    state.record_request(&request);
                    state.bytes_sent += payload.len() as u64;
                }

                pstate.detected = true;
                pstate.protocol = Some(Protocol::Http);
                pstate.bytes_to_server += payload.len() as u64;

                let tx = Transaction::new(pstate.current_tx_id() + 1, "http_request")
                    .with_metadata("method", request.method)
                    .with_metadata("uri", request.uri)
                    .complete();

                return ParseResult::Complete(tx);
            }
        } else if !is_request && Self::is_http_response(payload) {
            if let Some(response) = self.parse_response(payload) {
                // Set buffers for rule matching
                pstate.set_buffer("http.stat_code", response.status_code.to_string().into_bytes());
                pstate.set_buffer("http.stat_msg", response.status_msg.as_bytes().to_vec());
                pstate.set_buffer("http.protocol", response.version.as_bytes().to_vec());

                if let Some(ref server) = response.server {
                    pstate.set_buffer("http.server", server.as_bytes().to_vec());
                }

                if let Some(ref ct) = response.content_type {
                    pstate.set_buffer("http.content_type", ct.as_bytes().to_vec());
                }

                if let Some(ref location) = response.headers.get("location") {
                    pstate.set_buffer("http.location", location.as_bytes().to_vec());
                }

                if !response.body.is_empty() {
                    pstate.set_buffer("http.response_body", response.body.clone());
                    pstate.set_buffer("file.data", response.body.clone());
                }

                // Build response line
                let response_line = format!("{} {} {}", response.version, response.status_code, response.status_msg);
                pstate.set_buffer("http.response_line", response_line.into_bytes());

                // Update state
                if let Some(state) = pstate.get_inner_mut::<HttpState>() {
                    state.record_response(&response);
                    state.bytes_received += payload.len() as u64;
                }

                pstate.detected = true;
                pstate.protocol = Some(Protocol::Http);
                pstate.bytes_to_client += payload.len() as u64;

                let tx = Transaction::new(pstate.current_tx_id() + 1, "http_response")
                    .with_metadata("status_code", response.status_code.to_string())
                    .with_metadata("status_msg", response.status_msg)
                    .complete();

                return ParseResult::Complete(tx);
            }
        }

        ParseResult::NotThisProtocol
    }

    fn match_rules(
        &self,
        state: &ProtocolState,
        rules: &ProtocolRuleSet<'_>,
    ) -> Vec<ProtocolAlert> {
        self.matcher.match_rules(state, rules)
    }

    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> {
        state.get_buffer(name)
    }

    fn buffer_names(&self) -> &'static [&'static str] {
        HTTP_KEYWORDS
    }

    fn reset(&mut self) {
        // Parser is stateless, state is in ProtocolState
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_http_request() {
        let parser = HttpParser::new();
        assert_eq!(parser.probe(b"GET / HTTP/1.1\r\n", Direction::ToServer), 100);
        assert_eq!(parser.probe(b"POST /api HTTP/1.1\r\n", Direction::ToServer), 100);
    }

    #[test]
    fn test_probe_http_response() {
        let parser = HttpParser::new();
        assert_eq!(parser.probe(b"HTTP/1.1 200 OK\r\n", Direction::ToClient), 100);
    }

    #[test]
    fn test_probe_not_http() {
        let parser = HttpParser::new();
        assert_eq!(parser.probe(b"some random data", Direction::ToServer), 0);
    }

    #[test]
    fn test_parse_request() {
        let parser = HttpParser::new();
        let request = b"GET /index.html HTTP/1.1\r\n\
                        Host: example.com\r\n\
                        User-Agent: Mozilla/5.0\r\n\
                        \r\n";

        let parsed = parser.parse_request(request).unwrap();

        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.uri, "/index.html");
        assert_eq!(parsed.host, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_response() {
        let parser = HttpParser::new();
        let response = b"HTTP/1.1 200 OK\r\n\
                         Content-Type: text/html\r\n\
                         Server: nginx\r\n\
                         \r\n\
                         Hello, World!";

        let parsed = parser.parse_response(response).unwrap();

        assert_eq!(parsed.status_code, 200);
        assert_eq!(parsed.status_msg, "OK");
        assert_eq!(parsed.server, Some("nginx".to_string()));
    }
}
