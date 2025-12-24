//! HTTP protocol analyzer
//!
//! Parses HTTP/1.x requests and responses and matches Suricata rules.

pub mod types;
pub mod state;
pub mod parser;
pub mod match_;

pub use types::*;
pub use state::HttpState;
pub use parser::{HttpParser, HttpConfig};
pub use match_::HttpMatcher;

use crate::signatures::ast::Protocol;
use crate::protocols::registry::ProtocolRegistration;

/// Get HTTP protocol registration
pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration {
        name: "http",
        protocol: Protocol::Http,
        tcp_ports: &[80, 8080, 8000, 8008, 8888, 3000],
        udp_ports: &[],
        create_parser: || Box::new(HttpParser::new()),
        priority: 60, // High priority - common protocol
        keywords: HTTP_KEYWORDS,
    }
}

// Legacy compatibility - re-export for existing code
use crate::core::{Flow, Packet, Direction};
use super::{HttpConfig as LegacyHttpConfig, ProtocolAnalyzer, ProtocolEvent};

/// Legacy HTTP protocol analyzer for backwards compatibility
pub struct HttpAnalyzer {
    config: LegacyHttpConfig,
    parser: HttpParser,
}

impl HttpAnalyzer {
    pub fn new(config: LegacyHttpConfig) -> Self {
        let parser_config = parser::HttpConfig {
            enabled: config.enabled,
            ports: config.ports.clone(),
            extract_headers: config.extract_headers,
            max_request_body: config.max_request_body,
            max_response_body: config.max_response_body,
        };

        Self {
            config,
            parser: HttpParser::with_config(parser_config),
        }
    }

    /// Parse HTTP request from payload
    pub fn parse_request(&self, payload: &[u8]) -> Option<HttpRequest> {
        self.parser.parse_request(payload)
    }

    /// Parse HTTP response from payload
    pub fn parse_response(&self, payload: &[u8]) -> Option<HttpResponse> {
        self.parser.parse_response(payload)
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
        HttpParser::is_http_request(payload) || HttpParser::is_http_response(payload)
    }

    fn parse(&self, packet: &Packet, flow: &mut Flow) -> Option<ProtocolEvent> {
        if !self.config.enabled || packet.payload().is_empty() {
            return None;
        }

        let payload = &packet.payload();

        // Determine if request or response based on direction and content
        let transaction = match packet.direction {
            Direction::ToServer => {
                if HttpParser::is_http_request(payload) {
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
                if HttpParser::is_http_response(payload) {
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
                if HttpParser::is_http_request(payload) {
                    if let Some(request) = self.parse_request(payload) {
                        HttpTransaction {
                            request: Some(request),
                            ..Default::default()
                        }
                    } else {
                        return None;
                    }
                } else if HttpParser::is_http_response(payload) {
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
    fn test_legacy_parse_request() {
        let config = LegacyHttpConfig::default();
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
    fn test_legacy_parse_response() {
        let config = LegacyHttpConfig::default();
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
    fn test_legacy_detect_http() {
        let config = LegacyHttpConfig::default();
        let analyzer = HttpAnalyzer::new(config);

        assert!(analyzer.detect(b"GET / HTTP/1.1", 80));
        assert!(analyzer.detect(b"POST /api", 8080));
        assert!(analyzer.detect(b"HTTP/1.1 200 OK", 80));
        assert!(!analyzer.detect(b"random data", 12345));
    }
}
