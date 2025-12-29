//! SMTP protocol analyzer module
//!
//! Provides SMTP parsing and security analysis for email traffic.
//!
//! # Security Detections
//!
//! - Spam detection (subject patterns, excessive recipients)
//! - Phishing detection (subject patterns, domain spoofing, typosquatting)
//! - Email spoofing (SPF/DKIM/DMARC failures)
//! - Open relay abuse detection
//! - Authentication brute force attacks
//! - Malware attachment detection (dangerous file extensions)
//! - Mass mailer detection
//! - Header anomaly detection

pub mod types;
pub mod state;
pub mod parser;
pub mod analyzer;
pub mod match_;

pub use types::*;
pub use state::SmtpState;
pub use parser::{SmtpParser, SmtpCommand, SmtpResponse, SmtpParserState};
pub use analyzer::SmtpAnalyzer;
pub use match_::SmtpMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{
    ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction,
    ProtocolRuleSet,
};
use crate::protocols::registry::ProtocolRegistration;
use crate::protocols::traits::ParserStage;
use crate::types::protocols::spam_patterns::{SPAM_SUBJECT_PATTERNS, PHISHING_SUBJECT_PATTERNS};

/// Get SMTP protocol registration
pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration {
        name: "smtp",
        protocol: Protocol::Smtp,
        tcp_ports: &[25, 465, 587, 2525],
        udp_ports: &[],
        create_parser: || Box::new(SmtpProtocolParser::new()),
        priority: 70,
        keywords: SMTP_KEYWORDS,
    }
}

/// SMTP config for protocol parser
#[derive(Debug, Clone)]
pub struct SmtpParserConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_spam: bool,
    pub detect_phishing: bool,
    pub detect_spoofing: bool,
    pub detect_dangerous_attachments: bool,
}

impl Default for SmtpParserConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![25, 465, 587, 2525],
            detect_spam: true,
            detect_phishing: true,
            detect_spoofing: true,
            detect_dangerous_attachments: true,
        }
    }
}

/// SMTP Protocol Parser implementing unified interface
pub struct SmtpProtocolParser {
    config: SmtpParserConfig,
    client_parser: SmtpParser,
    server_parser: SmtpParser,
    matcher: SmtpMatcher,
}

impl SmtpProtocolParser {
    pub fn new() -> Self {
        Self {
            config: SmtpParserConfig::default(),
            client_parser: SmtpParser::new(true),
            server_parser: SmtpParser::new(false),
            matcher: SmtpMatcher::new(),
        }
    }

    pub fn with_config(config: SmtpParserConfig) -> Self {
        Self {
            config,
            client_parser: SmtpParser::new(true),
            server_parser: SmtpParser::new(false),
            matcher: SmtpMatcher::new(),
        }
    }

    fn process_client_command(&self, payload: &[u8], pstate: &mut ProtocolState) -> Option<ParseResult> {
        let mut parser = SmtpParser::new(true);
        let cmd = parser.parse_command(payload)?;

        // Initialize state if needed
        if pstate.get_inner::<SmtpState>().is_none() {
            pstate.set_inner(SmtpState::new());
        }

        match cmd {
            SmtpCommand::Ehlo(ref hostname) | SmtpCommand::Helo(ref hostname) => {
                let is_esmtp = matches!(cmd, SmtpCommand::Ehlo(_));

                if let Some(state) = pstate.get_inner_mut::<SmtpState>() {
                    state.record_helo(hostname, is_esmtp);
                }

                pstate.set_buffer("smtp.helo", hostname.as_bytes().to_vec());
                pstate.detected = true;
                pstate.protocol = Some(Protocol::Smtp);
                pstate.stage = ParserStage::Handshake;

                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "smtp_helo")
                        .with_metadata("hostname", hostname.clone())
                        .with_metadata("esmtp", is_esmtp.to_string())
                        .complete()
                ));
            }
            SmtpCommand::Auth { ref mechanism, .. } => {
                if let Some(state) = pstate.get_inner_mut::<SmtpState>() {
                    state.record_auth_start(mechanism.clone());
                }
                pstate.stage = ParserStage::Auth;

                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "smtp_auth_start")
                        .with_metadata("mechanism", format!("{:?}", mechanism))
                        .complete()
                ));
            }
            SmtpCommand::StartTls => {
                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "smtp_starttls").complete()
                ));
            }
            SmtpCommand::MailFrom { ref address, .. } => {
                if let Some(state) = pstate.get_inner_mut::<SmtpState>() {
                    state.start_transaction(address);
                }
                pstate.set_buffer("smtp.mail_from", address.as_bytes().to_vec());
                pstate.stage = ParserStage::Data;

                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "smtp_mail_from")
                        .with_metadata("address", address.clone())
                        .complete()
                ));
            }
            SmtpCommand::RcptTo { ref address, .. } => {
                if let Some(state) = pstate.get_inner_mut::<SmtpState>() {
                    state.add_recipient(address);
                }
                pstate.set_buffer("smtp.rcpt_to", address.as_bytes().to_vec());

                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "smtp_rcpt_to")
                        .with_metadata("address", address.clone())
                        .complete()
                ));
            }
            SmtpCommand::Data => {
                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "smtp_data").complete()
                ));
            }
            SmtpCommand::Rset => {
                if let Some(state) = pstate.get_inner_mut::<SmtpState>() {
                    state.reset_transaction();
                }
                pstate.clear_buffers();
            }
            SmtpCommand::Quit => {
                pstate.closed = true;
            }
            _ => {}
        }

        None
    }

    fn process_server_response(&self, payload: &[u8], pstate: &mut ProtocolState) -> Option<ParseResult> {
        let mut parser = SmtpParser::new(false);
        let response = parser.parse_response(payload)?;

        // Initialize state if needed
        if pstate.get_inner::<SmtpState>().is_none() {
            pstate.set_inner(SmtpState::new());
        }

        match response.code {
            220 => {
                // Server greeting
                if let Some(state) = pstate.get_inner_mut::<SmtpState>() {
                    state.record_greeting(&response.message);
                }
                pstate.detected = true;
                pstate.protocol = Some(Protocol::Smtp);
                pstate.stage = ParserStage::Init;

                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "smtp_greeting")
                        .with_metadata("banner", response.message)
                        .complete()
                ));
            }
            235 => {
                // Auth success
                if let Some(state) = pstate.get_inner_mut::<SmtpState>() {
                    state.record_auth_result(true, None);
                }

                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "smtp_auth_success").complete()
                ));
            }
            535 => {
                // Auth failure
                if let Some(state) = pstate.get_inner_mut::<SmtpState>() {
                    state.record_auth_result(false, None);
                }

                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "smtp_auth_failure")
                        .with_metadata("code", response.code.to_string())
                        .with_metadata("message", response.message)
                        .complete()
                ));
            }
            354 => {
                // Ready for data
                pstate.stage = ParserStage::Data;
            }
            code if code >= 400 => {
                // Error response
                if let Some(state) = pstate.get_inner_mut::<SmtpState>() {
                    state.record_error(code, &response.message);
                }

                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "smtp_error")
                        .with_metadata("code", code.to_string())
                        .with_metadata("message", response.message)
                        .complete()
                ));
            }
            _ => {}
        }

        None
    }

    fn analyze_headers(&self, pstate: &mut ProtocolState, headers: &crate::types::protocols::SmtpHeaders) {
        if let Some(state) = pstate.get_inner_mut::<SmtpState>() {
            // Check for spam subject patterns
            if self.config.detect_spam {
                if let Some(ref subject) = headers.subject {
                    let lower = subject.to_lowercase();
                    for pattern in SPAM_SUBJECT_PATTERNS {
                        if lower.contains(pattern) {
                            state.add_spam_indicator(pattern);
                        }
                    }
                }
            }

            // Check for phishing subject patterns
            if self.config.detect_phishing {
                if let Some(ref subject) = headers.subject {
                    let lower = subject.to_lowercase();
                    for pattern in PHISHING_SUBJECT_PATTERNS {
                        if lower.contains(pattern) {
                            state.add_phishing_indicator(pattern);
                        }
                    }
                }
            }

            // Check for spoofing
            if self.config.detect_spoofing {
                let spf_fail = headers.spf_result.as_ref()
                    .map(|r| r.to_lowercase().contains("fail"))
                    .unwrap_or(false);
                let dkim_missing = !headers.has_dkim;
                let dmarc_fail = headers.dmarc_result.as_ref()
                    .map(|r| r.to_lowercase().contains("fail"))
                    .unwrap_or(false);

                if dmarc_fail || (spf_fail && dkim_missing) {
                    state.spoofing_detected = true;
                }
            }

            // Set header buffers
            if let Some(ref from) = headers.from {
                pstate.set_buffer("smtp.from", from.as_bytes().to_vec());
            }
            if !headers.to.is_empty() {
                pstate.set_buffer("smtp.to", headers.to.join(", ").into_bytes());
            }
            if let Some(ref subject) = headers.subject {
                pstate.set_buffer("smtp.subject", subject.as_bytes().to_vec());
            }
        }
    }
}

impl Default for SmtpProtocolParser {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl ProtocolParser for SmtpProtocolParser {
    fn name(&self) -> &'static str { "smtp" }
    fn protocol(&self) -> Protocol { Protocol::Smtp }
    fn default_tcp_ports(&self) -> &'static [u16] { &[25, 465, 587, 2525] }
    fn default_udp_ports(&self) -> &'static [u16] { &[] }

    fn probe(&self, payload: &[u8], _direction: Direction) -> u8 {
        if SmtpParser::is_smtp(payload) {
            return 100;
        }
        0
    }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.is_empty() { return ParseResult::Incomplete; }

        let is_to_server = matches!(analysis.packet.direction, Direction::ToServer);

        // Initialize state if needed
        if pstate.get_inner::<SmtpState>().is_none() {
            pstate.set_inner(SmtpState::new());
        }

        if is_to_server {
            // Client -> Server (commands)
            if let Some(result) = self.process_client_command(payload, pstate) {
                return result;
            }
        } else {
            // Server -> Client (responses)
            if let Some(result) = self.process_server_response(payload, pstate) {
                return result;
            }
        }

        ParseResult::Incomplete
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        self.matcher.match_rules(state, rules)
    }

    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> {
        state.get_buffer(name)
    }

    fn buffer_names(&self) -> &'static [&'static str] { SMTP_KEYWORDS }
    fn reset(&mut self) {
        self.client_parser = SmtpParser::new(true);
        self.server_parser = SmtpParser::new(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_probe() {
        let parser = SmtpProtocolParser::new();

        // SMTP greeting
        assert_eq!(parser.probe(b"220 mail.example.com ESMTP\r\n", Direction::ToClient), 100);

        // EHLO command
        assert_eq!(parser.probe(b"EHLO localhost\r\n", Direction::ToServer), 100);

        // Not SMTP
        assert_eq!(parser.probe(b"HTTP/1.1 200 OK", Direction::ToServer), 0);
    }

    #[test]
    fn test_registration() {
        let reg = registration();
        assert_eq!(reg.name, "smtp");
        assert!(reg.tcp_ports.contains(&25));
        assert!(reg.tcp_ports.contains(&587));
    }
}
