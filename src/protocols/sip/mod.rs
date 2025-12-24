//! SIP protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::SipState; pub use match_::SipMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "sip", protocol: Protocol::Sip, tcp_ports: &[5060, 5061], udp_ports: &[5060],
        create_parser: || Box::new(SipParser::new()), priority: 70, keywords: SIP_KEYWORDS }
}

pub struct SipParser { matcher: SipMatcher }
impl SipParser {
    pub fn new() -> Self { Self { matcher: SipMatcher::new() } }
    fn is_sip(payload: &[u8]) -> bool {
        if let Ok(s) = std::str::from_utf8(payload.get(..20).unwrap_or(payload)) {
            let upper = s.to_uppercase();
            SIP_METHODS.iter().any(|m| upper.starts_with(m)) || upper.starts_with("SIP/")
        } else { false }
    }
}
impl Default for SipParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for SipParser {
    fn name(&self) -> &'static str { "sip" }
    fn protocol(&self) -> Protocol { Protocol::Sip }
    fn default_tcp_ports(&self) -> &'static [u16] { &[5060, 5061] }
    fn default_udp_ports(&self) -> &'static [u16] { &[5060] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 { if Self::is_sip(payload) { 100 } else { 0 } }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if !Self::is_sip(payload) { return ParseResult::NotThisProtocol; }
        if pstate.get_inner::<SipState>().is_none() { pstate.set_inner(SipState::new()); }

        if let Ok(text) = std::str::from_utf8(payload) {
            let first_line = text.lines().next().unwrap_or("");
            pstate.set_buffer("sip.request_line", first_line.as_bytes().to_vec());

            if first_line.starts_with("SIP/") {
                let parts: Vec<&str> = first_line.split_whitespace().collect();
                if parts.len() >= 2 { if let Ok(code) = parts[1].parse::<u16>() {
                    pstate.set_buffer("sip.stat_code", code.to_be_bytes().to_vec());
                    if let Some(s) = pstate.get_inner_mut::<SipState>() { s.status_code = Some(code); }
                }}
            } else {
                let parts: Vec<&str> = first_line.split_whitespace().collect();
                if !parts.is_empty() {
                    let method = parts[0].to_uppercase();
                    pstate.set_buffer("sip.method", method.as_bytes().to_vec());
                    if parts.len() > 1 { pstate.set_buffer("sip.uri", parts[1].as_bytes().to_vec()); }
                    if let Some(s) = pstate.get_inner_mut::<SipState>() {
                        s.method = Some(method.clone());
                        if method == "INVITE" { s.invite_count += 1; }
                    }
                }
            }
        }
        pstate.detected = true; pstate.protocol = Some(Protocol::Sip);
        ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "sip_msg").complete())
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { SIP_KEYWORDS }
    fn reset(&mut self) {}
}
