//! RDP protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::RdpState; pub use match_::RdpMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "rdp", protocol: Protocol::Rdp, tcp_ports: &[3389], udp_ports: &[3389],
        create_parser: || Box::new(RdpParser::new()), priority: 70, keywords: RDP_KEYWORDS }
}

pub struct RdpParser { matcher: RdpMatcher }
impl RdpParser { pub fn new() -> Self { Self { matcher: RdpMatcher::new() } } }
impl Default for RdpParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for RdpParser {
    fn name(&self) -> &'static str { "rdp" }
    fn protocol(&self) -> Protocol { Protocol::Rdp }
    fn default_tcp_ports(&self) -> &'static [u16] { &[3389] }
    fn default_udp_ports(&self) -> &'static [u16] { &[3389] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 { if payload.len() >= 4 && payload[0] == TPKT_VERSION { 80 } else { 0 } }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.len() < 11 { return ParseResult::Incomplete; }
        if payload[0] != TPKT_VERSION { return ParseResult::NotThisProtocol; }
        if pstate.get_inner::<RdpState>().is_none() { pstate.set_inner(RdpState::new()); }

        let x224_type = payload[5];
        if x224_type == X224_CONNECTION_REQUEST || x224_type == X224_CONNECTION_CONFIRM {
            if let Some(s) = pstate.get_inner_mut::<RdpState>() { s.connection_requests += 1; }
            if payload.len() > 11 {
                if let Ok(data) = std::str::from_utf8(&payload[11..]) {
                    if data.starts_with("Cookie:") { pstate.set_buffer("rdp.cookie", data[7..].trim().as_bytes().to_vec()); }
                }
            }
            pstate.detected = true; pstate.protocol = Some(Protocol::Rdp);
            return ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "rdp_connect").complete());
        }
        ParseResult::Incomplete
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { RDP_KEYWORDS }
    fn reset(&mut self) {}
}
