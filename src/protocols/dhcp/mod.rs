//! DHCP protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::DhcpState; pub use match_::DhcpMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "dhcp", protocol: Protocol::Dhcp, tcp_ports: &[], udp_ports: &[67, 68],
        create_parser: || Box::new(DhcpParser::new()), priority: 80, keywords: DHCP_KEYWORDS }
}

pub struct DhcpParser { matcher: DhcpMatcher }
impl DhcpParser { pub fn new() -> Self { Self { matcher: DhcpMatcher::new() } } }
impl Default for DhcpParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for DhcpParser {
    fn name(&self) -> &'static str { "dhcp" }
    fn protocol(&self) -> Protocol { Protocol::Dhcp }
    fn default_tcp_ports(&self) -> &'static [u16] { &[] }
    fn default_udp_ports(&self) -> &'static [u16] { &[67, 68] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 { if payload.len() >= 240 && payload[236..240] == DHCP_MAGIC { 100 } else { 0 } }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.len() < 244 { return ParseResult::Incomplete; }
        if payload[236..240] != DHCP_MAGIC { return ParseResult::NotThisProtocol; }
        if pstate.get_inner::<DhcpState>().is_none() { pstate.set_inner(DhcpState::new()); }

        let mut offset = 240;
        while offset < payload.len() - 2 {
            let opt = payload[offset]; let len = payload[offset + 1] as usize;
            if opt == 255 { break; }
            if opt == 53 && len >= 1 {
                let msg_type = payload[offset + 2];
                if let Some(s) = pstate.get_inner_mut::<DhcpState>() { s.msg_type = Some(msg_type); }
                pstate.set_buffer("dhcp.type", vec![msg_type]);
            }
            if opt == 12 && len > 0 {
                if let Ok(name) = std::str::from_utf8(&payload[offset + 2..offset + 2 + len]) {
                    pstate.set_buffer("dhcp.hostname", name.as_bytes().to_vec());
                }
            }
            offset += 2 + len;
        }
        pstate.detected = true; pstate.protocol = Some(Protocol::Dhcp);
        ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "dhcp_msg").complete())
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { DHCP_KEYWORDS }
    fn reset(&mut self) {}
}
