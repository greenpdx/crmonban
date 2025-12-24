//! SNMP protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::SnmpState; pub use match_::SnmpMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "snmp", protocol: Protocol::Snmp, tcp_ports: &[], udp_ports: &[161, 162],
        create_parser: || Box::new(SnmpParser::new()), priority: 70, keywords: SNMP_KEYWORDS }
}

pub struct SnmpParser { matcher: SnmpMatcher }
impl SnmpParser { pub fn new() -> Self { Self { matcher: SnmpMatcher::new() } } }
impl Default for SnmpParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for SnmpParser {
    fn name(&self) -> &'static str { "snmp" }
    fn protocol(&self) -> Protocol { Protocol::Snmp }
    fn default_tcp_ports(&self) -> &'static [u16] { &[] }
    fn default_udp_ports(&self) -> &'static [u16] { &[161, 162] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 { if payload.len() >= 10 && payload[0] == 0x30 { 80 } else { 0 } }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.len() < 10 || payload[0] != 0x30 { return ParseResult::NotThisProtocol; }
        if pstate.get_inner::<SnmpState>().is_none() { pstate.set_inner(SnmpState::new()); }

        // Parse version (offset varies)
        if payload.len() > 4 && payload[2] == 0x02 && payload[3] == 0x01 {
            let version = payload[4];
            pstate.set_buffer("snmp.version", vec![version]);
            if let Some(s) = pstate.get_inner_mut::<SnmpState>() { s.version = version; }

            // Try to extract community string
            if payload.len() > 7 && payload[5] == 0x04 {
                let len = payload[6] as usize;
                if payload.len() > 7 + len {
                    if let Ok(community) = std::str::from_utf8(&payload[7..7 + len]) {
                        pstate.set_buffer("snmp.community", community.as_bytes().to_vec());
                        if let Some(s) = pstate.get_inner_mut::<SnmpState>() {
                            s.community = Some(community.to_string());
                            s.default_community = DEFAULT_COMMUNITIES.iter().any(|c| c.eq_ignore_ascii_case(community));
                        }
                    }
                }
            }
        }
        pstate.detected = true; pstate.protocol = Some(Protocol::Snmp);
        ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "snmp_msg").complete())
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { SNMP_KEYWORDS }
    fn reset(&mut self) {}
}
