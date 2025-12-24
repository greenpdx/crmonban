//! Kerberos protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::KerberosState; pub use match_::KerberosMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "krb5", protocol: Protocol::Kerberos, tcp_ports: &[88], udp_ports: &[88],
        create_parser: || Box::new(KerberosParser::new()), priority: 70, keywords: KRB_KEYWORDS }
}

pub struct KerberosParser { matcher: KerberosMatcher }
impl KerberosParser { pub fn new() -> Self { Self { matcher: KerberosMatcher::new() } } }
impl Default for KerberosParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for KerberosParser {
    fn name(&self) -> &'static str { "krb5" }
    fn protocol(&self) -> Protocol { Protocol::Kerberos }
    fn default_tcp_ports(&self) -> &'static [u16] { &[88] }
    fn default_udp_ports(&self) -> &'static [u16] { &[88] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 { if payload.len() >= 4 && (payload[0] == 0x6a || payload[0] == 0x6b || payload[0] == 0x6c || payload[0] == 0x6d || payload[0] == 0x6e) { 90 } else { 0 } }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.len() < 4 { return ParseResult::Incomplete; }
        if pstate.get_inner::<KerberosState>().is_none() { pstate.set_inner(KerberosState::new()); }

        let tag = payload[0];
        let msg_type = match tag { 0x6a => 10, 0x6b => 11, 0x6c => 12, 0x6d => 13, 0x6e => 14, 0x6f => 15, 0x7e => 30, _ => return ParseResult::NotThisProtocol };

        if let Some(s) = pstate.get_inner_mut::<KerberosState>() {
            s.msg_type = Some(msg_type);
            s.ticket_requests += 1;
            if msg_type == 12 { s.kerberoasting = true; } // TGS-REQ could be kerberoasting
        }
        pstate.set_buffer("krb5.msg_type", vec![msg_type]);
        pstate.detected = true; pstate.protocol = Some(Protocol::Kerberos);
        ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "krb5_msg").with_metadata("msg_type", msg_type.to_string()).complete())
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { KRB_KEYWORDS }
    fn reset(&mut self) {}
}
