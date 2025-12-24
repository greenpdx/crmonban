//! DNP3 protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::Dnp3State; pub use match_::Dnp3Matcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "dnp3", protocol: Protocol::Dnp3, tcp_ports: &[20000], udp_ports: &[20000],
        create_parser: || Box::new(Dnp3Parser::new()), priority: 70, keywords: DNP3_KEYWORDS }
}

pub struct Dnp3Parser { matcher: Dnp3Matcher }
impl Dnp3Parser { pub fn new() -> Self { Self { matcher: Dnp3Matcher::new() } } }
impl Default for Dnp3Parser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for Dnp3Parser {
    fn name(&self) -> &'static str { "dnp3" }
    fn protocol(&self) -> Protocol { Protocol::Dnp3 }
    fn default_tcp_ports(&self) -> &'static [u16] { &[20000] }
    fn default_udp_ports(&self) -> &'static [u16] { &[20000] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 {
        // DNP3 starts with 0x0564
        if payload.len() >= 10 && payload[0] == DNP3_START_BYTES.0 && payload[1] == DNP3_START_BYTES.1 { 90 } else { 0 }
    }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.len() < 10 { return ParseResult::NotThisProtocol; }
        if payload[0] != DNP3_START_BYTES.0 || payload[1] != DNP3_START_BYTES.1 { return ParseResult::NotThisProtocol; }

        if pstate.get_inner::<Dnp3State>().is_none() { pstate.set_inner(Dnp3State::new()); }

        // DNP3 Data Link Layer: Start (2) + Length (1) + Control (1) + Dest (2) + Source (2) + CRC (2)
        let dest_addr = (payload[4] as u16) | ((payload[5] as u16) << 8);
        let source_addr = (payload[6] as u16) | ((payload[7] as u16) << 8);

        pstate.set_buffer("dnp3.header", payload[..10.min(payload.len())].to_vec());

        if let Some(s) = pstate.get_inner_mut::<Dnp3State>() {
            s.dest_addr = dest_addr;
            s.source_addr = source_addr;
            s.message_count += 1;
        }

        // Try to extract function code from application layer (after transport header)
        if payload.len() > 12 {
            let func = payload[12];
            pstate.set_buffer("dnp3.func", vec![func]);
            if let Some(s) = pstate.get_inner_mut::<Dnp3State>() {
                s.function_code = func;
                if func == 13 || func == 14 { s.restart_detected = true; }
                if DANGEROUS_DNP3_FUNCTIONS.contains(&func) { s.control_detected = true; }
            }
        }

        pstate.detected = true; pstate.protocol = Some(Protocol::Dnp3);
        ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "dnp3_msg").complete())
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { DNP3_KEYWORDS }
    fn reset(&mut self) {}
}
