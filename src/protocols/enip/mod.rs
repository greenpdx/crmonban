//! EtherNet/IP protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::EnipState; pub use match_::EnipMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "enip", protocol: Protocol::Enip, tcp_ports: &[44818], udp_ports: &[44818, 2222],
        create_parser: || Box::new(EnipParser::new()), priority: 70, keywords: ENIP_KEYWORDS }
}

pub struct EnipParser { matcher: EnipMatcher }
impl EnipParser { pub fn new() -> Self { Self { matcher: EnipMatcher::new() } } }
impl Default for EnipParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for EnipParser {
    fn name(&self) -> &'static str { "enip" }
    fn protocol(&self) -> Protocol { Protocol::Enip }
    fn default_tcp_ports(&self) -> &'static [u16] { &[44818] }
    fn default_udp_ports(&self) -> &'static [u16] { &[44818, 2222] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 {
        // ENIP header: Command (2) + Length (2) + Session (4) + Status (4) + Context (8) + Options (4) = 24 bytes
        if payload.len() >= 24 {
            let cmd = (payload[0] as u16) | ((payload[1] as u16) << 8);
            if ENIP_COMMANDS.iter().any(|(c, _)| *c == cmd) { return 85; }
        }
        0
    }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.len() < 24 { return ParseResult::NotThisProtocol; }

        let command = (payload[0] as u16) | ((payload[1] as u16) << 8);
        if !ENIP_COMMANDS.iter().any(|(c, _)| *c == command) { return ParseResult::NotThisProtocol; }

        if pstate.get_inner::<EnipState>().is_none() { pstate.set_inner(EnipState::new()); }

        let length = (payload[2] as u16) | ((payload[3] as u16) << 8);
        let session = (payload[4] as u32) | ((payload[5] as u32) << 8) | ((payload[6] as u32) << 16) | ((payload[7] as u32) << 24);
        let status = (payload[8] as u32) | ((payload[9] as u32) << 8) | ((payload[10] as u32) << 16) | ((payload[11] as u32) << 24);

        pstate.set_buffer("enip.command", command.to_le_bytes().to_vec());
        pstate.set_buffer("enip.length", length.to_le_bytes().to_vec());
        pstate.set_buffer("enip.session", session.to_le_bytes().to_vec());
        pstate.set_buffer("enip.status", status.to_le_bytes().to_vec());

        if let Some(s) = pstate.get_inner_mut::<EnipState>() {
            s.command = command;
            s.session_handle = session;
            s.status = status;
            s.message_count += 1;
        }

        // Check for CIP data in SendRRData/SendUnitData commands
        if (command == 0x006F || command == 0x0070) && payload.len() > 24 + length as usize {
            // CIP service is typically after encapsulation header + interface handle (4) + timeout (2) + item count (2)
            if payload.len() > 32 {
                let cip_offset = 24 + 8; // After interface/timeout/item header area
                if payload.len() > cip_offset {
                    let service = payload[cip_offset] & 0x7F;
                    pstate.set_buffer("cip.service", vec![service]);
                    if let Some(s) = pstate.get_inner_mut::<EnipState>() {
                        s.cip_service = Some(service);
                        if DANGEROUS_CIP_SERVICES.contains(&service) { s.control_detected = true; }
                    }
                }
            }
        }

        pstate.detected = true; pstate.protocol = Some(Protocol::Enip);
        ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "enip_msg").complete())
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { ENIP_KEYWORDS }
    fn reset(&mut self) {}
}
