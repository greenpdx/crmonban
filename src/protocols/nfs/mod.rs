//! NFS protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::NfsState; pub use match_::NfsMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "nfs", protocol: Protocol::Nfs, tcp_ports: &[2049, 111], udp_ports: &[2049, 111],
        create_parser: || Box::new(NfsParser::new()), priority: 60, keywords: NFS_KEYWORDS }
}

pub struct NfsParser { matcher: NfsMatcher }
impl NfsParser { pub fn new() -> Self { Self { matcher: NfsMatcher::new() } } }
impl Default for NfsParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for NfsParser {
    fn name(&self) -> &'static str { "nfs" }
    fn protocol(&self) -> Protocol { Protocol::Nfs }
    fn default_tcp_ports(&self) -> &'static [u16] { &[2049, 111] }
    fn default_udp_ports(&self) -> &'static [u16] { &[2049, 111] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 { if payload.len() >= 28 && u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]) == 0 { 70 } else { 0 } }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.len() < 28 { return ParseResult::Incomplete; }
        if pstate.get_inner::<NfsState>().is_none() { pstate.set_inner(NfsState::new()); }

        let prog = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let vers = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
        let proc = u32::from_be_bytes([payload[20], payload[21], payload[22], payload[23]]);

        if prog == 100003 || prog == 100005 { // NFS or MOUNT
            if let Some(s) = pstate.get_inner_mut::<NfsState>() { s.version = vers; s.procedures.push(proc); }
            pstate.set_buffer("nfs.procedure", proc.to_be_bytes().to_vec());
            pstate.detected = true; pstate.protocol = Some(Protocol::Nfs);
            return ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "nfs_call").with_metadata("procedure", proc.to_string()).complete());
        }
        ParseResult::NotThisProtocol
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { NFS_KEYWORDS }
    fn reset(&mut self) {}
}
