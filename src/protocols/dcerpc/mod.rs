//! DCE/RPC protocol parser
pub mod types;
pub mod state;
pub mod match_;

pub use types::*;
pub use state::DceRpcState;
pub use match_::DceRpcMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;
use crate::protocols::traits::ParserStage;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration {
        name: "dcerpc", protocol: Protocol::Dcerpc,
        tcp_ports: &[135, 593], udp_ports: &[135],
        create_parser: || Box::new(DceRpcParser::new()),
        priority: 60, keywords: DCERPC_KEYWORDS,
    }
}

pub struct DceRpcParser { matcher: DceRpcMatcher }

impl DceRpcParser {
    pub fn new() -> Self { Self { matcher: DceRpcMatcher::new() } }

    fn is_dcerpc(payload: &[u8]) -> bool {
        payload.len() >= 24 && payload[0] == 5 && (payload[1] == 0 || payload[1] == 1)
    }
}

impl Default for DceRpcParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for DceRpcParser {
    fn name(&self) -> &'static str { "dcerpc" }
    fn protocol(&self) -> Protocol { Protocol::Dcerpc }
    fn default_tcp_ports(&self) -> &'static [u16] { &[135, 593] }
    fn default_udp_ports(&self) -> &'static [u16] { &[135] }

    fn probe(&self, payload: &[u8], _dir: Direction) -> u8 {
        if Self::is_dcerpc(payload) { 100 } else { 0 }
    }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.len() < 24 { return ParseResult::Incomplete; }
        if !Self::is_dcerpc(payload) { return ParseResult::NotThisProtocol; }

        if pstate.get_inner::<DceRpcState>().is_none() { pstate.set_inner(DceRpcState::new()); }

        let ptype = payload[2];
        if let Ok(pt) = DceRpcPacketType::try_from(ptype) {
            match pt {
                DceRpcPacketType::Bind if payload.len() >= 40 => {
                    if let Some(uuid) = Uuid::from_bytes(&payload[24..40]) {
                        let iface = uuid.to_string();
                        pstate.set_buffer("dcerpc.iface", iface.as_bytes().to_vec());
                        if let Some(state) = pstate.get_inner_mut::<DceRpcState>() {
                            if SUSPICIOUS_INTERFACES.iter().any(|(i, _)| *i == iface) {
                                state.suspicious_interface = true;
                            }
                            state.add_interface(iface);
                        }
                    }
                    pstate.detected = true;
                    pstate.protocol = Some(Protocol::Dcerpc);
                    pstate.stage = ParserStage::Handshake;
                    return ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "dcerpc_bind").complete());
                }
                DceRpcPacketType::Request if payload.len() >= 28 => {
                    let opnum = u16::from_le_bytes([payload[22], payload[23]]);
                    pstate.set_buffer("dcerpc.opnum", opnum.to_le_bytes().to_vec());
                    if payload.len() > 24 { pstate.set_buffer("dcerpc.stub_data", payload[24..].to_vec()); }
                    if let Some(state) = pstate.get_inner_mut::<DceRpcState>() {
                        state.current_opnum = Some(opnum);
                        state.request_count += 1;
                    }
                    pstate.stage = ParserStage::Data;
                    return ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "dcerpc_request").with_metadata("opnum", opnum.to_string()).complete());
                }
                _ => {}
            }
        }
        ParseResult::Incomplete
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { DCERPC_KEYWORDS }
    fn reset(&mut self) {}
}
