//! IKE/IPsec protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::IkeState; pub use match_::IkeMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "ike", protocol: Protocol::Ike, tcp_ports: &[], udp_ports: &[500, 4500],
        create_parser: || Box::new(IkeParser::new()), priority: 70, keywords: IKE_KEYWORDS }
}

pub struct IkeParser { matcher: IkeMatcher }
impl IkeParser { pub fn new() -> Self { Self { matcher: IkeMatcher::new() } } }
impl Default for IkeParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for IkeParser {
    fn name(&self) -> &'static str { "ike" }
    fn protocol(&self) -> Protocol { Protocol::Ike }
    fn default_tcp_ports(&self) -> &'static [u16] { &[] }
    fn default_udp_ports(&self) -> &'static [u16] { &[500, 4500] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 {
        // IKE header: Initiator SPI (8) + Responder SPI (8) + Next Payload (1) + Version (1) + Exchange Type (1) + Flags (1) + Message ID (4) + Length (4) = 28 bytes
        if payload.len() >= 28 {
            let version = payload[17];
            // IKEv1: 0x10, IKEv2: 0x20
            if version == 0x10 || version == 0x20 { return 90; }
        }
        // NAT-T on port 4500 has 4-byte non-ESP marker
        if payload.len() >= 32 && payload[..4] == [0, 0, 0, 0] {
            let version = payload[21];
            if version == 0x10 || version == 0x20 { return 85; }
        }
        0
    }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        let offset = if payload.len() >= 32 && payload[..4] == [0, 0, 0, 0] { 4 } else { 0 };

        if payload.len() < offset + 28 { return ParseResult::NotThisProtocol; }

        let header = &payload[offset..];
        let version = header[17];
        if version != 0x10 && version != 0x20 { return ParseResult::NotThisProtocol; }

        if pstate.get_inner::<IkeState>().is_none() { pstate.set_inner(IkeState::new()); }

        let init_spi = u64::from_be_bytes(header[0..8].try_into().unwrap_or([0; 8]));
        let resp_spi = u64::from_be_bytes(header[8..16].try_into().unwrap_or([0; 8]));
        let exchange_type = header[18];
        let flags = header[19];

        pstate.set_buffer("ike.init_spi", init_spi.to_be_bytes().to_vec());
        pstate.set_buffer("ike.resp_spi", resp_spi.to_be_bytes().to_vec());
        pstate.set_buffer("ike.version", vec![version]);
        pstate.set_buffer("ike.exchange_type", vec![exchange_type]);
        pstate.set_buffer("ike.flags", vec![flags]);

        if let Some(s) = pstate.get_inner_mut::<IkeState>() {
            s.initiator_spi = init_spi;
            s.responder_spi = resp_spi;
            s.version = version >> 4;
            s.exchange_type = exchange_type;
            s.is_initiator = (flags & 0x08) != 0;
            s.is_response = (flags & 0x20) != 0;
            s.message_count += 1;
            // Aggressive mode in IKEv1
            if s.version == 1 && exchange_type == 4 { s.aggressive_mode = true; }
        }

        pstate.detected = true; pstate.protocol = Some(Protocol::Ike);
        ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "ike_msg").complete())
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { IKE_KEYWORDS }
    fn reset(&mut self) {}
}
