//! NTP protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::NtpState; pub use match_::NtpMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "ntp", protocol: Protocol::Ntp, tcp_ports: &[], udp_ports: &[123],
        create_parser: || Box::new(NtpParser::new()), priority: 70, keywords: NTP_KEYWORDS }
}

pub struct NtpParser { matcher: NtpMatcher }
impl NtpParser { pub fn new() -> Self { Self { matcher: NtpMatcher::new() } } }
impl Default for NtpParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for NtpParser {
    fn name(&self) -> &'static str { "ntp" }
    fn protocol(&self) -> Protocol { Protocol::Ntp }
    fn default_tcp_ports(&self) -> &'static [u16] { &[] }
    fn default_udp_ports(&self) -> &'static [u16] { &[123] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 {
        if payload.len() >= 48 {
            let version = (payload[0] >> 3) & 0x07;
            if version >= 1 && version <= 4 { return 85; }
        }
        // Mode 7 (private) can be shorter
        if payload.len() >= 8 && (payload[0] & 0x07) == 7 { return 70; }
        0
    }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.is_empty() { return ParseResult::NotThisProtocol; }

        let li_vn_mode = payload[0];
        let version = (li_vn_mode >> 3) & 0x07;
        let mode = li_vn_mode & 0x07;

        // Validate version
        if version < 1 || version > 4 {
            if mode != 7 { return ParseResult::NotThisProtocol; }
        }

        if pstate.get_inner::<NtpState>().is_none() { pstate.set_inner(NtpState::new()); }

        pstate.set_buffer("ntp.version", vec![version]);
        pstate.set_buffer("ntp.mode", vec![mode]);

        if let Some(s) = pstate.get_inner_mut::<NtpState>() {
            s.version = version;
            s.mode = mode;
            s.message_count += 1;
            if mode == 7 { s.private_mode = true; }
            if mode == 6 { s.control_mode = true; }
        }

        // Check for monlist in mode 7 private packets
        if mode == 7 && payload.len() >= 4 {
            let req_code = payload[3];
            if req_code == MONLIST_CMD {
                if let Some(s) = pstate.get_inner_mut::<NtpState>() { s.monlist_detected = true; }
            }
        }

        // Standard NTP packet has stratum at offset 1
        if payload.len() >= 48 && mode >= 1 && mode <= 5 {
            let stratum = payload[1];
            pstate.set_buffer("ntp.stratum", vec![stratum]);
            if let Some(s) = pstate.get_inner_mut::<NtpState>() { s.stratum = stratum; }
        }

        pstate.detected = true; pstate.protocol = Some(Protocol::Ntp);
        ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "ntp_msg").complete())
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { NTP_KEYWORDS }
    fn reset(&mut self) {}
}
