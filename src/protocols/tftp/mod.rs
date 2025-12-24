//! TFTP protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::TftpState; pub use match_::TftpMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "tftp", protocol: Protocol::Tftp, tcp_ports: &[], udp_ports: &[69],
        create_parser: || Box::new(TftpParser::new()), priority: 70, keywords: TFTP_KEYWORDS }
}

pub struct TftpParser { matcher: TftpMatcher }
impl TftpParser { pub fn new() -> Self { Self { matcher: TftpMatcher::new() } } }
impl Default for TftpParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for TftpParser {
    fn name(&self) -> &'static str { "tftp" }
    fn protocol(&self) -> Protocol { Protocol::Tftp }
    fn default_tcp_ports(&self) -> &'static [u16] { &[] }
    fn default_udp_ports(&self) -> &'static [u16] { &[69] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 {
        if payload.len() >= 4 {
            let opcode = ((payload[0] as u16) << 8) | payload[1] as u16;
            if opcode >= 1 && opcode <= 6 { return 80; }
        }
        0
    }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.len() < 4 { return ParseResult::NotThisProtocol; }

        let opcode = ((payload[0] as u16) << 8) | payload[1] as u16;
        if opcode < 1 || opcode > 6 { return ParseResult::NotThisProtocol; }

        if pstate.get_inner::<TftpState>().is_none() { pstate.set_inner(TftpState::new()); }

        pstate.set_buffer("tftp.opcode", opcode.to_be_bytes().to_vec());

        if let Some(s) = pstate.get_inner_mut::<TftpState>() {
            s.opcode = opcode;
            if opcode == 2 { s.is_write = true; }
        }

        // RRQ/WRQ: opcode (2) + filename (null-terminated) + mode (null-terminated)
        if opcode == 1 || opcode == 2 {
            if let Some(null_pos) = payload[2..].iter().position(|&b| b == 0) {
                if let Ok(filename) = std::str::from_utf8(&payload[2..2 + null_pos]) {
                    pstate.set_buffer("tftp.file", filename.as_bytes().to_vec());
                    if let Some(s) = pstate.get_inner_mut::<TftpState>() {
                        s.filename = Some(filename.to_string());
                        let lower = filename.to_lowercase();
                        if SUSPICIOUS_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
                            s.suspicious_file = true;
                        }
                    }
                    // Extract mode
                    let mode_start = 2 + null_pos + 1;
                    if payload.len() > mode_start {
                        if let Some(mode_end) = payload[mode_start..].iter().position(|&b| b == 0) {
                            if let Ok(mode) = std::str::from_utf8(&payload[mode_start..mode_start + mode_end]) {
                                pstate.set_buffer("tftp.mode", mode.as_bytes().to_vec());
                                if let Some(s) = pstate.get_inner_mut::<TftpState>() { s.mode = Some(mode.to_string()); }
                            }
                        }
                    }
                }
            }
        }

        // DATA/ACK: opcode (2) + block (2)
        if opcode == 3 || opcode == 4 {
            let block = ((payload[2] as u16) << 8) | payload[3] as u16;
            pstate.set_buffer("tftp.block", block.to_be_bytes().to_vec());
            if let Some(s) = pstate.get_inner_mut::<TftpState>() { s.block_count = block as u32; }
        }

        pstate.detected = true; pstate.protocol = Some(Protocol::Tftp);
        ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "tftp_msg").complete())
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { TFTP_KEYWORDS }
    fn reset(&mut self) {}
}
