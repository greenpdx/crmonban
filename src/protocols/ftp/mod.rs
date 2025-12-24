//! FTP protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::FtpState; pub use match_::FtpMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;
use crate::protocols::traits::ParserStage;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "ftp", protocol: Protocol::Ftp, tcp_ports: &[21, 20], udp_ports: &[],
        create_parser: || Box::new(FtpParser::new()), priority: 70, keywords: FTP_KEYWORDS }
}

pub struct FtpParser { matcher: FtpMatcher }
impl FtpParser {
    pub fn new() -> Self { Self { matcher: FtpMatcher::new() } }
    fn is_ftp(payload: &[u8]) -> bool {
        if payload.len() < 3 { return false; }
        let s = std::str::from_utf8(payload).unwrap_or("");
        let upper = s.to_uppercase();
        FTP_COMMANDS.iter().any(|c| upper.starts_with(c)) || (payload.len() >= 4 && payload[0].is_ascii_digit() && payload[1].is_ascii_digit() && payload[2].is_ascii_digit() && (payload[3] == b' ' || payload[3] == b'-'))
    }
}
impl Default for FtpParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for FtpParser {
    fn name(&self) -> &'static str { "ftp" }
    fn protocol(&self) -> Protocol { Protocol::Ftp }
    fn default_tcp_ports(&self) -> &'static [u16] { &[21, 20] }
    fn default_udp_ports(&self) -> &'static [u16] { &[] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 { if Self::is_ftp(payload) { 90 } else { 0 } }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.is_empty() { return ParseResult::Incomplete; }
        if pstate.get_inner::<FtpState>().is_none() { pstate.set_inner(FtpState::new()); }

        if let Ok(line) = std::str::from_utf8(payload) {
            let line = line.trim();
            if line.is_empty() { return ParseResult::Incomplete; }

            // Response
            if line.len() >= 3 && line[..3].chars().all(|c| c.is_ascii_digit()) {
                let code: u16 = line[..3].parse().unwrap_or(0);
                if code == 230 { if let Some(s) = pstate.get_inner_mut::<FtpState>() { s.authenticated = true; } }
                if code == 530 { if let Some(s) = pstate.get_inner_mut::<FtpState>() { s.auth_failures += 1; } }
                pstate.detected = true; pstate.protocol = Some(Protocol::Ftp);
                return ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "ftp_response").with_metadata("code", code.to_string()).complete());
            }

            // Command
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            let cmd = parts[0].to_uppercase();
            pstate.set_buffer("ftp.command", cmd.as_bytes().to_vec());
            if parts.len() > 1 { pstate.set_buffer("ftp.command_data", parts[1].as_bytes().to_vec()); }

            if let Some(s) = pstate.get_inner_mut::<FtpState>() {
                s.commands.push(cmd.clone());
                if cmd == "USER" && parts.len() > 1 { s.username = Some(parts[1].to_string()); }
                if cmd == "PORT" { s.passive_mode = false; s.bounce_attack = parts.get(1).map(|p| p.contains(",")).unwrap_or(false); }
                if cmd == "PASV" || cmd == "EPSV" { s.passive_mode = true; }
            }
            pstate.detected = true; pstate.protocol = Some(Protocol::Ftp); pstate.stage = ParserStage::Data;
            return ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "ftp_command").with_metadata("command", cmd).complete());
        }
        ParseResult::Incomplete
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { FTP_KEYWORDS }
    fn reset(&mut self) {}
}
