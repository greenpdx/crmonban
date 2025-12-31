//! RFB/VNC protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::RfbState; pub use match_::RfbMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "rfb", protocol: Protocol::Rfb, tcp_ports: &[5900, 5901, 5902, 5903], udp_ports: &[],
        create_parser: || Box::new(RfbParser::new()), priority: 70, keywords: RFB_KEYWORDS }
}

pub struct RfbParser { matcher: RfbMatcher }
impl RfbParser { pub fn new() -> Self { Self { matcher: RfbMatcher::new() } } }
impl Default for RfbParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for RfbParser {
    fn name(&self) -> &'static str { "rfb" }
    fn protocol(&self) -> Protocol { Protocol::Rfb }
    fn default_tcp_ports(&self) -> &'static [u16] { &[5900, 5901, 5902, 5903] }
    fn default_udp_ports(&self) -> &'static [u16] { &[] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 {
        // RFB version string: "RFB xxx.yyy\n" (12 bytes)
        if payload.len() >= 12 && payload.starts_with(b"RFB ") { return 100; }
        0
    }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.is_empty() { return ParseResult::NotThisProtocol; }

        if pstate.get_inner::<RfbState>().is_none() { pstate.set_inner(RfbState::new()); }

        // Version handshake - server sends first in VNC
        if payload.len() >= 12 && payload.starts_with(b"RFB ") {
            if let Ok(version) = std::str::from_utf8(&payload[..12]) {
                pstate.set_buffer("rfb.version", version.trim().as_bytes().to_vec());
                if let Some(s) = pstate.get_inner_mut::<RfbState>() {
                    // Determine direction from flow if available (server sends first version)
                    let is_server = analysis.flow.as_ref()
                        .map(|f| f.server_port == 5900 || f.server_port == 5901 || f.server_port == 5902 || f.server_port == 5903)
                        .unwrap_or(true);
                    if is_server {
                        s.server_version = Some(version.trim().to_string());
                    } else {
                        s.client_version = Some(version.trim().to_string());
                    }
                }
            }
        }
        // Security type selection (1 byte)
        else if payload.len() == 1 {
            let sec_type = payload[0];
            pstate.set_buffer("rfb.sectype", vec![sec_type]);
            if let Some(s) = pstate.get_inner_mut::<RfbState>() {
                s.security_type = sec_type;
                if WEAK_SECURITY.contains(&sec_type) { s.weak_auth = true; }
            }
        }
        // Security result (4 bytes: 0 = OK, 1 = Failed)
        else if payload.len() == 4 {
            let result = ((payload[0] as u32) << 24) | ((payload[1] as u32) << 16) | ((payload[2] as u32) << 8) | payload[3] as u32;
            pstate.set_buffer("rfb.secresult", payload.to_vec());
            if let Some(s) = pstate.get_inner_mut::<RfbState>() {
                s.security_result = Some(result);
                if result == 0 { s.authenticated = true; }
            }
        }
        // ServerInit message has desktop name length + name
        else if payload.len() > 24 {
            let name_len = ((payload[20] as u32) << 24) | ((payload[21] as u32) << 16) | ((payload[22] as u32) << 8) | payload[23] as u32;
            if payload.len() >= 24 + name_len as usize {
                if let Ok(name) = std::str::from_utf8(&payload[24..24 + name_len as usize]) {
                    pstate.set_buffer("rfb.name", name.as_bytes().to_vec());
                    if let Some(s) = pstate.get_inner_mut::<RfbState>() { s.desktop_name = Some(name.to_string()); }
                }
            }
        }

        pstate.detected = true; pstate.protocol = Some(Protocol::Rfb);
        ParseResult::Incomplete
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { RFB_KEYWORDS }
    fn reset(&mut self) {}
}
