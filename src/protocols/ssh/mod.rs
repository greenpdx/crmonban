//! SSH protocol analyzer
//!
//! Provides comprehensive SSH protocol analysis including:
//! - Version exchange parsing
//! - Key exchange (KEXINIT) parsing
//! - HASSH fingerprinting for client/server identification
//! - Authentication tracking
//! - Brute force detection (per-IP)
//! - Vulnerable version detection (CVE database)
//! - Weak algorithm detection

pub mod types;
pub mod state;
pub mod cve;
pub mod hassh;
pub mod parser;
pub mod analyzer;
pub mod match_;

pub use types::*;
pub use state::SshState;
pub use analyzer::{SshAnalyzer, SshAnalyzerConfig, SshAnalyzerStats, SshDetection};
pub use cve::{SshCveDatabase, CveEntry, CveSeverity, SemVer, CveLookupResult};
pub use hassh::{HasshDatabase, HasshEntry, HasshCategory, HasshLookupResult, HasshVectorDb};
pub use parser::{SshParser, SshMsgType, WEAK_KEX_ALGORITHMS, WEAK_CIPHERS, WEAK_MACS};
pub use match_::SshMatcher;

// Re-export types from crmonban-types
pub use crate::types::protocols::{
    SshEvent, SshAuthMethod, SshNegotiatedAlgorithms, SshVersionInfo, HasshFingerprint,
};

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{
    ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction,
    ProtocolRuleSet,
};
use crate::protocols::registry::ProtocolRegistration;
use crate::protocols::traits::ParserStage;

/// Get SSH protocol registration
pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration {
        name: "ssh",
        protocol: Protocol::Ssh,
        tcp_ports: &[22, 2222, 22222],
        udp_ports: &[],
        create_parser: || Box::new(SshProtocolParser::new()),
        priority: 80,
        keywords: SSH_KEYWORDS,
    }
}

/// SSH config for protocol parser
#[derive(Debug, Clone)]
pub struct SshConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub hassh_enabled: bool,
    pub detect_weak_algorithms: bool,
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![22, 2222, 22222],
            hassh_enabled: true,
            detect_weak_algorithms: true,
        }
    }
}

/// SSH Protocol Parser implementing unified interface
pub struct SshProtocolParser {
    config: SshConfig,
    client_parser: SshParser,
    server_parser: SshParser,
    matcher: SshMatcher,
    cve_db: SshCveDatabase,
}

impl SshProtocolParser {
    pub fn new() -> Self {
        Self {
            config: SshConfig::default(),
            client_parser: SshParser::new(true),
            server_parser: SshParser::new(false),
            matcher: SshMatcher::new(),
            cve_db: SshCveDatabase::load_embedded(),
        }
    }

    pub fn with_config(config: SshConfig) -> Self {
        Self {
            config,
            client_parser: SshParser::new(true),
            server_parser: SshParser::new(false),
            matcher: SshMatcher::new(),
            cve_db: SshCveDatabase::load_embedded(),
        }
    }

    fn process_version(&self, payload: &[u8], pstate: &mut ProtocolState, is_client: bool) -> Option<ParseResult> {
        let version_event = SshParser::parse_version(payload)?;

        if let SshEvent::VersionExchange { ref client_version, protocol_version, .. } = version_event {
            // Initialize state if needed
            if pstate.get_inner::<SshState>().is_none() {
                pstate.set_inner(SshState::new());
            }

            // Update state
            if let Some(state) = pstate.get_inner_mut::<SshState>() {
                if is_client {
                    state.record_client_version(client_version);
                    // Check for vulnerable version
                    if let Some(info) = &state.client_version {
                        if let Some(version) = SemVer::from_software(&info.software) {
                            if let Some(result) = self.cve_db.lookup(&info.software, Some(&version)) {
                                state.vulnerable_version = true;
                                state.cves = result.cves.iter().map(|c| c.cve_id.clone()).collect();
                            }
                        }
                    }
                } else {
                    state.record_server_version(client_version);
                }
            }

            // Set buffers for rule matching
            pstate.set_buffer("ssh.proto", protocol_version.to_string().into_bytes());

            if let Some(info) = SshVersionInfo::parse(client_version) {
                pstate.set_buffer("ssh.software", info.software.into_bytes());
            }

            pstate.detected = true;
            pstate.protocol = Some(Protocol::Ssh);
            pstate.stage = ParserStage::Handshake;

            return Some(ParseResult::Complete(
                Transaction::new(pstate.current_tx_id() + 1, "ssh_version_exchange").complete()
            ));
        }

        None
    }

    fn process_kex_init(&self, payload: &[u8], pstate: &mut ProtocolState, is_client: bool) -> Option<ParseResult> {
        let _parser = if is_client { &self.client_parser } else { &self.server_parser };
        let mut parser_copy = SshParser::new(is_client);
        let event = parser_copy.parse_packet(payload)?;

        match &event {
            SshEvent::KeyExchangeInit {
                hassh,
                kex_algorithms,
                encryption_c2s,
                mac_c2s,
                ..
            } => {
                if pstate.get_inner::<SshState>().is_none() {
                    pstate.set_inner(SshState::new());
                }

                if let Some(state) = pstate.get_inner_mut::<SshState>() {
                    state.record_client_hassh(&hassh.hash, &hassh.string);

                    // Check for weak algorithms
                    if self.config.detect_weak_algorithms {
                        let weak_kex = parser::has_weak_algorithms(kex_algorithms, WEAK_KEX_ALGORITHMS);
                        let weak_enc = parser::has_weak_algorithms(encryption_c2s, WEAK_CIPHERS);
                        let weak_mac = parser::has_weak_algorithms(mac_c2s, WEAK_MACS);

                        for algo in weak_kex.into_iter().chain(weak_enc).chain(weak_mac) {
                            state.add_weak_algorithm(algo);
                        }
                    }
                }

                // Set buffers
                pstate.set_buffer("ssh.hassh", hassh.hash.as_bytes().to_vec());
                pstate.set_buffer("ssh.hassh.string", hassh.string.as_bytes().to_vec());

                pstate.stage = ParserStage::Auth;

                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "ssh_kex_init")
                        .with_metadata("hassh", hassh.hash.clone())
                        .complete()
                ));
            }
            SshEvent::ServerKexInit { hassh_server, .. } => {
                if let Some(state) = pstate.get_inner_mut::<SshState>() {
                    state.record_server_hassh(&hassh_server.hash, &hassh_server.string);
                }

                pstate.set_buffer("ssh.hassh.server", hassh_server.hash.as_bytes().to_vec());
                pstate.set_buffer("ssh.hassh.server.string", hassh_server.string.as_bytes().to_vec());

                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "ssh_server_kex")
                        .with_metadata("hassh_server", hassh_server.hash.clone())
                        .complete()
                ));
            }
            _ => {}
        }

        None
    }

    fn process_auth(&self, payload: &[u8], pstate: &mut ProtocolState) -> Option<ParseResult> {
        let mut parser = SshParser::new(true);
        let event = parser.parse_packet(payload)?;

        match &event {
            SshEvent::AuthAttempt { username, method, success, .. } => {
                if let Some(state) = pstate.get_inner_mut::<SshState>() {
                    state.record_auth_attempt(username, *success);
                }

                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "ssh_auth")
                        .with_metadata("username", username.clone())
                        .with_metadata("method", format!("{}", method))
                        .with_metadata("success", success.to_string())
                        .complete()
                ));
            }
            SshEvent::ChannelOpen { channel_type, channel_id } => {
                if let Some(state) = pstate.get_inner_mut::<SshState>() {
                    state.record_channel(channel_type);
                }
                pstate.stage = ParserStage::Data;

                return Some(ParseResult::Complete(
                    Transaction::new(pstate.current_tx_id() + 1, "ssh_channel_open")
                        .with_metadata("channel_type", channel_type.clone())
                        .with_metadata("channel_id", channel_id.to_string())
                        .complete()
                ));
            }
            SshEvent::ChannelRequest { request_type, command, subsystem } => {
                if let Some(state) = pstate.get_inner_mut::<SshState>() {
                    if let Some(cmd) = command {
                        state.record_command(cmd);
                    }
                    if let Some(sub) = subsystem {
                        state.record_subsystem(sub);
                    }
                }

                let mut tx = Transaction::new(pstate.current_tx_id() + 1, "ssh_channel_request")
                    .with_metadata("request_type", request_type.clone());

                if let Some(cmd) = command {
                    tx = tx.with_metadata("command", cmd.clone());
                }
                if let Some(sub) = subsystem {
                    tx = tx.with_metadata("subsystem", sub.clone());
                }

                return Some(ParseResult::Complete(tx.complete()));
            }
            _ => {}
        }

        None
    }
}

impl Default for SshProtocolParser {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl ProtocolParser for SshProtocolParser {
    fn name(&self) -> &'static str { "ssh" }
    fn protocol(&self) -> Protocol { Protocol::Ssh }
    fn default_tcp_ports(&self) -> &'static [u16] { &[22, 2222, 22222] }
    fn default_udp_ports(&self) -> &'static [u16] { &[] }

    fn probe(&self, payload: &[u8], _direction: Direction) -> u8 {
        // Check for SSH version string
        if payload.starts_with(b"SSH-") {
            return 100;
        }

        // Check for SSH binary packet
        if SshParser::is_ssh(payload) {
            return 90;
        }

        0
    }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.is_empty() { return ParseResult::Incomplete; }

        let is_client = matches!(analysis.packet.direction, Direction::ToServer);

        // Initialize state if needed
        if pstate.get_inner::<SshState>().is_none() {
            pstate.set_inner(SshState::new());
        }

        // Try version exchange first
        if payload.starts_with(b"SSH-") {
            if let Some(result) = self.process_version(payload, pstate, is_client) {
                return result;
            }
        }

        // Try binary packet parsing
        if payload.len() >= 5 {
            // Try KEX_INIT
            if let Some(result) = self.process_kex_init(payload, pstate, is_client) {
                return result;
            }

            // Try auth/channel messages
            if let Some(result) = self.process_auth(payload, pstate) {
                return result;
            }
        }

        ParseResult::Incomplete
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> {
        self.matcher.match_rules(state, rules)
    }

    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> {
        state.get_buffer(name)
    }

    fn buffer_names(&self) -> &'static [&'static str] { SSH_KEYWORDS }
    fn reset(&mut self) {
        self.client_parser = SshParser::new(true);
        self.server_parser = SshParser::new(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssh_probe() {
        let parser = SshProtocolParser::new();

        // SSH version string
        assert_eq!(parser.probe(b"SSH-2.0-OpenSSH_8.9p1\r\n", Direction::ToServer), 100);

        // Not SSH
        assert_eq!(parser.probe(b"HTTP/1.1 200 OK", Direction::ToServer), 0);
    }

    #[test]
    fn test_registration() {
        let reg = registration();
        assert_eq!(reg.name, "ssh");
        assert!(reg.tcp_ports.contains(&22));
    }
}
