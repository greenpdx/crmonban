//! TLS protocol parser

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{
    ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction,
    ProtocolRuleSet,
};
use super::types::*;
use super::state::TlsState;
use super::match_::TlsMatcher;

/// TLS config
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub ja3_enabled: bool,
    pub ja3s_enabled: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![443, 8443, 993, 995, 465, 636],
            ja3_enabled: true,
            ja3s_enabled: true,
        }
    }
}

/// TLS Protocol Parser
pub struct TlsParser {
    config: TlsConfig,
    matcher: TlsMatcher,
}

impl TlsParser {
    pub fn new() -> Self {
        Self {
            config: TlsConfig::default(),
            matcher: TlsMatcher::new(),
        }
    }

    pub fn with_config(config: TlsConfig) -> Self {
        Self { config, matcher: TlsMatcher::new() }
    }

    fn parse_record<'a>(&self, payload: &'a [u8]) -> Option<(TlsRecordType, TlsVersion, &'a [u8])> {
        if payload.len() < 5 { return None; }
        let record_type = TlsRecordType::from(payload[0]);
        let version = TlsVersion(u16::from_be_bytes([payload[1], payload[2]]));
        let length = u16::from_be_bytes([payload[3], payload[4]]) as usize;
        if payload.len() < 5 + length { return None; }
        Some((record_type, version, &payload[5..5 + length]))
    }

    pub fn parse_client_hello(&self, data: &[u8]) -> Option<TlsHandshake> {
        if data.len() < 38 { return None; }
        let handshake_type = TlsHandshakeType::from(data[0]);
        if handshake_type != TlsHandshakeType::ClientHello { return None; }

        let mut handshake = TlsHandshake::default();
        handshake.version = TlsVersion(u16::from_be_bytes([data[4], data[5]]));

        let mut offset = 38;
        if offset >= data.len() { return Some(handshake); }
        let session_id_len = data[offset] as usize;
        offset += 1 + session_id_len;

        if offset + 2 > data.len() { return Some(handshake); }
        let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + cipher_suites_len > data.len() { return Some(handshake); }
        for i in (0..cipher_suites_len).step_by(2) {
            let suite = u16::from_be_bytes([data[offset + i], data[offset + i + 1]]);
            if !Self::is_grease(suite) { handshake.cipher_suites.push(suite); }
        }
        offset += cipher_suites_len;

        if offset >= data.len() { return Some(handshake); }
        let compression_len = data[offset] as usize;
        offset += 1 + compression_len;

        if offset + 2 > data.len() { return Some(handshake); }
        let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let extensions_end = offset + extensions_len;
        while offset + 4 <= extensions_end && offset + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            if offset + ext_len > data.len() { break; }
            if !Self::is_grease(ext_type) { handshake.extensions.push(ext_type); }

            let ext_data = &data[offset..offset + ext_len];
            match ext_type {
                0 => handshake.sni = self.parse_sni(ext_data),
                10 => handshake.supported_groups = self.parse_groups(ext_data),
                11 => handshake.ec_point_formats = self.parse_formats(ext_data),
                43 => handshake.supported_versions = self.parse_versions(ext_data),
                _ => {}
            }
            offset += ext_len;
        }

        if self.config.ja3_enabled {
            handshake.ja3 = Some(self.compute_ja3(&handshake));
        }
        Some(handshake)
    }

    fn parse_sni(&self, data: &[u8]) -> Option<String> {
        if data.len() < 5 { return None; }
        let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + name_len { return None; }
        String::from_utf8(data[5..5 + name_len].to_vec()).ok()
    }

    fn parse_groups(&self, data: &[u8]) -> Vec<u16> {
        let mut groups = Vec::new();
        if data.len() < 2 { return groups; }
        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        for i in (2..2 + len).step_by(2) {
            if i + 1 < data.len() {
                let g = u16::from_be_bytes([data[i], data[i + 1]]);
                if !Self::is_grease(g) { groups.push(g); }
            }
        }
        groups
    }

    fn parse_formats(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() { return Vec::new(); }
        let len = data[0] as usize;
        data[1..].iter().take(len).copied().collect()
    }

    fn parse_versions(&self, data: &[u8]) -> Vec<u16> {
        let mut versions = Vec::new();
        if data.is_empty() { return versions; }
        let len = data[0] as usize;
        for i in (1..1 + len).step_by(2) {
            if i + 1 < data.len() {
                let v = u16::from_be_bytes([data[i], data[i + 1]]);
                if !Self::is_grease(v) { versions.push(v); }
            }
        }
        versions
    }

    fn compute_ja3(&self, h: &TlsHandshake) -> Ja3Fingerprint {
        let ciphers = h.cipher_suites.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("-");
        let exts = h.extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-");
        let groups = h.supported_groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join("-");
        let formats = h.ec_point_formats.iter().map(|f| f.to_string()).collect::<Vec<_>>().join("-");
        let ja3_string = format!("{},{},{},{},{}", h.version.0, ciphers, exts, groups, formats);
        let hash = format!("{:x}", md5::compute(&ja3_string));
        Ja3Fingerprint { string: ja3_string, hash }
    }

    fn is_grease(val: u16) -> bool { (val & 0x0f0f) == 0x0a0a }
}

impl Default for TlsParser {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl ProtocolParser for TlsParser {
    fn name(&self) -> &'static str { "tls" }
    fn protocol(&self) -> Protocol { Protocol::Tls }
    fn default_tcp_ports(&self) -> &'static [u16] { &[443, 8443, 993, 995, 465, 636] }
    fn default_udp_ports(&self) -> &'static [u16] { &[] }

    fn probe(&self, payload: &[u8], _direction: Direction) -> u8 {
        if payload.len() >= 5 {
            let record_type = payload[0];
            let version = u16::from_be_bytes([payload[1], payload[2]]);
            if record_type == 22 && version >= 0x0300 && version <= 0x0304 { return 100; }
        }
        0
    }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.is_empty() { return ParseResult::Incomplete; }
        if pstate.get_inner::<TlsState>().is_none() { pstate.set_inner(TlsState::new()); }

        let (record_type, _version, record_data) = match self.parse_record(payload) {
            Some(r) => r,
            None => return ParseResult::NotThisProtocol,
        };

        if record_type != TlsRecordType::Handshake || record_data.is_empty() {
            return ParseResult::Incomplete;
        }

        let handshake_type = TlsHandshakeType::from(record_data[0]);
        let is_client = matches!(analysis.packet.direction, Direction::ToServer);

        if handshake_type == TlsHandshakeType::ClientHello && is_client {
            if let Some(handshake) = self.parse_client_hello(record_data) {
                if let Some(ref sni) = handshake.sni {
                    pstate.set_buffer("tls.sni", sni.as_bytes().to_vec());
                }
                if let Some(ref ja3) = handshake.ja3 {
                    pstate.set_buffer("ja3.hash", ja3.hash.as_bytes().to_vec());
                    pstate.set_buffer("ja3.string", ja3.string.as_bytes().to_vec());
                }

                if let Some(state) = pstate.get_inner_mut::<TlsState>() {
                    state.record_client_hello(&handshake);
                }

                pstate.detected = true;
                pstate.protocol = Some(Protocol::Tls);
                return ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "tls_client_hello").complete());
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

    fn buffer_names(&self) -> &'static [&'static str] { TLS_KEYWORDS }
    fn reset(&mut self) {}
}
