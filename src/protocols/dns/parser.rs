//! DNS protocol parser
//!
//! Parses DNS queries and responses.

use std::net::{Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;

use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{
    ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction,
    ProtocolRuleSet,
};
use super::types::*;
use super::state::DnsState;
use super::match_::DnsMatcher;

/// DNS config
#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub enabled: bool,
    pub ports: Vec<u16>,
    pub detect_tunneling: bool,
    pub detect_dga: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ports: vec![53, 5353],
            detect_tunneling: true,
            detect_dga: true,
        }
    }
}

/// DNS Protocol Parser
pub struct DnsParser {
    config: DnsConfig,
    matcher: DnsMatcher,
}

impl DnsParser {
    /// Create new DNS parser
    pub fn new() -> Self {
        Self {
            config: DnsConfig::default(),
            matcher: DnsMatcher::new(),
        }
    }

    /// Create with config
    pub fn with_config(config: DnsConfig) -> Self {
        Self {
            config,
            matcher: DnsMatcher::new(),
        }
    }

    /// Parse DNS message from payload
    pub fn parse_message(&self, payload: &[u8]) -> Option<DnsMessage> {
        if payload.len() < 12 {
            return None;
        }

        let id = u16::from_be_bytes([payload[0], payload[1]]);
        let flags = u16::from_be_bytes([payload[2], payload[3]]);

        let is_response = (flags & 0x8000) != 0;
        let opcode = ((flags >> 11) & 0x0F) as u8;
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        let rcode = (flags & 0x000F) as u8;

        let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
        let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;
        let nscount = u16::from_be_bytes([payload[8], payload[9]]) as usize;
        let arcount = u16::from_be_bytes([payload[10], payload[11]]) as usize;

        let mut msg = DnsMessage {
            id,
            is_response,
            opcode,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            rcode,
            ..Default::default()
        };

        let mut offset = 12;

        // Parse questions
        for _ in 0..qdcount {
            if let Some((query, new_offset)) = self.parse_question(payload, offset) {
                msg.queries.push(query);
                offset = new_offset;
            } else {
                break;
            }
        }

        // Parse answers
        for _ in 0..ancount {
            if let Some((answer, new_offset)) = self.parse_resource_record(payload, offset) {
                msg.answers.push(answer);
                offset = new_offset;
            } else {
                break;
            }
        }

        // Parse authority records
        for _ in 0..nscount {
            if let Some((answer, new_offset)) = self.parse_resource_record(payload, offset) {
                msg.authorities.push(answer);
                offset = new_offset;
            } else {
                break;
            }
        }

        // Parse additional records
        for _ in 0..arcount {
            if let Some((answer, new_offset)) = self.parse_resource_record(payload, offset) {
                msg.additionals.push(answer);
                offset = new_offset;
            } else {
                break;
            }
        }

        Some(msg)
    }

    /// Parse a DNS question
    fn parse_question(&self, payload: &[u8], offset: usize) -> Option<(DnsQuery, usize)> {
        let (name, offset) = self.parse_name(payload, offset)?;

        if offset + 4 > payload.len() {
            return None;
        }

        let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let qclass = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);

        Some((
            DnsQuery {
                name,
                qtype: DnsRecordType::from(qtype),
                qclass,
            },
            offset + 4,
        ))
    }

    /// Parse a DNS resource record
    fn parse_resource_record(&self, payload: &[u8], offset: usize) -> Option<(DnsAnswer, usize)> {
        let (name, offset) = self.parse_name(payload, offset)?;

        if offset + 10 > payload.len() {
            return None;
        }

        let rtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let rclass = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
        let ttl = u32::from_be_bytes([
            payload[offset + 4],
            payload[offset + 5],
            payload[offset + 6],
            payload[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]) as usize;

        let rdata_offset = offset + 10;
        if rdata_offset + rdlength > payload.len() {
            return None;
        }

        let rdata = self.parse_rdata(payload, rdata_offset, rdlength, DnsRecordType::from(rtype));

        Some((
            DnsAnswer {
                name,
                rtype: DnsRecordType::from(rtype),
                rclass,
                ttl,
                rdata,
            },
            rdata_offset + rdlength,
        ))
    }

    /// Parse DNS name (handles compression)
    fn parse_name(&self, payload: &[u8], mut offset: usize) -> Option<(String, usize)> {
        let mut name = String::new();
        let mut jumped = false;
        let mut return_offset = offset;
        let mut depth = 0;

        loop {
            if offset >= payload.len() || depth > 10 {
                break;
            }

            let len = payload[offset] as usize;

            if len == 0 {
                if !jumped {
                    return_offset = offset + 1;
                }
                break;
            }

            // Check for compression pointer
            if len & 0xC0 == 0xC0 {
                if offset + 1 >= payload.len() {
                    return None;
                }
                let pointer = (((len & 0x3F) as usize) << 8) | (payload[offset + 1] as usize);
                if !jumped {
                    return_offset = offset + 2;
                }
                offset = pointer;
                jumped = true;
                depth += 1;
                continue;
            }

            offset += 1;
            if offset + len > payload.len() {
                return None;
            }

            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&String::from_utf8_lossy(&payload[offset..offset + len]));
            offset += len;
        }

        Some((name, return_offset))
    }

    /// Parse RDATA based on record type
    fn parse_rdata(&self, payload: &[u8], offset: usize, length: usize, rtype: DnsRecordType) -> DnsRdata {
        let rdata = &payload[offset..offset + length];

        match rtype {
            DnsRecordType::A if length == 4 => {
                DnsRdata::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
            }
            DnsRecordType::AAAA if length == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                DnsRdata::AAAA(Ipv6Addr::from(octets))
            }
            DnsRecordType::CNAME | DnsRecordType::NS | DnsRecordType::PTR => {
                if let Some((name, _)) = self.parse_name(payload, offset) {
                    match rtype {
                        DnsRecordType::CNAME => DnsRdata::CNAME(name),
                        DnsRecordType::NS => DnsRdata::NS(name),
                        DnsRecordType::PTR => DnsRdata::PTR(name),
                        _ => DnsRdata::Unknown(rdata.to_vec()),
                    }
                } else {
                    DnsRdata::Unknown(rdata.to_vec())
                }
            }
            DnsRecordType::MX if length >= 2 => {
                let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
                if let Some((exchange, _)) = self.parse_name(payload, offset + 2) {
                    DnsRdata::MX { preference, exchange }
                } else {
                    DnsRdata::Unknown(rdata.to_vec())
                }
            }
            DnsRecordType::TXT => {
                let mut txt = String::new();
                let mut pos = 0;
                while pos < length {
                    let str_len = rdata[pos] as usize;
                    pos += 1;
                    if pos + str_len <= length {
                        txt.push_str(&String::from_utf8_lossy(&rdata[pos..pos + str_len]));
                        pos += str_len;
                    } else {
                        break;
                    }
                }
                DnsRdata::TXT(txt)
            }
            _ => DnsRdata::Unknown(rdata.to_vec()),
        }
    }

    /// Detect DNS tunneling attempts
    pub fn detect_tunneling(&self, query: &DnsQuery) -> bool {
        let name = &query.name;

        // Check for overly long labels (base64 encoded data)
        let labels: Vec<&str> = name.split('.').collect();
        for label in &labels {
            if label.len() > 63 {
                return true;
            }
            // High entropy in subdomain (likely encoded data)
            if label.len() > 30 {
                let unique: std::collections::HashSet<char> = label.chars().collect();
                let entropy_ratio = unique.len() as f32 / label.len() as f32;
                if entropy_ratio > 0.7 {
                    return true;
                }
            }
        }

        // Check for many subdomains
        if labels.len() > 7 {
            return true;
        }

        // Check for uncommon TXT queries (often used for tunneling)
        if matches!(query.qtype, DnsRecordType::TXT | DnsRecordType::ANY) {
            if name.len() > 100 {
                return true;
            }
        }

        false
    }

    /// Check if domain is in suspicious TLD
    pub fn check_suspicious_tld(&self, domain: &str) -> bool {
        for tld in SUSPICIOUS_TLD {
            if domain.ends_with(tld) {
                return true;
            }
        }
        false
    }
}

impl Default for DnsParser {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProtocolParser for DnsParser {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn protocol(&self) -> Protocol {
        Protocol::Dns
    }

    fn default_tcp_ports(&self) -> &'static [u16] {
        &[53]
    }

    fn default_udp_ports(&self) -> &'static [u16] {
        &[53, 5353]
    }

    fn probe(&self, payload: &[u8], _direction: Direction) -> u8 {
        // Basic DNS header validation
        if payload.len() < 12 {
            return 0;
        }

        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        let ancount = u16::from_be_bytes([payload[6], payload[7]]);

        // Reasonable counts
        if qdcount <= 20 && ancount <= 50 {
            70 // Good confidence for DNS
        } else {
            0
        }
    }

    async fn parse(
        &mut self,
        analysis: &PacketAnalysis,
        pstate: &mut ProtocolState,
    ) -> ParseResult {
        let payload = analysis.packet.payload();

        if payload.is_empty() {
            return ParseResult::Incomplete;
        }

        // Ensure DNS state exists
        if pstate.get_inner::<DnsState>().is_none() {
            pstate.set_inner(DnsState::new());
        }

        let msg = match self.parse_message(payload) {
            Some(m) => m,
            None => return ParseResult::NotThisProtocol,
        };

        // Set buffers for rule matching
        pstate.set_buffer("dns.opcode", vec![msg.opcode]);
        pstate.set_buffer("dns.rcode", vec![msg.rcode]);

        // Set query buffers
        for query in &msg.queries {
            pstate.set_buffer("dns.query", query.name.as_bytes().to_vec());
            pstate.set_buffer("dns.rrname", query.name.as_bytes().to_vec());
            pstate.set_buffer("dns.rrtype", format!("{:?}", query.qtype).into_bytes());
        }

        // Update state
        if let Some(state) = pstate.get_inner_mut::<DnsState>() {
            if msg.is_response {
                state.record_response(&msg);
                state.response_bytes += payload.len() as u64;
            } else {
                for query in &msg.queries {
                    state.record_query(query, msg.id);

                    // Check for tunneling
                    if self.config.detect_tunneling && self.detect_tunneling(query) {
                        state.tunneling_detected = true;
                    }

                    // Check for suspicious TLD
                    if self.check_suspicious_tld(&query.name) {
                        state.suspicious_domains.push(query.name.clone());
                    }
                }
                state.query_bytes += payload.len() as u64;
            }
        }

        pstate.detected = true;
        pstate.protocol = Some(Protocol::Dns);

        let tx_type = if msg.is_response { "dns_response" } else { "dns_query" };
        let tx = Transaction::new(pstate.current_tx_id() + 1, tx_type)
            .with_metadata("id", msg.id.to_string())
            .with_metadata("opcode", msg.opcode.to_string())
            .with_metadata("rcode", msg.rcode.to_string())
            .with_metadata("is_response", msg.is_response.to_string())
            .complete();

        ParseResult::Complete(tx)
    }

    fn match_rules(
        &self,
        state: &ProtocolState,
        rules: &ProtocolRuleSet<'_>,
    ) -> Vec<ProtocolAlert> {
        self.matcher.match_rules(state, rules)
    }

    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> {
        state.get_buffer(name)
    }

    fn buffer_names(&self) -> &'static [&'static str] {
        DNS_KEYWORDS
    }

    fn reset(&mut self) {
        // Parser is stateless
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_query() {
        let parser = DnsParser::new();

        let dns_query = [
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            // Question: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of name
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        let msg = parser.parse_message(&dns_query).unwrap();

        assert_eq!(msg.id, 0x1234);
        assert!(!msg.is_response);
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(msg.queries[0].name, "example.com");
        assert_eq!(msg.queries[0].qtype, DnsRecordType::A);
    }

    #[test]
    fn test_detect_tunneling() {
        let parser = DnsParser::new();

        // Normal query
        let normal = DnsQuery {
            name: "www.example.com".to_string(),
            qtype: DnsRecordType::A,
            qclass: 1,
        };
        assert!(!parser.detect_tunneling(&normal));

        // Many subdomains
        let many_subs = DnsQuery {
            name: "a.b.c.d.e.f.g.h.example.com".to_string(),
            qtype: DnsRecordType::A,
            qclass: 1,
        };
        assert!(parser.detect_tunneling(&many_subs));
    }

    #[test]
    fn test_probe() {
        let parser = DnsParser::new();

        let valid_dns = [
            0x00, 0x01, // ID
            0x01, 0x00, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        assert!(parser.probe(&valid_dns, Direction::ToServer) > 0);

        let invalid = b"not dns";
        assert_eq!(parser.probe(invalid, Direction::ToServer), 0);
    }
}
