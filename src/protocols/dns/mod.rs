//! DNS protocol analyzer
//!
//! Parses DNS queries and responses.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::core::{Flow, Packet};
use super::{DnsConfig, ProtocolAnalyzer, ProtocolEvent};

// Re-export types from crmonban-types
pub use crmonban_types::{DnsMessage, DnsQuery, DnsAnswer, DnsRecordType, DnsRdata};

/// DNS protocol analyzer
pub struct DnsAnalyzer {
    config: DnsConfig,
}

impl DnsAnalyzer {
    pub fn new(config: DnsConfig) -> Self {
        Self { config }
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
                // TXT records have length-prefixed strings
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
            // Additional heuristics for TXT tunneling
            if name.len() > 100 {
                return true;
            }
        }

        false
    }
}

impl ProtocolAnalyzer for DnsAnalyzer {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn detect(&self, payload: &[u8], port: u16) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Check port
        if self.config.ports.contains(&port) {
            // Basic validation of DNS header
            if payload.len() >= 12 {
                let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
                // Reasonable number of questions
                if qdcount <= 10 {
                    return true;
                }
            }
        }

        false
    }

    fn parse(&self, packet: &Packet, flow: &mut Flow) -> Option<ProtocolEvent> {
        if !self.config.enabled || packet.payload().is_empty() {
            return None;
        }

        let msg = self.parse_message(&packet.payload())?;

        // Store query names in flow
        for query in &msg.queries {
            flow.set_app_data("dns.query", serde_json::json!(&query.name));
            flow.set_app_data("dns.qtype", serde_json::json!(query.qtype.to_string()));

            // Check for tunneling
            if self.config.detect_tunneling && self.detect_tunneling(query) {
                flow.add_tag("dns_tunneling_suspect");
                flow.risk_score = (flow.risk_score + 0.5).min(1.0);
            }
        }

        // Store answer IPs
        for answer in &msg.answers {
            if let DnsRdata::A(ip) = &answer.rdata {
                flow.set_app_data("dns.answer_a", serde_json::json!(ip.to_string()));
            }
            if let DnsRdata::AAAA(ip) = &answer.rdata {
                flow.set_app_data("dns.answer_aaaa", serde_json::json!(ip.to_string()));
            }
        }

        Some(ProtocolEvent::Dns(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_query() {
        let config = DnsConfig::default();
        let analyzer = DnsAnalyzer::new(config);

        // DNS query for example.com type A
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

        let msg = analyzer.parse_message(&dns_query).unwrap();

        assert_eq!(msg.id, 0x1234);
        assert!(!msg.is_response);
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(msg.queries[0].name, "example.com");
        assert_eq!(msg.queries[0].qtype, DnsRecordType::A);
    }

    #[test]
    fn test_detect_tunneling() {
        let config = DnsConfig::default();
        let analyzer = DnsAnalyzer::new(config);

        // Normal query
        let normal = DnsQuery {
            name: "www.example.com".to_string(),
            qtype: DnsRecordType::A,
            qclass: 1,
        };
        assert!(!analyzer.detect_tunneling(&normal));

        // Suspicious query (very long TXT record - triggers name.len() > 100 check)
        let suspicious = DnsQuery {
            name: "abcdefghij.klmnopqrst.uvwxyz0123.456789abcd.efghijklmn.opqrstuvwx.yzABCDEFGH.IJKLMNOPQR.tunnel.example.com".to_string(),
            qtype: DnsRecordType::TXT,
            qclass: 1,
        };
        assert!(analyzer.detect_tunneling(&suspicious));
    }
}
