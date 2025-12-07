//! Types for WASM plugin interface

use std::net::IpAddr;
use serde::{Deserialize, Serialize};

/// Packet information passed to WASM plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    /// Source IP (as bytes for v4/v6)
    pub src_ip: Vec<u8>,
    /// Is IPv6?
    pub is_ipv6: bool,
    /// Destination port
    pub dst_port: u16,
    /// TCP flags
    pub is_syn: bool,
    pub is_ack: bool,
    pub is_rst: bool,
    /// Payload size
    pub payload_size: u32,
    /// TTL value
    pub ttl: Option<u8>,
}

impl PacketInfo {
    pub fn from_ip(ip: IpAddr, dst_port: u16) -> Self {
        match ip {
            IpAddr::V4(v4) => Self {
                src_ip: v4.octets().to_vec(),
                is_ipv6: false,
                dst_port,
                is_syn: false,
                is_ack: false,
                is_rst: false,
                payload_size: 0,
                ttl: None,
            },
            IpAddr::V6(v6) => Self {
                src_ip: v6.octets().to_vec(),
                is_ipv6: true,
                dst_port,
                is_syn: false,
                is_ack: false,
                is_rst: false,
                payload_size: 0,
                ttl: None,
            },
        }
    }

    pub fn with_syn(mut self) -> Self {
        self.is_syn = true;
        self
    }

    pub fn with_ack(mut self) -> Self {
        self.is_ack = true;
        self
    }

    pub fn with_rst(mut self) -> Self {
        self.is_rst = true;
        self
    }

    pub fn with_payload(mut self, size: u32) -> Self {
        self.payload_size = size;
        self
    }

    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }
}

/// Behavior summary for WASM plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorInfo {
    /// Half-open connections
    pub half_open_count: u32,
    /// Completed connections
    pub completed_count: u32,
    /// Unique ports touched
    pub unique_ports: u32,
    /// SYN rate (per second)
    pub syn_rate: f32,
    /// Current score
    pub current_score: f32,
    /// Sequential scan detected?
    pub has_sequential_pattern: bool,
    /// Duration since first seen (seconds)
    pub duration_secs: u64,
}

impl Default for BehaviorInfo {
    fn default() -> Self {
        Self {
            half_open_count: 0,
            completed_count: 0,
            unique_ports: 0,
            syn_rate: 0.0,
            current_score: 0.0,
            has_sequential_pattern: false,
            duration_secs: 0,
        }
    }
}

/// Result from a WASM rule evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmRuleResult {
    /// Rule ID
    pub rule_id: String,
    /// Score delta
    pub score_delta: f32,
    /// Confidence (0.0 - 1.0)
    pub confidence: f32,
    /// Evidence/reason
    pub evidence: String,
    /// Tags to apply
    pub tags: Vec<String>,
}

impl WasmRuleResult {
    pub fn new(rule_id: &str, score_delta: f32, evidence: &str) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            score_delta,
            confidence: 1.0,
            evidence: evidence.to_string(),
            tags: Vec::new(),
        }
    }

    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }
}

/// Convert WasmRuleResult to RuleResult
impl From<WasmRuleResult> for super::super::rules::RuleResult {
    fn from(wasm: WasmRuleResult) -> Self {
        super::super::rules::RuleResult {
            rule_id: wasm.rule_id,
            score_delta: wasm.score_delta,
            confidence: wasm.confidence,
            evidence: wasm.evidence,
            tags: wasm.tags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_packet_info() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let packet = PacketInfo::from_ip(ip, 80)
            .with_syn()
            .with_payload(100)
            .with_ttl(64);

        assert!(!packet.is_ipv6);
        assert_eq!(packet.dst_port, 80);
        assert!(packet.is_syn);
        assert!(!packet.is_ack);
        assert_eq!(packet.payload_size, 100);
        assert_eq!(packet.ttl, Some(64));
    }

    #[test]
    fn test_wasm_rule_result() {
        let result = WasmRuleResult::new("WASM1", 2.5, "Custom detection")
            .with_confidence(0.9)
            .with_tags(vec!["custom".into()]);

        assert_eq!(result.rule_id, "WASM1");
        assert_eq!(result.score_delta, 2.5);
        assert_eq!(result.confidence, 0.9);
    }
}
