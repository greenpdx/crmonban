//! MQTT protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::MqttState; pub use match_::MqttMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "mqtt", protocol: Protocol::Mqtt, tcp_ports: &[1883, 8883], udp_ports: &[],
        create_parser: || Box::new(MqttParser::new()), priority: 70, keywords: MQTT_KEYWORDS }
}

pub struct MqttParser { matcher: MqttMatcher }
impl MqttParser { pub fn new() -> Self { Self { matcher: MqttMatcher::new() } } }
impl Default for MqttParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for MqttParser {
    fn name(&self) -> &'static str { "mqtt" }
    fn protocol(&self) -> Protocol { Protocol::Mqtt }
    fn default_tcp_ports(&self) -> &'static [u16] { &[1883, 8883] }
    fn default_udp_ports(&self) -> &'static [u16] { &[] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 {
        if payload.len() >= 2 {
            let pkt_type = (payload[0] >> 4) & 0x0F;
            if pkt_type >= 1 && pkt_type <= 15 { return 70; }
        }
        0
    }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        if payload.len() < 2 { return ParseResult::NotThisProtocol; }

        let pkt_type = (payload[0] >> 4) & 0x0F;
        if pkt_type < 1 || pkt_type > 15 { return ParseResult::NotThisProtocol; }

        if pstate.get_inner::<MqttState>().is_none() { pstate.set_inner(MqttState::new()); }

        pstate.set_buffer("mqtt.type", vec![pkt_type]);
        pstate.set_buffer("mqtt.flags", vec![payload[0] & 0x0F]);

        // Parse CONNECT packet
        if pkt_type == 1 && payload.len() > 12 {
            if let Some(version_offset) = payload.windows(4).position(|w| w == b"MQTT") {
                if payload.len() > version_offset + 5 {
                    let version = payload[version_offset + 4];
                    pstate.set_buffer("mqtt.protocol_version", vec![version]);
                    if let Some(s) = pstate.get_inner_mut::<MqttState>() { s.protocol_version = version; }
                }
            }
        }

        // Parse PUBLISH packet - extract topic
        if pkt_type == 3 && payload.len() > 4 {
            let remaining_start = if payload[1] & 0x80 != 0 { 3 } else { 2 };
            if payload.len() > remaining_start + 2 {
                let topic_len = ((payload[remaining_start] as usize) << 8) | (payload[remaining_start + 1] as usize);
                if payload.len() > remaining_start + 2 + topic_len {
                    let topic = &payload[remaining_start + 2..remaining_start + 2 + topic_len];
                    pstate.set_buffer("mqtt.publish.topic", topic.to_vec());
                    if let Ok(topic_str) = std::str::from_utf8(topic) {
                        if let Some(s) = pstate.get_inner_mut::<MqttState>() {
                            s.topics_published.push(topic_str.to_string());
                            if topic_str.starts_with("$SYS/") { s.sys_topic_access = true; }
                        }
                    }
                }
            }
        }

        // Parse SUBSCRIBE packet
        if pkt_type == 8 && payload.len() > 6 {
            if let Some(s) = pstate.get_inner_mut::<MqttState>() {
                // Check for wildcard patterns in remaining payload
                if payload.windows(1).any(|w| w == b"#" || w == b"+") { s.wildcard_subscribe = true; }
            }
        }

        pstate.detected = true; pstate.protocol = Some(Protocol::Mqtt);
        if let Some(s) = pstate.get_inner_mut::<MqttState>() { s.message_count += 1; }
        ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "mqtt_msg").complete())
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { MQTT_KEYWORDS }
    fn reset(&mut self) {}
}
