//! Modbus protocol parser
pub mod types; pub mod state; pub mod match_;
pub use types::*; pub use state::ModbusState; pub use match_::ModbusMatcher;

use async_trait::async_trait;
use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use crate::protocols::{ProtocolParser, ProtocolState, ParseResult, ProtocolAlert, Transaction, ProtocolRuleSet};
use crate::protocols::registry::ProtocolRegistration;

pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration { name: "modbus", protocol: Protocol::Modbus, tcp_ports: &[502], udp_ports: &[],
        create_parser: || Box::new(ModbusParser::new()), priority: 70, keywords: MODBUS_KEYWORDS }
}

pub struct ModbusParser { matcher: ModbusMatcher }
impl ModbusParser { pub fn new() -> Self { Self { matcher: ModbusMatcher::new() } } }
impl Default for ModbusParser { fn default() -> Self { Self::new() } }

#[async_trait]
impl ProtocolParser for ModbusParser {
    fn name(&self) -> &'static str { "modbus" }
    fn protocol(&self) -> Protocol { Protocol::Modbus }
    fn default_tcp_ports(&self) -> &'static [u16] { &[502] }
    fn default_udp_ports(&self) -> &'static [u16] { &[] }
    fn probe(&self, payload: &[u8], _: Direction) -> u8 {
        // Modbus TCP: 7+ bytes, protocol ID should be 0x0000
        if payload.len() >= 8 && payload[2] == 0 && payload[3] == 0 { 80 } else { 0 }
    }

    async fn parse(&mut self, analysis: &PacketAnalysis, pstate: &mut ProtocolState) -> ParseResult {
        let payload = analysis.packet.payload();
        // Modbus TCP header: Transaction ID (2) + Protocol ID (2) + Length (2) + Unit ID (1) + Function (1)
        if payload.len() < 8 { return ParseResult::NotThisProtocol; }
        if payload[2] != 0 || payload[3] != 0 { return ParseResult::NotThisProtocol; } // Protocol ID must be 0

        if pstate.get_inner::<ModbusState>().is_none() { pstate.set_inner(ModbusState::new()); }

        let transaction_id = ((payload[0] as u16) << 8) | payload[1] as u16;
        let unit_id = payload[6];
        let function_code = payload[7];
        let is_exception = function_code & 0x80 != 0;
        let actual_function = function_code & 0x7F;

        pstate.set_buffer("modbus.function", vec![actual_function]);
        pstate.set_buffer("modbus.unit_id", vec![unit_id]);
        if is_exception { pstate.set_buffer("modbus.exception", vec![1]); }

        if let Some(s) = pstate.get_inner_mut::<ModbusState>() {
            s.transaction_id = transaction_id;
            s.unit_id = unit_id;
            s.function_code = actual_function;
            s.is_exception = is_exception;
            s.message_count += 1;
            if DANGEROUS_FUNCTIONS.contains(&actual_function) { s.write_detected = true; }
            if DIAGNOSTIC_FUNCTIONS.contains(&actual_function) { s.diagnostic_detected = true; }
        }

        // Extract address and quantity for read/write operations
        if payload.len() >= 12 && actual_function <= 6 {
            let address = ((payload[8] as u16) << 8) | payload[9] as u16;
            pstate.set_buffer("modbus.address", address.to_be_bytes().to_vec());
            if payload.len() >= 12 {
                let quantity = ((payload[10] as u16) << 8) | payload[11] as u16;
                pstate.set_buffer("modbus.quantity", quantity.to_be_bytes().to_vec());
            }
        }

        pstate.detected = true; pstate.protocol = Some(Protocol::Modbus);
        ParseResult::Complete(Transaction::new(pstate.current_tx_id() + 1, "modbus_msg").complete())
    }

    fn match_rules(&self, state: &ProtocolState, rules: &ProtocolRuleSet<'_>) -> Vec<ProtocolAlert> { self.matcher.match_rules(state, rules) }
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]> { state.get_buffer(name) }
    fn buffer_names(&self) -> &'static [&'static str] { MODBUS_KEYWORDS }
    fn reset(&mut self) {}
}
