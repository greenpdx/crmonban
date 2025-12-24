//! Modbus per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct ModbusState {
    pub unit_id: u8,
    pub function_code: u8,
    pub transaction_id: u16,
    pub is_exception: bool,
    pub write_detected: bool,
    pub diagnostic_detected: bool,
    pub message_count: u32,
}

impl ModbusState { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for ModbusState { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
