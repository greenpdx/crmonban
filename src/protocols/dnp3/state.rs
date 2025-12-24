//! DNP3 per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct Dnp3State {
    pub source_addr: u16,
    pub dest_addr: u16,
    pub function_code: u8,
    pub control_detected: bool,
    pub restart_detected: bool,
    pub unsolicited_enabled: bool,
    pub message_count: u32,
}

impl Dnp3State { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for Dnp3State { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
