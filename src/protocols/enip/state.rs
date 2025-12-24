//! EtherNet/IP per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct EnipState {
    pub command: u16,
    pub session_handle: u32,
    pub status: u32,
    pub cip_service: Option<u8>,
    pub control_detected: bool,
    pub message_count: u32,
}

impl EnipState { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for EnipState { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
