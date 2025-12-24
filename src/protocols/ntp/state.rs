//! NTP per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct NtpState {
    pub version: u8,
    pub mode: u8,
    pub stratum: u8,
    pub monlist_detected: bool,
    pub private_mode: bool,
    pub control_mode: bool,
    pub message_count: u32,
}

impl NtpState { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for NtpState { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
