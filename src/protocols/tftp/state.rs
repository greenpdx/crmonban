//! TFTP per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct TftpState {
    pub filename: Option<String>,
    pub mode: Option<String>,
    pub opcode: u16,
    pub is_write: bool,
    pub suspicious_file: bool,
    pub block_count: u32,
}

impl TftpState { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for TftpState { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
