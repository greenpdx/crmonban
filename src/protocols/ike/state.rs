//! IKE/IPsec per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct IkeState {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub version: u8,
    pub exchange_type: u8,
    pub is_initiator: bool,
    pub is_response: bool,
    pub vendor_ids: Vec<Vec<u8>>,
    pub aggressive_mode: bool,
    pub message_count: u32,
}

impl IkeState { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for IkeState { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
