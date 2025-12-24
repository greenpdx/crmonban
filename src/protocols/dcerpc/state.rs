//! DCE/RPC per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct DceRpcState {
    pub bound_interfaces: Vec<String>,
    pub current_opnum: Option<u16>,
    pub call_id: u32,
    pub suspicious_interface: bool,
    pub suspicious_opnum: bool,
    pub request_count: u32,
}

impl DceRpcState {
    pub fn new() -> Self { Self::default() }
    pub fn add_interface(&mut self, iface: String) { self.bound_interfaces.push(iface); }
}

impl ProtocolStateData for DceRpcState {
    fn as_any(&self) -> &dyn Any { self }
    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}
