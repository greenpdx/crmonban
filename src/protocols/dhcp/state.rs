//! DHCP per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct DhcpState { pub msg_type: Option<u8>, pub hostname: Option<String>, pub client_id: Option<Vec<u8>>, pub requested_ip: Option<[u8; 4]>, pub assigned_ip: Option<[u8; 4]>, pub server_id: Option<[u8; 4]>, pub rogue_server: bool }
impl DhcpState { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for DhcpState { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
