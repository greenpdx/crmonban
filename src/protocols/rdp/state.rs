//! RDP per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct RdpState { pub cookie: Option<String>, pub client_name: Option<String>, pub keyboard_layout: u32, pub auth_failures: u32, pub bluekeep_probe: bool, pub connection_requests: u32 }
impl RdpState { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for RdpState { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
