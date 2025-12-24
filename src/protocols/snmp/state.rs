//! SNMP per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct SnmpState { pub version: u8, pub community: Option<String>, pub default_community: bool, pub pdu_types: Vec<u8> }
impl SnmpState { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for SnmpState { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
