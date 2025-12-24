//! Kerberos per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct KerberosState { pub cname: Option<String>, pub sname: Option<String>, pub realm: Option<String>, pub msg_type: Option<u8>, pub encryption_types: Vec<i32>, pub weak_encryption: bool, pub ticket_requests: u32, pub kerberoasting: bool, pub golden_ticket: bool }
impl KerberosState { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for KerberosState { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
