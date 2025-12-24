//! SIP per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct SipState { pub method: Option<String>, pub uri: Option<String>, pub from: Option<String>, pub to: Option<String>, pub call_id: Option<String>, pub status_code: Option<u16>, pub toll_fraud: bool, pub invite_count: u32 }
impl SipState { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for SipState { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
