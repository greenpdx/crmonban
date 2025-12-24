//! RFB/VNC per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct RfbState {
    pub server_version: Option<String>,
    pub client_version: Option<String>,
    pub security_type: u8,
    pub security_result: Option<u32>,
    pub desktop_name: Option<String>,
    pub weak_auth: bool,
    pub authenticated: bool,
}

impl RfbState { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for RfbState { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
