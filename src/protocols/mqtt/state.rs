//! MQTT per-flow state
use std::any::Any;
use crate::protocols::traits::ProtocolStateData;

#[derive(Debug, Default)]
pub struct MqttState {
    pub protocol_version: u8,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub connected: bool,
    pub topics_subscribed: Vec<String>,
    pub topics_published: Vec<String>,
    pub wildcard_subscribe: bool,
    pub sys_topic_access: bool,
    pub message_count: u32,
}

impl MqttState { pub fn new() -> Self { Self::default() } }
impl ProtocolStateData for MqttState { fn as_any(&self) -> &dyn Any { self } fn as_any_mut(&mut self) -> &mut dyn Any { self } }
