//! Core protocol parser traits and types
//!
//! Defines the unified interface for all protocol parsers.

use std::any::Any;
use std::collections::HashMap;

use async_trait::async_trait;

use crate::core::{PacketAnalysis, Direction};
use crate::signatures::ast::Protocol;
use super::alerts::{ParseResult, ProtocolAlert};
use super::rules::ProtocolRuleSet;

/// Core protocol parser trait
///
/// All protocol parsers must implement this trait to integrate with
/// the protocol analysis pipeline.
#[async_trait]
pub trait ProtocolParser: Send + Sync {
    /// Protocol identifier (e.g., "smb", "ftp", "dcerpc")
    fn name(&self) -> &'static str;

    /// Protocol enum for rule filtering
    fn protocol(&self) -> Protocol;

    /// Default TCP ports for this protocol
    fn default_tcp_ports(&self) -> &'static [u16];

    /// Default UDP ports for this protocol
    fn default_udp_ports(&self) -> &'static [u16];

    /// Probe payload to detect if it matches this protocol
    ///
    /// Returns confidence score 0-100:
    /// - 0: Not this protocol
    /// - 1-50: Possible match
    /// - 51-99: Likely match
    /// - 100: Certain match
    fn probe(&self, payload: &[u8], direction: Direction) -> u8;

    /// Parse packet and update protocol state
    ///
    /// # Arguments
    /// * `analysis` - The packet being analyzed (borrowed)
    /// * `state` - Per-flow protocol state
    ///
    /// # Returns
    /// ParseResult indicating success, need more data, or fatal error
    async fn parse(
        &mut self,
        analysis: &PacketAnalysis,
        state: &mut ProtocolState,
    ) -> ParseResult;

    /// Match Suricata rules against current protocol state
    ///
    /// Called after successful parse to generate alerts
    fn match_rules(
        &self,
        state: &ProtocolState,
        rules: &ProtocolRuleSet<'_>,
    ) -> Vec<ProtocolAlert>;

    /// Get named buffer for rule matching
    ///
    /// Returns the buffer content for keywords like "smb.share", "http.uri"
    fn get_buffer<'a>(&self, name: &str, state: &'a ProtocolState) -> Option<&'a [u8]>;

    /// List all buffer names this protocol exposes
    ///
    /// Used for rule validation and documentation
    fn buffer_names(&self) -> &'static [&'static str];

    /// Reset parser for new flow
    fn reset(&mut self);
}

/// Per-flow protocol state
pub struct ProtocolState {
    /// Protocol-specific state data
    pub inner: Option<Box<dyn ProtocolStateData>>,

    /// Named buffers for rule matching (populated during parse)
    /// Maps buffer name (e.g., "smb.share") to content
    pub buffers: HashMap<&'static str, Vec<u8>>,

    /// Completed transactions
    pub transactions: Vec<Transaction>,

    /// Current transaction ID
    pub tx_id: u64,

    /// Parser stage
    pub stage: ParserStage,

    /// Total bytes parsed (to_server direction)
    pub bytes_to_server: u64,

    /// Total bytes parsed (to_client direction)
    pub bytes_to_client: u64,

    /// Protocol was positively detected (vs assumed by port)
    pub detected: bool,

    /// Flow has been closed/completed
    pub closed: bool,

    /// Protocol that was detected
    pub protocol: Option<Protocol>,
}

impl ProtocolState {
    /// Create new empty state
    pub fn new() -> Self {
        Self {
            inner: None,
            buffers: HashMap::new(),
            transactions: Vec::new(),
            tx_id: 0,
            stage: ParserStage::Init,
            bytes_to_server: 0,
            bytes_to_client: 0,
            detected: false,
            closed: false,
            protocol: None,
        }
    }

    /// Set buffer value for rule matching
    pub fn set_buffer(&mut self, name: &'static str, value: Vec<u8>) {
        self.buffers.insert(name, value);
    }

    /// Get buffer value
    pub fn get_buffer(&self, name: &str) -> Option<&[u8]> {
        self.buffers.get(name).map(|v| v.as_slice())
    }

    /// Clear all buffers (between transactions)
    pub fn clear_buffers(&mut self) {
        self.buffers.clear();
    }

    /// Get typed inner state
    pub fn get_inner<T: ProtocolStateData + 'static>(&self) -> Option<&T> {
        self.inner.as_ref()?.as_any().downcast_ref::<T>()
    }

    /// Get typed inner state mutably
    pub fn get_inner_mut<T: ProtocolStateData + 'static>(&mut self) -> Option<&mut T> {
        self.inner.as_mut()?.as_any_mut().downcast_mut::<T>()
    }

    /// Set inner state
    pub fn set_inner<T: ProtocolStateData + 'static>(&mut self, state: T) {
        self.inner = Some(Box::new(state));
    }

    /// Add completed transaction
    pub fn add_transaction(&mut self, tx: Transaction) {
        self.tx_id += 1;
        self.transactions.push(tx);
    }

    /// Get current transaction ID
    pub fn current_tx_id(&self) -> u64 {
        self.tx_id
    }
}

impl Default for ProtocolState {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for protocol-specific state data
pub trait ProtocolStateData: Send + Sync {
    /// Get as Any for downcasting
    fn as_any(&self) -> &dyn Any;

    /// Get as Any mut for downcasting
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Parser processing stage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParserStage {
    /// Initial connection, no data parsed
    #[default]
    Init,
    /// Protocol negotiation/handshake
    Handshake,
    /// Authentication phase
    Auth,
    /// Normal data exchange
    Data,
    /// Connection closing
    Closing,
    /// Error state (fatal)
    Error,
}

/// Completed protocol transaction
#[derive(Debug, Clone)]
pub struct Transaction {
    /// Transaction ID within flow
    pub id: u64,

    /// Transaction type (protocol-specific)
    pub tx_type: String,

    /// Request data (if applicable)
    pub request: Option<Vec<u8>>,

    /// Response data (if applicable)
    pub response: Option<Vec<u8>>,

    /// Transaction completed successfully
    pub complete: bool,

    /// Timestamp (epoch millis)
    pub timestamp: u64,

    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl Transaction {
    /// Create new transaction
    pub fn new(id: u64, tx_type: impl Into<String>) -> Self {
        Self {
            id,
            tx_type: tx_type.into(),
            request: None,
            response: None,
            complete: false,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            metadata: HashMap::new(),
        }
    }

    /// Set request data
    pub fn with_request(mut self, data: Vec<u8>) -> Self {
        self.request = Some(data);
        self
    }

    /// Set response data
    pub fn with_response(mut self, data: Vec<u8>) -> Self {
        self.response = Some(data);
        self
    }

    /// Mark as complete
    pub fn complete(mut self) -> Self {
        self.complete = true;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestState {
        value: u32,
    }

    impl ProtocolStateData for TestState {
        fn as_any(&self) -> &dyn Any { self }
        fn as_any_mut(&mut self) -> &mut dyn Any { self }
    }

    #[test]
    fn test_protocol_state_buffers() {
        let mut state = ProtocolState::new();
        state.set_buffer("test.buffer", vec![1, 2, 3]);

        assert_eq!(state.get_buffer("test.buffer"), Some(&[1u8, 2, 3][..]));
        assert_eq!(state.get_buffer("nonexistent"), None);
    }

    #[test]
    fn test_protocol_state_inner() {
        let mut state = ProtocolState::new();
        state.set_inner(TestState { value: 42 });

        let inner = state.get_inner::<TestState>().unwrap();
        assert_eq!(inner.value, 42);
    }

    #[test]
    fn test_transaction() {
        let tx = Transaction::new(1, "request")
            .with_request(vec![1, 2, 3])
            .with_metadata("key", "value")
            .complete();

        assert_eq!(tx.id, 1);
        assert_eq!(tx.tx_type, "request");
        assert!(tx.complete);
        assert_eq!(tx.metadata.get("key"), Some(&"value".to_string()));
    }
}
