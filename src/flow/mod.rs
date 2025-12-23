//! Flow tracking engine
//!
//! Tracks bidirectional TCP/UDP/ICMP flows, computes statistics,
//! and provides flow context for other analyzers.
//!
//! # Features
//!
//! - Connection state tracking (TCP state machine)
//! - Bidirectional statistics (packets, bytes, timing)
//! - Flow timeout management
//! - ML feature extraction (CICIDS2017 compatible)
//!
//! # Example
//!
//! ```ignore
//! use crmonban::flow::{FlowTracker, FlowConfig};
//!
//! let config = FlowConfig::default();
//! let mut tracker = FlowTracker::new(config);
//!
//! // Process packet
//! let (flow, direction) = tracker.process(&packet);
//!
//! // Get flow statistics
//! let stats = flow.stats();
//! ```

pub mod tracker;
pub mod table;

pub use tracker::FlowTracker;
pub use table::FlowTable;

use serde::{Deserialize, Serialize};
use std::time::Duration;

// Re-export core flow types
pub use crate::core::{Flow, FlowKey, FlowState, FlowStats, Direction};

/// Minimum reassembly buffer size (64 KB)
pub const MIN_REASSEMBLY_BUFFER_KB: usize = 64;
/// Maximum reassembly buffer size (1 MB)
pub const MAX_REASSEMBLY_BUFFER_KB: usize = 1024;

/// Configuration for flow tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowConfig {
    /// Enable flow tracking
    pub enabled: bool,

    /// Maximum concurrent flows
    pub table_size: usize,

    /// TCP established timeout (seconds)
    pub timeout_tcp_established: u64,

    /// TCP idle (pre-established) timeout (seconds)
    pub timeout_tcp_idle: u64,

    /// TCP time-wait timeout (seconds)
    pub timeout_tcp_time_wait: u64,

    /// UDP timeout (seconds)
    pub timeout_udp: u64,

    /// ICMP timeout (seconds)
    pub timeout_icmp: u64,

    /// Enable TCP stream reassembly
    pub enable_reassembly: bool,

    /// Maximum reassembly buffer per flow in KB (64-1024)
    /// Configurable from 64KB to 1MB
    pub max_reassembly_buffer_kb: usize,

    /// Export closed flows to database
    pub export_on_close: bool,

    /// Cleanup interval (seconds)
    pub cleanup_interval: u64,

    /// Track per-packet timing for ML
    pub track_timing: bool,

    /// Maximum packets to track for timing
    pub max_timing_packets: usize,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            table_size: 1_000_000,
            timeout_tcp_established: 3600,    // 1 hour
            timeout_tcp_idle: 300,             // 5 minutes
            timeout_tcp_time_wait: 120,        // 2 minutes
            timeout_udp: 180,                  // 3 minutes
            timeout_icmp: 30,                  // 30 seconds
            enable_reassembly: false,
            max_reassembly_buffer_kb: 64,      // 64 KB default
            export_on_close: true,
            cleanup_interval: 30,              // 30 seconds
            track_timing: true,
            max_timing_packets: 1000,
        }
    }
}

impl FlowConfig {
    /// Get reassembly buffer size in bytes, clamped to valid range (64KB-1MB)
    pub fn reassembly_buffer_bytes(&self) -> usize {
        let kb = self.max_reassembly_buffer_kb
            .max(MIN_REASSEMBLY_BUFFER_KB)
            .min(MAX_REASSEMBLY_BUFFER_KB);
        kb * 1024
    }

    /// Get timeout for a flow based on protocol and state
    pub fn timeout_for(&self, flow: &Flow) -> Duration {
        use crate::core::IpProtocol;

        match flow.protocol {
            IpProtocol::Tcp => {
                match flow.state {
                    FlowState::Established => Duration::from_secs(self.timeout_tcp_established),
                    FlowState::TimeWait => Duration::from_secs(self.timeout_tcp_time_wait),
                    _ => Duration::from_secs(self.timeout_tcp_idle),
                }
            }
            IpProtocol::Udp => Duration::from_secs(self.timeout_udp),
            IpProtocol::Icmp | IpProtocol::Icmpv6 => Duration::from_secs(self.timeout_icmp),
            _ => Duration::from_secs(self.timeout_udp),
        }
    }
}

/// Flow tracking statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrackerStats {
    /// Total flows created
    pub flows_created: u64,
    /// Total flows expired
    pub flows_expired: u64,
    /// Current active flows
    pub active_flows: usize,
    /// Packets processed
    pub packets_processed: u64,
    /// Bytes processed
    pub bytes_processed: u64,
    /// Flow table collisions
    pub table_collisions: u64,
    /// Flows rejected (table full)
    pub flows_rejected: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = FlowConfig::default();
        assert!(config.enabled);
        assert_eq!(config.table_size, 1_000_000);
        assert_eq!(config.timeout_tcp_established, 3600);
    }
}
