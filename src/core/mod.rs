//! Core shared types for packet processing and detection
//!
//! Provides unified data structures used by all analysis engines:
//! - `Packet`: Unified packet representation
//! - `Flow`: Connection flow tracking
//! - `DetectionEvent`: Detection/alert events
//! - `layers`: Strongly-typed network layer structs
//! - `parser`: Modular packet parsing functions

pub mod parser;

// Re-export all types from crmonban-types
pub use crmonban_types::{
    // Layers
    Layer3, Layer4, EthernetInfo,
    Ipv4Info, Ipv6Info,
    TcpInfo, UdpInfo, IcmpInfo, Icmpv6Info,
    // Packet
    Packet, TcpFlags, IpProtocol, Direction, TlsInfo,
    // Flow
    Flow, FlowState, FlowKey, FlowStats, StreamingStats,
    // Event
    DetectionEvent, DetectionType, DetectionAction, Severity, ThreatIntelInfo,
    // Analysis
    PacketAnalysis, FlowControl,
    // Protocols
    AppProtocol,
    // Pipeline (AlertAnalyzer only - StageProcessor imported directly from crmonban_types)
    AlertAnalyzer, AlertAnalyzerConfig, AnalyzerDecision,
};

// Re-export parser types
pub use parser::{parse_ethernet_packet, parse_ip_packet, IpInfo, TransportInfo};

/// Common trait for protocol-specific metadata
pub trait ProtocolMetadata: Send + Sync + std::fmt::Debug {
    fn protocol_name(&self) -> &'static str;
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Hash computation for JA3/HASSH fingerprints
#[cfg(feature = "protocols")]
pub fn compute_md5_hex(input: &str) -> String {
    let digest = md5::compute(input.as_bytes());
    format!("{:x}", digest)
}
