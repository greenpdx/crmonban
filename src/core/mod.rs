//! Core shared types for packet processing and detection
//!
//! Provides unified data structures used by all analysis engines:
//! - `Packet`: Unified packet representation
//! - `Flow`: Connection flow tracking
//! - `DetectionEvent`: Detection/alert events
//! - `layers`: Strongly-typed network layer structs
//! - `parser`: Modular packet parsing functions

pub mod analysis;
pub mod layers;
pub mod packet;
pub mod flow;
pub mod event;
pub mod parser;

pub use layers::{
    Layer3, Layer4, EthernetInfo,
    Ipv4Info, Ipv6Info,
    TcpInfo, UdpInfo, IcmpInfo, Icmpv6Info,
};
pub use packet::{Packet, TcpFlags, IpProtocol, Direction};
pub use flow::{Flow, FlowState, FlowKey, FlowStats};
pub use event::{DetectionEvent, DetectionType, DetectionAction, Severity};
pub use parser::{parse_ethernet_packet, parse_ip_packet, IpInfo, TransportInfo};
pub use analysis::{PacketAnalysis, FlowControl};

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
