//! Type definitions for crmonban network security pipeline
//!
//! This crate provides the core type definitions used for packet analysis,
//! flow tracking, and detection events in the crmonban NIDS.
//!
//! ## Stage Flow
//!
//! ```text
//! nfqueue stream → Stage1 → Stage2 → Stage3 → Stage4 → Stage5 → output
//!                    ↓        ↓        ↓        ↓        ↓
//!                 detect   detect   detect   detect   detect
//!                    ↓        ↓        ↓        ↓        ↓
//!                    └──────────────→ alert analyzer ─→ block
//!                                          │              OR
//!                                          └─ "maybe" ──→ next stage
//! ```
//!
//! ## Key Types
//!
//! - [`PacketAnalysis`] - Analysis context passed between pipeline stages
//! - [`Packet`] - Unified packet representation with strongly-typed layers
//! - [`Flow`] - Bidirectional flow tracking with streaming statistics
//! - [`DetectionEvent`] - Unified detection/alert event format

pub mod packet;
pub mod layers;
pub mod flow;
pub mod event;
pub mod analysis;
pub mod protocols;
pub mod pipeline;

// Re-export all public types at crate root
pub use packet::{Packet, IpProtocol, TcpFlags, TlsInfo, Direction};
pub use layers::{
    Layer3, Layer4, EthernetInfo,
    Ipv4Info, Ipv6Info,
    TcpInfo, UdpInfo, IcmpInfo, Icmpv6Info,
};
pub use flow::{Flow, FlowKey, FlowState, FlowStats, StreamingStats};
pub use event::{DetectionEvent, DetectionType, DetectionAction, Severity, ThreatIntelInfo};
pub use analysis::{PacketAnalysis, FlowControl};
pub use protocols::{
    AppProtocol, ProtocolEvent,
    HttpTransaction, HttpRequest, HttpResponse,
    DnsMessage, DnsQuery, DnsAnswer, DnsRecordType, DnsRdata,
    TlsEvent, Ja3Fingerprint,
};
pub use pipeline::{StageProcessor, AlertAnalyzer, AlertAnalyzerConfig, AnalyzerDecision};
