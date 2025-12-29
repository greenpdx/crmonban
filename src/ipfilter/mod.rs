//! IP Filter Library
//!
//! A comprehensive IP filtering system with support for:
//! - Individual IP blocking, watching, and allowing
//! - CIDR network-based filtering
//! - GeoIP-based country filtering
//! - Packet analysis interface using crmonban-types
//!
//! # Example
//!
//! ```rust,no_run
//! use std::net::{IpAddr, Ipv4Addr};
//! use ipfilter::{Packet, IpProtocol, Worker};
//! use ipfilter::filter::{IpFilter, GeoIpFilter};
//!
//! // Create an IP filter with some rules
//! let mut ip_filter = IpFilter::new();
//! ip_filter.block(
//!     IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
//!     "Known bad actor".to_string(),
//! );
//! ip_filter.watch(
//!     IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
//!     "Suspicious activity".to_string(),
//! );
//!
//! // Create a GeoIP filter
//! let mut geoip = GeoIpFilter::new();
//! geoip.block_countries(&["CN", "RU", "KP"]);
//!
//! // Create the worker
//! let worker = Worker::new(ip_filter).with_geoip(geoip);
//!
//! // Analyze a packet
//! let packet = Packet::new(
//!     0,
//!     IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
//!     IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
//!     IpProtocol::Tcp,
//!     "",
//! );
//!
//! let result = worker.analyze(&packet);
//! println!("Verdict: {:?}", result.verdict);
//! ```

pub mod engine;
pub mod filter;

// Re-export from crmonban-types
pub use crate::types::{
    DetectionAction, DetectionEvent, DetectionType, IpProtocol, Packet, PacketAnalysis, Severity,
    StageProcessor,
};

// Local types
pub use engine::{AnalysisResult, IpFilterConfig, IpFilterStage, PacketVerdict, Worker};
pub use filter::{GeoIpFilter, IpFilter, IpStatus};
