//! CR Monban HTTP Attack Detection Library
//!
//! Provides web attack detection using Aho-Corasick pattern matching
//! and regex-based detection rules.
//!
//! # Example
//!
//! ```ignore
//! use crmonban_detection::{DetectionEngine, ScanReport};
//!
//! let engine = DetectionEngine::from_file("patterns.json")?;
//! let report = engine.scan_request("GET", "/api?id=1", &headers, None);
//! if report.should_block() {
//!     // Block the request
//! }
//! ```

pub mod detection_rules;
pub mod packet_processor;

// Re-export main types
pub use detection_rules::{
    DetectionEngine, DetectionResult, ScanReport, FastScanResult,
    AttackPatternDb, PatternCategory, RateLimit,
    SeverityScore, ActionPriority,
};

pub use packet_processor::{
    PacketProcessor, PacketVerdict, IpTracker, AlertLogger,
};

// Re-export crmonban-types for convenience
pub use crate::types::{Severity, DetectionAction as Action};
