//! SSH protocol analyzer
//!
//! Provides comprehensive SSH protocol analysis including:
//! - Version exchange parsing
//! - Key exchange (KEXINIT) parsing
//! - HASSH fingerprinting for client/server identification
//! - Authentication tracking
//! - Brute force detection (per-IP)
//! - Vulnerable version detection (CVE database)
//! - Weak algorithm detection
//!
//! # Architecture
//!
//! The SSH analyzer integrates with the protocol analysis pipeline:
//!
//! ```text
//! Packet → Layer2Detect (SSH detection) → ProtocolAnalysis (SSH parsing)
//!                                                 ↓
//!                                         SshAnalyzer
//!                                                 ↓
//!                             ┌──────────────────┼──────────────────┐
//!                             ↓                  ↓                  ↓
//!                       CVE Lookup        HASSH Lookup       Auth Tracking
//!                             ↓                  ↓                  ↓
//!                       Detections ─────────────────────────────────→
//! ```
//!
//! # Example
//!
//! ```ignore
//! use crmonban::protocols::ssh::{SshAnalyzer, SshAnalyzerConfig};
//!
//! let config = SshAnalyzerConfig::default();
//! let mut analyzer = SshAnalyzer::new(config);
//!
//! // Analyze SSH event
//! let detections = analyzer.analyze(&ssh_event, src_ip, flow_id);
//! for detection in detections {
//!     println!("{:?}: {}", detection.detection_type, detection.description);
//! }
//! ```

pub mod cve;
pub mod hassh;
pub mod parser;
pub mod analyzer;

pub use analyzer::{SshAnalyzer, SshAnalyzerConfig, SshAnalyzerStats, SshDetection};
pub use cve::{SshCveDatabase, CveEntry, CveSeverity, SemVer, CveLookupResult};
pub use hassh::{HasshDatabase, HasshEntry, HasshCategory, HasshLookupResult, HasshVectorDb};
pub use parser::{SshParser, SshMsgType, WEAK_KEX_ALGORITHMS, WEAK_CIPHERS, WEAK_MACS};

// Re-export types from crmonban-types
pub use crmonban_types::protocols::{
    SshEvent, SshAuthMethod, SshNegotiatedAlgorithms, SshVersionInfo, HasshFingerprint,
};
