//! Log-Based Feedback System for Detection Tuning
//!
//! This module analyzes service logs (sshd, nginx, postfix, etc.) as ground truth
//! to measure detection accuracy and automatically tune detection parameters.
//!
//! # Architecture
//!
//! ```text
//! Service Logs (Ground Truth)
//!        │
//!        ▼
//!   Log Parsers (sshd, nginx, smtp)
//!        │
//!        ▼
//!   LogEvent { timestamp, src_ip, event_type, ... }
//!        │
//!        ├──────────────────────┐
//!        ▼                      ▼
//!   crmonban Alerts    Correlation Engine
//!        │                      │
//!        └──────────┬───────────┘
//!                   ▼
//!          Feedback Analyzer
//!          (TP/FP/FN rates)
//!                   │
//!                   ▼
//!          Parameter Adjuster
//!          (layer234, http_detect, signatures)
//! ```
//!
//! # Example
//!
//! ```ignore
//! use crmonban::feedback::{FeedbackAnalyzer, FeedbackConfig, SshdLogParser, NginxAccessParser};
//!
//! let config = FeedbackConfig::default();
//! let mut analyzer = FeedbackAnalyzer::new(config);
//!
//! // Add log parsers
//! analyzer.add_parser(Box::new(SshdLogParser::new()));
//! analyzer.add_parser(Box::new(NginxAccessParser::new()));
//!
//! // Run analysis
//! let report = analyzer.analyze("/var/log/auth.log", "/var/log/nginx/access.log")?;
//!
//! // Get recommendations
//! for rec in report.recommendations {
//!     println!("[{}] {}: {}", rec.priority, rec.path, rec.reason);
//! }
//! ```

pub mod log_parsers;
pub mod correlation;
pub mod analyzer;
pub mod adjuster;
pub mod daemon;

pub use log_parsers::{
    LogParser, LogEvent, LogEventType, Service,
    SshdLogParser, NginxAccessParser, NginxErrorParser, PostfixParser,
};
pub use correlation::{CorrelationEngine, CorrelationResult, MatchType};
pub use analyzer::{FeedbackAnalyzer, FeedbackConfig, FeedbackReport, FeedbackSummary, ModuleStats, SafeBounds};
pub use adjuster::{ParameterAdjuster, AdjusterConfig, AdjustmentStrategy, ConfigChange, AdjustmentDirection};
pub use daemon::{FeedbackDaemon, DaemonConfig, DaemonConfigBuilder, ChangeRecord};
