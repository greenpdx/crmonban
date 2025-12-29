//! Detection Testing and Feedback Framework
//!
//! Provides comprehensive tools for benchmarking detection accuracy and performance
//! across all pipeline stages, with feedback mechanisms to improve detection.
//!
//! # Modules
//!
//! - `metrics` - Per-stage performance and accuracy metrics
//! - `ground_truth` - Ground truth loading and matching
//! - `synthetic` - Synthetic attack traffic generation
//! - `benchmark` - Benchmark runner for PCAP and synthetic traffic
//! - `report` - Report generation (JSON, Markdown, CSV)
//! - `feedback` - Log analysis and improvement recommendations

pub mod metrics;
pub mod ground_truth;
pub mod synthetic;
pub mod benchmark;
pub mod report;
pub mod feedback;

// Re-export main types
pub use metrics::{StageMetrics, AccuracyMetrics, PerformanceMetrics, MetricsCollector};
pub use ground_truth::{GroundTruth, AttackRecord, MatchResult};
pub use synthetic::{AttackGenerator, AttackType, AttackConfig, MixedTrafficGenerator};
pub use benchmark::{DetectionBenchmark, BenchmarkConfig};
pub use report::{BenchmarkReport, ReportSummary, ReportFormat};
pub use feedback::{
    FeedbackAnalyzer, FeedbackConfig, FeedbackReport, Finding, Recommendation,
    DetectionEventRecord, ConfigChange,
};
