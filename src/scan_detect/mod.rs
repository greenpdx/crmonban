//! Probabilistic Scan Detection Module
//!
//! Replaces simple threshold-based detection with a probabilistic scoring system that:
//! - Tracks connection states (half-open vs completed)
//! - Weights different behaviors differently
//! - Detects network issues vs actual attacks
//! - Actively verifies suspected attackers
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                        Probabilistic Scan Engine                            │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │  Connection State Tracker → Scoring Engine → Network Health Monitor        │
//! │           ↓                       ↓                    ↓                    │
//! │  Per-IP State Machine      Alert Generator      Active Verifier            │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```

pub mod behavior;
pub mod config;
pub mod engine;
pub mod rules;

// Re-exports
pub use behavior::{SourceBehavior, ConnectionState, Classification};
pub use config::{ScanDetectConfig, ScoreThresholds, RuleWeights};
pub use engine::{ScanDetectEngine, ScanAlert, AlertType, NetworkHealth};
pub use rules::{DetectionRule, RuleResult, RuleCategory, EvaluationContext};
pub use rules::{GeoInfo, ReputationData, NetworkHealthContext};
