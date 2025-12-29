//! Engine module for packet processing and analysis
//!
//! This module provides the core worker functionality for analyzing
//! network packets and applying IP filters using crmonban-types.
//!
//! The `Worker` implements the `StageProcessor` trait for pipeline integration.

pub mod worker;

pub use worker::{AnalysisResult, IpFilterConfig, IpFilterStage, PacketVerdict, Worker};
