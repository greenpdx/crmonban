//! Detection and configuration types for netvec
//!
//! This module contains detector-specific types used for configuration,
//! internal threat classification, and real-time signature updates.
//!
//! Note: Core detection types (DetectionEvent, DetectionType, etc.) are
//! imported from crmonban-types for pipeline compatibility.

use serde::{Deserialize, Serialize};

// =============================================================================
// Pipeline Stage Types
// =============================================================================

/// Configuration passed to detector stage from pipeline
///
/// This config is passed via the StageProcessor::process() method.
/// The detector also maintains internal config (DetectorConfig) set at build time.
#[derive(Debug, Clone, Default)]
pub struct DetectorStageConfig {
    /// Override anomaly threshold for this packet (if set)
    pub anomaly_threshold_override: Option<f32>,
    /// Override signature threshold for this packet (if set)
    pub signature_threshold_override: Option<f32>,
}

/// Pipeline stage identifier for the detector
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DetectorStage {
    /// Threat detection stage (scans, brute force, DoS, anomalies)
    ThreatDetection,
}

// Feature vector configuration
pub const VECTOR_DIM: usize = 72; // Expanded from 64 to include DoS detection features (64-71)
pub type FeatureVector = [f32; VECTOR_DIM];

// =============================================================================
// Internal Threat Classification Types
// =============================================================================

/// Internal threat type used for heuristic detection before mapping to crmonban-types
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ThreatType {
    PortScan {
        scan_type: ScanType,
        ports_touched: u32,
    },
    BruteForce {
        attempts: u32,
        target_service: String,
    },
    Anomaly {
        deviation_score: f32,
    },
    PingSweep {
        hosts_probed: u32,
    },
    Amplification {
        protocol: String,
        amplification_factor: f32,
    },
    /// SYN flood attack - high rate of SYN packets without completing handshakes
    SynFlood {
        packets_per_sec: f32,
        half_open_connections: u32,
    },
    /// UDP flood attack - high rate of UDP packets overwhelming the target
    UdpFlood {
        packets_per_sec: f32,
        bytes_per_sec: f32,
    },
    /// ICMP flood attack - high rate of ICMP echo requests to single target
    IcmpFlood {
        packets_per_sec: f32,
        target_ip_count: u32,
    },
    /// Connection exhaustion - many half-open connections overwhelming resources
    ConnectionExhaustion {
        connection_rate: f32,
        half_open_ratio: f32,
    },
}

impl ThreatType {
    /// Get the threat type name as a string for config matching
    pub fn name(&self) -> &'static str {
        match self {
            ThreatType::PortScan { .. } => "PortScan",
            ThreatType::BruteForce { .. } => "BruteForce",
            ThreatType::Anomaly { .. } => "Anomaly",
            ThreatType::PingSweep { .. } => "PingSweep",
            ThreatType::Amplification { .. } => "Amplification",
            ThreatType::SynFlood { .. } => "SynFlood",
            ThreatType::UdpFlood { .. } => "UdpFlood",
            ThreatType::IcmpFlood { .. } => "IcmpFlood",
            ThreatType::ConnectionExhaustion { .. } => "ConnectionExhaustion",
        }
    }
}

/// Internal scan type classification
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum ScanType {
    TcpSyn,
    TcpConnect,
    TcpFin,
    TcpXmas,
    TcpNull,
    Udp,
    Unknown,
}

// =============================================================================
// Detector Configuration
// =============================================================================

#[derive(Clone, Debug)]
pub struct DetectorConfig {
    pub scan_detection: bool,
    pub bruteforce_detection: bool,
    pub anomaly_detection: bool,
    pub dos_detection: bool,
    pub anomaly_threshold: f32,
    pub signature_threshold: f32,
    pub window_size_ms: u64,
    pub min_packets_for_detection: usize,
    /// Minimum normalized packet rate to consider as potential DoS (0.1 = 10,000 pps)
    pub dos_min_packet_rate: f32,
    /// Half-open ratio threshold for SYN flood detection
    pub dos_half_open_threshold: f32,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            scan_detection: true,
            bruteforce_detection: true,
            anomaly_detection: true,
            dos_detection: true,
            anomaly_threshold: 0.7,
            signature_threshold: 0.85,
            window_size_ms: 60_000,
            min_packets_for_detection: 10,
            dos_min_packet_rate: 0.1,
            dos_half_open_threshold: 0.7,
        }
    }
}

// =============================================================================
// Real-time Signature Update Types
// =============================================================================

/// Commands for real-time signature updates via channel
#[derive(Debug, Clone)]
pub enum SignatureUpdate {
    /// Add a new signature to the detector
    Add {
        name: String,
        vector: FeatureVector,
    },
    /// Disable a signature by name (keeps in index, marks inactive)
    Disable { name: String },
    /// Re-enable a previously disabled signature
    Enable { name: String },
}

/// Handle for sending signature updates to the detector
///
/// This handle is Clone and can be shared across multiple tasks.
/// Use it to dynamically add or disable signatures at runtime.
///
/// # Example
/// ```ignore
/// let sender = detector.signature_update_channel();
///
/// // Add new signature
/// sender.send(SignatureUpdate::Add {
///     name: "new_attack".to_string(),
///     vector: attack_vector,
/// }).await?;
///
/// // Disable old signature
/// sender.send(SignatureUpdate::Disable {
///     name: "old_signature".to_string(),
/// }).await?;
/// ```
#[derive(Clone)]
pub struct SignatureUpdateSender {
    tx: tokio::sync::mpsc::Sender<SignatureUpdate>,
}

impl SignatureUpdateSender {
    /// Create a new sender from an mpsc sender
    pub fn new(tx: tokio::sync::mpsc::Sender<SignatureUpdate>) -> Self {
        Self { tx }
    }

    /// Send a signature update to the detector
    pub async fn send(&self, update: SignatureUpdate) -> Result<(), tokio::sync::mpsc::error::SendError<SignatureUpdate>> {
        self.tx.send(update).await
    }

    /// Try to send a signature update without waiting
    pub fn try_send(&self, update: SignatureUpdate) -> Result<(), tokio::sync::mpsc::error::TrySendError<SignatureUpdate>> {
        self.tx.try_send(update)
    }
}
