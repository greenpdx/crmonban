//! # NetVec
//!
//! A scan and brute force detection library using vector similarity with crvecdb.
//!
//! ## Features
//!
//! - **Scan Detection**: TCP SYN, Connect, FIN, Xmas, Null, UDP scans
//! - **Brute Force Detection**: Authentication attack patterns
//! - **Anomaly Detection**: Baseline-based deviation detection
//! - **ICMP Analysis**: Ping sweeps, traceroute detection
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use layer2detect::{Detector, PacketAnalysis, Packet};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> layer2detect::Result<()> {
//!     // Create detector with builder
//!     let mut detector = Detector::builder()
//!         .with_scan_detection(true)
//!         .with_anomaly_detection(true)
//!         .with_window_size(Duration::from_secs(60))
//!         .build()?;
//!
//!     // Subscribe to detection events
//!     let mut rx = detector.detection_stream();
//!
//!     // Process packets via PacketAnalysis (pipeline stage interface)
//!     // let mut analysis = PacketAnalysis::new(packet);
//!     // detector.process(&mut analysis).await;
//!
//!     Ok(())
//! }
//! ```

pub mod aggregator;
pub mod config;
pub mod detector;
pub mod error;
pub mod features;
pub mod output;
pub mod parser;
pub mod session;
pub mod store;
pub mod tls;
pub mod types;
pub mod weights;

// Re-export types from crmonban-types (pipeline interface)
pub use crate::types::{
    // Core pipeline types
    PacketAnalysis, FlowControl, StageProcessor,
    // Detection events
    DetectionEvent, DetectionType, DetectionAction, Severity,
    // Packet types
    Packet, Direction, IpProtocol, TcpFlags, TlsInfo,
    // Layer types
    Layer3, Layer4, EthernetInfo,
    Ipv4Info, Ipv6Info, TcpInfo, UdpInfo, IcmpInfo, Icmpv6Info,
    // Flow types
    Flow, FlowKey, FlowState, FlowStats,
    // Protocols
    AppProtocol,
};

// Re-export sub-types from event module
pub use crate::types::event::{
    DetectionSubType, ScanSubType, DosSubType, AnomalySubType, CustomSubType,
};

// Re-export main library types
pub use self::config::{Config, BruteForceSettings, ScanSettings, SignatureConfig};
pub use self::detector::{Detector, DetectorBuilder};
pub use self::error::{NetVecError, Result};
pub use self::parser::{parse_packet, parse_ip_packet};
pub use self::store::{BaselineStore, SearchResult, SignatureStore, VectorStore};

// Re-export detector-specific types (kept local)
pub use self::types::{
    DetectorConfig, DetectorStage, DetectorStageConfig, FeatureVector, ScanType,
    SignatureUpdate, SignatureUpdateSender, ThreatType, VECTOR_DIM,
};

// Re-export features for custom vector generation
pub use self::features::WindowStats;

// Re-export aggregator for custom processing
pub use self::aggregator::{AggregatedWindow, Aggregator};

// Re-export detailed TLS parsing types (for advanced use)
pub use self::tls::{ClientHelloInfo, TlsInfo as DetailedTlsInfo};

// Re-export session types (Direction is internal to session tracking)
pub use self::session::{
    Direction as SessionDirection, SessionEvent, SessionKey, SessionTracker,
    SessionTrackerStats, TcpSession, TcpState,
};

// Re-export detection weights
pub use self::weights::DetectionWeights;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn test_create_detector() {
        let detector = Detector::builder()
            .with_scan_detection(true)
            .with_bruteforce_detection(true)
            .with_anomaly_detection(true)
            .with_anomaly_threshold(0.7)
            .with_window_size(Duration::from_secs(60))
            .build();

        assert!(detector.is_ok());
    }

    #[test]
    fn test_manual_signature() {
        let mut detector = Detector::builder().build().unwrap();

        // Create a SYN scan signature vector
        let mut syn_scan_vector = [0.0f32; VECTOR_DIM];
        syn_scan_vector[1] = 0.5; // Many unique ports
        syn_scan_vector[12] = 0.95; // High SYN ratio
        syn_scan_vector[13] = 0.02; // Low SYN-ACK ratio
        syn_scan_vector[17] = 0.9; // High half-open ratio

        let id = detector
            .add_signature(&syn_scan_vector, "tcp_syn_scan".to_string())
            .unwrap();
        assert_eq!(id, 0);
        assert_eq!(detector.signature_count(), 1);
    }

    #[tokio::test]
    async fn test_baseline_training() {
        let mut detector = Detector::builder()
            .with_min_packets(1)
            .with_window_size(Duration::from_millis(100))
            .build()
            .unwrap();

        // Create some "normal" traffic packets using crmonban-types Packet
        let normal_packets: Vec<Packet> = (0..10)
            .map(|i| {
                let mut pkt = Packet::new(
                    i,
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    IpProtocol::Tcp,
                    "lo",
                );
                if let Some(tcp) = pkt.tcp_mut() {
                    tcp.dst_port = 80;
                    tcp.flags = TcpFlags {
                        syn: i % 3 == 0,
                        ack: i % 3 != 0,
                        ..Default::default()
                    };
                }
                pkt
            })
            .collect();

        detector.train_baseline(normal_packets).await.unwrap();
        assert!(detector.baseline_count() > 0);
    }

    #[test]
    fn test_window_stats() {
        let mut stats = WindowStats::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        for i in 0..20 {
            let mut pkt = Packet::new(
                i,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, (i % 10) as u8 + 1)),
                IpProtocol::Tcp,
                "lo",
            );
            if let Some(tcp) = pkt.tcp_mut() {
                tcp.dst_port = 1000 + i as u16;
                tcp.flags = TcpFlags {
                    syn: true,
                    ..Default::default()
                };
            }
            stats.add_packet(pkt);
        }

        let vector = stats.extract_features();
        assert_eq!(vector.len(), VECTOR_DIM);

        // Check that SYN ratio is high (index 12)
        assert!(vector[12] > 0.9, "Expected high SYN ratio, got {}", vector[12]);
    }
}
