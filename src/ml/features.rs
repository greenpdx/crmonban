//! Feature extraction from network flows
//!
//! Extracts CICIDS2017-compatible features for ML-based anomaly detection.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::flow::Flow;
use crate::core::packet::{AppProtocol, IpProtocol};

/// Standard feature names (subset of CICIDS2017 features applicable to flow data)
pub const FEATURE_NAMES: &[&str] = &[
    // Basic flow features
    "duration_ms",
    "protocol_type",
    "src_bytes",
    "dst_bytes",
    "total_packets",
    "src_packets",
    "dst_packets",

    // Packet size statistics
    "avg_packet_size",
    "min_packet_size",
    "max_packet_size",
    "std_packet_size",

    // Byte rate features
    "bytes_per_second",
    "packets_per_second",
    "src_bytes_per_second",
    "dst_bytes_per_second",

    // TCP flag features (if TCP)
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "urg_count",
    "syn_rate",
    "fin_rate",
    "rst_rate",

    // Inter-arrival time features
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",

    // Flow direction features
    "fwd_bwd_ratio",
    "bytes_ratio",

    // Connection features (from window)
    "same_dst_count",
    "same_src_count",
    "same_srv_count",
    "diff_srv_count",

    // Protocol-specific
    "is_tcp",
    "is_udp",
    "is_icmp",

    // Port-based service detection
    "dst_port_category",
    "is_well_known_port",
];

/// Number of features extracted
pub const NUM_FEATURES: usize = 39;

/// Extracted feature vector from a flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureVector {
    /// Feature values
    pub features: Vec<f32>,
    /// Flow ID for reference
    pub flow_id: u64,
    /// Timestamp of extraction
    pub timestamp: DateTime<Utc>,
    /// Original protocol
    pub protocol: AppProtocol,
}

impl FeatureVector {
    /// Get feature by name
    pub fn get(&self, name: &str) -> Option<f32> {
        FEATURE_NAMES.iter()
            .position(|&n| n == name)
            .and_then(|idx| self.features.get(idx).copied())
    }

    /// Get all features as a slice
    pub fn as_slice(&self) -> &[f32] {
        &self.features
    }

    /// Number of features
    pub fn len(&self) -> usize {
        self.features.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.features.is_empty()
    }
}

/// Record for connection window tracking (optimized - no String allocations)
#[derive(Debug, Clone, Copy)]
struct ConnectionRecord {
    timestamp: DateTime<Utc>,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
    #[allow(dead_code)]
    protocol: AppProtocol,
}

/// Feature extractor with window-based connection tracking
pub struct FeatureExtractor {
    /// Recent connections for rate features
    connection_window: VecDeque<ConnectionRecord>,
    /// Window duration for connection tracking
    window_duration: Duration,
    /// Maximum window size
    max_window_size: usize,
}

impl Default for FeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl FeatureExtractor {
    /// Create a new feature extractor
    pub fn new() -> Self {
        Self {
            connection_window: VecDeque::with_capacity(1000),
            window_duration: Duration::from_secs(120), // 2-minute window
            max_window_size: 10000,
        }
    }

    /// Create with custom window settings
    pub fn with_window(window_duration: Duration, max_size: usize) -> Self {
        Self {
            connection_window: VecDeque::with_capacity(max_size.min(1000)),
            window_duration,
            max_window_size: max_size,
        }
    }

    /// Extract features from a flow
    pub fn extract(&mut self, flow: &Flow) -> FeatureVector {
        let mut features = Vec::with_capacity(NUM_FEATURES);
        let now = Utc::now();

        // Clean up old entries from window
        self.cleanup_window(now);

        // Basic flow features
        let duration_ms = flow.duration().as_millis() as f32;
        let total_packets = flow.total_packets().max(1);
        let total_bytes = flow.total_bytes();

        features.push(duration_ms);                                    // duration_ms
        features.push(ip_protocol_to_numeric(flow.protocol));          // protocol_type
        features.push(flow.fwd_bytes as f32);                          // src_bytes
        features.push(flow.bwd_bytes as f32);                          // dst_bytes
        features.push(total_packets as f32);                           // total_packets
        features.push(flow.fwd_packets as f32);                        // src_packets
        features.push(flow.bwd_packets as f32);                        // dst_packets

        // Packet size statistics
        let avg_pkt_size = total_bytes as f32 / total_packets as f32;
        let (min_pkt, max_pkt, std_pkt_size) = compute_packet_size_stats(flow);
        features.push(avg_pkt_size);                                   // avg_packet_size
        features.push(min_pkt as f32);                                 // min_packet_size
        features.push(max_pkt as f32);                                 // max_packet_size
        features.push(std_pkt_size);                                   // std_packet_size

        // Rate features
        let duration_secs = (duration_ms / 1000.0).max(0.001);
        features.push(total_bytes as f32 / duration_secs);             // bytes_per_second
        features.push(total_packets as f32 / duration_secs);           // packets_per_second
        features.push(flow.fwd_bytes as f32 / duration_secs);          // src_bytes_per_second
        features.push(flow.bwd_bytes as f32 / duration_secs);          // dst_bytes_per_second

        // TCP flag features (use actual flow counters)
        let total_flags = (flow.syn_count + flow.ack_count + flow.fin_count
            + flow.rst_count + flow.psh_count + flow.urg_count).max(1) as f32;
        features.push(flow.syn_count as f32);                          // syn_count
        features.push(flow.ack_count as f32);                          // ack_count
        features.push(flow.fin_count as f32);                          // fin_count
        features.push(flow.rst_count as f32);                          // rst_count
        features.push(flow.psh_count as f32);                          // psh_count
        features.push(flow.urg_count as f32);                          // urg_count
        features.push(flow.syn_count as f32 / total_flags);            // syn_rate
        features.push(flow.fin_count as f32 / total_flags);            // fin_rate
        features.push(flow.rst_count as f32 / total_flags);            // rst_rate

        // Inter-arrival time features
        let (iat_mean, iat_std, iat_min, iat_max) = compute_iat_stats(flow);
        features.push(iat_mean);                                       // iat_mean
        features.push(iat_std);                                        // iat_std
        features.push(iat_min);                                        // iat_min
        features.push(iat_max);                                        // iat_max

        // Flow direction features
        let fwd_bwd_ratio = if flow.bwd_packets > 0 {
            flow.fwd_packets as f32 / flow.bwd_packets as f32
        } else {
            flow.fwd_packets as f32
        };
        let bytes_ratio = if flow.bwd_bytes > 0 {
            flow.fwd_bytes as f32 / flow.bwd_bytes as f32
        } else {
            flow.fwd_bytes as f32
        };
        features.push(fwd_bwd_ratio);                                  // fwd_bwd_ratio
        features.push(bytes_ratio);                                    // bytes_ratio

        // Connection window features
        let (same_dst, same_src, same_srv, diff_srv) = self.compute_window_features(flow);
        features.push(same_dst as f32);                                // same_dst_count
        features.push(same_src as f32);                                // same_src_count
        features.push(same_srv as f32);                                // same_srv_count
        features.push(diff_srv as f32);                                // diff_srv_count

        // Protocol flags
        features.push(if flow.protocol == IpProtocol::Tcp { 1.0 } else { 0.0 }); // is_tcp
        features.push(if flow.protocol == IpProtocol::Udp { 1.0 } else { 0.0 }); // is_udp
        features.push(if flow.protocol == IpProtocol::Icmp { 1.0 } else { 0.0 }); // is_icmp

        // Port-based features
        let port_category = categorize_port(flow.server_port);
        features.push(port_category);                                  // dst_port_category
        features.push(if flow.server_port < 1024 { 1.0 } else { 0.0 }); // is_well_known_port

        // Add this connection to the window
        self.add_to_window(flow, now);

        FeatureVector {
            features,
            flow_id: flow.id,
            timestamp: now,
            protocol: flow.app_protocol,
        }
    }

    /// Clean up old entries from the connection window
    fn cleanup_window(&mut self, now: DateTime<Utc>) {
        let cutoff = now - chrono::Duration::from_std(self.window_duration)
            .unwrap_or(chrono::Duration::seconds(120));

        while let Some(front) = self.connection_window.front() {
            if front.timestamp < cutoff {
                self.connection_window.pop_front();
            } else {
                break;
            }
        }
    }

    /// Add a connection to the window (no allocations)
    #[inline]
    fn add_to_window(&mut self, flow: &Flow, timestamp: DateTime<Utc>) {
        if self.connection_window.len() >= self.max_window_size {
            self.connection_window.pop_front();
        }

        self.connection_window.push_back(ConnectionRecord {
            timestamp,
            src_ip: flow.client_ip,
            dst_ip: flow.server_ip,
            dst_port: flow.server_port,
            protocol: flow.app_protocol,
        });
    }

    /// Compute window-based connection features (optimized - direct IpAddr comparison)
    #[inline]
    fn compute_window_features(&self, flow: &Flow) -> (u32, u32, u32, u32) {
        let dst_ip = flow.server_ip;
        let src_ip = flow.client_ip;
        let dst_port = flow.server_port;

        let mut same_dst = 0u32;
        let mut same_src = 0u32;
        let mut same_srv = 0u32;
        let mut diff_srv = 0u32;

        for record in &self.connection_window {
            if record.dst_ip == dst_ip {
                same_dst += 1;
            }
            if record.src_ip == src_ip {
                same_src += 1;
                if record.dst_port == dst_port {
                    same_srv += 1;
                } else {
                    diff_srv += 1;
                }
            }
        }

        (same_dst, same_src, same_srv, diff_srv)
    }

    /// Get current window size
    pub fn window_size(&self) -> usize {
        self.connection_window.len()
    }

    /// Clear the connection window
    pub fn clear_window(&mut self) {
        self.connection_window.clear();
    }
}

/// Compute packet size statistics from flow (uses streaming stats)
fn compute_packet_size_stats(flow: &Flow) -> (u16, u16, f32) {
    let fwd = &flow.fwd_pkt_stats;
    let bwd = &flow.bwd_pkt_stats;

    if fwd.count == 0 && bwd.count == 0 {
        return (0, 0, 0.0);
    }

    // Combine min/max from both directions
    let min_pkt = if fwd.count > 0 && bwd.count > 0 {
        fwd.min.min(bwd.min) as u16
    } else if fwd.count > 0 {
        fwd.min as u16
    } else {
        bwd.min as u16
    };

    let max_pkt = if fwd.count > 0 && bwd.count > 0 {
        fwd.max.max(bwd.max) as u16
    } else if fwd.count > 0 {
        fwd.max as u16
    } else {
        bwd.max as u16
    };

    // Combined std dev (approximation using pooled variance)
    let total_count = fwd.count + bwd.count;
    let combined_std = if total_count > 1 {
        let fwd_var = fwd.std().powi(2) * fwd.count as f32;
        let bwd_var = bwd.std().powi(2) * bwd.count as f32;
        ((fwd_var + bwd_var) / total_count as f32).sqrt()
    } else {
        0.0
    };

    (min_pkt, max_pkt, combined_std)
}

/// Compute inter-arrival time statistics from flow (uses streaming stats)
fn compute_iat_stats(flow: &Flow) -> (f32, f32, f32, f32) {
    let fwd = &flow.fwd_iat_stats;
    let bwd = &flow.bwd_iat_stats;

    if fwd.count == 0 && bwd.count == 0 {
        return (0.0, 0.0, 0.0, 0.0);
    }

    // Combine min/max from both directions
    let min_iat = if fwd.count > 0 && bwd.count > 0 {
        fwd.min.min(bwd.min)
    } else if fwd.count > 0 {
        fwd.min
    } else {
        bwd.min
    };

    let max_iat = if fwd.count > 0 && bwd.count > 0 {
        fwd.max.max(bwd.max)
    } else if fwd.count > 0 {
        fwd.max
    } else {
        bwd.max
    };

    // Combined mean (weighted average)
    let total_count = fwd.count + bwd.count;
    let combined_mean = if total_count > 0 {
        (fwd.mean * fwd.count as f32 + bwd.mean * bwd.count as f32) / total_count as f32
    } else {
        0.0
    };

    // Combined std dev (approximation using pooled variance)
    let combined_std = if total_count > 1 {
        let fwd_var = fwd.std().powi(2) * fwd.count as f32;
        let bwd_var = bwd.std().powi(2) * bwd.count as f32;
        ((fwd_var + bwd_var) / total_count as f32).sqrt()
    } else {
        0.0
    };

    (combined_mean, combined_std, min_iat, max_iat)
}

/// Convert IP protocol to numeric value
fn ip_protocol_to_numeric(protocol: IpProtocol) -> f32 {
    match protocol {
        IpProtocol::Tcp => 6.0,
        IpProtocol::Udp => 17.0,
        IpProtocol::Icmp => 1.0,
        IpProtocol::Icmpv6 => 58.0,
        IpProtocol::Other(n) => n as f32,
    }
}

/// Convert application protocol to numeric value
#[allow(dead_code)]
fn app_protocol_to_numeric(protocol: AppProtocol) -> f32 {
    match protocol {
        AppProtocol::Http => 1.0,
        AppProtocol::Https => 2.0,
        AppProtocol::Dns => 3.0,
        AppProtocol::Ssh => 4.0,
        AppProtocol::Ftp => 5.0,
        AppProtocol::Smtp => 6.0,
        AppProtocol::Imap => 7.0,
        AppProtocol::Pop3 => 8.0,
        AppProtocol::Telnet => 9.0,
        AppProtocol::Rdp => 10.0,
        AppProtocol::Smb => 11.0,
        AppProtocol::Mysql => 12.0,
        AppProtocol::Postgres => 13.0,
        AppProtocol::Redis => 14.0,
        AppProtocol::Ldap => 15.0,
        AppProtocol::Ntp => 16.0,
        AppProtocol::Snmp => 17.0,
        AppProtocol::Sip => 18.0,
        AppProtocol::Unknown => 0.0,
        _ => 0.0, // Catch any new variants
    }
}

/// Extract TCP flag counts from flow
#[allow(dead_code)]
fn extract_tcp_flags(flow: &Flow) -> (u32, u32, u32, u32, u32, u32) {
    // These would ideally come from accumulated flag counts in the flow
    // For now, estimate from flow state
    let total = flow.total_packets() as u32;

    // Estimate based on typical TCP behavior
    let syn = if total > 0 { 1 } else { 0 };
    let ack = total.saturating_sub(1);
    let fin = if flow.is_complete() { 2 } else { 0 };
    let rst = 0;
    let psh = total / 4; // Estimate ~25% of packets have PSH
    let urg = 0;

    (syn, ack, fin, rst, psh, urg)
}

/// Categorize port into service categories
fn categorize_port(port: u16) -> f32 {
    match port {
        20 | 21 => 1.0,        // FTP
        22 => 2.0,             // SSH
        23 => 3.0,             // Telnet
        25 | 465 | 587 => 4.0, // SMTP
        53 => 5.0,             // DNS
        80 | 8080 => 6.0,      // HTTP
        110 | 995 => 7.0,      // POP3
        143 | 993 => 8.0,      // IMAP
        443 | 8443 => 9.0,     // HTTPS
        3306 => 10.0,          // MySQL
        3389 => 11.0,          // RDP
        5432 => 12.0,          // PostgreSQL
        6379 => 13.0,          // Redis
        _ if port < 1024 => 14.0,   // Other well-known
        _ if port < 49152 => 15.0,  // Registered
        _ => 16.0,             // Dynamic/ephemeral
    }
}

/// Normalize a feature vector to [0, 1] range using provided min/max
pub fn normalize_features(features: &mut FeatureVector, min: &[f32], max: &[f32]) {
    for (i, f) in features.features.iter_mut().enumerate() {
        if i < min.len() && i < max.len() {
            let range = max[i] - min[i];
            if range > 0.0 {
                *f = (*f - min[i]) / range;
            } else {
                *f = 0.0;
            }
        }
    }
}

/// Standardize features (z-score normalization)
pub fn standardize_features(features: &mut FeatureVector, mean: &[f32], std: &[f32]) {
    for (i, f) in features.features.iter_mut().enumerate() {
        if i < mean.len() && i < std.len() && std[i] > 0.0 {
            *f = (*f - mean[i]) / std[i];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::core::packet::{Packet, IpProtocol};

    fn make_test_flow() -> Flow {
        let mut pkt = Packet::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpProtocol::Tcp,
        );
        if let Some(tcp) = pkt.tcp_mut() {
            tcp.src_port = 54321;
            tcp.dst_port = 80;
        }
        pkt.raw_len = 100;

        let mut flow = Flow::new(1, &pkt);
        // Use actual Flow fields
        flow.fwd_bytes = 1000;
        flow.bwd_bytes = 5000;
        flow.fwd_packets = 10;
        flow.bwd_packets = 20;
        // Add some packet sizes using streaming stats
        for size in [40.0, 100.0, 200.0, 500.0] {
            flow.fwd_pkt_stats.update(size);
        }
        for size in [60.0, 150.0, 300.0, 1500.0] {
            flow.bwd_pkt_stats.update(size);
        }
        flow
    }

    #[test]
    fn test_feature_extraction() {
        let mut extractor = FeatureExtractor::new();
        let flow = make_test_flow();

        let features = extractor.extract(&flow);

        assert_eq!(features.len(), NUM_FEATURES);
        assert_eq!(features.flow_id, 1);

        // Check some specific features
        assert!(features.get("src_bytes").unwrap() > 0.0);
        assert!(features.get("dst_bytes").unwrap() > 0.0);
        assert!(features.get("total_packets").unwrap() == 30.0);
    }

    #[test]
    fn test_window_tracking() {
        let mut extractor = FeatureExtractor::new();
        let flow = make_test_flow();

        // Extract multiple times to build up window
        for _ in 0..5 {
            extractor.extract(&flow);
        }

        assert_eq!(extractor.window_size(), 5);

        // Subsequent extractions should show same_dst > 0
        let features = extractor.extract(&flow);
        assert!(features.get("same_dst_count").unwrap() > 0.0);
    }

    #[test]
    fn test_port_categorization() {
        assert_eq!(categorize_port(80), 6.0);   // HTTP
        assert_eq!(categorize_port(443), 9.0);  // HTTPS
        assert_eq!(categorize_port(22), 2.0);   // SSH
        assert_eq!(categorize_port(53), 5.0);   // DNS
        assert!(categorize_port(50000) > 14.0); // High port
    }

    #[test]
    fn test_feature_normalization() {
        let mut features = FeatureVector {
            features: vec![100.0, 50.0, 200.0],
            flow_id: 1,
            timestamp: Utc::now(),
            protocol: AppProtocol::Unknown,
        };

        let min = vec![0.0, 0.0, 0.0];
        let max = vec![200.0, 100.0, 400.0];

        normalize_features(&mut features, &min, &max);

        assert!((features.features[0] - 0.5).abs() < 0.001);
        assert!((features.features[1] - 0.5).abs() < 0.001);
        assert!((features.features[2] - 0.5).abs() < 0.001);
    }
}
