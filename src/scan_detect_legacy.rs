//! Port Scan Detection Module
//!
//! Behavioral detection of port scanning by tracking unique destination ports
//! per source IP. Detects both horizontal scans (many ports) and targeted scans
//! (focusing on commonly exploited services).
//!
//! # Example
//! ```ignore
//! use crmonban::scan_detect::{PortScanTracker, ScanType};
//!
//! let mut tracker = PortScanTracker::new();
//!
//! // Track connection attempts
//! if let Some(alert) = tracker.track(src_ip, dst_port, is_syn) {
//!     println!("Scan detected from {}: {} unique ports", alert.src_ip, alert.unique_ports);
//! }
//! ```

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Configuration for port scan detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDetectConfig {
    /// Threshold for number of unique ports to trigger alert
    pub port_threshold: usize,
    /// Time window for tracking (ports outside window are forgotten)
    pub window_duration: Duration,
    /// Enable tracking of commonly targeted ports
    pub track_targeted_ports: bool,
}

impl Default for ScanDetectConfig {
    fn default() -> Self {
        Self {
            port_threshold: 10,
            window_duration: Duration::from_secs(60),
            track_targeted_ports: true,
        }
    }
}

/// Port scan detection - tracks unique destination ports per source IP
#[derive(Debug)]
pub struct PortScanTracker {
    /// Map of source IP to tracked port data
    sources: HashMap<IpAddr, SourcePortData>,
    /// Configuration
    config: ScanDetectConfig,
    /// Commonly targeted ports (weight scans targeting these higher)
    targeted_ports: HashSet<u16>,
    /// Total scan alerts triggered
    total_alerts: usize,
}

/// Per-source tracking data
#[derive(Debug)]
struct SourcePortData {
    /// Set of unique destination ports touched
    ports: HashSet<u16>,
    /// When tracking started for this source
    first_seen: Instant,
    /// Whether alert has already been triggered
    alerted: bool,
}

impl SourcePortData {
    fn new() -> Self {
        Self {
            ports: HashSet::new(),
            first_seen: Instant::now(),
            alerted: false,
        }
    }
}

impl PortScanTracker {
    /// Create a new port scan tracker with default configuration
    pub fn new() -> Self {
        Self::with_config(ScanDetectConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: ScanDetectConfig) -> Self {
        // 45+ commonly targeted ports by hackers/scanners
        let targeted_ports: HashSet<u16> = [
            21,    // FTP
            22,    // SSH
            23,    // Telnet
            25,    // SMTP
            53,    // DNS
            80,    // HTTP
            110,   // POP3
            111,   // RPC/Portmapper
            135,   // MSRPC
            139,   // NetBIOS Session
            143,   // IMAP
            161,   // SNMP
            179,   // BGP
            389,   // LDAP
            443,   // HTTPS
            445,   // SMB/CIFS
            465,   // SMTPS
            514,   // Syslog
            587,   // SMTP Submission
            636,   // LDAPS
            993,   // IMAPS
            995,   // POP3S
            1080,  // SOCKS Proxy
            1433,  // MSSQL
            1521,  // Oracle DB
            1723,  // PPTP VPN
            2049,  // NFS
            2082,  // cPanel
            2083,  // cPanel SSL
            2181,  // ZooKeeper
            3306,  // MySQL
            3389,  // RDP
            5432,  // PostgreSQL
            5900,  // VNC
            5938,  // TeamViewer
            6379,  // Redis
            6667,  // IRC
            8000,  // HTTP Alt
            8080,  // HTTP Proxy
            8443,  // HTTPS Alt
            9200,  // Elasticsearch
            9300,  // Elasticsearch
            11211, // Memcached
            27017, // MongoDB
            27018, // MongoDB
        ].into_iter().collect();

        Self {
            sources: HashMap::new(),
            config,
            targeted_ports,
            total_alerts: 0,
        }
    }

    /// Track a connection attempt and check for scanning
    ///
    /// Returns a ScanAlert if this connection triggers the scan detection threshold
    pub fn track(&mut self, src_ip: IpAddr, dst_port: u16, is_syn: bool) -> Option<ScanAlert> {
        // Only track SYN packets or existing tracked sources
        if !is_syn && !self.sources.contains_key(&src_ip) {
            return None;
        }

        let data = self.sources.entry(src_ip).or_insert_with(SourcePortData::new);

        // Check if window has expired - reset if so
        if data.first_seen.elapsed() > self.config.window_duration {
            data.ports.clear();
            data.first_seen = Instant::now();
            data.alerted = false;
        }

        data.ports.insert(dst_port);

        // Check if threshold exceeded and not already alerted
        if data.ports.len() >= self.config.port_threshold && !data.alerted {
            data.alerted = true;
            self.total_alerts += 1;

            // Count how many are commonly targeted ports
            let targeted_count = data.ports.iter()
                .filter(|p| self.targeted_ports.contains(p))
                .count();

            let scan_type = if targeted_count > data.ports.len() / 2 {
                ScanType::Targeted
            } else {
                ScanType::Horizontal
            };

            return Some(ScanAlert {
                src_ip,
                unique_ports: data.ports.len(),
                targeted_ports: targeted_count,
                scan_type,
                ports: data.ports.iter().copied().collect(),
            });
        }

        None
    }

    /// Check if a port is commonly targeted
    pub fn is_targeted_port(&self, port: u16) -> bool {
        self.targeted_ports.contains(&port)
    }

    /// Get total scan alerts triggered
    pub fn total_alerts(&self) -> usize {
        self.total_alerts
    }

    /// Get number of tracked sources
    pub fn tracked_sources(&self) -> usize {
        self.sources.len()
    }

    /// Get top scanners by unique port count
    pub fn top_scanners(&self, limit: usize) -> Vec<(IpAddr, usize)> {
        let mut scanners: Vec<_> = self.sources.iter()
            .map(|(ip, data)| (*ip, data.ports.len()))
            .collect();
        scanners.sort_by(|a, b| b.1.cmp(&a.1));
        scanners.truncate(limit);
        scanners
    }

    /// Get ports touched by a specific source
    pub fn get_source_ports(&self, src_ip: &IpAddr) -> Option<&HashSet<u16>> {
        self.sources.get(src_ip).map(|d| &d.ports)
    }

    /// Clear all tracking data
    pub fn clear(&mut self) {
        self.sources.clear();
        self.total_alerts = 0;
    }

    /// Remove expired entries (older than window duration)
    pub fn cleanup_expired(&mut self) {
        self.sources.retain(|_, data| {
            data.first_seen.elapsed() <= self.config.window_duration
        });
    }

    /// Get the set of commonly targeted ports
    pub fn targeted_ports(&self) -> &HashSet<u16> {
        &self.targeted_ports
    }
}

impl Default for PortScanTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Type of scan detected
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanType {
    /// Scanning common/targeted ports specifically
    Targeted,
    /// Horizontal scan across many ports
    Horizontal,
}

/// Port scan alert
#[derive(Debug, Clone)]
pub struct ScanAlert {
    /// Source IP performing the scan
    pub src_ip: IpAddr,
    /// Number of unique destination ports touched
    pub unique_ports: usize,
    /// Number of commonly targeted ports touched
    pub targeted_ports: usize,
    /// Type of scan detected
    pub scan_type: ScanType,
    /// List of ports touched
    pub ports: Vec<u16>,
}

impl ScanAlert {
    /// Get severity level (1-10) based on scan characteristics
    pub fn severity(&self) -> u8 {
        let mut severity = 3u8; // Base severity

        // More ports = higher severity
        if self.unique_ports >= 100 {
            severity += 3;
        } else if self.unique_ports >= 50 {
            severity += 2;
        } else if self.unique_ports >= 20 {
            severity += 1;
        }

        // Targeted scans are more concerning
        if self.scan_type == ScanType::Targeted {
            severity += 2;
        }

        severity.min(10)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_scan_tracker_basic() {
        let mut tracker = PortScanTracker::new();
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        // Should not alert for fewer than threshold ports
        for port in 1..10 {
            assert!(tracker.track(src, port, true).is_none());
        }

        // Should alert when reaching threshold
        let alert = tracker.track(src, 10, true);
        assert!(alert.is_some());
        assert_eq!(alert.unwrap().unique_ports, 10);
    }

    #[test]
    fn test_scan_tracker_targeted() {
        let mut tracker = PortScanTracker::new();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Scan commonly targeted ports - alert triggers on 10th port
        let targeted = [21, 22, 23, 25, 53, 80, 110, 135, 139];
        for port in targeted {
            assert!(tracker.track(src, port, true).is_none());
        }

        // 10th port triggers the alert
        let alert = tracker.track(src, 443, true);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.scan_type, ScanType::Targeted);
    }

    #[test]
    fn test_scan_tracker_horizontal() {
        let mut tracker = PortScanTracker::new();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Scan random high ports
        for port in 50000..50011 {
            tracker.track(src, port, true);
        }

        let scanners = tracker.top_scanners(1);
        assert_eq!(scanners.len(), 1);
        assert_eq!(scanners[0].1, 11);
    }

    #[test]
    fn test_scan_tracker_no_duplicate_alerts() {
        let mut tracker = PortScanTracker::new();
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 10 ports should trigger alert
        for port in 1..=10 {
            tracker.track(src, port, true);
        }

        // Additional ports should not trigger another alert
        for port in 11..=20 {
            assert!(tracker.track(src, port, true).is_none());
        }

        assert_eq!(tracker.total_alerts(), 1);
    }

    #[test]
    fn test_is_targeted_port() {
        let tracker = PortScanTracker::new();
        assert!(tracker.is_targeted_port(22));  // SSH
        assert!(tracker.is_targeted_port(3389)); // RDP
        assert!(!tracker.is_targeted_port(12345)); // Random
    }
}
