//! Ground truth loading and matching for detection benchmarking
//!
//! Supports multiple ground truth formats:
//! - Simple CSV (timestamp, src_ip, dst_ip, attack_type, severity)
//! - CICIDS2017 format
//! - IP-based attack windows

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{DetectionEvent, DetectionType, Severity};

/// Result of matching a detection against ground truth
#[derive(Debug, Clone, PartialEq)]
pub enum MatchResult {
    /// True positive - detection matches known attack
    TruePositive { attack_type: String },
    /// False positive - detection doesn't match any known attack
    FalsePositive,
    /// No detection made (used for tracking)
    NoDetection,
}

/// A single attack record from ground truth
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackRecord {
    /// Timestamp of the attack (if available)
    pub timestamp: Option<DateTime<Utc>>,
    /// Source IP of the attacker
    pub src_ip: IpAddr,
    /// Destination IP (target)
    pub dst_ip: Option<IpAddr>,
    /// Attack type label
    pub attack_type: String,
    /// Severity level
    pub severity: Severity,
    /// Attack window start (for time-based matching)
    pub window_start: Option<DateTime<Utc>>,
    /// Attack window end
    pub window_end: Option<DateTime<Utc>>,
    /// Has this attack been detected?
    pub detected: bool,
    /// Detection count (may be detected multiple times)
    pub detection_count: u64,
}

impl AttackRecord {
    /// Create a new attack record
    pub fn new(src_ip: IpAddr, attack_type: &str, severity: Severity) -> Self {
        Self {
            timestamp: None,
            src_ip,
            dst_ip: None,
            attack_type: attack_type.to_string(),
            severity,
            window_start: None,
            window_end: None,
            detected: false,
            detection_count: 0,
        }
    }

    /// Set time window for matching
    pub fn with_window(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.window_start = Some(start);
        self.window_end = Some(end);
        self
    }

    /// Check if a detection matches this attack record
    pub fn matches(&self, event: &DetectionEvent) -> bool {
        // Check source IP
        if event.src_ip != self.src_ip {
            return false;
        }

        // Check destination IP if specified
        if let Some(dst) = self.dst_ip {
            if event.dst_ip != dst {
                return false;
            }
        }

        // Check time window if specified
        if let (Some(start), Some(end)) = (self.window_start, self.window_end) {
            if event.timestamp < start || event.timestamp > end {
                return false;
            }
        }

        // Check attack type mapping
        self.attack_type_matches(&event.event_type)
    }

    /// Check if detection type matches attack type (with fuzzy matching)
    fn attack_type_matches(&self, detection_type: &DetectionType) -> bool {
        let attack_lower = self.attack_type.to_lowercase();

        // Map common attack type labels to detection types
        match detection_type {
            DetectionType::PortScan | DetectionType::NetworkScan => {
                attack_lower.contains("scan") || attack_lower.contains("recon")
            }
            DetectionType::BruteForce => {
                attack_lower.contains("brute") || attack_lower.contains("patator")
                    || attack_lower.contains("password") || attack_lower.contains("auth")
            }
            DetectionType::DoS => {
                attack_lower.contains("dos") || attack_lower.contains("flood")
                    || attack_lower.contains("denial") || attack_lower.contains("ddos")
            }
            DetectionType::SqlInjection => {
                attack_lower.contains("sql") || attack_lower.contains("injection")
            }
            DetectionType::Xss => attack_lower.contains("xss"),
            DetectionType::WebAttack => {
                attack_lower.contains("web") || attack_lower.contains("http")
            }
            DetectionType::DataExfiltration | DetectionType::Intrusion => {
                attack_lower.contains("infiltr") || attack_lower.contains("exfiltr")
                    || attack_lower.contains("botnet")
            }
            DetectionType::TlsHeartbleed => attack_lower.contains("heartbleed"),
            DetectionType::SignatureMatch => true, // Generic match
            DetectionType::AnomalyDetection => true, // Generic anomaly
            _ => false,
        }
    }
}

/// Ground truth dataset for benchmarking
#[derive(Debug, Clone, Default)]
pub struct GroundTruth {
    /// Attack records
    pub attacks: Vec<AttackRecord>,
    /// Set of known attacker IPs
    pub attacker_ips: HashSet<IpAddr>,
    /// Set of known target IPs
    pub target_ips: HashSet<IpAddr>,
    /// Count of benign packets (for FP rate calculation)
    pub benign_count: u64,
    /// Total packets in dataset
    pub total_packets: u64,
    /// Attack type counts
    pub attack_type_counts: HashMap<String, u64>,
}

impl GroundTruth {
    /// Create empty ground truth
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from simple CSV format
    /// Format: timestamp,src_ip,dst_ip,attack_type,severity
    pub fn from_csv(path: &Path) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut gt = Self::new();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;

            // Skip header
            if line_num == 0 && line.contains("timestamp") {
                continue;
            }

            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() < 4 {
                continue;
            }

            let timestamp = if !parts[0].is_empty() {
                parts[0].parse::<i64>().ok().map(|ts| {
                    DateTime::from_timestamp(ts, 0).unwrap_or_else(|| Utc::now())
                })
            } else {
                None
            };

            let src_ip = match IpAddr::from_str(parts[1].trim()) {
                Ok(ip) => ip,
                Err(_) => continue,
            };

            let dst_ip = if parts.len() > 2 && !parts[2].is_empty() {
                IpAddr::from_str(parts[2].trim()).ok()
            } else {
                None
            };

            let attack_type = parts[3].trim().to_string();

            let severity = if parts.len() > 4 {
                match parts[4].trim().to_lowercase().as_str() {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Medium,
                }
            } else {
                Severity::Medium
            };

            let mut record = AttackRecord::new(src_ip, &attack_type, severity);
            record.timestamp = timestamp;
            record.dst_ip = dst_ip;

            gt.attacker_ips.insert(src_ip);
            if let Some(dst) = dst_ip {
                gt.target_ips.insert(dst);
            }
            *gt.attack_type_counts.entry(attack_type).or_insert(0) += 1;
            gt.attacks.push(record);
        }

        Ok(gt)
    }

    /// Load from CICIDS2017 format (CSV with labeled flows)
    pub fn from_cicids2017(path: &Path) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut gt = Self::new();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;

            // Skip header
            if line_num == 0 {
                continue;
            }

            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() < 84 { // CICIDS2017 has many columns
                continue;
            }

            // Column indices for CICIDS2017
            // Src IP = col 1, Dst IP = col 3, Label = col 83
            let src_ip = match IpAddr::from_str(parts.get(1).unwrap_or(&"").trim()) {
                Ok(ip) => ip,
                Err(_) => continue,
            };

            let dst_ip = IpAddr::from_str(parts.get(3).unwrap_or(&"").trim()).ok();
            let label = parts.get(83).unwrap_or(&"BENIGN").trim();

            if label.eq_ignore_ascii_case("BENIGN") {
                gt.benign_count += 1;
            } else {
                let severity = match label.to_uppercase().as_str() {
                    "BOT" | "INFILTRATION" => Severity::Critical,
                    "DDOS" | "DOS" => Severity::High,
                    "PORTSCAN" | "FTP-PATATOR" | "SSH-PATATOR" => Severity::Medium,
                    _ => Severity::Medium,
                };

                let record = AttackRecord::new(src_ip, label, severity);
                gt.attacker_ips.insert(src_ip);
                if let Some(dst) = dst_ip {
                    gt.target_ips.insert(dst);
                }
                *gt.attack_type_counts.entry(label.to_string()).or_insert(0) += 1;
                gt.attacks.push(record);
            }

            gt.total_packets += 1;
        }

        Ok(gt)
    }

    /// Add attacker IP window (all traffic from this IP is attack)
    pub fn add_attacker(&mut self, ip: IpAddr, attack_type: &str, severity: Severity) {
        self.attacker_ips.insert(ip);
        let record = AttackRecord::new(ip, attack_type, severity);
        *self.attack_type_counts.entry(attack_type.to_string()).or_insert(0) += 1;
        self.attacks.push(record);
    }

    /// Add time-windowed attack
    pub fn add_attack_window(
        &mut self,
        src_ip: IpAddr,
        attack_type: &str,
        severity: Severity,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) {
        self.attacker_ips.insert(src_ip);
        let record = AttackRecord::new(src_ip, attack_type, severity)
            .with_window(start, end);
        *self.attack_type_counts.entry(attack_type.to_string()).or_insert(0) += 1;
        self.attacks.push(record);
    }

    /// Check if an IP is a known attacker
    pub fn is_attacker(&self, ip: &IpAddr) -> bool {
        self.attacker_ips.contains(ip)
    }

    /// Match a detection event against ground truth
    pub fn match_detection(&mut self, event: &DetectionEvent) -> MatchResult {
        // Check if source IP is a known attacker
        if !self.attacker_ips.contains(&event.src_ip) {
            return MatchResult::FalsePositive;
        }

        // Try to match against specific attack records
        for record in &mut self.attacks {
            if record.matches(event) {
                record.detected = true;
                record.detection_count += 1;
                return MatchResult::TruePositive {
                    attack_type: record.attack_type.clone(),
                };
            }
        }

        // IP is attacker but no specific match - still count as TP
        // (attacker detected even if type doesn't perfectly match)
        MatchResult::TruePositive {
            attack_type: "generic".to_string(),
        }
    }

    /// Get detection statistics
    pub fn get_statistics(&self) -> GroundTruthStats {
        let total_attacks = self.attacks.len() as u64;
        let detected_attacks = self.attacks.iter().filter(|a| a.detected).count() as u64;
        let missed_attacks = total_attacks - detected_attacks;

        let mut detected_by_type: HashMap<String, u64> = HashMap::new();
        let mut missed_by_type: HashMap<String, u64> = HashMap::new();

        for attack in &self.attacks {
            if attack.detected {
                *detected_by_type.entry(attack.attack_type.clone()).or_insert(0) += 1;
            } else {
                *missed_by_type.entry(attack.attack_type.clone()).or_insert(0) += 1;
            }
        }

        GroundTruthStats {
            total_attacks,
            detected_attacks,
            missed_attacks,
            benign_count: self.benign_count,
            total_packets: self.total_packets,
            unique_attackers: self.attacker_ips.len() as u64,
            detected_by_type,
            missed_by_type,
        }
    }

    /// Reset detection tracking
    pub fn reset(&mut self) {
        for attack in &mut self.attacks {
            attack.detected = false;
            attack.detection_count = 0;
        }
    }
}

/// Statistics from ground truth matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruthStats {
    pub total_attacks: u64,
    pub detected_attacks: u64,
    pub missed_attacks: u64,
    pub benign_count: u64,
    pub total_packets: u64,
    pub unique_attackers: u64,
    pub detected_by_type: HashMap<String, u64>,
    pub missed_by_type: HashMap<String, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_attack_record_matching() {
        let attacker = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let record = AttackRecord::new(attacker, "port_scan", Severity::Medium);

        // Create a matching detection event
        let event = DetectionEvent::new(
            DetectionType::PortScan,
            attacker,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );

        assert!(record.matches(&event));
    }

    #[test]
    fn test_ground_truth_matching() {
        let mut gt = GroundTruth::new();
        let attacker = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        gt.add_attacker(attacker, "brute_force", Severity::High);

        let event = DetectionEvent::new(
            DetectionType::BruteForce,
            attacker,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );

        let result = gt.match_detection(&event);
        assert!(matches!(result, MatchResult::TruePositive { .. }));
    }

    #[test]
    fn test_false_positive_detection() {
        let mut gt = GroundTruth::new();
        let attacker = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let innocent = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));

        gt.add_attacker(attacker, "port_scan", Severity::Medium);

        // Detection from non-attacker IP
        let event = DetectionEvent::new(
            DetectionType::PortScan,
            innocent,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        );

        let result = gt.match_detection(&event);
        assert_eq!(result, MatchResult::FalsePositive);
    }
}
