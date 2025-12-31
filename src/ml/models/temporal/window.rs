//! Temporal Sequence Windows
//!
//! Manages per-IP sequence buffers for temporal pattern analysis.
//! Each IP maintains a sliding window of recent feature vectors.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::ml::unified::{UnifiedFeatureVector, UNIFIED_DIM};

/// Configuration for sequence windows
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowConfig {
    /// Maximum sequence length per IP
    pub max_sequence_length: usize,
    /// Time window for sequence (older entries expire)
    pub time_window: Duration,
    /// Maximum number of IPs to track
    pub max_ips: usize,
    /// Minimum sequence length for analysis
    pub min_sequence_length: usize,
}

impl Default for WindowConfig {
    fn default() -> Self {
        Self {
            max_sequence_length: 100,
            time_window: Duration::from_secs(300), // 5 minutes
            max_ips: 10_000,
            min_sequence_length: 5,
        }
    }
}

/// A timestamped feature entry
#[derive(Debug, Clone)]
pub struct TimestampedFeatures {
    /// Feature values
    pub features: [f32; UNIFIED_DIM],
    /// When this was recorded
    pub timestamp: Instant,
    /// Flow ID (for reference)
    pub flow_id: u64,
}

/// Sequence buffer for a single IP
#[derive(Debug)]
pub struct IpSequence {
    /// Feature sequence
    entries: Vec<TimestampedFeatures>,
    /// Last access time (for LRU eviction)
    last_access: Instant,
    /// Statistics
    stats: SequenceStats,
}

/// Statistics about a sequence
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SequenceStats {
    /// Total entries added
    pub total_added: u64,
    /// Entries expired
    pub expired: u64,
    /// Maximum sequence length reached
    pub max_length_reached: u64,
}

impl IpSequence {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_access: Instant::now(),
            stats: SequenceStats::default(),
        }
    }

    fn add(&mut self, features: [f32; UNIFIED_DIM], flow_id: u64, max_len: usize) {
        self.stats.total_added += 1;
        self.last_access = Instant::now();

        if self.entries.len() >= max_len {
            self.entries.remove(0);
            self.stats.max_length_reached += 1;
        }

        self.entries.push(TimestampedFeatures {
            features,
            timestamp: Instant::now(),
            flow_id,
        });
    }

    fn expire_old(&mut self, max_age: Duration) {
        let now = Instant::now();
        let before = self.entries.len();

        self.entries.retain(|e| now.duration_since(e.timestamp) < max_age);

        let removed = before - self.entries.len();
        self.stats.expired += removed as u64;
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get features as a 2D slice for LSTM input
    fn as_sequence(&self) -> Vec<[f32; UNIFIED_DIM]> {
        self.entries.iter().map(|e| e.features).collect()
    }

    /// Get recent N features
    fn recent(&self, n: usize) -> Vec<[f32; UNIFIED_DIM]> {
        self.entries
            .iter()
            .rev()
            .take(n)
            .map(|e| e.features)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }
}

/// Manager for per-IP sequence windows
#[derive(Debug)]
pub struct SequenceManager {
    /// Configuration
    config: WindowConfig,
    /// Per-IP sequences
    sequences: HashMap<IpAddr, IpSequence>,
    /// Statistics
    stats: ManagerStats,
}

/// Manager statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManagerStats {
    /// Total IPs tracked
    pub ips_tracked: u64,
    /// IPs evicted due to LRU
    pub ips_evicted: u64,
    /// Total features added
    pub features_added: u64,
    /// Sequences ready for analysis
    pub sequences_ready: u64,
}

impl SequenceManager {
    /// Create a new sequence manager
    pub fn new(config: WindowConfig) -> Self {
        Self {
            config,
            sequences: HashMap::new(),
            stats: ManagerStats::default(),
        }
    }

    /// Add a feature vector for an IP
    pub fn add(&mut self, ip: IpAddr, vector: &UnifiedFeatureVector) {
        self.stats.features_added += 1;

        // Get or create sequence
        let seq = self.sequences.entry(ip).or_insert_with(|| {
            self.stats.ips_tracked += 1;
            IpSequence::new()
        });

        // Add to sequence
        seq.add(vector.features, vector.flow_id, self.config.max_sequence_length);

        // Expire old entries
        seq.expire_old(self.config.time_window);

        // Evict LRU IPs if over limit
        self.evict_lru();
    }

    /// Evict least recently used IPs if over limit
    fn evict_lru(&mut self) {
        if self.sequences.len() <= self.config.max_ips {
            return;
        }

        // Find oldest accessed IP
        let oldest = self
            .sequences
            .iter()
            .min_by_key(|(_, seq)| seq.last_access)
            .map(|(ip, _)| *ip);

        if let Some(ip) = oldest {
            self.sequences.remove(&ip);
            self.stats.ips_evicted += 1;
        }
    }

    /// Get sequence for an IP (if exists and meets minimum length)
    pub fn get_sequence(&self, ip: &IpAddr) -> Option<Vec<[f32; UNIFIED_DIM]>> {
        self.sequences.get(ip).and_then(|seq| {
            if seq.len() >= self.config.min_sequence_length {
                Some(seq.as_sequence())
            } else {
                None
            }
        })
    }

    /// Get recent N features for an IP
    pub fn get_recent(&self, ip: &IpAddr, n: usize) -> Option<Vec<[f32; UNIFIED_DIM]>> {
        self.sequences.get(ip).and_then(|seq| {
            if seq.len() >= n {
                Some(seq.recent(n))
            } else {
                None
            }
        })
    }

    /// Check if an IP has enough data for analysis
    pub fn is_ready(&self, ip: &IpAddr) -> bool {
        self.sequences
            .get(ip)
            .map(|seq| seq.len() >= self.config.min_sequence_length)
            .unwrap_or(false)
    }

    /// Get number of IPs ready for analysis
    pub fn ready_count(&self) -> usize {
        self.sequences
            .values()
            .filter(|seq| seq.len() >= self.config.min_sequence_length)
            .count()
    }

    /// Get all IPs with ready sequences
    pub fn ready_ips(&self) -> Vec<IpAddr> {
        self.sequences
            .iter()
            .filter(|(_, seq)| seq.len() >= self.config.min_sequence_length)
            .map(|(ip, _)| *ip)
            .collect()
    }

    /// Get sequence length for an IP
    pub fn sequence_length(&self, ip: &IpAddr) -> usize {
        self.sequences.get(ip).map(|seq| seq.len()).unwrap_or(0)
    }

    /// Get statistics
    pub fn stats(&self) -> &ManagerStats {
        &self.stats
    }

    /// Get configuration
    pub fn config(&self) -> &WindowConfig {
        &self.config
    }

    /// Get number of tracked IPs
    pub fn ip_count(&self) -> usize {
        self.sequences.len()
    }

    /// Clear all sequences
    pub fn clear(&mut self) {
        self.sequences.clear();
    }

    /// Remove sequence for an IP
    pub fn remove(&mut self, ip: &IpAddr) {
        self.sequences.remove(ip);
    }

    /// Cleanup expired entries from all sequences
    pub fn cleanup(&mut self) {
        for seq in self.sequences.values_mut() {
            seq.expire_old(self.config.time_window);
        }

        // Remove empty sequences
        self.sequences.retain(|_, seq| !seq.is_empty());
    }
}

impl Default for SequenceManager {
    fn default() -> Self {
        Self::new(WindowConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    fn make_test_vector(flow_id: u64) -> UnifiedFeatureVector {
        UnifiedFeatureVector {
            features: [flow_id as f32 * 0.1; UNIFIED_DIM],
            flow_id,
            ..Default::default()
        }
    }

    #[test]
    fn test_sequence_manager_creation() {
        let manager = SequenceManager::default();
        assert_eq!(manager.ip_count(), 0);
    }

    #[test]
    fn test_add_features() {
        let mut manager = SequenceManager::default();
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        for i in 0..10 {
            manager.add(ip, &make_test_vector(i));
        }

        assert_eq!(manager.ip_count(), 1);
        assert_eq!(manager.sequence_length(&ip), 10);
        assert!(manager.is_ready(&ip));
    }

    #[test]
    fn test_sequence_retrieval() {
        let config = WindowConfig {
            min_sequence_length: 3,
            ..Default::default()
        };
        let mut manager = SequenceManager::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Add fewer than min - should not be ready
        for i in 0..2 {
            manager.add(ip, &make_test_vector(i));
        }
        assert!(!manager.is_ready(&ip));
        assert!(manager.get_sequence(&ip).is_none());

        // Add more - should now be ready
        manager.add(ip, &make_test_vector(2));
        assert!(manager.is_ready(&ip));

        let seq = manager.get_sequence(&ip).unwrap();
        assert_eq!(seq.len(), 3);
    }

    #[test]
    fn test_max_sequence_length() {
        let config = WindowConfig {
            max_sequence_length: 5,
            ..Default::default()
        };
        let mut manager = SequenceManager::new(config);
        let ip: IpAddr = "172.16.0.1".parse().unwrap();

        // Add more than max
        for i in 0..10 {
            manager.add(ip, &make_test_vector(i));
        }

        assert_eq!(manager.sequence_length(&ip), 5);
    }

    #[test]
    fn test_recent_features() {
        let mut manager = SequenceManager::default();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();

        for i in 0..10 {
            manager.add(ip, &make_test_vector(i));
        }

        let recent = manager.get_recent(&ip, 3).unwrap();
        assert_eq!(recent.len(), 3);
        // Should be features 7, 8, 9 (most recent)
        assert!((recent[2][0] - 0.9).abs() < 0.01);
    }
}
