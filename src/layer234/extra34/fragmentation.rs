//! IP Fragmentation Attack Detection
//!
//! Detects various IP fragmentation-based attacks:
//! - Teardrop: Overlapping fragment offsets
//! - Ping of Death: Reassembled size > 65535 bytes
//! - Fragment floods: High rate of incomplete fragments
//! - Tiny fragments: Fragments smaller than minimum viable size

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::layer234::ThreatType;

/// Minimum fragment size (IP header + 8 bytes of data)
const MIN_FRAGMENT_SIZE: u16 = 28;

/// Maximum IPv4 packet size
const MAX_IP_PACKET_SIZE: u32 = 65535;

/// Fragment reassembly timeout (seconds)
const FRAGMENT_TIMEOUT_SECS: u64 = 30;

/// Maximum tracked fragment groups
const MAX_FRAGMENT_GROUPS: usize = 10000;

/// State of a fragment reassembly group
#[derive(Debug, Clone)]
pub struct FragmentState {
    /// First fragment arrival time
    pub first_seen: Instant,
    /// Last fragment arrival time
    pub last_seen: Instant,
    /// Fragment offsets and sizes: Vec<(offset, size)>
    pub fragments: Vec<(u16, u16)>,
    /// Total bytes received
    pub total_bytes: u32,
    /// Whether we've seen the last fragment (MF=0)
    pub seen_last: bool,
    /// Expected total size (from last fragment)
    pub expected_size: Option<u32>,
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination IP
    pub dst_ip: IpAddr,
}

impl FragmentState {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr) -> Self {
        let now = Instant::now();
        Self {
            first_seen: now,
            last_seen: now,
            fragments: Vec::new(),
            total_bytes: 0,
            seen_last: false,
            expected_size: None,
            src_ip,
            dst_ip,
        }
    }

    /// Add a fragment and check for overlap
    /// Returns true if overlap detected
    pub fn add_fragment(&mut self, offset: u16, size: u16, more_fragments: bool) -> bool {
        self.last_seen = Instant::now();
        self.total_bytes += size as u32;

        if !more_fragments {
            self.seen_last = true;
            // Calculate expected total size from last fragment
            self.expected_size = Some((offset as u32 * 8) + size as u32);
        }

        // Check for overlapping fragments (Teardrop attack)
        let new_start = offset as u32 * 8;
        let new_end = new_start + size as u32;

        for &(existing_offset, existing_size) in &self.fragments {
            let existing_start = existing_offset as u32 * 8;
            let existing_end = existing_start + existing_size as u32;

            // Check for overlap (not just touching)
            if new_start < existing_end && new_end > existing_start {
                // Overlapping fragments detected
                return true;
            }
        }

        self.fragments.push((offset, size));
        false
    }

    /// Check if reassembly is complete
    pub fn is_complete(&self) -> bool {
        if !self.seen_last {
            return false;
        }

        // Check if we have all fragments (simplified check)
        if let Some(expected) = self.expected_size {
            // Sort fragments by offset and check for gaps
            let mut sorted: Vec<_> = self.fragments.iter().cloned().collect();
            sorted.sort_by_key(|&(offset, _)| offset);

            let mut current_pos: u32 = 0;
            for (offset, size) in sorted {
                let frag_start = offset as u32 * 8;
                if frag_start > current_pos {
                    // Gap in fragments
                    return false;
                }
                current_pos = current_pos.max(frag_start + size as u32);
            }

            current_pos >= expected
        } else {
            false
        }
    }

    /// Check if timed out
    pub fn is_expired(&self) -> bool {
        self.first_seen.elapsed() > Duration::from_secs(FRAGMENT_TIMEOUT_SECS)
    }
}

/// Fragment tracking and attack detection
#[derive(Debug)]
pub struct FragmentTracker {
    /// Active fragment groups: (src_ip, dst_ip, id) -> state
    fragments: HashMap<(IpAddr, IpAddr, u16), FragmentState>,
    /// Statistics
    stats: FragmentStats,
    /// Last cleanup time
    last_cleanup: Instant,
}

#[derive(Debug, Default, Clone)]
pub struct FragmentStats {
    /// Total fragments seen
    pub total_fragments: u64,
    /// Completed reassemblies
    pub completed: u64,
    /// Timed out (incomplete) reassemblies
    pub incomplete: u64,
    /// Overlapping fragments detected
    pub overlaps_detected: u64,
    /// Oversized packets detected
    pub oversized_detected: u64,
    /// Tiny fragments detected
    pub tiny_detected: u64,
}

impl Default for FragmentTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FragmentTracker {
    pub fn new() -> Self {
        Self {
            fragments: HashMap::new(),
            stats: FragmentStats::default(),
            last_cleanup: Instant::now(),
        }
    }

    /// Process an IP fragment and detect attacks
    pub fn process_fragment(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        identification: u16,
        fragment_offset: u16,
        fragment_size: u16,
        more_fragments: bool,
    ) -> Vec<ThreatType> {
        let mut threats = Vec::new();
        self.stats.total_fragments += 1;

        // Periodic cleanup
        if self.last_cleanup.elapsed() > Duration::from_secs(5) {
            self.cleanup_expired();
            self.last_cleanup = Instant::now();
        }

        // Check for tiny fragments (potential evasion or attack)
        if fragment_size < MIN_FRAGMENT_SIZE && more_fragments {
            self.stats.tiny_detected += 1;
            threats.push(ThreatType::FragmentTiny {
                id: identification,
                fragment_size,
            });
        }

        let key = (src_ip, dst_ip, identification);

        // Get or create fragment state
        let state = self.fragments
            .entry(key)
            .or_insert_with(|| FragmentState::new(src_ip, dst_ip));

        // Add fragment and check for overlap
        if state.add_fragment(fragment_offset, fragment_size, more_fragments) {
            self.stats.overlaps_detected += 1;
            // Find the overlapping offset for reporting
            let overlap_offset = state.fragments.iter()
                .find(|&&(o, _)| o != fragment_offset)
                .map(|&(o, _)| o)
                .unwrap_or(0);
            threats.push(ThreatType::FragmentOverlap {
                id: identification,
                offset1: fragment_offset,
                offset2: overlap_offset,
            });
        }

        // Check for oversized packet (Ping of Death)
        if let Some(expected) = state.expected_size {
            if expected > MAX_IP_PACKET_SIZE {
                self.stats.oversized_detected += 1;
                threats.push(ThreatType::FragmentOversized {
                    id: identification,
                    total_size: expected,
                });
            }
        }

        // Also check running total
        if state.total_bytes > MAX_IP_PACKET_SIZE {
            if !threats.iter().any(|t| matches!(t, ThreatType::FragmentOversized { .. })) {
                self.stats.oversized_detected += 1;
                threats.push(ThreatType::FragmentOversized {
                    id: identification,
                    total_size: state.total_bytes,
                });
            }
        }

        // Check if complete and remove
        if state.is_complete() {
            self.stats.completed += 1;
            self.fragments.remove(&key);
        }

        // Limit tracked groups
        if self.fragments.len() > MAX_FRAGMENT_GROUPS {
            self.cleanup_oldest();
        }

        threats
    }

    /// Check for fragment flood (called periodically)
    pub fn check_fragment_flood(&self, threshold_per_sec: f32) -> Option<ThreatType> {
        // Calculate incomplete fragment rate
        let incomplete_count = self.fragments.len() as u32;

        // Simple heuristic: if too many incomplete fragment groups, it's suspicious
        if incomplete_count > 100 {
            // Estimate rate based on oldest fragment
            if let Some(oldest) = self.fragments.values().min_by_key(|s| s.first_seen) {
                let elapsed = oldest.first_seen.elapsed().as_secs_f32().max(1.0);
                let rate = self.stats.total_fragments as f32 / elapsed;

                if rate > threshold_per_sec {
                    return Some(ThreatType::FragmentFlood {
                        fragments_per_sec: rate,
                        incomplete_count,
                    });
                }
            }
        }
        None
    }

    /// Get current statistics
    pub fn stats(&self) -> &FragmentStats {
        &self.stats
    }

    /// Get feature vector values for extra34
    pub fn get_features(&self, total_packets: u64) -> [f32; 4] {
        let total = total_packets.max(1) as f32;
        let frag_total = self.stats.total_fragments.max(1) as f32;

        [
            // FRAG_RATE: Fragment rate as ratio of total packets
            self.stats.total_fragments as f32 / total,
            // FRAG_OVERLAP_RATIO: Overlaps per fragment
            self.stats.overlaps_detected as f32 / frag_total,
            // FRAG_INCOMPLETE_RATIO: Incomplete reassemblies
            self.stats.incomplete as f32 / frag_total.max(1.0),
            // FRAG_TINY_RATIO: Tiny fragments
            self.stats.tiny_detected as f32 / frag_total,
        ]
    }

    /// Clean up expired fragment groups
    fn cleanup_expired(&mut self) {
        let before = self.fragments.len();
        self.fragments.retain(|_, state| !state.is_expired());
        let removed = before - self.fragments.len();
        self.stats.incomplete += removed as u64;
    }

    /// Remove oldest entries when limit exceeded
    fn cleanup_oldest(&mut self) {
        // Remove oldest 10%
        let to_remove = self.fragments.len() / 10;
        let mut entries: Vec<_> = self.fragments.iter()
            .map(|(k, v)| (*k, v.first_seen))
            .collect();
        entries.sort_by_key(|(_, time)| *time);

        for (key, _) in entries.into_iter().take(to_remove) {
            self.fragments.remove(&key);
            self.stats.incomplete += 1;
        }
    }

    /// Get count of active fragment groups
    pub fn active_groups(&self) -> usize {
        self.fragments.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_normal_fragmentation() {
        let mut tracker = FragmentTracker::new();
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // First fragment
        let threats = tracker.process_fragment(src, dst, 1234, 0, 1480, true);
        assert!(threats.is_empty());

        // Second fragment (last)
        let threats = tracker.process_fragment(src, dst, 1234, 185, 100, false);
        assert!(threats.is_empty());

        // Should be complete and removed
        assert_eq!(tracker.active_groups(), 0);
    }

    #[test]
    fn test_overlapping_fragments() {
        let mut tracker = FragmentTracker::new();
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // First fragment
        let threats = tracker.process_fragment(src, dst, 1234, 0, 1000, true);
        assert!(threats.is_empty());

        // Overlapping fragment (Teardrop)
        let threats = tracker.process_fragment(src, dst, 1234, 50, 500, true);
        assert!(threats.iter().any(|t| matches!(t, ThreatType::FragmentOverlap { .. })));
    }

    #[test]
    fn test_oversized_packet() {
        let mut tracker = FragmentTracker::new();
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Last fragment with huge offset (Ping of Death)
        // offset 8000 * 8 = 64000, + size = 65535+
        let threats = tracker.process_fragment(src, dst, 1234, 8000, 2000, false);
        assert!(threats.iter().any(|t| matches!(t, ThreatType::FragmentOversized { .. })));
    }

    #[test]
    fn test_tiny_fragment() {
        let mut tracker = FragmentTracker::new();
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Tiny fragment with more_fragments=true
        let threats = tracker.process_fragment(src, dst, 1234, 0, 8, true);
        assert!(threats.iter().any(|t| matches!(t, ThreatType::FragmentTiny { .. })));
    }
}
