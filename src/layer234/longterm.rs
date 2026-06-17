//! Long-term behavioral profiling — per-source state and features (Phase A).
//!
//! See `docs/DESIGN-LONGTERM-VECTORDB.md`. This module is the data layer: it
//! profiles each source over a long horizon as a **sliding window of epoch
//! snapshots**, updated O(1) per packet, and derives a feature vector whose
//! magnitude differences are large at long horizon (so the volume/timing signal
//! survives, unlike the short-term 10s window). Detection (self-drift + a
//! population vector store) is layered on top in Phase B.

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;

/// Dimensionality of the long-term feature vector.
pub const LONGTERM_DIM: usize = 8;

/// Cap on distinct ports/IPs and connection timestamps stored per epoch, so a
/// single noisy epoch can't blow up memory.
const CAP_PORTS: usize = 1024;
const CAP_IPS: usize = 1024;
const CAP_CONN_TIMES: usize = 4096;

/// One epoch's raw accumulators for a source.
#[derive(Default)]
struct EpochStats {
    start_ns: u64,
    bytes_sent: u64,
    packets: u64,
    syns: u64,
    auth_syns: u64,
    dst_ports: HashSet<u16>,
    dst_ips: HashSet<IpAddr>,
    /// SYN (connection-open) timestamps, for inter-arrival / periodicity.
    conn_times: Vec<u64>,
}

impl EpochStats {
    fn has_data(&self) -> bool {
        self.packets > 0
    }
}

/// Derived long-term features for a source over its sliding window. Named for
/// clarity; `to_vector` packs them for the vector store.
#[derive(Debug, Clone, Copy)]
pub struct LongTermFeatures {
    /// Cumulative bytes the source sent over the horizon.
    pub bytes_sent: u64,
    /// Connection opens (SYNs) over the horizon.
    pub conn_count: u64,
    /// Coefficient of variation of connection inter-arrival times (std/mean).
    /// Low + many connections = a regular beacon; ~0 when too few to judge.
    pub interval_cv: f32,
    /// Mean connection inter-arrival (seconds), 0 if < 2 connections.
    pub interval_mean_secs: f32,
    /// Distinct destination ports touched over the horizon.
    pub distinct_dst_ports: u32,
    /// Distinct destination IPs touched over the horizon.
    pub distinct_dst_ips: u32,
    /// Cumulative SYNs to auth ports (slow brute signal).
    pub auth_syns: u64,
    /// Packets per second over the active span.
    pub packets_per_sec: f32,
}

impl LongTermFeatures {
    /// Pack into a fixed-size vector. Volume/count features are log-scaled so a
    /// realistic-scale difference is a large coordinate move (the short-term path
    /// failed precisely because it did not do this).
    pub fn to_vector(&self) -> [f32; LONGTERM_DIM] {
        [
            (self.bytes_sent as f32 + 1.0).ln(),
            (self.conn_count as f32 + 1.0).ln(),
            self.interval_cv,
            (self.interval_mean_secs + 1.0).ln(),
            (self.distinct_dst_ports as f32 + 1.0).ln(),
            (self.distinct_dst_ips as f32 + 1.0).ln(),
            (self.auth_syns as f32 + 1.0).ln(),
            (self.packets_per_sec + 1.0).ln(),
        ]
    }
}

/// Rolling per-source long-term profile: a sliding window of recent epochs.
pub struct LongTermProfile {
    current: EpochStats,
    /// Last `horizon` completed epochs (oldest at front).
    epochs: VecDeque<EpochStats>,
    epoch_ns: u64,
    horizon: usize,
    first_seen_ns: u64,
    last_seen_ns: u64,
}

impl LongTermProfile {
    /// New profile with the given epoch length and how many epochs of history to
    /// retain (the sliding window).
    pub fn new(epoch_secs: u64, horizon_epochs: usize) -> Self {
        Self {
            current: EpochStats::default(),
            epochs: VecDeque::new(),
            epoch_ns: epoch_secs.max(1) * 1_000_000_000,
            horizon: horizon_epochs.max(1),
            first_seen_ns: 0,
            last_seen_ns: 0,
        }
    }

    /// Fold one packet from this source into the current epoch (O(1)), rolling
    /// over to a new epoch when the current one elapses.
    pub fn record(
        &mut self,
        now_ns: u64,
        bytes: u32,
        is_syn: bool,
        dst_port: u16,
        dst_ip: IpAddr,
        is_auth_port: bool,
    ) {
        if self.first_seen_ns == 0 {
            self.first_seen_ns = now_ns;
        }
        // Roll over once when the current epoch (with data) has elapsed. A long
        // idle gap just means the in-between epochs were empty (not stored); the
        // active span is recovered from timestamps.
        if self.current.has_data() && now_ns >= self.current.start_ns + self.epoch_ns {
            let finished = std::mem::take(&mut self.current);
            self.epochs.push_back(finished);
            while self.epochs.len() > self.horizon {
                self.epochs.pop_front();
            }
        }
        if self.current.start_ns == 0 {
            self.current.start_ns = now_ns;
        }

        let c = &mut self.current;
        c.bytes_sent += bytes as u64;
        c.packets += 1;
        if is_syn {
            c.syns += 1;
            if is_auth_port {
                c.auth_syns += 1;
            }
            if c.conn_times.len() < CAP_CONN_TIMES {
                c.conn_times.push(now_ns);
            }
        }
        if c.dst_ports.len() < CAP_PORTS {
            c.dst_ports.insert(dst_port);
        }
        if c.dst_ips.len() < CAP_IPS {
            c.dst_ips.insert(dst_ip);
        }
        self.last_seen_ns = now_ns;
    }

    /// Last activity timestamp (for eviction).
    pub fn last_seen_ns(&self) -> u64 {
        self.last_seen_ns
    }

    fn epochs_with_current(&self) -> impl Iterator<Item = &EpochStats> {
        self.epochs
            .iter()
            .chain(std::iter::once(&self.current))
            .filter(|e| e.has_data())
    }

    /// Derive the long-term features from the sliding window.
    pub fn features(&self) -> LongTermFeatures {
        let mut bytes_sent = 0u64;
        let mut conn_count = 0u64;
        let mut auth_syns = 0u64;
        let mut packets = 0u64;
        let mut ports: HashSet<u16> = HashSet::new();
        let mut ips: HashSet<IpAddr> = HashSet::new();
        let mut conn_times: Vec<u64> = Vec::new();

        for e in self.epochs_with_current() {
            bytes_sent += e.bytes_sent;
            conn_count += e.syns;
            auth_syns += e.auth_syns;
            packets += e.packets;
            ports.extend(e.dst_ports.iter().copied());
            ips.extend(e.dst_ips.iter().copied());
            conn_times.extend(e.conn_times.iter().copied());
        }

        // Inter-arrival statistics for periodicity. conn_times are appended in
        // epoch order; sort defensively before differencing.
        conn_times.sort_unstable();
        let (interval_cv, interval_mean_secs) = interval_stats(&conn_times);

        let span_ns = self.last_seen_ns.saturating_sub(self.first_seen_ns);
        let span_secs = (span_ns as f32 / 1e9).max(1e-6);
        let packets_per_sec = packets as f32 / span_secs;

        LongTermFeatures {
            bytes_sent,
            conn_count,
            interval_cv,
            interval_mean_secs,
            distinct_dst_ports: ports.len() as u32,
            distinct_dst_ips: ips.len() as u32,
            auth_syns,
            packets_per_sec,
        }
    }
}

/// (coefficient of variation, mean seconds) of inter-arrival gaps. CV is 0 when
/// there are fewer than 3 connections (not enough to judge regularity).
fn interval_stats(sorted_times: &[u64]) -> (f32, f32) {
    if sorted_times.len() < 2 {
        return (0.0, 0.0);
    }
    let gaps: Vec<f32> = sorted_times
        .windows(2)
        .map(|w| (w[1].saturating_sub(w[0])) as f32 / 1e9)
        .collect();
    let n = gaps.len() as f32;
    let mean = gaps.iter().sum::<f32>() / n;
    if gaps.len() < 2 || mean <= 0.0 {
        return (0.0, mean);
    }
    let var = gaps.iter().map(|g| (g - mean).powi(2)).sum::<f32>() / n;
    let cv = var.sqrt() / mean;
    (cv, mean)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, d))
    }
    const S: u64 = 1_000_000_000;

    /// Regular beacon: a connection every 60s to one destination.
    #[test]
    fn beacon_has_low_interval_cv() {
        let mut p = LongTermProfile::new(60, 120);
        for i in 0..20u64 {
            p.record(i * 60 * S, 200, true, 443, ip(1), false);
        }
        let f = p.features();
        assert!(f.conn_count >= 20, "expected many connections");
        assert!(f.interval_cv < 0.05, "regular beacon should have ~0 CV, got {}", f.interval_cv);
        assert!((f.interval_mean_secs - 60.0).abs() < 1.0, "mean interval ~60s");
    }

    /// Irregular connections have a much higher CV than a beacon.
    #[test]
    fn irregular_has_higher_cv_than_beacon() {
        let mut p = LongTermProfile::new(60, 120);
        let gaps = [5u64, 90, 7, 200, 3, 140, 11, 60, 2, 175];
        let mut t = 0u64;
        for g in gaps {
            t += g * S;
            p.record(t, 200, true, 443, ip(1), false);
        }
        let f = p.features();
        assert!(f.interval_cv > 0.3, "irregular traffic should have high CV, got {}", f.interval_cv);
    }

    /// Bulk exfil: one source sends a large cumulative volume.
    #[test]
    fn exfil_volume_accumulates() {
        let mut p = LongTermProfile::new(60, 120);
        for i in 0..50u64 {
            p.record(i * S, 1400, i % 10 == 0, 443, ip(1), false);
        }
        let f = p.features();
        assert!(f.bytes_sent >= 50 * 1400, "cumulative bytes should accumulate");
        // log-scaled volume is a large coordinate vs a small session.
        let v = f.to_vector();
        assert!(v[0] > 10.0, "log(bytes) should be sizeable, got {}", v[0]);
    }

    /// Low-and-slow scan: many distinct destination ports over the horizon.
    #[test]
    fn slow_scan_port_fanout() {
        let mut p = LongTermProfile::new(60, 120);
        for port in 0..40u16 {
            // one SYN per port, well spread (a few minutes apart)
            p.record(port as u64 * 90 * S, 60, true, 1000 + port, ip(1), false);
        }
        let f = p.features();
        assert_eq!(f.distinct_dst_ports, 40, "should count all distinct ports");
    }

    /// The sliding window retains at most `horizon` completed epochs.
    #[test]
    fn sliding_window_bounds_history() {
        let mut p = LongTermProfile::new(1, 5); // 1s epochs, keep 5
        for i in 0..100u64 {
            p.record(i * 1_000_000_000 + 1, 100, true, 80, ip(1), false);
        }
        // completed epochs are capped; current is separate.
        assert!(p.epochs.len() <= 5, "history must be bounded to horizon");
    }

    /// Auth-port SYNs are counted for the slow-brute signal.
    #[test]
    fn auth_syns_counted() {
        let mut p = LongTermProfile::new(60, 120);
        for i in 0..12u64 {
            p.record(i * 20 * S, 60, true, 22, ip(1), true);
        }
        assert_eq!(p.features().auth_syns, 12);
    }
}
