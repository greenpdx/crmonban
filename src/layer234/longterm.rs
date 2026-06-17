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
    /// Smoothed reference of this source's past profile vectors (self-drift).
    ewma: Option<[f32; LONGTERM_DIM]>,
    /// Completed epochs observed (warmup for self-drift).
    history_epochs: usize,
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
            ewma: None,
            history_epochs: 0,
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
    ) -> bool {
        if self.first_seen_ns == 0 {
            self.first_seen_ns = now_ns;
        }
        // Roll over once when the current epoch (with data) has elapsed. A long
        // idle gap just means the in-between epochs were empty (not stored); the
        // active span is recovered from timestamps. Returns true on a rollover,
        // which is the natural point to (re)evaluate the source.
        let rolled = self.current.has_data() && now_ns >= self.current.start_ns + self.epoch_ns;
        if rolled {
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
        rolled
    }

    /// Last activity timestamp (for eviction).
    pub fn last_seen_ns(&self) -> u64 {
        self.last_seen_ns
    }

    /// Self-drift: distance of the current profile vector from this source's own
    /// smoothed history, then fold the current vector into the reference. Returns
    /// `None` until `min_history` epochs have been observed (warmup). This is the
    /// primary signal — a host compared to itself, immune to cross-host variety.
    fn drift_and_update(&mut self, min_history: usize) -> Option<f32> {
        let v = self.features().to_vector();
        let drift = self.ewma.as_ref().map(|r| euclidean(&v, r));
        match self.ewma {
            Some(ref mut r) => {
                for i in 0..LONGTERM_DIM {
                    r[i] = 0.8 * r[i] + 0.2 * v[i];
                }
            }
            None => self.ewma = Some(v),
        }
        self.history_epochs += 1;
        if self.history_epochs > min_history {
            drift
        } else {
            None
        }
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

/// Euclidean distance between two long-term vectors.
fn euclidean(a: &[f32; LONGTERM_DIM], b: &[f32; LONGTERM_DIM]) -> f32 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f32>()
        .sqrt()
}

// === Classification ============================================================

/// What kind of long-term behavior an anomalous profile most resembles. The
/// anomaly itself is decided by distance; this just names the dominant deviation
/// for the emitted event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongTermKind {
    Beaconing,
    Exfiltration,
    SlowScan,
    SlowBrute,
    Anomaly,
}

/// Label an anomalous profile by its dominant feature. Order reflects specificity.
fn classify(f: &LongTermFeatures) -> LongTermKind {
    if f.conn_count >= 8 && f.interval_cv < 0.25 {
        LongTermKind::Beaconing
    } else if f.auth_syns >= 10 {
        LongTermKind::SlowBrute
    } else if f.distinct_dst_ports >= 20 {
        LongTermKind::SlowScan
    } else if f.bytes_sent >= 1_000_000 {
        LongTermKind::Exfiltration
    } else {
        LongTermKind::Anomaly
    }
}

// === Population store ==========================================================

/// Euclidean crvecdb of learned NORMAL per-source profile vectors. A source whose
/// current profile is far from every normal one is anomalous even with no clean
/// self-history (a host that was bad from first observation).
pub struct LongTermStore {
    index: crvecdb::Index,
    next_id: u64,
}

impl LongTermStore {
    pub fn new(capacity: usize) -> super::error::Result<Self> {
        let index = crvecdb::Index::builder(LONGTERM_DIM)
            .metric(crvecdb::DistanceMetric::Euclidean)
            .m(16)
            .ef_construction(200)
            .capacity(capacity)
            .build()
            .map_err(|e| super::error::NetVecError::StoreError(e.to_string()))?;
        Ok(Self { index, next_id: 0 })
    }

    /// Learn a normal profile. Insert failures are non-fatal (detection must not
    /// crash on a store hiccup).
    pub fn learn(&mut self, v: &[f32; LONGTERM_DIM]) {
        let id = self.next_id;
        if self.index.insert(id, &v[..]).is_ok() {
            self.next_id += 1;
        }
    }

    /// Distance to the nearest learned profile, or None if empty/error.
    pub fn nearest(&self, v: &[f32; LONGTERM_DIM]) -> Option<f32> {
        self.index
            .search(&v[..], 1)
            .ok()
            .and_then(|r| r.first().map(|m| m.distance))
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}

// === Tracker ===================================================================

/// Configuration for the long-term tracker.
#[derive(Debug, Clone)]
pub struct LongTermConfig {
    pub epoch_secs: u64,
    pub horizon_epochs: usize,
    pub max_sources: usize,
    /// Normal profiles required before population anomaly is enabled (warmup).
    pub min_baseline_profiles: usize,
    /// Per-source epochs of history before self-drift fires (warmup).
    pub min_history_epochs: usize,
    pub population_threshold: f32,
    pub self_drift_threshold: f32,
    /// Learn clean profiles into the population store online.
    pub auto_learn: bool,
}

impl Default for LongTermConfig {
    fn default() -> Self {
        Self {
            epoch_secs: 60,
            horizon_epochs: 60,
            max_sources: 50_000,
            min_baseline_profiles: 200,
            min_history_epochs: 3,
            population_threshold: 1.5,
            self_drift_threshold: 1.5,
            auto_learn: true,
        }
    }
}

/// A confirmed long-term anomaly for a source.
#[derive(Debug, Clone)]
pub struct LongTermHit {
    pub src: IpAddr,
    pub kind: LongTermKind,
    /// Which signal fired.
    pub signal: &'static str,
    pub distance: f32,
}

/// Per-source long-term profiles + the population store; evaluates a source on
/// each epoch rollover via self-drift (primary) and population anomaly (backstop).
pub struct LongTermTracker {
    profiles: std::collections::HashMap<IpAddr, LongTermProfile>,
    store: LongTermStore,
    config: LongTermConfig,
    last_cleanup_ns: u64,
}

impl LongTermTracker {
    pub fn new(config: LongTermConfig) -> super::error::Result<Self> {
        let store = LongTermStore::new(config.max_sources.max(1))?;
        Ok(Self {
            profiles: std::collections::HashMap::new(),
            store,
            config,
            last_cleanup_ns: 0,
        })
    }

    /// Fold one packet from `src` into its profile. Returns a hit when an epoch
    /// rollover evaluation finds the source anomalous.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        src: IpAddr,
        now_ns: u64,
        bytes: u32,
        is_syn: bool,
        dst_port: u16,
        dst_ip: IpAddr,
        is_auth_port: bool,
    ) -> Option<LongTermHit> {
        let (epoch_secs, horizon) = (self.config.epoch_secs, self.config.horizon_epochs);
        let rolled = self
            .profiles
            .entry(src)
            .or_insert_with(|| LongTermProfile::new(epoch_secs, horizon))
            .record(now_ns, bytes, is_syn, dst_port, dst_ip, is_auth_port);

        let hit = if rolled { self.evaluate(src) } else { None };
        self.maybe_cleanup(now_ns);
        hit
    }

    /// Evaluate a source's just-rolled profile: self-drift first, then population
    /// anomaly; learn the profile if it looks clean.
    fn evaluate(&mut self, src: IpAddr) -> Option<LongTermHit> {
        let (v, features, drift) = {
            let profile = self.profiles.get_mut(&src)?;
            let features = profile.features();
            let v = features.to_vector();
            let drift = profile.drift_and_update(self.config.min_history_epochs);
            (v, features, drift)
        };

        let drift_hit = drift
            .map(|d| d > self.config.self_drift_threshold)
            .unwrap_or(false);

        let trained = self.store.len() >= self.config.min_baseline_profiles;
        let pop_dist = self.store.nearest(&v);
        let pop_hit = trained
            && pop_dist
                .map(|d| d > self.config.population_threshold)
                .unwrap_or(false);

        if drift_hit || pop_hit {
            let (signal, distance) = if drift_hit {
                ("self-drift", drift.unwrap_or(0.0))
            } else {
                ("population", pop_dist.unwrap_or(0.0))
            };
            return Some(LongTermHit { src, kind: classify(&features), signal, distance });
        }

        // Clean profile — fold it into the population baseline.
        if self.config.auto_learn {
            self.store.learn(&v);
        }
        None
    }

    fn maybe_cleanup(&mut self, now_ns: u64) {
        let horizon_ns = self.config.epoch_secs * self.config.horizon_epochs as u64 * 1_000_000_000;
        if now_ns.saturating_sub(self.last_cleanup_ns) < horizon_ns.max(1) {
            return;
        }
        self.last_cleanup_ns = now_ns;
        // Drop sources idle for longer than the horizon.
        self.profiles
            .retain(|_, p| now_ns.saturating_sub(p.last_seen_ns()) <= horizon_ns);
        // Hard cap: if still over budget, evict the least-recently-seen.
        while self.profiles.len() > self.config.max_sources {
            if let Some(oldest) = self
                .profiles
                .iter()
                .min_by_key(|(_, p)| p.last_seen_ns())
                .map(|(ip, _)| *ip)
            {
                self.profiles.remove(&oldest);
            } else {
                break;
            }
        }
    }

    pub fn tracked_sources(&self) -> usize {
        self.profiles.len()
    }

    pub fn baseline_len(&self) -> usize {
        self.store.len()
    }
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

    // === Phase B ===============================================================

    fn src_ip(n: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, (n >> 8) as u8, (n & 0xff) as u8, 1))
    }

    fn feats(bytes: u64, conns: u64, cv: f32, ports: u32, auth: u64) -> LongTermFeatures {
        LongTermFeatures {
            bytes_sent: bytes,
            conn_count: conns,
            interval_cv: cv,
            interval_mean_secs: 60.0,
            distinct_dst_ports: ports,
            distinct_dst_ips: 1,
            auth_syns: auth,
            packets_per_sec: 1.0,
        }
    }

    #[test]
    fn classify_labels_dominant_behavior() {
        assert_eq!(classify(&feats(2000, 20, 0.02, 1, 0)), LongTermKind::Beaconing);
        assert_eq!(classify(&feats(2000, 30, 0.9, 1, 15)), LongTermKind::SlowBrute);
        assert_eq!(classify(&feats(2000, 5, 0.9, 40, 0)), LongTermKind::SlowScan);
        assert_eq!(classify(&feats(5_000_000, 5, 0.9, 2, 0)), LongTermKind::Exfiltration);
        assert_eq!(classify(&feats(2000, 2, 0.9, 1, 0)), LongTermKind::Anomaly);
    }

    #[test]
    fn population_store_flags_outlier() {
        let mut store = LongTermStore::new(1000).unwrap();
        // Learn many "normal" light profiles.
        for i in 0..50u32 {
            let f = feats(2000 + i as u64 * 10, 5, 0.9, 2, 0);
            store.learn(&f.to_vector());
        }
        let normal = feats(2500, 5, 0.9, 2, 0).to_vector();
        let exfil = feats(5_000_000, 5, 0.9, 2, 0).to_vector();
        let dn = store.nearest(&normal).unwrap();
        let dx = store.nearest(&exfil).unwrap();
        assert!(dn < 0.5, "a normal profile is close to the baseline: {dn}");
        assert!(dx > 3.0, "the exfil profile is far from the baseline: {dx}");
    }

    /// Feed a source `epochs` epochs of a behavior; return the last hit seen.
    fn drive(
        t: &mut LongTermTracker,
        src: IpAddr,
        epoch_range: std::ops::Range<u64>,
        bytes: u32,
        pkts: u64,
        ports: &[u16],
    ) -> Option<LongTermHit> {
        let mut last = None;
        for e in epoch_range {
            let est = e * 60 * S;
            for i in 0..pkts {
                let now = est + i * S; // within the 60s epoch
                let port = ports[(i as usize) % ports.len()];
                if let Some(h) = t.record(src, now, bytes, i == 0, port, ip(1), false) {
                    last = Some(h);
                }
            }
        }
        last
    }

    #[test]
    fn population_anomaly_flags_exfil() {
        let mut cfg = LongTermConfig::default();
        cfg.min_baseline_profiles = 20;
        cfg.min_history_epochs = 1000; // disable self-drift; isolate population signal
        cfg.population_threshold = 1.0;
        let mut t = LongTermTracker::new(cfg).unwrap();

        // Train: many normal sources, light traffic over several epochs.
        for s in 0..40u32 {
            drive(&mut t, src_ip(s), 0..4, 200, 10, &[443]);
        }
        assert!(t.baseline_len() >= 20, "baseline should be trained: {}", t.baseline_len());

        // A new high-volume source — far from the learned normal profiles.
        let hit = drive(&mut t, src_ip(9999), 0..4, 1400, 50, &[443]);
        let hit = hit.expect("exfil should be flagged by population anomaly");
        assert_eq!(hit.signal, "population");
    }

    #[test]
    fn self_drift_detects_behavior_change() {
        let mut cfg = LongTermConfig::default();
        cfg.min_baseline_profiles = usize::MAX; // disable population; isolate self-drift
        cfg.min_history_epochs = 2;
        cfg.self_drift_threshold = 1.0;
        let mut t = LongTermTracker::new(cfg).unwrap();

        let src = src_ip(1);
        // Establish a normal history for this one source.
        drive(&mut t, src, 0..5, 200, 10, &[443]);
        // Then it abruptly starts exfiltrating — drifts from its OWN history.
        let hit = drive(&mut t, src, 5..8, 1400, 50, &[443]);
        let hit = hit.expect("a source changing its own behavior should drift");
        assert_eq!(hit.signal, "self-drift");
    }
}
