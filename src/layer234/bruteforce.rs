//! Cross-window cumulative brute-force counter (detection mechanism #2).
//!
//! The volumetric branch in the heuristic catches a brute force whose attempts
//! pile up inside one aggregation window. But a *slow* campaign — a handful of
//! connection attempts per window, spread over minutes — never fills a window
//! enough to trip it (or even to reach `min_packets`). This tracker closes that
//! gap: it counts connection attempts (TCP SYNs) per `(source, auth port)` over a
//! longer sliding window and fires once the cumulative count crosses a threshold.
//!
//! It keys on the attacker's own SYNs, so — like mechanism #1 — it works on the
//! unidirectional INPUT path, and it covers every configured auth port (SSH,
//! SMTP, FTP, IMAP, RDP, the databases, ...), not just SSH.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;

/// Sliding window over which attempts are counted.
pub const DEFAULT_BRUTE_WINDOW_SECS: u64 = 300;
/// Cumulative attempts within the window that confirm a slow brute force.
pub const DEFAULT_BRUTE_THRESHOLD: usize = 10;
/// Minimum gap between alerts for the same source, so one campaign fires once
/// rather than on every attempt past the threshold.
pub const DEFAULT_BRUTE_COOLDOWN_SECS: u64 = 60;

/// A confirmed slow brute force against one auth port from one source.
#[derive(Debug, Clone, Copy)]
pub struct BruteForceHit {
    /// Attempts counted in the current window.
    pub attempts: usize,
    /// The auth port under attack.
    pub port: u16,
    /// The window the attempts accumulated over (seconds).
    pub window_secs: u64,
}

#[derive(Default)]
struct AttemptRecord {
    /// Timestamps (ns) of attempts still inside the sliding window.
    attempts: VecDeque<u64>,
    /// Last time this source alerted (ns), for cooldown.
    last_alert_ns: u64,
}

/// Per-`(source, auth port)` cumulative attempt counter.
pub struct BruteForceTracker {
    by_source: HashMap<(IpAddr, u16), AttemptRecord>,
    auth_ports: Arc<HashSet<u16>>,
    window_ns: u64,
    threshold: usize,
    cooldown_ns: u64,
    last_cleanup_ns: u64,
}

impl BruteForceTracker {
    /// New tracker for the given auth ports and thresholds.
    pub fn new(
        auth_ports: Arc<HashSet<u16>>,
        window_secs: u64,
        threshold: usize,
        cooldown_secs: u64,
    ) -> Self {
        Self {
            by_source: HashMap::new(),
            auth_ports,
            window_ns: window_secs * 1_000_000_000,
            threshold: threshold.max(1),
            cooldown_ns: cooldown_secs * 1_000_000_000,
            last_cleanup_ns: 0,
        }
    }

    /// Tracker with default thresholds.
    pub fn with_defaults(auth_ports: Arc<HashSet<u16>>) -> Self {
        Self::new(
            auth_ports,
            DEFAULT_BRUTE_WINDOW_SECS,
            DEFAULT_BRUTE_THRESHOLD,
            DEFAULT_BRUTE_COOLDOWN_SECS,
        )
    }

    /// Record a connection attempt (a TCP SYN) to `dst_port` from `src` at
    /// `now_ns`. Returns a hit when the cumulative count for that source crosses
    /// the threshold, rate-limited by the per-source cooldown so a campaign fires
    /// once rather than on every attempt. Non-auth ports are ignored.
    pub fn record_syn(&mut self, src: IpAddr, dst_port: u16, now_ns: u64) -> Option<BruteForceHit> {
        if !self.auth_ports.contains(&dst_port) {
            return None;
        }
        let window_ns = self.window_ns;
        let threshold = self.threshold;
        let cooldown_ns = self.cooldown_ns;

        let hit = {
            let rec = self.by_source.entry((src, dst_port)).or_default();
            // Drop attempts that have aged out of the sliding window.
            while let Some(&front) = rec.attempts.front() {
                if now_ns.saturating_sub(front) > window_ns {
                    rec.attempts.pop_front();
                } else {
                    break;
                }
            }
            rec.attempts.push_back(now_ns);

            // last_alert_ns == 0 is the "never alerted" sentinel: the first alert
            // for a source always fires (otherwise an early timestamp below the
            // cooldown would suppress it).
            if rec.attempts.len() >= threshold
                && (rec.last_alert_ns == 0
                    || now_ns.saturating_sub(rec.last_alert_ns) >= cooldown_ns)
            {
                rec.last_alert_ns = now_ns;
                Some(BruteForceHit {
                    attempts: rec.attempts.len(),
                    port: dst_port,
                    window_secs: window_ns / 1_000_000_000,
                })
            } else {
                None
            }
        };

        self.maybe_cleanup(now_ns);
        hit
    }

    /// Drop empty / fully-aged records occasionally so memory stays bounded.
    fn maybe_cleanup(&mut self, now_ns: u64) {
        if now_ns.saturating_sub(self.last_cleanup_ns) < self.window_ns {
            return;
        }
        self.last_cleanup_ns = now_ns;
        let window_ns = self.window_ns;
        self.by_source.retain(|_, rec| {
            while let Some(&front) = rec.attempts.front() {
                if now_ns.saturating_sub(front) > window_ns {
                    rec.attempts.pop_front();
                } else {
                    break;
                }
            }
            !rec.attempts.is_empty()
        });
    }

    /// Number of sources currently tracked (for stats/tests).
    pub fn tracked_sources(&self) -> usize {
        self.by_source.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ports() -> Arc<HashSet<u16>> {
        Arc::new([22u16, 25, 21].into_iter().collect())
    }
    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(45, 33, 1, 1))
    }
    const S: u64 = 1_000_000_000;

    #[test]
    fn slow_smtp_brute_crosses_threshold() {
        // 12 attempts to SMTP, one every 20s — never enough per 10s window, but
        // cumulatively over the 300s window it crosses the threshold of 10.
        let mut t = BruteForceTracker::new(ports(), 300, 10, 60);
        let mut hit = None;
        for i in 0..12u64 {
            if let Some(h) = t.record_syn(ip(), 25, i * 20 * S) {
                hit = Some(h);
            }
        }
        let hit = hit.expect("slow SMTP brute force should be detected");
        assert!(hit.attempts >= 10);
        assert_eq!(hit.port, 25);
    }

    #[test]
    fn non_auth_port_is_ignored() {
        let mut t = BruteForceTracker::new(ports(), 300, 3, 0);
        for i in 0..20u64 {
            assert!(t.record_syn(ip(), 80, i * S).is_none(), "port 80 is not an auth port");
        }
    }

    #[test]
    fn attempts_aging_out_do_not_accumulate() {
        // One attempt every 60s with a 120s window: at most ~2 in-window, never
        // reaching a threshold of 5 — a legitimate periodic login, not a brute.
        let mut t = BruteForceTracker::new(ports(), 120, 5, 0);
        let mut fired = false;
        for i in 0..30u64 {
            if t.record_syn(ip(), 22, i * 60 * S).is_some() {
                fired = true;
            }
        }
        assert!(!fired, "spaced-out attempts must age out, not accumulate");
    }

    #[test]
    fn cooldown_prevents_repeat_alerts() {
        let mut t = BruteForceTracker::new(ports(), 300, 5, 60);
        let mut hits = 0;
        // 30 rapid attempts: crosses threshold but should alert only once within
        // the cooldown.
        for i in 0..30u64 {
            if t.record_syn(ip(), 22, i * S).is_some() {
                hits += 1;
            }
        }
        assert_eq!(hits, 1, "cooldown should collapse a single campaign to one alert");
    }
}
