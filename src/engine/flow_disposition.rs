//! Per-flow verdict cache (inline DPI milestone M3).
//!
//! Caches a flow's terminal disposition so subsequent packets of an
//! already-judged stream short-circuit the 8-stage pipeline:
//!
//! - a **bad** stream is dropped without re-inspection — once any packet of a
//!   flow is flagged blocking, the bad disposition is *sticky* for the rest of
//!   the stream (the user's "new drop removes the stream from processing"), and
//! - a **good** stream can be *bypassed* (accepted without re-inspection) once it
//!   is proven safe to bypass.
//!
//! The "can this flow still go bad?" gate is deliberately conservative: good
//! bypass is **off by default**, so a good-looking flow keeps being inspected
//! unless an operator opts in (the user's "if there is a possibility of bad
//! packets they are continued"). Bad short-circuiting is always on.
//!
//! Scope (M3): this cache only *accelerates* a flow's verdict — a bad stream is
//! dropped without re-inspection. The "until banned and audited" resolution
//! (move the source into the in-kernel `@blocked` set + emit the audit) is the
//! separate ban path (ActionExecutor/firewall) and is not performed here.
//!
//! See `docs/DESIGN-FLOW-DISPOSITION.md`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::core::FlowKey;

/// Terminal disposition cached for a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDisposition {
    /// Proven good and safe to bypass: accept without re-inspection.
    Good,
    /// Flagged bad: drop the rest of the stream without re-inspection.
    Bad,
}

/// Configuration for the per-flow verdict cache.
#[derive(Debug, Clone)]
pub struct FlowVerdictCacheConfig {
    /// Master switch. When false the cache is inert and every packet is fully
    /// inspected.
    pub enabled: bool,
    /// Allow caching GOOD flows for bypass. When false (default) only bad
    /// streams short-circuit; good flows are always re-inspected, because a
    /// flow that looks good now can still carry an attack later.
    ///
    /// EXPERIMENTAL: the current eligibility gate is a raw clean-packet count and
    /// is direction-blind (server responses count too). Do NOT enable for
    /// keep-alive / HTTP-2 / persistent-TLS flows — a later request could be the
    /// attack. See DESIGN-FLOW-DISPOSITION.md §4 for the proper gate.
    pub bypass_good: bool,
    /// Clean (accepted) packets a flow must accumulate before it becomes
    /// eligible for a GOOD bypass. Bounds the "judged good too early" window.
    pub bypass_after_packets: u32,
    /// TTL for a cached GOOD disposition; the flow is re-inspected after it
    /// expires, bounding how long a bypass can stay blind to a mid-stream turn.
    pub good_ttl: Duration,
    /// TTL for a cached BAD disposition.
    pub bad_ttl: Duration,
    /// Soft cap on cached flows. At the cap, an expiry sweep runs; if still full
    /// the flow is left uncached (re-inspected) rather than evicting a live entry.
    pub max_flows: usize,
    /// How often to sweep expired entries.
    pub sweep_interval: Duration,
}

impl Default for FlowVerdictCacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bypass_good: false,
            bypass_after_packets: 8,
            good_ttl: Duration::from_secs(60),
            // Kept short (~TCP TIME_WAIT) so a recycled 5-tuple / NAT reuse does
            // not inherit a stale BAD verdict for long. SYN invalidation handles
            // new TCP connections explicitly; this bounds the UDP/lingering case.
            bad_ttl: Duration::from_secs(120),
            max_flows: 100_000,
            sweep_interval: Duration::from_secs(1),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    disposition: FlowDisposition,
    expires_at: Instant,
}

/// Cache hit/miss/short-circuit counters (observability).
#[derive(Debug, Clone, Copy, Default)]
pub struct FlowCacheStats {
    /// Packets accepted via a cached GOOD bypass (stages skipped).
    pub bypass_hits: u64,
    /// Packets dropped via a cached BAD disposition (stages skipped).
    pub bad_hits: u64,
    /// Packets that had no cache entry and were fully inspected.
    pub misses: u64,
}

/// Per-flow verdict cache. Single-threaded: owned and driven by the pipeline
/// task, so it needs no interior locking.
pub struct FlowVerdictCache {
    config: FlowVerdictCacheConfig,
    entries: HashMap<FlowKey, Entry>,
    /// Clean-packet counters for not-yet-cached flows (drives bypass_after_packets).
    /// Dormant unless `bypass_good` is enabled.
    pending_good: HashMap<FlowKey, u32>,
    last_sweep: Instant,
    stats: FlowCacheStats,
}

impl FlowVerdictCache {
    pub fn new(config: FlowVerdictCacheConfig) -> Self {
        Self {
            entries: HashMap::with_capacity((config.max_flows / 4).max(16)),
            pending_good: HashMap::new(),
            last_sweep: Instant::now(),
            config,
            stats: FlowCacheStats::default(),
        }
    }

    /// Look up a cached verdict for this flow.
    ///
    /// Returns `Some(true)` for a cached GOOD (accept, skip inspection),
    /// `Some(false)` for a cached BAD (drop, skip inspection), or `None` if the
    /// flow has no live entry and must be inspected. Expired entries are dropped
    /// and treated as a miss so the flow is re-inspected.
    pub fn lookup(&mut self, key: &FlowKey, now: Instant) -> Option<bool> {
        if !self.config.enabled {
            return None;
        }
        // Time-driven expiry: runs at most once per sweep_interval regardless of
        // the hit/miss ratio, so cleanup does not depend on miss traffic.
        self.maybe_sweep(now);
        match self.entries.get(key) {
            Some(e) if e.expires_at > now => {
                let accept = e.disposition == FlowDisposition::Good;
                if accept {
                    self.stats.bypass_hits += 1;
                } else {
                    self.stats.bad_hits += 1;
                }
                Some(accept)
            }
            Some(_) => {
                // Expired: re-inspect.
                self.entries.remove(key);
                self.stats.misses += 1;
                None
            }
            None => {
                self.stats.misses += 1;
                None
            }
        }
    }

    /// Record the outcome of fully inspecting a packet of `key`.
    ///
    /// `blocking` is true when the packet's verdict was Drop/Reject. A blocking
    /// verdict marks the whole flow bad (sticky); a clean verdict advances the
    /// good-bypass counter only when `bypass_good` is enabled.
    ///
    /// Returns `true` when this call transitioned the flow to a cached GOOD
    /// disposition (so the caller can mark it for the in-kernel bypass).
    pub fn record(&mut self, key: &FlowKey, blocking: bool, now: Instant) -> bool {
        if !self.config.enabled {
            return false;
        }

        let mut became_good = false;
        if blocking {
            // Bad is sticky for the rest of the stream.
            self.pending_good.remove(key);
            self.insert(
                key,
                Entry {
                    disposition: FlowDisposition::Bad,
                    expires_at: now + self.config.bad_ttl,
                },
                now,
            );
        } else if self.config.bypass_good {
            let n = self.pending_good.entry(key.clone()).or_insert(0);
            *n += 1;
            if *n >= self.config.bypass_after_packets {
                self.pending_good.remove(key);
                self.insert(
                    key,
                    Entry {
                        disposition: FlowDisposition::Good,
                        expires_at: now + self.config.good_ttl,
                    },
                    now,
                );
                became_good = true;
            } else if self.pending_good.len() > self.config.max_flows {
                // Bound the counter map; resetting only delays a bypass (safe).
                self.pending_good.clear();
            }
        }

        self.maybe_sweep(now);
        became_good
    }

    /// Forget any cached verdict (and good-progress) for a flow — used when a new
    /// TCP connection (SYN) reuses a 5-tuple, so the new instance is re-inspected
    /// instead of inheriting the previous connection's verdict.
    pub fn invalidate(&mut self, key: &FlowKey) {
        self.entries.remove(key);
        self.pending_good.remove(key);
    }

    /// Insert/refresh an entry, honoring the cap. A refresh of an existing key
    /// always succeeds. A new key past the cap triggers a sweep; if still full,
    /// an arbitrary live entry is evicted so a fresh verdict is never starved —
    /// this stops a flood of unique bad 5-tuples from pinning the cache.
    fn insert(&mut self, key: &FlowKey, entry: Entry, now: Instant) {
        if self.entries.contains_key(key) {
            self.entries.insert(key.clone(), entry);
            return;
        }
        if self.entries.len() >= self.config.max_flows {
            self.sweep(now);
            if self.entries.len() >= self.config.max_flows {
                if let Some(victim) = self.entries.keys().next().cloned() {
                    self.entries.remove(&victim);
                }
            }
        }
        self.entries.insert(key.clone(), entry);
    }

    fn maybe_sweep(&mut self, now: Instant) {
        if now.duration_since(self.last_sweep) >= self.config.sweep_interval {
            self.sweep(now);
        }
    }

    fn sweep(&mut self, now: Instant) {
        self.entries.retain(|_, e| e.expires_at > now);
        self.last_sweep = now;
    }

    /// Number of cached flow dispositions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn stats(&self) -> FlowCacheStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::IpProtocol;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(p: u16) -> FlowKey {
        FlowKey {
            ip_a: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ip_b: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            port_a: 1000,
            port_b: p,
            protocol: IpProtocol::Tcp,
        }
    }

    #[test]
    fn bad_is_sticky_and_short_circuits() {
        let mut c = FlowVerdictCache::new(FlowVerdictCacheConfig::default());
        let now = Instant::now();
        let k = key(80);
        assert_eq!(c.lookup(&k, now), None); // first packet: inspect
        c.record(&k, true, now); // flagged bad
        assert_eq!(c.lookup(&k, now), Some(false)); // rest of stream: drop, no inspect
    }

    #[test]
    fn good_not_cached_by_default() {
        let mut c = FlowVerdictCache::new(FlowVerdictCacheConfig::default());
        let now = Instant::now();
        let k = key(443);
        for _ in 0..50 {
            c.record(&k, false, now); // clean packets
        }
        assert_eq!(c.lookup(&k, now), None); // still inspected: no auto-bypass
    }

    #[test]
    fn good_bypass_after_threshold_when_enabled() {
        let cfg = FlowVerdictCacheConfig {
            bypass_good: true,
            bypass_after_packets: 3,
            ..Default::default()
        };
        let mut c = FlowVerdictCache::new(cfg);
        let now = Instant::now();
        let k = key(443);
        c.record(&k, false, now);
        c.record(&k, false, now);
        assert_eq!(c.lookup(&k, now), None); // not yet (2 < 3)
        c.record(&k, false, now); // 3rd clean packet
        assert_eq!(c.lookup(&k, now), Some(true)); // now bypassed
    }

    #[test]
    fn expired_entry_is_a_miss() {
        let mut c = FlowVerdictCache::new(FlowVerdictCacheConfig::default());
        let now = Instant::now();
        let k = key(80);
        c.record(&k, true, now);
        let later = now + Duration::from_secs(121); // past bad_ttl (120s)
        assert_eq!(c.lookup(&k, later), None);
    }

    #[test]
    fn invalidate_forgets_verdict() {
        let mut c = FlowVerdictCache::new(FlowVerdictCacheConfig::default());
        let now = Instant::now();
        let k = key(80);
        c.record(&k, true, now);
        assert_eq!(c.lookup(&k, now), Some(false));
        c.invalidate(&k);
        assert_eq!(c.lookup(&k, now), None);
    }

    #[test]
    fn cap_evicts_rather_than_freezing() {
        let cfg = FlowVerdictCacheConfig {
            max_flows: 4,
            ..Default::default()
        };
        let mut c = FlowVerdictCache::new(cfg);
        let now = Instant::now();
        // Insert far more bad flows than the cap: size must stay bounded and the
        // freshest verdict must still be admitted (the cache never freezes).
        for p in 0..20u16 {
            c.record(&key(p), true, now);
        }
        assert!(c.len() <= 4, "cache exceeded cap: {}", c.len());
        assert_eq!(c.lookup(&key(19), now), Some(false));
    }
}
