# Design — Long-Term Behavioral VectorDB

Status: design (approved) — implementing in phases.

## 1. Problem

The Layer234 detectors operate on **10-second per-source windows**. That catches
bursty attacks (scans, floods, fast brute force) but is structurally blind to
**slow / persistent** behavior, because:

- A window that holds only a slice of time never accumulates the signal.
- The window feature vector normalizes rate/volume for *massive* attack scales
  (50k pps, 125 MB/s), so realistic-scale differences collapse to ~0 distance —
  the short-term anomaly baseline (`baseline_store`, Euclidean) measured a
  bulk-exfil window at distance **0.0036** from normal. The signal is absent, not
  mis-thresholded.

Slow threats that slip through today: **beaconing/C2, data exfiltration,
low-and-slow scans, slow brute force, behavioral drift (compromise).**

## 2. Approach

Profile each **source over a long horizon (minutes–hours)** in a dedicated
vector store, separate from the short-term path. Aggregating per-source over an
hour makes the same differences **large and discriminative** (exfil = 100× normal
cumulative bytes; a beacon's inter-arrival variance ≈ 0; a slow scan touches 50×
the ports). Volume features are **log-scaled** so we never repeat the
collapse-to-zero mistake.

This is the learned successor to the hand-rolled `BruteForceTracker` (cumulative
slow-brute counter) — that counter is long-term tracking v0; this generalizes it.

**Out of scope:** payload inspection (SQLi, Log4Shell, DNS-tunnel content) stays
with the protocol/signature engines. This path is behavioral / volumetric /
temporal only. It will not catch deliberately-randomized-interval C2 (noted in
risks).

## 3. Architecture

### 3.1 Tracking unit & state

Per **source IP**, in a bounded `HashMap<IpAddr, LongTermProfile>` with
activity-based eviction (same shape and injectable clock — `packet.timestamp_ns()`
— as `BruteForceTracker`, so it stays deterministic and testable).

**Memory model: sliding window of epochs.** Each profile keeps the last `N`
completed **epoch snapshots** (e.g. 60 epochs × 60 s = 1 h) plus the in-progress
epoch. A sliding window (vs EWMA) is chosen so periodicity / coefficient-of-
variation can be computed exactly from real inter-arrival timestamps.

```
EpochStats        // one epoch's raw accumulators for a source
  start_ns
  bytes_sent, packets, syns, auth_syns
  dst_ports: capped set        distinct destination ports
  dst_ips:   capped set        distinct destination IPs
  conn_times: Vec<u64>         SYN timestamps (for periodicity)

LongTermProfile
  current: EpochStats
  epochs:  VecDeque<EpochStats>   // last N completed epochs (the sliding window)
  ewma:    ProfileVector          // self-drift reference (see 3.3)
  last_seen_ns
```

Per-packet update is **O(1)** (bump counters in `current`). On epoch rollover
(driven by packet timestamps), push `current` into `epochs`, drop the oldest
beyond the horizon, reset `current`.

### 3.2 Feature vector (the crux)

Computed at epoch rollover from the sliding window. Fixed-size `[f32; LONGTERM_DIM]`
for the vector store. Each feature is chosen so the magnitude difference is large
at long horizon:

| Feature | Signal it carries |
| --- | --- |
| `log1p(cum_bytes_sent)` | exfil / bulk upload volume |
| connection inter-arrival **CV** (std/mean) | **beaconing** — low CV = regular cadence |
| connection count over horizon | beaconing support / activity |
| active-epoch ratio | persistence (active across many small epochs) |
| distinct dst ports over horizon | low-and-slow scan fan-out |
| dst-port entropy | scan vs normal service use |
| distinct dst IPs over horizon | network sweep |
| cumulative auth-port SYNs | slow brute (subsumes the counter) |
| packets/epoch cadence, mean conn duration | volumetric / cadence anomalies |

Volume features are log-scaled; counts normalized against horizon-appropriate
caps (validated in Phase D, **not** the 50k-pps scale that broke the short-term
path).

### 3.3 Detection — two signals (self-drift primary)

1. **Self-drift (primary).** Compare a source's *current* profile vector to its
   own recent EWMA. A host that suddenly starts beaconing / exfiltrating /
   scanning drifts from its own history. Robust across heterogeneous hosts (a
   quiet client and a busy server each compared to themselves — no cross-host
   false positives). Distance > `self_drift_threshold` ⇒ drift event.

2. **Population anomaly (backstop).** A new `LongTermStore` — crvecdb, **Euclidean**
   — holds learned *normal host profiles*. A source whose profile is far from
   every normal profile is anomalous even with no clean self-history (a host that
   was bad from first observation). Online-learned from clean hosts, gated by a
   warmup count (`min_baseline_profiles`); flagged hosts are never learned
   (poison guard) — same discipline as `baseline_store`.

A source is flagged if **either** fires. Self-drift covers compromise; population
anomaly covers born-bad hosts.

### 3.4 Epoch evaluation

Evaluate a source on **epoch rollover**, not per-packet (the signal is long-term
and per-packet evaluation is wasteful). Time advances from packet timestamps, so
a quiet source is evaluated when its next packet crosses the boundary, and idle
sources are swept by the periodic eviction pass.

## 4. Integration & verdict

- New `long_term_tracker` field on the Layer234 `Detector` (mirrors
  `brute_tracker`).
- `Detector::process`: O(1) per-packet feed; on epoch boundary, roll up → run
  both signals → emit events.
- Events: `DetectionType::{Beaconing, DataExfiltration, AnomalyDetection}`,
  action **Ban**, severity High. Long-term detection is inherently after-the-fact:
  it identifies a bad **source**, bans it, and inline drops follow via the
  existing ban path. `event.src_ip` is the banned entity, so attribution is
  correct regardless of which packet carries the event.

## 5. Config (`LongTermSettings`, mirroring existing config patterns)

`enable`, `epoch_secs`, `horizon_epochs`, `max_sources` (capacity + eviction),
`min_baseline_profiles` (warmup), `population_threshold`, `self_drift_threshold`,
`auto_learn`.

## 6. Phasing

- **Phase A — state + features.** `LongTermProfile`, per-packet update, epoch
  rollup, feature vector. Unit tests: synthetic beacon ⇒ high periodicity (low
  CV); exfil ⇒ high volume; slow scan ⇒ high port fan-out; normal ⇒ none.
- **Phase B — store + detection.** `LongTermStore` (Euclidean) population anomaly
  + online learn + warmup; self-drift EWMA. Emit events.
- **Phase C — integration.** Wire into `Detector::process` (feed + epoch eval),
  ban routing, `LongTermSettings` config.
- **Phase D — validation.** Extend the anomaly harness: simulate a diverse normal
  host population over (virtual) time to train, then inject beacon / exfil /
  slow-scan sources; confirm detection at low false-positive rate; tune.

## 7. Risks & mitigations

- **Periodicity is hard** (jittered/randomized beacons) — CV + active-epoch ratio
  together; accept that fully-randomized C2 evades a cadence detector (documented
  limitation).
- **Normalization collapse (again)** — log-scale volume; pick caps from realistic
  per-source hourly behavior; validate in Phase D before trusting thresholds.
- **Heterogeneous hosts ⇒ false positives** — self-drift primary; diverse
  population training for the backstop.
- **Memory** — bounded `max_sources` + activity eviction; the sliding window is
  the per-source cost, so the horizon and source cap bound total state.
- **Cold start** — warmup gate; until trained, learn-only (no population
  detection); self-drift needs a few epochs of history before it fires.

## 8. Validation targets (Phase D exit criteria)

The four currently-missed behavioral novels — **beaconing, bulk exfil,
low-and-slow scan, slow brute** — caught, with the normal control clean.
