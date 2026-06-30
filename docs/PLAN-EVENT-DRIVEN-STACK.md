# NORTH STAR — Event-driven stack

**Status:** direction / principle. Not scheduled. Captures the target architecture and the
per-seam path. The Cloudflare reconcile (`docs/PLAN-CF-EVENT-DRIVEN-RECONCILE.md`) is the first
worked instance of this pattern. No code changes implied by this doc.

## The principle (and what it is *not*)

The stack should be **event-driven**, where that means:

> **arrival-driven fast path + backpressure/coalescing + a periodic backstop.**

It does **not** mean "timer-free." The naive reading — fire one unit of work per source event —
is exactly what took this system down once (see The Scar). Every event seam must have all three
properties or it is not done:

1. **Arrival drives the work.** No fixed-interval latency on the hot path; work starts when the
   thing happens, not on the next tick.
2. **Backpressure / coalescing.** One "something changed" wakeup drains *all* currently-pending
   work (to EOF / to empty), debounced. Channels are bounded; the hot path uses `try_send` and is
   allowed to **drop** under overload. A fast producer must never be able to outrun the consumer
   one-event-at-a-time.
3. **A slow backstop timer.** A low-frequency sweep reconciles whatever the fast path missed or
   dropped, so the fast path is *allowed* to be best-effort. The backstop is what makes (2) safe.

Timers don't all disappear. The **polling-for-work** ones do. The survivors are **backstops** and
**irreducible time triggers** (TTL expiry) — safety nets, not the primary path.

## The Scar (the binding constraint)

`src/monitor.rs:360` — *"we deliberately do NOT use an inotify watcher. Watching a busy directory…"*

Log ingest was once event-driven via inotify. On a busy `/var/log`, inotify fired per write (tens
of thousands/sec), saturated the single tokio worker, starved the event loop so detection died, and
the resulting busy-loop filled the disk (the incident in [memory: crmonban-known-bugs]). It was
replaced by a bounded 2s poll. **That poll is the fix for an event-driven failure, not laziness.**
Any move back toward event-driven log ingest must carry property (2) — coalescing — or it
reproduces the storm.

## Current map

| Seam | Today | Target | Notes |
|---|---|---|---|
| Packet engine (`src/engine/mod.rs`) | arrival (`next_packet`→pipeline→verdict) | ✅ already this shape | bypass/drop under load = its backpressure |
| L2 monitor (`src/l2_monitor.rs:106`) | arrival (`next_packet`→`event_tx`) | ✅ already this shape | blocking-thread capture, shared sink |
| Event loop / ban sink (`src/lib.rs:914`) | arrival (`event_tx`→`recv`) | ✅ already this shape | the convergence point all detectors feed |
| Log monitors (`src/monitor.rs:375`) | 2s poll *(scar)* | coalesced inotify + poll **backstop** | see below — the dangerous one |
| Port-scan monitor (`src/port_scan_monitor.rs:344`) | 2s poll *(scar)* | same as log monitors | reads kern.log; same shape |
| CF reconcile (`src/lib.rs:839`) | periodic full sweep | push-on-ban + debounce + sweep backstop | `docs/PLAN-CF-EVENT-DRIVEN-RECONCILE.md` |
| Cleanup / ban expiry (`src/lib.rs:815`) | 60s timer | **stays a timer** | "time passed" *is* a timer; correct as-is |

## Per-seam path

### Log + port-scan ingest — "inotify done right" (the one that bit us)
- One inotify watch per watched file/dir → on any event, **drain the file(s) to EOF** in a single
  pass (the existing `manager.poll()` drain logic at `src/monitor.rs:368/381` is already the drain;
  the change is *what wakes it*).
- **Debounce/coalesce:** collapse a burst of inotify events into one drain (e.g. wake, then sleep a
  few ms, then drain everything pending). Never one-read-per-event.
- **Keep the 2s poll as the backstop** (demoted), so a missed/coalesced-away inotify event or a
  rotated/truncated file still gets picked up. Best-of-both: event latency in the common case,
  poll safety in the tail.
- Net effect: sub-second detection latency without the event storm — the storm came from *no
  coalescing*, not from inotify itself.

### Cloudflare reconcile
- Per `docs/PLAN-CF-EVENT-DRIVEN-RECONCILE.md`: dedicated push worker fed from the ban hotpath
  (`src/lib.rs:946`), debounce/batch, periodic sweep demoted to backstop. This doc's pattern, instantiated.

### Ban expiry
- Leave as a timer. Optionally evolve to a timer-wheel keyed on the nearest expiry (wake exactly
  when the next ban expires instead of every 60s) — an optimization, not an event-driven change;
  expiry has no external event to subscribe to.

### Packet engine
- Already arrival-driven with backpressure. The reference shape. The only watch item is that its
  backpressure (NFQUEUE `bypass` / drop) is *visible* — i.e. surfaced as a metric, not silent — so
  "dropping under load" is observable rather than mistaken for "nothing happening" (cf. the
  `captured` vs `processed` instrumentation added 2026-06-19).

## Anti-patterns (the checklist this doc exists to enforce)

- ❌ One unit of work per source event with no coalescing (the inotify storm).
- ❌ Unbounded channel / `send().await` on the hot path (lets a producer wedge the consumer).
- ❌ Event-driven fast path with **no** backstop (silent permanent drift when an event is lost).
- ❌ Polling-for-work as the *primary* path where an arrival signal exists (adds latency for nothing).
- ✅ Bounded channel + `try_send`/drop + coalesced drain + slow reconciling backstop.

## Rollout ordering (when scheduled)

1. **CF event-driven** — smallest, self-contained, plan already written. Proves the pattern in prod.
2. **Log + port-scan coalesced-inotify** — highest value (detection latency), highest risk (the scar);
   do it only with the debounce + poll-backstop in place and load-test against a busy `/var/log`.
3. **Expiry timer-wheel** — optional polish.

Guiding test for any seam: *does it stay correct and bounded when the source produces 10k events/sec?*
If the answer needs the backstop, that's fine — that's the design. If it needs luck, it's not done.
