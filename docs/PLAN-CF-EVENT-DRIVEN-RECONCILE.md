# PLAN — Event-driven Cloudflare reconcile

**Status:** deferred (agreed better; do later). Periodic reconcile stays in place until this lands.

## Goal

Push a ban to the Cloudflare edge **the moment it is committed locally**, instead of
waiting for the next periodic sweep. Eliminates the transient window where the local
nft `@blocked` set is ahead of CF (the "4-vs-5" we saw — local ban immediate, CF push
on the next periodic pass). Keep the periodic sweep as a **backstop**, not the primary path.

## Current state (as of 2026-06-19)

- **Local ban (immediate):** event loop `MonitorEvent::Ban` handler — `src/lib.rs:914`
  → whitelist check → `crmonban.ban(ip, …)` (`src/lib.rs:939`) → `db.add_ban` (`src/lib.rs:372`)
  + nft `@blocked` + D-Bus signal. Synchronous, fast, local-only.
- **CF push (delayed):** a **separate periodic task** — `src/lib.rs:825-867`. Every
  `cloudflare.reconcile_interval_secs` (`.max(10)`) it snapshots active bans and calls
  `cloudflare_api::reconcile_once(cfg, active)` → a **full diff** (list edge state, compute
  add+remove). Gated on `cloudflare.enabled && general.enforce`.
- **CF API primitives that already exist** (`src/cloudflare_api.rs`):
  - list mode: `add_items(list_id, &[ip])` (`:230`), `remove_items(list_id, &[item_id])` (`:259`)
  - access_rules mode: `add_zone_block(zone, ip)`, `remove_zone_rule(zone, id)`, `zone_block_rules(zone)`
  - `edge_list(cfg)` (`:491+`) for listing; `reconcile_access_rules` / `reconcile` for the full sweep.

So all the incremental pieces exist; what's missing is a path that fires them on the ban event.

## Design

A **dedicated CF-push worker task** fed by an mpsc channel — keeps network I/O off the event loop
and lets us **batch** (a scan that bans 50 IPs in a second must not become 50 sequential CF calls).

```
event loop (Ban committed) ──(ip, Add)──┐
cleanup/unban (ban expired) ─(ip, Remove)┤── mpsc ──► CF-push worker
                                          │             • debounce ~1s OR N IPs
                                          │             • batch add_items / add_zone_block(×zones)
                                          │             • tolerate "already exists" (idempotent)
periodic reconcile (backstop, lower freq)─┘             • on error → leave for the backstop sweep
```

### Pieces

1. **Channel + worker.** New `mpsc::Sender<CfEdgeOp>` (where `CfEdgeOp = Add(IpAddr) | Remove(IpAddr)`),
   created in the daemon, cloned to the event loop + cleanup task. A `tokio::spawn` worker drains it,
   coalesces into a batch over a short debounce window (e.g. 1s or 64 IPs), then calls the incremental API.
   Gated on `cloudflare.enabled && general.enforce` (snapshot the flag per batch, mirror the existing
   reconciler's "snapshot under lock, release before I/O" rule — `src/lib.rs:842-856`).
2. **Emit on ban.** After `crmonban.ban(...)` succeeds (`src/lib.rs:946` else-branch), `try_send(Add(ip))`.
   `try_send` (non-blocking) so a full/closed channel never stalls the event loop — a dropped enqueue
   is harmless because the periodic backstop still catches it.
3. **Emit on unban.** Hook the expiry/cleanup path (the 60s cleanup task, `src/lib.rs:815`) and any manual
   unban → `Remove(ip)`. **Phase 2** — adds are the urgent half (a ban must bite fast); removes are not
   time-critical and the backstop already handles them.
4. **New API helpers** in `cloudflare_api.rs` (thin wrappers over the existing primitives):
   - `push_bans(cfg, &[ip])` — add a batch across all zones (access_rules) or to the list. Idempotent.
   - `remove_bans(cfg, &[ip])` — resolve ip→rule_id/item_id per zone/list and delete.
5. **Keep the periodic reconcile** as the backstop, but it can drop to a longer interval (e.g. 5–10 min):
   it now only fixes drift, missed/failed pushes, and expiry removals — not the steady-state path.

## Safety / correctness

- **Never block the event loop:** worker model + `try_send`. No network I/O on the ban hotpath.
- **Idempotent adds:** CF "rule already exists" must be a no-op (the periodic sweep already relies on this).
- **enforce gating:** observe mode (`enforce=false`) never enqueues/pushes — same as the reconciler today.
- **Whitelist:** already enforced before `crmonban.ban` (`src/lib.rs:918`), so only real bans get enqueued.
- **Self-healing:** any failed/dropped incremental op is reconciled by the next backstop sweep. The
  backstop is what makes the fast path allowed to be best-effort.
- **Burst control:** debounce/batch prevents a scan-driven ban storm from tripping CF API rate limits.

## Phases

- **P1 — immediate add (the win):** channel + worker + emit-on-ban + `push_bans` + keep periodic as backstop.
- **P2 — immediate remove:** emit-on-unban + `remove_bans`; shorten nothing else.
- **P3 — tune:** lengthen the backstop interval; metrics (enqueued / pushed / dropped / backstop-corrected);
  optional small bounded retry in the worker before deferring to the backstop.

## Testing

- VM (CF disabled): unit-test the batching/debounce worker with a mock sink; assert coalescing + idempotency.
- Staging/main (CF enabled, enforce=true): ban a test IP → assert it appears at CF within ~1–2s
  (`crmonban cloudflare list`) instead of up to one reconcile interval; expire it → assert removal;
  drift test: manually delete a CF rule → assert the backstop restores it.

## Open decisions

- Debounce window + batch cap (start 1s / 64 IPs).
- Backstop interval after P1 (start 300s).
- Whether P2 removal is event-driven or left entirely to the backstop (removals aren't urgent).
