# Plan: deploy crmonban on `main` for real-traffic evaluation

Status: **Plan / awaiting go.** A remote-debug deployment of the current crmonban
build onto the production host `main` (45.79.225.213) to evaluate detection,
timing, and events against real internet traffic — **without** affecting live
sites.

## Decisions (locked)
- **Posture: observe-only.** Detect/log/audit everything; ban/drop **nothing**.
- **Detail: event-detail + hourly perf snapshots.** Bounded + rotated; per-packet
  trace only in short on-demand windows.

## 0. Current state of `main` (read-only recon, 2026-06-17)
- x86_64, Debian 12, Linode kernel 7.0.5; 3 vCPU / 5.8 GB; `/` 31 G (9 %),
  **`/var` separate 48 G (7 %)** — log blast-radius is contained to `/var`.
- Docker edge: `caddy` (caddy-cf) publishes 80/443 tcp+udp→host, proxies to
  backend containers (`*-nginx`, `tnv-*`); `postgres` bound to 127.0.0.1.
- crmonban **already running** — `crmonban.service` active, **Dec 29 build**
  (predates our fixes). Config `/etc/crmonban/config.toml`:
  - Caddy `access.log` monitor (web attacks) — **on**.
  - `caddy_tls` monitor (`/opt/caddy/logs/tls.log`) — **on**.
  - `[packet_engine] enabled=true`, **`capture_method="af_packet"`** (passive
    sniff, *no* inline NFQUEUE / no DPI queue chain).
  - nft: only the `input` `@blocked drop` ban chain (priority −100).
  - `log_level="info"`; not logging to journald (sink TBD).
- `svvs` has passwordless sudo; binary root-owned at `/usr/local/bin/crmonban`.

**Implication:** this is a *reconfigure + binary upgrade*, not a fresh install,
and the box is x86_64 Debian 12 — **identical to our build VM, so the binary is
drop-in** (needs `libvectorscan5` for hyperscan).

## 1. Guardrails (non-negotiable — crmonban has a disk-fill/fd-leak history)
- **Observe-only** via `enforce=false` (§2). af_packet stays passive — no inline
  netfilter change, the live sites cannot be blackholed.
- **Hard log caps** + rotation on `/var/log/crmonban` (§5) so detail logging
  cannot fill `/var`.
- **Resource watchdog** (§8): RSS / fd-count / `/var`-usage timer → alert +
  restart on runaway. systemd `MemoryMax`, `LimitNOFILE`, `Restart=on-failure`.
- **Snapshot + one-command rollback** (§4, §12).

## 2. Phase 0 — code prep (small, on our build)
1. **`enforce` flag (observe-only).** Add `[general] enforce = true` (default).
   Gate the single choke point `CrmonbanCore::ban()` (`src/lib.rs:324`): when
   `!enforce`, write a `WOULD_BAN` audit/event record (full context) and **return
   without `firewall.ban()`**. Neutralizes every path (log monitors, packet
   engine `MonitorEvent::Ban` at `lib.rs:768`, manual) while preserving detection
   + audit. This is the FP-measurement instrument.
2. **Structured event sink.** Emit each detection/would-ban as one JSON line to
   `/var/log/crmonban/events-YYYYMMDD.jsonl`: ts, src ip, vhost, service/stage,
   rule/sid, severity, matched content (truncated), **per-stage timing**,
   computed verdict, would-action. (Reuse the existing event/DB path + a JSONL
   writer; don't rely on journald.)
3. **Perf snapshots.** With the `profiling` feature, emit a p50/p95/p99 latency +
   throughput + queue/observed-pps line hourly to
   `/var/log/crmonban/perf-YYYYMMDD.log`.
4. (already done) the `CRMONBAN_TRACE_PACKETS` env toggle for short deep-dives.

## 3. Pipeline / detection config for the eval
- Keep `capture_method="af_packet"` (passive) — L3/4 + flow + timing, zero inline
  risk. (NFQUEUE inline is a *later* phase, separate go.)
- Keep Caddy `access.log` + `tls.log` monitors on — the real HTTP + TLS-metadata
  surface (decrypted requests where the actual web attacks are visible).
- Load the full ruleset (`/var/lib/crmonban/data/rules`) so SignatureMatching is
  live (push our local + ET Open set; ~34 k rules, ~0.5 GB RAM — fine on 5.8 GB).
- `log_level="info"` globally; event detail goes to the JSONL sink, not the
  console, to keep volume bounded.

## 4. Phase 1 — build & stage
- Build release (x86_64, default features incl. hyperscan) — same artifact as the
  VM build. `apt install libvectorscan5` on `main` (runtime dep).
- **Snapshot:** copy `/usr/local/bin/crmonban` → `~/crmonban.bak-<date>` and
  `/etc/crmonban/config.toml` → `~/config.toml.bak-<date>`.
- Stage new binary + edited config (enforce=false, rules dir, log sink) but do not
  cut over yet.

## 5. Logging design (bounded)
- Dir `/var/log/crmonban/`: `events-*.jsonl`, `perf-*.log`, `audit-*.txt`.
- `logrotate`: daily, `rotate 14`, `compress`, **`maxsize 500M`**, `missingok`,
  `copytruncate`. Total cap well under `/var`'s 44 G free.
- Disk guard in the watchdog: if `/var` > 80 %, stop the detail sink + alert.

## 6. Phase 2 — cut over to observe-only
1. `systemctl stop crmonban`; install new binary + config.
2. `systemctl start crmonban`; verify:
   - log: monitors + af_packet engine up; rules loaded + hyperscan built;
   - nft: **only** the `@blocked` chain, **no `dpi_inspect`/queue** (af_packet);
   - drive a known-benign + a synthetic attack (curl a SQLi-looking URI at a test
     vhost) → confirm a `WOULD_BAN` event is logged and **no nft ban appears**;
   - `crmonban` RSS/fd steady.
3. Let it run on real traffic.

## 7. Daily audit / report
- `crmonban-audit.timer` (daily, + optional hourly rollup) runs a script that
  summarizes the day's `events-*.jsonl` into `audit-YYYYMMDD.txt`:
  - counts by detection type / severity / service/stage;
  - **would-bans** (count + top sources + which rule) ← the core eval output;
  - top source IPs / vhosts / URIs; bot vs human; geo if cheap;
  - **FP candidates** (would-bans on traffic that looks legitimate);
  - latency p50/p95/p99 + throughput (from perf log); resource high-water.
- **Delivery:** email via main's existing msmtp **and** leave in
  `/var/log/crmonban/` for the **home log-pull cron** to fetch.

## 8. Resource watchdog (the known-bug guard)
- systemd drop-in: `MemoryMax=1500M`, `LimitNOFILE=4096`,
  `Restart=on-failure`, `RestartSec=10`.
- `crmonban-watch.timer` (every 5 min): check crmonban RSS, fd count
  (`ls /proc/$(pidof crmonban)/fd | wc -l`), and `/var` usage; on threshold →
  log + email + `systemctl restart crmonban`; record to `audit`.

## 9. Remote-debug workflow (me, from home)
- Home cron already pulls server logs; extend it to fetch
  `/var/log/crmonban/{events,perf,audit}-*` into the home tree daily.
- I analyze: detection volume + mix, would-ban list & **FP rate**, latency
  distributions, resource trend, rule noise (top-firing SIDs), coverage gaps.
- Feedback loop: tune noisy rules (the ET-INFO work), confirm true positives,
  decide if/when to graduate from observe-only to enforce.

## 10. Evaluation metrics (what "good" looks like)
- **Detection:** TP confirmed by spot-check; attack types seen on real traffic.
- **False positives:** would-bans / day on legitimate traffic → must trend → ~0
  before any enforcement.
- **Performance:** per-event p50/p95/p99; sustained pps; CPU%; **RSS/fd stable
  over days** (the leak check).
- **Stability:** zero unplanned restarts; `/var` flat.

## 11. Timeline / cadence
- Day 0: Phase 0 code + build + stage + cut over to observe-only.
- Days 1–7: daily audit pulled home + reviewed; tune noisy rules; watch
  resources. "more than daily" = the hourly perf rollup + on-demand trace windows.
- After a clean week (low FP, stable resources): decide on graduating to
  log-based enforcement, then (separate go, separate risk review) inline NFQUEUE.

## 12. Rollback
`systemctl stop crmonban` → restore `~/crmonban.bak-<date>` and
`~/config.toml.bak-<date>` → `systemctl start crmonban`. Drop the nft table +
`/var/log/crmonban` if backing all the way out.

## 13. Open items / risks
- Locate the current log sink (journald shows nothing) before cut-over.
- Confirm the af_packet engine's interface on `main` (host iface vs docker
  bridges) so it sees the right traffic; access.log is the primary surface
  regardless.
- ET-Open rule noise on real traffic — expect to tune (use the existing severity
  filter + per-SID excludes).
- Inline NFQUEUE on this Docker host (80/443 are DNAT→forward to the caddy
  container) is **out of scope** for this eval; it needs forward-mode + a
  separate risk review.
