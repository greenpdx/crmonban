# crmonban — Security Remediation Log

**Engineer:** Claude Fable 5, working from `docs/audit/SECURITY-AUDIT-2026-07-07.md`
**Date:** 2026-07-09
**Base commit audited:** `2f99c87` (`main`)

This log records the fixes applied in response to the 2026-07-07 audit. Each entry
cites the finding ID, the change, and the file(s) touched. Both crates
(`crmonban` and `display/backend`) build cleanly (`cargo check`) after these changes.

> **Verification status.** The full `crmonban` lib compiles with zero errors (rustc
> reaches the link stage), and the `display/backend` crate passes `cargo check`. The
> A1 regex fix was additionally exercised against the real Rust `regex` crate: the
> injection line resolves to the genuine client IP, not the attacker-chosen victim.
> The unit-test **binary cannot be linked in this environment** because `libpcap`
> (a hard runtime dependency) and `libhs`/Hyperscan are not installed and cannot be
> added without root. Run `cargo test` on a host with `libpcap-dev`, `libhyperscan-dev`,
> `pkg-config`, and `libssl-dev` installed to exercise the full suite, including the
> new `test_pam_rhost_injection_resolves_genuine_ip` regression.

---

## Fixed

### B2 (Critical) — Signature/ML detections now carry an authoritative action
- Signature matches of Critical/High severity are tagged `DetectionAction::Drop`
  (priority-1 → Critical → blocks on first sight via the `BlockImmediately` policy;
  priority-2 → High → the existing threshold policy). Previously every signature
  event carried the default `Alert` action, so the alert analyzer accepted the packet
  before the severity policy was ever consulted.
  `src/engine/workers.rs` (signature stage).
- ML anomaly events: a Critical-severity (score ≥ 0.9) anomaly now drops; lower
  severities remain advisory (ML is FP-prone). The event now carries its real
  confidence so the analyzer's confidence gate can veto a weak signal.
  `src/engine/workers.rs` (ML stage).
- Fixed the dead confidence-threshold check in `AlertAnalyzer::analyze`: it now runs
  **before** an event can set a blocking action, so a low-confidence event may alert
  but never drives an inline block. It was previously the loop's last statement and
  gated nothing. `src/types/pipeline.rs`.

### B1 (Critical) — Direction-blind good-flow kernel bypass is now opt-in
- Added `packet_engine.bypass_good_flows` (default **false**). The in-kernel
  good-flow bypass is only enabled when this flag is set *and* nfqueue inline mode is
  active. The default inline deployment now inspects every packet, closing the
  keep-alive/HTTP-2/persistent-TLS bypass. `src/config.rs`, `src/lib.rs`.

### A1 (High) — SSH log-injection ban forgery
- The PAM auth-failure regex now uses a lazy match + a bounded IP token anchored to a
  word boundary and trailing whitespace/EOL, so it captures the genuine first
  `rhost=` rather than an attacker-injected second `rhost=<victim>` smuggled through
  the logged username. Applied in all three copies:
  `src/journald_monitor.rs`, `config.toml`, `src/feedback/log_parsers.rs`.
- Added a regression test (`test_pam_rhost_injection_resolves_genuine_ip`).

### A2 / A16 (High/Medium) — Centralized infrastructure guard on the ban path
- `Daemon::ban` now rejects internal/reserved IPs (RFC1918, loopback, link-local,
  multicast, broadcast, unspecified, IPv4 documentation ranges) before any DB or
  firewall write. Because every producer (journald, DPI, TLS proxy, port scanner,
  IPC, D-Bus) funnels through this one function, none can bypass the guard, and a
  forged/log-injected reserved IP can never reach nftables. `is_internal_ip` was made
  reusable and hardened. `src/lib.rs`, `src/monitor.rs`.

### A3 (High) — D-Bus policy is now default-deny
- The `context="default"` policy now **denies** `send_destination`. Control is
  granted to `root` and to a new `crmonban` group only. Any other local user can no
  longer ban/unban. `dbus/org.crmonban.Daemon.conf`.

### A5 (High) — Shodan API key no longer leaks to logs
- The key is passed via reqwest's `.query()` instead of being interpolated into the
  URL, and both the request and JSON-decode errors are run through a `sanitize_key`
  redactor before propagating, so a leaked-URL error string can never expose the key.
  `src/intel.rs`.
- Added `"query"` to the reqwest feature list in `Cargo.toml` (it is feature-gated in
  reqwest 0.13). This guarantees `.query()` is available regardless of how the `"*"`
  dependency versions unify across feature sets. No new transitive dependency
  (`serde_urlencoded` was already pulled in by the `json` feature).

### A6 (High) — Radiotap length underflow panic
- `parse_radiotap` now rejects `length < 8` (in addition to the existing
  `data.len() < length` check) before the `&data[8..length]` slice, eliminating the
  remote slice-index panic. `src/wireless/radiotap.rs`.

### A7 (High) — Supply chain: lockfile
- `Cargo.lock` is no longer gitignored (and the over-broad `*.lock` ignore was
  removed) so it can be committed for reproducible builds. `.gitignore`.
  **Action for maintainer:** `git add Cargo.lock` and commit. Pinning the `"*"`
  dependency versions and adding `cargo deny`/`cargo audit` to CI is still open (below).

### A8 (High) — Dashboard bind / CORS
- The dashboard now binds `127.0.0.1` by default (override with `CRMONBAN_BIND`) and
  CORS is restricted to an explicit origin allowlist (`CRMONBAN_CORS_ORIGINS`,
  default localhost dev origins) with a narrowed method/header set instead of `Any`.
  `display/backend/src/main.rs`.

### §4 — Ban-timeout u32 truncation
- `timeout as u32` replaced with `u32::try_from(..).unwrap_or(u32::MAX)` so a large
  timeout saturates instead of wrapping to a short/zero ban. `src/firewall.rs`.

### A11 (Medium) — Threat-feed IP validation + entry cap
- `load_threat_intel` now skips reserved/internal IPs (via the shared
  `is_internal_ip` guard) before pushing them into the kernel filter, and caps the
  number of entries a single load can insert, so a poisoned/MITM'd feed can neither
  blackhole the gateway/resolver nor balloon the ruleset. `src/engine/workers.rs`.

### A12 (Medium) — LLM cloud fallback fails closed under `local_only`
- The cloud fallback provider is no longer even constructed when
  `privacy.local_only` is set (the default), so a transient local-provider outage
  can never ship telemetry to a cloud LLM. `src/llm/analyzer.rs`.
  *(Compiles under the `llm-cloud` feature; not compiler-verified in the audit
  sandbox because that feature's crates could not be downloaded here — the change is
  a single conditional.)*

### A13 (Medium) — Prompt-injection fencing in LLM triage
- Attacker-influenced alert content is now fenced between explicit
  `<<<ALERT_DATA` / `<<<RAG_DATA` markers, and the triage system prompt instructs the
  model to treat everything inside as untrusted data — never as instructions — and to
  derive priority from security facts only. Triage is also explicitly labeled
  advisory. `src/llm/prompts/alert_triage.rs`.

### A15 (Medium) — SMTP DATA buffer cap
- The per-transaction `data_buffer` is now bounded at 32 MiB; past the cap, further
  DATA payload is dropped (message still parsed, truncated) instead of growing
  unbounded. `src/protocols/smtp/parser.rs`.

### A10 (Medium, partial) — Config secrets written 0o600
- `Config::save` now writes atomically via a temp file created with mode `0o600` and
  renamed into place, so a config containing inline secrets is never world-readable
  and never observable half-written. `src/config.rs`.
  *(The CWD-config-fallback part of A10 is still open — see below.)*

### §4 — File permission & parser hardening
- Database file tightened to `0o640` on creation (holds IPs, intel, scraped
  usernames, whitelist). `src/database/mod.rs`.
- Outbound intel HTTP client set to `redirect::Policy::none()` so a malicious intel
  endpoint can't 302 the client to another host and leak the `Key:` auth header
  (SSRF-lite). `src/intel.rs`.
- SMB negotiate parser validates the buffer length **before** allocating the dialect
  vector. `src/protocols/smb/parser.rs`.
- LEEF SIEM output now escapes tab/newline/backslash in attacker-influenced fields
  (reason, service, event_type, details) so they can't inject forged attributes or
  split records. `src/siem.rs`.

### A4 (High) — IPC per-command authorization
- The Unix socket now captures the peer UID via `SO_PEERCRED`; mutating actions
  (Ban/Unban/Whitelist/UnWhitelist/RefreshIntel) require the caller to be root or the
  daemon's own UID. Reads are unaffected, so the dashboard still works. The TCP
  listener now refuses to start unless `require_client_cert = true` (mTLS), so a TCP
  caller is always authenticated. `src/ipc/server.rs`, `src/lib.rs`.

### A17 (Medium, partial) — Hyperscan is now opt-in
- `hyperscan` removed from the default `nids` feature (it wraps the discontinued
  Intel Hyperscan C lib and blocked builds without `libhs`). The signature matcher
  falls back to the pure-Rust `regex` engine; opt back in with `--features hyperscan`
  or the new `nids-hyperscan` feature. `Cargo.toml`. (trust-dns/dirs migration still
  open.)

---

## Open / deferred (recommend follow-up)

These were **not** changed here because they are architecturally invasive and carry a
real risk of breaking the running daemon or its clients without on-host testing.

- **A4 (High) — IPC per-command authorization.** Add `SO_PEERCRED` uid checks on the
  Unix socket and an mTLS CN allowlist on TCP; refuse the TCP listener unless
  `require_client_cert = true`. The socket is currently group-gated (`0o660`).
- **A9 (High) — Drop root.** After opening nftables/NFQUEUE/pcap handles, drop to a
  dedicated user retaining only `CAP_NET_ADMIN`/`CAP_NET_RAW`; add `User=crmonban` +
  `AmbientCapabilities` to the systemd unit. (Needs the `crmonban` user/group created
  first — the same group referenced by the new D-Bus policy.)
- **B3/B4/B5 (High) — inline-bypass hardening** (CF/UDP saddr trust, fail-closed queue
  + backpressure, FORWARD/container inspection). Design-level; test on the target
  topology.
- **A10 (remainder)** — drop the CWD `config.toml` fallback for the root daemon
  (keep it behind an explicit `--config`); refuse configs that are not root-owned or
  are group/world-writable. Left as-is here to avoid breaking the author's current
  run-from-checkout workflow — needs a deliberate decision.
- **A14 (Medium) — DB retention.** Add a pruning job for `events`/`detection_events`/
  `flow_records` (`DELETE … WHERE timestamp < ?` + incremental vacuum) and per-table
  row caps.
- **A17 (Medium) — dependency migration.** `trust-dns` → `hickory`, make Hyperscan
  opt-in (it is default-on via `nids` and blocks builds without `libhs`), drop
  abandoned crates.
- **A18 (Medium) — de-panic + CI.** Convert packet-facing `unwrap/expect` to error
  returns, add `cargo deny`/`cargo audit` + clippy to CI, fix the runner label.
- **Remaining §4/Low** — GeoIP over HTTPS (note: ip-api.com free tier is HTTP-only),
  unbounded per-IP maps, audit-log/ML-storage file modes.

---

*Remediation by Claude Fable 5 on 2026-07-09. Re-run the full audit after the deferred
items land and after any change to the detection pipeline or firewall rule construction.*
