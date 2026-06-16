# Core feature gap: packet-based detection is inert by default — crmonban should auto-configure the packet engine (real interfaces + DPI)

## Summary
crmonban's headline value is **packet-based detection** — seeing attacks on the
wire and blocking them *faster and earlier* than log-tailing IPS/fail2ban-style
tools. But on a real deployment the packet engine comes up **bound to loopback
with DPI disabled**, so it sees and analyzes nothing, and **all actual detection
silently falls back to log parsing** — the slower, post-hoc path the product is
supposed to beat. crmonban should set the packet engine up **itself**.

## Why this matters
Log-based detection is inherently slower and reactive: crmonban must wait for the
fronting app (Caddy/nginx/sshd) to *write* a log line, then tail and regex it —
seconds of latency, after the request already completed. (It's also what drove the
busy-poll log-reading disk-fill bug — see `crmonban-issue.md`.) Packet-based
detection on the live interface can flag and block an abuser **in real time, at
the moment of the attack**, before/independent of any log line. That speed is the
whole pitch — and right now it isn't running.

## Current behavior (observed on a production host)
Startup log:
```
INFO Deep packet inspection is disabled
INFO Daemon started, monitoring logs...
INFO Added monitor for service 'caddy_tls'  watching /opt/caddy/logs/tls.log
INFO Added monitor for service 'ssh'         watching /var/log/auth.log
INFO Added monitor for service 'nginx_access' watching /opt/caddy/logs/access.log
INFO Starting packet engine on interface: Some("lo")
INFO Capture opened successfully on lo
INFO Packet engine started, listening for packets...
```
Evidence the packet engine is doing nothing useful:
- **Interface = `lo` (loopback only).** Real ingress arrives on `eth0` and the
  docker bridges (`br-*`/`docker0`), never on `lo`. So the capture sees no attack
  traffic.
- **`Deep packet inspection is disabled`** — even what it does capture isn't
  analyzed.
- The `inet crmonban` nftables table contains **only** `@blocked_v4/v6 drop`
  (enforcement) — no `nflog`/`queue`/`counter` feeding events to userspace.
- An `AF_PACKET` raw socket exists but is bound to `lo`.
- Net result: **every ban actually comes from the log monitors**, not packets.

## Requested behavior
1. **Auto-configure the capture interface.** crmonban should detect and bind the
   real ingress interface(s) itself — the default-route NIC (e.g. `eth0`) and,
   where relevant, the bridge(s) where proxied traffic lands — instead of
   defaulting to `lo`. (Allow an explicit override, but the *default* must be the
   live interface, possibly `any`.)
2. **Enable DPI by default** when packet-based detection is the intended mode (or
   document clearly why it's off and what's lost).
3. **Make packets the primary detector**, with logs as enrichment/fallback — i.e.
   detect & block from the wire, and use logs to augment, not the other way round.
4. **Loudly surface degraded mode.** If the engine can't capture on a real
   interface or DPI is off, log a prominent WARNING that crmonban is running in
   **log-only fallback** and the core feature is inactive — so operators aren't
   misled into thinking packet detection is protecting them.

## Acceptance criteria
- [ ] Out of the box, the packet engine binds a real ingress interface (not `lo`)
      and DPI is active.
- [ ] crmonban can detect and ban an abuser from packets **without** a
      corresponding log line.
- [ ] If it falls back to log-only (no capture / DPI off), it emits a clear WARN.
- [ ] Capture interface + DPI are overridable in config, but default to "live".
- [ ] Works alongside the existing log services (enrichment), and respects the
      whitelist (incl. the CIDR whitelist requested separately).
