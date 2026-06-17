# Design: TLS interception / SSL inspection

Status: **Draft / future work.** Partial scaffolding exists (`src/tls_proxy.rs`,
`firewall.rs::add_tls_proxy_rules`, `config::TlsProxyConfig`); this doc plans the
path from scaffold to a working, safe inline feature. Companion to
`DESIGN-FLOW-DISPOSITION.md` §13 (the "opaque" protocol class) and
`DESIGN-INLINE-DPI-PIPELINE.md`.

## 1. Why

TLS is the **opaque** class in the flow-disposition model (§13): after a clean
handshake (JA3/SNI/cert) the bulk is ciphertext, so a payload attack *inside* TLS
is invisible to the pipeline. Interception terminates TLS at the box so the
plaintext can be run through the same detection stages as cleartext traffic.

**The trade it makes (from §13):** an intercepted TLS flow stops being
opaque-bulk (bypass-friendly, huge offload) and becomes **cleartext-recurring**
(frontier-always — every HTTP request inspected). You gain visibility and lose
the kernel offload for that flow. Therefore interception must be **selective**,
never blanket — especially on an RPi.

## 2. Two modes (pick per deployment)

### Mode A — Inbound / reverse inspection (protect *your* servers)
You own the destination's certificate **and private key**, so you terminate the
client's TLS with the **real** key — no fake cert, no client-trust changes, no
pinning problems. This is the low-friction mode and the best fit for crmonban's
actual deployment (guarding `savages.com` / `crmep` services). If a reverse proxy
(Caddy) already terminates TLS, inbound inspection can alternatively read the
post-TLS plaintext there instead of re-terminating.

- Trust model: none changed — you present the genuine cert.
- Breaks on: nothing client-side (you are the server). mTLS still needs the
  client's cert handling, but that is the server's normal job.
- Status: **not implemented** (current code always mints fake certs).

### Mode B — Outbound / forward MITM (inspect *managed clients*' egress)
For clients **you control** going to arbitrary servers. Mint an on-the-fly leaf
cert for the SNI, signed by a **local CA the clients trust**; open a real TLS
session upstream (validating the true cert against public roots); relay plaintext
through the pipeline.

- Trust model: the local CA **must be installed in every client's trust store** —
  works only for managed devices; foreign clients get a cert error (correct
  boundary).
- Breaks on: **certificate pinning** (apps that pin reject any substitute),
  **mTLS** (no client key to present), **ECH** (encrypted SNI hides the host).
  Each failure is itself a detectable signal.
- Status: **mostly built** (`tls_proxy.rs`), with gaps in §5/§6.

> The two modes share ~all plumbing (peek ClientHello, dual TLS, inspect loop,
> verdict→ban); they differ only in *where the leaf cert comes from*: real
> key (A) vs CA-minted (B).

## 3. Architecture & data flow

```
                    nft NAT (tls_redirect chain): REDIRECT tcp dport {443,…}
                    → 127.0.0.1:<listen_port>   (only non-locally-generated)
client ──TLS──►  [ crmonban TLS proxy ]
                    1. peek ClientHello → SNI                (extract_sni)
                    2. recover ORIGINAL DST (SO_ORIGINAL_DST)  ← GAP
                    3. bypass_domains? → splice TCP, no terminate  ← GAP (TODO)
                    4. leaf cert:  Mode A real key | Mode B CertCache.get_cert(SNI)
                    5. TlsAcceptor.accept(client)             (present leaf)
                    6. TlsConnector.connect(orig_dst|SNI)     (real upstream)
client ◄──TLS────   7. relay loop: decrypt → INSPECT → re-encrypt both ways
                    8. threat → MonitorEvent::Ban + drop      (shared ban path)
```

The redirect must exclude the proxy's *own* upstream connections (mark/owner
match) to avoid a loop, and exclude `bypass_domains` destinations.

## 4. Current state — have vs need

| Piece | Symbol | State |
|-------|--------|-------|
| Config surface | `TlsProxyConfig` (ports, CA paths, cert cache, bypass list, verify_upstream, limits) | **have** |
| Local CA (gen/load/save, sign leaves) | `CertificateAuthority`, `generate_cert_for_domain` | **have** (Mode B) |
| Per-SNI leaf cache | `CertCache` | **have** |
| Dual-TLS relay + inspect loop | `handle_connection` | **have** |
| nft transparent redirect | `add_tls_proxy_rules` → `tls_redirect` chain, `Statement::Redirect` | **have** |
| Threat → ban | `MonitorEvent::Ban` from the proxy | **have** |
| Original-dst recovery | — | **need** (drops when SNI absent) |
| `bypass_domains` passthrough | `// TODO: Implement passthrough` | **need** (today it *drops* the flow) |
| Pinning/mTLS graceful handling | — | **need** |
| Decrypted inspection via the 8-stage pipeline | uses `DpiEngine.inspect_payload` (simpler path) | **need** (unify) |
| Mode A (reverse, real key) | — | **need** |
| Proxy task lifecycle/wiring in the daemon | config plumbed; spawn not confirmed | **verify / need** |
| `verify_upstream` honored | always webpki_roots | **need** |

## 5. Gaps & work plan

1. **Original-destination recovery.** Read `SO_ORIGINAL_DST` (the pre-REDIRECT
   dst IP:port) and prefer it for the upstream connect; use SNI for the cert CN
   and the upstream SNI. Fixes: SNI-absent clients, ECH, DNS split-horizon, and
   the hardcoded `:443` (honor all `intercept_ports`). Today absent-SNI → the
   connection is dropped.
2. **`bypass_domains` passthrough.** For pinned/sensitive destinations (banking,
   OS/app update channels, anything mTLS- or pin-protected), **splice the raw TCP**
   to the upstream without terminating TLS — do *not* drop (current behavior
   breaks them). Match on SNI suffix and/or original-dst.
3. **Pinning / mTLS failure → graceful + signal.** When the client aborts the
   handshake (pin failure) or the server demands a client cert, fall back to
   passthrough where possible and **emit a signal** (a pin-failure spike is a
   useful detection, not just an error).
4. **Unify decrypted inspection with the pipeline.** Feed decrypted bytes through
   the same 8-stage `PacketEngine` path (hyperscan over the full ruleset,
   protocol analysis, web-attack heuristic, layer234 context) so MITM detection
   == NFQUEUE detection and shares one event/ban path — instead of the narrower
   `inspect_payload`. Frame the plaintext as a reconstructed L7 stream.
5. **Mode A (reverse, real key).** Load the server's real cert+key (or per-SNI
   keypairs) and present them instead of CA-minted certs; skip the CertCache.
   Smallest, safest win for the homelab.
6. **Proxy lifecycle.** Confirm/implement the daemon spawning `run()`, bounded by
   `max_connections` and `timeout_secs`; clean shutdown; backpressure when the
   inspection pipeline is the bottleneck (fail-open vs fail-closed, §7).
7. **Honor `verify_upstream`.** Default true (validate the real server). A
   relaxed mode is dangerous (strips the security TLS provides) — gate behind an
   explicit, loud config and never default it on.

## 6. Selective interception (the §13 tie-in)

Interception turns an offload-friendly flow into a frontier-always one, so decide
*what* to intercept:

- **Default: do not intercept.** Inspect TLS *metadata* only (JA3/JA3S, SNI,
  cert chain, version/cipher) — cheap, no termination, catches a lot (malware
  JA3, bad SNI, self-signed C2).
- **Intercept selectively** when metadata or the cascade raises suspicion, or for
  an allowlist of high-value destinations/segments.
- **`bypass_domains` is the hard opt-out** (privacy/pinning) and is honored
  *before* any termination.

This keeps the RPi's userspace budget for the flows that actually warrant
plaintext inspection.

## 7. Security & safety

- **CA private key is crown-jewel.** Whoever holds it can forge any cert your
  clients trust. Store with strict perms (ideally outside the repo / in a
  keystore), short-lived leaves, name-constrain the CA if possible, and log every
  signature. Rotate on exposure.
- **Trust boundary is the whole game** (Mode B): only managed clients, never a
  shared/guest network.
- **Fail policy:** default **fail-open** for availability (a proxy/inspection
  stall must not blackhole TLS) — mirror the NFQUEUE `bypass` flag. A strict
  deployment may choose fail-closed; make it explicit.
- **Privacy / legal:** interception decrypts user traffic. Fine on your own
  infra/devices (the crmonban context); document consent/scope and exclude
  sensitive categories via `bypass_domains`.
- **Don't weaken upstream TLS:** always validate the real server (`verify_upstream`);
  a MITM that accepts bad upstream certs is worse than no inspection.

## 8. Performance (RPi)

- **Cert cache** (have) — sign once per SNI, reuse; persist to `cert_cache_dir`.
- **ECDSA (P-256) leaf keys** over RSA — far cheaper signing/handshake on ARM.
- **TLS session resumption** (tickets/IDs) to skip full handshakes.
- **Connection caps + timeouts** (`max_connections`, `timeout_secs`).
- **Selective interception** (§6) is the biggest lever — keep the elephant TLS
  flows opaque-and-bypassed; only terminate what's worth it.

## 9. ECH and the future

Encrypted ClientHello hides the SNI, defeating SNI-based cert minting and
domain bypass. Mitigations: lean on `SO_ORIGINAL_DST` + reverse-DNS/cert-CN for
the host; treat ECH connections as a policy class (intercept-or-block-or-allow by
destination IP reputation). Track adoption; SNI-based interception degrades as
ECH spreads.

## 10. Phased plan

- **M1 — Metadata-only (no termination).** JA3/JA3S, SNI, cert-chain, version
  extraction in the pipeline; detections + bans. Highest value/lowest risk; no
  trust changes. *(Much may already exist in protocol analysis — audit first.)*
- **M2 — Mode A (reverse, real key).** Terminate inbound TLS for your own servers
  with the real key; route plaintext through the unified pipeline (gap #4).
- **M3 — Mode B hardening.** Original-dst (#1), bypass passthrough (#2),
  pinning/mTLS handling (#3), `verify_upstream` (#7), lifecycle (#6).
- **M4 — Selective-interception policy** wired to the flow-disposition cascade
  (§6) + CA distribution runbook.
- **M5 — Perf** (ECDSA leaves, resumption) + ECH policy (§9).

## 11. Config & operational runbook

Existing `TlsProxyConfig`: `enabled`, `listen_addr/port`, `ca_cert_path`,
`ca_key_path`, `cert_cache_dir`, `intercept_ports`, `bypass_domains`,
`verify_upstream`, `inspect_decrypted`, `log_decrypted`/`decrypted_log_path`,
`max_connections`, `timeout_secs`, `ca_validity_days`, `cert_validity_days`,
`ca_common_name`, `ca_organization`.

Bring-up (Mode B): (1) generate the CA (auto on first run, or pre-seed
`ca_cert_path`/`ca_key_path`); (2) distribute the CA cert to managed clients'
trust stores (per-OS); (3) set `intercept_ports`/`bypass_domains`; (4) enable and
confirm the `tls_redirect` nft chain applied + the proxy is listening; (5) verify
a test client sees the CA-signed leaf and a pinned app correctly fails (then add
it to `bypass_domains`).
