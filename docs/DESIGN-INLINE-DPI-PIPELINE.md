# Design: Inline DPI pipeline — queue streams on INPUT/FORWARD/OUTPUT until a verdict

Status: **Draft / design** — captures the target architecture and the gap from
today's implementation.

## 1. Goal

crmonban should run as a true **inline IPS/DPI**: every packet on the **input,
forward, and output** netfilter hooks is handed to crmonban via **NFQUEUE**, the
packet's **flow/stream** is held (queued) until crmonban reaches a **verdict**
(good / bad / alert / rate-limit / ban), and only then is the packet released
(ACCEPT) or stopped (DROP/REJECT). Detection happens on the wire — before the
request completes — not after, from logs.

This is the product's differentiator. Log monitoring becomes **enrichment**, not
the primary detector.

## 2. Where we are today (gap)

The 8-stage detection pipeline exists in code, but the inline path that would feed
and act on it does **not** run:

- **NFQUEUE is stubbed.** `engine::capture::NfqueueCapture::next_packet()` returns
  dummy packets (`Ok(None)`, sleeps); `set_verdict()` is a no-op
  (`// would use msg.set_verdict()`). No queue is actually bound.
- **Only the INPUT chain is wired**, and only for enforcement: `table inet crmonban`
  has `chain input { ip saddr @blocked_v4 drop; ip6 saddr @blocked_v6 drop }`.
  There are **no `queue` rules** on input/forward/output.
- The live deployment captures **passively** with `af_packet` on `lo` (see
  ISSUE #8 / `[packet_engine].interface = "lo"`), so packets are not even seen on
  real interfaces, let alone verdicted. The **log monitors** do all real work.

So: the stages are designed; the inline engine + nft queue plumbing + per-stream
verdict loop are the missing pieces.

## 3. Target architecture

```
            netfilter hooks (input, forward, output)
                          │  nft: ... queue num N bypass
                          ▼
                  ┌──────────────────┐
                  │  NFQUEUE  (N)     │  packet_id, raw bytes
                  └────────┬─────────┘
                           ▼
                  ┌──────────────────┐   key = 5-tuple (+ direction/hook)
                  │  Flow/Stream mgr  │   reassemble, batch by flow,
                  │  (FlowBuffer)     │   cache per-flow disposition
                  └────────┬─────────┘
                           ▼
   ┌───────────────────── 8-stage pipeline (per flow/packet) ─────────────────────┐
   │ 0 IpFilter      blocklist + GeoIP + threat-intel  ── known-bad → DROP (fast)  │
   │ 1 FlowTracker   connection/stream state                                       │
   │ 2 Layer234Detect scans / DoS / brute force (vector similarity)                │
   │ 3 SignatureMatching  Aho-Corasick + rules                                     │
   │ 4 ProtocolAnalysis   HTTP/DNS/TLS/SSH parse + attack detection                │
   │ 5 WasmPlugins        custom detection                                         │
   │ 6 MLDetection        flow-based anomaly scoring                               │
   │ 7 Correlation        DB write + alert generation                              │
   └────────┬────────────────────────────────────────────────────────────────────┘
            ▼
   ┌──────────────────┐   Action: None(accept) | Drop | Reject | Ban | Alert | RateLimit
   │  Verdict / Action │   → set_verdict(packet_id, accept) back to NFQUEUE
   │   (actions.rs)    │   → update @blocked set, emit event, write DB
   └──────────────────┘
```

Existing symbols this maps onto:
`engine::capture::{PacketCapture, NfqueueCapture, set_verdict}`,
`engine::flow_buffer::FlowBuffer`,
`engine::pipeline::{Pipeline, PipelineStage}`,
`engine::actions::Action`, `firewall.rs` (nft) — `table inet crmonban`.

## 4. nftables integration

Add a managed **prerouting/input/forward/output** rule set that queues traffic
crmonban should inspect, while keeping the existing blocklist drop as a cheap
short-circuit:

```
chain input {
    type filter hook input priority -100; policy accept;
    ip  saddr @cf_v4 accept              # whitelist short-circuit
    ip  saddr @blocked_v4 drop           # stage-0 fast drop, no queue needed
    ip6 saddr @blocked_v6 drop
    ct state established,related accept   # optional: only queue NEW/first-N
    queue num 100 bypass                  # everything else → NFQUEUE 100
}
chain forward { type filter hook forward priority -100; policy accept; ... queue num 100 bypass }
chain output  { type filter hook output  priority -100; policy accept; ... queue num 101 bypass }
```

Design points:
- **`bypass`** on the queue verdict = **fail-open**: if crmonban isn't listening
  (crashed/restarting), packets are accepted rather than dropped. Safety first.
  (A "fail-closed" mode can be a config toggle for high-security deployments.)
- **Blocklist before queue**: known-bad IPs are dropped without ever entering the
  queue — Stage 0 done in-kernel.
- **Whitelist before everything** (the CF/CIDR sets — see ISSUE #5).
- **Scope what gets queued** to bound load: e.g. only `ct state new` + first K
  packets/flow, or only specific ports/services, configurable. Established flows
  that already earned an ACCEPT verdict shouldn't be re-queued.
- Separate queue numbers per direction so workers/policies can differ
  (e.g. output egress-DLP vs input intrusion).

## 5. Stream "queue-until-verdict" semantics

The core new behavior. Per **flow** (5-tuple + hook/direction):

1. **First packet** of a flow enters NFQUEUE → held. Flow state created in
   `FlowBuffer`. Disposition = `Pending`.
2. Packets are **batched by flow** and pushed through the stages. Stages may need
   several packets (e.g. an HTTP request line, a TLS ClientHello) before deciding —
   so the flow stays `Pending` and packets accumulate up to a **hold budget**
   (bytes / packets / time).
3. A stage produces an `Action` → flow disposition becomes terminal:
   - `None` → **Good**: ACCEPT held packets, **cache `Accept`** for the flow so
     subsequent packets fast-path (verdict ACCEPT without re-running stages).
   - `Drop`/`Reject` → **Bad**: DROP/REJECT held + future packets; optionally
     `Ban` the source (add to `@blocked`, kernel drops the rest).
   - `Alert` → log/emit but ACCEPT (observe-only) — or escalate per policy.
   - `RateLimit` → ACCEPT but throttle the source.
4. **Hold-budget exhausted with no decision** → default verdict (configurable;
   default ACCEPT = fail-open) + mark flow `Inconclusive` for the log/ML path.

Key requirements:
- **Per-flow verdict cache** so we don't deep-inspect every packet of an
  already-judged flow (latency + CPU). This is what makes inline viable.
- **Bounded hold**: never hold a flow indefinitely (latency, memory). Time +
  size caps, with a default verdict on expiry.
- **Ordering / head-of-line**: packets of one flow are ordered; independent flows
  proceed in parallel across workers. A slow flow must not stall others.

## 6. Verdict / decision model

`engine::actions::Action` already expresses the dispositions:
`None` (accept/good) · `Drop{packet_id}` · `Reject{packet_id}` · `Ban{ip,duration,reason}`
· `Alert` · `RateLimit{ip,pps}`. The inline loop maps a stage's `Action` to:
- a **per-packet NFQUEUE verdict** (`set_verdict(packet_id, accept)`), and
- a **per-flow disposition** (cached), and
- **side effects** (`@blocked` set update, event emit, DB write via Correlation).

"good / bad / alert / …" = {None} / {Drop,Reject,Ban} / {Alert} / {RateLimit}.

## 7. Implementation plan (milestones)

1. **Real NFQUEUE capture** — bind the queue (e.g. via `nfq`/`nfqueue` crate or
   libnetfilter_queue FFI), implement `next_packet()` (read packet_id + payload)
   and `set_verdict()` (ACCEPT/DROP back to kernel). Replace the stub.
2. **nft plumbing** in `firewall.rs` — add managed `queue num … bypass` rules on
   input/forward/output, keep blocklist/whitelist short-circuits, with a teardown
   on exit and `ExecStartPost`-safe (re)apply. Config-gated.
3. **Flow disposition state machine** in `FlowBuffer` — `Pending → Accept/Drop/
   Alert/RateLimit/Inconclusive`, per-flow verdict cache, hold budget (bytes/pkts/
   time) + default verdict on expiry.
4. **Wire stages → verdicts** — each `PipelineStage` returns `Action`; pipeline
   collapses to a flow disposition and issues the NFQUEUE verdict.
5. **Config** — `[packet_engine].capture_method = "nfqueue"`, queue nums per
   hook, fail-open/closed, hold budgets, which traffic to queue (ct state/ports).
6. **Safety/perf** — fail-open default, queue-full handling, latency budget,
   benchmark with `benches/`, soak test; metrics for held/accepted/dropped/
   timed-out per flow.
7. **Auto-interface (ISSUE #8)** stays relevant for the **passive** af_packet/pcap
   modes; inline NFQUEUE is interface-agnostic (operates at the hooks).

## 8. Open questions

- Which crate for NFQUEUE (maintained libnetfilter_queue binding) vs FFI?
- Default-queue scope: all NEW flows, or per-service opt-in, to bound latency?
- Output-chain DPI: egress data-loss/exfil detection — same pipeline or a subset?
- Fail-open vs fail-closed default (lean fail-open; toggle for strict mode).
- Per-flow hold budget defaults (latency SLO vs detection completeness).

## 9. Relationship to existing issues

- **#8** — get the *passive* engine off `lo` (prerequisite for af_packet/pcap;
  orthogonal to NFQUEUE).
- **#5 (CIDR whitelist)** / **#6 (rate/volume)** / **#7 (instant ban on known
  paths)** — become in-kernel/inline short-circuits and verdict rules under this
  design instead of post-hoc log bans.
- **#4 (busy-poll log reader)** — once packets are primary, the log path is
  secondary enrichment and its hot-loop cost matters less.
