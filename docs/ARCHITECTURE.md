# crmonban architecture — packet flow

How a packet travels through crmonban, from the kernel to userspace and back.
The guiding idea is a **funnel**: the kernel cheaply drops/accepts/bypasses the
bulk of traffic, userspace deep-inspects only the *undecided* opening packets of
a flow, and the learned "normal" model pushes recognised-good flows back down to
the kernel so they cost nothing.

Companion docs: `DESIGN-INLINE-DPI-PIPELINE.md` (target design),
`DESIGN-FLOW-DISPOSITION.md` (per-flow state machine).

> **Not eBPF.** crmonban programs the kernel with **nftables** (the `nftables`
> crate, over netlink/JSON) and hands packets to userspace with **NFQUEUE** (the
> classic netfilter queue, via the `nfq` crate). There is no eBPF/XDP today; an
> XDP pre-filter is a possible *future* layer, not the current mechanism.

## 1. The kernel layer — nftables

crmonban owns one table, `table inet crmonban`, with **base chains on the
netfilter hooks**. Multiple base chains can share a hook; they run in **priority
order** (lower number first), and only a `drop` is terminal across chains — an
`accept` ends the *current* chain but the packet still traverses later chains on
the same hook. This separation is load-bearing.

```
                 ┌──────────────── INPUT hook (host ingress) ────────────────┐
 priority:   -100│ block chain:  ip saddr @blocked_v4 drop   (also v6)        │
              -95│ dpi_inspect:  (see below)                                  │
              -90│ portscan_detect: log                                       │
              -50│ port_filter:  per-port allow/deny (policy drop, opt-in)    │
                 └───────────────────────────────────────────────────────────┘
   forward hook (-100 block)   — transit; queueing deferred (Docker-host risk)
   output  hook (-100 block)   — egress; queueing deferred
   postrouting                 — NAT (masquerade/snat) in gateway mode
```

### The `dpi_inspect` chain (the heart of the inline path)

Rules in order — the first three are **filters** (verdicts), the queue is the
**hand-off to userspace**, the last is a **modification**:

| # | Rule | Kind | Purpose |
|---|------|------|---------|
| 1 | `ip/ip6 saddr @dpi_allow_v4/v6 accept` | filter | whitelist + Cloudflare short-circuit — never queued, never inline-dropped |
| 2 | `ct mark 0x40000000 accept` | filter | **good-flow bypass** — a flow the engine judged good skips the queue in-kernel |
| 3 | `meta l4proto tcp ct state {new,established} ct packets(original) ≤ 8 queue num 100 bypass` | **→ NFQUEUE** | queue the **first N packets** of each undecided TCP flow |
| 4 | `meta mark 0x40000000 ct mark set 0x40000000` | **modify** | persist the engine's "good" skb-mark onto the connection's ct mark |

The only things that **change the packet stream** are the **marks** (rule 4, and
the engine setting the skb mark on its verdict) and **NAT** in gateway mode.
Everything else is a verdict (accept / drop / queue).

**Black/white is kernel-first.** `@blocked` (drop) and `@dpi_allow` (accept,
fed from the DB whitelist + Cloudflare CIDRs) are enforced *before* the queue, at
kernel speed. The userspace IP-filter stage is a second layer (+ GeoIP + threat
intel).

`queue ... bypass` is **fail-open**: if no userspace listener is attached
(crmonban crashed/restarting) **or the queue is full**, the kernel *accepts* the
packet rather than dropping it. Availability over coverage — under overload,
traffic passes uninspected (watch queue depth).

## 2. The kernel ↔ userspace boundary — NFQUEUE

The `queue num 100` rule hands the packet to **NFQUEUE**. The packet is *held in
the kernel* until userspace returns a verdict. `engine::capture::NfqueueCapture`
(the `nfq` crate) `recv`s the packet, the pipeline decides, and
`set_verdict[_marked]` issues `ACCEPT`/`DROP` (optionally tagging the skb mark) —
exactly one verdict per packet, or the kernel queue stalls.

```
   kernel queue 100  ──recv──►  NfqueueCapture  ──►  pipeline (§3)
        ▲                                                  │
        └──────────── set_verdict(id, accept[, mark]) ◄────┘
```

## 3. The userspace pipeline — 8 stages

`engine::PacketEngine` runs a capture thread (feeds packets over a channel) and
an async pipeline (`engine::pipeline::Pipeline`) that pushes each packet through
`WorkerThread::process_full`, an ordered run over `PipelineStage`:

| Stage | Name | What it does |
|-------|------|--------------|
| 0 | **IpFilter** | blocklist + GeoIP + threat-intel IOCs (kernel already did most black/white) |
| 1 | **FlowTracker** | per-flow / 5-tuple state — *creates the "stream"* |
| 2 | **Layer234Detect** | scans / DoS / brute-force via **crvecdb** vector similarity |
| 3 | **SignatureMatching** | Aho-Corasick + rules — the large "snort-like" signature DB |
| 4 | **ProtocolAnalysis** | HTTP/DNS/TLS/SSH parse + attack detection (vecdb again, e.g. HASSH) |
| 5 | **WasmPlugins** | custom detection |
| 6 | **MLDetection** | flow anomaly scoring + the **learn-normal** model |
| 7 | **Correlation** | DB write + alert generation |

Each stage may add **DetectionEvents** to the `PacketAnalysis`. After a stage
that flags the packet, the **AlertAnalyzer** maps events (severity + confidence +
per-severity policy) to the authoritative `PacketAnalysis.verdict`
(Accept / Drop / Reject / Queue).

## 4. Verdict, ban, and the mark

The pipeline reads `analysis.verdict` and sends `(packet_id, accept, mark_good)`
back to the capture thread:

- **accept** → kernel releases the packet.
- **drop/reject** → kernel discards it, **and** the source is **banned**: the
  engine's `DetectionEvent` is bridged to the daemon's ban path
  (`crmonban.ban` → add to `@blocked` + DB `add_ban` + activity log + whitelist
  check). Future packets from that source are dropped **in-kernel**, never
  re-queued.
- **good** → the verdict sets the skb mark; the kernel's `ct mark set` rule
  (§1 rule 4) copies it to the connection, and rule 2 then bypasses the rest of
  the flow in-kernel.

## 5. Audit

Audit is **collected anywhere, persisted in one place**: any stage may *generate*
a DetectionEvent, but the **Correlation stage (7)** writes events to the DB and
emits alerts, and the **ban path** writes bans (`add_ban` + activity log). So
"audit from any stage" really means *events flow from any stage into a central
sink* — not a per-stage DB write.

## 6. The fast-path funnel (the volume story)

Not every packet runs all 8 stages. Three layers shed work, cheapest first:

```
   ALL traffic
      │  kernel:  @blocked drop / @dpi_allow accept / ct mark accept   ← never reach userspace
      ▼
   undecided flows (first N=8 packets only — ct packets ≤ N)           ← only flow-openings queued
      │  userspace pipeline
      ▼
   per flow, after FlowTracker (stage 1): score vs the learned baseline
      ├─ normal   → skip heavy stages 4/5/6 + mark good → ct-mark kernel bypass
      └─ novel    → full deep pipeline (signatures, protocol, ML)
```

- **first-N** (`ct packets ≤ 8`): once a flow exceeds N packets the queue rule
  stops matching, so established traffic is accepted in-kernel with zero
  userspace cost.
- **ct-mark bypass**: a flow the engine marks good leaves the queue entirely.
- **learn-normal stage-skip**: a flow scored normal pays only the *cheap* stages
  (IP filter, flow, scan-detect, signatures); it is only marked good if those
  cheap stages also stayed clean.

## 7. The learn → apply loop

The "normal" model (`ml::Baseline`, shared `Arc<RwLock<>>` per worker) is:

- **learned at stage 6** — a flow that reaches a representative packet count with
  no detection events is, by construction, clean; its feature vector is added to
  the baseline.
- **applied at stage 1** — right after FlowTracker, a new flow's features are
  scored against the baseline; a ready model that finds it un-anomalous fast-paths
  it (skip heavy stages → mark good → kernel bypass).

So the model is *trained late* (where the full pipeline gives ground truth) but
*used early* (to steer inspection depth before the expensive stages).

## 8. End-to-end

```
 packet ─► nft INPUT/-100: @blocked? ──drop──► (banned source, dropped in-kernel)
                │ no
                ▼
           nft /-95 dpi_inspect:
                @dpi_allow? ──accept──► (whitelist/CF: never inspected)
                ct mark good? ──accept──► (already-judged-good flow: bypass)
                tcp, new/estab, ct packets ≤ N ──► QUEUE 100 ─────────────┐
                else ──accept──► (established beyond N: in-kernel)         │
                                                                          ▼
                                                          NfqueueCapture (userspace)
                                                                          │
                                    ┌───────── pipeline (process_full) ───┤
                                    │ 0 IpFilter → 1 FlowTracker          │
                                    │   └─ score vs baseline:             │
                                    │        normal → skip 4/5/6 + mark   │
                                    │ 2 Layer234 (vecdb) → 3 Signatures   │
                                    │ [4 Protocol → 5 WASM → 6 ML]        │
                                    │ 7 Correlation (DB + alert)          │
                                    └──────────────┬──────────────────────┘
                                                   ▼
                                  verdict: accept │ drop(+ban @blocked) │ mark good
                                                   │
                              set_verdict[_marked] ▼  → kernel releases / drops / ct-mark
```

## 9. What is *not* here (yet)

- **No eBPF/XDP** — an XDP pre-filter could classify even earlier (a future
  layer); today it's nftables + NFQUEUE.
- **Forward/output queueing** is deferred (on a forwarding/Docker host an output
  queue would funnel all transit/egress traffic to userspace).
- **Reject** verdicts collapse to silent `Drop` over the boolean verdict channel.
- Signature/Protocol/ML stages do not yet drive inline **bans** on their own
  (only IpFilter + Layer234 do); they record + alert.

See the design docs for the milestone history and open items.
