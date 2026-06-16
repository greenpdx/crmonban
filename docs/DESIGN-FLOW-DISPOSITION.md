# Design: per-flow disposition state machine (inline DPI, milestone M3)

Status: **Draft / design.** Builds on the completed per-packet verdict path
(M2 + verdict feedback) and the overall architecture in
`DESIGN-INLINE-DPI-PIPELINE.md` (§5).

## 1. Scope

M2 gave us the substrate: every NFQUEUE packet flows
`capture → pipeline → set_verdict(packet_id, accept)` and gets **exactly one**
ACCEPT/DROP. That is *per packet*.

M3 adds the **per-flow** layer: decide, **cache**, and act on a verdict per
*stream*, so the IPS

- inspects each flow only as long as it actually needs to,
- **bypasses** flows it has proven good *and that cannot still go bad*, and
- **fully resolves** bad flows — the bad state is sticky until the source is
  **banned and audited**.

A flow is keyed by the 5-tuple (src/dst IP+port, L4 proto) plus hook/direction,
and its state lives in `engine::flow_buffer::FlowBuffer`.

## 2. Dispositions

At any moment a flow is in exactly one state:

- **Pending** — under inspection, no verdict yet. New flows start here. Packets
  are ACCEPTed within the hold budget (fail-open) or held; the stages keep
  running on subsequent packets of the flow.
- **Good — bypass** — proven good **and cannot still carry an attack**. Cache
  `Accept` and install a kernel **bypass** so the flow's packets stop being
  queued. Removed from active processing. (The user's *"old allow"*.)
- **Good — watch** — looks good so far but **could still carry bad packets**
  (long-lived / multi-request / per-datagram). ACCEPT the current packet but
  **keep inspecting** — do *not* bypass. Behaves like Pending for inspection.
  (The user's *"if there is a possibility of bad packets they are continued"*.)
- **Bad — unresolved** — a stage flagged the flow bad. The packet is DROPped and
  the disposition is **sticky**: it propagates up the chain and the verdict can
  no longer be downgraded to Accept. Stays here until banned + audited.
  (The user's *"new drop"*, mid-resolution.)
- **Bad — resolved** — source **banned** (added to `@blocked`, kernel drops the
  rest) and the event **audited** (DB write + alert). Terminal; flow removed from
  active processing; future packets from a banned source are dropped in-kernel
  and never re-enter the queue.
- **Inconclusive** — hold budget exhausted with no verdict → default verdict
  (fail-open ACCEPT) and flagged for the slower log/ML enrichment path. Terminal
  for the inline path.

## 3. State machine

```
                          packet (flow F)
                               │
                    ┌──────────▼───────────┐
                    │  FlowBuffer cache?    │
                    └──────────┬───────────┘
   cached GOOD(bypass) ◄───────┤───────► cached BAD(resolved)
   ACCEPT, no re-inspect       │         DROP (and source already @blocked)
                               │ no entry / Pending / Good-watch
                               ▼
                     ┌───────────────────┐
                     │  run 8 stages     │  (IpFilter … Correlation)
                     └─────────┬─────────┘
        ┌────────────────┬─────┴───────────┬────────────────────┐
        ▼                ▼                  ▼                    ▼
   GOOD and          GOOD but           BAD flagged         no verdict,
 can't-go-bad     can-still-go-bad      (sticky)            budget left
        │                │                  │ continue up chain    │
        ▼                ▼                  ▼  (characterize)       ▼
  Good(bypass):    Good(watch) ==     resolve: Ban(@blocked)   stay Pending
  cache + kernel   Pending: ACCEPT    + Audit (DB + alert)
  bypass; remove   keep inspecting         │
                                           ▼
                                     Bad(resolved): DROP;
                                     future pkts dropped
                                     in-kernel; remove

   Pending/Good-watch + budget exhausted ──► Inconclusive:
        ACCEPT (fail-open) + flag for log/ML enrichment
```

Mapping to the user's three cases:
*"old allow"* = **Good(bypass)**; *"keep processing"* = **Pending / Good(watch)**;
*"new drop"* = **Bad(unresolved) → Bad(resolved)**.

## 4. The "can this flow still go bad?" gate — bypass vs watch

This is the single most important policy, and the user's key constraint: a Good
verdict only earns a **bypass** if the flow **cannot still carry an attack**.
Otherwise it stays under inspection (Good-watch).

**Bypass** (Good → leave the queue) when:
- source/destination is whitelisted (the CF / CIDR allow sets — issue #5), or
- the flow's inspectable content is complete and benign — a single short
  transaction, fully parsed, with no further payload expected.

**Keep inspecting** (Good-watch, no bypass) when there is still attack surface
ahead:
- long-lived / keep-alive / multiplexed connections (HTTP keep-alive, HTTP/2,
  persistent TLS) — request *N+1* can be the attack;
- connectionless flows (UDP/QUIC) where each datagram is independent;
- any flow whose protocol state means more bytes are still to come.

**Optional middle ground** — *bypass with a TTL / re-sample*: install the bypass
but expire it after N seconds, or re-queue 1-in-K packets, to bound the blindness
window on mostly-good long flows. Config knob; default = inspect.

## 5. Bypass mechanism

Once a flow is Good(bypass):

1. **Userspace cache** — record `flow → Accept` in `FlowBuffer`; a cache hit
   returns the verdict without re-running the stages (this is what makes inline
   viable under load).
2. **Kernel offload** — so packets don't even reach userspace. Options, in
   `firewall.rs` (M2.2 queue rules):
   - rely on `ct state established,related accept` for an already-accepted flow
     (see `DESIGN-INLINE-DPI-PIPELINE.md` §4), or
   - set a conntrack mark on the flow (`ct mark set 0x1`) and short-circuit
     before the queue rule (`ct mark 0x1 accept` above `queue num N`), or
   - add a per-flow accept element.

Kernel bypass is the real win: a proven-good flow costs ~0 after the decision.

## 6. Bad → resolution (ban + audit): the sticky path

When any stage flags the flow bad:

1. **Lock the verdict** — set `PacketAnalysis.verdict = Drop` (or `Reject`) for
   the current and subsequent packets of the flow. It can no longer be
   downgraded to Accept.
2. **Stay Bad-unresolved up the chain** — remaining stages still run, to fully
   *characterize* the threat for the audit (which signatures, protocol anomaly,
   correlation context). The verdict is fixed; the enrichment continues. (A
   `fast_drop` config knob can short-circuit straight to resolution when full
   characterization isn't wanted.)
3. **Resolve at the action point** (Correlation stage / `ActionExecutor`):
   - **Ban** the source — `Action::Ban` → `firewall.ban(ip, ttl)` → add to
     `@blocked_v4/v6`. The kernel now drops *all* further traffic from that
     source **in-kernel**; it never reaches the queue again (consistent with the
     core invariant: blocked traffic is dropped before the queue).
   - **Audit** — Correlation writes the event to the DB and emits an alert; the
     record carries the full characterization gathered up the chain.
4. Only after **both** ban and audit complete is the flow **Bad(resolved)** and
   removed from active processing.

So *"the drop continues up the chain as bad until that bad has been resolved
(banned and audited)"* = the disposition is held Bad-unresolved through the
pipeline until the ban **and** the audit are both done.

**flow-drop vs ban — kept distinct.** Dropping this one 5-tuple is not the same
as banning the whole source IP. A single bad flow may be dropped without a ban;
an **escalation policy** (severity threshold, or N bad flows from a source —
issues #6 / #7) decides when a drop becomes a ban. "Resolved" requires the ban
whenever the policy calls for it.

## 7. Hold budget — bounded Pending

A Pending (or Good-watch) flow must never hold forever:

- budget = `max(bytes, packets, wall-time)`, configurable per service/port;
- on exhaustion → **default verdict** (fail-open ACCEPT) + mark **Inconclusive**
  (handed to the slower log/ML enrichment path).

This bounds inline latency and memory: a flow that needs more than its budget to
judge is let through but flagged, rather than stalling the queue.

## 8. Maps onto existing symbols

- `engine::flow_buffer::FlowBuffer` — per-flow state, the verdict cache, the hold
  budget, and the disposition above.
- `PacketAnalysis.verdict : PacketVerdict` (Accept/Drop/Reject/Queue) — already
  wired to NFQUEUE `set_verdict` in M2. M3 sets it from the flow disposition
  (cache hit) or from the stages.
- `engine::actions::{Action::Ban, ActionExecutor}` — the resolution (ban +
  audit). `ActionExecutor` is currently stubbed; wiring it to `firewall.ban` is
  part of M3/M4.
- `firewall.rs` — `@blocked_v4/v6` (the in-kernel ban) and the `ct state` /
  `ct mark` + `queue num N bypass` rules (the kernel bypass, M2.2).
- Correlation stage (7) — the audit (DB write + alert generation).

## 9. Relationship to current state

The per-packet verdict plumbing (M2, done) is the substrate — every packet
already gets exactly one verdict. M3 makes that verdict come from a **flow**
decision (cache + state machine) instead of being recomputed per packet, adds the
**bypass** so good flows leave the queue, and adds the **ban + audit resolution**
so bad flows are fully closed out. M2.2 (the nft queue/bypass rules) is the
kernel half of the bypass.

## 10. Open questions / policy knobs

- Bypass policy for Good-watch flows: permanent vs TTL vs re-sample
  (latency/CPU vs mid-stream detection).
- Drop → Ban escalation thresholds (issues #6 / #7).
- Per-service hold budgets and default-verdict (fail-open vs fail-closed for
  strict deployments).
- Output-chain (egress) disposition — same state machine or a subset
  (exfil/DLP)?
- Re-evaluating a bypassed flow on conntrack events (e.g. a new HTTP request
  boundary) without fully re-queuing it.
