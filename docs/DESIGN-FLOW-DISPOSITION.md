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
  boundary) without fully re-queuing it. **→ designed in §11–§13 below.**

## 11. The determination cascade — quick-bad / quick-good / undecided

The disposition (§2) is produced by the 8 stages acting as a **decision
cascade**. Each stage emits one of three signals for the flow:

- **quick-bad** — the stage is confident the flow is bad → terminal: lock the
  verdict to Drop, mark the flow Bad (§6).
- **quick-good** — the stage can *authoritatively* clear the flow → terminal for
  bypass eligibility (subject to the §4 "can it still go bad?" gate).
- **undecided** — the stage cannot tell → fall through to the next stage. The
  flow stays Pending (§2) and the next packet re-runs the cascade.

**The asymmetry that drives everything: bad is democratic, good is
authoritative.** *Any* stage may condemn a flow; almost none may absolve it,
because "I found nothing" is not the same as "there is nothing." What each stage
can actually emit:

| Stage | quick-bad | quick-good | rationale |
|-------|-----------|------------|-----------|
| IpFilter (threat-intel) | yes (known-malicious src) | **yes** (trusted/high-rep src, allow set) | reputation cuts both ways — the one cheap absolver |
| FlowTracker | rarely | no | bookkeeping; feeds the normal model |
| Layer234 (crvecdb) | yes (flood/scan/brute/bad-flags) | scoped only | "not an L3/4 attack" ≠ payload is clean |
| SignatureMatching | yes (rule hit) | **never** | no-match ≠ good (zero-day) |
| ProtocolAnalysis | yes (anomaly / web-attack) | weak | clean parse leans good, not authoritative |
| WasmPlugins | either | either | custom |
| MLDetection | yes (high anomaly) | **yes** (calibrated low anomaly) | the other real absolver |
| Correlation | yes (campaign) | no | cross-flow condemner |

So the safe policy is **democratic-bad + conservative-good**: a flow earns the
GOOD mark only after the payload-bearing packets have *cleared the condemning
stages* (signature + protocol + ML), or an authoritative allowlist/reputation
hit fired. Cheap early stages can only *fail to condemn* (= undecided), never
grant good. This also yields the cost ordering for free: cheap condemners first
(reputation, volumetric) so quick-bads exit in stages 0–2; the expensive deep
inspection (sig/proto/ML) runs only on the undecided middle, and clearing it is
what earns GOOD.

Already present in code: `analysis.fast_path_good` (an ML/learned-normal
quick-good), the `skip_heavy` early-out after FlowTracker, and any blocking
stage verdict (quick-bad). §11 formalizes these into one explicit tri-state.

## 12. Three tiers and the novelty principle

The disposition lives in a **conntrack mark** with three states — unset
(undecided), GOOD, BAD — which splits enforcement across three tiers:

- **Tier 1 — nftables, in-kernel, line rate.** Decided flows: `ct mark GOOD →
  accept`, `ct mark BAD → drop`. These packets never reach the queue or the
  engine. The bulk of traffic ends here.
- **Tier 2 — NFQUEUE → userspace cascade (§11).** Only the **undecided
  frontier**: new flows until decided, plus the slow-determination tail. The
  only thing the expensive engine ever sees.
- **Tier 3 — the writeback.** The verdict packet sets the skb mark; the
  `persist` rule copies it to the conntrack mark; from the next packet on the
  flow is Tier 1. The ct mark *is* the userspace→kernel handoff.

**Load model:**

```
userspace pps ≈ (new-flows/s × packets-to-decide)
              + (good-flows/s × re-inspection packets at good_ttl)
              + (undecided tail, bounded by the per-src rate window §?)
```

Cost scales with the **flow-decision rate, not the bandwidth** — the reason this
runs inline on an RPi. A 4 GB elephant flow costs ~the first few packets, then
it is Tier 1. The nft per-rule counters (the `queue` counter vs the `ct mark …
accept` bypass counter) measure exactly this split — their ratio is the
userspace-offload efficiency to watch on the device.

**The novelty principle.** Every flow passes the frontier *once*, at decision
time — that is when the baseline learns its head. Re-sampling the bypassed
continuation of a flow that is *still behaving the same* adds **no new
information** (same 5-tuple, same profile, already characterised). The only thing
in a bypassed flow that carries new information is **deviation** from the head
the baseline already learned — which is also a security event. So the engine
must spend userspace cycles only on **novelty: new flows and *changed* flows.**
That flips the job from *sampling bypassed traffic* (redundant) to
*change-detection* (§13). The re-inspection triggers are what *make* "bypassed =
no new info" true by construction.

## 13. Re-inspection of bypassed flows — per-protocol classes

A GOOD flow is re-inspected only when it may have entered a **new chapter**.
Two kernel-cheap triggers approximate that without running any model in-kernel:

- **`good_ttl` (time)** — catches a long-lived flow that goes quiet then turns.
- **volume (`ct bytes` / `ct packets`)** — re-touch at chapter boundaries of a
  high-volume flow instead of on a wall clock. conntrack already counts both.

The right thresholds fall out of two questions per protocol — **(a) where is the
attack surface** (head-only vs recurring-per-unit) and **(b) is the bulk
visible** (cleartext vs encrypted/opaque):

|                  | head-only attack surface            | recurring attack surface                  |
|------------------|-------------------------------------|-------------------------------------------|
| **opaque bulk**  | TLS, SSH-session, QUIC — bypass hard | h2/h3-over-TLS — requests invisible → opaque |
| **cleartext bulk** | rare                              | HTTP/1.1, SMTP DATA, FTP-ctrl, DNS — every unit is new surface |

- **Opaque (top row): bypass aggressively.** After the head is clean (JA3/SNI/
  cert for TLS; HASSH/auth for SSH) the rest is ciphertext — nothing to
  payload-inspect. Long `good_ttl`, no per-byte *payload* re-inspect; the later
  signal is **behavioral** (volume/rate → exfil) handed to layer234/longterm,
  not a payload re-scan. Where the offload lives.
- **Cleartext-recurring (bottom right): stay on the frontier.** Every request /
  message / query is fresh attacker-controlled content, and you cannot *sample*
  your way to catching a specific malicious one. These earn little/no bypass;
  small `good_ttl` only to coast the idle gap between units.

**Starting points (tune from the offload counters):**

| Protocol            | class      | good_ttl | volume re-inspect            | bypass payoff |
|---------------------|------------|----------|------------------------------|---------------|
| TLS / QUIC bulk     | opaque     | ~300 s   | none for payload; ~50–100 MB → behavioral | huge |
| SSH (post-auth)     | opaque     | ~120 s   | ~10 MB → exfil check         | high |
| HTTP/2,3-over-TLS   | opaque     | ~300 s   | none (requests invisible)    | high |
| HTTP/1.1 cleartext  | recurring  | ~15 s    | per-request → ~frontier      | low |
| SMTP                | recurring  | ~30 s    | per-message (~16–32 KB)      | low |
| DNS                 | recurring  | n/a      | per-query → frontier (cheap) | ~none |
| FTP ctrl / data     | recurring / opaque | 30 / 60 s | per-command / file-head then bypass | mixed |
| generic TCP         | unknown    | ~60 s    | conservative                 | moderate |

**Why it works on an RPi:** the high-byte protocols (TLS bulk, encrypted
tunnels, file transfer) are exactly the **opaque/head-only, bypass-friendly**
ones; the inspection-hungry protocols (HTTP, SMTP, DNS) are usually
**low-bandwidth**. The offload lands precisely where the bytes are.

**Mechanism (collapses 20 protocols → 3 classes):**

- **Userspace classifies** at decision time (it knows the L7 protocol — nft only
  knows ports) and encodes a 2-bit **re-inspect class** into the GOOD mark:
  `GOOD | {opaque, recurring, generic}`.
- **`good_ttl` is the primary trigger**, implemented as a per-class nft
  **timeout set** (`dpi_good_opaque` ~300 s, `dpi_good_generic` ~60 s, recurring
  → tiny/none). Membership expiry → the flow is undecided again → re-queued.
  This is clean in nft (`ct bytes` is cumulative, so "every N bytes" is *not* a
  clean rule).
- **Per-byte re-inspection is only for the opaque/behavioral case** (exfil), and
  is coarse: a high cumulative `ct bytes >` one-shot bumps the flow back to the
  frontier once, which re-decides and re-arms a fresh GOOD with a higher next
  threshold. Cleartext-recurring never deeply bypasses, so it never needs it.

So the whole per-protocol story is: **classify into {opaque, recurring, generic}
at decision time, give each class a `good_ttl` timeout set, and let opaque carry
a coarse byte-budget for a behavioral re-check.**

### 13.1 Making the opaque class inspectable — TLS interception

The opaque class is bypass-friendly *because* its bulk is unreadable — which also
means a payload attack inside TLS is invisible. To inspect it you must terminate
the TLS at the box (transparent MITM): accept the client's TLS with an on-the-fly
leaf cert minted for the SNI and signed by a **local CA the client trusts**, open
a *real* TLS session to the true upstream (validating its cert against the public
roots), and relay plaintext through the pipeline in the middle. Scaffolded in
`src/tls_proxy.rs` (`CertificateAuthority` + per-SNI `CertCache` + `TlsAcceptor`/
`TlsConnector`). Requirements/limits: the local CA must be installed in the
client trust store (works only for managed clients); **cert-pinned** apps and
**mTLS** servers refuse interception (and that refusal is itself a signal); and
each new flow costs two handshakes + a cert sign (cache leaf certs per SNI).

**Note the trade it makes against §13:** interception converts an opaque flow
into a **cleartext-recurring** one (you now see every HTTP request) — so an
intercepted TLS flow *leaves* the bypass-friendly quadrant and becomes
frontier-always. You gain visibility and lose the offload for that flow. Hence
interception should be **selective** (high-value destinations), not blanket —
especially on an RPi.
