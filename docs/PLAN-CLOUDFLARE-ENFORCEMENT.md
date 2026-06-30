# Plan: Cloudflare-edge enforcement plane

Status: **Plan / future.** Adds a second enforcement plane to crmonban so a banned
IP is dropped on *both* attack paths: the kernel `@blocked` set for **direct-to-origin**
hits, and the Cloudflare edge (via API) for **CF-proxied** hits.

## 1. The gap it fills
A CF-proxied attacker's real IP rides in the encrypted `CF-Connecting-IP` header,
so it never appears in a packet at the origin — only Caddy (or CF) sees it. An nft
`@blocked` rule of that IP is a no-op (packets come from CF, which is whitelisted).
The only point earlier than Caddy that knows the real IP is **Cloudflare's edge**,
reachable via the CF API. Direct-IP attacks (the majority) are already handled by
nft; this completes the picture for the proxied path.

## 2. Flow
```
Caddy @hack → respond 403 + emit event(real_ip = {client_ip} / CF-Connecting-IP)
   → crmonban event ingress → count policy (immediate | N-in-window)
   → crmonban.ban(ip):
        if !enforce: WOULD_BAN (observe), stop
        nft @blocked add ip            # drops the ip's DIRECT connections (L3/4)
        cf_list add ip                 # drops the ip's PROXIED connections (CF edge)
   → reconciler keeps cf_list == active bans (add new, remove expired/unbanned)
```
**One blocklist, two planes.** Every ban goes to both: nft catches the IP if it
ever hits the origin directly; CF catches it on the proxied path. A scanner that
probes both ways is covered both ways.

## 3. Cloudflare API mechanism — use IP **Lists** (not per-IP rules)
| Option | API | Scale | Verdict |
|--------|-----|-------|---------|
| IP Access Rules | `POST …/firewall/access_rules/rules` (one rule per IP) | ~thousands, 1 call/IP | quick start |
| **IP Lists + 1 WAF rule** | `POST …/accounts/{acct}/rules/lists/{list}/items` (bulk array) | 10k+ items, bulk calls | **recommended** |

Create an account **IP list** once + a single WAF custom rule `(ip.src in $list)` →
block. Then runtime = **add/remove list items** (bulk-capable), not rule churn.

**Auth:** a scoped **API token** (Account → *Account Filter Lists: Edit*, or Zone
→ *Firewall Services: Edit*) — never the global key. Store with strict perms
(treat like the TLS-proxy CA key).

## 4. Components to build
1. **`[cloudflare]` config** — `enabled`, `api_token`(path/env), `account_id`,
   `list_id` (or zone_id for access-rules mode), `mode = "list" | "access_rules"`.
2. **CF client module** (`src/cloudflare_api.rs`) — async add/remove IP(s), **bulk
   batched**, with retries + **rate-limit** handling (CF ≈ 1200 req/5 min; the bulk
   list-items endpoint keeps it to a few calls).
3. **Ban-plane hook** — in `CrmonbanCore::ban()` / `unban()` (the single choke
   point), after nft, also enqueue the IP for the CF list. Gated by
   `general.enforce` **and** `cloudflare.enabled`.
4. **Reconciler task** (the important part) — periodic loop that makes the CF list
   equal the **active-ban set in the DB**: add missing, **remove expired** (CF list
   items have **no native TTL**, unlike nft timeout sets), heal drift after a
   restart, and absorb transient API failures (eventual consistency; nft is the
   fast path, CF converges).
5. **Observe-only** — `enforce=false` → `WOULD_BAN` only, **no** CF push (so the
   eval never mutates your CF account).
6. **Real-IP ingress** — the event carries the real IP (`CF-Connecting-IP` for CF,
   packet src for direct). crmonban already extracts the CF real IP (`cloudflare.rs`).

## 5. Routing which plane (refinement, optional)
Default: **push every ban to both planes** (cheapest, most robust). Optional
optimization to cut CF API calls: only push to CF when the *observed* source was a
CF IP (i.e. the attack came proxied) — `src_ip ∈ CF ranges`. But "both, always" is
simpler and pre-blocks an attacker's *other* path, so start there.

## 6. Operational concerns
- **Expiry**: nft auto-expires (timeout set); CF does not → the reconciler removes
  expired IPs. The DB ban table is the source of truth.
- **Failure isolation**: CF API down → nft still enforces; the reconciler retries
  CF. CF is best-effort/eventually-consistent, never on the packet hot path.
- **Rate/size limits**: batch via the bulk items endpoint; cap list size + log if
  capped (no silent truncation).
- **Token security + audit**: every CF add/remove logged with reason; token
  rotatable.

## 7. Optional: block by JA3, not just IP
CF WAF expressions support `cf.bot_management.ja3_hash`. crmonban already computes
JA3 (the SSL recorder). A follow-up could push **bad JA3 fingerprints** to a CF
rule — blocking a scanner's *tooling* across IP rotation. Beyond IP lists; M3.

## 8. Phasing
- **M1** — `[cloudflare]` config + CF client + reconciler against an account IP
  list (sync the existing ban DB → CF). No detection change; just mirrors bans.
- **M2** — the Caddy `event` ingress + per-ban two-plane hook + observe-only gate.
- **M3** — JA3 / advanced expressions; per-plane routing optimization.

## 9. Prior art + decision
See the chat note — the *pattern* (log/event → CF API IP block) is well-trodden
(fail2ban `cloudflare` action, CrowdSec CF bouncer, CF's own WAF/bot-management).
crmonban's differentiator is **unifying** it with its L3/4 packet engine + JA3 +
log + correlation detection and the kernel `@blocked` plane — one system, one
blocklist, both attack paths. Worth adding as a clean, well-scoped feature
(reuses the ban choke point, DB, observe gate), but **after** the direct-path eval
proves out — the nft ban already covers the majority (direct-IP) case.
