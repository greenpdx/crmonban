# Feature request: volume/rate-based banning (ban IPs exceeding N requests per window)

## Summary
crmonban bans on **attack-pattern matches** (failed auth, SQLi, path traversal,
unknown-SNI, …). It has no way to ban a client purely for **abusive volume** — an
aggressive scraper/bot that hammers the site but never matches an attack signature
is never throttled, no matter how many requests it makes.

## Why this matters (real scenario)
On a Caddy-fronted host, the daily log report showed:

- **~247,000 requests / 24h**, of which a **single IP (`38.77.2.245`) made 119,023**
  — ~49% of all traffic, ~1.4 req/s sustained for a day.
- **crmonban bans in that window: 0.** The scraper hit `/`, `/robots.txt`, RSS/
  taxonomy feeds, etc. — nothing matched an exploit pattern, so it ran unthrottled.

That's exactly the class of abuse (content scraping, resource exhaustion) that a
volume threshold is meant to catch, and crmonban currently can't.

## Current behavior
Every `[[services.X.patterns]]` rule requires a regex hit; `max_failures` /
`find_time` count *pattern* matches per IP. There is no rule that counts **all**
requests from an IP and bans on the total.

## Requested behavior
A per-service **volume threshold** that bans an IP exceeding a request count within
a window, independent of attack patterns. For example:

```toml
[services.nginx_access]
log_path = "/opt/caddy/logs/access.log"
# existing pattern-based rules ...

[services.nginx_access.rate]      # new
enabled = true
max_requests = 20000              # ban over N requests ...
window = 86400                    # ... within this many seconds (per-day)
ban_time = 86400
# optional: exclude_status = [301,308]   # don't count redirects
# optional: exclude_paths  = ["/robots.txt"]
```

Semantics: count log lines per source IP over `window`; when an IP crosses
`max_requests`, ban for `ban_time`. (The source IP should be the **real client**
— i.e. the `client_ip` crmonban already parses — not a fronting CDN; see the CIDR
whitelist issue.)

## Possible implementation / workaround
This may be partly approximable today with a catch-all pattern
(`(?P<ip>\d+\.\d+\.\d+\.\d+)`, very high `max_failures`, large `find_time`), but:
- it's a hack (abuses the failure counter for "all requests"),
- needs confirmation that `find_time` of 86400 is supported and that per-IP
  timestamp tracking over a full day is efficient,
- offers no status/path exclusion (redirect & asset noise inflates the count).

A first-class `rate`/`volume` rule (above) would be clearer and let operators
exclude 3xx/asset noise.

## Acceptance criteria
- [ ] An IP exceeding `max_requests` within `window` is banned, with **no** attack
      pattern required.
- [ ] Counting uses the real client IP (CDN-aware).
- [ ] Optional status/path exclusions so redirects/assets don't inflate counts.
- [ ] Reasonable memory/CPU for day-long windows under heavy traffic.
