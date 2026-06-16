# Feature request: per-pattern "instant ban" for known-malicious paths (single hit, long ban)

## Summary
crmonban's ban threshold (`max_failures` / `find_time`) is configured **per service**,
so every pattern in a service shares the same counter. But some patterns are
**unambiguously malicious on the very first hit** — a request for `/.env`,
`/.git/config`, `/wp-login.php`, `/info.php`, `/php.php`, `/vendor/phpunit/...`,
etc. is a known hacking/recon attempt, not something a real user ever does. These
should ban **immediately** and for a **long** time, without waiting to accumulate
N hits.

## Why this matters (real scenario)
The daily log report showed scanners hitting, among others:
```
503  /.git/config
503  /info.php
503  /.env
503  /php.php
```
Each of those is a single-shot probe for exposed secrets/config. Under the current
model they merely add to a shared `5 in 60s` counter — a scanner that fires one
`/.env` then moves on never reaches the threshold and is never banned, even though
that one request already proved hostile.

## Current behavior
`max_failures`, `find_time`, `ban_time` live on `[services.X]` and apply to **all**
of that service's `[[patterns]]`. There is no way to mark an individual pattern as
"ban on first match" or give it a different (longer) ban duration.

## Requested behavior
Per-pattern overrides so a high-confidence pattern can ban instantly and long:

```toml
[[services.nginx_access.patterns]]
name = "dotenv_probe"
regex = '(?P<ip>\d+\.\d+\.\d+\.\d+).*\s/(\.env|\.git/config|wp-login\.php|info\.php|php\.php)\b'
event_type = "exploit"
max_failures = 1          # NEW: ban on first hit (overrides service default)
ban_time = 2592000        # NEW: 30 days (or 0 = permanent)
```

i.e. a pattern may optionally carry its own `max_failures` and `ban_time`; if
present they override the service-level values for matches of that pattern.

Nice-to-haves:
- A built-in, maintained **known-malicious-path** ruleset shipped with crmonban
  (so operators don't have to curate it), toggled on per service.
- An `action`/severity shorthand, e.g. `action = "ban_now"` implying
  `max_failures = 1` + a long `ban_time`.

## Acceptance criteria
- [ ] A pattern with `max_failures = 1` bans the source IP on the first match,
      regardless of the service-level threshold.
- [ ] A pattern can set its own `ban_time` (incl. permanent).
- [ ] Patterns without overrides keep using the service defaults (back-compat).
- [ ] Works with the real client IP (CDN-aware) and respects the whitelist.
