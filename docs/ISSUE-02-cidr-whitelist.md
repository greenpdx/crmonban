# Feature request: CIDR / network-range support in the IP whitelist (and protected list)

## Summary
crmonban's whitelist accepts **single IP addresses only** — not CIDR ranges. This
makes it impossible to whitelist a CDN/reverse-proxy provider (Cloudflare, etc.)
that fronts the origin, which is exactly the case where a false-positive ban is
most damaging.

## Why this matters (real scenario)
When crmonban monitors a log whose source address is the **CDN's** IP rather than
the real client, a CDN IP can trip a ban rule and get dropped — breaking the site
for *all* traffic arriving via that CDN IP.

Concretely, on a host behind Cloudflare:
- Caddy logs TLS-handshake failures (`no certificate matching TLS ClientHello`)
  with `remote_ip` = the **TCP peer**, which for proxied traffic is a **Cloudflare
  edge IP**, not the visitor.
- A crmonban service that bans on that log (e.g. unknown-SNI scan detection) can
  therefore ban a Cloudflare IP. Once it's in `@blocked_v4`, the `inet crmonban`
  input chain drops it, and a slice of CF→origin traffic fails.

Cloudflare publishes its ranges as **~15 IPv4 + 7 IPv6 CIDRs**, several as large as
`104.16.0.0/13` / `172.64.0.0/13` — these **cannot** be enumerated as individual
IPs, so the current whitelist can't cover them.

## Current behavior
```
$ crmonban whitelist add 173.245.48.0/20
error: invalid value '173.245.48.0/20' for '<IP>': invalid IP address syntax
```
`/etc/crmonban-protected` also appears to do exact-string matching, so a CIDR line
there does not match member IPs either.

## Requested behavior
1. `crmonban whitelist add <CIDR>` accepts a network (v4/v6), and the ban logic
   skips any IP contained in a whitelisted network.
2. `/etc/crmonban-protected` accepts CIDR lines too.
3. Optionally: a config option to load provider lists by URL
   (e.g. `trusted_networks_url = ["https://www.cloudflare.com/ips-v4", ...]`)
   refreshed periodically.

## Implementation note (maps cleanly onto what crmonban already does)
crmonban already drives nftables (`table inet crmonban`, chain `input`,
`ip saddr @blocked_v4 drop`). A whitelist network set is a natural fit:

```
set wl_v4 { type ipv4_addr; flags interval; }
chain input {
    ip  saddr @wl_v4 accept        # whitelist wins, evaluated first
    ip6 saddr @wl_v6 accept
    ip  saddr @blocked_v4 drop
    ip6 saddr @blocked_v6 drop
}
```
`flags interval` sets natively store CIDRs, and an `accept` placed above the drop
short-circuits it.

## Workaround in use (until this lands)
Because crmonban rebuilds its chain on each (re)start, I add the CF ranges out-of-
band and re-apply on start:
- `/usr/local/sbin/crmonban-cf-allow.sh` — creates `cf_v4`/`cf_v6` interval sets in
  `inet crmonban` and `nft insert`s `ip saddr @cf_v4 accept` (and v6) at the top of
  the `input` chain.
- A systemd drop-in `crmonban.service.d/cf-allow.conf` with
  `ExecStartPost=/usr/local/sbin/crmonban-cf-allow.sh` re-applies it every start.

This works but is fragile (hard-coded ranges, depends on crmonban's chain/set
names staying `input`/`blocked_v*`). Native CIDR whitelist support would replace it.

## Acceptance criteria
- [ ] `crmonban whitelist add 1.2.3.0/24` succeeds; `whitelist list` shows it.
- [ ] An IP inside a whitelisted CIDR is never added to `@blocked_*` (or is accepted
      before the drop).
- [ ] CIDR entries work in `/etc/crmonban-protected`.
- [ ] Mixed v4/v6 supported.
