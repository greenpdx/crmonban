# Bug: monitoring loop busy-polls log files with no sleep/backoff → 100% CPU and unbounded error logging (filled disk)

## Severity
Critical — on a production host this filled `/var` (18 GB of syslog, 98.7M lines, ~10 MB/s) in ~32 minutes and pegged a full CPU core. A misconfiguration that should have been a single error instead became a denial-of-service against the host it's meant to protect.

## Environment
- Debian 12.14, crmonban running as root via systemd (`crmonban start --foreground`)
- Services monitored: `ssh` (`/var/log/auth.log`), `nginx_access` (`/var/log/nginx/access.log`)

## Root cause (confirmed via strace)
The per-service log monitor loop **re-opens and re-reads each log file from offset 0 on every iteration, in a tight loop with no sleep and no inotify wait**. 5-second `strace -c` of the running daemon:

```
% time     calls    syscall
 40.91       101     epoll_wait
 39.49     21318     futex
  6.44     42663     statx
  4.41     42663     lseek
  3.70     21332     openat
  2.51     21331     close
  2.51     21666     read
```

That is **~4,200 open/stat/read/close cycles per second per file**, with **zero `nanosleep`** calls. The loop never yields between polls.

## Three distinct bugs, in priority order

### 1. Busy-poll loop (no sleep / no inotify) — causes the 100% CPU
The monitor should either:
- use inotify (`notify`/`inotify` crate) to block until the file changes, **or**
- sleep a configurable interval between polls (e.g. `poll_interval_ms`, default 250–1000 ms), **and**
- tail incrementally from the last byte offset instead of re-reading from 0 each time.

There is currently **no config knob** for poll interval (`grep -iE 'interval|poll|sleep|backoff' config.toml` → nothing), so operators cannot mitigate this without a code change.

### 2. No rate-limit / backoff on monitor errors — caused the disk fill
When a log read fails, the loop emits **two ERROR lines per iteration** and immediately retries with no backoff:

```
ERROR Monitor error: Error monitoring nginx_access: Permission denied (os error 13)
ERROR Error processing log for service nginx_access: Permission denied (os error 13)
```

Combined with bug #1 (~4,200 iterations/sec), this produced ~51,000 log lines/sec → 18 GB in 32 min. Fix:
- exponential backoff when a monitor errors (e.g. 1s → 2s → … → cap 60s),
- log the same recurring error **once** (or rate-limited, e.g. "repeated N times in last 60s"),
- consider disabling a service after K consecutive failures and logging a single fatal line.

### 3. File-descriptor exhaustion under default `LimitNOFILE` (soft 1024)
Re-opening files every poll, plus `auto_intel` opening a socket per IP for rdns/whois during a backlog of attacker IPs, blew past the 1024 soft limit:

```
ERROR Error processing log for service ssh: Too many open files (os error 24)
```

Fix: don't re-open per poll (see #1), bound concurrent intel lookups, and/or ship `LimitNOFILE=` in the unit. Reproduces whenever a large backlog of distinct IPs is processed at once (e.g. after a restart).

## Secondary issue: capabilities vs. log file permissions (packaging)
The shipped unit runs as root but sets `CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN`, which **drops `CAP_DAC_OVERRIDE`**. Root therefore obeys normal file permissions, and the default Debian log files are group-`adm`, mode `0640`:

```
-rw-r----- 1 root     adm /var/log/auth.log
-rw-r----- 1 www-data adm /var/log/nginx/access.log
```

With nothing in group `adm`, crmonban gets `EACCES` on **every** monitored log out of the box → triggers bugs #1/#2 immediately. Fixes (pick one, and document it):
- ship `SupplementaryGroups=adm` in the unit (least privilege — what I applied to recover this host), or
- add `CAP_DAC_READ_SEARCH` to the bounding/ambient set, or
- document the required group membership in install docs.

## Suggested acceptance criteria
- [ ] Idle CPU ~0% when logs are quiet (no busy-poll).
- [ ] A permanently-failing monitor (e.g. unreadable file) logs **≤ a few lines/min**, not thousands/sec, and backs off.
- [ ] `poll_interval` (or inotify) is configurable in `config.toml`.
- [ ] No fd exhaustion when processing a large backlog of unique IPs.
- [ ] Fresh install can read `/var/log/auth.log` + nginx logs without manual permission changes (or docs state the requirement).

## Workarounds applied on the affected host (until fixed in code)
- `SupplementaryGroups=adm` drop-in (resolves the EACCES root trigger)
- `CPUQuota=25%` drop-in (bounds the busy-poll CPU burn)
- journald `SystemMaxUse=500M` + rate-limit (caps blast radius of any future log flood)
