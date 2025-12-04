# crmonban

nftables-based intrusion prevention system with attacker intelligence gathering.

A modern alternative to fail2ban/crowdsec that uses nftables directly and gathers comprehensive information about attackers.

## Features

- **nftables Integration** - Uses nftables sets for O(1) IP blocking (no iptables)
- **Log Monitoring** - Real-time monitoring of auth.log, nginx, apache, postfix, dovecot
- **Attacker Intelligence** - Automatically gathers:
  - GeoIP location (country, city, coordinates)
  - WHOIS data (organization, registrar, abuse contact)
  - Reverse DNS
  - ASN & ISP information
  - Shodan data (optional, requires API key)
  - AbuseIPDB threat score (optional, requires API key)
- **SQLite Database** - Persistent storage for bans, events, intel, whitelist
- **CLI Interface** - Full command-line management
- **Daemon Mode** - Background monitoring with auto-banning
- **Whitelist Support** - Protect trusted IPs from being banned
- **D-Bus Interface** - External control and event notifications for integration with other applications
- **crrouter_web Integration** - Seamless integration with crrouter_web firewall:
  - Zone-aware banning (trust levels, implicit whitelists)
  - eBPF fast-path blocking for sub-microsecond drops
  - Shared whitelist across systems
  - SIEM export (CEF, LEEF, Syslog, JSON formats)

## Installation

### Build from source

```bash
# Clone the repository
git clone https://github.com/greenpdx/crmonban.git
cd crmonban

# Build
cargo build --release

# Install (optional)
sudo cp target/release/crmonban /usr/local/bin/

# Install D-Bus policy file
sudo cp dbus/org.crmonban.Daemon.conf /usr/share/dbus-1/system.d/
sudo systemctl reload dbus
```

### Dependencies

- Rust 2024 edition
- nftables (nft command must be available)
- Linux kernel with nftables support
- D-Bus (for D-Bus interface support)

## Quick Start

```bash
# Generate default configuration
sudo mkdir -p /etc/crmonban
crmonban gen-config -o /etc/crmonban/config.toml

# Create database directory
sudo mkdir -p /var/lib/crmonban

# Initialize nftables table and sets
sudo crmonban init

# Start the daemon in foreground (for testing)
sudo crmonban start -f

# Or start as background daemon
sudo crmonban start
```

## CLI Commands

```
crmonban start [-f]              Start monitoring daemon (-f for foreground)
crmonban stop                    Stop the daemon
crmonban status                  Show daemon status

crmonban ban <ip> [-d secs]      Ban an IP address (-d duration, 0=permanent)
crmonban unban <ip>              Unban an IP address
crmonban list [-f format]        List active bans (table/json/simple)

crmonban intel <ip> [-r] [-j]    Gather intel on IP (-r refresh, -j json)

crmonban whitelist add <ip>      Add IP to whitelist
crmonban whitelist rm <ip>       Remove IP from whitelist
crmonban whitelist list          List whitelisted IPs

crmonban logs [-l limit]         Show recent activity logs
crmonban stats                   Show attack statistics

crmonban init                    Initialize nftables configuration
crmonban flush --yes             Flush all bans (dangerous!)
crmonban gen-config [-o path]    Generate default configuration
```

## Configuration

Configuration file: `/etc/crmonban/config.toml`

### General Settings

```toml
[general]
db_path = "/var/lib/crmonban/crmonban.db"
pid_file = "/var/run/crmonban.pid"
log_level = "info"              # trace, debug, info, warn, error
auto_intel = true               # Gather intel automatically on ban
default_ban_duration = 3600     # Default ban duration in seconds
```

### nftables Settings

```toml
[nftables]
table_name = "crmonban"
chain_name = "input"
set_v4 = "blocked_v4"
set_v6 = "blocked_v6"
priority = -100                 # Chain priority (lower = earlier)
```

### Intelligence Settings

```toml
[intel]
geoip_enabled = true
rdns_enabled = true
whois_enabled = true
timeout_secs = 10

# Optional API keys for enhanced intelligence
# shodan_api_key = "your-key"
# abuseipdb_api_key = "your-key"
```

### Service Monitoring

```toml
[services.ssh]
enabled = true
log_path = "/var/log/auth.log"
max_failures = 5                # Failures before ban
find_time = 600                 # Time window (seconds)
ban_time = 3600                 # Ban duration (seconds)

[[services.ssh.patterns]]
name = "failed_password"
regex = 'Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'
event_type = "failed_auth"

[[services.ssh.patterns]]
name = "invalid_user"
regex = 'Invalid user .* from (?P<ip>\d+\.\d+\.\d+\.\d+)'
event_type = "invalid_user"
```

### Available Services

- **ssh** - SSH authentication failures (enabled by default)
- **nginx** - Rate limiting violations
- **apache** - Authentication failures
- **postfix** - SMTP authentication failures
- **dovecot** - IMAP/POP3 authentication failures

### D-Bus Settings

```toml
[dbus]
enabled = true          # Enable D-Bus interface
system_bus = true       # Use system bus (recommended for daemon)
```

## D-Bus Interface

crmonban exposes a D-Bus interface for external applications to control the daemon and receive events.

**Service**: `org.crmonban.Daemon`
**Object Path**: `/org/crmonban/Daemon`

### Methods

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `Status` | - | `StatusInfo` | Get daemon status |
| `Ban` | `ip: String, duration_secs: u32, reason: String` | `bool` | Ban an IP address |
| `Unban` | `ip: String` | `bool` | Unban an IP address |
| `GetBans` | - | `Array<BanInfo>` | List active bans |
| `IsBanned` | `ip: String` | `bool` | Check if IP is banned |

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `Running` | `bool` | Always true if reachable |
| `ActiveBanCount` | `u64` | Number of active bans |
| `UptimeSeconds` | `u64` | Daemon uptime in seconds |
| `EventsProcessed` | `u64` | Total events processed |

### Signals

| Signal | Parameters | Description |
|--------|------------|-------------|
| `BanAdded` | `ip, reason, source, duration_secs` | Emitted when an IP is banned |
| `BanRemoved` | `ip, reason` | Emitted when an IP is unbanned |
| `AttackDetected` | `ip, service, event_type` | Emitted on each detected attack |
| `DaemonStarted` | - | Emitted when daemon starts |
| `DaemonStopping` | - | Emitted when daemon is stopping |

### Example: Monitor Events with dbus-monitor

```bash
dbus-monitor --system "interface='org.crmonban.Daemon'"
```

### Example: Query Status with busctl

```bash
busctl call org.crmonban.Daemon /org/crmonban/Daemon org.crmonban.Daemon Status
```

## crrouter_web Integration

crmonban integrates with crrouter_web for enhanced firewall management.

### Zone Configuration

```toml
[zones]
enabled = true
config_file = "/etc/crrouter/firewall.yaml"  # Shared with crrouter_web
whitelist_threshold = 80                      # Trust level for implicit whitelist

[[zones.zones]]
name = "internal"
trust_level = 80
networks = ["10.0.0.0/8", "192.168.0.0/16"]
implicit_whitelist = true

[[zones.zones]]
name = "external"
trust_level = 0
networks = ["0.0.0.0/0"]
```

### SIEM Export

```toml
[siem]
enabled = true
format = "cef"  # cef, leef, syslog, json

[[siem.targets]]
type = "file"
path = "/var/log/crmonban/siem.log"

[[siem.targets]]
type = "syslog"
socket = "/dev/log"

[[siem.targets]]
type = "webhook"
url = "https://siem.example.com/api/events"
headers = [["Authorization", "Bearer token"]]
```

### eBPF Fast-Path Blocking

```toml
[ebpf]
enabled = true
method = "dbus"           # dbus, mapfile, disabled
sync_interval_secs = 60   # Sync with nftables
max_entries = 10000
```

### Shared Whitelist

```toml
[whitelist]
enabled = true
cache_ttl_secs = 300

[[whitelist.sources]]
type = "database"         # Local crmonban whitelist

[[whitelist.sources]]
type = "zones"            # Zone-based implicit whitelist

[[whitelist.sources]]
type = "networks"
networks = ["10.0.0.0/8", "172.16.0.0/12"]

[[whitelist.sources]]
type = "file"
path = "/etc/crmonban/whitelist.txt"
watch = true

[[whitelist.sources]]
type = "crrouter_web"     # Query crrouter_web via D-Bus
```

### crrouter_web Plugin

Enable the crmonban plugin in crrouter_web:

```bash
# Build crrouter_web with crmonban support
cargo build --features crmonban

# The plugin provides these JSON-RPC methods:
# crmonban.status - Get crmonban daemon status
# crmonban.bans   - List active bans
# crmonban.ban    - Ban an IP
# crmonban.unban  - Unban an IP
# crmonban.sync   - Sync bans to eBPF
```

## nftables Structure

crmonban creates the following nftables structure:

```
table inet crmonban {
    set blocked_v4 {
        type ipv4_addr
        flags timeout
    }

    set blocked_v6 {
        type ipv6_addr
        flags timeout
    }

    chain input {
        type filter hook input priority -100; policy accept;
        ip saddr @blocked_v4 drop
        ip6 saddr @blocked_v6 drop
    }
}
```

## Systemd Service

Create `/etc/systemd/system/crmonban.service`:

```ini
[Unit]
Description=crmonban intrusion prevention system
After=network.target

[Service]
Type=forking
PIDFile=/var/run/crmonban.pid
ExecStart=/usr/local/bin/crmonban start
ExecStop=/usr/local/bin/crmonban stop
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable crmonban
sudo systemctl start crmonban
```

## Examples

### Manual ban with 24-hour duration

```bash
sudo crmonban ban 192.168.1.100 -d 86400 -r "Port scanning"
```

### Gather intelligence on an IP

```bash
crmonban intel 8.8.8.8
```

Output:
```
IP: 8.8.8.8
Gathered: 2024-01-15 10:30:00 UTC

--- Location ---
Country: United States (US)
City: Mountain View, California
Coordinates: 37.4056, -122.0775
Timezone: America/Los_Angeles

--- Network ---
ASN: AS15169 (Google LLC)
ISP: Google LLC
Reverse DNS: dns.google

--- Flags ---
⚠ Hosting/Datacenter
```

### View attack statistics

```bash
crmonban stats
```

### Whitelist a trusted server

```bash
sudo crmonban whitelist add 10.0.0.1 -c "Internal monitoring server"
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        crmonban                              │
├─────────────────────────────────────────────────────────────┤
│  CLI Interface                                               │
│  ├── ban/unban/list                                         │
│  ├── whitelist management                                   │
│  ├── intel gathering                                        │
│  └── statistics                                             │
├─────────────────────────────────────────────────────────────┤
│  Daemon                                                      │
│  ├── Log Monitor (watches files, matches patterns)          │
│  ├── Event Processor (counts failures, triggers bans)       │
│  ├── Intel Gatherer (GeoIP, WHOIS, rDNS)                   │
│  └── Cleanup Task (removes expired bans)                    │
├─────────────────────────────────────────────────────────────┤
│  Firewall (nftables)              │  Database (SQLite)      │
│  ├── Table: crmonban              │  ├── bans               │
│  ├── Sets: blocked_v4/v6          │  ├── events             │
│  └── Chain: input                 │  ├── intel              │
│                                   │  ├── whitelist          │
│                                   │  └── activity_log       │
└─────────────────────────────────────────────────────────────┘
```

## License

MIT

## Contributing

Contributions welcome! Please open issues or pull requests on GitHub.
