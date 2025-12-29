# Nginx Configuration for Cloudflare Real IP Logging

When using Cloudflare as a reverse proxy, nginx logs the Cloudflare proxy IP instead of the real client IP. This document explains how to configure nginx to log the real client IP.

## Option 1: Use CF-Connecting-IP Header (Recommended)

Cloudflare sends the real client IP in the `CF-Connecting-IP` header. This is the most reliable method.

### Step 1: Create a custom log format

Add to `/etc/nginx/nginx.conf` in the `http` block:

```nginx
http {
    # Custom log format with real IP from Cloudflare
    log_format cloudflare '$http_cf_connecting_ip - $remote_user [$time_local] '
                          '"$request" $status $body_bytes_sent '
                          '"$http_referer" "$http_user_agent" '
                          '"$remote_addr"';

    # Alternative: Use X-Forwarded-For (works with any proxy)
    log_format realip '$http_x_forwarded_for - $remote_user [$time_local] '
                      '"$request" $status $body_bytes_sent '
                      '"$http_referer" "$http_user_agent" '
                      '"$remote_addr"';

    # Keep the original combined format for comparison
    log_format combined_plus '$remote_addr - $remote_user [$time_local] '
                             '"$request" $status $body_bytes_sent '
                             '"$http_referer" "$http_user_agent" '
                             '"$http_x_forwarded_for"';
}
```

### Step 2: Use the log format in your server block

```nginx
server {
    listen 80;
    server_name example.com;

    # Use Cloudflare format for access logs
    access_log /var/log/nginx/access.log cloudflare;

    # ... rest of config
}
```

## Option 2: Use ngx_http_realip_module

This method replaces `$remote_addr` with the real IP system-wide.

### Step 1: Add Cloudflare IP ranges to nginx config

```nginx
http {
    # Cloudflare IPv4 ranges
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 131.0.72.0/22;

    # Cloudflare IPv6 ranges
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2a06:98c0::/29;
    set_real_ip_from 2c0f:f248::/32;

    # Use CF-Connecting-IP header (preferred)
    real_ip_header CF-Connecting-IP;
    # Or use X-Forwarded-For
    # real_ip_header X-Forwarded-For;

    # Trust recursive proxies
    real_ip_recursive on;
}
```

### Step 2: Verify the module is loaded

```bash
nginx -V 2>&1 | grep -o with-http_realip_module
```

If not present, you may need to recompile nginx or use a different package.

## Option 3: Quick Fix - Log Both IPs

If you can't modify the nginx config, use this format to log both IPs:

```nginx
log_format debug '$remote_addr - $remote_user [$time_local] '
                 '"$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent" '
                 'XFF:"$http_x_forwarded_for" CF:"$http_cf_connecting_ip"';
```

## Crmonban Configuration

Once nginx is logging real IPs, update crmonban's `config.toml`:

```toml
[services.nginx_access]
enabled = true
log_path = "/var/log/nginx/access.log"
max_failures = 5
find_time = 60
ban_time = 3600

# Patterns will now extract the real IP from the first field
```

## Verifying Real IP Logging

After making changes, restart nginx and verify:

```bash
sudo nginx -t && sudo systemctl reload nginx
tail -f /var/log/nginx/access.log
```

You should now see real client IPs (e.g., `203.0.113.50`) instead of Cloudflare IPs (e.g., `172.69.x.x`).

## Cloudflare IP Ranges

Cloudflare publishes their IP ranges at:
- IPv4: https://www.cloudflare.com/ips-v4
- IPv6: https://www.cloudflare.com/ips-v6

These ranges are also embedded in crmonban's `src/cloudflare.rs` module.
