//! Cloudflare IP detection and real IP extraction
//!
//! Cloudflare proxies requests through their network, replacing the client IP
//! with a Cloudflare IP. This module:
//! - Detects Cloudflare proxy IPs
//! - Extracts real client IPs from X-Forwarded-For or CF-Connecting-IP headers
//! - Provides the official Cloudflare IP ranges

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Cloudflare IPv4 ranges (as of Dec 2025)
/// Source: https://www.cloudflare.com/ips-v4
pub const CLOUDFLARE_IPV4_RANGES: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
];

/// Cloudflare IPv6 ranges
/// Source: https://www.cloudflare.com/ips-v6
pub const CLOUDFLARE_IPV6_RANGES: &[&str] = &[
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Parsed CIDR range
#[derive(Debug, Clone)]
pub struct CidrRange {
    network: IpAddr,
    prefix_len: u8,
}

impl CidrRange {
    pub fn parse(cidr: &str) -> Option<Self> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return None;
        }

        let network = IpAddr::from_str(parts[0]).ok()?;
        let prefix_len = parts[1].parse::<u8>().ok()?;

        Some(Self { network, prefix_len })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let net_bits = u32::from(net);
                let addr_bits = u32::from(addr);
                let mask = if self.prefix_len >= 32 {
                    u32::MAX
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                (net_bits & mask) == (addr_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let net_bits = u128::from(net);
                let addr_bits = u128::from(addr);
                let mask = if self.prefix_len >= 128 {
                    u128::MAX
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                (net_bits & mask) == (addr_bits & mask)
            }
            _ => false,
        }
    }
}

/// Cloudflare IP checker
pub struct CloudflareChecker {
    ipv4_ranges: Vec<CidrRange>,
    ipv6_ranges: Vec<CidrRange>,
}

impl CloudflareChecker {
    pub fn new() -> Self {
        let ipv4_ranges: Vec<CidrRange> = CLOUDFLARE_IPV4_RANGES
            .iter()
            .filter_map(|s| CidrRange::parse(s))
            .collect();

        let ipv6_ranges: Vec<CidrRange> = CLOUDFLARE_IPV6_RANGES
            .iter()
            .filter_map(|s| CidrRange::parse(s))
            .collect();

        Self {
            ipv4_ranges,
            ipv6_ranges,
        }
    }

    /// Check if an IP belongs to Cloudflare
    pub fn is_cloudflare_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => self.ipv4_ranges.iter().any(|r| r.contains(ip)),
            IpAddr::V6(_) => self.ipv6_ranges.iter().any(|r| r.contains(ip)),
        }
    }

    /// Extract real client IP from X-Forwarded-For header
    /// Format: "client, proxy1, proxy2, ..."
    /// Returns the leftmost non-Cloudflare IP
    pub fn extract_real_ip(&self, xff_header: &str) -> Option<IpAddr> {
        for part in xff_header.split(',') {
            let ip_str = part.trim();
            if let Ok(ip) = IpAddr::from_str(ip_str) {
                if !self.is_cloudflare_ip(ip) {
                    return Some(ip);
                }
            }
        }
        None
    }

    /// Extract real IP from CF-Connecting-IP header (preferred)
    pub fn extract_cf_connecting_ip(header: &str) -> Option<IpAddr> {
        IpAddr::from_str(header.trim()).ok()
    }
}

impl Default for CloudflareChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse nginx log line and extract real client IP
/// Supports multiple log formats:
/// 1. Standard combined: `$remote_addr - - [time] "request" status size "referer" "ua"`
/// 2. With XFF: `$remote_addr - - [time] "request" status size "referer" "ua" "$http_x_forwarded_for"`
/// 3. With CF-IP: `$http_cf_connecting_ip - - [time] "request" status size "referer" "ua"`
pub fn extract_client_ip(log_line: &str, cf_checker: &CloudflareChecker) -> Option<IpAddr> {
    // Try to find X-Forwarded-For at the end of the line (quoted)
    if let Some(xff_start) = log_line.rfind("\" \"") {
        let after_ua = &log_line[xff_start + 3..];
        if let Some(xff_end) = after_ua.find('"') {
            let xff = &after_ua[..xff_end];
            if xff.contains(',') || xff.contains('.') || xff.contains(':') {
                if let Some(real_ip) = cf_checker.extract_real_ip(xff) {
                    return Some(real_ip);
                }
            }
        }
    }

    // Fall back to first IP in the line
    let first_space = log_line.find(' ')?;
    let ip_str = &log_line[..first_space];
    let ip = IpAddr::from_str(ip_str).ok()?;

    // If it's a Cloudflare IP and we couldn't find real IP, return None
    // to indicate this should be investigated
    if cf_checker.is_cloudflare_ip(ip) {
        // Still return it, but caller should know it's a proxy IP
        return Some(ip);
    }

    Some(ip)
}

/// Represents a parsed log entry with both proxy and real IP
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub proxy_ip: IpAddr,
    pub real_ip: Option<IpAddr>,
    pub is_cloudflare: bool,
    pub request: String,
    pub status: u16,
    pub user_agent: String,
}

impl LogEntry {
    /// Get the effective IP to use for banning
    pub fn effective_ip(&self) -> IpAddr {
        self.real_ip.unwrap_or(self.proxy_ip)
    }
}

/// Parse a nginx combined log line
pub fn parse_nginx_log(line: &str, cf_checker: &CloudflareChecker) -> Option<LogEntry> {
    // Standard combined format:
    // IP - - [time] "METHOD path HTTP/x.x" status size "referer" "user-agent"

    let mut parts = line.splitn(2, " - - ");
    let ip_str = parts.next()?.trim();
    let rest = parts.next()?;

    let proxy_ip = IpAddr::from_str(ip_str).ok()?;
    let is_cloudflare = cf_checker.is_cloudflare_ip(proxy_ip);

    // Extract request (between first pair of quotes)
    let request_start = rest.find('"')? + 1;
    let request_end = rest[request_start..].find('"')? + request_start;
    let request = rest[request_start..request_end].to_string();

    // Extract status (after request quotes)
    let after_request = &rest[request_end + 2..];
    let status_str = after_request.split_whitespace().next()?;
    let status = status_str.parse::<u16>().unwrap_or(0);

    // Extract user-agent (last quoted string before optional XFF)
    let ua = extract_quoted_field(rest, -2).unwrap_or_default();

    // Try to extract real IP from X-Forwarded-For if present
    let real_ip = if is_cloudflare {
        // Check for XFF at the end
        extract_quoted_field(rest, -1)
            .and_then(|xff| cf_checker.extract_real_ip(&xff))
    } else {
        None
    };

    Some(LogEntry {
        proxy_ip,
        real_ip,
        is_cloudflare,
        request,
        status,
        user_agent: ua,
    })
}

/// Extract the nth quoted field from a string (negative index counts from end)
fn extract_quoted_field(s: &str, index: i32) -> Option<String> {
    let quotes: Vec<usize> = s.match_indices('"').map(|(i, _)| i).collect();

    if quotes.len() < 2 {
        return None;
    }

    let pairs: Vec<(usize, usize)> = quotes.chunks(2)
        .filter_map(|chunk| {
            if chunk.len() == 2 {
                Some((chunk[0], chunk[1]))
            } else {
                None
            }
        })
        .collect();

    let idx = if index < 0 {
        (pairs.len() as i32 + index) as usize
    } else {
        index as usize
    };

    pairs.get(idx).map(|(start, end)| s[start + 1..*end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_detection() {
        let checker = CloudflareChecker::new();

        // Cloudflare IPs
        assert!(checker.is_cloudflare_ip("104.22.17.139".parse().unwrap()));
        assert!(checker.is_cloudflare_ip("172.69.23.127".parse().unwrap()));
        assert!(checker.is_cloudflare_ip("162.158.167.73".parse().unwrap()));

        // Non-Cloudflare IPs
        assert!(!checker.is_cloudflare_ip("192.168.1.1".parse().unwrap()));
        assert!(!checker.is_cloudflare_ip("8.8.8.8".parse().unwrap()));
        assert!(!checker.is_cloudflare_ip("185.16.39.146".parse().unwrap()));
    }

    #[test]
    fn test_xff_extraction() {
        let checker = CloudflareChecker::new();

        // Simple XFF
        assert_eq!(
            checker.extract_real_ip("203.0.113.50"),
            Some("203.0.113.50".parse().unwrap())
        );

        // XFF with Cloudflare proxy
        assert_eq!(
            checker.extract_real_ip("203.0.113.50, 172.69.23.127"),
            Some("203.0.113.50".parse().unwrap())
        );

        // Multiple proxies
        assert_eq!(
            checker.extract_real_ip("198.51.100.1, 10.0.0.1, 172.69.23.127"),
            Some("198.51.100.1".parse().unwrap())
        );
    }

    #[test]
    fn test_parse_nginx_log() {
        let checker = CloudflareChecker::new();

        // Standard combined format
        let line = r#"185.16.39.146 - - [28/Dec/2025:00:01:37 +0000] "GET / HTTP/1.1" 200 615 "-" "Wget""#;
        let entry = parse_nginx_log(line, &checker).unwrap();

        assert_eq!(entry.proxy_ip.to_string(), "185.16.39.146");
        assert!(!entry.is_cloudflare);
        assert_eq!(entry.request, "GET / HTTP/1.1");
        assert_eq!(entry.status, 200);

        // Cloudflare proxied request
        let line = r#"172.69.23.127 - - [28/Dec/2025:00:02:42 +0000] "GET /test HTTP/1.1" 404 187 "-" "Mozilla/5.0""#;
        let entry = parse_nginx_log(line, &checker).unwrap();

        assert!(entry.is_cloudflare);
        assert_eq!(entry.effective_ip().to_string(), "172.69.23.127"); // No XFF available
    }
}
