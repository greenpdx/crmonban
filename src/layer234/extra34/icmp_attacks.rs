//! ICMP Attack Detection
//!
//! Detects malicious ICMP traffic:
//! - ICMP Redirect (Type 5): Route manipulation attacks
//! - ICMP Source Quench (Type 4): Deprecated, attack vector
//! - ICMP Rate-based attacks: Floods of specific types

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::layer234::ThreatType;

/// ICMP type codes
pub mod icmp_types {
    pub const ECHO_REPLY: u8 = 0;
    pub const DESTINATION_UNREACHABLE: u8 = 3;
    pub const SOURCE_QUENCH: u8 = 4;
    pub const REDIRECT: u8 = 5;
    pub const ECHO_REQUEST: u8 = 8;
    pub const TIME_EXCEEDED: u8 = 11;
    pub const PARAMETER_PROBLEM: u8 = 12;
    pub const TIMESTAMP_REQUEST: u8 = 13;
    pub const TIMESTAMP_REPLY: u8 = 14;
    pub const ADDRESS_MASK_REQUEST: u8 = 17;
    pub const ADDRESS_MASK_REPLY: u8 = 18;
}

/// ICMP Redirect codes
pub mod redirect_codes {
    pub const NETWORK: u8 = 0;
    pub const HOST: u8 = 1;
    pub const TOS_NETWORK: u8 = 2;
    pub const TOS_HOST: u8 = 3;
}

/// Statistics window for rate-based detection
#[derive(Debug, Clone)]
struct RateWindow {
    /// Counts per type
    counts: HashMap<u8, u64>,
    /// Window start time
    window_start: Instant,
    /// Window duration
    window_duration: Duration,
}

impl RateWindow {
    fn new(duration: Duration) -> Self {
        Self {
            counts: HashMap::new(),
            window_start: Instant::now(),
            window_duration: duration,
        }
    }

    fn increment(&mut self, icmp_type: u8) {
        // Reset if window expired
        if self.window_start.elapsed() > self.window_duration {
            self.counts.clear();
            self.window_start = Instant::now();
        }
        *self.counts.entry(icmp_type).or_insert(0) += 1;
    }

    fn get_rate(&self, icmp_type: u8) -> f32 {
        let elapsed = self.window_start.elapsed().as_secs_f32().max(0.1);
        let count = self.counts.get(&icmp_type).copied().unwrap_or(0);
        count as f32 / elapsed
    }
}

/// ICMP Attack Detector
#[derive(Debug)]
pub struct IcmpAttackDetector {
    /// Rate tracking per source IP
    rate_windows: HashMap<IpAddr, RateWindow>,
    /// Global rate tracking
    global_rates: RateWindow,
    /// Statistics
    stats: IcmpStats,
    /// Detection thresholds
    config: IcmpDetectionConfig,
    /// Last cleanup time
    last_cleanup: Instant,
}

#[derive(Debug, Clone)]
pub struct IcmpDetectionConfig {
    /// Threshold for redirect rate (per second)
    pub redirect_rate_threshold: f32,
    /// Threshold for source quench rate (per second)
    pub source_quench_threshold: f32,
    /// Threshold for unreachable rate (per second)
    pub unreachable_threshold: f32,
    /// Threshold for TTL exceeded rate (per second)
    pub ttl_exceeded_threshold: f32,
    /// Window duration for rate calculation
    pub rate_window_secs: u64,
    /// Maximum tracked sources
    pub max_tracked_sources: usize,
}

impl Default for IcmpDetectionConfig {
    fn default() -> Self {
        Self {
            redirect_rate_threshold: 5.0,      // 5 redirects/sec is suspicious
            source_quench_threshold: 1.0,      // Source quench is deprecated, any is suspicious
            unreachable_threshold: 100.0,      // High rate of unreachables
            ttl_exceeded_threshold: 50.0,      // High rate of TTL exceeded
            rate_window_secs: 10,
            max_tracked_sources: 10000,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct IcmpStats {
    pub total_icmp: u64,
    pub redirects_detected: u64,
    pub source_quench_detected: u64,
    pub redirect_floods: u64,
    pub unreachable_floods: u64,
    pub ttl_exceeded_floods: u64,
}

impl Default for IcmpAttackDetector {
    fn default() -> Self {
        Self::new(IcmpDetectionConfig::default())
    }
}

impl IcmpAttackDetector {
    pub fn new(config: IcmpDetectionConfig) -> Self {
        let window = Duration::from_secs(config.rate_window_secs);
        Self {
            rate_windows: HashMap::new(),
            global_rates: RateWindow::new(window),
            stats: IcmpStats::default(),
            config,
            last_cleanup: Instant::now(),
        }
    }

    /// Process an ICMP packet and detect attacks
    pub fn process_icmp(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        icmp_type: u8,
        code: u8,
        payload: &[u8],
    ) -> Vec<ThreatType> {
        let mut threats = Vec::new();
        self.stats.total_icmp += 1;

        // Periodic cleanup
        if self.last_cleanup.elapsed() > Duration::from_secs(60) {
            self.cleanup_old_entries();
            self.last_cleanup = Instant::now();
        }

        // Update rate tracking
        let window = Duration::from_secs(self.config.rate_window_secs);
        {
            let source_window = self.rate_windows
                .entry(src_ip)
                .or_insert_with(|| RateWindow::new(window));
            source_window.increment(icmp_type);
        }
        self.global_rates.increment(icmp_type);

        // Check for specific attack types
        match icmp_type {
            icmp_types::REDIRECT => {
                self.stats.redirects_detected += 1;

                // Extract gateway and target from redirect payload
                let (gateway, target) = self.parse_redirect_payload(payload, src_ip);

                // ICMP redirect is always suspicious in most networks
                threats.push(ThreatType::IcmpRedirect { gateway, target });

                // Check for redirect flood
                if let Some(source_window) = self.rate_windows.get(&src_ip) {
                    if source_window.get_rate(icmp_types::REDIRECT) > self.config.redirect_rate_threshold {
                        self.stats.redirect_floods += 1;
                    }
                }
            }

            icmp_types::SOURCE_QUENCH => {
                self.stats.source_quench_detected += 1;

                // Source quench is deprecated (RFC 6633) and should not be seen
                threats.push(ThreatType::IcmpSourceQuench {
                    target: dst_ip.to_string(),
                });
            }

            icmp_types::DESTINATION_UNREACHABLE => {
                // Check for unreachable flood (potential scanning/DoS indicator)
                if let Some(source_window) = self.rate_windows.get(&src_ip) {
                    let rate = source_window.get_rate(icmp_types::DESTINATION_UNREACHABLE);
                    if rate > self.config.unreachable_threshold {
                        self.stats.unreachable_floods += 1;
                        // Note: This could be a scan response flood
                    }
                }
            }

            icmp_types::TIME_EXCEEDED => {
                // Check for TTL exceeded flood (potential traceroute flood or attack)
                if let Some(source_window) = self.rate_windows.get(&src_ip) {
                    let rate = source_window.get_rate(icmp_types::TIME_EXCEEDED);
                    if rate > self.config.ttl_exceeded_threshold {
                        self.stats.ttl_exceeded_floods += 1;
                    }
                }
            }

            _ => {}
        }

        // Limit tracked sources
        if self.rate_windows.len() > self.config.max_tracked_sources {
            self.cleanup_old_entries();
        }

        threats
    }

    /// Parse ICMP redirect payload to extract gateway and target
    fn parse_redirect_payload(&self, payload: &[u8], src_ip: IpAddr) -> (String, String) {
        // ICMP Redirect format:
        // - 4 bytes: gateway address (the new router to use)
        // - 20+ bytes: original IP header + first 8 bytes of original datagram

        if payload.len() >= 4 {
            let gateway = format!("{}.{}.{}.{}", payload[0], payload[1], payload[2], payload[3]);

            // Try to extract target from embedded IP header
            if payload.len() >= 24 {
                // Destination from embedded IP header (bytes 16-19 of embedded header, at offset 4+16)
                let target = format!(
                    "{}.{}.{}.{}",
                    payload[20], payload[21], payload[22], payload[23]
                );
                return (gateway, target);
            }

            return (gateway, "unknown".to_string());
        }

        (src_ip.to_string(), "unknown".to_string())
    }

    /// Get statistics
    pub fn stats(&self) -> &IcmpStats {
        &self.stats
    }

    /// Get feature vector values
    pub fn get_features(&self) -> [f32; 4] {
        let total = self.stats.total_icmp.max(1) as f32;

        [
            // ICMP_REDIRECT_RATE
            self.global_rates.get_rate(icmp_types::REDIRECT),
            // ICMP_QUENCH_RATE
            self.global_rates.get_rate(icmp_types::SOURCE_QUENCH),
            // ICMP_UNREACHABLE_RATE
            self.global_rates.get_rate(icmp_types::DESTINATION_UNREACHABLE),
            // ICMP_TTL_EXCEEDED_RATE
            self.global_rates.get_rate(icmp_types::TIME_EXCEEDED),
        ]
    }

    /// Clean up old entries
    fn cleanup_old_entries(&mut self) {
        let cutoff = Duration::from_secs(self.config.rate_window_secs * 2);
        self.rate_windows.retain(|_, window| {
            window.window_start.elapsed() < cutoff
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_icmp_redirect_detection() {
        let mut detector = IcmpAttackDetector::default();
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Redirect payload: gateway (4 bytes) + embedded IP header
        let payload = [
            192, 168, 1, 254,  // Gateway
            0x45, 0x00, 0x00, 0x28, // IP header version/ihl, tos, length
            0x00, 0x01, 0x00, 0x00, // id, flags/offset
            0x40, 0x06, 0x00, 0x00, // ttl, proto (TCP), checksum
            192, 168, 1, 1,         // Source IP
            10, 0, 0, 100,          // Destination IP (target)
        ];

        let threats = detector.process_icmp(src, dst, icmp_types::REDIRECT, 0, &payload);
        assert!(threats.iter().any(|t| matches!(t, ThreatType::IcmpRedirect { .. })));
    }

    #[test]
    fn test_source_quench_detection() {
        let mut detector = IcmpAttackDetector::default();
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let threats = detector.process_icmp(src, dst, icmp_types::SOURCE_QUENCH, 0, &[]);
        assert!(threats.iter().any(|t| matches!(t, ThreatType::IcmpSourceQuench { .. })));
    }

    #[test]
    fn test_normal_icmp_ok() {
        let mut detector = IcmpAttackDetector::default();
        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Echo request should not trigger threats
        let threats = detector.process_icmp(src, dst, icmp_types::ECHO_REQUEST, 0, &[]);
        assert!(threats.is_empty());

        // Echo reply should not trigger threats
        let threats = detector.process_icmp(src, dst, icmp_types::ECHO_REPLY, 0, &[]);
        assert!(threats.is_empty());
    }
}
