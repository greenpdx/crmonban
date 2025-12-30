//! State trackers for Layer 2-3 attack detection
//!
//! Maintains state for detecting ARP spoofing, DHCP attacks, and IPv6 RA spoofing.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use super::protocols::{ArpPacket, ArpOp, DhcpPacket, DhcpMessageType, Icmpv6Ra};

// ============================================================================
// ARP State Tracker
// ============================================================================

/// MAC-IP binding with history
#[derive(Debug, Clone)]
struct MacBinding {
    mac: [u8; 6],
    first_seen: Instant,
    last_seen: Instant,
    change_count: u32,
    previous_macs: Vec<[u8; 6]>,  // History of previous MACs for this IP
}

/// Result of ARP spoofing check
#[derive(Debug, Clone)]
pub struct ArpSpoofingAlert {
    pub ip: Ipv4Addr,
    pub original_mac: [u8; 6],
    pub new_mac: [u8; 6],
    pub change_count: u32,
}

/// ARP state tracker for detecting spoofing attacks
#[derive(Debug)]
pub struct ArpStateTracker {
    /// Known MAC-IP bindings (learned from traffic)
    bindings: HashMap<Ipv4Addr, MacBinding>,
    /// Gratuitous ARP counter per source MAC
    gratuitous_count: HashMap<[u8; 6], (u32, Instant)>,
    /// IPs claimed by each MAC (for detecting one MAC claiming multiple IPs)
    mac_to_ips: HashMap<[u8; 6], HashSet<Ipv4Addr>>,
    /// Configured static bindings (won't trigger alerts)
    static_bindings: HashMap<Ipv4Addr, [u8; 6]>,
    /// Time window for counting gratuitous ARPs
    window_duration: Duration,
    /// Threshold for MAC changes before alerting
    change_threshold: u32,
}

impl ArpStateTracker {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
            gratuitous_count: HashMap::new(),
            mac_to_ips: HashMap::new(),
            static_bindings: HashMap::new(),
            window_duration: Duration::from_secs(60),
            change_threshold: 2,
        }
    }

    /// Add a static MAC-IP binding (e.g., for gateways)
    pub fn add_static_binding(&mut self, ip: Ipv4Addr, mac: [u8; 6]) {
        self.static_bindings.insert(ip, mac);
    }

    /// Set the MAC change threshold
    pub fn set_change_threshold(&mut self, threshold: u32) {
        self.change_threshold = threshold;
    }

    /// Process an ARP packet and check for spoofing
    pub fn process_arp(&mut self, arp: &ArpPacket) -> Option<ArpSpoofingAlert> {
        let now = Instant::now();

        // Track gratuitous ARPs
        if arp.is_gratuitous() {
            let entry = self.gratuitous_count
                .entry(arp.sender_mac)
                .or_insert((0, now));

            // Reset counter if window expired
            if now.duration_since(entry.1) > self.window_duration {
                entry.0 = 0;
                entry.1 = now;
            }
            entry.0 += 1;
        }

        // Only track replies (they contain the actual IP-MAC mapping)
        if !matches!(arp.operation, ArpOp::Reply) {
            return None;
        }

        // Skip if this IP has a static binding
        if let Some(static_mac) = self.static_bindings.get(&arp.sender_ip) {
            if arp.sender_mac != *static_mac {
                // Someone is trying to spoof a statically configured IP!
                return Some(ArpSpoofingAlert {
                    ip: arp.sender_ip,
                    original_mac: *static_mac,
                    new_mac: arp.sender_mac,
                    change_count: 0,
                });
            }
            return None;
        }

        // Track MAC-to-IPs mapping
        self.mac_to_ips
            .entry(arp.sender_mac)
            .or_default()
            .insert(arp.sender_ip);

        // Check for MAC change
        if let Some(binding) = self.bindings.get_mut(&arp.sender_ip) {
            if binding.mac != arp.sender_mac {
                // MAC changed for this IP!
                let old_mac = binding.mac;
                binding.previous_macs.push(old_mac);
                binding.mac = arp.sender_mac;
                binding.change_count += 1;
                binding.last_seen = now;

                // Alert if threshold exceeded
                if binding.change_count >= self.change_threshold {
                    return Some(ArpSpoofingAlert {
                        ip: arp.sender_ip,
                        original_mac: old_mac,
                        new_mac: arp.sender_mac,
                        change_count: binding.change_count,
                    });
                }
            } else {
                binding.last_seen = now;
            }
        } else {
            // New binding
            self.bindings.insert(arp.sender_ip, MacBinding {
                mac: arp.sender_mac,
                first_seen: now,
                last_seen: now,
                change_count: 0,
                previous_macs: Vec::new(),
            });
        }

        None
    }

    /// Get gratuitous ARP count for a MAC in the current window
    pub fn gratuitous_arp_count(&self, mac: &[u8; 6]) -> u32 {
        self.gratuitous_count
            .get(mac)
            .map(|(count, _)| *count)
            .unwrap_or(0)
    }

    /// Get number of unique IPs claimed by a MAC
    pub fn ips_claimed_by_mac(&self, mac: &[u8; 6]) -> usize {
        self.mac_to_ips
            .get(mac)
            .map(|ips| ips.len())
            .unwrap_or(0)
    }

    /// Clean up old entries
    pub fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();

        self.bindings.retain(|_, binding| {
            now.duration_since(binding.last_seen) < max_age
        });

        self.gratuitous_count.retain(|_, (_, time)| {
            now.duration_since(*time) < max_age
        });
    }

    /// Get current stats
    pub fn stats(&self) -> ArpStats {
        ArpStats {
            total_bindings: self.bindings.len(),
            static_bindings: self.static_bindings.len(),
            active_macs: self.mac_to_ips.len(),
        }
    }
}

impl Default for ArpStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct ArpStats {
    pub total_bindings: usize,
    pub static_bindings: usize,
    pub active_macs: usize,
}

// ============================================================================
// DHCP State Tracker
// ============================================================================

/// DHCP client state
#[derive(Debug, Clone)]
struct DhcpClientState {
    first_seen: Instant,
    last_seen: Instant,
    request_count: u32,
    offered_ips: Vec<Ipv4Addr>,
}

/// Result of DHCP starvation check
#[derive(Debug, Clone)]
pub struct DhcpStarvationAlert {
    pub unique_macs: u32,
    pub requests_in_window: u32,
    pub window_seconds: u64,
}

/// Result of rogue DHCP check
#[derive(Debug, Clone)]
pub struct RogueDhcpAlert {
    pub server_ip: Ipv4Addr,
    pub offers_count: u32,
}

/// DHCP state tracker for detecting starvation and rogue servers
#[derive(Debug)]
pub struct DhcpStateTracker {
    /// Known legitimate DHCP servers
    known_servers: HashSet<Ipv4Addr>,
    /// Client MAC tracking
    clients: HashMap<[u8; 6], DhcpClientState>,
    /// DHCP offers by server IP
    offers_by_server: HashMap<Ipv4Addr, (u32, Instant)>,
    /// All unique client MACs seen in window
    unique_macs_in_window: HashSet<[u8; 6]>,
    /// Window start time
    window_start: Instant,
    /// Window duration
    window_duration: Duration,
    /// Thresholds
    starvation_mac_threshold: u32,
}

impl DhcpStateTracker {
    pub fn new() -> Self {
        Self {
            known_servers: HashSet::new(),
            clients: HashMap::new(),
            offers_by_server: HashMap::new(),
            unique_macs_in_window: HashSet::new(),
            window_start: Instant::now(),
            window_duration: Duration::from_secs(60),
            starvation_mac_threshold: 50,
        }
    }

    /// Add a known DHCP server
    pub fn add_known_server(&mut self, ip: Ipv4Addr) {
        self.known_servers.insert(ip);
    }

    /// Set starvation detection threshold
    pub fn set_starvation_threshold(&mut self, threshold: u32) {
        self.starvation_mac_threshold = threshold;
    }

    /// Process a DHCP packet
    pub fn process_dhcp(&mut self, dhcp: &DhcpPacket, src_ip: Ipv4Addr)
        -> (Option<DhcpStarvationAlert>, Option<RogueDhcpAlert>)
    {
        let now = Instant::now();

        // Reset window if needed
        if now.duration_since(self.window_start) > self.window_duration {
            self.unique_macs_in_window.clear();
            self.window_start = now;
        }

        let mut starvation_alert = None;
        let mut rogue_alert = None;

        match dhcp.message_type {
            DhcpMessageType::Discover | DhcpMessageType::Request => {
                // Track client
                self.unique_macs_in_window.insert(dhcp.client_mac);

                let client = self.clients
                    .entry(dhcp.client_mac)
                    .or_insert(DhcpClientState {
                        first_seen: now,
                        last_seen: now,
                        request_count: 0,
                        offered_ips: Vec::new(),
                    });
                client.last_seen = now;
                client.request_count += 1;

                // Check for starvation attack
                let unique_macs = self.unique_macs_in_window.len() as u32;
                if unique_macs >= self.starvation_mac_threshold {
                    starvation_alert = Some(DhcpStarvationAlert {
                        unique_macs,
                        requests_in_window: self.clients.values()
                            .map(|c| c.request_count)
                            .sum(),
                        window_seconds: self.window_duration.as_secs(),
                    });
                }
            }
            DhcpMessageType::Offer | DhcpMessageType::Ack => {
                // Track server
                let server_ip = dhcp.server_identifier.unwrap_or(src_ip);

                let entry = self.offers_by_server
                    .entry(server_ip)
                    .or_insert((0, now));

                // Reset if window expired
                if now.duration_since(entry.1) > self.window_duration {
                    entry.0 = 0;
                    entry.1 = now;
                }
                entry.0 += 1;

                // Check for rogue server
                if !self.known_servers.is_empty() && !self.known_servers.contains(&server_ip) {
                    rogue_alert = Some(RogueDhcpAlert {
                        server_ip,
                        offers_count: entry.0,
                    });
                }
            }
            _ => {}
        }

        (starvation_alert, rogue_alert)
    }

    /// Check if a server is known
    pub fn is_known_server(&self, ip: &Ipv4Addr) -> bool {
        self.known_servers.contains(ip)
    }

    /// Get number of unique client MACs in current window
    pub fn unique_clients_in_window(&self) -> usize {
        self.unique_macs_in_window.len()
    }

    /// Get number of unique DHCP servers seen
    pub fn unique_servers(&self) -> usize {
        self.offers_by_server.len()
    }

    /// Clean up old entries
    pub fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();

        self.clients.retain(|_, client| {
            now.duration_since(client.last_seen) < max_age
        });

        self.offers_by_server.retain(|_, (_, time)| {
            now.duration_since(*time) < max_age
        });
    }
}

impl Default for DhcpStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// IPv6 RA State Tracker
// ============================================================================

/// Router information
#[derive(Debug, Clone)]
struct RouterInfo {
    mac: Option<[u8; 6]>,
    first_seen: Instant,
    last_seen: Instant,
    ra_count: u32,
    prefixes: Vec<Ipv6Prefix>,
    is_known: bool,  // Configured as trusted
}

use super::protocols::Ipv6Prefix;

/// Result of RA spoofing check
#[derive(Debug, Clone)]
pub struct RaSpoofingAlert {
    pub src_ip: Ipv6Addr,
    pub src_mac: Option<[u8; 6]>,
    pub router_lifetime: u16,
}

/// Result of RA flood check
#[derive(Debug, Clone)]
pub struct RaFloodAlert {
    pub unique_routers: u32,
    pub ra_per_sec: f32,
}

/// IPv6 Router Advertisement state tracker
#[derive(Debug)]
pub struct RaStateTracker {
    /// Known routers
    routers: HashMap<Ipv6Addr, RouterInfo>,
    /// Configured trusted routers
    trusted_routers: HashSet<Ipv6Addr>,
    /// RA count in current window
    ra_count_window: u32,
    /// Window start time
    window_start: Instant,
    /// Window duration
    window_duration: Duration,
    /// RA flood threshold (per window)
    flood_threshold: u32,
}

impl RaStateTracker {
    pub fn new() -> Self {
        Self {
            routers: HashMap::new(),
            trusted_routers: HashSet::new(),
            ra_count_window: 0,
            window_start: Instant::now(),
            window_duration: Duration::from_secs(60),
            flood_threshold: 10,
        }
    }

    /// Add a trusted router
    pub fn add_trusted_router(&mut self, ip: Ipv6Addr) {
        self.trusted_routers.insert(ip);
    }

    /// Set flood detection threshold
    pub fn set_flood_threshold(&mut self, threshold: u32) {
        self.flood_threshold = threshold;
    }

    /// Process a Router Advertisement
    pub fn process_ra(&mut self, ra: &Icmpv6Ra, src_ip: Ipv6Addr)
        -> (Option<RaSpoofingAlert>, Option<RaFloodAlert>)
    {
        let now = Instant::now();

        // Reset window if needed
        if now.duration_since(self.window_start) > self.window_duration {
            self.ra_count_window = 0;
            self.window_start = now;
        }

        self.ra_count_window += 1;

        let mut spoof_alert = None;
        let mut flood_alert = None;

        // Track router
        let router = self.routers
            .entry(src_ip)
            .or_insert(RouterInfo {
                mac: ra.source_link_addr,
                first_seen: now,
                last_seen: now,
                ra_count: 0,
                prefixes: Vec::new(),
                is_known: self.trusted_routers.contains(&src_ip),
            });
        router.last_seen = now;
        router.ra_count += 1;
        router.prefixes = ra.prefixes.clone();
        if router.mac.is_none() {
            router.mac = ra.source_link_addr;
        }

        // Check for spoofing (unknown router)
        if !self.trusted_routers.is_empty() && !self.trusted_routers.contains(&src_ip) {
            spoof_alert = Some(RaSpoofingAlert {
                src_ip,
                src_mac: ra.source_link_addr,
                router_lifetime: ra.router_lifetime,
            });
        }

        // Check for flood
        let unique_routers = self.routers.len() as u32;
        if self.ra_count_window >= self.flood_threshold {
            let elapsed = now.duration_since(self.window_start).as_secs_f32();
            let ra_per_sec = if elapsed > 0.0 {
                self.ra_count_window as f32 / elapsed
            } else {
                self.ra_count_window as f32
            };

            flood_alert = Some(RaFloodAlert {
                unique_routers,
                ra_per_sec,
            });
        }

        (spoof_alert, flood_alert)
    }

    /// Check if a router is known/trusted
    pub fn is_known_router(&self, ip: &Ipv6Addr) -> bool {
        self.trusted_routers.contains(ip)
    }

    /// Get number of unique routers seen
    pub fn unique_routers(&self) -> usize {
        self.routers.len()
    }

    /// Clean up old entries
    pub fn cleanup(&mut self, max_age: Duration) {
        let now = Instant::now();

        self.routers.retain(|_, router| {
            now.duration_since(router.last_seen) < max_age
        });
    }
}

impl Default for RaStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_spoofing_detection() {
        let mut tracker = ArpStateTracker::new();
        tracker.set_change_threshold(1);  // Alert on first change

        // First ARP reply
        let arp1 = ArpPacket {
            operation: ArpOp::Reply,
            sender_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            sender_ip: Ipv4Addr::new(192, 168, 1, 1),
            target_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            target_ip: Ipv4Addr::new(192, 168, 1, 100),
        };
        assert!(tracker.process_arp(&arp1).is_none());

        // Different MAC for same IP - spoofing!
        let arp2 = ArpPacket {
            operation: ArpOp::Reply,
            sender_mac: [0x11, 0x11, 0x11, 0x11, 0x11, 0x11],  // Different MAC
            sender_ip: Ipv4Addr::new(192, 168, 1, 1),         // Same IP
            target_mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            target_ip: Ipv4Addr::new(192, 168, 1, 100),
        };
        let alert = tracker.process_arp(&arp2);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.ip, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_static_binding_protection() {
        let mut tracker = ArpStateTracker::new();

        // Configure static binding for gateway
        let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
        let gateway_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        tracker.add_static_binding(gateway_ip, gateway_mac);

        // Someone tries to spoof the gateway
        let spoof_arp = ArpPacket {
            operation: ArpOp::Reply,
            sender_mac: [0x11, 0x11, 0x11, 0x11, 0x11, 0x11],  // Attacker MAC
            sender_ip: gateway_ip,                              // Gateway IP
            target_mac: [0x00; 6],
            target_ip: Ipv4Addr::new(192, 168, 1, 100),
        };

        let alert = tracker.process_arp(&spoof_arp);
        assert!(alert.is_some());  // Should alert immediately
    }

    #[test]
    fn test_dhcp_starvation_detection() {
        let mut tracker = DhcpStateTracker::new();
        tracker.set_starvation_threshold(3);  // Low threshold for testing

        // Simulate multiple unique MACs requesting IPs
        for i in 0..5 {
            let dhcp = DhcpPacket {
                op: 1,
                message_type: DhcpMessageType::Discover,
                client_mac: [0x00, 0x00, 0x00, 0x00, 0x00, i as u8],
                client_ip: Ipv4Addr::UNSPECIFIED,
                your_ip: Ipv4Addr::UNSPECIFIED,
                server_ip: Ipv4Addr::UNSPECIFIED,
                transaction_id: i as u32,
                server_identifier: None,
                requested_ip: None,
            };

            let (starvation, _) = tracker.process_dhcp(&dhcp, Ipv4Addr::UNSPECIFIED);

            if i >= 3 {
                assert!(starvation.is_some(), "Should detect starvation at {} MACs", i);
            }
        }
    }

    #[test]
    fn test_rogue_dhcp_detection() {
        let mut tracker = DhcpStateTracker::new();
        tracker.add_known_server(Ipv4Addr::new(192, 168, 1, 1));

        // Legitimate server offer
        let legitimate = DhcpPacket {
            op: 2,
            message_type: DhcpMessageType::Offer,
            client_mac: [0x11; 6],
            client_ip: Ipv4Addr::UNSPECIFIED,
            your_ip: Ipv4Addr::new(192, 168, 1, 100),
            server_ip: Ipv4Addr::new(192, 168, 1, 1),
            transaction_id: 1,
            server_identifier: Some(Ipv4Addr::new(192, 168, 1, 1)),
            requested_ip: None,
        };
        let (_, rogue) = tracker.process_dhcp(&legitimate, Ipv4Addr::new(192, 168, 1, 1));
        assert!(rogue.is_none());

        // Rogue server offer
        let rogue_offer = DhcpPacket {
            op: 2,
            message_type: DhcpMessageType::Offer,
            client_mac: [0x11; 6],
            client_ip: Ipv4Addr::UNSPECIFIED,
            your_ip: Ipv4Addr::new(192, 168, 1, 101),
            server_ip: Ipv4Addr::new(192, 168, 1, 254),  // Unknown server!
            transaction_id: 1,
            server_identifier: Some(Ipv4Addr::new(192, 168, 1, 254)),
            requested_ip: None,
        };
        let (_, rogue) = tracker.process_dhcp(&rogue_offer, Ipv4Addr::new(192, 168, 1, 254));
        assert!(rogue.is_some());
    }
}
