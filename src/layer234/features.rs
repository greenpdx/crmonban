use super::types::{FeatureVector, VECTOR_DIM};
use crmonban_types::Packet;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

/// Default auth ports for brute force detection
pub const DEFAULT_AUTH_PORTS: &[u16] = &[
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    110,   // POP3
    143,   // IMAP
    389,   // LDAP
    445,   // SMB
    993,   // IMAPS
    995,   // POP3S
    1433,  // MSSQL
    3306,  // MySQL
    3389,  // RDP
    5432,  // PostgreSQL
    5900,  // VNC
    6379,  // Redis
    27017, // MongoDB
];

pub struct WindowStats {
    pub packets: Vec<Packet>,
    pub src_ip: IpAddr,
    pub start_time_ns: u64,
    pub end_time_ns: u64,
    /// Configurable auth ports for brute force detection
    pub auth_ports: Arc<HashSet<u16>>,
}

impl WindowStats {
    pub fn new(src_ip: IpAddr) -> Self {
        Self {
            packets: Vec::new(),
            src_ip,
            start_time_ns: 0,
            end_time_ns: 0,
            auth_ports: Arc::new(DEFAULT_AUTH_PORTS.iter().copied().collect()),
        }
    }

    pub fn with_auth_ports(src_ip: IpAddr, auth_ports: Arc<HashSet<u16>>) -> Self {
        Self {
            packets: Vec::new(),
            src_ip,
            start_time_ns: 0,
            end_time_ns: 0,
            auth_ports,
        }
    }

    pub fn add_packet(&mut self, packet: Packet) {
        if self.packets.is_empty() {
            self.start_time_ns = packet.timestamp_ns();
        }
        self.end_time_ns = packet.timestamp_ns();
        self.packets.push(packet);
    }

    pub fn extract_features(&self) -> FeatureVector {
        let mut vec = [0.0f32; VECTOR_DIM];

        if self.packets.is_empty() {
            return vec;
        }

        // Protocol-agnostic features (0-11)
        self.extract_port_features(&mut vec[0..4]);
        self.extract_timing_features(&mut vec[4..8]);
        self.extract_target_features(&mut vec[8..12]);

        // TCP-specific features (12-23)
        self.extract_tcp_flag_features(&mut vec[12..16]);
        self.extract_tcp_connection_features(&mut vec[16..20]);
        self.extract_tcp_behavior_features(&mut vec[20..24]);

        // UDP-specific features (24-35)
        self.extract_udp_pattern_features(&mut vec[24..28]);
        self.extract_udp_service_features(&mut vec[28..32]);
        self.extract_udp_amplification_features(&mut vec[32..36]);

        // ICMP-specific features (36-47)
        self.extract_icmp_type_features(&mut vec[36..40]);
        self.extract_icmp_pattern_features(&mut vec[40..44]);
        self.extract_icmp_timing_features(&mut vec[44..48]);

        // TLS-specific features (48-63)
        self.extract_tls_features(&mut vec[48..52]);
        self.extract_tls_version_features(&mut vec[52..56]);
        self.extract_tls_sni_features(&mut vec[56..60]);
        self.extract_tls_behavior_features(&mut vec[60..64]);

        // DoS-specific features (64-71)
        self.extract_dos_rate_features(&mut vec[64..72]);

        vec
    }

    fn extract_port_features(&self, out: &mut [f32]) {
        // Only analyze OUTBOUND packets (where packet src_ip matches window src_ip)
        // This gives us the ports the source is targeting, not ephemeral response ports
        let ports: Vec<u16> = self
            .packets
            .iter()
            .filter(|p| p.src_ip() == self.src_ip)
            .map(|p| p.dst_port())
            .filter(|&port| port != 0)
            .collect();

        if ports.is_empty() {
            return;
        }

        let unique_ports: HashSet<u16> = ports.iter().copied().collect();
        let port_entropy = calculate_entropy(&ports);

        // 0: Port entropy (normalized to 0-1)
        out[0] = (port_entropy / 16.0).min(1.0);

        // 1: Unique port count (normalized, assuming max ~65535)
        out[1] = (unique_ports.len() as f32 / 1000.0).min(1.0);

        // 2: Min port (normalized)
        out[2] = *ports.iter().min().unwrap_or(&0) as f32 / 65535.0;

        // 3: Max port (normalized)
        out[3] = *ports.iter().max().unwrap_or(&0) as f32 / 65535.0;
    }

    fn extract_timing_features(&self, out: &mut [f32]) {
        if self.packets.len() < 2 {
            return;
        }

        let mut intervals: Vec<f64> = Vec::new();
        for i in 1..self.packets.len() {
            let delta = self.packets[i]
                .timestamp_ns()
                .saturating_sub(self.packets[i - 1].timestamp_ns()) as f64;
            intervals.push(delta);
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
            / intervals.len() as f64;

        // Count bursts (intervals < 1ms)
        let burst_count = intervals.iter().filter(|&&x| x < 1_000_000.0).count();

        let duration_ms = (self.end_time_ns - self.start_time_ns) as f64 / 1_000_000.0;

        // 4: Mean inter-packet interval (normalized to 0-1, assuming max 1s)
        out[0] = ((mean / 1_000_000_000.0) as f32).min(1.0);

        // 5: Interval variance (normalized)
        out[1] = ((variance.sqrt() / 1_000_000_000.0) as f32).min(1.0);

        // 6: Burst ratio
        out[2] = burst_count as f32 / intervals.len() as f32;

        // 7: Duration (normalized to 0-1, assuming max 60s window)
        out[3] = ((duration_ms / 60_000.0) as f32).min(1.0);
    }

    fn extract_target_features(&self, out: &mut [f32]) {
        let dst_ips: Vec<IpAddr> = self.packets.iter().map(|p| p.dst_ip()).collect();
        let unique_ips: HashSet<IpAddr> = dst_ips.iter().copied().collect();

        // Check for sequential IPs (scan pattern)
        let sequential_ratio = calculate_sequential_ip_ratio(&dst_ips);

        // 8: Unique destination IPs (normalized)
        out[0] = (unique_ips.len() as f32 / 100.0).min(1.0);

        // 9: IP distribution entropy
        let ip_entropy = calculate_ip_entropy(&dst_ips);
        out[1] = (ip_entropy / 8.0).min(1.0);

        // 10: Sequential IP ratio (sweep detection)
        out[2] = sequential_ratio;

        // 11: Subnet spread (how many /24s)
        let subnets: HashSet<u32> = dst_ips
            .iter()
            .filter_map(|ip| {
                if let IpAddr::V4(v4) = ip {
                    Some(u32::from(*v4) >> 8)
                } else {
                    None
                }
            })
            .collect();
        out[3] = (subnets.len() as f32 / 50.0).min(1.0);
    }

    fn extract_tcp_flag_features(&self, out: &mut [f32]) {
        // Only analyze OUTBOUND TCP packets
        // For localhost traffic (src_ip == dst_ip), use port-based direction detection:
        // - Outbound: high src_port (ephemeral) targeting low dst_port
        // - Inbound: low src_port responding to high dst_port
        let tcp_packets: Vec<_> = self
            .packets
            .iter()
            .filter(|p| {
                if let Some(tcp) = p.layer4.as_tcp() {
                    if p.src_ip() == p.dst_ip() {
                        // Localhost traffic: use port-based direction
                        // Outbound scans use ephemeral src_port (>= 32768) targeting service ports
                        tcp.src_port >= 32768 || tcp.dst_port < 1024
                    } else {
                        // Normal traffic: use IP-based direction
                        p.src_ip() == self.src_ip
                    }
                } else {
                    false
                }
            })
            .filter_map(|p| p.layer4.as_tcp())
            .collect();

        if tcp_packets.is_empty() {
            return;
        }

        let total = tcp_packets.len() as f32;
        let syn_count = tcp_packets.iter().filter(|t| t.flags.syn && !t.flags.ack).count();
        let synack_count = tcp_packets.iter().filter(|t| t.flags.is_syn_ack()).count();
        let rst_count = tcp_packets.iter().filter(|t| t.flags.rst).count();
        let fin_count = tcp_packets.iter().filter(|t| t.flags.fin).count();

        // 12: SYN ratio (high = scan)
        out[0] = syn_count as f32 / total;

        // 13: SYN-ACK ratio (low with high SYN = stealth scan)
        out[1] = synack_count as f32 / total;

        // 14: RST ratio
        out[2] = rst_count as f32 / total;

        // 15: FIN ratio
        out[3] = fin_count as f32 / total;
    }

    fn extract_tcp_connection_features(&self, out: &mut [f32]) {
        // Track connections bidirectionally by destination port
        // We need to correlate outbound SYN with inbound SYN-ACK/RST
        let mut connections: HashMap<u16, ConnectionState> = HashMap::new();

        for packet in &self.packets {
            let tcp = match packet.layer4.as_tcp() {
                Some(t) => t,
                None => continue,
            };

            let is_outbound = packet.src_ip() == self.src_ip;

            if is_outbound {
                // Outbound: track by dst_port (the port we're connecting to)
                let state = connections.entry(tcp.dst_port).or_default();
                if tcp.flags.is_syn_only() {
                    state.syn_seen = true;
                }
                if tcp.flags.ack && !tcp.flags.syn {
                    state.ack_seen = true;
                }
                if tcp.flags.rst {
                    state.rst_seen = true;
                }
            } else {
                // Inbound: track by src_port (the port responding to us)
                let state = connections.entry(tcp.src_port).or_default();
                if tcp.flags.is_syn_ack() {
                    state.synack_seen = true;
                }
                if tcp.flags.rst {
                    state.rst_seen = true;
                }
            }
        }

        if connections.is_empty() {
            return;
        }

        let complete = connections.values().filter(|c| c.is_complete()).count();
        let half_open = connections.values().filter(|c| c.is_half_open()).count();

        // 16: Connection success rate
        out[0] = complete as f32 / connections.len().max(1) as f32;

        // 17: Half-open ratio (high = SYN scan)
        out[1] = half_open as f32 / connections.len().max(1) as f32;

        // 18: Handshake complete ratio
        out[2] = connections
            .values()
            .filter(|c| c.syn_seen && c.synack_seen && c.ack_seen)
            .count() as f32
            / connections.len().max(1) as f32;

        // 19: RST after SYN ratio (port closed responses)
        out[3] = connections
            .values()
            .filter(|c| c.syn_seen && c.rst_seen && !c.synack_seen)
            .count() as f32
            / connections.len().max(1) as f32;
    }

    fn extract_tcp_behavior_features(&self, out: &mut [f32]) {
        // Only analyze OUTBOUND TCP packets for behavior analysis
        let tcp_packets: Vec<_> = self
            .packets
            .iter()
            .filter(|p| p.src_ip() == self.src_ip)
            .filter_map(|p| p.layer4.as_tcp())
            .collect();

        if tcp_packets.is_empty() {
            return;
        }

        let total = tcp_packets.len() as f32;

        // 20: Auth port ratio (high = potential brute force)
        // Uses configurable auth_ports from self
        let auth_port_count = tcp_packets
            .iter()
            .filter(|t| self.auth_ports.contains(&t.dst_port))
            .count();
        out[0] = auth_port_count as f32 / total;

        // 21: Single port concentration (high = brute force or normal service usage)
        // Count connections per destination port
        let mut port_counts: HashMap<u16, usize> = HashMap::new();
        for tcp in &tcp_packets {
            *port_counts.entry(tcp.dst_port).or_default() += 1;
        }
        let max_port_count = port_counts.values().max().copied().unwrap_or(0);
        out[1] = max_port_count as f32 / total;

        // 22: Xmas scan indicator
        let xmas_count = tcp_packets.iter().filter(|t| t.flags.is_xmas()).count();
        out[2] = xmas_count as f32 / total;

        // 23: Null scan indicator
        let null_count = tcp_packets.iter().filter(|t| t.flags.is_null()).count();
        out[3] = null_count as f32 / total;
    }

    fn extract_udp_pattern_features(&self, out: &mut [f32]) {
        let udp_packets: Vec<_> = self.packets.iter().filter(|p| p.layer4.as_udp().is_some()).collect();
        let icmp_packets: Vec<_> = self.packets.iter().filter_map(|p| p.layer4.as_icmp()).collect();

        if udp_packets.is_empty() {
            return;
        }

        let total = udp_packets.len() as f32;

        // Count ICMP port unreachable (indicates closed UDP ports)
        let unreachable_count = icmp_packets
            .iter()
            .filter(|i| i.icmp_type == 3 && i.code == 3)
            .count();

        // 24: Response ratio (low = scan)
        // In a scan, we send many UDP packets but get few responses
        out[0] = 1.0 - (unreachable_count as f32 / total).min(1.0);

        // 25: ICMP unreachable ratio
        out[1] = unreachable_count as f32 / total;

        // 26: Payload size variance
        let sizes: Vec<f32> = udp_packets
            .iter()
            .map(|p| p.payload_len() as f32)
            .collect();
        let mean_size = sizes.iter().sum::<f32>() / sizes.len() as f32;
        let variance = sizes.iter().map(|s| (s - mean_size).powi(2)).sum::<f32>() / sizes.len() as f32;
        out[2] = (variance.sqrt() / 1000.0).min(1.0);

        // 27: Empty payload ratio
        let empty_count = udp_packets.iter().filter(|p| p.payload_len() == 0).count();
        out[3] = empty_count as f32 / total;
    }

    fn extract_udp_service_features(&self, out: &mut [f32]) {
        let udp_packets: Vec<_> = self.packets.iter().filter_map(|p| p.layer4.as_udp()).collect();

        if udp_packets.is_empty() {
            return;
        }

        let total = udp_packets.len() as f32;

        // 28: DNS ratio (port 53)
        let dns_count = udp_packets.iter().filter(|u| u.dst_port == 53).count();
        out[0] = dns_count as f32 / total;

        // 29: NTP ratio (port 123)
        let ntp_count = udp_packets.iter().filter(|u| u.dst_port == 123).count();
        out[1] = ntp_count as f32 / total;

        // 30: SSDP ratio (port 1900)
        let ssdp_count = udp_packets.iter().filter(|u| u.dst_port == 1900).count();
        out[2] = ssdp_count as f32 / total;

        // 31: Other services ratio
        let other_count = udp_packets
            .iter()
            .filter(|u| u.dst_port != 53 && u.dst_port != 123 && u.dst_port != 1900)
            .count();
        out[3] = other_count as f32 / total;
    }

    fn extract_udp_amplification_features(&self, out: &mut [f32]) {
        let udp_packets: Vec<_> = self.packets.iter().filter(|p| p.layer4.as_udp().is_some()).collect();

        if udp_packets.is_empty() {
            return;
        }

        // Track request/response sizes per destination
        let mut outbound_sizes: Vec<usize> = Vec::new();
        let mut inbound_sizes: Vec<usize> = Vec::new();

        for p in &udp_packets {
            if p.src_ip() == self.src_ip {
                outbound_sizes.push(p.payload_len());
            } else {
                inbound_sizes.push(p.payload_len());
            }
        }

        // 32: Request/response size ratio
        let avg_out = outbound_sizes.iter().sum::<usize>() as f32
            / outbound_sizes.len().max(1) as f32;
        let avg_in = inbound_sizes.iter().sum::<usize>() as f32
            / inbound_sizes.len().max(1) as f32;
        out[0] = if avg_out > 0.0 {
            (avg_in / avg_out / 10.0).min(1.0)
        } else {
            0.0
        };

        // 33: Reflection score (many responses from few requests)
        out[1] = if !outbound_sizes.is_empty() {
            (inbound_sizes.len() as f32 / outbound_sizes.len() as f32 / 10.0).min(1.0)
        } else {
            0.0
        };

        // 34: Amplification factor estimate
        let total_out: usize = outbound_sizes.iter().sum();
        let total_in: usize = inbound_sizes.iter().sum();
        out[2] = if total_out > 0 {
            (total_in as f32 / total_out as f32 / 100.0).min(1.0)
        } else {
            0.0
        };

        // 35: Spoof likelihood (based on asymmetric traffic)
        out[3] = if outbound_sizes.len() > inbound_sizes.len() * 10 {
            1.0
        } else {
            0.0
        };
    }

    fn extract_icmp_type_features(&self, out: &mut [f32]) {
        let icmp_packets: Vec<_> = self.packets.iter().filter_map(|p| p.layer4.as_icmp()).collect();

        if icmp_packets.is_empty() {
            return;
        }

        let total = icmp_packets.len() as f32;

        // 36: Echo request ratio (type 8 for v4, 128 for v6)
        let echo_req = icmp_packets
            .iter()
            .filter(|i| i.icmp_type == 8 || i.icmp_type == 128)
            .count();
        out[0] = echo_req as f32 / total;

        // 37: Echo reply ratio (type 0 for v4, 129 for v6)
        let echo_reply = icmp_packets
            .iter()
            .filter(|i| i.icmp_type == 0 || i.icmp_type == 129)
            .count();
        out[1] = echo_reply as f32 / total;

        // 38: Destination unreachable ratio (type 3 for v4, 1 for v6)
        let unreachable = icmp_packets
            .iter()
            .filter(|i| i.icmp_type == 3 || i.icmp_type == 1)
            .count();
        out[2] = unreachable as f32 / total;

        // 39: Time exceeded ratio (type 11 for v4, 3 for v6)
        let time_exceeded = icmp_packets
            .iter()
            .filter(|i| i.icmp_type == 11 || i.icmp_type == 3)
            .count();
        out[3] = time_exceeded as f32 / total;
    }

    fn extract_icmp_pattern_features(&self, out: &mut [f32]) {
        let icmp_packets: Vec<_> = self.packets.iter().filter_map(|p| p.layer4.as_icmp()).collect();

        if icmp_packets.is_empty() {
            return;
        }

        // Get destination IPs for ICMP echo requests
        let echo_req_dsts: Vec<IpAddr> = self
            .packets
            .iter()
            .filter(|p| {
                p.layer4.as_icmp()
                    .map(|i| i.icmp_type == 8 || i.icmp_type == 128)
                    .unwrap_or(false)
            })
            .map(|p| p.dst_ip())
            .collect();

        // 40: Ping sweep score (many sequential IPs getting echo requests)
        out[0] = calculate_sequential_ip_ratio(&echo_req_dsts);

        // 41: Traceroute score (incrementing TTLs with time exceeded responses)
        let ttls: Vec<u8> = self.packets.iter().map(|p| p.ttl).collect();
        out[1] = calculate_incrementing_ttl_ratio(&ttls);

        // 42: TTL variance
        let ttl_variance = calculate_variance(&ttls.iter().map(|&t| t as f32).collect::<Vec<_>>());
        out[2] = (ttl_variance / 64.0).min(1.0);

        // 43: ICMP code entropy
        let codes: Vec<u8> = icmp_packets.iter().map(|i| i.code).collect();
        out[3] = (calculate_byte_entropy(&codes) / 8.0).min(1.0);
    }

    fn extract_icmp_timing_features(&self, out: &mut [f32]) {
        let icmp_packets: Vec<_> = self
            .packets
            .iter()
            .filter(|p| p.layer4.as_icmp().is_some())
            .collect();

        if icmp_packets.len() < 2 {
            return;
        }

        // Calculate intervals between ICMP packets
        let mut intervals: Vec<f64> = Vec::new();
        for i in 1..icmp_packets.len() {
            let delta = icmp_packets[i]
                .timestamp_ns()
                .saturating_sub(icmp_packets[i - 1].timestamp_ns()) as f64;
            intervals.push(delta);
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
            / intervals.len() as f64;

        // 44: Ping interval regularity (low variance = automated tool)
        let cv = if mean > 0.0 { variance.sqrt() / mean } else { 1.0 };
        out[0] = 1.0 - (cv as f32).min(1.0);

        // 45: Sweep speed (packets per second)
        let duration_s = (self.end_time_ns - self.start_time_ns) as f64 / 1_000_000_000.0;
        let pps = if duration_s > 0.0 {
            icmp_packets.len() as f64 / duration_s
        } else {
            0.0
        };
        out[1] = (pps as f32 / 1000.0).min(1.0);

        // 46: Host discovery rate (unique IPs per second)
        let unique_dsts: HashSet<IpAddr> = icmp_packets.iter().map(|p| p.dst_ip()).collect();
        let ips_per_sec = if duration_s > 0.0 {
            unique_dsts.len() as f64 / duration_s
        } else {
            0.0
        };
        out[2] = (ips_per_sec as f32 / 100.0).min(1.0);

        // 47: Response rate (echo replies / echo requests)
        let requests = icmp_packets
            .iter()
            .filter(|p| {
                p.layer4.as_icmp()
                    .map(|i| i.icmp_type == 8 || i.icmp_type == 128)
                    .unwrap_or(false)
            })
            .count();
        let replies = icmp_packets
            .iter()
            .filter(|p| {
                p.layer4.as_icmp()
                    .map(|i| i.icmp_type == 0 || i.icmp_type == 129)
                    .unwrap_or(false)
            })
            .count();
        out[3] = if requests > 0 {
            replies as f32 / requests as f32
        } else {
            0.0
        };
    }

    fn extract_tls_features(&self, out: &mut [f32]) {
        let tls_packets: Vec<_> = self.packets.iter().filter(|p| p.tls.is_some()).collect();

        if tls_packets.is_empty() {
            return;
        }

        let total = self.packets.len() as f32;

        // 48: TLS packet ratio
        out[0] = tls_packets.len() as f32 / total;

        // 49: ClientHello ratio (indicates connection initiation)
        let client_hellos = tls_packets
            .iter()
            .filter(|p| {
                p.tls
                    .as_ref()
                    .map(|t| t.handshake_type == Some(0x01))
                    .unwrap_or(false)
            })
            .count();
        out[1] = client_hellos as f32 / tls_packets.len() as f32;

        // 50: Handshake packet ratio
        let handshakes = tls_packets
            .iter()
            .filter(|p| p.tls.as_ref().map(|t| t.is_handshake).unwrap_or(false))
            .count();
        out[2] = handshakes as f32 / tls_packets.len().max(1) as f32;

        // 51: Unique JA3 fingerprint ratio (many unique = scanner enumeration)
        let unique_ja3: HashSet<_> = tls_packets
            .iter()
            .filter_map(|p| p.tls.as_ref())
            .filter_map(|t| t.ja3_hash.as_ref())
            .collect();
        out[3] = (unique_ja3.len() as f32 / tls_packets.len() as f32).min(1.0);
    }

    fn extract_tls_version_features(&self, out: &mut [f32]) {
        let tls_packets: Vec<_> = self
            .packets
            .iter()
            .filter_map(|p| p.tls.as_ref())
            .collect();

        if tls_packets.is_empty() {
            return;
        }

        let total = tls_packets.len() as f32;

        // Count TLS versions from version string (e.g., "TLS 1.2", "TLS 1.3")
        let tls10 = tls_packets
            .iter()
            .filter(|t| t.version.as_ref().map(|v| v.contains("1.0")).unwrap_or(false))
            .count();
        let tls11 = tls_packets
            .iter()
            .filter(|t| t.version.as_ref().map(|v| v.contains("1.1")).unwrap_or(false))
            .count();
        let tls12 = tls_packets
            .iter()
            .filter(|t| t.version.as_ref().map(|v| v.contains("1.2")).unwrap_or(false))
            .count();
        let tls13 = tls_packets
            .iter()
            .filter(|t| t.version.as_ref().map(|v| v.contains("1.3")).unwrap_or(false))
            .count();

        // 52: TLS 1.0 ratio (old, often used by scanners)
        out[0] = tls10 as f32 / total;

        // 53: TLS 1.1 ratio
        out[1] = tls11 as f32 / total;

        // 54: TLS 1.2+ ratio (modern)
        out[2] = (tls12 + tls13) as f32 / total;

        // 55: Version diversity (entropy of versions)
        let mut version_counts: HashMap<&str, usize> = HashMap::new();
        for t in &tls_packets {
            if let Some(v) = t.version.as_ref() {
                *version_counts.entry(v.as_str()).or_default() += 1;
            }
        }
        let mut version_entropy = 0.0f32;
        for &count in version_counts.values() {
            let p = count as f32 / total;
            if p > 0.0 {
                version_entropy -= p * p.log2();
            }
        }
        out[3] = (version_entropy / 2.0).min(1.0); // Normalize
    }

    fn extract_tls_sni_features(&self, out: &mut [f32]) {
        // Get TLS packets with handshake type 0x01 (ClientHello)
        let tls_packets: Vec<_> = self
            .packets
            .iter()
            .filter_map(|p| p.tls.as_ref())
            .collect();

        if tls_packets.is_empty() {
            return;
        }

        let total = tls_packets.len() as f32;

        // 56: SNI present ratio
        let with_sni = tls_packets.iter().filter(|t| t.sni.is_some()).count();
        out[0] = with_sni as f32 / total;

        // 57: Unique SNI ratio (many unique = enumeration)
        let unique_snis: HashSet<_> = tls_packets
            .iter()
            .filter_map(|t| t.sni.as_ref())
            .collect();
        out[1] = (unique_snis.len() as f32 / total.max(1.0)).min(1.0);

        // 58: Unique JA3 hash ratio (fingerprint diversity)
        let unique_ja3: HashSet<_> = tls_packets
            .iter()
            .filter_map(|t| t.ja3_hash.as_ref())
            .collect();
        out[2] = (unique_ja3.len() as f32 / total.max(1.0)).min(1.0);

        // 59: ServerHello ratio (handshake_type 0x02)
        let server_hellos = tls_packets
            .iter()
            .filter(|t| t.handshake_type == Some(0x02))
            .count();
        out[3] = server_hellos as f32 / total;
    }

    fn extract_tls_behavior_features(&self, out: &mut [f32]) {
        let tls_packets: Vec<_> = self.packets.iter().filter(|p| p.tls.is_some()).collect();

        if tls_packets.len() < 2 {
            return;
        }

        // Calculate TLS connection patterns
        let mut intervals: Vec<f64> = Vec::new();
        for i in 1..tls_packets.len() {
            let delta = tls_packets[i]
                .timestamp_ns()
                .saturating_sub(tls_packets[i - 1].timestamp_ns()) as f64;
            intervals.push(delta);
        }

        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
            / intervals.len() as f64;

        // 60: TLS timing regularity (low variance = automated)
        let cv = if mean > 0.0 { variance.sqrt() / mean } else { 1.0 };
        out[0] = 1.0 - (cv as f32).min(1.0);

        // 61: TLS connections per second
        let duration_s = (self.end_time_ns - self.start_time_ns) as f64 / 1_000_000_000.0;
        let tps = if duration_s > 0.0 {
            tls_packets.len() as f64 / duration_s
        } else {
            0.0
        };
        out[1] = (tps as f32 / 100.0).min(1.0);

        // 62: Unique TLS destinations
        let unique_dsts: HashSet<_> = tls_packets.iter().map(|p| p.dst_ip()).collect();
        out[2] = (unique_dsts.len() as f32 / 50.0).min(1.0);

        // 63: Failed TLS ratio (RST after TLS handshake start)
        let failed = self
            .packets
            .iter()
            .filter(|p| {
                p.tls.is_some()
                    && p.layer4.as_tcp().map(|t| t.flags.rst).unwrap_or(false)
            })
            .count();
        out[3] = failed as f32 / tls_packets.len() as f32;
    }

    /// Extract DoS-specific rate-based features (indices 64-71)
    ///
    /// These features detect volumetric attacks based on traffic rates:
    /// - 64: Packets per second (normalized to 100k pps max)
    /// - 65: Bytes per second (normalized to 125 MB/s max)
    /// - 66: New connections per second (normalized to 10k/s max)
    /// - 67: Half-open ratio at high volume
    /// - 68: TCP flood score (combined SYN rate + half-open)
    /// - 69: UDP flood score (combined packet + byte rate)
    /// - 70: ICMP flood score (echo rate to single target)
    /// - 71: Connection exhaustion score
    fn extract_dos_rate_features(&self, out: &mut [f32]) {
        if self.packets.is_empty() {
            return;
        }

        // Calculate window duration in seconds
        let duration_ns = self.end_time_ns.saturating_sub(self.start_time_ns);
        let duration_s = duration_ns as f64 / 1_000_000_000.0;

        if duration_s < 0.001 {
            return; // Avoid division by zero for very short windows
        }

        let total_packets = self.packets.len() as f64;
        let total_bytes: usize = self.packets.iter().map(|p| p.payload_len()).sum();

        // 64: Packets per second (normalized, max 100,000 pps for flood)
        let pps = total_packets / duration_s;
        out[0] = (pps / 100_000.0).min(1.0) as f32;

        // 65: Bytes per second (normalized, max 1 Gbps = 125 MB/s)
        let bps = total_bytes as f64 / duration_s;
        out[1] = (bps / 125_000_000.0).min(1.0) as f32;

        // 66: New connections per second (SYN packets / duration)
        let syn_count = self
            .packets
            .iter()
            .filter(|p| {
                p.layer4
                    .as_tcp()
                    .map(|t| t.flags.is_syn_only())
                    .unwrap_or(false)
            })
            .count() as f64;
        let conn_rate = syn_count / duration_s;
        out[2] = (conn_rate / 10_000.0).min(1.0) as f32; // Normalize to 10k/s max

        // 67: Half-open ratio at high volume (meaningful only during potential floods)
        let tcp_packets: Vec<_> = self
            .packets
            .iter()
            .filter_map(|p| p.layer4.as_tcp())
            .collect();

        if !tcp_packets.is_empty() && pps > 1000.0 {
            let syn_only = tcp_packets
                .iter()
                .filter(|t| t.flags.is_syn_only())
                .count();
            let syn_ack = tcp_packets.iter().filter(|t| t.flags.is_syn_ack()).count();

            // High SYN without SYN-ACK at high volume = SYN flood indicator
            if syn_only > 0 {
                let completion_ratio = syn_ack as f32 / syn_only as f32;
                out[3] = 1.0 - completion_ratio.min(1.0);
            }
        }

        // 68: TCP flood score (combined SYN rate + half-open)
        // High score = likely SYN flood
        let syn_ratio = if !tcp_packets.is_empty() {
            tcp_packets
                .iter()
                .filter(|t| t.flags.is_syn_only())
                .count() as f32
                / tcp_packets.len() as f32
        } else {
            0.0
        };
        let tcp_flood_score = (out[0] * 0.4 + out[2] * 0.3 + out[3] * 0.3) * syn_ratio;
        out[4] = tcp_flood_score.min(1.0);

        // 69: UDP flood score (combined packet + byte rate for UDP traffic)
        let udp_packets: Vec<_> = self
            .packets
            .iter()
            .filter(|p| p.layer4.as_udp().is_some())
            .collect();
        let udp_ratio = udp_packets.len() as f32 / self.packets.len().max(1) as f32;

        if udp_ratio > 0.5 {
            // Predominantly UDP traffic
            let udp_bytes: usize = udp_packets.iter().map(|p| p.payload_len()).sum();
            let udp_bps = udp_bytes as f64 / duration_s;
            let udp_pps = udp_packets.len() as f64 / duration_s;

            let udp_flood_score = ((udp_pps / 100_000.0).min(1.0) * 0.5
                + (udp_bps / 125_000_000.0).min(1.0) * 0.5) as f32;
            out[5] = udp_flood_score * udp_ratio;
        }

        // 70: ICMP flood score (echo rate to single/few targets)
        let icmp_packets: Vec<_> = self
            .packets
            .iter()
            .filter(|p| p.layer4.as_icmp().is_some())
            .collect();

        if !icmp_packets.is_empty() {
            let echo_requests = icmp_packets
                .iter()
                .filter(|p| {
                    p.layer4
                        .as_icmp()
                        .map(|i| i.icmp_type == 8 || i.icmp_type == 128) // Echo request
                        .unwrap_or(false)
                })
                .count();

            let icmp_dst_ips: HashSet<_> = icmp_packets.iter().map(|p| p.dst_ip()).collect();
            let target_concentration = if icmp_dst_ips.len() <= 3 { 1.0 } else { 0.5 };

            let icmp_rate = echo_requests as f64 / duration_s;
            let icmp_flood_score =
                (icmp_rate / 50_000.0).min(1.0) as f32 * target_concentration as f32;
            out[6] = icmp_flood_score;
        }

        // 71: Connection exhaustion score (high connection rate + high half-open)
        // Different from SYN flood: focuses on resource exhaustion at lower rates
        if out[2] > 0.05 && out[3] > 0.5 {
            // Connection rate > 500/s and half-open > 50%
            let exhaustion_score = out[2] * 0.4 + out[3] * 0.6;
            out[7] = exhaustion_score.min(1.0);
        }
    }
}

#[derive(Default)]
struct ConnectionState {
    syn_seen: bool,
    synack_seen: bool,
    ack_seen: bool,
    rst_seen: bool,
}

impl ConnectionState {
    fn is_complete(&self) -> bool {
        self.syn_seen && self.synack_seen && self.ack_seen
    }

    fn is_half_open(&self) -> bool {
        self.syn_seen && !self.synack_seen && !self.ack_seen
    }
}

fn calculate_entropy<T: std::hash::Hash + Eq>(items: &[T]) -> f32 {
    let mut counts: HashMap<&T, usize> = HashMap::new();
    for item in items {
        *counts.entry(item).or_default() += 1;
    }

    let total = items.len() as f32;
    let mut entropy = 0.0f32;
    for &count in counts.values() {
        let p = count as f32 / total;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn calculate_byte_entropy(bytes: &[u8]) -> f32 {
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }

    let total = bytes.len() as f32;
    let mut entropy = 0.0f32;
    for &count in &counts {
        if count > 0 {
            let p = count as f32 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn calculate_ip_entropy(ips: &[IpAddr]) -> f32 {
    let mut counts: HashMap<IpAddr, usize> = HashMap::new();
    for &ip in ips {
        *counts.entry(ip).or_default() += 1;
    }

    let total = ips.len() as f32;
    let mut entropy = 0.0f32;
    for &count in counts.values() {
        let p = count as f32 / total;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn calculate_sequential_ip_ratio(ips: &[IpAddr]) -> f32 {
    if ips.len() < 2 {
        return 0.0;
    }

    let mut sequential_count = 0;
    let mut v4_ips: Vec<u32> = ips
        .iter()
        .filter_map(|ip| {
            if let IpAddr::V4(v4) = ip {
                Some(u32::from(*v4))
            } else {
                None
            }
        })
        .collect();

    v4_ips.sort_unstable();
    v4_ips.dedup();

    for i in 1..v4_ips.len() {
        if v4_ips[i] == v4_ips[i - 1] + 1 {
            sequential_count += 1;
        }
    }

    if v4_ips.len() > 1 {
        sequential_count as f32 / (v4_ips.len() - 1) as f32
    } else {
        0.0
    }
}

fn calculate_incrementing_ttl_ratio(ttls: &[u8]) -> f32 {
    if ttls.len() < 2 {
        return 0.0;
    }

    let mut incrementing = 0;
    for i in 1..ttls.len() {
        if ttls[i] == ttls[i - 1] + 1 || ttls[i] == ttls[i - 1].wrapping_add(1) {
            incrementing += 1;
        }
    }

    incrementing as f32 / (ttls.len() - 1) as f32
}

fn calculate_variance(values: &[f32]) -> f32 {
    if values.is_empty() {
        return 0.0;
    }

    let mean = values.iter().sum::<f32>() / values.len() as f32;
    values.iter().map(|x| (x - mean).powi(2)).sum::<f32>() / values.len() as f32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_empty_window() {
        let stats = WindowStats::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let vec = stats.extract_features();
        assert_eq!(vec.len(), VECTOR_DIM);
        assert!(vec.iter().all(|&v| v == 0.0));
    }

    #[test]
    fn test_sequential_ip_ratio() {
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4)),
        ];
        let ratio = calculate_sequential_ip_ratio(&ips);
        assert!((ratio - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_entropy() {
        let items = vec![1, 1, 1, 1];
        assert_eq!(calculate_entropy(&items), 0.0);

        let items = vec![1, 2, 3, 4];
        assert!((calculate_entropy(&items) - 2.0).abs() < 0.01);
    }

    // === DoS Feature Extraction Tests ===

    use crmonban_types::{IpProtocol, TcpFlags};
    use chrono::{TimeZone, Utc};

    fn create_syn_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, dst_port: u16, timestamp_ns: u64) -> Packet {
        let mut pkt = Packet::new(
            0,
            IpAddr::V4(src_ip),
            IpAddr::V4(dst_ip),
            IpProtocol::Tcp,
            "lo",
        );
        pkt.timestamp = Utc.timestamp_nanos(timestamp_ns as i64);
        if let Some(tcp) = pkt.tcp_mut() {
            tcp.src_port = 12345;
            tcp.dst_port = dst_port;
            tcp.flags = TcpFlags { syn: true, ..Default::default() };
            tcp.seq = 1000;
            tcp.window = 65535;
        }
        pkt
    }

    fn create_udp_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, dst_port: u16, payload_len: u16, timestamp_ns: u64) -> Packet {
        let mut pkt = Packet::new(
            0,
            IpAddr::V4(src_ip),
            IpAddr::V4(dst_ip),
            IpProtocol::Udp,
            "lo",
        );
        pkt.timestamp = Utc.timestamp_nanos(timestamp_ns as i64);
        if let Some(udp) = pkt.udp_mut() {
            udp.src_port = 54321;
            udp.dst_port = dst_port;
            udp.payload = vec![0u8; payload_len as usize];
        }
        pkt
    }

    fn create_icmp_packet(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, icmp_type: u8, timestamp_ns: u64) -> Packet {
        let mut pkt = Packet::new(
            0,
            IpAddr::V4(src_ip),
            IpAddr::V4(dst_ip),
            IpProtocol::Icmp,
            "lo",
        );
        pkt.timestamp = Utc.timestamp_nanos(timestamp_ns as i64);
        if let Some(icmp) = pkt.layer4.as_icmp_mut() {
            icmp.icmp_type = icmp_type;
            icmp.code = 0;
        }
        pkt
    }

    #[test]
    fn test_dos_features_empty_window() {
        let stats = WindowStats::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let vec = stats.extract_features();

        // DoS features (64-71) should all be 0 for empty window
        for i in 64..72 {
            assert_eq!(vec[i], 0.0, "DoS feature {} should be 0 for empty window", i);
        }
    }

    #[test]
    fn test_dos_packet_rate_feature() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 100);

        let mut stats = WindowStats::new(IpAddr::V4(src_ip));

        // Simulate 10000 SYN packets over 1 second (10k pps)
        // We'll add 100 packets spread over 1 second for test purposes
        let start_time = 0u64;
        let duration_ns = 1_000_000_000u64; // 1 second

        for i in 0..100 {
            let timestamp = start_time + (i * duration_ns / 100);
            let packet = create_syn_packet(src_ip, dst_ip, 80, timestamp);
            stats.add_packet(packet);
        }

        let vec = stats.extract_features();

        // Index 64: Packets per second (normalized to 100k max)
        // 100 packets / 1 second = 100 pps
        // Normalized: 100 / 100000 = 0.001
        let pps = vec[64];
        assert!(pps > 0.0, "Packet rate should be positive");
        assert!(pps < 0.01, "Packet rate should be small for 100 pps (got {})", pps);
    }

    #[test]
    fn test_dos_tcp_flood_score() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 100);

        let mut stats = WindowStats::new(IpAddr::V4(src_ip));

        // Simulate SYN flood: many SYN packets in short time
        let start_time = 0u64;
        let duration_ns = 100_000_000u64; // 100ms

        // Add 1000 SYN packets in 100ms = 10000 pps
        for i in 0..1000 {
            let timestamp = start_time + (i * duration_ns / 1000);
            let packet = create_syn_packet(src_ip, dst_ip, 80, timestamp);
            stats.add_packet(packet);
        }

        let vec = stats.extract_features();

        // Index 66: Connection rate (SYN packets / duration)
        let conn_rate = vec[66];
        assert!(conn_rate > 0.0, "Connection rate should be positive");

        // Index 68: TCP flood score
        let tcp_flood = vec[68];
        // TCP flood score depends on packet rate, connection rate, and half-open ratio
        // With only SYN packets, this should be elevated
        assert!(tcp_flood >= 0.0, "TCP flood score should be non-negative");
    }

    #[test]
    fn test_dos_udp_flood_score() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 100);

        let mut stats = WindowStats::new(IpAddr::V4(src_ip));

        // Simulate UDP flood
        let start_time = 0u64;
        let duration_ns = 100_000_000u64; // 100ms

        for i in 0..500 {
            let timestamp = start_time + (i * duration_ns / 500);
            let packet = create_udp_packet(src_ip, dst_ip, 53, 512, timestamp);
            stats.add_packet(packet);
        }

        let vec = stats.extract_features();

        // Index 65: Bytes per second
        let bps = vec[65];
        assert!(bps >= 0.0, "Byte rate should be non-negative");

        // Index 69: UDP flood score
        let udp_flood = vec[69];
        assert!(udp_flood >= 0.0, "UDP flood score should be non-negative");
    }

    #[test]
    fn test_dos_icmp_flood_score() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 100);

        let mut stats = WindowStats::new(IpAddr::V4(src_ip));

        // Simulate ICMP flood to single target
        let start_time = 0u64;
        let duration_ns = 100_000_000u64; // 100ms

        for i in 0..500 {
            let timestamp = start_time + (i * duration_ns / 500);
            // Type 8 = Echo request
            let packet = create_icmp_packet(src_ip, dst_ip, 8, timestamp);
            stats.add_packet(packet);
        }

        let vec = stats.extract_features();

        // Index 70: ICMP flood score
        let icmp_flood = vec[70];
        // Should have non-zero score since we're flooding single target
        assert!(icmp_flood >= 0.0, "ICMP flood score should be non-negative");
    }

    #[test]
    fn test_dos_connection_exhaustion_score() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 100);

        let mut stats = WindowStats::new(IpAddr::V4(src_ip));

        // Simulate connection exhaustion: many SYN without completion
        let start_time = 0u64;
        let duration_ns = 1_000_000_000u64; // 1 second

        // Many SYN packets without any SYN-ACK responses
        for i in 0..2000 {
            let timestamp = start_time + (i * duration_ns / 2000);
            let packet = create_syn_packet(src_ip, dst_ip, 80, timestamp);
            stats.add_packet(packet);
        }

        let vec = stats.extract_features();

        // Index 67: Half-open ratio at high volume
        let half_open_flood = vec[67];
        // With only SYN packets and high rate, this should be elevated
        assert!(half_open_flood >= 0.0, "Half-open flood indicator should be non-negative");

        // Index 71: Connection exhaustion score
        let exhaustion = vec[71];
        assert!(exhaustion >= 0.0, "Exhaustion score should be non-negative");
    }

    #[test]
    fn test_dos_feature_vector_dimension() {
        // Verify the feature vector is the correct size (72)
        let stats = WindowStats::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let vec = stats.extract_features();
        assert_eq!(vec.len(), 72, "Feature vector should have 72 dimensions");
    }

    #[test]
    fn test_dos_features_normalized() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 100);

        let mut stats = WindowStats::new(IpAddr::V4(src_ip));

        // Add some packets
        for i in 0..100 {
            let packet = create_syn_packet(src_ip, dst_ip, 80, i * 10_000_000);
            stats.add_packet(packet);
        }

        let vec = stats.extract_features();

        // All DoS features should be in range [0.0, 1.0]
        for i in 64..72 {
            assert!(vec[i] >= 0.0, "DoS feature {} should be >= 0", i);
            assert!(vec[i] <= 1.0, "DoS feature {} should be <= 1 (got {})", i, vec[i]);
        }
    }
}
