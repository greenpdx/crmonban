//! Connection flow tracking
//!
//! Tracks bidirectional flows and computes statistics for ML/anomaly detection.
//!
//! Optimizations:
//! - Streaming statistics (O(1) space vs O(n) for storing all samples)
//! - Inline hints on hot paths
//! - Pre-computed duration in update path

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::packet::{AppProtocol, Direction, IpProtocol, Packet, TcpFlags};

/// Streaming statistics accumulator (Welford's algorithm)
/// Computes min, max, mean, variance in O(1) space
#[derive(Debug, Clone, Default)]
pub struct StreamingStats {
    pub count: u64,
    pub min: f32,
    pub max: f32,
    pub mean: f32,
    pub m2: f32,  // For variance calculation
    pub sum: f64, // For total
}

impl StreamingStats {
    #[inline]
    pub fn new() -> Self {
        Self {
            count: 0,
            min: f32::MAX,
            max: f32::MIN,
            mean: 0.0,
            m2: 0.0,
            sum: 0.0,
        }
    }

    /// Update with a new sample (Welford's online algorithm)
    #[inline]
    pub fn update(&mut self, value: f32) {
        self.count += 1;
        self.sum += value as f64;

        // Min/max
        if value < self.min { self.min = value; }
        if value > self.max { self.max = value; }

        // Welford's algorithm for mean and variance
        let delta = value - self.mean;
        self.mean += delta / self.count as f32;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    /// Get standard deviation
    #[inline]
    pub fn std(&self) -> f32 {
        if self.count < 2 {
            0.0
        } else {
            (self.m2 / (self.count - 1) as f32).sqrt()
        }
    }

    /// Get total sum
    #[inline]
    pub fn total(&self) -> f64 {
        self.sum
    }
}

/// Unique key identifying a flow (5-tuple normalized)
/// Custom Hash implementation for better performance
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowKey {
    pub ip_a: IpAddr,
    pub ip_b: IpAddr,
    pub port_a: u16,
    pub port_b: u16,
    pub protocol: IpProtocol,
}

impl Hash for FlowKey {
    /// Optimized hash - combines all fields efficiently
    #[inline]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Hash IPs as bytes directly (faster than derived)
        match self.ip_a {
            IpAddr::V4(v4) => state.write(&v4.octets()),
            IpAddr::V6(v6) => state.write(&v6.octets()),
        }
        match self.ip_b {
            IpAddr::V4(v4) => state.write(&v4.octets()),
            IpAddr::V6(v6) => state.write(&v6.octets()),
        }
        // Combine ports and protocol into single write
        state.write_u32(
            (self.port_a as u32) | ((self.port_b as u32) << 16)
        );
        state.write_u8(self.protocol as u8);
    }
}

impl FlowKey {
    /// Create from packet (normalized so smaller IP/port is always first)
    #[inline]
    pub fn from_packet(pkt: &Packet) -> Self {
        if (pkt.src_ip, pkt.src_port) <= (pkt.dst_ip, pkt.dst_port) {
            Self {
                ip_a: pkt.src_ip,
                ip_b: pkt.dst_ip,
                port_a: pkt.src_port,
                port_b: pkt.dst_port,
                protocol: pkt.protocol,
            }
        } else {
            Self {
                ip_a: pkt.dst_ip,
                ip_b: pkt.src_ip,
                port_a: pkt.dst_port,
                port_b: pkt.src_port,
                protocol: pkt.protocol,
            }
        }
    }
}

/// TCP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    /// New flow, waiting for SYN-ACK
    New,
    /// SYN sent
    SynSent,
    /// SYN-ACK received
    SynReceived,
    /// Connection established
    Established,
    /// FIN sent
    FinWait1,
    /// FIN-ACK received
    FinWait2,
    /// Closing
    Closing,
    /// Time-wait
    TimeWait,
    /// Closed
    Closed,
    /// Reset
    Reset,
    /// UDP flow (stateless)
    UdpActive,
    /// ICMP flow
    IcmpActive,
}

impl Default for FlowState {
    fn default() -> Self {
        FlowState::New
    }
}

impl std::fmt::Display for FlowState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowState::New => write!(f, "NEW"),
            FlowState::SynSent => write!(f, "SYN_SENT"),
            FlowState::SynReceived => write!(f, "SYN_RCVD"),
            FlowState::Established => write!(f, "ESTABLISHED"),
            FlowState::FinWait1 => write!(f, "FIN_WAIT1"),
            FlowState::FinWait2 => write!(f, "FIN_WAIT2"),
            FlowState::Closing => write!(f, "CLOSING"),
            FlowState::TimeWait => write!(f, "TIME_WAIT"),
            FlowState::Closed => write!(f, "CLOSED"),
            FlowState::Reset => write!(f, "RESET"),
            FlowState::UdpActive => write!(f, "UDP_ACTIVE"),
            FlowState::IcmpActive => write!(f, "ICMP_ACTIVE"),
        }
    }
}

/// Bidirectional connection flow (optimized with streaming stats)
#[derive(Debug, Clone)]
pub struct Flow {
    /// Unique flow ID
    pub id: u64,
    /// Flow key
    pub key: FlowKey,

    // Connection endpoints (client = initiator)
    /// Client (initiator) IP
    pub client_ip: IpAddr,
    /// Client port
    pub client_port: u16,
    /// Server (responder) IP
    pub server_ip: IpAddr,
    /// Server port
    pub server_port: u16,
    /// Protocol
    pub protocol: IpProtocol,

    /// Connection state
    pub state: FlowState,

    // Timing
    /// Flow start time
    pub start_time: Instant,
    /// Last packet time
    pub last_seen: Instant,

    // Forward (client to server) statistics
    /// Packets from client
    pub fwd_packets: u64,
    /// Bytes from client
    pub fwd_bytes: u64,
    /// Packet size streaming stats (forward) - O(1) space
    pub fwd_pkt_stats: StreamingStats,
    /// Inter-arrival time streaming stats (forward) - O(1) space
    pub fwd_iat_stats: StreamingStats,
    /// Last forward packet time
    pub fwd_last_time: Option<Instant>,

    // Backward (server to client) statistics
    /// Packets from server
    pub bwd_packets: u64,
    /// Bytes from server
    pub bwd_bytes: u64,
    /// Packet size streaming stats (backward) - O(1) space
    pub bwd_pkt_stats: StreamingStats,
    /// Inter-arrival time streaming stats (backward) - O(1) space
    pub bwd_iat_stats: StreamingStats,
    /// Last backward packet time
    pub bwd_last_time: Option<Instant>,

    // TCP-specific
    /// Initial sequence number (client)
    pub client_isn: Option<u32>,
    /// Initial sequence number (server)
    pub server_isn: Option<u32>,
    /// SYN count
    pub syn_count: u32,
    /// SYN-ACK count
    pub syn_ack_count: u32,
    /// FIN count
    pub fin_count: u32,
    /// RST count
    pub rst_count: u32,
    /// PSH count
    pub psh_count: u32,
    /// URG count
    pub urg_count: u32,
    /// ACK count
    pub ack_count: u32,

    // Application layer
    /// Detected application protocol
    pub app_protocol: AppProtocol,
    /// Protocol metadata (HTTP headers, DNS queries, etc.)
    pub app_data: HashMap<String, serde_json::Value>,

    // Detection state
    /// Risk score (0.0 - 1.0)
    pub risk_score: f32,
    /// Tags applied by detection
    pub tags: Vec<String>,
    /// Alert IDs triggered by this flow
    pub alert_ids: Vec<u64>,
}

impl Flow {
    /// Create a new flow from the first packet
    #[inline]
    pub fn new(id: u64, pkt: &Packet) -> Self {
        let key = FlowKey::from_packet(pkt);

        // First packet sender is the client
        let (client_ip, client_port, server_ip, server_port) =
            (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port);

        let initial_state = match pkt.protocol {
            IpProtocol::Tcp => {
                if pkt.tcp_flags.map(|f| f.is_syn()).unwrap_or(false) {
                    FlowState::SynSent
                } else {
                    FlowState::New
                }
            }
            IpProtocol::Udp => FlowState::UdpActive,
            IpProtocol::Icmp | IpProtocol::Icmpv6 => FlowState::IcmpActive,
            _ => FlowState::New,
        };

        let now = Instant::now();

        // Initialize streaming stats with first packet
        let mut fwd_pkt_stats = StreamingStats::new();
        fwd_pkt_stats.update(pkt.raw_len as f32);

        Self {
            id,
            key,
            client_ip,
            client_port,
            server_ip,
            server_port,
            protocol: pkt.protocol,
            state: initial_state,
            start_time: now,
            last_seen: now,
            fwd_packets: 1,
            fwd_bytes: pkt.raw_len as u64,
            fwd_pkt_stats,
            fwd_iat_stats: StreamingStats::new(),
            fwd_last_time: Some(now),
            bwd_packets: 0,
            bwd_bytes: 0,
            bwd_pkt_stats: StreamingStats::new(),
            bwd_iat_stats: StreamingStats::new(),
            bwd_last_time: None,
            client_isn: pkt.seq,
            server_isn: None,
            syn_count: if pkt.tcp_flags.map(|f| f.syn).unwrap_or(false) { 1 } else { 0 },
            syn_ack_count: 0,
            fin_count: 0,
            rst_count: 0,
            psh_count: 0,
            urg_count: 0,
            ack_count: 0,
            app_protocol: pkt.app_protocol,
            app_data: HashMap::new(),
            risk_score: 0.0,
            tags: Vec::new(),
            alert_ids: Vec::new(),
        }
    }

    /// Update flow with a new packet (optimized with streaming stats)
    #[inline]
    pub fn update(&mut self, pkt: &Packet) -> Direction {
        let now = Instant::now();
        self.last_seen = now;

        // Determine direction
        let is_forward = pkt.src_ip == self.client_ip && pkt.src_port == self.client_port;
        let direction = if is_forward {
            Direction::ToServer
        } else {
            Direction::ToClient
        };

        let pkt_size = pkt.raw_len as f32;

        // Update statistics with streaming stats (O(1) space)
        if is_forward {
            self.fwd_packets += 1;
            self.fwd_bytes += pkt.raw_len as u64;
            self.fwd_pkt_stats.update(pkt_size);
            if let Some(last) = self.fwd_last_time {
                let iat_us = now.duration_since(last).as_micros() as f32;
                self.fwd_iat_stats.update(iat_us);
            }
            self.fwd_last_time = Some(now);
        } else {
            self.bwd_packets += 1;
            self.bwd_bytes += pkt.raw_len as u64;
            self.bwd_pkt_stats.update(pkt_size);
            if let Some(last) = self.bwd_last_time {
                let iat_us = now.duration_since(last).as_micros() as f32;
                self.bwd_iat_stats.update(iat_us);
            }
            self.bwd_last_time = Some(now);

            // Capture server ISN from SYN-ACK
            if self.server_isn.is_none() {
                self.server_isn = pkt.seq;
            }
        }

        // Update TCP flags
        if let Some(flags) = pkt.tcp_flags {
            if flags.syn { self.syn_count += 1; }
            if flags.syn && flags.ack { self.syn_ack_count += 1; }
            if flags.fin { self.fin_count += 1; }
            if flags.rst { self.rst_count += 1; }
            if flags.psh { self.psh_count += 1; }
            if flags.urg { self.urg_count += 1; }
            if flags.ack { self.ack_count += 1; }

            // Update TCP state
            self.update_tcp_state(&flags, is_forward);
        }

        // Update app protocol if detected
        if pkt.app_protocol != AppProtocol::Unknown {
            self.app_protocol = pkt.app_protocol;
        }

        direction
    }

    /// Update TCP state machine
    fn update_tcp_state(&mut self, flags: &TcpFlags, is_forward: bool) {
        self.state = match self.state {
            FlowState::New => {
                if flags.is_syn() {
                    FlowState::SynSent
                } else {
                    FlowState::Established // Mid-stream pickup
                }
            }
            FlowState::SynSent => {
                if flags.is_syn_ack() && !is_forward {
                    FlowState::SynReceived
                } else if flags.is_rst() {
                    FlowState::Reset
                } else {
                    self.state
                }
            }
            FlowState::SynReceived => {
                if flags.ack && is_forward {
                    FlowState::Established
                } else if flags.is_rst() {
                    FlowState::Reset
                } else {
                    self.state
                }
            }
            FlowState::Established => {
                if flags.is_rst() {
                    FlowState::Reset
                } else if flags.is_fin() {
                    FlowState::FinWait1
                } else {
                    self.state
                }
            }
            FlowState::FinWait1 => {
                if flags.is_fin() && flags.ack {
                    FlowState::TimeWait
                } else if flags.is_fin() {
                    FlowState::Closing
                } else if flags.ack {
                    FlowState::FinWait2
                } else if flags.is_rst() {
                    FlowState::Reset
                } else {
                    self.state
                }
            }
            FlowState::FinWait2 => {
                if flags.is_fin() {
                    FlowState::TimeWait
                } else if flags.is_rst() {
                    FlowState::Reset
                } else {
                    self.state
                }
            }
            FlowState::Closing => {
                if flags.ack {
                    FlowState::TimeWait
                } else if flags.is_rst() {
                    FlowState::Reset
                } else {
                    self.state
                }
            }
            FlowState::TimeWait => {
                if flags.is_rst() {
                    FlowState::Reset
                } else {
                    self.state
                }
            }
            FlowState::Closed | FlowState::Reset => self.state,
            FlowState::UdpActive | FlowState::IcmpActive => self.state,
        };
    }

    /// Check if flow is complete (closed or timed out)
    pub fn is_complete(&self) -> bool {
        matches!(self.state, FlowState::Closed | FlowState::Reset | FlowState::TimeWait)
    }

    /// Check if flow is established
    pub fn is_established(&self) -> bool {
        matches!(self.state, FlowState::Established | FlowState::UdpActive)
    }

    /// Get flow duration
    pub fn duration(&self) -> Duration {
        self.last_seen.duration_since(self.start_time)
    }

    /// Get total packets
    pub fn total_packets(&self) -> u64 {
        self.fwd_packets + self.bwd_packets
    }

    /// Get total bytes
    pub fn total_bytes(&self) -> u64 {
        self.fwd_bytes + self.bwd_bytes
    }

    /// Calculate flow statistics for ML
    pub fn stats(&self) -> FlowStats {
        FlowStats::from_flow(self)
    }

    /// Add a tag to the flow
    pub fn add_tag(&mut self, tag: &str) {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
    }

    /// Store app-layer data
    pub fn set_app_data(&mut self, key: &str, value: serde_json::Value) {
        self.app_data.insert(key.to_string(), value);
    }
}

/// Flow statistics for ML feature extraction (CICIDS2017 compatible)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowStats {
    // Duration
    pub duration_us: u64,

    // Packet counts
    pub total_fwd_packets: u64,
    pub total_bwd_packets: u64,

    // Byte counts
    pub total_fwd_bytes: u64,
    pub total_bwd_bytes: u64,

    // Packet length stats (forward)
    pub fwd_pkt_len_min: u16,
    pub fwd_pkt_len_max: u16,
    pub fwd_pkt_len_mean: f32,
    pub fwd_pkt_len_std: f32,

    // Packet length stats (backward)
    pub bwd_pkt_len_min: u16,
    pub bwd_pkt_len_max: u16,
    pub bwd_pkt_len_mean: f32,
    pub bwd_pkt_len_std: f32,

    // Flow rates
    pub flow_bytes_per_sec: f32,
    pub flow_packets_per_sec: f32,

    // Inter-arrival times (forward)
    pub fwd_iat_total_us: u64,
    pub fwd_iat_mean_us: f32,
    pub fwd_iat_std_us: f32,
    pub fwd_iat_min_us: u64,
    pub fwd_iat_max_us: u64,

    // Inter-arrival times (backward)
    pub bwd_iat_total_us: u64,
    pub bwd_iat_mean_us: f32,
    pub bwd_iat_std_us: f32,
    pub bwd_iat_min_us: u64,
    pub bwd_iat_max_us: u64,

    // TCP flags
    pub syn_flag_count: u32,
    pub fin_flag_count: u32,
    pub rst_flag_count: u32,
    pub psh_flag_count: u32,
    pub ack_flag_count: u32,
    pub urg_flag_count: u32,

    // Ratios
    pub down_up_ratio: f32,

    // Per-second averages
    pub fwd_packets_per_sec: f32,
    pub bwd_packets_per_sec: f32,

    // Bulk metrics
    pub fwd_bulk_rate: f32,
    pub bwd_bulk_rate: f32,

    // Subflow metrics
    pub subflow_fwd_packets: u64,
    pub subflow_bwd_packets: u64,
    pub subflow_fwd_bytes: u64,
    pub subflow_bwd_bytes: u64,

    // Active/idle times
    pub active_mean_us: f32,
    pub active_std_us: f32,
    pub idle_mean_us: f32,
    pub idle_std_us: f32,
}

impl FlowStats {
    /// Extract features from a flow (optimized - uses pre-computed streaming stats)
    #[inline]
    pub fn from_flow(flow: &Flow) -> Self {
        let duration = flow.duration();
        let duration_us = duration.as_micros() as u64;
        let duration_secs = duration.as_secs_f32().max(0.001);

        // Get stats directly from streaming accumulators (O(1) - no iteration)
        let fwd_pkt = &flow.fwd_pkt_stats;
        let bwd_pkt = &flow.bwd_pkt_stats;
        let fwd_iat = &flow.fwd_iat_stats;
        let bwd_iat = &flow.bwd_iat_stats;

        // Handle uninitialized stats (min = MAX means no samples)
        let fwd_min = if fwd_pkt.count > 0 { fwd_pkt.min as u16 } else { 0 };
        let fwd_max = if fwd_pkt.count > 0 { fwd_pkt.max as u16 } else { 0 };
        let bwd_min = if bwd_pkt.count > 0 { bwd_pkt.min as u16 } else { 0 };
        let bwd_max = if bwd_pkt.count > 0 { bwd_pkt.max as u16 } else { 0 };

        let fwd_iat_min = if fwd_iat.count > 0 { fwd_iat.min as u64 } else { 0 };
        let fwd_iat_max = if fwd_iat.count > 0 { fwd_iat.max as u64 } else { 0 };
        let bwd_iat_min = if bwd_iat.count > 0 { bwd_iat.min as u64 } else { 0 };
        let bwd_iat_max = if bwd_iat.count > 0 { bwd_iat.max as u64 } else { 0 };

        // Ratios
        let down_up_ratio = if flow.fwd_bytes > 0 {
            flow.bwd_bytes as f32 / flow.fwd_bytes as f32
        } else {
            0.0
        };

        Self {
            duration_us,
            total_fwd_packets: flow.fwd_packets,
            total_bwd_packets: flow.bwd_packets,
            total_fwd_bytes: flow.fwd_bytes,
            total_bwd_bytes: flow.bwd_bytes,
            fwd_pkt_len_min: fwd_min,
            fwd_pkt_len_max: fwd_max,
            fwd_pkt_len_mean: fwd_pkt.mean,
            fwd_pkt_len_std: fwd_pkt.std(),
            bwd_pkt_len_min: bwd_min,
            bwd_pkt_len_max: bwd_max,
            bwd_pkt_len_mean: bwd_pkt.mean,
            bwd_pkt_len_std: bwd_pkt.std(),
            flow_bytes_per_sec: flow.total_bytes() as f32 / duration_secs,
            flow_packets_per_sec: flow.total_packets() as f32 / duration_secs,
            fwd_iat_total_us: fwd_iat.total() as u64,
            fwd_iat_mean_us: fwd_iat.mean,
            fwd_iat_std_us: fwd_iat.std(),
            fwd_iat_min_us: fwd_iat_min,
            fwd_iat_max_us: fwd_iat_max,
            bwd_iat_total_us: bwd_iat.total() as u64,
            bwd_iat_mean_us: bwd_iat.mean,
            bwd_iat_std_us: bwd_iat.std(),
            bwd_iat_min_us: bwd_iat_min,
            bwd_iat_max_us: bwd_iat_max,
            syn_flag_count: flow.syn_count,
            fin_flag_count: flow.fin_count,
            rst_flag_count: flow.rst_count,
            psh_flag_count: flow.psh_count,
            ack_flag_count: flow.ack_count,
            urg_flag_count: flow.urg_count,
            down_up_ratio,
            fwd_packets_per_sec: flow.fwd_packets as f32 / duration_secs,
            bwd_packets_per_sec: flow.bwd_packets as f32 / duration_secs,
            fwd_bulk_rate: 0.0, // TODO: implement bulk detection
            bwd_bulk_rate: 0.0,
            subflow_fwd_packets: flow.fwd_packets,
            subflow_bwd_packets: flow.bwd_packets,
            subflow_fwd_bytes: flow.fwd_bytes,
            subflow_bwd_bytes: flow.bwd_bytes,
            active_mean_us: 0.0, // TODO: implement active/idle detection
            active_std_us: 0.0,
            idle_mean_us: 0.0,
            idle_std_us: 0.0,
        }
    }

    /// Convert to feature vector for ML
    pub fn to_feature_vector(&self) -> Vec<f32> {
        vec![
            self.duration_us as f32,
            self.total_fwd_packets as f32,
            self.total_bwd_packets as f32,
            self.total_fwd_bytes as f32,
            self.total_bwd_bytes as f32,
            self.fwd_pkt_len_min as f32,
            self.fwd_pkt_len_max as f32,
            self.fwd_pkt_len_mean,
            self.fwd_pkt_len_std,
            self.bwd_pkt_len_min as f32,
            self.bwd_pkt_len_max as f32,
            self.bwd_pkt_len_mean,
            self.bwd_pkt_len_std,
            self.flow_bytes_per_sec,
            self.flow_packets_per_sec,
            self.fwd_iat_mean_us,
            self.fwd_iat_std_us,
            self.fwd_iat_min_us as f32,
            self.fwd_iat_max_us as f32,
            self.bwd_iat_mean_us,
            self.bwd_iat_std_us,
            self.bwd_iat_min_us as f32,
            self.bwd_iat_max_us as f32,
            self.syn_flag_count as f32,
            self.fin_flag_count as f32,
            self.rst_flag_count as f32,
            self.psh_flag_count as f32,
            self.ack_flag_count as f32,
            self.urg_flag_count as f32,
            self.down_up_ratio,
            self.fwd_packets_per_sec,
            self.bwd_packets_per_sec,
        ]
    }

    /// Feature names for the vector
    pub fn feature_names() -> Vec<&'static str> {
        vec![
            "duration_us",
            "total_fwd_packets",
            "total_bwd_packets",
            "total_fwd_bytes",
            "total_bwd_bytes",
            "fwd_pkt_len_min",
            "fwd_pkt_len_max",
            "fwd_pkt_len_mean",
            "fwd_pkt_len_std",
            "bwd_pkt_len_min",
            "bwd_pkt_len_max",
            "bwd_pkt_len_mean",
            "bwd_pkt_len_std",
            "flow_bytes_per_sec",
            "flow_packets_per_sec",
            "fwd_iat_mean_us",
            "fwd_iat_std_us",
            "fwd_iat_min_us",
            "fwd_iat_max_us",
            "bwd_iat_mean_us",
            "bwd_iat_std_us",
            "bwd_iat_min_us",
            "bwd_iat_max_us",
            "syn_flag_count",
            "fin_flag_count",
            "rst_flag_count",
            "psh_flag_count",
            "ack_flag_count",
            "urg_flag_count",
            "down_up_ratio",
            "fwd_packets_per_sec",
            "bwd_packets_per_sec",
        ]
    }
}

// Note: compute_stats functions removed - now using StreamingStats

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_flow_creation() {
        let mut pkt = Packet::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpProtocol::Tcp,
        );
        pkt.src_port = 54321;
        pkt.dst_port = 80;
        pkt.tcp_flags = Some(TcpFlags { syn: true, ..Default::default() });
        pkt.raw_len = 64;

        let flow = Flow::new(1, &pkt);

        assert_eq!(flow.client_ip, pkt.src_ip);
        assert_eq!(flow.server_port, 80);
        assert_eq!(flow.state, FlowState::SynSent);
        assert_eq!(flow.fwd_packets, 1);
    }

    #[test]
    fn test_flow_update() {
        let mut pkt1 = Packet::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpProtocol::Tcp,
        );
        pkt1.src_port = 54321;
        pkt1.dst_port = 80;
        pkt1.tcp_flags = Some(TcpFlags { syn: true, ..Default::default() });
        pkt1.raw_len = 64;

        let mut flow = Flow::new(1, &pkt1);

        // SYN-ACK response
        let mut pkt2 = Packet::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpProtocol::Tcp,
        );
        pkt2.src_port = 80;
        pkt2.dst_port = 54321;
        pkt2.tcp_flags = Some(TcpFlags { syn: true, ack: true, ..Default::default() });
        pkt2.raw_len = 64;

        let dir = flow.update(&pkt2);

        assert_eq!(dir, Direction::ToClient);
        assert_eq!(flow.state, FlowState::SynReceived);
        assert_eq!(flow.bwd_packets, 1);
    }

    #[test]
    fn test_flow_stats() {
        let mut pkt = Packet::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpProtocol::Tcp,
        );
        pkt.src_port = 54321;
        pkt.dst_port = 80;
        pkt.raw_len = 100;

        let flow = Flow::new(1, &pkt);
        let stats = flow.stats();

        assert_eq!(stats.total_fwd_packets, 1);
        assert_eq!(stats.total_fwd_bytes, 100);
    }
}
