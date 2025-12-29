//! TCP session tracking and stream reassembly

use crmonban_types::{Packet, TcpInfo, TlsInfo as PacketTlsInfo};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Maximum bytes to buffer per direction
const MAX_BUFFER_SIZE: usize = 1024 * 1024; // 1MB

/// Maximum gap in sequence numbers to buffer
const MAX_SEQ_GAP: u32 = 65535;

/// Session timeout
const SESSION_TIMEOUT_NS: u64 = 120_000_000_000; // 120 seconds

/// TCP connection state
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    /// Initial state, no packets seen
    Closed,
    /// SYN sent, waiting for SYN-ACK
    SynSent,
    /// SYN received (server side)
    SynReceived,
    /// Connection established
    Established,
    /// FIN sent, waiting for ACK
    FinWait1,
    /// FIN sent and ACKed, waiting for FIN from peer
    FinWait2,
    /// Received FIN, sent ACK
    CloseWait,
    /// Sent FIN after receiving FIN
    LastAck,
    /// Both sides sent FIN
    Closing,
    /// Waiting for timeout after close
    TimeWait,
}

impl Default for TcpState {
    fn default() -> Self {
        TcpState::Closed
    }
}

/// Direction of data flow
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Client to server (initiator)
    ClientToServer,
    /// Server to client (responder)
    ServerToClient,
}

/// Unique identifier for a TCP session
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionKey {
    /// Lower IP:port (for consistent ordering)
    pub low: SocketAddr,
    /// Higher IP:port
    pub high: SocketAddr,
}

impl SessionKey {
    pub fn new(a: SocketAddr, b: SocketAddr) -> Self {
        if a < b {
            Self { low: a, high: b }
        } else {
            Self { low: b, high: a }
        }
    }

    pub fn from_packet(src_ip: IpAddr, dst_ip: IpAddr, tcp: &TcpInfo) -> Self {
        let src = SocketAddr::new(src_ip, tcp.src_port);
        let dst = SocketAddr::new(dst_ip, tcp.dst_port);
        Self::new(src, dst)
    }
}

/// Buffer for reassembling out-of-order TCP segments
#[derive(Debug, Default)]
pub struct StreamBuffer {
    /// Expected next sequence number
    next_seq: u32,
    /// Initial sequence number
    initial_seq: Option<u32>,
    /// Reassembled data
    data: Vec<u8>,
    /// Out-of-order segments: seq -> data
    pending: BTreeMap<u32, Vec<u8>>,
    /// Total bytes received
    bytes_received: usize,
}

impl StreamBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the initial sequence number (from SYN)
    pub fn set_initial_seq(&mut self, seq: u32) {
        self.initial_seq = Some(seq);
        self.next_seq = seq.wrapping_add(1); // SYN consumes one sequence number
    }

    /// Add a segment to the buffer
    /// Returns newly available contiguous data
    pub fn add_segment(&mut self, seq: u32, data: &[u8]) -> Option<Vec<u8>> {
        if data.is_empty() {
            return None;
        }

        // Initialize if needed
        if self.initial_seq.is_none() {
            self.initial_seq = Some(seq);
            self.next_seq = seq;
        }

        self.bytes_received += data.len();

        // Check if this is the expected segment
        if seq == self.next_seq {
            // In order - append directly
            self.data.extend_from_slice(data);
            self.next_seq = seq.wrapping_add(data.len() as u32);

            // Try to consume pending segments
            self.consume_pending();

            // Return all available data
            if !self.data.is_empty() {
                let result = std::mem::take(&mut self.data);
                return Some(result);
            }
        } else if self.seq_after(seq, self.next_seq) {
            // Future segment - buffer it if gap is reasonable
            let gap = seq.wrapping_sub(self.next_seq);
            if gap <= MAX_SEQ_GAP && self.pending_size() < MAX_BUFFER_SIZE {
                self.pending.insert(seq, data.to_vec());
            }
        }
        // Else: retransmission or old segment, ignore

        None
    }

    /// Try to consume buffered segments that are now in order
    fn consume_pending(&mut self) {
        while let Some((&seq, _)) = self.pending.first_key_value() {
            if seq == self.next_seq {
                let data = self.pending.remove(&seq).unwrap();
                self.data.extend_from_slice(&data);
                self.next_seq = seq.wrapping_add(data.len() as u32);
            } else if self.seq_before(seq, self.next_seq) {
                // Old segment, remove it
                self.pending.remove(&seq);
            } else {
                // Gap still exists
                break;
            }
        }
    }

    /// Check if seq a is before seq b (handles wraparound)
    fn seq_before(&self, a: u32, b: u32) -> bool {
        let diff = b.wrapping_sub(a);
        diff > 0 && diff < (1 << 31)
    }

    /// Check if seq a is after seq b (handles wraparound)
    fn seq_after(&self, a: u32, b: u32) -> bool {
        self.seq_before(b, a)
    }

    fn pending_size(&self) -> usize {
        self.pending.values().map(|v| v.len()).sum()
    }

    pub fn bytes_received(&self) -> usize {
        self.bytes_received
    }

    pub fn has_gaps(&self) -> bool {
        !self.pending.is_empty()
    }
}

/// Statistics for a single direction of a session
#[derive(Debug, Default)]
pub struct DirectionStats {
    /// Number of packets
    pub packets: usize,
    /// Total bytes (payload)
    pub bytes: usize,
    /// Number of retransmissions detected
    pub retransmissions: usize,
    /// Number of out-of-order packets
    pub out_of_order: usize,
    /// Window sizes seen
    pub window_sizes: Vec<u16>,
}

/// A tracked TCP session
#[derive(Debug)]
pub struct TcpSession {
    /// Session key
    pub key: SessionKey,
    /// Client (initiator) address
    pub client: SocketAddr,
    /// Server (responder) address
    pub server: SocketAddr,
    /// Current TCP state
    pub state: TcpState,
    /// Client to server stream buffer
    pub client_buffer: StreamBuffer,
    /// Server to client stream buffer
    pub server_buffer: StreamBuffer,
    /// Client to server stats
    pub client_stats: DirectionStats,
    /// Server to client stats
    pub server_stats: DirectionStats,
    /// First packet timestamp
    pub start_time_ns: u64,
    /// Last packet timestamp
    pub last_time_ns: u64,
    /// Parsed TLS info (if TLS detected)
    pub tls_info: Option<PacketTlsInfo>,
    /// All SNIs seen in this session
    pub snis: Vec<String>,
    /// Session terminated (FIN/RST seen)
    pub terminated: bool,
}

impl TcpSession {
    pub fn new(key: SessionKey, client: SocketAddr, server: SocketAddr, timestamp_ns: u64) -> Self {
        Self {
            key,
            client,
            server,
            state: TcpState::Closed,
            client_buffer: StreamBuffer::new(),
            server_buffer: StreamBuffer::new(),
            client_stats: DirectionStats::default(),
            server_stats: DirectionStats::default(),
            start_time_ns: timestamp_ns,
            last_time_ns: timestamp_ns,
            tls_info: None,
            snis: Vec::new(),
            terminated: false,
        }
    }

    /// Process a packet belonging to this session
    pub fn process_packet(&mut self, packet: &Packet) -> Option<SessionEvent> {
        let tcp = packet.layer4.as_tcp()?;
        let src = SocketAddr::new(packet.src_ip(), tcp.src_port);

        self.last_time_ns = packet.timestamp_ns();

        let direction = if src == self.client {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };

        // Update stats
        let stats = match direction {
            Direction::ClientToServer => &mut self.client_stats,
            Direction::ServerToClient => &mut self.server_stats,
        };
        stats.packets += 1;
        stats.bytes += packet.payload_len();
        stats.window_sizes.push(tcp.window);

        // Handle state transitions
        let event = self.handle_tcp_flags(tcp, direction);

        // Handle data reassembly
        if packet.payload_len() > 0 && self.state == TcpState::Established {
            let buffer = match direction {
                Direction::ClientToServer => &mut self.client_buffer,
                Direction::ServerToClient => &mut self.server_buffer,
            };

            if let Some(data) = buffer.add_segment(tcp.seq, &tcp.payload) {
                // Data reassembled
                let _ = data;
            }

            // Try to parse TLS from packet's existing TLS info
            if self.tls_info.is_none() {
                if let Some(ref tls) = packet.tls {
                    self.tls_info = Some(tls.clone());
                    if let Some(ref sni) = tls.sni {
                        if !self.snis.contains(sni) {
                            self.snis.push(sni.clone());
                        }
                    }
                }
            }
        }

        event
    }

    fn handle_tcp_flags(&mut self, tcp: &TcpInfo, direction: Direction) -> Option<SessionEvent> {
        let flags = &tcp.flags;

        // Handle RST - immediate termination
        if flags.rst {
            self.state = TcpState::Closed;
            self.terminated = true;
            return Some(SessionEvent::Reset);
        }

        // State machine
        match self.state {
            TcpState::Closed => {
                if flags.syn && !flags.ack {
                    self.state = TcpState::SynSent;
                    self.client_buffer.set_initial_seq(tcp.seq);
                    return Some(SessionEvent::SynSent);
                }
            }
            TcpState::SynSent => {
                if flags.syn && flags.ack && direction == Direction::ServerToClient {
                    self.state = TcpState::SynReceived;
                    self.server_buffer.set_initial_seq(tcp.seq);
                    return Some(SessionEvent::SynAckReceived);
                }
            }
            TcpState::SynReceived => {
                if flags.ack && !flags.syn && direction == Direction::ClientToServer {
                    self.state = TcpState::Established;
                    return Some(SessionEvent::Established);
                }
            }
            TcpState::Established => {
                if flags.fin {
                    self.state = if direction == Direction::ClientToServer {
                        TcpState::FinWait1
                    } else {
                        TcpState::CloseWait
                    };
                    return Some(SessionEvent::FinSent);
                }
            }
            TcpState::FinWait1 => {
                if flags.ack && !flags.fin {
                    self.state = TcpState::FinWait2;
                } else if flags.fin {
                    self.state = TcpState::Closing;
                }
            }
            TcpState::FinWait2 => {
                if flags.fin {
                    self.state = TcpState::TimeWait;
                    self.terminated = true;
                    return Some(SessionEvent::Closed);
                }
            }
            TcpState::CloseWait => {
                if flags.fin {
                    self.state = TcpState::LastAck;
                }
            }
            TcpState::LastAck => {
                if flags.ack {
                    self.state = TcpState::Closed;
                    self.terminated = true;
                    return Some(SessionEvent::Closed);
                }
            }
            TcpState::Closing => {
                if flags.ack {
                    self.state = TcpState::TimeWait;
                    self.terminated = true;
                    return Some(SessionEvent::Closed);
                }
            }
            TcpState::TimeWait => {
                // Already closed
            }
        }

        None
    }

    /// Check if session has timed out
    pub fn is_expired(&self, current_time_ns: u64) -> bool {
        current_time_ns.saturating_sub(self.last_time_ns) > SESSION_TIMEOUT_NS
    }

    /// Get session duration in milliseconds
    pub fn duration_ms(&self) -> u64 {
        (self.last_time_ns - self.start_time_ns) / 1_000_000
    }

    /// Total bytes transferred
    pub fn total_bytes(&self) -> usize {
        self.client_stats.bytes + self.server_stats.bytes
    }

    /// Total packets
    pub fn total_packets(&self) -> usize {
        self.client_stats.packets + self.server_stats.packets
    }

    /// Check if this looks like a scan (SYN without completion)
    pub fn is_scan_like(&self) -> bool {
        matches!(self.state, TcpState::SynSent | TcpState::SynReceived)
            && self.client_stats.packets <= 2
    }

    /// Check if connection completed handshake
    pub fn handshake_complete(&self) -> bool {
        matches!(
            self.state,
            TcpState::Established
                | TcpState::FinWait1
                | TcpState::FinWait2
                | TcpState::CloseWait
                | TcpState::LastAck
                | TcpState::Closing
                | TcpState::TimeWait
                | TcpState::Closed
        ) && self.client_stats.packets >= 3
    }
}

/// Events emitted during session processing
#[derive(Clone, Debug)]
pub enum SessionEvent {
    /// New session created
    NewSession(SessionKey),
    /// SYN sent
    SynSent,
    /// SYN-ACK received
    SynAckReceived,
    /// Connection established
    Established,
    /// FIN sent
    FinSent,
    /// Connection closed normally
    Closed,
    /// Connection reset
    Reset,
    /// TLS ClientHello seen
    TlsClientHello { sni: Option<String> },
    /// Session expired
    Expired(SessionKey),
    /// Data reassembled
    DataReassembled { direction: Direction, len: usize },
}

/// Manages all TCP sessions
pub struct SessionTracker {
    /// Active sessions
    sessions: HashMap<SessionKey, TcpSession>,
    /// Maximum concurrent sessions
    max_sessions: usize,
    /// Session timeout
    timeout_ns: u64,
    /// Events queue (reserved for future async use)
    #[allow(dead_code)]
    events: VecDeque<SessionEvent>,
}

impl SessionTracker {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::with_capacity(max_sessions.min(10000)),
            max_sessions,
            timeout_ns: SESSION_TIMEOUT_NS,
            events: VecDeque::new(),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout_ns = timeout.as_nanos() as u64;
        self
    }

    /// Process a packet
    pub fn process_packet(&mut self, packet: &Packet) -> Vec<SessionEvent> {
        let tcp = match packet.layer4.as_tcp() {
            Some(t) => t,
            None => return Vec::new(),
        };

        let key = SessionKey::from_packet(packet.src_ip(), packet.dst_ip(), tcp);
        let src = SocketAddr::new(packet.src_ip(), tcp.src_port);
        let dst = SocketAddr::new(packet.dst_ip(), tcp.dst_port);

        let mut events = Vec::new();

        // Get or create session
        let session = if let Some(session) = self.sessions.get_mut(&key) {
            session
        } else {
            // New session - only create on SYN
            if !tcp.flags.syn || tcp.flags.ack {
                return events;
            }

            // Enforce max sessions
            if self.sessions.len() >= self.max_sessions {
                // Remove oldest/expired sessions
                self.cleanup_sessions(packet.timestamp_ns());
                if self.sessions.len() >= self.max_sessions {
                    return events;
                }
            }

            // Create new session
            let session = TcpSession::new(key, src, dst, packet.timestamp_ns());
            events.push(SessionEvent::NewSession(key));
            self.sessions.entry(key).or_insert(session)
        };

        // Process packet
        if let Some(event) = session.process_packet(packet) {
            // Check for TLS
            if let Some(ref tls) = packet.tls {
                if tls.handshake_type == Some(0x01) {
                    let sni = tls.sni.clone();
                    events.push(SessionEvent::TlsClientHello { sni });
                }
            }
            events.push(event);
        }

        events
    }

    /// Clean up expired sessions
    pub fn cleanup_sessions(&mut self, current_time_ns: u64) -> Vec<SessionEvent> {
        let mut events = Vec::new();
        let expired: Vec<SessionKey> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_expired(current_time_ns) || s.terminated)
            .map(|(k, _)| *k)
            .collect();

        for key in expired {
            self.sessions.remove(&key);
            events.push(SessionEvent::Expired(key));
        }

        events
    }

    /// Get a session by key
    pub fn get_session(&self, key: &SessionKey) -> Option<&TcpSession> {
        self.sessions.get(key)
    }

    /// Get all sessions for analysis
    pub fn sessions(&self) -> impl Iterator<Item = &TcpSession> {
        self.sessions.values()
    }

    /// Number of active sessions
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get session statistics
    pub fn stats(&self) -> SessionTrackerStats {
        let mut stats = SessionTrackerStats::default();
        stats.total_sessions = self.sessions.len();

        for session in self.sessions.values() {
            match session.state {
                TcpState::Established => stats.established += 1,
                TcpState::SynSent | TcpState::SynReceived => stats.half_open += 1,
                TcpState::Closed => stats.closed += 1,
                _ => stats.closing += 1,
            }

            if session.tls_info.is_some() {
                stats.tls_sessions += 1;
            }
        }

        stats
    }
}

/// Statistics from session tracker
#[derive(Clone, Debug, Default)]
pub struct SessionTrackerStats {
    pub total_sessions: usize,
    pub established: usize,
    pub half_open: usize,
    pub closing: usize,
    pub closed: usize,
    pub tls_sessions: usize,
}

/// Extract features from session data
pub fn extract_session_features(sessions: &[&TcpSession]) -> [f32; 16] {
    let mut features = [0.0f32; 16];

    if sessions.is_empty() {
        return features;
    }

    let total = sessions.len() as f32;

    // 0: Established ratio
    let established = sessions.iter().filter(|s| s.handshake_complete()).count();
    features[0] = established as f32 / total;

    // 1: Half-open ratio (scan indicator)
    let half_open = sessions.iter().filter(|s| s.is_scan_like()).count();
    features[1] = half_open as f32 / total;

    // 2: Reset ratio
    let resets = sessions.iter().filter(|s| s.state == TcpState::Closed && s.terminated).count();
    features[2] = resets as f32 / total;

    // 3: TLS ratio
    let tls_count = sessions.iter().filter(|s| s.tls_info.is_some()).count();
    features[3] = tls_count as f32 / total;

    // 4: Average session duration (normalized to 0-1, assuming max 60s)
    let avg_duration: f32 = sessions.iter().map(|s| s.duration_ms() as f32).sum::<f32>() / total;
    features[4] = (avg_duration / 60000.0).min(1.0);

    // 5: Average bytes per session (normalized)
    let avg_bytes: f32 = sessions.iter().map(|s| s.total_bytes() as f32).sum::<f32>() / total;
    features[5] = (avg_bytes / 10000.0).min(1.0);

    // 6: Client/server byte ratio
    let client_bytes: usize = sessions.iter().map(|s| s.client_stats.bytes).sum();
    let server_bytes: usize = sessions.iter().map(|s| s.server_stats.bytes).sum();
    features[6] = if server_bytes > 0 {
        (client_bytes as f32 / server_bytes as f32).min(10.0) / 10.0
    } else {
        1.0
    };

    // 7: Unique SNI count (normalized)
    let mut all_snis: Vec<&String> = sessions.iter().flat_map(|s| &s.snis).collect();
    all_snis.sort();
    all_snis.dedup();
    features[7] = (all_snis.len() as f32 / 100.0).min(1.0);

    // 8: Sessions with SNI ratio
    let with_sni = sessions.iter().filter(|s| !s.snis.is_empty()).count();
    features[8] = with_sni as f32 / total;

    // 9: Average packets per session
    let avg_packets: f32 = sessions.iter().map(|s| s.total_packets() as f32).sum::<f32>() / total;
    features[9] = (avg_packets / 100.0).min(1.0);

    // 10: Single-packet session ratio (port scan indicator)
    let single_packet = sessions.iter().filter(|s| s.total_packets() <= 2).count();
    features[10] = single_packet as f32 / total;

    // 11: Server port diversity
    let server_ports: std::collections::HashSet<u16> = sessions.iter().map(|s| s.server.port()).collect();
    features[11] = (server_ports.len() as f32 / 100.0).min(1.0);

    // 12: Common port ratio (22, 23, 80, 443, 3389, etc.)
    let common_ports = [22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080];
    let common_count = sessions.iter().filter(|s| common_ports.contains(&s.server.port())).count();
    features[12] = common_count as f32 / total;

    // 13: TLS without SNI ratio (suspicious)
    let tls_no_sni = sessions.iter().filter(|s| s.tls_info.is_some() && s.snis.is_empty()).count();
    features[13] = if tls_count > 0 {
        tls_no_sni as f32 / tls_count as f32
    } else {
        0.0
    };

    // 14: Session rate (sessions per second, normalized)
    if sessions.len() > 1 {
        let first_time = sessions.iter().map(|s| s.start_time_ns).min().unwrap_or(0);
        let last_time = sessions.iter().map(|s| s.last_time_ns).max().unwrap_or(0);
        let duration_s = (last_time - first_time) as f64 / 1_000_000_000.0;
        if duration_s > 0.0 {
            features[14] = (sessions.len() as f32 / duration_s as f32 / 100.0).min(1.0);
        }
    }

    // 15: Retransmission ratio (not fully implemented without payload tracking)
    features[15] = 0.0;

    features
}

#[cfg(test)]
mod tests {
    use super::*;
    use crmonban_types::{Ipv4Info, Layer3, Layer4, TcpFlags};
    use chrono::{TimeZone, Utc};
    use std::net::Ipv4Addr;

    fn make_tcp_packet(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        flags: TcpFlags,
        seq: u32,
        timestamp_ns: u64,
    ) -> Packet {
        let (src_addr, dst_addr) = match (src_ip, dst_ip) {
            (IpAddr::V4(s), IpAddr::V4(d)) => (s, d),
            _ => (Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED),
        };

        Packet {
            timestamp: Utc.timestamp_nanos(timestamp_ns as i64),
            layer3: Layer3::Ipv4(Ipv4Info {
                src_addr,
                dst_addr,
                protocol: 6,
                ..Default::default()
            }),
            layer4: Layer4::Tcp(TcpInfo {
                src_port,
                dst_port,
                seq,
                ack: 0,
                flags,
                window: 65535,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_session_key_ordering() {
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 1000);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)), 80);

        let key1 = SessionKey::new(a, b);
        let key2 = SessionKey::new(b, a);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_session_handshake() {
        let mut tracker = SessionTracker::new(1000);

        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let server_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // SYN
        let syn = make_tcp_packet(
            client_ip,
            server_ip,
            50000,
            443,
            TcpFlags { syn: true, ..Default::default() },
            1000,
            0,
        );
        let events = tracker.process_packet(&syn);
        assert!(events.iter().any(|e| matches!(e, SessionEvent::NewSession(_))));
        assert!(events.iter().any(|e| matches!(e, SessionEvent::SynSent)));

        // SYN-ACK
        let syn_ack = make_tcp_packet(
            server_ip,
            client_ip,
            443,
            50000,
            TcpFlags { syn: true, ack: true, ..Default::default() },
            2000,
            1_000_000,
        );
        let events = tracker.process_packet(&syn_ack);
        assert!(events.iter().any(|e| matches!(e, SessionEvent::SynAckReceived)));

        // ACK
        let ack = make_tcp_packet(
            client_ip,
            server_ip,
            50000,
            443,
            TcpFlags { ack: true, ..Default::default() },
            1001,
            2_000_000,
        );
        let events = tracker.process_packet(&ack);
        assert!(events.iter().any(|e| matches!(e, SessionEvent::Established)));

        // Verify session state
        assert_eq!(tracker.session_count(), 1);
        let stats = tracker.stats();
        assert_eq!(stats.established, 1);
    }

    #[test]
    fn test_stream_buffer() {
        let mut buffer = StreamBuffer::new();
        buffer.set_initial_seq(100);

        // In-order segment
        let data = buffer.add_segment(101, b"hello");
        assert!(data.is_some());
        assert_eq!(data.unwrap(), b"hello");

        // Out-of-order segment (should be buffered)
        let data = buffer.add_segment(111, b"world");
        assert!(data.is_none());

        // Fill the gap
        let data = buffer.add_segment(106, b"_____");
        assert!(data.is_some());
        assert_eq!(data.unwrap(), b"_____world");
    }

    #[test]
    fn test_scan_detection() {
        let mut tracker = SessionTracker::new(1000);

        let client_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let server_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Create multiple SYN-only sessions (scan pattern)
        for port in 1..100 {
            let syn = make_tcp_packet(
                client_ip,
                server_ip,
                50000,
                port,
                TcpFlags { syn: true, ..Default::default() },
                1000,
                port as u64 * 1_000_000,
            );
            tracker.process_packet(&syn);
        }

        let stats = tracker.stats();
        assert_eq!(stats.half_open, 99);
        assert_eq!(stats.established, 0);
    }
}
