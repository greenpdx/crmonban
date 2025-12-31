//! TCP Attack Detection
//!
//! Detects TCP-based attacks:
//! - RST injection: Spoofed RST packets to terminate connections
//! - Session hijacking: Sequence number jumps indicating injection
//! - SYN-ACK reflection: Spoofed SYN causing SYN-ACK flood to victim

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::layer234::ThreatType;

/// TCP session state for attack detection
#[derive(Debug, Clone)]
pub struct TcpSessionState {
    /// Expected next sequence number (client -> server)
    pub client_next_seq: u32,
    /// Expected next sequence number (server -> client)
    pub server_next_seq: u32,
    /// Last seen sequence (client)
    pub client_last_seq: u32,
    /// Last seen sequence (server)
    pub server_last_seq: u32,
    /// Window size (client)
    pub client_window: u16,
    /// Window size (server)
    pub server_window: u16,
    /// Session established
    pub established: bool,
    /// RST count seen
    pub rst_count: u32,
    /// Last activity
    pub last_seen: Instant,
    /// Sequence anomalies detected
    pub seq_anomalies: u32,
}

impl TcpSessionState {
    pub fn new() -> Self {
        Self {
            client_next_seq: 0,
            server_next_seq: 0,
            client_last_seq: 0,
            server_last_seq: 0,
            client_window: 0,
            server_window: 0,
            established: false,
            rst_count: 0,
            last_seen: Instant::now(),
            seq_anomalies: 0,
        }
    }
}

impl Default for TcpSessionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Flow key for TCP session tracking
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct TcpFlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl TcpFlowKey {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16) -> Self {
        Self { src_ip, dst_ip, src_port, dst_port }
    }

    /// Get the reverse direction key
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }

    /// Normalize to canonical form (lower IP:port first)
    pub fn canonical(&self) -> (Self, bool) {
        let self_tuple = (self.src_ip, self.src_port);
        let rev_tuple = (self.dst_ip, self.dst_port);

        if format!("{:?}", self_tuple) < format!("{:?}", rev_tuple) {
            (*self, true)
        } else {
            (self.reverse(), false)
        }
    }
}

impl std::fmt::Display for TcpFlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{} -> {}:{}",
            self.src_ip, self.src_port,
            self.dst_ip, self.dst_port
        )
    }
}

/// SYN-ACK tracking for reflection detection
#[derive(Debug, Clone)]
struct SynAckTracker {
    /// Count of SYN-ACKs per destination
    counts: HashMap<IpAddr, u64>,
    /// Window start
    window_start: Instant,
}

/// TCP Attack Tracker
#[derive(Debug)]
pub struct TcpAttackTracker {
    /// Tracked TCP sessions
    sessions: HashMap<TcpFlowKey, TcpSessionState>,
    /// SYN-ACK reflection tracking
    synack_tracker: SynAckTracker,
    /// Configuration
    config: TcpAttackConfig,
    /// Statistics
    stats: TcpAttackStats,
    /// Last cleanup
    last_cleanup: Instant,
}

#[derive(Debug, Clone)]
pub struct TcpAttackConfig {
    /// Maximum sequence number jump before flagging as anomaly
    pub max_seq_jump: u32,
    /// Maximum RST packets per session before flagging
    pub max_rst_per_session: u32,
    /// SYN-ACK reflection threshold (per second to single target)
    pub synack_reflection_threshold: f32,
    /// Session timeout (seconds)
    pub session_timeout_secs: u64,
    /// Maximum tracked sessions
    pub max_sessions: usize,
    /// Rate window for SYN-ACK tracking
    pub rate_window_secs: u64,
}

impl Default for TcpAttackConfig {
    fn default() -> Self {
        Self {
            max_seq_jump: 1_000_000,          // 1MB jump is suspicious
            max_rst_per_session: 3,           // Multiple RSTs suspicious
            synack_reflection_threshold: 100.0, // 100 SYN-ACKs/sec to same target
            session_timeout_secs: 120,
            max_sessions: 100000,
            rate_window_secs: 10,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct TcpAttackStats {
    pub total_packets: u64,
    pub sessions_tracked: u64,
    pub rst_injections: u64,
    pub session_hijacks: u64,
    pub synack_reflections: u64,
    pub seq_anomalies: u64,
}

impl Default for TcpAttackTracker {
    fn default() -> Self {
        Self::new(TcpAttackConfig::default())
    }
}

impl TcpAttackTracker {
    pub fn new(config: TcpAttackConfig) -> Self {
        Self {
            sessions: HashMap::new(),
            synack_tracker: SynAckTracker {
                counts: HashMap::new(),
                window_start: Instant::now(),
            },
            config,
            stats: TcpAttackStats::default(),
            last_cleanup: Instant::now(),
        }
    }

    /// Process a TCP packet and detect attacks
    pub fn process_tcp(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        window: u16,
        payload_len: u16,
    ) -> Vec<ThreatType> {
        let mut threats = Vec::new();
        self.stats.total_packets += 1;

        // Periodic cleanup
        if self.last_cleanup.elapsed() > Duration::from_secs(30) {
            self.cleanup_expired();
            self.last_cleanup = Instant::now();
        }

        let flow_key = TcpFlowKey::new(src_ip, dst_ip, src_port, dst_port);

        // Handle SYN-ACK (potential reflection attack)
        if flags.syn && flags.ack && !flags.rst {
            if let Some(threat) = self.check_synack_reflection(dst_ip) {
                threats.push(threat);
            }
        }

        // Handle RST
        if flags.rst {
            if let Some(threat) = self.check_rst_injection(&flow_key, seq) {
                threats.push(threat);
            }
        }

        // Track session state for established connections
        if !flags.syn || flags.ack {
            if let Some(threat) = self.track_session(&flow_key, seq, ack, flags, window, payload_len) {
                threats.push(threat);
            }
        }

        // Handle new SYN (connection initiation)
        if flags.syn && !flags.ack {
            self.init_session(&flow_key, seq);
        }

        threats
    }

    /// Initialize a new session on SYN
    fn init_session(&mut self, flow_key: &TcpFlowKey, seq: u32) {
        if self.sessions.len() >= self.config.max_sessions {
            self.cleanup_oldest();
        }

        let mut state = TcpSessionState::new();
        state.client_next_seq = seq.wrapping_add(1);
        state.client_last_seq = seq;
        self.sessions.insert(*flow_key, state);
        self.stats.sessions_tracked += 1;
    }

    /// Track session and detect sequence anomalies
    fn track_session(
        &mut self,
        flow_key: &TcpFlowKey,
        seq: u32,
        ack: u32,
        flags: TcpFlags,
        window: u16,
        payload_len: u16,
    ) -> Option<ThreatType> {
        // Check forward direction
        if let Some(state) = self.sessions.get_mut(flow_key) {
            state.last_seen = Instant::now();

            // Check for sequence number jump (potential hijacking)
            if state.established {
                let expected = state.client_next_seq;
                let delta = seq_distance(seq, expected);

                if delta > self.config.max_seq_jump {
                    state.seq_anomalies += 1;
                    self.stats.seq_anomalies += 1;

                    if state.seq_anomalies >= 2 {
                        self.stats.session_hijacks += 1;
                        return Some(ThreatType::TcpSessionHijack {
                            flow: flow_key.to_string(),
                            seq_jump: delta,
                        });
                    }
                }
            }

            // Update expected sequence
            state.client_last_seq = seq;
            state.client_next_seq = seq.wrapping_add(payload_len as u32);
            if flags.syn || flags.fin {
                state.client_next_seq = state.client_next_seq.wrapping_add(1);
            }
            state.client_window = window;

            // Mark as established after seeing ACK to SYN-ACK
            if flags.ack && !state.established {
                state.established = true;
            }

            return None;
        }

        // Check reverse direction
        let rev_key = flow_key.reverse();
        if let Some(state) = self.sessions.get_mut(&rev_key) {
            state.last_seen = Instant::now();

            // This is a response, track server sequence
            if state.established {
                let expected = state.server_next_seq;
                let delta = seq_distance(seq, expected);

                if delta > self.config.max_seq_jump && state.server_next_seq != 0 {
                    state.seq_anomalies += 1;
                    self.stats.seq_anomalies += 1;

                    if state.seq_anomalies >= 2 {
                        self.stats.session_hijacks += 1;
                        return Some(ThreatType::TcpSessionHijack {
                            flow: rev_key.to_string(),
                            seq_jump: delta,
                        });
                    }
                }
            }

            state.server_last_seq = seq;
            state.server_next_seq = seq.wrapping_add(payload_len as u32);
            if flags.syn || flags.fin {
                state.server_next_seq = state.server_next_seq.wrapping_add(1);
            }
            state.server_window = window;

            // SYN-ACK received
            if flags.syn && flags.ack {
                state.server_next_seq = seq.wrapping_add(1);
            }
        }

        None
    }

    /// Check for RST injection attack
    fn check_rst_injection(&mut self, flow_key: &TcpFlowKey, seq: u32) -> Option<ThreatType> {
        // Check if we have a session for this flow
        let (state, is_forward) = if let Some(s) = self.sessions.get_mut(flow_key) {
            (s, true)
        } else if let Some(s) = self.sessions.get_mut(&flow_key.reverse()) {
            (s, false)
        } else {
            // RST for unknown session - could be legitimate or scan
            return None;
        };

        state.rst_count += 1;

        // Check if RST is within expected window
        let expected_seq = if is_forward {
            state.client_next_seq
        } else {
            state.server_next_seq
        };

        let window = if is_forward {
            state.server_window
        } else {
            state.client_window
        };

        // RST should be within window, but attackers may send out-of-window RST
        let delta = seq_distance(seq, expected_seq);

        // If RST is far outside window and we've seen multiple, it's suspicious
        if delta > window as u32 * 2 && state.rst_count > 1 {
            self.stats.rst_injections += 1;
            return Some(ThreatType::TcpRstInjection {
                flow: flow_key.to_string(),
                seq_delta: delta as i64,
            });
        }

        // Multiple RSTs is also suspicious
        if state.rst_count > self.config.max_rst_per_session {
            self.stats.rst_injections += 1;
            return Some(ThreatType::TcpRstInjection {
                flow: flow_key.to_string(),
                seq_delta: 0,
            });
        }

        None
    }

    /// Check for SYN-ACK reflection attack
    fn check_synack_reflection(&mut self, target_ip: IpAddr) -> Option<ThreatType> {
        // Reset window if expired
        if self.synack_tracker.window_start.elapsed()
            > Duration::from_secs(self.config.rate_window_secs)
        {
            self.synack_tracker.counts.clear();
            self.synack_tracker.window_start = Instant::now();
        }

        *self.synack_tracker.counts.entry(target_ip).or_insert(0) += 1;

        let count = self.synack_tracker.counts[&target_ip];
        let elapsed = self.synack_tracker.window_start.elapsed().as_secs_f32().max(0.1);
        let rate = count as f32 / elapsed;

        if rate > self.config.synack_reflection_threshold {
            self.stats.synack_reflections += 1;
            return Some(ThreatType::TcpSynAckReflection {
                target: target_ip.to_string(),
                rate,
            });
        }

        None
    }

    /// Get statistics
    pub fn stats(&self) -> &TcpAttackStats {
        &self.stats
    }

    /// Get feature vector values
    pub fn get_features(&self, total_packets: u64) -> [f32; 4] {
        let total = total_packets.max(1) as f32;
        let tcp_total = self.stats.total_packets.max(1) as f32;

        [
            // TCP_RST_RATIO: RST injections relative to TCP packets
            self.stats.rst_injections as f32 / tcp_total,
            // TCP_SEQ_ANOMALY: Sequence anomalies
            self.stats.seq_anomalies as f32 / tcp_total,
            // TCP_SYNACK_REFLECTION
            self.stats.synack_reflections as f32 / total,
            // TCP_WINDOW_ANOMALY (placeholder)
            0.0,
        ]
    }

    /// Clean up expired sessions
    fn cleanup_expired(&mut self) {
        let timeout = Duration::from_secs(self.config.session_timeout_secs);
        self.sessions.retain(|_, state| state.last_seen.elapsed() < timeout);
    }

    /// Remove oldest sessions when limit exceeded
    fn cleanup_oldest(&mut self) {
        let to_remove = self.sessions.len() / 10;
        let mut entries: Vec<_> = self.sessions.iter()
            .map(|(k, v)| (*k, v.last_seen))
            .collect();
        entries.sort_by_key(|(_, time)| *time);

        for (key, _) in entries.into_iter().take(to_remove) {
            self.sessions.remove(&key);
        }
    }

    /// Get count of active sessions
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }
}

/// Calculate distance between sequence numbers (handling wrap)
fn seq_distance(a: u32, b: u32) -> u32 {
    let forward = a.wrapping_sub(b);
    let backward = b.wrapping_sub(a);
    forward.min(backward)
}

/// TCP flags structure
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    pub fn from_u8(flags: u8) -> Self {
        Self {
            fin: flags & 0x01 != 0,
            syn: flags & 0x02 != 0,
            rst: flags & 0x04 != 0,
            psh: flags & 0x08 != 0,
            ack: flags & 0x10 != 0,
            urg: flags & 0x20 != 0,
            ece: flags & 0x40 != 0,
            cwr: flags & 0x80 != 0,
        }
    }

    pub fn from_u16(flags: u16) -> Self {
        Self::from_u8(flags as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_normal_tcp_handshake() {
        let mut tracker = TcpAttackTracker::default();
        let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // SYN
        let syn = TcpFlags { syn: true, ..Default::default() };
        let threats = tracker.process_tcp(client, server, 12345, 80, 1000, 0, syn, 65535, 0);
        assert!(threats.is_empty());

        // SYN-ACK
        let synack = TcpFlags { syn: true, ack: true, ..Default::default() };
        let threats = tracker.process_tcp(server, client, 80, 12345, 2000, 1001, synack, 65535, 0);
        assert!(threats.is_empty());

        // ACK
        let ack = TcpFlags { ack: true, ..Default::default() };
        let threats = tracker.process_tcp(client, server, 12345, 80, 1001, 2001, ack, 65535, 0);
        assert!(threats.is_empty());
    }

    #[test]
    fn test_rst_injection() {
        let mut tracker = TcpAttackTracker::default();
        let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let server = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Establish connection
        let syn = TcpFlags { syn: true, ..Default::default() };
        tracker.process_tcp(client, server, 12345, 80, 1000, 0, syn, 65535, 0);

        let synack = TcpFlags { syn: true, ack: true, ..Default::default() };
        tracker.process_tcp(server, client, 80, 12345, 2000, 1001, synack, 65535, 0);

        let ack = TcpFlags { ack: true, ..Default::default() };
        tracker.process_tcp(client, server, 12345, 80, 1001, 2001, ack, 65535, 0);

        // Multiple RSTs (suspicious)
        let rst = TcpFlags { rst: true, ..Default::default() };
        tracker.process_tcp(client, server, 12345, 80, 1001, 0, rst, 0, 0);
        tracker.process_tcp(client, server, 12345, 80, 1001, 0, rst, 0, 0);
        tracker.process_tcp(client, server, 12345, 80, 1001, 0, rst, 0, 0);
        let threats = tracker.process_tcp(client, server, 12345, 80, 1001, 0, rst, 0, 0);

        assert!(threats.iter().any(|t| matches!(t, ThreatType::TcpRstInjection { .. })));
    }

    #[test]
    fn test_seq_distance() {
        // Normal case
        assert_eq!(seq_distance(100, 90), 10);
        assert_eq!(seq_distance(90, 100), 10);

        // Wrap case
        assert_eq!(seq_distance(10, u32::MAX - 10), 21);
    }
}
