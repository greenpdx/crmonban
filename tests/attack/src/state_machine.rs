//! TCP State Machine for stateful packet generation
//!
//! Maintains TCP connection state to generate realistic packet sequences.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use rand::Rng;

/// TCP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

/// TCP flags
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
    pub fn syn() -> Self {
        Self { syn: true, ..Default::default() }
    }

    pub fn syn_ack() -> Self {
        Self { syn: true, ack: true, ..Default::default() }
    }

    pub fn ack() -> Self {
        Self { ack: true, ..Default::default() }
    }

    pub fn fin_ack() -> Self {
        Self { fin: true, ack: true, ..Default::default() }
    }

    pub fn rst() -> Self {
        Self { rst: true, ..Default::default() }
    }

    pub fn rst_ack() -> Self {
        Self { rst: true, ack: true, ..Default::default() }
    }

    pub fn psh_ack() -> Self {
        Self { psh: true, ack: true, ..Default::default() }
    }

    /// NULL scan - no flags
    pub fn null() -> Self {
        Self::default()
    }

    /// Xmas scan - FIN, PSH, URG
    pub fn xmas() -> Self {
        Self { fin: true, psh: true, urg: true, ..Default::default() }
    }

    /// FIN scan
    pub fn fin() -> Self {
        Self { fin: true, ..Default::default() }
    }

    /// Convert to u8 for packet building
    pub fn to_u8(&self) -> u8 {
        let mut flags = 0u8;
        if self.fin { flags |= 0x01; }
        if self.syn { flags |= 0x02; }
        if self.rst { flags |= 0x04; }
        if self.psh { flags |= 0x08; }
        if self.ack { flags |= 0x10; }
        if self.urg { flags |= 0x20; }
        if self.ece { flags |= 0x40; }
        if self.cwr { flags |= 0x80; }
        flags
    }

    /// Create from u8
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
}

/// Connection key for tracking
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ConnectionKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl ConnectionKey {
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        Self { src, dst }
    }

    /// Get the reverse connection key
    pub fn reverse(&self) -> Self {
        Self { src: self.dst, dst: self.src }
    }
}

/// Connection tracking entry
#[derive(Debug, Clone)]
pub struct Connection {
    pub state: TcpState,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub packets_sent: u64,
    pub bytes_sent: u64,
}

impl Default for Connection {
    fn default() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            state: TcpState::Closed,
            seq: rng.gen(),
            ack: 0,
            window: 65535,
            packets_sent: 0,
            bytes_sent: 0,
        }
    }
}

impl Connection {
    /// Advance sequence number
    pub fn advance_seq(&mut self, bytes: u32) {
        self.seq = self.seq.wrapping_add(bytes);
    }

    /// Set ack to received seq + 1
    pub fn set_ack(&mut self, remote_seq: u32) {
        self.ack = remote_seq.wrapping_add(1);
    }
}

/// TCP State Machine for generating realistic sequences
pub struct TcpStateMachine {
    connections: HashMap<ConnectionKey, Connection>,
}

impl Default for TcpStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpStateMachine {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    /// Get or create a connection
    pub fn get_connection(&mut self, key: &ConnectionKey) -> &mut Connection {
        self.connections.entry(key.clone()).or_insert_with(Connection::default)
    }

    /// Generate SYN packet for new connection
    pub fn start_handshake(&mut self, src: SocketAddr, dst: SocketAddr) -> (u32, u32, TcpFlags) {
        let key = ConnectionKey::new(src, dst);
        let conn = self.get_connection(&key);
        conn.state = TcpState::SynSent;
        let seq = conn.seq;
        conn.advance_seq(1); // SYN consumes 1 seq
        (seq, 0, TcpFlags::syn())
    }

    /// Generate SYN-ACK response
    pub fn respond_syn(&mut self, src: SocketAddr, dst: SocketAddr, remote_seq: u32) -> (u32, u32, TcpFlags) {
        let key = ConnectionKey::new(src, dst);
        let conn = self.get_connection(&key);
        conn.state = TcpState::SynReceived;
        conn.set_ack(remote_seq);
        let seq = conn.seq;
        conn.advance_seq(1);
        (seq, conn.ack, TcpFlags::syn_ack())
    }

    /// Complete handshake with ACK
    pub fn complete_handshake(&mut self, src: SocketAddr, dst: SocketAddr, remote_seq: u32) -> (u32, u32, TcpFlags) {
        let key = ConnectionKey::new(src, dst);
        let conn = self.get_connection(&key);
        conn.state = TcpState::Established;
        conn.set_ack(remote_seq);
        (conn.seq, conn.ack, TcpFlags::ack())
    }

    /// Send data packet
    pub fn send_data(&mut self, src: SocketAddr, dst: SocketAddr, data_len: u32) -> (u32, u32, TcpFlags) {
        let key = ConnectionKey::new(src, dst);
        let conn = self.get_connection(&key);
        let seq = conn.seq;
        conn.advance_seq(data_len);
        conn.packets_sent += 1;
        conn.bytes_sent += data_len as u64;
        (seq, conn.ack, TcpFlags::psh_ack())
    }

    /// Acknowledge data
    pub fn ack_data(&mut self, src: SocketAddr, dst: SocketAddr, remote_seq: u32, data_len: u32) -> (u32, u32, TcpFlags) {
        let key = ConnectionKey::new(src, dst);
        let conn = self.get_connection(&key);
        conn.ack = remote_seq.wrapping_add(data_len);
        (conn.seq, conn.ack, TcpFlags::ack())
    }

    /// Start connection close
    pub fn start_close(&mut self, src: SocketAddr, dst: SocketAddr) -> (u32, u32, TcpFlags) {
        let key = ConnectionKey::new(src, dst);
        let conn = self.get_connection(&key);
        conn.state = TcpState::FinWait1;
        let seq = conn.seq;
        conn.advance_seq(1); // FIN consumes 1 seq
        (seq, conn.ack, TcpFlags::fin_ack())
    }

    /// Send RST to abort
    pub fn reset(&mut self, src: SocketAddr, dst: SocketAddr) -> (u32, u32, TcpFlags) {
        let key = ConnectionKey::new(src, dst);
        let conn = self.get_connection(&key);
        conn.state = TcpState::Closed;
        (conn.seq, conn.ack, TcpFlags::rst_ack())
    }

    /// Remove a connection
    pub fn remove(&mut self, key: &ConnectionKey) {
        self.connections.remove(key);
    }

    /// Get connection count
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Clear all connections
    pub fn clear(&mut self) {
        self.connections.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags() {
        let syn = TcpFlags::syn();
        assert_eq!(syn.to_u8(), 0x02);

        let syn_ack = TcpFlags::syn_ack();
        assert_eq!(syn_ack.to_u8(), 0x12);

        let xmas = TcpFlags::xmas();
        assert_eq!(xmas.to_u8(), 0x29); // FIN + PSH + URG
    }

    #[test]
    fn test_handshake() {
        let mut sm = TcpStateMachine::new();
        let src: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let dst: SocketAddr = "10.0.0.1:80".parse().unwrap();

        // Client sends SYN
        let (seq1, _, flags1) = sm.start_handshake(src, dst);
        assert!(flags1.syn);
        assert!(!flags1.ack);

        // Server responds SYN-ACK
        let (seq2, ack2, flags2) = sm.respond_syn(dst, src, seq1);
        assert!(flags2.syn);
        assert!(flags2.ack);
        assert_eq!(ack2, seq1.wrapping_add(1));

        // Client sends ACK
        let (_, ack3, flags3) = sm.complete_handshake(src, dst, seq2);
        assert!(!flags3.syn);
        assert!(flags3.ack);
        assert_eq!(ack3, seq2.wrapping_add(1));
    }
}
