//! Unified packet representation
//!
//! Represents a network packet with all layers parsed for analysis.
//! Uses strongly-typed layer structs from `layers.rs`.

use std::net::IpAddr;
use std::time::Instant;
use serde::{Deserialize, Serialize};

use super::layers::{
    Layer3, Layer4, Ipv4Info, Ipv6Info,
    TcpInfo, UdpInfo, IcmpInfo, Icmpv6Info,
    EthernetInfo,
};

/// IP protocol numbers
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum IpProtocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Icmpv6 = 58,
    Other(u8),
}

impl From<u8> for IpProtocol {
    fn from(val: u8) -> Self {
        match val {
            1 => IpProtocol::Icmp,
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            58 => IpProtocol::Icmpv6,
            other => IpProtocol::Other(other),
        }
    }
}

impl From<IpProtocol> for u8 {
    fn from(val: IpProtocol) -> Self {
        match val {
            IpProtocol::Icmp => 1,
            IpProtocol::Tcp => 6,
            IpProtocol::Udp => 17,
            IpProtocol::Icmpv6 => 58,
            IpProtocol::Other(v) => v,
        }
    }
}

impl std::fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpProtocol::Icmp => write!(f, "ICMP"),
            IpProtocol::Tcp => write!(f, "TCP"),
            IpProtocol::Udp => write!(f, "UDP"),
            IpProtocol::Icmpv6 => write!(f, "ICMPv6"),
            IpProtocol::Other(n) => write!(f, "Proto({})", n),
        }
    }
}

/// TCP flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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

    pub fn is_syn(&self) -> bool {
        self.syn && !self.ack
    }

    pub fn is_syn_ack(&self) -> bool {
        self.syn && self.ack
    }

    pub fn is_fin(&self) -> bool {
        self.fin
    }

    pub fn is_rst(&self) -> bool {
        self.rst
    }
}

impl std::fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        if self.syn { s.push('S'); }
        if self.ack { s.push('A'); }
        if self.fin { s.push('F'); }
        if self.rst { s.push('R'); }
        if self.psh { s.push('P'); }
        if self.urg { s.push('U'); }
        if self.ece { s.push('E'); }
        if self.cwr { s.push('C'); }
        if s.is_empty() { s.push('.'); }
        write!(f, "{}", s)
    }
}

/// Packet direction relative to connection initiator
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// From client to server (initiator -> responder)
    ToServer,
    /// From server to client (responder -> initiator)
    ToClient,
    /// Unknown direction
    Unknown,
}

impl Default for Direction {
    fn default() -> Self {
        Direction::Unknown
    }
}

/// Unified packet representation for all analyzers
///
/// Uses strongly-typed layer structs:
/// - Layer 2: Optional `ethernet` field (EthernetInfo)
/// - Layer 3: `layer3` field (Layer3 enum: Ipv4/Ipv6)
/// - Layer 4: `layer4` field (Layer4 enum: Tcp/Udp/Icmp/Icmpv6)
///
/// Provides backward-compatible accessor methods for common fields.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet arrival timestamp
    pub timestamp: Instant,
    /// Unique packet ID
    pub id: u64,

    // Layer 2 (optional)
    /// Ethernet frame info
    pub ethernet: Option<EthernetInfo>,

    // Layer 3
    /// IP layer (IPv4 or IPv6)
    pub layer3: Layer3,

    // Layer 4
    /// Transport layer (TCP, UDP, ICMP, etc.)
    pub layer4: Layer4,

    // Metadata
    /// Associated flow ID
    pub flow_id: Option<u64>,
    /// Packet direction
    pub direction: Direction,
    /// Capture interface
    pub interface: String,
    /// Raw packet length (including headers)
    pub raw_len: u32,
}

impl Packet {
    /// Create a new packet from layer info
    pub fn from_layers(packet_id: u64, layer3: Layer3, layer4: Layer4, interface: String) -> Self {
        Self {
            timestamp: Instant::now(),
            id: packet_id,
            ethernet: None,
            layer3,
            layer4,
            flow_id: None,
            direction: Direction::Unknown,
            interface,
            raw_len: 0,
        }
    }

    /// Create a new packet with minimal info (backward compatible)
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, protocol: IpProtocol) -> Self {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let layer3 = match (src_ip, dst_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => Layer3::Ipv4(Ipv4Info {
                src_addr: src,
                dst_addr: dst,
                protocol: protocol.into(),
                ttl: 64,
                ..Default::default()
            }),
            (IpAddr::V6(src), IpAddr::V6(dst)) => Layer3::Ipv6(Ipv6Info {
                src_addr: src,
                dst_addr: dst,
                next_header: protocol.into(),
                hop_limit: 64,
                ..Default::default()
            }),
            // Mixed - default to IPv4 with unspecified
            _ => Layer3::Ipv4(Ipv4Info {
                src_addr: Ipv4Addr::UNSPECIFIED,
                dst_addr: Ipv4Addr::UNSPECIFIED,
                protocol: protocol.into(),
                ttl: 64,
                ..Default::default()
            }),
        };

        let layer4 = match protocol {
            IpProtocol::Tcp => Layer4::Tcp(TcpInfo::default()),
            IpProtocol::Udp => Layer4::Udp(UdpInfo::default()),
            IpProtocol::Icmp => Layer4::Icmp(IcmpInfo::default()),
            IpProtocol::Icmpv6 => Layer4::Icmpv6(Icmpv6Info::default()),
            IpProtocol::Other(n) => Layer4::Unknown { protocol: n },
        };

        Self {
            timestamp: Instant::now(),
            id: 0,
            ethernet: None,
            layer3,
            layer4,
            flow_id: None,
            direction: Direction::Unknown,
            interface: String::new(),
            raw_len: 0,
        }
    }

    // =========================================================================
    // Backward-compatible accessors for Layer 3
    // =========================================================================

    /// Get source IP address
    pub fn src_ip(&self) -> IpAddr {
        self.layer3.src_ip()
    }

    /// Get destination IP address
    pub fn dst_ip(&self) -> IpAddr {
        self.layer3.dst_ip()
    }

    /// Get IP protocol
    pub fn protocol(&self) -> IpProtocol {
        IpProtocol::from(self.layer3.protocol())
    }

    /// Get TTL/hop limit
    pub fn ttl(&self) -> u8 {
        self.layer3.ttl()
    }

    /// Get IP flags (IPv4 only, returns 0 for IPv6)
    pub fn ip_flags(&self) -> u8 {
        match &self.layer3 {
            Layer3::Ipv4(info) => info.flags,
            Layer3::Ipv6(_) => 0,
        }
    }

    /// Get fragment offset (IPv4 only, returns 0 for IPv6)
    pub fn frag_offset(&self) -> u16 {
        match &self.layer3 {
            Layer3::Ipv4(info) => info.fragment_offset,
            Layer3::Ipv6(_) => 0,
        }
    }

    /// Get IP ID (IPv4 only, returns 0 for IPv6)
    pub fn ip_id(&self) -> u16 {
        match &self.layer3 {
            Layer3::Ipv4(info) => info.identification,
            Layer3::Ipv6(_) => 0,
        }
    }

    // =========================================================================
    // Backward-compatible accessors for Layer 4
    // =========================================================================

    /// Get source port (TCP/UDP only, returns 0 for ICMP)
    pub fn src_port(&self) -> u16 {
        self.layer4.src_port().unwrap_or(0)
    }

    /// Get destination port (TCP/UDP only, returns 0 for ICMP)
    pub fn dst_port(&self) -> u16 {
        self.layer4.dst_port().unwrap_or(0)
    }

    /// Get TCP flags (None for non-TCP)
    pub fn tcp_flags(&self) -> Option<TcpFlags> {
        self.layer4.as_tcp().map(|t| t.flags)
    }

    /// Get TCP sequence number (None for non-TCP)
    pub fn seq(&self) -> Option<u32> {
        self.layer4.as_tcp().map(|t| t.seq)
    }

    /// Get TCP acknowledgment number (None for non-TCP)
    pub fn ack(&self) -> Option<u32> {
        self.layer4.as_tcp().map(|t| t.ack)
    }

    /// Get TCP window size (None for non-TCP)
    pub fn window(&self) -> Option<u16> {
        self.layer4.as_tcp().map(|t| t.window)
    }

    /// Get ICMP type (None for non-ICMP)
    pub fn icmp_type(&self) -> Option<u8> {
        match &self.layer4 {
            Layer4::Icmp(info) => Some(info.icmp_type),
            Layer4::Icmpv6(info) => Some(info.icmp_type),
            _ => None,
        }
    }

    /// Get ICMP code (None for non-ICMP)
    pub fn icmp_code(&self) -> Option<u8> {
        match &self.layer4 {
            Layer4::Icmp(info) => Some(info.code),
            Layer4::Icmpv6(info) => Some(info.code),
            _ => None,
        }
    }

    /// Get payload reference
    pub fn payload(&self) -> &[u8] {
        self.layer4.payload()
    }

    // =========================================================================
    // Backward-compatible accessors for Layer 2
    // =========================================================================

    /// Get source MAC address
    pub fn src_mac(&self) -> Option<[u8; 6]> {
        self.ethernet.as_ref().map(|e| e.src_mac)
    }

    /// Get destination MAC address
    pub fn dst_mac(&self) -> Option<[u8; 6]> {
        self.ethernet.as_ref().map(|e| e.dst_mac)
    }

    /// Get VLAN tag
    pub fn vlan(&self) -> Option<u16> {
        self.ethernet.as_ref().and_then(|e| e.vlan)
    }

    // =========================================================================
    // Utility methods
    // =========================================================================

    /// Get 5-tuple key for flow tracking
    pub fn flow_key(&self) -> (IpAddr, IpAddr, u16, u16, IpProtocol) {
        let src_ip = self.src_ip();
        let dst_ip = self.dst_ip();
        let src_port = self.src_port();
        let dst_port = self.dst_port();
        let protocol = self.protocol();

        // Normalize so smaller IP/port is always first
        if (src_ip, src_port) <= (dst_ip, dst_port) {
            (src_ip, dst_ip, src_port, dst_port, protocol)
        } else {
            (dst_ip, src_ip, dst_port, src_port, protocol)
        }
    }

    /// Check if this is the client-to-server direction
    pub fn is_to_server(&self) -> bool {
        matches!(self.direction, Direction::ToServer)
    }

    /// Check if packet is fragmented
    pub fn is_fragmented(&self) -> bool {
        match &self.layer3 {
            Layer3::Ipv4(info) => info.is_fragmented(),
            Layer3::Ipv6(_) => false, // TODO: check IPv6 fragment header
        }
    }

    /// Get payload as string (lossy UTF-8)
    pub fn payload_str(&self) -> String {
        String::from_utf8_lossy(self.payload()).to_string()
    }

    // =========================================================================
    // Direct layer access
    // =========================================================================

    /// Get TCP info if this is a TCP packet
    pub fn tcp(&self) -> Option<&TcpInfo> {
        self.layer4.as_tcp()
    }

    /// Get mutable TCP info if this is a TCP packet
    pub fn tcp_mut(&mut self) -> Option<&mut TcpInfo> {
        self.layer4.as_tcp_mut()
    }

    /// Get UDP info if this is a UDP packet
    pub fn udp(&self) -> Option<&UdpInfo> {
        self.layer4.as_udp()
    }

    /// Get mutable UDP info if this is a UDP packet
    pub fn udp_mut(&mut self) -> Option<&mut UdpInfo> {
        self.layer4.as_udp_mut()
    }

    /// Get ICMP info if this is an ICMP packet
    pub fn icmp(&self) -> Option<&IcmpInfo> {
        self.layer4.as_icmp()
    }

    /// Get ICMPv6 info if this is an ICMPv6 packet
    pub fn icmpv6(&self) -> Option<&Icmpv6Info> {
        self.layer4.as_icmpv6()
    }

    /// Get IPv4 info if this is an IPv4 packet
    pub fn ipv4(&self) -> Option<&Ipv4Info> {
        self.layer3.as_ipv4()
    }

    /// Get IPv6 info if this is an IPv6 packet
    pub fn ipv6(&self) -> Option<&Ipv6Info> {
        self.layer3.as_ipv6()
    }

    /// Check if this is a TCP packet
    pub fn is_tcp(&self) -> bool {
        self.layer4.is_tcp()
    }

    /// Check if this is a UDP packet
    pub fn is_udp(&self) -> bool {
        self.layer4.is_udp()
    }

    /// Check if this is an ICMP packet (v4 or v6)
    pub fn is_icmp(&self) -> bool {
        self.layer4.is_icmp()
    }

    /// Check if this is an IPv4 packet
    pub fn is_ipv4(&self) -> bool {
        self.layer3.is_ipv4()
    }

    /// Check if this is an IPv6 packet
    pub fn is_ipv6(&self) -> bool {
        self.layer3.is_ipv6()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_tcp_flags() {
        let flags = TcpFlags::from_u8(0x12); // SYN+ACK
        assert!(flags.syn);
        assert!(flags.ack);
        assert!(!flags.fin);
        assert!(flags.is_syn_ack());
        assert_eq!(flags.to_u8(), 0x12);
    }

    #[test]
    fn test_packet_new() {
        let pkt = Packet::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            IpProtocol::Tcp,
        );
        assert_eq!(pkt.protocol(), IpProtocol::Tcp);
        assert_eq!(pkt.ttl(), 64);
        assert!(pkt.is_tcp());
        assert!(pkt.is_ipv4());
    }

    #[test]
    fn test_packet_from_layers() {
        let layer3 = Layer3::Ipv4(Ipv4Info {
            src_addr: Ipv4Addr::new(10, 0, 0, 1),
            dst_addr: Ipv4Addr::new(10, 0, 0, 2),
            protocol: 6,
            ttl: 128,
            ..Default::default()
        });

        let layer4 = Layer4::Tcp(TcpInfo {
            src_port: 12345,
            dst_port: 80,
            flags: TcpFlags { syn: true, ..Default::default() },
            ..Default::default()
        });

        let pkt = Packet::from_layers(42, layer3, layer4, "test0".to_string());

        assert_eq!(pkt.id, 42);
        assert_eq!(pkt.src_ip().to_string(), "10.0.0.1");
        assert_eq!(pkt.interface, "test0");
        assert_eq!(pkt.dst_ip().to_string(), "10.0.0.2");
        assert_eq!(pkt.src_port(), 12345);
        assert_eq!(pkt.dst_port(), 80);
        assert!(pkt.tcp_flags().unwrap().syn);
        assert!(pkt.tcp().unwrap().is_syn());
    }

    #[test]
    fn test_backward_compat_accessors() {
        let pkt = Packet::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            IpProtocol::Udp,
        );

        // These should all work even though internally using layer structs
        let _ = pkt.src_ip();
        let _ = pkt.dst_ip();
        let _ = pkt.protocol();
        let _ = pkt.ttl();
        let _ = pkt.ip_flags();
        let _ = pkt.frag_offset();
        let _ = pkt.ip_id();
        let _ = pkt.src_port();
        let _ = pkt.dst_port();
        let _ = pkt.tcp_flags();
        let _ = pkt.seq();
        let _ = pkt.ack();
        let _ = pkt.window();
        let _ = pkt.icmp_type();
        let _ = pkt.icmp_code();
        let _ = pkt.payload();
    }
}
