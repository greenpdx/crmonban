//! Network layer types for packet parsing
//!
//! Provides strongly-typed structs for each network layer:
//! - Layer 2: Ethernet (EthernetInfo)
//! - Layer 3: IPv4, IPv6 (Layer3)
//! - Layer 4: TCP, UDP, ICMP, ICMPv6 (Layer4)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use serde::{Deserialize, Serialize};

use super::packet::TcpFlags;

// ============================================================================
// Layer 2 - Data Link
// ============================================================================

/// Ethernet frame information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EthernetInfo {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub vlan: Option<u16>,
}

// ============================================================================
// Layer 3 - Network
// ============================================================================

/// Layer 3 protocol variants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Layer3 {
    Ipv4(Ipv4Info),
    Ipv6(Ipv6Info),
}

impl Layer3 {
    /// Get source IP address (works for both IPv4 and IPv6)
    pub fn src_ip(&self) -> IpAddr {
        match self {
            Layer3::Ipv4(info) => IpAddr::V4(info.src_addr),
            Layer3::Ipv6(info) => IpAddr::V6(info.src_addr),
        }
    }

    /// Get destination IP address (works for both IPv4 and IPv6)
    pub fn dst_ip(&self) -> IpAddr {
        match self {
            Layer3::Ipv4(info) => IpAddr::V4(info.dst_addr),
            Layer3::Ipv6(info) => IpAddr::V6(info.dst_addr),
        }
    }

    /// Get TTL/hop limit
    pub fn ttl(&self) -> u8 {
        match self {
            Layer3::Ipv4(info) => info.ttl,
            Layer3::Ipv6(info) => info.hop_limit,
        }
    }

    /// Get next protocol number
    pub fn protocol(&self) -> u8 {
        match self {
            Layer3::Ipv4(info) => info.protocol,
            Layer3::Ipv6(info) => info.next_header,
        }
    }

    /// Check if IPv4
    pub fn is_ipv4(&self) -> bool {
        matches!(self, Layer3::Ipv4(_))
    }

    /// Check if IPv6
    pub fn is_ipv6(&self) -> bool {
        matches!(self, Layer3::Ipv6(_))
    }

    /// Get IPv4 info if present
    pub fn as_ipv4(&self) -> Option<&Ipv4Info> {
        match self {
            Layer3::Ipv4(info) => Some(info),
            _ => None,
        }
    }

    /// Get IPv6 info if present
    pub fn as_ipv6(&self) -> Option<&Ipv6Info> {
        match self {
            Layer3::Ipv6(info) => Some(info),
            _ => None,
        }
    }
}

/// IPv4 header information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Info {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub protocol: u8,
    pub ttl: u8,
    pub identification: u16,
    pub flags: u8,           // DF, MF bits
    pub fragment_offset: u16,
    pub header_length: u8,   // in 32-bit words
    pub total_length: u16,
    pub dscp: u8,
    pub ecn: u8,
}

impl Default for Ipv4Info {
    fn default() -> Self {
        Self {
            src_addr: Ipv4Addr::UNSPECIFIED,
            dst_addr: Ipv4Addr::UNSPECIFIED,
            protocol: 0,
            ttl: 64,
            identification: 0,
            flags: 0,
            fragment_offset: 0,
            header_length: 5,
            total_length: 0,
            dscp: 0,
            ecn: 0,
        }
    }
}

impl Ipv4Info {
    /// Check if Don't Fragment flag is set
    pub fn dont_fragment(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Check if More Fragments flag is set
    pub fn more_fragments(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Check if packet is fragmented
    pub fn is_fragmented(&self) -> bool {
        self.fragment_offset > 0 || self.more_fragments()
    }
}

/// IPv6 header information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Info {
    pub src_addr: Ipv6Addr,
    pub dst_addr: Ipv6Addr,
    pub next_header: u8,
    pub hop_limit: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
}

impl Default for Ipv6Info {
    fn default() -> Self {
        Self {
            src_addr: Ipv6Addr::UNSPECIFIED,
            dst_addr: Ipv6Addr::UNSPECIFIED,
            next_header: 0,
            hop_limit: 64,
            traffic_class: 0,
            flow_label: 0,
            payload_length: 0,
        }
    }
}

// ============================================================================
// Layer 4 - Transport
// ============================================================================

/// Layer 4 protocol variants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Layer4 {
    Tcp(TcpInfo),
    Udp(UdpInfo),
    Icmp(IcmpInfo),
    Icmpv6(Icmpv6Info),
    /// Unknown or unsupported protocol
    Unknown { protocol: u8 },
}

impl Layer4 {
    /// Get source port (TCP/UDP only)
    pub fn src_port(&self) -> Option<u16> {
        match self {
            Layer4::Tcp(info) => Some(info.src_port),
            Layer4::Udp(info) => Some(info.src_port),
            _ => None,
        }
    }

    /// Get destination port (TCP/UDP only)
    pub fn dst_port(&self) -> Option<u16> {
        match self {
            Layer4::Tcp(info) => Some(info.dst_port),
            Layer4::Udp(info) => Some(info.dst_port),
            _ => None,
        }
    }

    /// Get TCP info if present
    pub fn as_tcp(&self) -> Option<&TcpInfo> {
        match self {
            Layer4::Tcp(info) => Some(info),
            _ => None,
        }
    }

    /// Get mutable TCP info if present
    pub fn as_tcp_mut(&mut self) -> Option<&mut TcpInfo> {
        match self {
            Layer4::Tcp(info) => Some(info),
            _ => None,
        }
    }

    /// Get UDP info if present
    pub fn as_udp(&self) -> Option<&UdpInfo> {
        match self {
            Layer4::Udp(info) => Some(info),
            _ => None,
        }
    }

    /// Get mutable UDP info if present
    pub fn as_udp_mut(&mut self) -> Option<&mut UdpInfo> {
        match self {
            Layer4::Udp(info) => Some(info),
            _ => None,
        }
    }

    /// Get ICMP info if present
    pub fn as_icmp(&self) -> Option<&IcmpInfo> {
        match self {
            Layer4::Icmp(info) => Some(info),
            _ => None,
        }
    }

    /// Get ICMPv6 info if present
    pub fn as_icmpv6(&self) -> Option<&Icmpv6Info> {
        match self {
            Layer4::Icmpv6(info) => Some(info),
            _ => None,
        }
    }

    /// Check if TCP
    pub fn is_tcp(&self) -> bool {
        matches!(self, Layer4::Tcp(_))
    }

    /// Check if UDP
    pub fn is_udp(&self) -> bool {
        matches!(self, Layer4::Udp(_))
    }

    /// Check if ICMP (v4 or v6)
    pub fn is_icmp(&self) -> bool {
        matches!(self, Layer4::Icmp(_) | Layer4::Icmpv6(_))
    }

    /// Get payload reference
    pub fn payload(&self) -> &[u8] {
        match self {
            Layer4::Tcp(info) => &info.payload,
            Layer4::Udp(info) => &info.payload,
            Layer4::Icmp(info) => &info.payload,
            Layer4::Icmpv6(info) => &info.payload,
            Layer4::Unknown { .. } => &[],
        }
    }

    /// Get protocol number
    pub fn protocol_number(&self) -> u8 {
        match self {
            Layer4::Tcp(_) => 6,
            Layer4::Udp(_) => 17,
            Layer4::Icmp(_) => 1,
            Layer4::Icmpv6(_) => 58,
            Layer4::Unknown { protocol } => *protocol,
        }
    }
}

impl Default for Layer4 {
    fn default() -> Self {
        Layer4::Unknown { protocol: 0 }
    }
}

/// TCP segment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window: u16,
    pub urgent_ptr: u16,
    pub data_offset: u8,  // header length in 32-bit words
    pub payload: Vec<u8>,
}

impl Default for TcpInfo {
    fn default() -> Self {
        Self {
            src_port: 0,
            dst_port: 0,
            seq: 0,
            ack: 0,
            flags: TcpFlags::default(),
            window: 0,
            urgent_ptr: 0,
            data_offset: 5,
            payload: Vec::new(),
        }
    }
}

impl TcpInfo {
    /// Check if this is a SYN packet (SYN only, not SYN-ACK)
    pub fn is_syn(&self) -> bool {
        self.flags.syn && !self.flags.ack
    }

    /// Check if this is a SYN-ACK packet
    pub fn is_syn_ack(&self) -> bool {
        self.flags.syn && self.flags.ack
    }

    /// Check if this is a FIN packet
    pub fn is_fin(&self) -> bool {
        self.flags.fin
    }

    /// Check if this is a RST packet
    pub fn is_rst(&self) -> bool {
        self.flags.rst
    }

    /// Check if ACK flag is set
    pub fn is_ack(&self) -> bool {
        self.flags.ack
    }
}

/// UDP datagram information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub payload: Vec<u8>,
}

impl Default for UdpInfo {
    fn default() -> Self {
        Self {
            src_port: 0,
            dst_port: 0,
            length: 0,
            payload: Vec::new(),
        }
    }
}

/// ICMP (v4) message information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpInfo {
    pub icmp_type: u8,
    pub code: u8,
    pub payload: Vec<u8>,
}

impl Default for IcmpInfo {
    fn default() -> Self {
        Self {
            icmp_type: 0,
            code: 0,
            payload: Vec::new(),
        }
    }
}

impl IcmpInfo {
    /// Check if this is an echo request (ping)
    pub fn is_echo_request(&self) -> bool {
        self.icmp_type == 8
    }

    /// Check if this is an echo reply
    pub fn is_echo_reply(&self) -> bool {
        self.icmp_type == 0
    }

    /// Check if this is a destination unreachable message
    pub fn is_dest_unreachable(&self) -> bool {
        self.icmp_type == 3
    }

    /// Check if this is a time exceeded message
    pub fn is_time_exceeded(&self) -> bool {
        self.icmp_type == 11
    }
}

/// ICMPv6 message information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Icmpv6Info {
    pub icmp_type: u8,
    pub code: u8,
    pub payload: Vec<u8>,
}

impl Default for Icmpv6Info {
    fn default() -> Self {
        Self {
            icmp_type: 0,
            code: 0,
            payload: Vec::new(),
        }
    }
}

impl Icmpv6Info {
    /// Check if this is an echo request (ping)
    pub fn is_echo_request(&self) -> bool {
        self.icmp_type == 128
    }

    /// Check if this is an echo reply
    pub fn is_echo_reply(&self) -> bool {
        self.icmp_type == 129
    }

    /// Check if this is a destination unreachable message
    pub fn is_dest_unreachable(&self) -> bool {
        self.icmp_type == 1
    }

    /// Check if this is a neighbor solicitation (NDP)
    pub fn is_neighbor_solicitation(&self) -> bool {
        self.icmp_type == 135
    }

    /// Check if this is a neighbor advertisement (NDP)
    pub fn is_neighbor_advertisement(&self) -> bool {
        self.icmp_type == 136
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_layer3_accessors() {
        let ipv4 = Layer3::Ipv4(Ipv4Info {
            src_addr: Ipv4Addr::new(192, 168, 1, 1),
            dst_addr: Ipv4Addr::new(10, 0, 0, 1),
            protocol: 6,
            ttl: 64,
            ..Default::default()
        });

        assert!(ipv4.is_ipv4());
        assert!(!ipv4.is_ipv6());
        assert_eq!(ipv4.src_ip().to_string(), "192.168.1.1");
        assert_eq!(ipv4.dst_ip().to_string(), "10.0.0.1");
        assert_eq!(ipv4.ttl(), 64);
        assert_eq!(ipv4.protocol(), 6);
    }

    #[test]
    fn test_layer4_tcp() {
        let tcp = Layer4::Tcp(TcpInfo {
            src_port: 12345,
            dst_port: 80,
            flags: TcpFlags { syn: true, ..Default::default() },
            ..Default::default()
        });

        assert!(tcp.is_tcp());
        assert!(!tcp.is_udp());
        assert_eq!(tcp.src_port(), Some(12345));
        assert_eq!(tcp.dst_port(), Some(80));
        assert!(tcp.as_tcp().unwrap().is_syn());
    }

    #[test]
    fn test_layer4_icmp() {
        let icmp = Layer4::Icmp(IcmpInfo {
            icmp_type: 8,
            code: 0,
            payload: vec![],
        });

        assert!(icmp.is_icmp());
        assert!(icmp.as_icmp().unwrap().is_echo_request());
    }

    #[test]
    fn test_ipv4_fragmentation() {
        let mut info = Ipv4Info::default();
        assert!(!info.is_fragmented());

        info.fragment_offset = 100;
        assert!(info.is_fragmented());

        info.fragment_offset = 0;
        info.flags = 0x01; // MF
        assert!(info.is_fragmented());
    }
}
