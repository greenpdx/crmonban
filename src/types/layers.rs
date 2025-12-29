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

    /// Parse IP header from raw bytes (IPv4 or IPv6)
    ///
    /// Detects IP version from first nibble and parses accordingly.
    /// Returns (Layer3, remaining payload bytes) or None if parsing fails.
    pub fn from_bytes(data: &[u8]) -> Option<(Self, &[u8])> {
        if data.is_empty() {
            return None;
        }

        // Check IP version from first nibble
        let version = data[0] >> 4;

        match version {
            4 => Self::parse_ipv4(data),
            6 => Self::parse_ipv6(data),
            _ => None,
        }
    }

    /// Parse IPv4 header
    fn parse_ipv4(data: &[u8]) -> Option<(Self, &[u8])> {
        // Minimum IPv4 header is 20 bytes
        if data.len() < 20 {
            return None;
        }

        let ihl = (data[0] & 0x0F) as usize;
        let header_len = ihl * 4;

        if data.len() < header_len {
            return None;
        }

        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let flags_frag = u16::from_be_bytes([data[6], data[7]]);

        let info = Ipv4Info {
            src_addr: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            dst_addr: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
            protocol: data[9],
            ttl: data[8],
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags: ((flags_frag >> 13) & 0x07) as u8,
            fragment_offset: flags_frag & 0x1FFF,
            header_length: ihl as u8,
            total_length,
            dscp: (data[1] >> 2) & 0x3F,
            ecn: data[1] & 0x03,
        };

        let payload = &data[header_len..];
        Some((Layer3::Ipv4(info), payload))
    }

    /// Parse IPv6 header
    fn parse_ipv6(data: &[u8]) -> Option<(Self, &[u8])> {
        // IPv6 header is fixed 40 bytes
        if data.len() < 40 {
            return None;
        }

        let mut src_addr = [0u8; 16];
        let mut dst_addr = [0u8; 16];
        src_addr.copy_from_slice(&data[8..24]);
        dst_addr.copy_from_slice(&data[24..40]);

        let info = Ipv6Info {
            src_addr: Ipv6Addr::from(src_addr),
            dst_addr: Ipv6Addr::from(dst_addr),
            next_header: data[6],
            hop_limit: data[7],
            traffic_class: ((data[0] & 0x0F) << 4) | ((data[1] & 0xF0) >> 4),
            flow_label: u32::from_be_bytes([0, data[1] & 0x0F, data[2], data[3]]),
            payload_length: u16::from_be_bytes([data[4], data[5]]),
        };

        let payload = &data[40..];
        Some((Layer3::Ipv6(info), payload))
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

    /// Get mutable ICMP info if present
    pub fn as_icmp_mut(&mut self) -> Option<&mut IcmpInfo> {
        match self {
            Layer4::Icmp(info) => Some(info),
            _ => None,
        }
    }

    /// Get mutable ICMPv6 info if present
    pub fn as_icmpv6_mut(&mut self) -> Option<&mut Icmpv6Info> {
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

    /// Parse transport layer from raw bytes
    ///
    /// protocol: IP protocol number (6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6)
    pub fn from_bytes(protocol: u8, data: &[u8]) -> Option<Self> {
        match protocol {
            6 => Self::parse_tcp(data),
            17 => Self::parse_udp(data),
            1 => Self::parse_icmp(data),
            58 => Self::parse_icmpv6(data),
            other => Some(Layer4::Unknown { protocol: other }),
        }
    }

    /// Parse TCP header
    fn parse_tcp(data: &[u8]) -> Option<Self> {
        // Minimum TCP header is 20 bytes
        if data.len() < 20 {
            return None;
        }

        let data_offset = ((data[12] >> 4) & 0x0F) as usize;
        let header_len = data_offset * 4;

        if data.len() < header_len {
            return None;
        }

        let flags_byte = data[13];

        let info = TcpInfo {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            flags: TcpFlags {
                fin: flags_byte & 0x01 != 0,
                syn: flags_byte & 0x02 != 0,
                rst: flags_byte & 0x04 != 0,
                psh: flags_byte & 0x08 != 0,
                ack: flags_byte & 0x10 != 0,
                urg: flags_byte & 0x20 != 0,
                ece: flags_byte & 0x40 != 0,
                cwr: flags_byte & 0x80 != 0,
            },
            window: u16::from_be_bytes([data[14], data[15]]),
            urgent_ptr: u16::from_be_bytes([data[18], data[19]]),
            data_offset: data_offset as u8,
            payload: data[header_len..].to_vec(),
        };

        Some(Layer4::Tcp(info))
    }

    /// Parse UDP header
    fn parse_udp(data: &[u8]) -> Option<Self> {
        // UDP header is 8 bytes
        if data.len() < 8 {
            return None;
        }

        let info = UdpInfo {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length: u16::from_be_bytes([data[4], data[5]]),
            payload: data[8..].to_vec(),
        };

        Some(Layer4::Udp(info))
    }

    /// Parse ICMP header
    fn parse_icmp(data: &[u8]) -> Option<Self> {
        // Minimum ICMP header is 8 bytes
        if data.len() < 4 {
            return None;
        }

        let info = IcmpInfo {
            icmp_type: data[0],
            code: data[1],
            payload: if data.len() > 8 { data[8..].to_vec() } else { Vec::new() },
        };

        Some(Layer4::Icmp(info))
    }

    /// Parse ICMPv6 header
    fn parse_icmpv6(data: &[u8]) -> Option<Self> {
        // Minimum ICMPv6 header is 4 bytes
        if data.len() < 4 {
            return None;
        }

        let info = Icmpv6Info {
            icmp_type: data[0],
            code: data[1],
            payload: if data.len() > 8 { data[8..].to_vec() } else { Vec::new() },
        };

        Some(Layer4::Icmpv6(info))
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
