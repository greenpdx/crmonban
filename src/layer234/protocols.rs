//! Protocol parsers for Layer 2-4 attack detection
//!
//! Parsers for ARP, DHCP, ICMPv6 Router Advertisements, and BGP.

use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};

// ============================================================================
// ARP Protocol
// ============================================================================

/// ARP operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOp {
    Request,  // 1
    Reply,    // 2
    Unknown(u16),
}

impl From<u16> for ArpOp {
    fn from(val: u16) -> Self {
        match val {
            1 => ArpOp::Request,
            2 => ArpOp::Reply,
            n => ArpOp::Unknown(n),
        }
    }
}

/// Parsed ARP packet
#[derive(Debug, Clone)]
pub struct ArpPacket {
    pub operation: ArpOp,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    /// Parse ARP packet from raw bytes (after Ethernet header)
    /// ARP for IPv4 over Ethernet is 28 bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 28 {
            return None;
        }

        // Hardware type (2 bytes) - should be 1 for Ethernet
        let hw_type = u16::from_be_bytes([data[0], data[1]]);
        if hw_type != 1 {
            return None;
        }

        // Protocol type (2 bytes) - should be 0x0800 for IPv4
        let proto_type = u16::from_be_bytes([data[2], data[3]]);
        if proto_type != 0x0800 {
            return None;
        }

        // Hardware address length - should be 6 for Ethernet
        if data[4] != 6 {
            return None;
        }

        // Protocol address length - should be 4 for IPv4
        if data[5] != 4 {
            return None;
        }

        let operation = ArpOp::from(u16::from_be_bytes([data[6], data[7]]));

        let sender_mac = [data[8], data[9], data[10], data[11], data[12], data[13]];
        let sender_ip = Ipv4Addr::new(data[14], data[15], data[16], data[17]);
        let target_mac = [data[18], data[19], data[20], data[21], data[22], data[23]];
        let target_ip = Ipv4Addr::new(data[24], data[25], data[26], data[27]);

        Some(ArpPacket {
            operation,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }

    /// Check if this is a gratuitous ARP (sender_ip == target_ip)
    pub fn is_gratuitous(&self) -> bool {
        self.sender_ip == self.target_ip
    }

    /// Check if this is an ARP announcement (gratuitous reply)
    pub fn is_announcement(&self) -> bool {
        matches!(self.operation, ArpOp::Reply) && self.is_gratuitous()
    }
}

// ============================================================================
// DHCP Protocol
// ============================================================================

/// DHCP message types (option 53)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover,   // 1
    Offer,      // 2
    Request,    // 3
    Decline,    // 4
    Ack,        // 5
    Nak,        // 6
    Release,    // 7
    Inform,     // 8
    Unknown(u8),
}

impl From<u8> for DhcpMessageType {
    fn from(val: u8) -> Self {
        match val {
            1 => DhcpMessageType::Discover,
            2 => DhcpMessageType::Offer,
            3 => DhcpMessageType::Request,
            4 => DhcpMessageType::Decline,
            5 => DhcpMessageType::Ack,
            6 => DhcpMessageType::Nak,
            7 => DhcpMessageType::Release,
            8 => DhcpMessageType::Inform,
            n => DhcpMessageType::Unknown(n),
        }
    }
}

/// Parsed DHCP packet
#[derive(Debug, Clone)]
pub struct DhcpPacket {
    pub op: u8,                          // 1=Request, 2=Reply
    pub message_type: DhcpMessageType,
    pub client_mac: [u8; 6],
    pub client_ip: Ipv4Addr,             // ciaddr
    pub your_ip: Ipv4Addr,               // yiaddr (offered IP)
    pub server_ip: Ipv4Addr,             // siaddr
    pub transaction_id: u32,
    pub server_identifier: Option<Ipv4Addr>,  // Option 54
    pub requested_ip: Option<Ipv4Addr>,       // Option 50
}

impl DhcpPacket {
    /// Parse DHCP packet from UDP payload (ports 67/68)
    /// DHCP header is 236 bytes minimum, plus options
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 240 {  // 236 header + 4 magic cookie
            return None;
        }

        let op = data[0];

        // Hardware type should be 1 (Ethernet)
        if data[1] != 1 {
            return None;
        }

        // Hardware address length should be 6
        if data[2] != 6 {
            return None;
        }

        let transaction_id = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let client_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let your_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let server_ip = Ipv4Addr::new(data[20], data[21], data[22], data[23]);

        let client_mac = [data[28], data[29], data[30], data[31], data[32], data[33]];

        // Check magic cookie at offset 236
        if data.len() < 240 {
            return None;
        }
        let magic = u32::from_be_bytes([data[236], data[237], data[238], data[239]]);
        if magic != 0x63825363 {
            return None;  // Not a valid DHCP packet
        }

        // Parse options starting at offset 240
        let mut message_type = DhcpMessageType::Unknown(0);
        let mut server_identifier = None;
        let mut requested_ip = None;

        let mut i = 240;
        while i < data.len() {
            let option = data[i];
            if option == 255 {
                break;  // End option
            }
            if option == 0 {
                i += 1;  // Pad option
                continue;
            }

            if i + 1 >= data.len() {
                break;
            }
            let len = data[i + 1] as usize;
            if i + 2 + len > data.len() {
                break;
            }

            match option {
                53 if len >= 1 => {
                    // DHCP Message Type
                    message_type = DhcpMessageType::from(data[i + 2]);
                }
                54 if len >= 4 => {
                    // Server Identifier
                    server_identifier = Some(Ipv4Addr::new(
                        data[i + 2], data[i + 3], data[i + 4], data[i + 5]
                    ));
                }
                50 if len >= 4 => {
                    // Requested IP Address
                    requested_ip = Some(Ipv4Addr::new(
                        data[i + 2], data[i + 3], data[i + 4], data[i + 5]
                    ));
                }
                _ => {}
            }

            i += 2 + len;
        }

        Some(DhcpPacket {
            op,
            message_type,
            client_mac,
            client_ip,
            your_ip,
            server_ip,
            transaction_id,
            server_identifier,
            requested_ip,
        })
    }

    /// Check if this is a server message (Offer, Ack, Nak)
    pub fn is_server_message(&self) -> bool {
        matches!(
            self.message_type,
            DhcpMessageType::Offer | DhcpMessageType::Ack | DhcpMessageType::Nak
        )
    }

    /// Check if this is a client request
    pub fn is_client_request(&self) -> bool {
        matches!(
            self.message_type,
            DhcpMessageType::Discover | DhcpMessageType::Request
        )
    }
}

// ============================================================================
// ICMPv6 Router Advertisement
// ============================================================================

/// IPv6 prefix information (from RA Prefix Information option)
#[derive(Debug, Clone)]
pub struct Ipv6Prefix {
    pub prefix_len: u8,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub prefix: Ipv6Addr,
}

/// Parsed ICMPv6 Router Advertisement
#[derive(Debug, Clone)]
pub struct Icmpv6Ra {
    pub cur_hop_limit: u8,
    pub managed_flag: bool,      // M flag - managed address configuration
    pub other_flag: bool,        // O flag - other configuration
    pub router_lifetime: u16,    // Seconds (0 = not a default router)
    pub reachable_time: u32,
    pub retrans_timer: u32,
    pub prefixes: Vec<Ipv6Prefix>,
    pub mtu: Option<u32>,
    pub source_link_addr: Option<[u8; 6]>,  // Source Link-Layer Address option
}

impl Icmpv6Ra {
    /// Parse ICMPv6 Router Advertisement from ICMPv6 payload
    /// ICMPv6 type 134
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Minimum RA size: 8 bytes (type, code, checksum, cur_hop, flags, lifetime, times)
        if data.len() < 16 {
            return None;
        }

        // Check ICMPv6 type (134 = Router Advertisement)
        if data[0] != 134 {
            return None;
        }

        let cur_hop_limit = data[4];
        let flags = data[5];
        let managed_flag = (flags & 0x80) != 0;
        let other_flag = (flags & 0x40) != 0;
        let router_lifetime = u16::from_be_bytes([data[6], data[7]]);
        let reachable_time = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let retrans_timer = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

        let mut prefixes = Vec::new();
        let mut mtu = None;
        let mut source_link_addr = None;

        // Parse options starting at offset 16
        let mut i = 16;
        while i + 2 <= data.len() {
            let opt_type = data[i];
            let opt_len = data[i + 1] as usize * 8;  // Length in units of 8 bytes

            if opt_len == 0 || i + opt_len > data.len() {
                break;
            }

            match opt_type {
                1 if opt_len >= 8 => {
                    // Source Link-Layer Address
                    source_link_addr = Some([
                        data[i + 2], data[i + 3], data[i + 4],
                        data[i + 5], data[i + 6], data[i + 7]
                    ]);
                }
                3 if opt_len >= 32 => {
                    // Prefix Information
                    let prefix_len = data[i + 2];
                    let prefix_flags = data[i + 3];
                    let valid_lifetime = u32::from_be_bytes([
                        data[i + 4], data[i + 5], data[i + 6], data[i + 7]
                    ]);
                    let preferred_lifetime = u32::from_be_bytes([
                        data[i + 8], data[i + 9], data[i + 10], data[i + 11]
                    ]);
                    // Skip reserved 4 bytes
                    let prefix = Ipv6Addr::new(
                        u16::from_be_bytes([data[i + 16], data[i + 17]]),
                        u16::from_be_bytes([data[i + 18], data[i + 19]]),
                        u16::from_be_bytes([data[i + 20], data[i + 21]]),
                        u16::from_be_bytes([data[i + 22], data[i + 23]]),
                        u16::from_be_bytes([data[i + 24], data[i + 25]]),
                        u16::from_be_bytes([data[i + 26], data[i + 27]]),
                        u16::from_be_bytes([data[i + 28], data[i + 29]]),
                        u16::from_be_bytes([data[i + 30], data[i + 31]]),
                    );

                    prefixes.push(Ipv6Prefix {
                        prefix_len,
                        on_link: (prefix_flags & 0x80) != 0,
                        autonomous: (prefix_flags & 0x40) != 0,
                        valid_lifetime,
                        preferred_lifetime,
                        prefix,
                    });
                }
                5 if opt_len >= 8 => {
                    // MTU option
                    mtu = Some(u32::from_be_bytes([
                        data[i + 4], data[i + 5], data[i + 6], data[i + 7]
                    ]));
                }
                _ => {}
            }

            i += opt_len;
        }

        Some(Icmpv6Ra {
            cur_hop_limit,
            managed_flag,
            other_flag,
            router_lifetime,
            reachable_time,
            retrans_timer,
            prefixes,
            mtu,
            source_link_addr,
        })
    }

    /// Check if this RA claims to be a default router
    pub fn is_default_router(&self) -> bool {
        self.router_lifetime > 0
    }

    /// Check if this is a router deprecation (lifetime = 0)
    pub fn is_deprecation(&self) -> bool {
        self.router_lifetime == 0
    }
}

// ============================================================================
// 802.1Q VLAN Tag
// ============================================================================

/// 802.1Q VLAN tag
#[derive(Debug, Clone, Copy)]
pub struct VlanTag {
    pub priority: u8,      // 3 bits PCP
    pub dei: bool,         // Drop Eligible Indicator
    pub vlan_id: u16,      // 12 bits VLAN ID
}

impl VlanTag {
    /// Parse VLAN tag from 4 bytes (TPID + TCI)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        let tpid = u16::from_be_bytes([data[0], data[1]]);

        // Check for 802.1Q TPID (0x8100) or 802.1ad QinQ (0x88a8)
        if tpid != 0x8100 && tpid != 0x88a8 {
            return None;
        }

        let tci = u16::from_be_bytes([data[2], data[3]]);
        let priority = ((tci >> 13) & 0x07) as u8;
        let dei = (tci & 0x1000) != 0;
        let vlan_id = tci & 0x0FFF;

        Some(VlanTag {
            priority,
            dei,
            vlan_id,
        })
    }
}

/// Check for VLAN hopping (double-tagged frame)
pub fn detect_vlan_hopping(data: &[u8]) -> Option<(VlanTag, VlanTag)> {
    if data.len() < 8 {
        return None;
    }

    // First tag
    let outer = VlanTag::parse(&data[0..4])?;

    // Check if there's a second tag
    let inner_tpid = u16::from_be_bytes([data[4], data[5]]);
    if inner_tpid == 0x8100 || inner_tpid == 0x88a8 {
        let inner = VlanTag::parse(&data[4..8])?;
        return Some((outer, inner));
    }

    None
}

// ============================================================================
// ICMP Tunneling Detection Helpers
// ============================================================================

/// Calculate Shannon entropy of data (normalized 0.0-1.0)
pub fn calculate_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f32;
    let mut entropy: f32 = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }

    // Normalize to 0-1 range (max entropy for bytes is 8 bits)
    entropy / 8.0
}

/// ICMP tunnel detection metrics
#[derive(Debug, Clone)]
pub struct IcmpTunnelMetrics {
    pub payload_size: usize,
    pub entropy: f32,
    pub is_echo: bool,       // Type 8 (request) or 0 (reply)
    pub sequence: u16,
    pub identifier: u16,
}

impl IcmpTunnelMetrics {
    /// Extract metrics from ICMP packet for tunnel detection
    pub fn from_icmp(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }

        let icmp_type = data[0];
        let is_echo = icmp_type == 8 || icmp_type == 0;

        if !is_echo {
            return None;  // Only analyze echo request/reply for tunneling
        }

        let identifier = u16::from_be_bytes([data[4], data[5]]);
        let sequence = u16::from_be_bytes([data[6], data[7]]);

        let payload = &data[8..];
        let entropy = calculate_entropy(payload);

        Some(IcmpTunnelMetrics {
            payload_size: payload.len(),
            entropy,
            is_echo,
            sequence,
            identifier,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arp_parse() {
        // ARP reply: 192.168.1.1 is at aa:bb:cc:dd:ee:ff
        let arp_data = [
            0x00, 0x01,  // Hardware type: Ethernet
            0x08, 0x00,  // Protocol type: IPv4
            0x06,        // Hardware size: 6
            0x04,        // Protocol size: 4
            0x00, 0x02,  // Opcode: Reply
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  // Sender MAC
            0xc0, 0xa8, 0x01, 0x01,              // Sender IP: 192.168.1.1
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,  // Target MAC
            0xc0, 0xa8, 0x01, 0x02,              // Target IP: 192.168.1.2
        ];

        let arp = ArpPacket::parse(&arp_data).unwrap();
        assert!(matches!(arp.operation, ArpOp::Reply));
        assert_eq!(arp.sender_ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(arp.target_ip, Ipv4Addr::new(192, 168, 1, 2));
        assert!(!arp.is_gratuitous());
    }

    #[test]
    fn test_gratuitous_arp() {
        let arp_data = [
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04,
            0x00, 0x02,  // Reply
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0xc0, 0xa8, 0x01, 0x01,  // Sender IP
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xc0, 0xa8, 0x01, 0x01,  // Target IP = Sender IP (gratuitous)
        ];

        let arp = ArpPacket::parse(&arp_data).unwrap();
        assert!(arp.is_gratuitous());
        assert!(arp.is_announcement());
    }

    #[test]
    fn test_entropy_calculation() {
        // All zeros - minimum entropy
        let zeros = [0u8; 100];
        assert!(calculate_entropy(&zeros) < 0.01);

        // Random-like data - high entropy
        let random: Vec<u8> = (0..=255).collect();
        let entropy = calculate_entropy(&random);
        assert!(entropy > 0.99);
    }

    #[test]
    fn test_vlan_tag_parse() {
        let vlan_data = [
            0x81, 0x00,  // TPID: 802.1Q
            0x00, 0x64,  // TCI: VLAN 100
        ];

        let tag = VlanTag::parse(&vlan_data).unwrap();
        assert_eq!(tag.vlan_id, 100);
        assert_eq!(tag.priority, 0);
        assert!(!tag.dei);
    }

    #[test]
    fn test_double_vlan_detection() {
        // QinQ double-tagged frame
        let double_tagged = [
            0x88, 0xa8,  // Outer TPID (802.1ad)
            0x00, 0xc8,  // Outer VLAN 200
            0x81, 0x00,  // Inner TPID (802.1Q)
            0x00, 0x64,  // Inner VLAN 100
        ];

        let (outer, inner) = detect_vlan_hopping(&double_tagged).unwrap();
        assert_eq!(outer.vlan_id, 200);
        assert_eq!(inner.vlan_id, 100);
    }
}
