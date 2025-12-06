//! Unified packet representation
//!
//! Represents a network packet with all layers parsed for analysis.

use std::net::IpAddr;
use std::time::Instant;
use serde::{Deserialize, Serialize};

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

/// Application layer protocol (auto-detected or by port)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AppProtocol {
    Unknown,
    Http,
    Https,
    Dns,
    Ssh,
    Ftp,
    FtpData,
    Smtp,
    Pop3,
    Imap,
    Smb,
    Mysql,
    Postgres,
    Redis,
    Mongodb,
    Ldap,
    Rdp,
    Vnc,
    Telnet,
    Sip,
    Ntp,
    Dhcp,
    Snmp,
}

impl AppProtocol {
    /// Guess protocol from well-known port
    pub fn from_port(port: u16, proto: IpProtocol) -> Self {
        match (proto, port) {
            (IpProtocol::Tcp, 80) => AppProtocol::Http,
            (IpProtocol::Tcp, 443) => AppProtocol::Https,
            (IpProtocol::Tcp, 8080) => AppProtocol::Http,
            (IpProtocol::Tcp, 8443) => AppProtocol::Https,
            (IpProtocol::Udp, 53) | (IpProtocol::Tcp, 53) => AppProtocol::Dns,
            (IpProtocol::Tcp, 22) => AppProtocol::Ssh,
            (IpProtocol::Tcp, 21) => AppProtocol::Ftp,
            (IpProtocol::Tcp, 20) => AppProtocol::FtpData,
            (IpProtocol::Tcp, 25) | (IpProtocol::Tcp, 587) | (IpProtocol::Tcp, 465) => AppProtocol::Smtp,
            (IpProtocol::Tcp, 110) | (IpProtocol::Tcp, 995) => AppProtocol::Pop3,
            (IpProtocol::Tcp, 143) | (IpProtocol::Tcp, 993) => AppProtocol::Imap,
            (IpProtocol::Tcp, 445) | (IpProtocol::Tcp, 139) => AppProtocol::Smb,
            (IpProtocol::Tcp, 3306) => AppProtocol::Mysql,
            (IpProtocol::Tcp, 5432) => AppProtocol::Postgres,
            (IpProtocol::Tcp, 6379) => AppProtocol::Redis,
            (IpProtocol::Tcp, 27017) => AppProtocol::Mongodb,
            (IpProtocol::Tcp, 389) | (IpProtocol::Tcp, 636) => AppProtocol::Ldap,
            (IpProtocol::Tcp, 3389) => AppProtocol::Rdp,
            (IpProtocol::Tcp, 5900..=5909) => AppProtocol::Vnc,
            (IpProtocol::Tcp, 23) => AppProtocol::Telnet,
            (IpProtocol::Udp, 5060) | (IpProtocol::Tcp, 5060) => AppProtocol::Sip,
            (IpProtocol::Udp, 123) => AppProtocol::Ntp,
            (IpProtocol::Udp, 67) | (IpProtocol::Udp, 68) => AppProtocol::Dhcp,
            (IpProtocol::Udp, 161) | (IpProtocol::Udp, 162) => AppProtocol::Snmp,
            _ => AppProtocol::Unknown,
        }
    }
}

impl std::fmt::Display for AppProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppProtocol::Unknown => write!(f, "unknown"),
            AppProtocol::Http => write!(f, "http"),
            AppProtocol::Https => write!(f, "https"),
            AppProtocol::Dns => write!(f, "dns"),
            AppProtocol::Ssh => write!(f, "ssh"),
            AppProtocol::Ftp => write!(f, "ftp"),
            AppProtocol::FtpData => write!(f, "ftp-data"),
            AppProtocol::Smtp => write!(f, "smtp"),
            AppProtocol::Pop3 => write!(f, "pop3"),
            AppProtocol::Imap => write!(f, "imap"),
            AppProtocol::Smb => write!(f, "smb"),
            AppProtocol::Mysql => write!(f, "mysql"),
            AppProtocol::Postgres => write!(f, "postgres"),
            AppProtocol::Redis => write!(f, "redis"),
            AppProtocol::Mongodb => write!(f, "mongodb"),
            AppProtocol::Ldap => write!(f, "ldap"),
            AppProtocol::Rdp => write!(f, "rdp"),
            AppProtocol::Vnc => write!(f, "vnc"),
            AppProtocol::Telnet => write!(f, "telnet"),
            AppProtocol::Sip => write!(f, "sip"),
            AppProtocol::Ntp => write!(f, "ntp"),
            AppProtocol::Dhcp => write!(f, "dhcp"),
            AppProtocol::Snmp => write!(f, "snmp"),
        }
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
#[derive(Debug, Clone)]
pub struct Packet {
    /// Packet arrival timestamp
    pub timestamp: Instant,
    /// Unique packet ID
    pub id: u64,

    // Layer 2 (optional)
    /// Source MAC address
    pub src_mac: Option<[u8; 6]>,
    /// Destination MAC address
    pub dst_mac: Option<[u8; 6]>,
    /// VLAN tag
    pub vlan: Option<u16>,

    // Layer 3
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// IP protocol
    pub protocol: IpProtocol,
    /// Time to live
    pub ttl: u8,
    /// IP flags (fragmentation)
    pub ip_flags: u8,
    /// Fragment offset
    pub frag_offset: u16,
    /// IP ID
    pub ip_id: u16,

    // Layer 4
    /// Source port (TCP/UDP)
    pub src_port: u16,
    /// Destination port (TCP/UDP)
    pub dst_port: u16,
    /// TCP flags
    pub tcp_flags: Option<TcpFlags>,
    /// TCP sequence number
    pub seq: Option<u32>,
    /// TCP acknowledgment number
    pub ack: Option<u32>,
    /// TCP window size
    pub window: Option<u16>,
    /// ICMP type
    pub icmp_type: Option<u8>,
    /// ICMP code
    pub icmp_code: Option<u8>,

    // Layer 7
    /// Detected application protocol
    pub app_protocol: AppProtocol,
    /// Payload data
    pub payload: Vec<u8>,

    // Metadata
    /// Associated flow ID
    pub flow_id: Option<u64>,
    /// Packet direction
    pub direction: Direction,
    /// Capture interface
    pub interface: Option<String>,
    /// Raw packet length (including headers)
    pub raw_len: u32,
}

impl Packet {
    /// Create a new packet with minimal info
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, protocol: IpProtocol) -> Self {
        Self {
            timestamp: Instant::now(),
            id: 0,
            src_mac: None,
            dst_mac: None,
            vlan: None,
            src_ip,
            dst_ip,
            protocol,
            ttl: 64,
            ip_flags: 0,
            frag_offset: 0,
            ip_id: 0,
            src_port: 0,
            dst_port: 0,
            tcp_flags: None,
            seq: None,
            ack: None,
            window: None,
            icmp_type: None,
            icmp_code: None,
            app_protocol: AppProtocol::Unknown,
            payload: Vec::new(),
            flow_id: None,
            direction: Direction::Unknown,
            interface: None,
            raw_len: 0,
        }
    }

    /// Parse packet from etherparse SlicedPacket
    pub fn from_etherparse(data: &[u8], id: u64) -> Option<Self> {
        use etherparse::SlicedPacket;

        let sliced = SlicedPacket::from_ethernet(data).ok()?;

        let (src_mac, dst_mac) = match &sliced.link {
            Some(etherparse::LinkSlice::Ethernet2(eth)) => {
                (Some(eth.source()), Some(eth.destination()))
            }
            _ => (None, None),
        };

        let (src_ip, dst_ip, protocol, ttl, ip_flags, ip_id, frag_offset) = match &sliced.net {
            Some(etherparse::NetSlice::Ipv4(ipv4)) => {
                let header = ipv4.header();
                (
                    IpAddr::V4(header.source_addr()),
                    IpAddr::V4(header.destination_addr()),
                    IpProtocol::from(header.protocol().0),
                    header.ttl(),
                    if header.dont_fragment() { 0x40 } else { 0 } |
                        if header.more_fragments() { 0x20 } else { 0 },
                    header.identification(),
                    header.fragments_offset().value(),
                )
            }
            Some(etherparse::NetSlice::Ipv6(ipv6)) => {
                let header = ipv6.header();
                (
                    IpAddr::V6(header.source_addr()),
                    IpAddr::V6(header.destination_addr()),
                    IpProtocol::from(header.next_header().0),
                    header.hop_limit(),
                    0,
                    0,
                    0,
                )
            }
            Some(etherparse::NetSlice::Arp(_)) | None => return None,
        };

        let mut pkt = Packet::new(src_ip, dst_ip, protocol);
        pkt.id = id;
        pkt.src_mac = src_mac;
        pkt.dst_mac = dst_mac;
        pkt.ttl = ttl;
        pkt.ip_flags = ip_flags;
        pkt.ip_id = ip_id;
        pkt.frag_offset = frag_offset;
        pkt.raw_len = data.len() as u32;

        match &sliced.transport {
            Some(etherparse::TransportSlice::Tcp(tcp)) => {
                pkt.src_port = tcp.source_port();
                pkt.dst_port = tcp.destination_port();
                pkt.tcp_flags = Some(TcpFlags {
                    fin: tcp.fin(),
                    syn: tcp.syn(),
                    rst: tcp.rst(),
                    psh: tcp.psh(),
                    ack: tcp.ack(),
                    urg: tcp.urg(),
                    ece: tcp.ece(),
                    cwr: tcp.cwr(),
                });
                pkt.seq = Some(tcp.sequence_number());
                pkt.ack = Some(tcp.acknowledgment_number());
                pkt.window = Some(tcp.window_size());
            }
            Some(etherparse::TransportSlice::Udp(udp)) => {
                pkt.src_port = udp.source_port();
                pkt.dst_port = udp.destination_port();
            }
            Some(etherparse::TransportSlice::Icmpv4(icmp)) => {
                pkt.icmp_type = Some(icmp.type_u8());
                pkt.icmp_code = Some(icmp.code_u8());
            }
            Some(etherparse::TransportSlice::Icmpv6(icmp)) => {
                pkt.icmp_type = Some(icmp.type_u8());
                pkt.icmp_code = Some(icmp.code_u8());
            }
            None => {}
        }

        if let Some(ip_payload) = sliced.ip_payload() {
            pkt.payload = ip_payload.payload.to_vec();
        }

        // Guess app protocol from ports
        let server_port = pkt.dst_port.min(pkt.src_port);
        pkt.app_protocol = AppProtocol::from_port(server_port, pkt.protocol);

        Some(pkt)
    }

    /// Get 5-tuple key for flow tracking
    pub fn flow_key(&self) -> (IpAddr, IpAddr, u16, u16, IpProtocol) {
        // Normalize so smaller IP/port is always first
        if (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port) {
            (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)
        } else {
            (self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol)
        }
    }

    /// Check if this is the client-to-server direction
    pub fn is_to_server(&self) -> bool {
        matches!(self.direction, Direction::ToServer)
    }

    /// Check if packet is fragmented
    pub fn is_fragmented(&self) -> bool {
        self.frag_offset > 0 || (self.ip_flags & 0x20) != 0
    }

    /// Get payload as string (lossy UTF-8)
    pub fn payload_str(&self) -> String {
        String::from_utf8_lossy(&self.payload).to_string()
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
    fn test_app_protocol_from_port() {
        assert_eq!(AppProtocol::from_port(80, IpProtocol::Tcp), AppProtocol::Http);
        assert_eq!(AppProtocol::from_port(443, IpProtocol::Tcp), AppProtocol::Https);
        assert_eq!(AppProtocol::from_port(53, IpProtocol::Udp), AppProtocol::Dns);
        assert_eq!(AppProtocol::from_port(22, IpProtocol::Tcp), AppProtocol::Ssh);
    }

    #[test]
    fn test_packet_new() {
        let pkt = Packet::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            IpProtocol::Tcp,
        );
        assert_eq!(pkt.protocol, IpProtocol::Tcp);
        assert_eq!(pkt.ttl, 64);
    }
}
