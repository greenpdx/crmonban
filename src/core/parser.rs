//! Modular packet parsing functions
//!
//! Separates packet parsing into distinct stages:
//! - `parse_ethernet()` - Layer 2 (Ethernet frame)
//! - `parse_ip()` - Layer 3 (IPv4/IPv6)
//! - `parse_transport()` - Layer 4 (TCP/UDP/ICMP)
//!
//! App protocol detection is NOT done here - that belongs in the Protocol Analysis stage.

use std::net::IpAddr;
use etherparse::SlicedPacket;

use crmonban_types::{
    Packet, IpProtocol, TcpFlags,
    Layer3, Layer4, EthernetInfo,
    Ipv4Info, Ipv6Info,
    TcpInfo as LayerTcpInfo, UdpInfo, IcmpInfo, Icmpv6Info,
};

/// Result of parsing the IP layer
#[derive(Debug, Clone)]
pub struct IpInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: IpProtocol,
    pub ttl: u8,
    pub ip_flags: u8,
    pub frag_offset: u16,
    pub ip_id: u16,
}

/// Result of parsing the transport layer
#[derive(Debug, Clone)]
pub struct TransportInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: Option<TcpFlags>,
    pub seq: Option<u32>,
    pub ack: Option<u32>,
    pub window: Option<u16>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub payload: Vec<u8>,
}

impl Default for TransportInfo {
    fn default() -> Self {
        Self {
            src_port: 0,
            dst_port: 0,
            tcp_flags: None,
            seq: None,
            ack: None,
            window: None,
            icmp_type: None,
            icmp_code: None,
            payload: Vec::new(),
        }
    }
}

/// Parse the IP layer from etherparse SlicedPacket
///
/// Returns None for non-IP packets (ARP, etc.)
pub fn parse_ip(sliced: &SlicedPacket<'_>) -> Option<IpInfo> {
    match &sliced.net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            Some(IpInfo {
                src_ip: IpAddr::from(header.source_addr()),
                dst_ip: IpAddr::from(header.destination_addr()),
                protocol: match header.protocol() {
                    etherparse::IpNumber::TCP => IpProtocol::Tcp,
                    etherparse::IpNumber::UDP => IpProtocol::Udp,
                    etherparse::IpNumber::ICMP => IpProtocol::Icmp,
                    other => IpProtocol::Other(other.0),
                },
                ttl: header.ttl(),
                ip_flags: if header.dont_fragment() { 0x40 } else { 0 }
                    | if header.more_fragments() { 0x20 } else { 0 },
                frag_offset: header.fragments_offset().value(),
                ip_id: header.identification(),
            })
        }
        Some(etherparse::NetSlice::Ipv6(ipv6)) => {
            let header = ipv6.header();
            Some(IpInfo {
                src_ip: IpAddr::from(header.source_addr()),
                dst_ip: IpAddr::from(header.destination_addr()),
                protocol: match header.next_header() {
                    etherparse::IpNumber::TCP => IpProtocol::Tcp,
                    etherparse::IpNumber::UDP => IpProtocol::Udp,
                    etherparse::IpNumber::IPV6_ICMP => IpProtocol::Icmpv6,
                    other => IpProtocol::Other(other.0),
                },
                ttl: header.hop_limit(),
                ip_flags: 0,
                frag_offset: 0,
                ip_id: 0,
            })
        }
        _ => None, // ARP, etc.
    }
}

/// Parse the transport layer from etherparse SlicedPacket
pub fn parse_transport(sliced: &SlicedPacket<'_>) -> TransportInfo {
    match &sliced.transport {
        Some(etherparse::TransportSlice::Tcp(tcp)) => {
            TransportInfo {
                src_port: tcp.source_port(),
                dst_port: tcp.destination_port(),
                tcp_flags: Some(TcpFlags {
                    fin: tcp.fin(),
                    syn: tcp.syn(),
                    rst: tcp.rst(),
                    psh: tcp.psh(),
                    ack: tcp.ack(),
                    urg: tcp.urg(),
                    ece: tcp.ece(),
                    cwr: tcp.cwr(),
                }),
                seq: Some(tcp.sequence_number()),
                ack: Some(tcp.acknowledgment_number()),
                window: Some(tcp.window_size()),
                icmp_type: None,
                icmp_code: None,
                payload: tcp.payload().to_vec(),
            }
        }
        Some(etherparse::TransportSlice::Udp(udp)) => {
            TransportInfo {
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
                tcp_flags: None,
                seq: None,
                ack: None,
                window: None,
                icmp_type: None,
                icmp_code: None,
                payload: udp.payload().to_vec(),
            }
        }
        Some(etherparse::TransportSlice::Icmpv4(icmp)) => {
            // Extract ICMP type and code from the slice bytes
            let bytes = icmp.slice();
            let (icmp_type, icmp_code) = if bytes.len() >= 2 {
                (bytes[0], bytes[1])
            } else {
                (0, 0)
            };
            TransportInfo {
                src_port: 0,
                dst_port: 0,
                tcp_flags: None,
                seq: None,
                ack: None,
                window: None,
                icmp_type: Some(icmp_type),
                icmp_code: Some(icmp_code),
                payload: icmp.payload().to_vec(),
            }
        }
        Some(etherparse::TransportSlice::Icmpv6(icmp)) => {
            // Extract ICMPv6 type and code from the slice bytes
            let bytes = icmp.slice();
            let (icmp_type, icmp_code) = if bytes.len() >= 2 {
                (bytes[0], bytes[1])
            } else {
                (0, 0)
            };
            TransportInfo {
                src_port: 0,
                dst_port: 0,
                tcp_flags: None,
                seq: None,
                ack: None,
                window: None,
                icmp_type: Some(icmp_type),
                icmp_code: Some(icmp_code),
                payload: icmp.payload().to_vec(),
            }
        }
        _ => TransportInfo::default(),
    }
}

/// Build Layer3 from parsed IP info
fn build_layer3(sliced: &SlicedPacket<'_>) -> Option<Layer3> {
    match &sliced.net {
        Some(etherparse::NetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            Some(Layer3::Ipv4(Ipv4Info {
                src_addr: header.source_addr(),
                dst_addr: header.destination_addr(),
                protocol: header.protocol().0,
                ttl: header.ttl(),
                identification: header.identification(),
                flags: if header.dont_fragment() { 0x02 } else { 0 }
                    | if header.more_fragments() { 0x01 } else { 0 },
                fragment_offset: header.fragments_offset().value(),
                header_length: header.ihl(),
                total_length: header.total_len(),
                dscp: header.dcp().value(),
                ecn: header.ecn().value(),
            }))
        }
        Some(etherparse::NetSlice::Ipv6(ipv6)) => {
            let header = ipv6.header();
            Some(Layer3::Ipv6(Ipv6Info {
                src_addr: header.source_addr(),
                dst_addr: header.destination_addr(),
                next_header: header.next_header().0,
                hop_limit: header.hop_limit(),
                traffic_class: header.traffic_class(),
                flow_label: header.flow_label().value(),
                payload_length: header.payload_length(),
            }))
        }
        _ => None,
    }
}

/// Build Layer4 from parsed transport info
fn build_layer4(sliced: &SlicedPacket<'_>, protocol: IpProtocol) -> Layer4 {
    match &sliced.transport {
        Some(etherparse::TransportSlice::Tcp(tcp)) => {
            Layer4::Tcp(LayerTcpInfo {
                src_port: tcp.source_port(),
                dst_port: tcp.destination_port(),
                seq: tcp.sequence_number(),
                ack: tcp.acknowledgment_number(),
                flags: TcpFlags {
                    fin: tcp.fin(),
                    syn: tcp.syn(),
                    rst: tcp.rst(),
                    psh: tcp.psh(),
                    ack: tcp.ack(),
                    urg: tcp.urg(),
                    ece: tcp.ece(),
                    cwr: tcp.cwr(),
                },
                window: tcp.window_size(),
                urgent_ptr: tcp.urgent_pointer(),
                data_offset: tcp.data_offset(),
                payload: tcp.payload().to_vec(),
            })
        }
        Some(etherparse::TransportSlice::Udp(udp)) => {
            Layer4::Udp(UdpInfo {
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
                length: udp.length(),
                payload: udp.payload().to_vec(),
            })
        }
        Some(etherparse::TransportSlice::Icmpv4(icmp)) => {
            let bytes = icmp.slice();
            let (icmp_type, icmp_code) = if bytes.len() >= 2 {
                (bytes[0], bytes[1])
            } else {
                (0, 0)
            };
            Layer4::Icmp(IcmpInfo {
                icmp_type,
                code: icmp_code,
                payload: icmp.payload().to_vec(),
            })
        }
        Some(etherparse::TransportSlice::Icmpv6(icmp)) => {
            let bytes = icmp.slice();
            let (icmp_type, icmp_code) = if bytes.len() >= 2 {
                (bytes[0], bytes[1])
            } else {
                (0, 0)
            };
            Layer4::Icmpv6(Icmpv6Info {
                icmp_type,
                code: icmp_code,
                payload: icmp.payload().to_vec(),
            })
        }
        _ => Layer4::Unknown { protocol: protocol.into() },
    }
}

/// Parse a raw ethernet frame into a Packet
///
/// This is the main entry point for packet parsing.
/// Note: app_protocol is NOT set here - that's done in the Protocol Analysis stage.
pub fn parse_ethernet_packet(
    data: &[u8],
    packet_id: u64,
    interface: String,
) -> Option<Packet> {
    // Parse with etherparse
    let sliced = match SlicedPacket::from_ethernet(data) {
        Ok(s) => s,
        Err(_) => return None,
    };

    // Build Layer 3
    let layer3 = build_layer3(&sliced)?;

    // Get protocol for Layer 4 building
    let protocol = IpProtocol::from(layer3.protocol());

    // Build Layer 4
    let layer4 = build_layer4(&sliced, protocol);

    // Build packet from layers
    let mut packet = Packet::from_layers(packet_id, layer3, layer4, interface);
    packet.raw_len = data.len() as u32;

    // Extract ethernet info
    if let Some(link) = &sliced.link {
        match link {
            etherparse::LinkSlice::Ethernet2(eth) => {
                packet.ethernet = Some(EthernetInfo {
                    src_mac: eth.source(),
                    dst_mac: eth.destination(),
                    vlan: None, // TODO: parse VLAN tags
                });
            }
            _ => {}
        }
    }

    // Note: app_protocol is left as Unknown - Protocol Analysis stage will set it

    Some(packet)
}

/// Parse raw IP packet (no ethernet header) - for NFQUEUE
pub fn parse_ip_packet(
    data: &[u8],
    packet_id: u64,
    interface: String,
) -> Option<Packet> {
    // Determine IP version
    if data.is_empty() {
        return None;
    }

    let version = (data[0] >> 4) & 0x0f;
    if version != 4 && version != 6 {
        return None;
    }

    let sliced = SlicedPacket::from_ip(data).ok()?;

    // Build Layer 3
    let layer3 = build_layer3(&sliced)?;

    // Get protocol for Layer 4 building
    let protocol = IpProtocol::from(layer3.protocol());

    // Build Layer 4
    let layer4 = build_layer4(&sliced, protocol);

    // Build packet from layers
    let mut packet = Packet::from_layers(packet_id, layer3, layer4, interface);
    packet.raw_len = data.len() as u32;

    Some(packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Simple TCP SYN packet over IPv4/Ethernet
    fn make_tcp_syn_packet() -> Vec<u8> {
        // Ethernet header (14 bytes)
        let mut pkt = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst mac
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src mac
            0x08, 0x00, // ethertype IPv4
        ];

        // IPv4 header (20 bytes)
        pkt.extend_from_slice(&[
            0x45, // version=4, ihl=5
            0x00, // dscp/ecn
            0x00, 0x28, // total length (40 = 20 IP + 20 TCP)
            0x12, 0x34, // identification
            0x40, 0x00, // flags (DF), fragment offset
            0x40, // TTL
            0x06, // protocol TCP
            0x00, 0x00, // checksum (ignored)
            192, 168, 1, 100, // src IP
            10, 0, 0, 1, // dst IP
        ]);

        // TCP header (20 bytes) - SYN
        pkt.extend_from_slice(&[
            0x30, 0x39, // src port 12345
            0x00, 0x50, // dst port 80
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, // data offset=5, flags=SYN
            0xff, 0xff, // window
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent pointer
        ]);

        pkt
    }

    #[test]
    fn test_parse_ethernet_packet() {
        let data = make_tcp_syn_packet();
        let packet = parse_ethernet_packet(&data, 1, "eth0".to_string());

        assert!(packet.is_some());
        let pkt = packet.unwrap();

        assert_eq!(pkt.id, 1);
        assert_eq!(pkt.interface, "eth0");
        assert_eq!(pkt.src_ip().to_string(), "192.168.1.100");
        assert_eq!(pkt.dst_ip().to_string(), "10.0.0.1");
        assert_eq!(pkt.protocol(), IpProtocol::Tcp);
        assert_eq!(pkt.src_port(), 12345);
        assert_eq!(pkt.dst_port(), 80);
        assert_eq!(pkt.ttl(), 64);

        // Check TCP flags
        let flags = pkt.tcp_flags().unwrap();
        assert!(flags.syn);
        assert!(!flags.ack);
        assert!(!flags.fin);
    }

    #[test]
    fn test_parse_ip_functions() {
        let data = make_tcp_syn_packet();
        let sliced = SlicedPacket::from_ethernet(&data).unwrap();

        let ip_info = parse_ip(&sliced);
        assert!(ip_info.is_some());
        let ip = ip_info.unwrap();
        assert_eq!(ip.protocol, IpProtocol::Tcp);
        assert_eq!(ip.ttl, 64);

        let transport = parse_transport(&sliced);
        assert_eq!(transport.src_port, 12345);
        assert_eq!(transport.dst_port, 80);
        assert!(transport.tcp_flags.unwrap().syn);
    }

}
