use super::error::{NetVecError, Result};
use super::tls::{parse_tls, version_string, TlsInfo as DetailedTlsInfo};
use chrono::{TimeZone, Utc};
use crmonban_types::{
    Direction, EthernetInfo, IcmpInfo, Icmpv6Info, Ipv4Info, Ipv6Info, Layer3, Layer4, Packet,
    TcpFlags, TcpInfo, TlsInfo, UdpInfo,
};
use etherparse::{Icmpv4Type, Icmpv6Type, SlicedPacket, TransportSlice};

pub fn parse_packet(raw: &[u8], timestamp_ns: u64) -> Result<Packet> {
    let sliced = SlicedPacket::from_ethernet(raw)
        .map_err(|e| NetVecError::ParseError(e.to_string()))?;
    parse_sliced_packet(sliced, timestamp_ns, raw.len(), true)
}

/// Parse a raw IP packet (without ethernet header)
/// Used for NFQUEUE which provides IP-level packets
pub fn parse_ip_packet(raw: &[u8], timestamp_ns: u64) -> Result<Packet> {
    let sliced = SlicedPacket::from_ip(raw)
        .map_err(|e| NetVecError::ParseError(e.to_string()))?;
    parse_sliced_packet(sliced, timestamp_ns, raw.len(), false)
}

fn parse_sliced_packet(
    sliced: SlicedPacket,
    timestamp_ns: u64,
    raw_len: usize,
    _has_ethernet: bool,
) -> Result<Packet> {
    // Build timestamp
    let timestamp = Utc.timestamp_nanos(timestamp_ns as i64);

    // Layer 2 - Ethernet
    let ethernet = if let Some(link) = &sliced.link {
        match link {
            etherparse::LinkSlice::Ethernet2(eth) => Some(EthernetInfo {
                src_mac: eth.source(),
                dst_mac: eth.destination(),
                vlan: None,
            }),
            _ => None,
        }
    } else {
        None
    };

    // Layer 3 - IP
    let (layer3, ttl) = match &sliced.net {
        Some(etherparse::InternetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            let info = Ipv4Info {
                src_addr: header.source_addr(),
                dst_addr: header.destination_addr(),
                protocol: header.protocol().0,
                ttl: header.ttl(),
                identification: header.identification(),
                flags: (if header.dont_fragment() { 0x40 } else { 0 })
                    | (if header.more_fragments() { 0x20 } else { 0 }),
                fragment_offset: header.fragments_offset().value(),
                header_length: header.ihl(),
                total_length: header.total_len(),
                dscp: header.dcp().value(),
                ecn: header.ecn().value(),
            };
            (Layer3::Ipv4(info), header.ttl())
        }
        Some(etherparse::InternetSlice::Ipv6(ipv6)) => {
            let header = ipv6.header();
            let info = Ipv6Info {
                src_addr: header.source_addr(),
                dst_addr: header.destination_addr(),
                next_header: header.next_header().0,
                hop_limit: header.hop_limit(),
                traffic_class: header.traffic_class(),
                flow_label: header.flow_label().value(),
                payload_length: header.payload_length(),
            };
            (Layer3::Ipv6(info), header.hop_limit())
        }
        // ARP and other non-IP protocols
        Some(_) => return Err(NetVecError::NoIpLayer),
        None => return Err(NetVecError::NoIpLayer),
    };

    // Get TCP payload for TLS parsing
    let tcp_payload: Option<Vec<u8>> = if let Some(TransportSlice::Tcp(tcp)) = &sliced.transport {
        if let Some(ip_payload) = sliced.ip_payload() {
            let tcp_header_len = tcp.slice().len();
            if ip_payload.payload.len() > tcp_header_len {
                Some(ip_payload.payload[tcp_header_len..].to_vec())
            } else {
                Some(Vec::new())
            }
        } else {
            Some(Vec::new())
        }
    } else {
        None
    };

    // Layer 4 - Transport
    let (layer4, tls) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let payload = tcp_payload.clone().unwrap_or_default();
            let tcp_info = TcpInfo {
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
                payload,
            };

            // Try to parse TLS
            let tls_info = tcp_payload
                .as_ref()
                .filter(|p| !p.is_empty())
                .and_then(|p| parse_tls(p))
                .map(|t| convert_tls_info(&t));

            (Layer4::Tcp(tcp_info), tls_info)
        }
        Some(TransportSlice::Udp(udp)) => {
            let payload = if let Some(ip_payload) = sliced.ip_payload() {
                let udp_header_len = 8; // UDP header is always 8 bytes
                if ip_payload.payload.len() > udp_header_len {
                    ip_payload.payload[udp_header_len..].to_vec()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            let udp_info = UdpInfo {
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
                length: udp.length(),
                payload,
            };
            (Layer4::Udp(udp_info), None)
        }
        Some(TransportSlice::Icmpv4(icmp)) => {
            let payload = icmp.payload().to_vec();
            (Layer4::Icmp(parse_icmpv4(icmp, payload)), None)
        }
        Some(TransportSlice::Icmpv6(icmp)) => {
            let payload = icmp.payload().to_vec();
            (Layer4::Icmpv6(parse_icmpv6(icmp, payload)), None)
        }
        _ => (Layer4::Unknown { protocol: 0 }, None),
    };

    Ok(Packet {
        timestamp,
        id: 0,
        ttl,
        ethernet,
        layer3,
        layer4,
        tls,
        flow_id: None,
        direction: Direction::Unknown,
        interface: String::new(),
        raw_len: raw_len as u32,
    })
}

/// Convert detailed TLS info to simplified packet TLS info
fn convert_tls_info(detailed: &DetailedTlsInfo) -> TlsInfo {
    let version = Some(version_string(detailed.record_version).to_string());
    let sni = detailed
        .client_hello
        .as_ref()
        .and_then(|ch| ch.sni.clone());

    // Generate a simple JA3-like hash from available info
    let ja3_hash = detailed.client_hello.as_ref().map(|ch| {
        format!(
            "{:x}{:x}{:x}",
            ch.ja3_version, ch.ja3_cipher_count, ch.ja3_extension_count
        )
    });

    TlsInfo {
        sni,
        ja3_hash,
        version,
        is_handshake: detailed.record_type == 0x16,
        handshake_type: detailed.handshake_type,
    }
}

fn parse_icmpv4(icmp: &etherparse::Icmpv4Slice, payload: Vec<u8>) -> IcmpInfo {
    let header = icmp.header();
    let (icmp_type, code) = match header.icmp_type {
        Icmpv4Type::EchoRequest(_) => (8, 0),
        Icmpv4Type::EchoReply(_) => (0, 0),
        Icmpv4Type::DestinationUnreachable(du) => (3, du.code_u8()),
        Icmpv4Type::TimeExceeded(te) => (11, te.code_u8()),
        Icmpv4Type::Redirect(r) => (5, r.code.code_u8()),
        _ => (icmp.type_u8(), icmp.code_u8()),
    };

    IcmpInfo {
        icmp_type,
        code,
        payload,
    }
}

fn parse_icmpv6(icmp: &etherparse::Icmpv6Slice, payload: Vec<u8>) -> Icmpv6Info {
    let header = icmp.header();
    let (icmp_type, code) = match header.icmp_type {
        Icmpv6Type::EchoRequest(_) => (128, 0),
        Icmpv6Type::EchoReply(_) => (129, 0),
        Icmpv6Type::DestinationUnreachable(du) => (1, du.code_u8()),
        Icmpv6Type::TimeExceeded(te) => (3, te.code_u8()),
        _ => (icmp.type_u8(), icmp.code_u8()),
    };

    Icmpv6Info {
        icmp_type,
        code,
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_fails() {
        let result = parse_packet(&[], 0);
        assert!(result.is_err());
    }
}
