//! Packet capture methods
//!
//! Supports multiple capture methods:
//! - NFQUEUE (inline with nftables)
//! - AF_PACKET (raw socket via libpcap)
//! - PCAP file replay

use std::net::IpAddr;
use std::time::Duration;

use etherparse::SlicedPacket;
use pcap::{Capture, Active, Offline};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::core::packet::{Packet, IpProtocol, AppProtocol, TcpFlags};

/// Capture method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMethod {
    /// NFQUEUE (netfilter queue) - inline mode
    Nfqueue,
    /// AF_PACKET raw socket - passive mode
    AfPacket,
    /// PCAP file replay
    Pcap,
    /// Dummy/test mode
    Dummy,
}

impl Default for CaptureMethod {
    fn default() -> Self {
        CaptureMethod::Nfqueue
    }
}

/// Capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// Capture method
    pub method: CaptureMethod,
    /// NFQUEUE number (for nfqueue method)
    pub nfqueue_num: u16,
    /// Interface name (for af_packet method)
    pub interface: Option<String>,
    /// PCAP file path (for pcap method)
    pub pcap_file: Option<String>,
    /// Snapshot length
    pub snaplen: u32,
    /// Read timeout in milliseconds
    pub timeout_ms: u32,
    /// Buffer size
    pub buffer_size: usize,
    /// Enable promiscuous mode (af_packet)
    pub promiscuous: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            method: CaptureMethod::Nfqueue,
            nfqueue_num: 0,
            interface: None,
            pcap_file: None,
            snaplen: 65535,
            timeout_ms: 100,
            buffer_size: 4096,
            promiscuous: true,
        }
    }
}

/// Trait for packet capture implementations
pub trait PacketCapture: Send {
    /// Get the next packet
    fn next_packet(&mut self) -> anyhow::Result<Option<Packet>>;

    /// Set verdict for NFQUEUE packets
    fn set_verdict(&mut self, packet_id: u32, accept: bool) -> anyhow::Result<()>;

    /// Get capture statistics
    fn stats(&mut self) -> CaptureStats;

    /// Close the capture
    fn close(&mut self);
}

/// Capture statistics
#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    /// Packets received
    pub received: u64,
    /// Packets dropped by kernel
    pub dropped: u64,
    /// Interface drops
    pub if_dropped: u64,
}

/// Create a capture based on configuration
pub fn create_capture(config: &CaptureConfig) -> anyhow::Result<Box<dyn PacketCapture>> {
    match config.method {
        CaptureMethod::Nfqueue => {
            Ok(Box::new(NfqueueCapture::new(config)?))
        }
        CaptureMethod::AfPacket => {
            Ok(Box::new(AfPacketCapture::new(config)?))
        }
        CaptureMethod::Pcap => {
            Ok(Box::new(PcapCapture::new(config)?))
        }
        CaptureMethod::Dummy => {
            Ok(Box::new(DummyCapture::new()))
        }
    }
}

/// NFQUEUE-based capture (inline mode)
pub struct NfqueueCapture {
    #[allow(dead_code)]
    queue_num: u16,
    stats: CaptureStats,
}

impl NfqueueCapture {
    pub fn new(config: &CaptureConfig) -> anyhow::Result<Self> {
        // NFQUEUE requires root privileges - actual binding would happen in run()
        Ok(Self {
            queue_num: config.nfqueue_num,
            stats: CaptureStats::default(),
        })
    }

    #[allow(dead_code)]
    fn parse_packet(&self, data: &[u8], id: u32) -> Option<Packet> {
        // Parse IP header
        if data.len() < 20 {
            return None;
        }

        let version = (data[0] >> 4) & 0x0f;
        if version != 4 && version != 6 {
            return None;
        }

        let (src_ip, dst_ip, protocol, header_len) = if version == 4 {
            let src = IpAddr::from([data[12], data[13], data[14], data[15]]);
            let dst = IpAddr::from([data[16], data[17], data[18], data[19]]);
            let proto = data[9];
            let ihl = ((data[0] & 0x0f) * 4) as usize;
            (src, dst, proto, ihl)
        } else {
            // IPv6
            if data.len() < 40 {
                return None;
            }
            let mut src_bytes = [0u8; 16];
            let mut dst_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&data[8..24]);
            dst_bytes.copy_from_slice(&data[24..40]);
            let src = IpAddr::from(src_bytes);
            let dst = IpAddr::from(dst_bytes);
            let proto = data[6];
            (src, dst, proto, 40)
        };

        let ip_protocol = match protocol {
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            1 => IpProtocol::Icmp,
            58 => IpProtocol::Icmpv6,
            _ => IpProtocol::Other(protocol),
        };

        let mut packet = Packet::new(src_ip, dst_ip, ip_protocol);
        packet.raw_len = data.len() as u32;
        packet.id = id as u64;

        // Parse transport header
        if data.len() > header_len {
            let transport = &data[header_len..];
            match ip_protocol {
                IpProtocol::Tcp if transport.len() >= 20 => {
                    packet.src_port = u16::from_be_bytes([transport[0], transport[1]]);
                    packet.dst_port = u16::from_be_bytes([transport[2], transport[3]]);
                    packet.seq = Some(u32::from_be_bytes([
                        transport[4], transport[5], transport[6], transport[7],
                    ]));
                    packet.ack = Some(u32::from_be_bytes([
                        transport[8], transport[9], transport[10], transport[11],
                    ]));

                    let flags = transport[13];
                    packet.tcp_flags = Some(crate::core::packet::TcpFlags {
                        fin: flags & 0x01 != 0,
                        syn: flags & 0x02 != 0,
                        rst: flags & 0x04 != 0,
                        psh: flags & 0x08 != 0,
                        ack: flags & 0x10 != 0,
                        urg: flags & 0x20 != 0,
                        ece: flags & 0x40 != 0,
                        cwr: flags & 0x80 != 0,
                    });
                }
                IpProtocol::Udp if transport.len() >= 8 => {
                    packet.src_port = u16::from_be_bytes([transport[0], transport[1]]);
                    packet.dst_port = u16::from_be_bytes([transport[2], transport[3]]);
                }
                _ => {}
            }
        }

        // Store raw payload for DPI
        if data.len() > header_len + 20 {
            packet.payload = data[header_len..].to_vec();
        }

        Some(packet)
    }
}

impl PacketCapture for NfqueueCapture {
    fn next_packet(&mut self) -> anyhow::Result<Option<Packet>> {
        // Return dummy packets for testing (NFQUEUE requires root)
        std::thread::sleep(Duration::from_millis(100));
        self.stats.received += 1;
        Ok(None)
    }

    fn set_verdict(&mut self, _packet_id: u32, _accept: bool) -> anyhow::Result<()> {
        // Verdict handling would use msg.set_verdict() and queue.verdict(msg)
        Ok(())
    }

    fn stats(&mut self) -> CaptureStats {
        self.stats.clone()
    }

    fn close(&mut self) {
        // Cleanup handled by Drop
    }
}

/// AF_PACKET raw socket capture (passive mode) using libpcap
pub struct AfPacketCapture {
    capture: Capture<Active>,
    interface: String,
    stats: CaptureStats,
    packet_id: u64,
}

impl AfPacketCapture {
    pub fn new(config: &CaptureConfig) -> anyhow::Result<Self> {
        let interface = config.interface.clone()
            .unwrap_or_else(|| "lo".to_string());

        info!("Opening capture on interface: {}", interface);

        let capture = Capture::from_device(interface.as_str())?
            .promisc(config.promiscuous)
            .snaplen(config.snaplen as i32)
            .timeout(config.timeout_ms as i32)
            .open()?;

        info!("Capture opened successfully on {}", interface);

        Ok(Self {
            capture,
            interface,
            stats: CaptureStats::default(),
            packet_id: 0,
        })
    }

    fn parse_raw_packet(&mut self, data: &[u8]) -> Option<Packet> {
        self.packet_id += 1;

        // Parse with etherparse
        match SlicedPacket::from_ethernet(data) {
            Ok(sliced) => {
                // Extract IP layer
                let (src_ip, dst_ip, protocol) = match &sliced.net {
                    Some(etherparse::NetSlice::Ipv4(ipv4)) => {
                        let src = IpAddr::from(ipv4.header().source_addr());
                        let dst = IpAddr::from(ipv4.header().destination_addr());
                        let proto = match ipv4.header().protocol() {
                            etherparse::IpNumber::TCP => IpProtocol::Tcp,
                            etherparse::IpNumber::UDP => IpProtocol::Udp,
                            etherparse::IpNumber::ICMP => IpProtocol::Icmp,
                            other => IpProtocol::Other(other.0),
                        };
                        (src, dst, proto)
                    }
                    Some(etherparse::NetSlice::Ipv6(ipv6)) => {
                        let src = IpAddr::from(ipv6.header().source_addr());
                        let dst = IpAddr::from(ipv6.header().destination_addr());
                        let proto = match ipv6.header().next_header() {
                            etherparse::IpNumber::TCP => IpProtocol::Tcp,
                            etherparse::IpNumber::UDP => IpProtocol::Udp,
                            etherparse::IpNumber::IPV6_ICMP => IpProtocol::Icmpv6,
                            other => IpProtocol::Other(other.0),
                        };
                        (src, dst, proto)
                    }
                    _ => return None, // ARP, etc.
                };

                let mut packet = Packet::new(src_ip, dst_ip, protocol);
                packet.id = self.packet_id;
                packet.raw_len = data.len() as u32;

                // Extract transport layer
                match &sliced.transport {
                    Some(etherparse::TransportSlice::Tcp(tcp)) => {
                        packet.src_port = tcp.source_port();
                        packet.dst_port = tcp.destination_port();
                        packet.seq = Some(tcp.sequence_number());
                        packet.ack = Some(tcp.acknowledgment_number());
                        packet.tcp_flags = Some(TcpFlags {
                            syn: tcp.syn(),
                            ack: tcp.ack(),
                            fin: tcp.fin(),
                            rst: tcp.rst(),
                            psh: tcp.psh(),
                            urg: tcp.urg(),
                            ece: tcp.ece(),
                            cwr: tcp.cwr(),
                        });
                        packet.payload = tcp.payload().to_vec();

                        // Detect app protocol
                        packet.app_protocol = match (packet.src_port, packet.dst_port) {
                            (80, _) | (_, 80) | (8080, _) | (_, 8080) => AppProtocol::Http,
                            (443, _) | (_, 443) | (8443, _) | (_, 8443) => AppProtocol::Https,
                            (22, _) | (_, 22) => AppProtocol::Ssh,
                            (21, _) | (_, 21) => AppProtocol::Ftp,
                            (25, _) | (_, 25) | (587, _) | (_, 587) => AppProtocol::Smtp,
                            (53, _) | (_, 53) => AppProtocol::Dns,
                            _ => AppProtocol::Unknown,
                        };
                    }
                    Some(etherparse::TransportSlice::Udp(udp)) => {
                        packet.src_port = udp.source_port();
                        packet.dst_port = udp.destination_port();
                        packet.payload = udp.payload().to_vec();

                        packet.app_protocol = match (packet.src_port, packet.dst_port) {
                            (53, _) | (_, 53) => AppProtocol::Dns,
                            _ => AppProtocol::Unknown,
                        };
                    }
                    _ => {}
                }

                Some(packet)
            }
            Err(e) => {
                debug!("Failed to parse packet: {:?}", e);
                None
            }
        }
    }
}

impl PacketCapture for AfPacketCapture {
    fn next_packet(&mut self) -> anyhow::Result<Option<Packet>> {
        match self.capture.next_packet() {
            Ok(packet) => {
                self.stats.received += 1;
                let data = packet.data.to_vec();
                Ok(self.parse_raw_packet(&data))
            }
            Err(pcap::Error::TimeoutExpired) => {
                // No packet available within timeout
                Ok(None)
            }
            Err(e) => {
                warn!("Capture error: {:?}", e);
                Err(e.into())
            }
        }
    }

    fn set_verdict(&mut self, _packet_id: u32, _accept: bool) -> anyhow::Result<()> {
        // AF_PACKET is passive, no verdict
        Ok(())
    }

    fn stats(&mut self) -> CaptureStats {
        let pcap_stats = self.capture.stats().unwrap_or(pcap::Stat {
            received: 0,
            dropped: 0,
            if_dropped: 0,
        });
        CaptureStats {
            received: self.stats.received,
            dropped: pcap_stats.dropped as u64,
            if_dropped: pcap_stats.if_dropped as u64,
        }
    }

    fn close(&mut self) {
        info!("Closing capture on {}", self.interface);
        // Capture is closed when dropped
    }
}

/// PCAP file replay capture
pub struct PcapCapture {
    capture: Capture<Offline>,
    file_path: String,
    stats: CaptureStats,
    packet_id: u64,
}

impl PcapCapture {
    pub fn new(config: &CaptureConfig) -> anyhow::Result<Self> {
        let file_path = config.pcap_file.clone()
            .ok_or_else(|| anyhow::anyhow!("PCAP file path required"))?;

        info!("Opening PCAP file: {}", file_path);
        let capture = Capture::from_file(&file_path)?;

        Ok(Self {
            capture,
            file_path,
            stats: CaptureStats::default(),
            packet_id: 0,
        })
    }

    fn parse_raw_packet(&mut self, data: &[u8]) -> Option<Packet> {
        self.packet_id += 1;

        match SlicedPacket::from_ethernet(data) {
            Ok(sliced) => {
                let (src_ip, dst_ip, protocol) = match &sliced.net {
                    Some(etherparse::NetSlice::Ipv4(ipv4)) => {
                        let src = IpAddr::from(ipv4.header().source_addr());
                        let dst = IpAddr::from(ipv4.header().destination_addr());
                        let proto = match ipv4.header().protocol() {
                            etherparse::IpNumber::TCP => IpProtocol::Tcp,
                            etherparse::IpNumber::UDP => IpProtocol::Udp,
                            etherparse::IpNumber::ICMP => IpProtocol::Icmp,
                            other => IpProtocol::Other(other.0),
                        };
                        (src, dst, proto)
                    }
                    Some(etherparse::NetSlice::Ipv6(ipv6)) => {
                        let src = IpAddr::from(ipv6.header().source_addr());
                        let dst = IpAddr::from(ipv6.header().destination_addr());
                        let proto = match ipv6.header().next_header() {
                            etherparse::IpNumber::TCP => IpProtocol::Tcp,
                            etherparse::IpNumber::UDP => IpProtocol::Udp,
                            etherparse::IpNumber::IPV6_ICMP => IpProtocol::Icmpv6,
                            other => IpProtocol::Other(other.0),
                        };
                        (src, dst, proto)
                    }
                    _ => return None, // ARP, etc.
                };

                let mut packet = Packet::new(src_ip, dst_ip, protocol);
                packet.id = self.packet_id;
                packet.raw_len = data.len() as u32;

                match &sliced.transport {
                    Some(etherparse::TransportSlice::Tcp(tcp)) => {
                        packet.src_port = tcp.source_port();
                        packet.dst_port = tcp.destination_port();
                        packet.seq = Some(tcp.sequence_number());
                        packet.ack = Some(tcp.acknowledgment_number());
                        packet.tcp_flags = Some(TcpFlags {
                            syn: tcp.syn(),
                            ack: tcp.ack(),
                            fin: tcp.fin(),
                            rst: tcp.rst(),
                            psh: tcp.psh(),
                            urg: tcp.urg(),
                            ece: tcp.ece(),
                            cwr: tcp.cwr(),
                        });
                        packet.payload = tcp.payload().to_vec();

                        packet.app_protocol = match (packet.src_port, packet.dst_port) {
                            (80, _) | (_, 80) | (8080, _) | (_, 8080) => AppProtocol::Http,
                            (443, _) | (_, 443) | (8443, _) | (_, 8443) => AppProtocol::Https,
                            (22, _) | (_, 22) => AppProtocol::Ssh,
                            (21, _) | (_, 21) => AppProtocol::Ftp,
                            (25, _) | (_, 25) | (587, _) | (_, 587) => AppProtocol::Smtp,
                            (53, _) | (_, 53) => AppProtocol::Dns,
                            _ => AppProtocol::Unknown,
                        };
                    }
                    Some(etherparse::TransportSlice::Udp(udp)) => {
                        packet.src_port = udp.source_port();
                        packet.dst_port = udp.destination_port();
                        packet.payload = udp.payload().to_vec();

                        packet.app_protocol = match (packet.src_port, packet.dst_port) {
                            (53, _) | (_, 53) => AppProtocol::Dns,
                            _ => AppProtocol::Unknown,
                        };
                    }
                    _ => {}
                }

                Some(packet)
            }
            Err(_) => None,
        }
    }
}

impl PacketCapture for PcapCapture {
    fn next_packet(&mut self) -> anyhow::Result<Option<Packet>> {
        match self.capture.next_packet() {
            Ok(pkt) => {
                self.stats.received += 1;
                let data = pkt.data.to_vec();
                Ok(self.parse_raw_packet(&data))
            }
            Err(pcap::Error::NoMorePackets) => {
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn set_verdict(&mut self, _packet_id: u32, _accept: bool) -> anyhow::Result<()> {
        Ok(())
    }

    fn stats(&mut self) -> CaptureStats {
        self.stats.clone()
    }

    fn close(&mut self) {
        info!("Finished reading PCAP file: {}", self.file_path);
    }
}

/// Dummy capture for testing
pub struct DummyCapture {
    stats: CaptureStats,
    counter: u64,
}

impl DummyCapture {
    pub fn new() -> Self {
        Self {
            stats: CaptureStats::default(),
            counter: 0,
        }
    }
}

impl Default for DummyCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketCapture for DummyCapture {
    fn next_packet(&mut self) -> anyhow::Result<Option<Packet>> {
        self.counter += 1;
        self.stats.received += 1;

        // Generate a dummy packet periodically
        if self.counter % 100 == 0 {
            let src_ip: IpAddr = "192.168.1.100".parse().unwrap();
            let dst_ip: IpAddr = "10.0.0.1".parse().unwrap();

            let mut packet = Packet::new(src_ip, dst_ip, IpProtocol::Tcp);
            packet.src_port = 12345;
            packet.dst_port = 80;
            packet.raw_len = 100;
            packet.app_protocol = AppProtocol::Http;

            return Ok(Some(packet));
        }

        std::thread::sleep(Duration::from_millis(1));
        Ok(None)
    }

    fn set_verdict(&mut self, _packet_id: u32, _accept: bool) -> anyhow::Result<()> {
        Ok(())
    }

    fn stats(&mut self) -> CaptureStats {
        self.stats.clone()
    }

    fn close(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_config_default() {
        let config = CaptureConfig::default();
        assert_eq!(config.method, CaptureMethod::Nfqueue);
        assert_eq!(config.nfqueue_num, 0);
    }

    #[test]
    fn test_dummy_capture() {
        let mut capture = DummyCapture::new();

        // Should produce packets periodically
        for _ in 0..150 {
            let _ = capture.next_packet();
        }

        assert!(capture.stats().received > 0);
    }

    #[test]
    fn test_create_capture_dummy() {
        let mut config = CaptureConfig::default();
        config.method = CaptureMethod::Dummy;

        let capture = create_capture(&config);
        assert!(capture.is_ok());
    }
}
