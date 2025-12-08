//! Packet generator and sender
//!
//! Generates and sends packets using pcap for injection.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use chrono::{DateTime, Utc};
use pcap::Device;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::icmp::{MutableIcmpPacket, IcmpTypes};
use pnet::util::MacAddr;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::attacks::AttackType;
use crate::state_machine::TcpFlags;

/// Packet record for logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketRecord {
    /// Unique packet ID
    pub id: u64,
    /// Timestamp when sent
    pub timestamp: DateTime<Utc>,
    /// Attack type
    pub attack_type: AttackType,
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination port
    pub dst_port: u16,
    /// Protocol (tcp/udp/icmp)
    pub protocol: String,
    /// TCP flags if applicable
    pub tcp_flags: Option<u8>,
    /// Payload size
    pub payload_size: usize,
    /// Payload hash (first 8 chars of MD5)
    pub payload_hash: Option<String>,
    /// Sequence number for TCP
    pub seq: Option<u32>,
    /// Ack number for TCP
    pub ack: Option<u32>,
}

impl PacketRecord {
    pub fn new(id: u64, attack_type: AttackType) -> Self {
        Self {
            id,
            timestamp: Utc::now(),
            attack_type,
            src_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            src_port: 0,
            dst_port: 0,
            protocol: String::new(),
            tcp_flags: None,
            payload_size: 0,
            payload_hash: None,
            seq: None,
            ack: None,
        }
    }

    pub fn with_tcp(
        mut self,
        src: SocketAddr,
        dst: SocketAddr,
        flags: TcpFlags,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> Self {
        self.src_ip = src.ip();
        self.dst_ip = dst.ip();
        self.src_port = src.port();
        self.dst_port = dst.port();
        self.protocol = "tcp".to_string();
        self.tcp_flags = Some(flags.to_u8());
        self.seq = Some(seq);
        self.ack = Some(ack);
        self.payload_size = payload.len();
        if !payload.is_empty() {
            let hash = format!("{:x}", md5::compute(payload));
            self.payload_hash = Some(hash[..8].to_string());
        }
        self
    }

    pub fn with_udp(mut self, src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Self {
        self.src_ip = src.ip();
        self.dst_ip = dst.ip();
        self.src_port = src.port();
        self.dst_port = dst.port();
        self.protocol = "udp".to_string();
        self.payload_size = payload.len();
        if !payload.is_empty() {
            let hash = format!("{:x}", md5::compute(payload));
            self.payload_hash = Some(hash[..8].to_string());
        }
        self
    }

    pub fn with_icmp(mut self, src: IpAddr, dst: IpAddr) -> Self {
        self.src_ip = src;
        self.dst_ip = dst;
        self.protocol = "icmp".to_string();
        self
    }
}

/// Packet sender configuration
#[derive(Debug, Clone)]
pub struct SenderConfig {
    /// Network interface to send on
    pub interface: String,
    /// Source MAC address (if known)
    pub src_mac: Option<MacAddr>,
    /// Destination MAC address (gateway)
    pub dst_mac: Option<MacAddr>,
    /// Packets per second limit (0 = unlimited)
    pub rate_limit: u64,
    /// Whether to actually send or dry-run
    pub dry_run: bool,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            src_mac: None,
            dst_mac: None,
            rate_limit: 0,
            dry_run: false,
        }
    }
}

/// Packet sender using pcap
pub struct PacketSender {
    config: SenderConfig,
    cap: Option<pcap::Capture<pcap::Active>>,
    packet_counter: AtomicU64,
    start_time: Instant,
}

impl PacketSender {
    pub fn new(config: SenderConfig) -> anyhow::Result<Self> {
        let cap = if !config.dry_run {
            let device = Device::list()?
                .into_iter()
                .find(|d| d.name == config.interface);

            if let Some(dev) = device {
                let capture = pcap::Capture::from_device(dev)?
                    .promisc(false)
                    .snaplen(65535)
                    .open()?;
                Some(capture)
            } else {
                warn!("Interface {} not found, available interfaces:", config.interface);
                for dev in Device::list()? {
                    warn!("  - {}", dev.name);
                }
                None
            }
        } else {
            None
        };

        Ok(Self {
            config,
            cap,
            packet_counter: AtomicU64::new(0),
            start_time: Instant::now(),
        })
    }

    /// Get next packet ID
    pub fn next_id(&self) -> u64 {
        self.packet_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Get total packets sent
    pub fn packets_sent(&self) -> u64 {
        self.packet_counter.load(Ordering::SeqCst)
    }

    /// Get packets per second rate
    pub fn current_rate(&self) -> f64 {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.packets_sent() as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Build a TCP packet
    pub fn build_tcp_packet(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        flags: TcpFlags,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let src_ip = match src.ip() {
            IpAddr::V4(ip) => ip,
            _ => return vec![],
        };
        let dst_ip = match dst.ip() {
            IpAddr::V4(ip) => ip,
            _ => return vec![],
        };

        // Calculate sizes
        let tcp_header_len = 20;
        let ip_header_len = 20;
        let eth_header_len = 14;
        let total_len = eth_header_len + ip_header_len + tcp_header_len + payload.len();

        let mut buffer = vec![0u8; total_len];

        // Ethernet header
        {
            let mut eth = MutableEthernetPacket::new(&mut buffer[..eth_header_len]).unwrap();
            eth.set_source(self.config.src_mac.unwrap_or(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)));
            eth.set_destination(self.config.dst_mac.unwrap_or(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)));
            eth.set_ethertype(EtherTypes::Ipv4);
        }

        // IP header
        {
            let mut ip = MutableIpv4Packet::new(&mut buffer[eth_header_len..eth_header_len + ip_header_len + tcp_header_len + payload.len()]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((ip_header_len + tcp_header_len + payload.len()) as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip.set_source(src_ip);
            ip.set_destination(dst_ip);
            // Checksum calculated by kernel usually
        }

        // TCP header
        {
            let tcp_start = eth_header_len + ip_header_len;
            let mut tcp = MutableTcpPacket::new(&mut buffer[tcp_start..]).unwrap();
            tcp.set_source(src.port());
            tcp.set_destination(dst.port());
            tcp.set_sequence(seq);
            tcp.set_acknowledgement(ack);
            tcp.set_data_offset(5);
            tcp.set_flags(flags.to_u8());
            tcp.set_window(65535);

            // Copy payload
            if !payload.is_empty() {
                let payload_start = tcp_start + tcp_header_len;
                buffer[payload_start..payload_start + payload.len()].copy_from_slice(payload);
            }
        }

        buffer
    }

    /// Build a UDP packet
    pub fn build_udp_packet(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        let src_ip = match src.ip() {
            IpAddr::V4(ip) => ip,
            _ => return vec![],
        };
        let dst_ip = match dst.ip() {
            IpAddr::V4(ip) => ip,
            _ => return vec![],
        };

        let udp_header_len = 8;
        let ip_header_len = 20;
        let eth_header_len = 14;
        let total_len = eth_header_len + ip_header_len + udp_header_len + payload.len();

        let mut buffer = vec![0u8; total_len];

        // Ethernet header
        {
            let mut eth = MutableEthernetPacket::new(&mut buffer[..eth_header_len]).unwrap();
            eth.set_source(self.config.src_mac.unwrap_or(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)));
            eth.set_destination(self.config.dst_mac.unwrap_or(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)));
            eth.set_ethertype(EtherTypes::Ipv4);
        }

        // IP header
        {
            let mut ip = MutableIpv4Packet::new(&mut buffer[eth_header_len..]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((ip_header_len + udp_header_len + payload.len()) as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip.set_source(src_ip);
            ip.set_destination(dst_ip);
        }

        // UDP header
        {
            let udp_start = eth_header_len + ip_header_len;
            let mut udp = MutableUdpPacket::new(&mut buffer[udp_start..]).unwrap();
            udp.set_source(src.port());
            udp.set_destination(dst.port());
            udp.set_length((udp_header_len + payload.len()) as u16);

            // Copy payload
            if !payload.is_empty() {
                let payload_start = udp_start + udp_header_len;
                buffer[payload_start..payload_start + payload.len()].copy_from_slice(payload);
            }
        }

        buffer
    }

    /// Build ICMP echo request
    pub fn build_icmp_packet(&self, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let icmp_len = 8;
        let ip_header_len = 20;
        let eth_header_len = 14;
        let total_len = eth_header_len + ip_header_len + icmp_len;

        let mut buffer = vec![0u8; total_len];

        // Ethernet header
        {
            let mut eth = MutableEthernetPacket::new(&mut buffer[..eth_header_len]).unwrap();
            eth.set_source(self.config.src_mac.unwrap_or(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)));
            eth.set_destination(self.config.dst_mac.unwrap_or(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)));
            eth.set_ethertype(EtherTypes::Ipv4);
        }

        // IP header
        {
            let mut ip = MutableIpv4Packet::new(&mut buffer[eth_header_len..]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((ip_header_len + icmp_len) as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip.set_source(src);
            ip.set_destination(dst);
        }

        // ICMP header
        {
            let icmp_start = eth_header_len + ip_header_len;
            let mut icmp = MutableIcmpPacket::new(&mut buffer[icmp_start..]).unwrap();
            icmp.set_icmp_type(IcmpTypes::EchoRequest);
            icmp.set_icmp_code(pnet::packet::icmp::IcmpCode::new(0));
        }

        buffer
    }

    /// Send a raw packet (dry run just counts)
    pub fn send(&mut self, packet: &[u8]) -> anyhow::Result<bool> {
        self.packet_counter.fetch_add(1, Ordering::SeqCst);

        if self.config.dry_run || self.cap.is_none() {
            // Just count, don't actually send
            return Ok(true);
        }

        // Rate limiting
        if self.config.rate_limit > 0 {
            let target_rate = self.config.rate_limit as f64;
            let current = self.current_rate();
            if current > target_rate {
                let delay_us = ((current - target_rate) / target_rate * 1000.0) as u64;
                std::thread::sleep(std::time::Duration::from_micros(delay_us.min(1000)));
            }
        }

        // Actually send via pcap
        if let Some(ref mut cap) = self.cap {
            match cap.sendpacket(packet) {
                Ok(_) => Ok(true),
                Err(e) => {
                    warn!("Failed to send packet: {:?}", e);
                    Ok(false)
                }
            }
        } else {
            Ok(false)
        }
    }

    /// Check if we can actually send
    pub fn can_send(&self) -> bool {
        !self.config.dry_run && self.cap.is_some()
    }
}

/// Statistics collector
#[derive(Debug, Clone, Default, Serialize)]
pub struct GeneratorStats {
    pub total_packets: u64,
    pub packets_by_type: std::collections::HashMap<String, u64>,
    pub bytes_sent: u64,
    pub duration_secs: f64,
    pub packets_per_second: f64,
}
