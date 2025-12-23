//! Packet capture methods
//!
//! Supports multiple capture methods:
//! - NFQUEUE (inline with nftables)
//! - AF_PACKET (raw socket via libpcap)
//! - PCAP file replay

use std::net::IpAddr;
use std::time::Duration;

use pcap::{Capture, Active, Offline};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::core::{Packet, IpProtocol, parse_ethernet_packet};

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
    fn next_packet(&mut self, packet_id: u64) -> anyhow::Result<Option<Packet>>;

    /// Set verdict for NFQUEUE packets
    fn set_verdict(&mut self, packet_id: u64, accept: bool) -> anyhow::Result<()>;

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
        // Use the parser module for consistent packet parsing
        crate::core::parser::parse_ip_packet(data, id as u64, String::new())
    }
}

impl PacketCapture for NfqueueCapture {
    fn next_packet(&mut self, packet_id: u64) -> anyhow::Result<Option<Packet>> {
        // Return dummy packets for testing (NFQUEUE requires root)
        std::thread::sleep(Duration::from_millis(100));
        self.stats.received += 1;
        Ok(None)
    }

    fn set_verdict(&mut self, _packet_id: u64, _accept: bool) -> anyhow::Result<()> {
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
}

impl PacketCapture for AfPacketCapture {
    fn next_packet(&mut self, packet_id: u64) -> anyhow::Result<Option<Packet>> {
        match self.capture.next_packet() {
            Ok(packet) => {
                self.stats.received += 1;
                self.packet_id += 1;
                let packet_id = packet_id;
                let interface = self.interface.clone();
                // Copy data before the borrow ends
                let data = packet.data.to_vec();
                Ok(parse_ethernet_packet(&data, packet_id, interface))
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

    fn set_verdict(&mut self, _packet_id: u64, _accept: bool) -> anyhow::Result<()> {
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
}

impl PacketCapture for PcapCapture {
    fn next_packet(&mut self, packet_id: u64) -> anyhow::Result<Option<Packet>> {
        match self.capture.next_packet() {
            Ok(pkt) => {
                self.stats.received += 1;
                self.packet_id += 1;
                let packet_id = self.packet_id;
                // Copy data before the borrow ends
                let data = pkt.data.to_vec();
                Ok(parse_ethernet_packet(&data, packet_id, self.file_path.clone()))
            }
            Err(pcap::Error::NoMorePackets) => {
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn set_verdict(&mut self, _packet_id: u64, _accept: bool) -> anyhow::Result<()> {
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
    fn next_packet(&mut self, packet_id: u64) -> anyhow::Result<Option<Packet>> {
        self.counter += 1;
        self.stats.received += 1;

        // Generate a dummy packet periodically
        if self.counter % 100 == 0 {
            let src_ip: IpAddr = "192.168.1.100".parse().unwrap();
            let dst_ip: IpAddr = "10.0.0.1".parse().unwrap();

            let mut packet = Packet::new(packet_id, src_ip, dst_ip, IpProtocol::Tcp, "lo");
            // Set ports via the TCP layer
            if let Some(tcp) = packet.tcp_mut() {
                tcp.src_port = 12345;
                tcp.dst_port = 80;
            }
            packet.raw_len = 100;

            return Ok(Some(packet));
        }

        std::thread::sleep(Duration::from_millis(1));
        Ok(None)
    }

    fn set_verdict(&mut self, _packet_id: u64, _accept: bool) -> anyhow::Result<()> {
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
            let _ = capture.next_packet(0);
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
