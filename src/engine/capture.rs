//! Packet capture methods
//!
//! Supports multiple capture methods:
//! - NFQUEUE (inline with nftables)
//! - AF_PACKET (raw socket via libpcap)
//! - PCAP file replay

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::time::Duration;

use nfq::{Message, Queue, Verdict};
use pcap::{Capture, Active, Offline};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::core::{Packet, IpProtocol, parse_ethernet_packet, parse_ip_packet};

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

    /// Issue a verdict and, when `mark_good` is set and the packet is ACCEPTED,
    /// tag it with the DPI good-flow mark so nftables bypasses the rest of the
    /// flow in-kernel. Default: ignore the mark (passive captures cannot mark).
    fn set_verdict_marked(
        &mut self,
        packet_id: u64,
        accept: bool,
        _mark_good: bool,
    ) -> anyhow::Result<()> {
        self.set_verdict(packet_id, accept)
    }

    /// Get capture statistics
    fn stats(&mut self) -> CaptureStats;

    /// Close the capture
    fn close(&mut self);

    /// Number of packets captured but not yet verdicted (parked awaiting a
    /// verdict). Non-zero only for inline captures (NFQUEUE); passive captures
    /// issue no verdicts and always return 0. Used at shutdown to drain
    /// in-flight verdicts before closing.
    fn pending_verdicts(&self) -> usize {
        0
    }
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
///
/// Receives packets that nftables has queued to userspace and lets the engine
/// issue an ACCEPT/DROP verdict per packet. Note: traffic from already-blocked
/// IPs is dropped in-kernel by nftables (at a lower chain priority) and never
/// reaches this queue, so this capture only ever sees undecided traffic — there
/// is no blocklist logic here.
pub struct NfqueueCapture {
    queue_num: u16,
    queue: Queue,
    stats: CaptureStats,
    /// Messages awaiting a verdict, keyed by the kernel NFQUEUE packet id.
    ///
    /// `nfq::Queue::verdict` consumes the `Message`, so each received message is
    /// parked here between `next_packet` and `set_verdict` and is removed exactly
    /// once when its verdict is issued.
    pending: HashMap<u64, Message>,
}

impl NfqueueCapture {
    pub fn new(config: &CaptureConfig) -> anyhow::Result<Self> {
        // Opening and binding the queue requires CAP_NET_ADMIN (root).
        let mut queue = Queue::open()
            .map_err(|e| anyhow::anyhow!("failed to open NFQUEUE: {}", e))?;

        queue
            .bind(config.nfqueue_num)
            .map_err(|e| anyhow::anyhow!("failed to bind NFQUEUE {}: {}", config.nfqueue_num, e))?;

        // Non-blocking so the engine's capture loop can poll for the stop signal
        // instead of blocking indefinitely inside `recv`.
        queue.set_nonblocking(true);

        info!("NFQUEUE capture bound to queue {}", config.nfqueue_num);

        Ok(Self {
            queue_num: config.nfqueue_num,
            queue,
            stats: CaptureStats::default(),
            pending: HashMap::new(),
        })
    }
}

impl PacketCapture for NfqueueCapture {
    fn next_packet(&mut self, _packet_id: u64) -> anyhow::Result<Option<Packet>> {
        // The engine assigns ids; for NFQUEUE we must use the kernel-provided
        // packet id so the matching verdict can be routed back to the kernel.
        let msg = match self.queue.recv() {
            Ok(msg) => msg,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // No packet currently queued.
                return Ok(None);
            }
            Err(e) => {
                warn!("NFQUEUE recv error on queue {}: {}", self.queue_num, e);
                return Err(e.into());
            }
        };

        self.stats.received += 1;

        let packet_id = msg.get_packet_id() as u64;

        // NFQUEUE delivers IP-layer payloads (no Ethernet header), so parse from IP.
        let parsed = parse_ip_packet(msg.get_payload(), packet_id, String::new());

        match parsed {
            Some(packet) => {
                // Park the message until the engine issues a verdict for this id.
                self.pending.insert(packet_id, msg);
                Ok(Some(packet))
            }
            None => {
                // Unparseable packet: accept it rather than leak the message (and
                // thereby stall the kernel queue). Every received message must get
                // exactly one verdict.
                debug!(
                    "NFQUEUE packet {} unparseable; accepting by default",
                    packet_id
                );
                self.issue_verdict(msg, true, false);
                Ok(None)
            }
        }
    }

    fn set_verdict(&mut self, packet_id: u64, accept: bool) -> anyhow::Result<()> {
        self.set_verdict_marked(packet_id, accept, false)
    }

    fn set_verdict_marked(
        &mut self,
        packet_id: u64,
        accept: bool,
        mark_good: bool,
    ) -> anyhow::Result<()> {
        match self.pending.remove(&packet_id) {
            Some(msg) => {
                self.issue_verdict(msg, accept, mark_good);
                Ok(())
            }
            None => {
                // Either an unknown id or a packet already verdicted. Treat as a
                // soft error so the engine never panics over a stray id.
                warn!("set_verdict for unknown NFQUEUE packet id {}", packet_id);
                Ok(())
            }
        }
    }

    fn stats(&mut self) -> CaptureStats {
        self.stats.clone()
    }

    fn close(&mut self) {
        // Issue a default ACCEPT for any packets still in flight so the kernel
        // queue does not stall, then unbind.
        for (id, mut msg) in self.pending.drain() {
            msg.set_verdict(Verdict::Accept);
            if let Err(e) = self.queue.verdict(msg) {
                warn!("failed to flush verdict for NFQUEUE packet {}: {}", id, e);
            }
        }
        if let Err(e) = self.queue.unbind(self.queue_num) {
            warn!("failed to unbind NFQUEUE {}: {}", self.queue_num, e);
        }
    }

    fn pending_verdicts(&self) -> usize {
        self.pending.len()
    }
}

impl NfqueueCapture {
    /// Send a single ACCEPT/DROP verdict to the kernel, consuming the message.
    /// When `mark_good` is set and the packet is accepted, tag it with the DPI
    /// good-flow mark; nftables copies that to the connection's ct mark so the
    /// rest of the flow bypasses the queue in-kernel.
    fn issue_verdict(&mut self, mut msg: Message, accept: bool, mark_good: bool) {
        if accept && mark_good {
            msg.set_nfmark(crate::firewall::DPI_GOOD_MARK);
        }
        msg.set_verdict(if accept { Verdict::Accept } else { Verdict::Drop });
        if let Err(e) = self.queue.verdict(msg) {
            warn!("failed to send NFQUEUE verdict: {}", e);
        }
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
    fn next_packet(&mut self, _packet_id: u64) -> anyhow::Result<Option<Packet>> {
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
