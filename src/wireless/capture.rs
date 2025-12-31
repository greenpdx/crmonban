//! Wireless Packet Capture
//!
//! Captures 802.11 frames from a monitor mode interface.
//! Uses pcap for raw packet capture.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::radiotap::{parse_radiotap, RadiotapInfo};
use super::ieee80211::{parse_ieee80211, Ieee80211Frame};
use super::interface::{WirelessInterface, InterfaceMode, WirelessBand, WirelessError};

/// Captured wireless frame with metadata
#[derive(Debug, Clone)]
pub struct WirelessFrame {
    /// Raw frame data (without radiotap)
    pub data: Vec<u8>,
    /// Radiotap metadata
    pub radiotap: RadiotapInfo,
    /// Parsed 802.11 frame
    pub frame: Ieee80211Frame,
    /// Capture timestamp
    pub timestamp: Instant,
}

/// Wireless capture configuration
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Interface name
    pub interface: String,
    /// Enable channel hopping
    pub channel_hop: bool,
    /// Channels to hop through (if channel_hop is true)
    pub channels: Vec<u8>,
    /// Channel dwell time in milliseconds
    pub hop_interval_ms: u64,
    /// Filter by BSSID (if set)
    pub bssid_filter: Option<[u8; 6]>,
    /// Capture buffer size
    pub buffer_size: usize,
    /// Promiscuous mode (usually true for monitor mode)
    pub promiscuous: bool,
    /// Immediate mode (lower latency)
    pub immediate: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            interface: String::new(),
            channel_hop: true,
            channels: vec![1, 6, 11], // Common 2.4GHz non-overlapping channels
            hop_interval_ms: 200,
            bssid_filter: None,
            buffer_size: 65536,
            promiscuous: true,
            immediate: true,
        }
    }
}

impl CaptureConfig {
    /// Create config for a specific interface
    pub fn for_interface(name: &str) -> Self {
        Self {
            interface: name.to_string(),
            ..Default::default()
        }
    }

    /// Set channels to hop through
    pub fn with_channels(mut self, channels: Vec<u8>) -> Self {
        self.channels = channels;
        self
    }

    /// Disable channel hopping (stay on one channel)
    pub fn without_hopping(mut self) -> Self {
        self.channel_hop = false;
        self
    }

    /// Filter to specific BSSID
    pub fn with_bssid_filter(mut self, bssid: [u8; 6]) -> Self {
        self.bssid_filter = Some(bssid);
        self
    }

    /// Use 2.4GHz band channels
    pub fn band_2_4ghz(mut self) -> Self {
        self.channels = WirelessBand::Band2_4GHz.channels().to_vec();
        self
    }

    /// Use 5GHz band channels
    pub fn band_5ghz(mut self) -> Self {
        self.channels = WirelessBand::Band5GHz.channels().to_vec();
        self
    }
}

/// Wireless packet capture
pub struct WirelessCapture {
    /// Interface being captured
    interface: WirelessInterface,
    /// Configuration
    config: CaptureConfig,
    /// Running flag
    running: Arc<AtomicBool>,
    /// Current channel index
    current_channel_idx: usize,
    /// Last channel hop time
    last_hop: Instant,
    /// Frame callback
    frame_handler: Option<Box<dyn Fn(WirelessFrame) + Send + Sync>>,
}

impl WirelessCapture {
    /// Create a new wireless capture
    pub fn new(config: CaptureConfig) -> Result<Self, WirelessError> {
        let mut interface = WirelessInterface::get(&config.interface)?;

        // Ensure monitor mode
        if !interface.is_monitor_mode() {
            interface.set_mode(InterfaceMode::Monitor)?;
        }

        // Set initial channel
        if !config.channels.is_empty() {
            interface.set_channel(config.channels[0])?;
        }

        Ok(Self {
            interface,
            config,
            running: Arc::new(AtomicBool::new(false)),
            current_channel_idx: 0,
            last_hop: Instant::now(),
            frame_handler: None,
        })
    }

    /// Set frame handler callback
    pub fn on_frame<F>(&mut self, handler: F)
    where
        F: Fn(WirelessFrame) + Send + Sync + 'static,
    {
        self.frame_handler = Some(Box::new(handler));
    }

    /// Start capture (blocking)
    pub fn start_blocking(&mut self) -> Result<(), CaptureError> {
        self.running.store(true, Ordering::SeqCst);

        // Open pcap capture
        let mut cap = pcap::Capture::from_device(self.config.interface.as_str())
            .map_err(|e| CaptureError::PcapError(e.to_string()))?
            .promisc(self.config.promiscuous)
            .immediate_mode(self.config.immediate)
            .buffer_size(self.config.buffer_size as i32)
            .open()
            .map_err(|e| CaptureError::PcapError(e.to_string()))?;

        while self.running.load(Ordering::SeqCst) {
            // Channel hopping
            if self.config.channel_hop {
                self.maybe_hop_channel();
            }

            // Capture next packet
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some(frame) = self.process_packet(packet.data) {
                        if let Some(ref handler) = self.frame_handler {
                            handler(frame);
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Normal timeout, continue
                }
                Err(e) => {
                    return Err(CaptureError::PcapError(e.to_string()));
                }
            }
        }

        Ok(())
    }

    /// Stop capture
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if capture is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Get running flag for async control
    pub fn running_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.running)
    }

    /// Process a raw packet
    fn process_packet(&self, data: &[u8]) -> Option<WirelessFrame> {
        // Parse radiotap header
        let (_, radiotap, offset) = parse_radiotap(data)?;

        // Parse 802.11 frame
        let frame_data = &data[offset..];
        let frame = parse_ieee80211(frame_data)?;

        // Apply BSSID filter if set
        if let Some(filter_bssid) = &self.config.bssid_filter {
            if let Some(bssid) = frame.bssid() {
                if bssid.as_bytes() != filter_bssid {
                    return None;
                }
            }
        }

        Some(WirelessFrame {
            data: frame_data.to_vec(),
            radiotap,
            frame,
            timestamp: Instant::now(),
        })
    }

    /// Maybe hop to next channel
    fn maybe_hop_channel(&mut self) {
        if self.config.channels.is_empty() {
            return;
        }

        let hop_interval = Duration::from_millis(self.config.hop_interval_ms);
        if self.last_hop.elapsed() >= hop_interval {
            self.current_channel_idx = (self.current_channel_idx + 1) % self.config.channels.len();
            let channel = self.config.channels[self.current_channel_idx];

            if self.interface.set_channel(channel).is_ok() {
                self.last_hop = Instant::now();
            }
        }
    }

    /// Get current channel
    pub fn current_channel(&self) -> Option<u8> {
        self.interface.channel
    }

    /// Get interface info
    pub fn interface(&self) -> &WirelessInterface {
        &self.interface
    }
}

/// Capture errors
#[derive(Debug)]
pub enum CaptureError {
    InterfaceError(WirelessError),
    PcapError(String),
    ChannelError(String),
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptureError::InterfaceError(e) => write!(f, "Interface error: {}", e),
            CaptureError::PcapError(s) => write!(f, "PCAP error: {}", s),
            CaptureError::ChannelError(s) => write!(f, "Channel error: {}", s),
        }
    }
}

impl std::error::Error for CaptureError {}

impl From<WirelessError> for CaptureError {
    fn from(e: WirelessError) -> Self {
        CaptureError::InterfaceError(e)
    }
}
