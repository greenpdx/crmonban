//! 802.11 Wireless Attack Detection Module
//!
//! This module provides detection for wireless network attacks:
//! - Deauth/disassoc floods
//! - Evil twin AP detection
//! - Beacon/probe floods
//! - WPA handshake capture detection
//! - KRACK attack detection
//! - Karma attack detection
//!
//! Requires a wireless interface in monitor mode for live capture.

pub mod radiotap;
pub mod interface;
pub mod capture;
pub mod ieee80211;
pub mod detection;
pub mod state;

pub use radiotap::{RadiotapHeader, RadiotapInfo};
pub use interface::{WirelessInterface, InterfaceMode, WirelessBand, WirelessCapabilities};
pub use capture::WirelessCapture;
pub use ieee80211::{
    Ieee80211Frame, FrameControl, FrameType, FrameSubtype,
    ManagementFrame, ControlFrame, DataFrame,
    BeaconFrame, ProbeRequest, ProbeResponse,
    DeauthFrame, DisassocFrame, AuthFrame,
    MacAddr,
};
pub use detection::{
    WirelessDetector, WirelessThreat,
    DeauthDetector, EvilTwinDetector, BeaconDetector,
    HandshakeDetector, KrackDetector,
};
pub use state::{ApState, ClientState, WirelessStateTracker};

// ═══════════════════════════════════════════════════════════════════════════════
// Feature Vector Indices (128-143)
// ═══════════════════════════════════════════════════════════════════════════════

/// Deauth/Disassoc features (128-131)
pub const DEAUTH_RATE: usize = 128;
pub const DISASSOC_RATE: usize = 129;
pub const DEAUTH_UNIQUE_TARGETS: usize = 130;
pub const DEAUTH_REASON_DIVERSITY: usize = 131;

/// Beacon/Probe features (132-135)
pub const BEACON_RATE: usize = 132;
pub const PROBE_REQUEST_RATE: usize = 133;
pub const PROBE_RESPONSE_RATE: usize = 134;
pub const SSID_DIVERSITY: usize = 135;

/// Evil Twin features (136-139)
pub const DUPLICATE_SSID_COUNT: usize = 136;
pub const BSSID_CHANGE_RATE: usize = 137;
pub const SIGNAL_STRENGTH_ANOMALY: usize = 138;
pub const CHANNEL_ANOMALY: usize = 139;

/// Handshake/Crypto features (140-143)
pub const EAPOL_KEY_RATE: usize = 140;
pub const HANDSHAKE_REPLAY_RATIO: usize = 141;
pub const KEY_REINSTALL_DETECTED: usize = 142;
pub const PMKID_CAPTURE_DETECTED: usize = 143;

/// Total feature count for wireless
pub const WIRELESS_FEATURE_COUNT: usize = 16;

/// Starting index for wireless features
pub const WIRELESS_FEATURE_START: usize = 128;
