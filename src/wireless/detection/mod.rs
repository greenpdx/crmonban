//! Wireless Attack Detection
//!
//! Detects various wireless attacks.

mod deauth;
mod evil_twin;
mod beacon;
mod handshake;
mod krack;

pub use deauth::DeauthDetector;
pub use evil_twin::EvilTwinDetector;
pub use beacon::BeaconDetector;
pub use handshake::HandshakeDetector;
pub use krack::KrackDetector;

use crate::wireless::state::WirelessStateTracker;
use crate::wireless::ieee80211::{Ieee80211Frame, MacAddr};
use crate::wireless::radiotap::RadiotapInfo;

/// Wireless threat types
#[derive(Debug, Clone)]
pub enum WirelessThreat {
    /// Deauthentication flood
    DeauthFlood {
        bssid: MacAddr,
        rate: f32,
        reason_code: u16,
    },
    /// Disassociation flood
    DisassocFlood {
        bssid: MacAddr,
        rate: f32,
    },
    /// Evil twin AP detected
    EvilTwin {
        ssid: String,
        legitimate_bssid: MacAddr,
        rogue_bssid: MacAddr,
        signal_diff: Option<i16>,
    },
    /// Fake AP detected
    FakeAp {
        ssid: String,
        bssid: MacAddr,
    },
    /// Beacon flood
    BeaconFlood {
        source_mac: MacAddr,
        ssid_count: u32,
    },
    /// Karma attack (responding to all probes)
    KarmaAttack {
        ap_mac: MacAddr,
        probe_count: u32,
    },
    /// Authentication flood
    AuthFlood {
        bssid: MacAddr,
        rate: f32,
    },
    /// Probe flood
    ProbeFlood {
        source_mac: MacAddr,
        rate: f32,
    },
    /// PMKID capture attempt
    PmkidCapture {
        bssid: MacAddr,
        client: MacAddr,
    },
    /// WPA handshake capture
    HandshakeCapture {
        bssid: MacAddr,
        client: MacAddr,
    },
    /// KRACK attack
    KrackAttack {
        bssid: MacAddr,
        client: MacAddr,
        msg_num: u8,
    },
}

/// Main wireless detector combining all sub-detectors
#[derive(Debug)]
pub struct WirelessDetector {
    /// State tracker
    state: WirelessStateTracker,
    /// Deauth detector
    deauth: DeauthDetector,
    /// Evil twin detector
    evil_twin: EvilTwinDetector,
    /// Beacon detector
    beacon: BeaconDetector,
    /// Handshake detector
    handshake: HandshakeDetector,
    /// KRACK detector
    krack: KrackDetector,
}

impl Default for WirelessDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl WirelessDetector {
    pub fn new() -> Self {
        Self {
            state: WirelessStateTracker::new(),
            deauth: DeauthDetector::new(),
            evil_twin: EvilTwinDetector::new(),
            beacon: BeaconDetector::new(),
            handshake: HandshakeDetector::new(),
            krack: KrackDetector::new(),
        }
    }

    /// Set trusted APs
    pub fn set_trusted_aps(&mut self, aps: Vec<MacAddr>) {
        self.state.set_trusted_aps(aps.clone());
        self.evil_twin.set_trusted_aps(aps);
    }

    /// Process a wireless frame and detect threats
    pub fn process_frame(&mut self, frame: &Ieee80211Frame, radiotap: &RadiotapInfo) -> Vec<WirelessThreat> {
        let mut threats = Vec::new();

        // Update state based on frame type
        self.update_state(frame, radiotap);

        // Run all detectors
        if let Some(t) = self.deauth.check(frame, &self.state) {
            threats.push(t);
        }

        if let Some(t) = self.evil_twin.check(frame, &self.state) {
            threats.push(t);
        }

        threats.extend(self.beacon.check(frame, &self.state));

        if let Some(t) = self.handshake.check(frame) {
            threats.push(t);
        }

        if let Some(t) = self.krack.check(frame) {
            threats.push(t);
        }

        // Periodic cleanup
        self.state.cleanup();

        threats
    }

    /// Update state from frame
    fn update_state(&mut self, frame: &Ieee80211Frame, radiotap: &RadiotapInfo) {
        use crate::wireless::ieee80211::{FrameBody, ManagementFrame};

        if let FrameBody::Management(mgmt) = &frame.body {
            match mgmt {
                ManagementFrame::Beacon(beacon) => {
                    if let Some(bssid) = frame.bssid() {
                        self.state.process_beacon(bssid, beacon, radiotap.signal_dbm);
                    }
                }
                ManagementFrame::ProbeRequest(probe) => {
                    if let Some(src) = frame.source() {
                        self.state.process_probe_request(src, &probe.ssid);
                    }
                }
                ManagementFrame::Deauthentication(_) => {
                    if let (Some(bssid), Some(client)) = (frame.bssid(), frame.destination()) {
                        self.state.process_deauth(bssid, client);
                    }
                }
                ManagementFrame::Disassociation(_) => {
                    if let (Some(bssid), Some(client)) = (frame.bssid(), frame.destination()) {
                        self.state.process_disassoc(bssid, client);
                    }
                }
                ManagementFrame::Authentication(auth) => {
                    if let (Some(bssid), Some(client)) = (frame.bssid(), frame.source()) {
                        self.state.process_auth(bssid, client, auth.is_success());
                    }
                }
                _ => {}
            }
        }
    }

    /// Get state tracker
    pub fn state(&self) -> &WirelessStateTracker {
        &self.state
    }

    /// Get mutable state tracker
    pub fn state_mut(&mut self) -> &mut WirelessStateTracker {
        &mut self.state
    }
}
