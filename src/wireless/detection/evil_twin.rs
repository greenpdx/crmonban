//! Evil Twin AP Detection

use std::collections::HashMap;
use std::time::Instant;

use crate::wireless::ieee80211::{Ieee80211Frame, FrameBody, ManagementFrame, MacAddr};
use crate::wireless::state::WirelessStateTracker;
use super::WirelessThreat;

/// Evil twin detector
#[derive(Debug)]
pub struct EvilTwinDetector {
    /// Known SSIDs and their legitimate BSSIDs
    known_ssids: HashMap<String, MacAddr>,
    /// Trusted AP BSSIDs
    trusted_aps: Vec<MacAddr>,
    /// Recently detected evil twins (to avoid duplicate alerts)
    recent_detections: HashMap<(String, MacAddr), Instant>,
}

impl Default for EvilTwinDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl EvilTwinDetector {
    pub fn new() -> Self {
        Self {
            known_ssids: HashMap::new(),
            trusted_aps: Vec::new(),
            recent_detections: HashMap::new(),
        }
    }

    /// Set trusted APs
    pub fn set_trusted_aps(&mut self, aps: Vec<MacAddr>) {
        self.trusted_aps = aps;
    }

    /// Register a known SSID -> BSSID mapping
    pub fn register_known_ap(&mut self, ssid: String, bssid: MacAddr) {
        self.known_ssids.insert(ssid, bssid);
    }

    pub fn check(&mut self, frame: &Ieee80211Frame, state: &WirelessStateTracker) -> Option<WirelessThreat> {
        // Only check beacons and probe responses
        let ssid = match &frame.body {
            FrameBody::Management(ManagementFrame::Beacon(b)) => &b.ssid,
            FrameBody::Management(ManagementFrame::ProbeResponse(p)) => &p.ssid,
            _ => return None,
        };

        if ssid.is_empty() {
            return None;
        }

        let bssid = frame.bssid()?;

        // Skip if this is a trusted AP
        if self.trusted_aps.contains(&bssid) {
            return None;
        }

        // Check if we've seen this SSID with a different trusted BSSID
        if let Some((trusted_bssid, rogue_bssid)) = state.check_evil_twin(ssid) {
            // Avoid duplicate alerts
            let key = (ssid.clone(), rogue_bssid);
            if let Some(last) = self.recent_detections.get(&key) {
                if last.elapsed().as_secs() < 60 {
                    return None;
                }
            }
            self.recent_detections.insert(key, Instant::now());

            // Get signal difference if available
            let signal_diff = if let (Some(trusted_ap), Some(rogue_ap)) =
                (state.get_ap(&trusted_bssid), state.get_ap(&rogue_bssid))
            {
                match (trusted_ap.avg_signal(), rogue_ap.avg_signal()) {
                    (Some(t), Some(r)) => Some(r as i16 - t as i16),
                    _ => None,
                }
            } else {
                None
            };

            return Some(WirelessThreat::EvilTwin {
                ssid: ssid.clone(),
                legitimate_bssid: trusted_bssid,
                rogue_bssid,
                signal_diff,
            });
        }

        // Check against known SSIDs
        if let Some(known_bssid) = self.known_ssids.get(ssid) {
            if *known_bssid != bssid {
                let key = (ssid.clone(), bssid);
                if let Some(last) = self.recent_detections.get(&key) {
                    if last.elapsed().as_secs() < 60 {
                        return None;
                    }
                }
                self.recent_detections.insert(key, Instant::now());

                return Some(WirelessThreat::EvilTwin {
                    ssid: ssid.clone(),
                    legitimate_bssid: *known_bssid,
                    rogue_bssid: bssid,
                    signal_diff: None,
                });
            }
        }

        None
    }
}
