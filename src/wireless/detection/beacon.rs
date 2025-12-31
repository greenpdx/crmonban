//! Beacon and Probe Flood Detection

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::wireless::ieee80211::{Ieee80211Frame, FrameBody, ManagementFrame, MacAddr};
use crate::wireless::state::WirelessStateTracker;
use super::WirelessThreat;

/// Beacon/probe flood detector
#[derive(Debug)]
pub struct BeaconDetector {
    /// Beacon counts per source MAC
    beacon_sources: HashMap<MacAddr, BeaconStats>,
    /// Probe response counts (for Karma detection)
    probe_responses: HashMap<MacAddr, ProbeStats>,
    /// Config
    config: BeaconConfig,
}

#[derive(Debug, Clone)]
struct BeaconStats {
    ssids: Vec<String>,
    count: u64,
    window_start: Instant,
}

#[derive(Debug, Clone)]
struct ProbeStats {
    responded_ssids: Vec<String>,
    window_start: Instant,
}

#[derive(Debug, Clone)]
pub struct BeaconConfig {
    /// SSIDs per source threshold for beacon flood
    pub ssid_threshold: u32,
    /// Probe responses threshold for Karma detection
    pub karma_threshold: u32,
    /// Window duration
    pub window_secs: u64,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            ssid_threshold: 20,   // 20 unique SSIDs from one source
            karma_threshold: 10,  // Responding to 10+ different probe requests
            window_secs: 60,
        }
    }
}

impl Default for BeaconDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BeaconDetector {
    pub fn new() -> Self {
        Self {
            beacon_sources: HashMap::new(),
            probe_responses: HashMap::new(),
            config: BeaconConfig::default(),
        }
    }

    pub fn check(&mut self, frame: &Ieee80211Frame, _state: &WirelessStateTracker) -> Vec<WirelessThreat> {
        let mut threats = Vec::new();
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_secs);

        match &frame.body {
            FrameBody::Management(ManagementFrame::Beacon(beacon)) => {
                let source = frame.addr2.unwrap_or(MacAddr::ZERO);

                let stats = self.beacon_sources.entry(source).or_insert_with(|| BeaconStats {
                    ssids: Vec::new(),
                    count: 0,
                    window_start: now,
                });

                // Reset window if expired
                if stats.window_start.elapsed() > window {
                    stats.ssids.clear();
                    stats.count = 0;
                    stats.window_start = now;
                }

                stats.count += 1;
                if !beacon.ssid.is_empty() && !stats.ssids.contains(&beacon.ssid) {
                    stats.ssids.push(beacon.ssid.clone());
                }

                // Check for beacon flood (many SSIDs from one source)
                if stats.ssids.len() as u32 > self.config.ssid_threshold {
                    threats.push(WirelessThreat::BeaconFlood {
                        source_mac: source,
                        ssid_count: stats.ssids.len() as u32,
                    });
                }
            }

            FrameBody::Management(ManagementFrame::ProbeResponse(probe)) => {
                // Karma attack: AP responding to many different SSIDs
                let bssid = frame.bssid().unwrap_or(MacAddr::ZERO);

                let stats = self.probe_responses.entry(bssid).or_insert_with(|| ProbeStats {
                    responded_ssids: Vec::new(),
                    window_start: now,
                });

                if stats.window_start.elapsed() > window {
                    stats.responded_ssids.clear();
                    stats.window_start = now;
                }

                if !probe.ssid.is_empty() && !stats.responded_ssids.contains(&probe.ssid) {
                    stats.responded_ssids.push(probe.ssid.clone());
                }

                if stats.responded_ssids.len() as u32 > self.config.karma_threshold {
                    threats.push(WirelessThreat::KarmaAttack {
                        ap_mac: bssid,
                        probe_count: stats.responded_ssids.len() as u32,
                    });
                }
            }

            _ => {}
        }

        threats
    }
}
