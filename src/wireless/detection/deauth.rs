//! Deauthentication/Disassociation Flood Detection

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::wireless::ieee80211::{Ieee80211Frame, FrameBody, ManagementFrame, FrameSubtype, MacAddr};
use crate::wireless::state::WirelessStateTracker;
use super::WirelessThreat;

/// Deauth/disassoc flood detector
#[derive(Debug)]
pub struct DeauthDetector {
    /// Deauth counts per BSSID in current window
    deauth_counts: HashMap<MacAddr, DeauthStats>,
    /// Detection thresholds
    config: DeauthConfig,
}

#[derive(Debug, Clone)]
struct DeauthStats {
    count: u64,
    window_start: Instant,
    last_reason: u16,
}

#[derive(Debug, Clone)]
pub struct DeauthConfig {
    /// Deauths per second threshold
    pub rate_threshold: f32,
    /// Window duration
    pub window_secs: u64,
}

impl Default for DeauthConfig {
    fn default() -> Self {
        Self {
            rate_threshold: 10.0,  // 10 deauths/sec is suspicious
            window_secs: 5,
        }
    }
}

impl DeauthDetector {
    pub fn new() -> Self {
        Self {
            deauth_counts: HashMap::new(),
            config: DeauthConfig::default(),
        }
    }

    pub fn with_config(config: DeauthConfig) -> Self {
        Self {
            deauth_counts: HashMap::new(),
            config,
        }
    }

    pub fn check(&mut self, frame: &Ieee80211Frame, _state: &WirelessStateTracker) -> Option<WirelessThreat> {
        // Check for deauth or disassoc frames
        let (reason_code, is_disassoc) = match &frame.body {
            FrameBody::Management(ManagementFrame::Deauthentication(d)) => (d.reason_code, false),
            FrameBody::Management(ManagementFrame::Disassociation(d)) => (d.reason_code, true),
            _ => return None,
        };

        let bssid = frame.bssid()?;

        // Update counts
        let now = Instant::now();
        let window = Duration::from_secs(self.config.window_secs);

        let stats = self.deauth_counts.entry(bssid).or_insert_with(|| DeauthStats {
            count: 0,
            window_start: now,
            last_reason: 0,
        });

        // Reset window if expired
        if stats.window_start.elapsed() > window {
            stats.count = 0;
            stats.window_start = now;
        }

        stats.count += 1;
        stats.last_reason = reason_code;

        // Calculate rate
        let elapsed = stats.window_start.elapsed().as_secs_f32().max(0.1);
        let rate = stats.count as f32 / elapsed;

        if rate > self.config.rate_threshold {
            if is_disassoc {
                return Some(WirelessThreat::DisassocFlood {
                    bssid,
                    rate,
                });
            } else {
                return Some(WirelessThreat::DeauthFlood {
                    bssid,
                    rate,
                    reason_code,
                });
            }
        }

        None
    }
}

impl Default for DeauthDetector {
    fn default() -> Self {
        Self::new()
    }
}
