//! WPA Handshake Capture Detection

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::wireless::ieee80211::{Ieee80211Frame, FrameBody, DataFrame, MacAddr};
use super::WirelessThreat;

/// Handshake capture detector
#[derive(Debug)]
pub struct HandshakeDetector {
    /// Tracked handshakes: (bssid, client) -> HandshakeState
    handshakes: HashMap<(MacAddr, MacAddr), HandshakeState>,
    /// Config
    config: HandshakeConfig,
}

#[derive(Debug, Clone)]
struct HandshakeState {
    /// Messages seen (bits for msg 1-4)
    messages_seen: u8,
    /// First message time
    first_seen: Instant,
    /// PMKID detected
    pmkid_detected: bool,
}

#[derive(Debug, Clone)]
pub struct HandshakeConfig {
    /// Timeout for handshake completion
    pub handshake_timeout_secs: u64,
}

impl Default for HandshakeConfig {
    fn default() -> Self {
        Self {
            handshake_timeout_secs: 30,
        }
    }
}

impl Default for HandshakeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeDetector {
    pub fn new() -> Self {
        Self {
            handshakes: HashMap::new(),
            config: HandshakeConfig::default(),
        }
    }

    pub fn check(&mut self, frame: &Ieee80211Frame) -> Option<WirelessThreat> {
        // Only check data frames with EAPOL
        let eapol = match &frame.body {
            FrameBody::Data(d) if d.has_eapol() => d.eapol.as_ref()?,
            _ => return None,
        };

        // Only EAPOL-Key frames
        if !eapol.is_key() {
            return None;
        }

        let key_data = eapol.key_data.as_ref()?;
        let msg_num = key_data.message_number();
        if msg_num == 0 {
            return None;
        }

        let bssid = frame.bssid()?;
        let client = if frame.frame_control.from_ds {
            frame.destination()?
        } else {
            frame.source()?
        };

        let key = (bssid, client);
        let now = Instant::now();
        let timeout = Duration::from_secs(self.config.handshake_timeout_secs);

        let state = self.handshakes.entry(key).or_insert_with(|| HandshakeState {
            messages_seen: 0,
            first_seen: now,
            pmkid_detected: false,
        });

        // Reset if timeout
        if state.first_seen.elapsed() > timeout {
            state.messages_seen = 0;
            state.first_seen = now;
            state.pmkid_detected = false;
        }

        // Mark message seen
        state.messages_seen |= 1 << (msg_num - 1);

        // Check for PMKID in message 1
        if msg_num == 1 && key_data.has_pmkid() {
            if !state.pmkid_detected {
                state.pmkid_detected = true;
                return Some(WirelessThreat::PmkidCapture {
                    bssid,
                    client,
                });
            }
        }

        // Check if we've captured a complete handshake (all 4 messages)
        // This indicates someone might be capturing for offline cracking
        if state.messages_seen == 0x0f {
            // Reset to avoid duplicate alerts
            state.messages_seen = 0;
            return Some(WirelessThreat::HandshakeCapture {
                bssid,
                client,
            });
        }

        None
    }
}
