//! KRACK (Key Reinstallation Attack) Detection

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::wireless::ieee80211::{Ieee80211Frame, FrameBody, DataFrame, MacAddr};
use super::WirelessThreat;

/// KRACK attack detector
/// Detects key reinstallation by monitoring for:
/// - Retransmission of message 3 in 4-way handshake
/// - Abnormal replay counter behavior
/// - Multiple identical key nonces
#[derive(Debug)]
pub struct KrackDetector {
    /// Tracked sessions: (bssid, client) -> KrackState
    sessions: HashMap<(MacAddr, MacAddr), KrackState>,
    /// Config
    config: KrackConfig,
}

#[derive(Debug, Clone)]
struct KrackState {
    /// Message 3 count
    msg3_count: u32,
    /// Last replay counter seen
    last_replay_counter: u64,
    /// Nonces seen for each message
    nonces: HashMap<u8, Vec<[u8; 32]>>,
    /// First seen time
    first_seen: Instant,
}

#[derive(Debug, Clone)]
pub struct KrackConfig {
    /// Message 3 retransmit threshold
    pub msg3_threshold: u32,
    /// Session timeout
    pub session_timeout_secs: u64,
}

impl Default for KrackConfig {
    fn default() -> Self {
        Self {
            msg3_threshold: 3,     // 3 msg3s in a short period is suspicious
            session_timeout_secs: 60,
        }
    }
}

impl Default for KrackDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl KrackDetector {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            config: KrackConfig::default(),
        }
    }

    pub fn check(&mut self, frame: &Ieee80211Frame) -> Option<WirelessThreat> {
        // Only check data frames with EAPOL-Key
        let eapol = match &frame.body {
            FrameBody::Data(d) if d.has_eapol() => d.eapol.as_ref()?,
            _ => return None,
        };

        if !eapol.is_key() {
            return None;
        }

        let key_data = eapol.key_data.as_ref()?;
        let msg_num = key_data.message_number();

        let bssid = frame.bssid()?;
        let client = if frame.frame_control.from_ds {
            frame.destination()?
        } else {
            frame.source()?
        };

        let key = (bssid, client);
        let now = Instant::now();
        let timeout = Duration::from_secs(self.config.session_timeout_secs);

        let state = self.sessions.entry(key).or_insert_with(|| KrackState {
            msg3_count: 0,
            last_replay_counter: 0,
            nonces: HashMap::new(),
            first_seen: now,
        });

        // Reset if timeout
        if state.first_seen.elapsed() > timeout {
            state.msg3_count = 0;
            state.last_replay_counter = 0;
            state.nonces.clear();
            state.first_seen = now;
        }

        // Track replay counter
        let replay_counter = key_data.replay_counter;

        // Check for replay counter reuse (key reinstallation indicator)
        if replay_counter != 0 && replay_counter <= state.last_replay_counter && msg_num == 3 {
            // Replay counter went backwards or stayed same - suspicious
            return Some(WirelessThreat::KrackAttack {
                bssid,
                client,
                msg_num,
            });
        }

        state.last_replay_counter = replay_counter;

        // Track nonces per message type
        let nonce = key_data.nonce;
        let nonces = state.nonces.entry(msg_num).or_insert_with(Vec::new);

        // Check for nonce reuse (another KRACK indicator)
        if nonces.contains(&nonce) && msg_num == 3 {
            return Some(WirelessThreat::KrackAttack {
                bssid,
                client,
                msg_num,
            });
        }

        nonces.push(nonce);
        if nonces.len() > 10 {
            nonces.remove(0); // Keep last 10
        }

        // Count message 3 occurrences
        if msg_num == 3 {
            state.msg3_count += 1;

            if state.msg3_count >= self.config.msg3_threshold {
                // Reset count to avoid duplicate alerts
                state.msg3_count = 0;
                return Some(WirelessThreat::KrackAttack {
                    bssid,
                    client,
                    msg_num,
                });
            }
        }

        None
    }
}
