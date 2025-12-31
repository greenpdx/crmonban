//! Wireless State Tracking
//!
//! Tracks known APs, clients, and their relationships.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::ieee80211::{MacAddr, BeaconFrame, RsnInfo};

/// Access Point state
#[derive(Debug, Clone)]
pub struct ApState {
    /// BSSID (MAC address)
    pub bssid: MacAddr,
    /// SSID
    pub ssid: String,
    /// Channel
    pub channel: u8,
    /// RSN/security info
    pub rsn: Option<RsnInfo>,
    /// Last beacon time
    pub last_beacon: Instant,
    /// Beacon count
    pub beacon_count: u64,
    /// Signal strength history (last N readings)
    pub signal_history: Vec<i8>,
    /// Known associated clients
    pub clients: Vec<MacAddr>,
    /// Is this an expected/known AP?
    pub is_known: bool,
    /// First seen time
    pub first_seen: Instant,
}

impl ApState {
    pub fn new(bssid: MacAddr, ssid: String, channel: u8) -> Self {
        let now = Instant::now();
        Self {
            bssid,
            ssid,
            channel,
            rsn: None,
            last_beacon: now,
            beacon_count: 0,
            signal_history: Vec::with_capacity(10),
            clients: Vec::new(),
            is_known: false,
            first_seen: now,
        }
    }

    /// Update from beacon
    pub fn update_from_beacon(&mut self, beacon: &BeaconFrame, signal: Option<i8>) {
        self.last_beacon = Instant::now();
        self.beacon_count += 1;

        if let Some(ch) = beacon.channel {
            self.channel = ch;
        }

        if beacon.rsn.is_some() {
            self.rsn = beacon.rsn.clone();
        }

        if let Some(sig) = signal {
            self.signal_history.push(sig);
            if self.signal_history.len() > 10 {
                self.signal_history.remove(0);
            }
        }
    }

    /// Add client
    pub fn add_client(&mut self, client: MacAddr) {
        if !self.clients.contains(&client) {
            self.clients.push(client);
        }
    }

    /// Get average signal strength
    pub fn avg_signal(&self) -> Option<i8> {
        if self.signal_history.is_empty() {
            return None;
        }
        let sum: i32 = self.signal_history.iter().map(|&s| s as i32).sum();
        Some((sum / self.signal_history.len() as i32) as i8)
    }

    /// Check if AP is active (seen recently)
    pub fn is_active(&self, timeout: Duration) -> bool {
        self.last_beacon.elapsed() < timeout
    }
}

/// Client state
#[derive(Debug, Clone)]
pub struct ClientState {
    /// Client MAC address
    pub mac: MacAddr,
    /// Associated AP BSSID
    pub associated_bssid: Option<MacAddr>,
    /// Last seen time
    pub last_seen: Instant,
    /// Probe requests sent
    pub probe_requests: u64,
    /// SSIDs probed for
    pub probed_ssids: Vec<String>,
    /// First seen time
    pub first_seen: Instant,
    /// Is this client authenticated?
    pub authenticated: bool,
}

impl ClientState {
    pub fn new(mac: MacAddr) -> Self {
        let now = Instant::now();
        Self {
            mac,
            associated_bssid: None,
            last_seen: now,
            probe_requests: 0,
            probed_ssids: Vec::new(),
            first_seen: now,
            authenticated: false,
        }
    }

    /// Record a probe request
    pub fn add_probe(&mut self, ssid: &str) {
        self.last_seen = Instant::now();
        self.probe_requests += 1;

        if !ssid.is_empty() && !self.probed_ssids.contains(&ssid.to_string()) {
            self.probed_ssids.push(ssid.to_string());
        }
    }

    /// Associate with an AP
    pub fn associate(&mut self, bssid: MacAddr) {
        self.associated_bssid = Some(bssid);
        self.last_seen = Instant::now();
    }

    /// Deauthenticate
    pub fn deauthenticate(&mut self) {
        self.authenticated = false;
    }
}

/// Wireless state tracker
#[derive(Debug)]
pub struct WirelessStateTracker {
    /// Known APs by BSSID
    aps: HashMap<MacAddr, ApState>,
    /// Known clients by MAC
    clients: HashMap<MacAddr, ClientState>,
    /// SSIDs and their BSSIDs (for evil twin detection)
    ssid_to_bssids: HashMap<String, Vec<MacAddr>>,
    /// Known/trusted APs (for whitelisting)
    trusted_aps: Vec<MacAddr>,
    /// Statistics
    stats: WirelessStats,
    /// Last cleanup time
    last_cleanup: Instant,
    /// Timeout for inactive entries
    inactive_timeout: Duration,
}

#[derive(Debug, Default, Clone)]
pub struct WirelessStats {
    pub total_beacons: u64,
    pub total_probes: u64,
    pub total_deauths: u64,
    pub total_disassocs: u64,
    pub total_auth: u64,
    pub unique_aps: u64,
    pub unique_clients: u64,
}

impl Default for WirelessStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl WirelessStateTracker {
    pub fn new() -> Self {
        Self {
            aps: HashMap::new(),
            clients: HashMap::new(),
            ssid_to_bssids: HashMap::new(),
            trusted_aps: Vec::new(),
            stats: WirelessStats::default(),
            last_cleanup: Instant::now(),
            inactive_timeout: Duration::from_secs(300),
        }
    }

    /// Set trusted APs
    pub fn set_trusted_aps(&mut self, aps: Vec<MacAddr>) {
        self.trusted_aps = aps;
    }

    /// Add trusted AP
    pub fn add_trusted_ap(&mut self, bssid: MacAddr) {
        if !self.trusted_aps.contains(&bssid) {
            self.trusted_aps.push(bssid);
        }
    }

    /// Process a beacon frame
    pub fn process_beacon(&mut self, bssid: MacAddr, beacon: &BeaconFrame, signal: Option<i8>) {
        self.stats.total_beacons += 1;

        let ap = self.aps.entry(bssid).or_insert_with(|| {
            self.stats.unique_aps += 1;
            let mut ap = ApState::new(bssid, beacon.ssid.clone(), beacon.channel.unwrap_or(0));
            ap.is_known = self.trusted_aps.contains(&bssid);
            ap
        });

        ap.update_from_beacon(beacon, signal);

        // Track SSID -> BSSID mapping
        let bssids = self.ssid_to_bssids.entry(beacon.ssid.clone()).or_insert_with(Vec::new);
        if !bssids.contains(&bssid) {
            bssids.push(bssid);
        }
    }

    /// Process a probe request
    pub fn process_probe_request(&mut self, client_mac: MacAddr, ssid: &str) {
        self.stats.total_probes += 1;

        let client = self.clients.entry(client_mac).or_insert_with(|| {
            self.stats.unique_clients += 1;
            ClientState::new(client_mac)
        });

        client.add_probe(ssid);
    }

    /// Process a deauth frame
    pub fn process_deauth(&mut self, _bssid: MacAddr, client_mac: MacAddr) {
        self.stats.total_deauths += 1;

        if let Some(client) = self.clients.get_mut(&client_mac) {
            client.deauthenticate();
        }
    }

    /// Process a disassoc frame
    pub fn process_disassoc(&mut self, _bssid: MacAddr, client_mac: MacAddr) {
        self.stats.total_disassocs += 1;

        if let Some(client) = self.clients.get_mut(&client_mac) {
            client.associated_bssid = None;
        }
    }

    /// Process authentication
    pub fn process_auth(&mut self, bssid: MacAddr, client_mac: MacAddr, success: bool) {
        self.stats.total_auth += 1;

        if success {
            let client = self.clients.entry(client_mac).or_insert_with(|| {
                self.stats.unique_clients += 1;
                ClientState::new(client_mac)
            });
            client.authenticated = true;
            client.associated_bssid = Some(bssid);
        }
    }

    /// Get AP by BSSID
    pub fn get_ap(&self, bssid: &MacAddr) -> Option<&ApState> {
        self.aps.get(bssid)
    }

    /// Get all APs with the same SSID (for evil twin detection)
    pub fn get_aps_by_ssid(&self, ssid: &str) -> Vec<&ApState> {
        self.ssid_to_bssids.get(ssid)
            .map(|bssids| bssids.iter().filter_map(|b| self.aps.get(b)).collect())
            .unwrap_or_default()
    }

    /// Check for potential evil twin (multiple BSSIDs for same SSID)
    pub fn check_evil_twin(&self, ssid: &str) -> Option<(MacAddr, MacAddr)> {
        let aps = self.get_aps_by_ssid(ssid);
        if aps.len() >= 2 {
            // Find the trusted one and an untrusted one
            let trusted = aps.iter().find(|a| a.is_known);
            let untrusted = aps.iter().find(|a| !a.is_known);

            if let (Some(t), Some(u)) = (trusted, untrusted) {
                return Some((t.bssid, u.bssid));
            }
        }
        None
    }

    /// Get client by MAC
    pub fn get_client(&self, mac: &MacAddr) -> Option<&ClientState> {
        self.clients.get(mac)
    }

    /// Get statistics
    pub fn stats(&self) -> &WirelessStats {
        &self.stats
    }

    /// Get active AP count
    pub fn active_ap_count(&self) -> usize {
        self.aps.values().filter(|a| a.is_active(self.inactive_timeout)).count()
    }

    /// Cleanup inactive entries
    pub fn cleanup(&mut self) {
        if self.last_cleanup.elapsed() < Duration::from_secs(60) {
            return;
        }

        self.aps.retain(|_, ap| ap.is_active(self.inactive_timeout));
        self.clients.retain(|_, c| c.last_seen.elapsed() < self.inactive_timeout);

        // Clean up SSID mapping
        for bssids in self.ssid_to_bssids.values_mut() {
            bssids.retain(|b| self.aps.contains_key(b));
        }
        self.ssid_to_bssids.retain(|_, bssids| !bssids.is_empty());

        self.last_cleanup = Instant::now();
    }
}
