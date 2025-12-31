//! Wireless Interface Management
//!
//! Uses nl80211 (via neli-wifi) for interface discovery and
//! iw command for mode/channel operations.

use neli_wifi::Socket;

/// Wireless interface mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceMode {
    /// Standard managed mode (client)
    Managed,
    /// Monitor mode for passive capture
    Monitor,
    /// Access point mode
    Ap,
    /// Ad-hoc mode
    Ibss,
    /// Wireless distribution system
    Wds,
    /// Mesh point
    Mesh,
    /// Unknown/other mode
    Unknown,
}

impl From<u32> for InterfaceMode {
    fn from(mode: u32) -> Self {
        match mode {
            0 => InterfaceMode::Ibss,
            1 => InterfaceMode::Managed,
            2 => InterfaceMode::Ap,
            3 => InterfaceMode::Wds,
            4 => InterfaceMode::Monitor,
            5 => InterfaceMode::Mesh,
            _ => InterfaceMode::Unknown,
        }
    }
}

impl InterfaceMode {
    fn as_str(&self) -> &'static str {
        match self {
            InterfaceMode::Ibss => "ibss",
            InterfaceMode::Managed => "managed",
            InterfaceMode::Ap => "ap",
            InterfaceMode::Wds => "wds",
            InterfaceMode::Monitor => "monitor",
            InterfaceMode::Mesh => "mesh",
            InterfaceMode::Unknown => "managed",
        }
    }
}

/// Wireless frequency band
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WirelessBand {
    /// 2.4 GHz (802.11b/g/n)
    Band2_4GHz,
    /// 5 GHz (802.11a/n/ac)
    Band5GHz,
    /// 6 GHz (802.11ax - WiFi 6E)
    Band6GHz,
}

impl WirelessBand {
    /// Get frequency range for this band
    pub fn frequency_range(&self) -> (u32, u32) {
        match self {
            WirelessBand::Band2_4GHz => (2400, 2500),
            WirelessBand::Band5GHz => (5150, 5925),
            WirelessBand::Band6GHz => (5925, 7125),
        }
    }

    /// Get common channels for this band
    pub fn channels(&self) -> &'static [u8] {
        match self {
            WirelessBand::Band2_4GHz => &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
            WirelessBand::Band5GHz => &[36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165],
            WirelessBand::Band6GHz => &[], // TODO: Add 6GHz channels
        }
    }

    /// Determine band from frequency
    pub fn from_freq(freq: u32) -> Option<Self> {
        if freq >= 2400 && freq <= 2500 {
            Some(WirelessBand::Band2_4GHz)
        } else if freq >= 5150 && freq <= 5925 {
            Some(WirelessBand::Band5GHz)
        } else if freq >= 5925 && freq <= 7125 {
            Some(WirelessBand::Band6GHz)
        } else {
            None
        }
    }
}

/// Wireless interface capabilities
#[derive(Debug, Clone, Default)]
pub struct WirelessCapabilities {
    /// Supported interface modes
    pub supported_modes: Vec<InterfaceMode>,
    /// Supported bands
    pub supported_bands: Vec<WirelessBand>,
    /// Supports monitor mode
    pub monitor_mode: bool,
    /// Supports packet injection
    pub injection: bool,
    /// Maximum channel width (MHz)
    pub max_channel_width: u32,
    /// Physical device name (phy0, etc.)
    pub phy_name: Option<String>,
}

/// Wireless interface wrapper
#[derive(Debug)]
pub struct WirelessInterface {
    /// Interface name (wlan0, etc.)
    pub name: String,
    /// Interface index
    pub ifindex: i32,
    /// Physical device index
    pub wiphy: u32,
    /// Current mode
    pub mode: InterfaceMode,
    /// Current channel
    pub channel: Option<u8>,
    /// Current frequency (MHz)
    pub frequency: Option<u32>,
    /// MAC address
    pub mac_addr: Option<[u8; 6]>,
}

impl WirelessInterface {
    /// List all wireless interfaces
    pub fn list() -> Result<Vec<Self>, WirelessError> {
        let mut socket = Socket::connect().map_err(|e| WirelessError::SocketError(e.to_string()))?;

        let interfaces = socket.get_interfaces_info()
            .map_err(|e| WirelessError::Nl80211Error(e.to_string()))?;

        let mut result = Vec::new();
        for iface in interfaces {
            // Convert name from Vec<u8> to String
            let name = iface.name
                .map(|n| String::from_utf8_lossy(&n).trim_end_matches('\0').to_string())
                .unwrap_or_default();

            // Convert mac from Vec<u8> to [u8; 6]
            let mac_addr = iface.mac.and_then(|m| {
                if m.len() >= 6 {
                    let mut arr = [0u8; 6];
                    arr.copy_from_slice(&m[..6]);
                    Some(arr)
                } else {
                    None
                }
            });

            // Get current mode from iw
            let mode = Self::get_mode_for_interface(&name).unwrap_or(InterfaceMode::Unknown);

            result.push(Self {
                name,
                ifindex: iface.index.unwrap_or(0),
                wiphy: iface.phy.unwrap_or(0),
                mode,
                channel: iface.channel.map(|c| c as u8),
                frequency: iface.frequency,
                mac_addr,
            });
        }

        Ok(result)
    }

    /// Get a specific interface by name
    pub fn get(name: &str) -> Result<Self, WirelessError> {
        let interfaces = Self::list()?;
        interfaces.into_iter()
            .find(|i| i.name == name)
            .ok_or_else(|| WirelessError::InterfaceNotFound(name.to_string()))
    }

    /// Get current mode using iw
    fn get_mode_for_interface(name: &str) -> Option<InterfaceMode> {
        use std::process::Command;
        let output = Command::new("iw")
            .args(["dev", name, "info"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("type ") {
                let mode_str = line.strip_prefix("type ")?;
                return Some(match mode_str {
                    "managed" => InterfaceMode::Managed,
                    "monitor" => InterfaceMode::Monitor,
                    "AP" => InterfaceMode::Ap,
                    "IBSS" => InterfaceMode::Ibss,
                    "WDS" => InterfaceMode::Wds,
                    "mesh point" => InterfaceMode::Mesh,
                    _ => InterfaceMode::Unknown,
                });
            }
        }
        None
    }

    /// Set interface mode (requires root/CAP_NET_ADMIN)
    pub fn set_mode(&mut self, mode: InterfaceMode) -> Result<(), WirelessError> {
        // First, bring interface down
        Self::set_interface_down(&self.name)?;

        // Set the mode via iw command
        use std::process::Command;
        let status = Command::new("iw")
            .args(["dev", &self.name, "set", "type", mode.as_str()])
            .status()
            .map_err(|e| WirelessError::SystemError(e.to_string()))?;

        if !status.success() {
            return Err(WirelessError::Nl80211Error(format!("Failed to set mode to {}", mode.as_str())));
        }

        // Bring interface back up
        Self::set_interface_up(&self.name)?;

        self.mode = mode;
        Ok(())
    }

    /// Set channel (frequency)
    pub fn set_channel(&mut self, channel: u8) -> Result<(), WirelessError> {
        let freq = channel_to_freq(channel);
        if freq == 0 {
            return Err(WirelessError::InvalidChannel(channel));
        }

        use std::process::Command;
        let status = Command::new("iw")
            .args(["dev", &self.name, "set", "freq", &freq.to_string()])
            .status()
            .map_err(|e| WirelessError::SystemError(e.to_string()))?;

        if !status.success() {
            return Err(WirelessError::Nl80211Error(format!("Failed to set channel {}", channel)));
        }

        self.channel = Some(channel);
        self.frequency = Some(freq);
        Ok(())
    }

    /// Get interface capabilities using iw
    pub fn capabilities(&self) -> Result<WirelessCapabilities, WirelessError> {
        use std::process::Command;

        // Get phy name from interface
        let output = Command::new("iw")
            .args(["dev", &self.name, "info"])
            .output()
            .map_err(|e| WirelessError::SystemError(e.to_string()))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut phy_name = None;

        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("wiphy ") {
                if let Some(idx) = line.strip_prefix("wiphy ") {
                    phy_name = Some(format!("phy{}", idx.trim()));
                }
            }
        }

        let mut caps = WirelessCapabilities {
            phy_name: phy_name.clone(),
            ..Default::default()
        };

        // Get capabilities from phy
        if let Some(ref phy) = phy_name {
            let output = Command::new("iw")
                .args(["phy", phy, "info"])
                .output()
                .map_err(|e| WirelessError::SystemError(e.to_string()))?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut in_modes = false;

            for line in stdout.lines() {
                let line = line.trim();

                // Parse supported interface modes
                if line.starts_with("Supported interface modes:") {
                    in_modes = true;
                    continue;
                }

                if in_modes {
                    if line.starts_with("*") {
                        let mode_str = line.trim_start_matches("* ").trim();
                        let mode = match mode_str {
                            "managed" => InterfaceMode::Managed,
                            "monitor" => InterfaceMode::Monitor,
                            "AP" => InterfaceMode::Ap,
                            "IBSS" => InterfaceMode::Ibss,
                            "WDS" => InterfaceMode::Wds,
                            "mesh point" => InterfaceMode::Mesh,
                            _ => continue,
                        };
                        if mode == InterfaceMode::Monitor {
                            caps.monitor_mode = true;
                        }
                        caps.supported_modes.push(mode);
                    } else if !line.is_empty() {
                        in_modes = false;
                    }
                }

                // Parse frequencies to determine bands
                if line.starts_with("* ") && line.contains("MHz") {
                    // Parse frequency like "* 2412 MHz [1] (20.0 dBm)"
                    if let Some(freq_str) = line.split_whitespace().nth(1) {
                        if let Ok(freq) = freq_str.parse::<u32>() {
                            if let Some(band) = WirelessBand::from_freq(freq) {
                                if !caps.supported_bands.contains(&band) {
                                    caps.supported_bands.push(band);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(caps)
    }

    /// Check if interface is in monitor mode
    pub fn is_monitor_mode(&self) -> bool {
        self.mode == InterfaceMode::Monitor
    }

    // Helper to bring interface down
    fn set_interface_down(name: &str) -> Result<(), WirelessError> {
        use std::process::Command;
        let status = Command::new("ip")
            .args(["link", "set", name, "down"])
            .status()
            .map_err(|e| WirelessError::SystemError(e.to_string()))?;

        if !status.success() {
            return Err(WirelessError::SystemError(format!("Failed to bring {} down", name)));
        }
        Ok(())
    }

    // Helper to bring interface up
    fn set_interface_up(name: &str) -> Result<(), WirelessError> {
        use std::process::Command;
        let status = Command::new("ip")
            .args(["link", "set", name, "up"])
            .status()
            .map_err(|e| WirelessError::SystemError(e.to_string()))?;

        if !status.success() {
            return Err(WirelessError::SystemError(format!("Failed to bring {} up", name)));
        }
        Ok(())
    }
}

/// Convert channel number to frequency
pub fn channel_to_freq(channel: u8) -> u32 {
    match channel {
        // 2.4 GHz
        1..=13 => 2407 + (channel as u32 * 5),
        14 => 2484,
        // 5 GHz
        36 => 5180,
        40 => 5200,
        44 => 5220,
        48 => 5240,
        52 => 5260,
        56 => 5280,
        60 => 5300,
        64 => 5320,
        100 => 5500,
        104 => 5520,
        108 => 5540,
        112 => 5560,
        116 => 5580,
        120 => 5600,
        124 => 5620,
        128 => 5640,
        132 => 5660,
        136 => 5680,
        140 => 5700,
        144 => 5720,
        149 => 5745,
        153 => 5765,
        157 => 5785,
        161 => 5805,
        165 => 5825,
        _ => 0,
    }
}

/// Wireless interface errors
#[derive(Debug)]
pub enum WirelessError {
    SocketError(String),
    Nl80211Error(String),
    InterfaceNotFound(String),
    InvalidChannel(u8),
    SystemError(String),
    NotSupported(String),
    PermissionDenied,
}

impl std::fmt::Display for WirelessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WirelessError::SocketError(s) => write!(f, "Socket error: {}", s),
            WirelessError::Nl80211Error(s) => write!(f, "nl80211 error: {}", s),
            WirelessError::InterfaceNotFound(s) => write!(f, "Interface not found: {}", s),
            WirelessError::InvalidChannel(c) => write!(f, "Invalid channel: {}", c),
            WirelessError::SystemError(s) => write!(f, "System error: {}", s),
            WirelessError::NotSupported(s) => write!(f, "Not supported: {}", s),
            WirelessError::PermissionDenied => write!(f, "Permission denied (need root/CAP_NET_ADMIN)"),
        }
    }
}

impl std::error::Error for WirelessError {}
