//! Radiotap Header Parser
//!
//! Parses radiotap headers from wireless captures.
//! Radiotap is a de facto standard for 802.11 frame injection and reception.
//!
//! Reference: https://www.radiotap.org/

use std::io::{Cursor, Read};

/// Radiotap present flags
pub mod flags {
    pub const TSFT: u32 = 1 << 0;
    pub const FLAGS: u32 = 1 << 1;
    pub const RATE: u32 = 1 << 2;
    pub const CHANNEL: u32 = 1 << 3;
    pub const FHSS: u32 = 1 << 4;
    pub const DBM_ANTSIGNAL: u32 = 1 << 5;
    pub const DBM_ANTNOISE: u32 = 1 << 6;
    pub const LOCK_QUALITY: u32 = 1 << 7;
    pub const TX_ATTENUATION: u32 = 1 << 8;
    pub const DB_TX_ATTENUATION: u32 = 1 << 9;
    pub const DBM_TX_POWER: u32 = 1 << 10;
    pub const ANTENNA: u32 = 1 << 11;
    pub const DB_ANTSIGNAL: u32 = 1 << 12;
    pub const DB_ANTNOISE: u32 = 1 << 13;
    pub const RX_FLAGS: u32 = 1 << 14;
    pub const MCS: u32 = 1 << 19;
    pub const AMPDU_STATUS: u32 = 1 << 20;
    pub const VHT: u32 = 1 << 21;
    pub const EXT: u32 = 1 << 31;
}

/// Channel flags
pub mod channel_flags {
    pub const TURBO: u16 = 0x0010;
    pub const CCK: u16 = 0x0020;
    pub const OFDM: u16 = 0x0040;
    pub const SPECTRUM_2GHZ: u16 = 0x0080;
    pub const SPECTRUM_5GHZ: u16 = 0x0100;
    pub const PASSIVE: u16 = 0x0200;
    pub const DYN_CCK_OFDM: u16 = 0x0400;
    pub const GFSK: u16 = 0x0800;
}

/// Parsed radiotap header
#[derive(Debug, Clone, Default)]
pub struct RadiotapHeader {
    /// Header version (usually 0)
    pub version: u8,
    /// Total header length including fields
    pub length: u16,
    /// Present flags indicating which fields are present
    pub present_flags: u32,
}

/// Extracted information from radiotap header
#[derive(Debug, Clone, Default)]
pub struct RadiotapInfo {
    /// MAC timestamp in microseconds
    pub tsft: Option<u64>,
    /// Frame flags
    pub flags: Option<u8>,
    /// Data rate in 500Kbps units (e.g., 11 = 5.5 Mbps)
    pub rate: Option<u8>,
    /// Channel frequency in MHz
    pub channel_freq: Option<u16>,
    /// Channel flags
    pub channel_flags: Option<u16>,
    /// Signal strength in dBm
    pub signal_dbm: Option<i8>,
    /// Noise floor in dBm
    pub noise_dbm: Option<i8>,
    /// Antenna index
    pub antenna: Option<u8>,
    /// Signal strength in dB
    pub signal_db: Option<u8>,
    /// Noise in dB
    pub noise_db: Option<u8>,
}

impl RadiotapInfo {
    /// Get signal-to-noise ratio if available
    pub fn snr(&self) -> Option<i16> {
        match (self.signal_dbm, self.noise_dbm) {
            (Some(sig), Some(noise)) => Some(sig as i16 - noise as i16),
            _ => None,
        }
    }

    /// Check if this is 2.4GHz band
    pub fn is_2_4ghz(&self) -> bool {
        self.channel_freq.map(|f| f >= 2400 && f <= 2500).unwrap_or(false)
    }

    /// Check if this is 5GHz band
    pub fn is_5ghz(&self) -> bool {
        self.channel_freq.map(|f| f >= 5000 && f <= 6000).unwrap_or(false)
    }

    /// Get channel number from frequency
    pub fn channel(&self) -> Option<u8> {
        self.channel_freq.map(|freq| freq_to_channel(freq))
    }
}

/// Convert frequency to channel number
fn freq_to_channel(freq: u16) -> u8 {
    if freq >= 2412 && freq <= 2484 {
        // 2.4 GHz band
        if freq == 2484 {
            14
        } else {
            ((freq - 2407) / 5) as u8
        }
    } else if freq >= 5170 && freq <= 5825 {
        // 5 GHz band
        ((freq - 5000) / 5) as u8
    } else if freq >= 5955 && freq <= 7115 {
        // 6 GHz band (WiFi 6E)
        ((freq - 5950) / 5) as u8
    } else {
        0
    }
}

/// Parse radiotap header and extract information
pub fn parse_radiotap(data: &[u8]) -> Option<(RadiotapHeader, RadiotapInfo, usize)> {
    if data.len() < 8 {
        return None;
    }

    // Parse fixed header
    let version = data[0];
    if version != 0 {
        return None; // Only version 0 supported
    }

    let _pad = data[1];
    let length = u16::from_le_bytes([data[2], data[3]]);
    let present_flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    if data.len() < length as usize {
        return None;
    }

    let header = RadiotapHeader {
        version,
        length,
        present_flags,
    };

    // Parse optional fields based on present flags
    let info = parse_radiotap_fields(&data[8..length as usize], present_flags);

    Some((header, info, length as usize))
}

/// Parse radiotap fields based on present flags
fn parse_radiotap_fields(data: &[u8], present: u32) -> RadiotapInfo {
    let mut info = RadiotapInfo::default();
    let mut cursor = Cursor::new(data);
    let mut pos = 0usize;

    // Helper to read and align
    macro_rules! read_aligned {
        ($type:ty, $align:expr) => {{
            // Align position
            let align = $align;
            if pos % align != 0 {
                pos += align - (pos % align);
            }
            let size = std::mem::size_of::<$type>();
            if pos + size <= data.len() {
                cursor.set_position(pos as u64);
                let mut buf = [0u8; std::mem::size_of::<$type>()];
                if cursor.read_exact(&mut buf).is_ok() {
                    pos += size;
                    Some(<$type>::from_le_bytes(buf))
                } else {
                    None
                }
            } else {
                None
            }
        }};
    }

    // TSFT (8 bytes, 8-byte aligned)
    if present & flags::TSFT != 0 {
        if pos % 8 != 0 {
            pos += 8 - (pos % 8);
        }
        if pos + 8 <= data.len() {
            info.tsft = Some(u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]));
            pos += 8;
        }
    }

    // Flags (1 byte)
    if present & flags::FLAGS != 0 {
        if pos < data.len() {
            info.flags = Some(data[pos]);
            pos += 1;
        }
    }

    // Rate (1 byte)
    if present & flags::RATE != 0 {
        if pos < data.len() {
            info.rate = Some(data[pos]);
            pos += 1;
        }
    }

    // Channel (4 bytes, 2-byte aligned)
    if present & flags::CHANNEL != 0 {
        if pos % 2 != 0 {
            pos += 1;
        }
        if pos + 4 <= data.len() {
            info.channel_freq = Some(u16::from_le_bytes([data[pos], data[pos+1]]));
            info.channel_flags = Some(u16::from_le_bytes([data[pos+2], data[pos+3]]));
            pos += 4;
        }
    }

    // FHSS (2 bytes)
    if present & flags::FHSS != 0 {
        pos += 2;
    }

    // Antenna signal (1 byte, signed)
    if present & flags::DBM_ANTSIGNAL != 0 {
        if pos < data.len() {
            info.signal_dbm = Some(data[pos] as i8);
            pos += 1;
        }
    }

    // Antenna noise (1 byte, signed)
    if present & flags::DBM_ANTNOISE != 0 {
        if pos < data.len() {
            info.noise_dbm = Some(data[pos] as i8);
            pos += 1;
        }
    }

    // Lock quality (2 bytes)
    if present & flags::LOCK_QUALITY != 0 {
        if pos % 2 != 0 {
            pos += 1;
        }
        pos += 2;
    }

    // TX attenuation (2 bytes)
    if present & flags::TX_ATTENUATION != 0 {
        if pos % 2 != 0 {
            pos += 1;
        }
        pos += 2;
    }

    // dB TX attenuation (2 bytes)
    if present & flags::DB_TX_ATTENUATION != 0 {
        if pos % 2 != 0 {
            pos += 1;
        }
        pos += 2;
    }

    // dBm TX power (1 byte, signed)
    if present & flags::DBM_TX_POWER != 0 {
        pos += 1;
    }

    // Antenna (1 byte)
    if present & flags::ANTENNA != 0 {
        if pos < data.len() {
            info.antenna = Some(data[pos]);
            pos += 1;
        }
    }

    // dB antenna signal (1 byte)
    if present & flags::DB_ANTSIGNAL != 0 {
        if pos < data.len() {
            info.signal_db = Some(data[pos]);
            pos += 1;
        }
    }

    // dB antenna noise (1 byte)
    if present & flags::DB_ANTNOISE != 0 {
        if pos < data.len() {
            info.noise_db = Some(data[pos]);
        }
    }

    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_freq_to_channel() {
        assert_eq!(freq_to_channel(2412), 1);
        assert_eq!(freq_to_channel(2437), 6);
        assert_eq!(freq_to_channel(2462), 11);
        assert_eq!(freq_to_channel(2484), 14);
        assert_eq!(freq_to_channel(5180), 36);
        assert_eq!(freq_to_channel(5745), 149);
    }

    #[test]
    fn test_parse_minimal_radiotap() {
        // Minimal radiotap header: version, pad, length=8, present=0
        let data = [0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = parse_radiotap(&data);
        assert!(result.is_some());

        let (header, info, len) = result.unwrap();
        assert_eq!(header.version, 0);
        assert_eq!(header.length, 8);
        assert_eq!(header.present_flags, 0);
        assert_eq!(len, 8);
        assert!(info.tsft.is_none());
    }

    #[test]
    fn test_radiotap_info_band_detection() {
        let mut info = RadiotapInfo::default();

        info.channel_freq = Some(2437);
        assert!(info.is_2_4ghz());
        assert!(!info.is_5ghz());
        assert_eq!(info.channel(), Some(6));

        info.channel_freq = Some(5180);
        assert!(!info.is_2_4ghz());
        assert!(info.is_5ghz());
        assert_eq!(info.channel(), Some(36));
    }
}
