//! Detection weights configuration
//!
//! All heuristic detection thresholds are defined here and can be loaded/saved from config.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// All detection weights for heuristic-based threat detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionWeights {
    /// SYN scan detection weights
    pub syn_scan: SynScanWeights,
    /// Connect scan detection weights
    pub connect_scan: ConnectScanWeights,
    /// UDP scan detection weights
    pub udp_scan: UdpScanWeights,
    /// Ping sweep detection weights
    pub ping_sweep: PingSweepWeights,
    /// Brute force detection weights
    pub brute_force: BruteForceWeights,
    /// SYN flood detection weights
    pub syn_flood: SynFloodWeights,
    /// UDP flood detection weights
    pub udp_flood: UdpFloodWeights,
    /// ICMP flood detection weights
    pub icmp_flood: IcmpFloodWeights,
    /// Connection exhaustion detection weights
    pub conn_exhaustion: ConnExhaustionWeights,
    /// Special scan detection weights (XMAS, NULL)
    pub special_scans: SpecialScanWeights,
    /// Amplification attack detection weights
    pub amplification: AmplificationWeights,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynScanWeights {
    /// Minimum SYN ratio for early scan detection
    pub syn_ratio_min: f32,
    /// Maximum SYN-ACK ratio (should be low for scans)
    pub synack_ratio_max: f32,
    /// Minimum unique port ratio (scans target many ports)
    pub unique_port_ratio_min: f32,
    /// Minimum half-open ratio for large scans
    pub half_open_ratio_min: f32,
    /// Higher SYN ratio for small/targeted scans
    pub small_scan_syn_ratio_min: f32,
    /// Higher half-open ratio for small scans
    pub small_scan_half_open_min: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectScanWeights {
    /// Minimum SYN ratio
    pub syn_ratio_min: f32,
    /// Maximum SYN ratio
    pub syn_ratio_max: f32,
    /// Minimum RST ratio
    pub rst_ratio_min: f32,
    /// Maximum RST ratio
    pub rst_ratio_max: f32,
    /// Maximum SYN-ACK ratio
    pub synack_ratio_max: f32,
    /// Minimum RST-after-SYN ratio
    pub rst_after_syn_min: f32,
    /// Minimum unique port ratio
    pub unique_port_ratio_min: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpScanWeights {
    /// Minimum UDP unreachable ratio
    pub unreachable_ratio_min: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingSweepWeights {
    /// Minimum echo request ratio
    pub echo_req_ratio_min: f32,
    /// Minimum ping sweep score
    pub sweep_score_min: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BruteForceWeights {
    /// Minimum auth port ratio
    pub auth_port_ratio_min: f32,
    /// Minimum single port concentration
    pub single_port_concentration_min: f32,
    /// Minimum handshake complete ratio
    pub handshake_complete_ratio_min: f32,
    /// Maximum unique port ratio
    pub unique_port_ratio_max: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynFloodWeights {
    /// Minimum packets per second (normalized)
    pub packets_per_sec_min: f32,
    /// Minimum SYN ratio
    pub syn_ratio_min: f32,
    /// Maximum SYN-ACK ratio
    pub synack_ratio_max: f32,
    /// Minimum half-open flood indicator
    pub half_open_flood_min: f32,
    /// Maximum unique port ratio (floods target few ports)
    pub unique_port_ratio_max: f32,
    /// Minimum TCP flood score for score-based detection
    pub tcp_flood_score_min: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpFloodWeights {
    /// Minimum UDP flood score
    pub flood_score_min: f32,
    /// Minimum packets per second for rate-based detection
    pub packets_per_sec_min: f32,
    /// Minimum bytes per second for rate-based detection
    pub bytes_per_sec_min: f32,
    /// Minimum UDP other services ratio
    pub other_services_min: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpFloodWeights {
    /// Minimum ICMP flood score
    pub flood_score_min: f32,
    /// Minimum packets per second for rate-based detection
    pub packets_per_sec_min: f32,
    /// Minimum echo request ratio
    pub echo_req_ratio_min: f32,
    /// Maximum unique destination IPs (floods target few IPs)
    pub unique_dst_ips_max: f32,
    /// Minimum echo ratio for single-target flood
    pub single_target_echo_min: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnExhaustionWeights {
    /// Minimum exhaustion score
    pub exhaustion_score_min: f32,
    /// Maximum bytes per second (exhaustion attacks don't send data)
    pub bytes_per_sec_max: f32,
    /// Maximum unique port ratio
    pub unique_port_ratio_max: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialScanWeights {
    /// Minimum XMAS indicator
    pub xmas_indicator_min: f32,
    /// Minimum NULL indicator
    pub null_indicator_min: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmplificationWeights {
    /// Minimum amplification factor
    pub factor_min: f32,
}

impl Default for DetectionWeights {
    fn default() -> Self {
        Self {
            syn_scan: SynScanWeights::default(),
            connect_scan: ConnectScanWeights::default(),
            udp_scan: UdpScanWeights::default(),
            ping_sweep: PingSweepWeights::default(),
            brute_force: BruteForceWeights::default(),
            syn_flood: SynFloodWeights::default(),
            udp_flood: UdpFloodWeights::default(),
            icmp_flood: IcmpFloodWeights::default(),
            conn_exhaustion: ConnExhaustionWeights::default(),
            special_scans: SpecialScanWeights::default(),
            amplification: AmplificationWeights::default(),
        }
    }
}

impl Default for SynScanWeights {
    fn default() -> Self {
        Self {
            syn_ratio_min: 0.6,
            synack_ratio_max: 0.15,
            unique_port_ratio_min: 0.05,
            half_open_ratio_min: 0.4,
            small_scan_syn_ratio_min: 0.7,
            small_scan_half_open_min: 0.6,
        }
    }
}

impl Default for ConnectScanWeights {
    fn default() -> Self {
        Self {
            syn_ratio_min: 0.15,
            syn_ratio_max: 0.6,
            rst_ratio_min: 0.15,
            rst_ratio_max: 0.6,
            synack_ratio_max: 0.15,
            rst_after_syn_min: 0.5,
            unique_port_ratio_min: 0.01,
        }
    }
}

impl Default for UdpScanWeights {
    fn default() -> Self {
        Self {
            unreachable_ratio_min: 0.3,
        }
    }
}

impl Default for PingSweepWeights {
    fn default() -> Self {
        Self {
            echo_req_ratio_min: 0.4,
            sweep_score_min: 0.3,
        }
    }
}

impl Default for BruteForceWeights {
    fn default() -> Self {
        Self {
            auth_port_ratio_min: 0.5,
            single_port_concentration_min: 0.7,
            handshake_complete_ratio_min: 0.3,
            unique_port_ratio_max: 0.1,
        }
    }
}

impl Default for SynFloodWeights {
    fn default() -> Self {
        Self {
            packets_per_sec_min: 0.01,
            syn_ratio_min: 0.7,
            synack_ratio_max: 0.15,
            half_open_flood_min: 0.5,
            unique_port_ratio_max: 0.1,
            tcp_flood_score_min: 0.4,
        }
    }
}

impl Default for UdpFloodWeights {
    fn default() -> Self {
        Self {
            flood_score_min: 0.3,
            packets_per_sec_min: 0.01,
            bytes_per_sec_min: 0.01,
            other_services_min: 0.5,
        }
    }
}

impl Default for IcmpFloodWeights {
    fn default() -> Self {
        Self {
            flood_score_min: 0.3,
            packets_per_sec_min: 0.01,
            echo_req_ratio_min: 0.7,
            unique_dst_ips_max: 0.2,
            single_target_echo_min: 0.7,
        }
    }
}

impl Default for ConnExhaustionWeights {
    fn default() -> Self {
        Self {
            exhaustion_score_min: 0.3,
            bytes_per_sec_max: 0.1,
            unique_port_ratio_max: 0.1,
        }
    }
}

impl Default for SpecialScanWeights {
    fn default() -> Self {
        Self {
            xmas_indicator_min: 0.5,
            null_indicator_min: 0.5,
        }
    }
}

impl Default for AmplificationWeights {
    fn default() -> Self {
        Self {
            factor_min: 0.3,
        }
    }
}

impl DetectionWeights {
    /// Load weights from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let weights: DetectionWeights = toml::from_str(&content)?;
        Ok(weights)
    }

    /// Save weights to a TOML file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), Box<dyn std::error::Error>> {
        let content = toml::to_string_pretty(self)?;
        fs::write(path, content)?;
        Ok(())
    }

}
