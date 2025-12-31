//! Feature Index Mapping
//!
//! Maps feature indices to names and provides metadata about each feature.

use super::dims;
use serde::{Deserialize, Serialize};

/// Feature source identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeatureSource {
    /// ML Flow features (CICIDS2017-compatible)
    MlFlow,
    /// Layer234 features
    Layer234,
    /// Extra34 features
    Extra34,
    /// Wireless features
    Wireless,
}

impl FeatureSource {
    /// Get the dimension range for this source
    pub fn range(&self) -> (usize, usize) {
        match self {
            FeatureSource::MlFlow => (dims::ML_START, dims::ML_END),
            FeatureSource::Layer234 => (dims::L234_START, dims::L234_END),
            FeatureSource::Extra34 => (dims::EXTRA34_START, dims::EXTRA34_END),
            FeatureSource::Wireless => (dims::WIRELESS_START, dims::WIRELESS_END),
        }
    }

    /// Get the dimension count for this source
    pub fn dim(&self) -> usize {
        match self {
            FeatureSource::MlFlow => dims::ML_DIM,
            FeatureSource::Layer234 => dims::L234_DIM,
            FeatureSource::Extra34 => dims::EXTRA34_DIM,
            FeatureSource::Wireless => dims::WIRELESS_DIM,
        }
    }
}

/// Feature range metadata
#[derive(Debug, Clone)]
pub struct FeatureRange {
    /// Source identifier
    pub source: FeatureSource,
    /// Start index (inclusive)
    pub start: usize,
    /// End index (exclusive)
    pub end: usize,
    /// Feature names within this range
    pub names: &'static [&'static str],
    /// Description of this feature group
    pub description: &'static str,
}

/// All feature ranges in order
pub static FEATURE_RANGES: &[FeatureRange] = &[
    FeatureRange {
        source: FeatureSource::MlFlow,
        start: dims::ML_START,
        end: dims::ML_END,
        names: ML_FEATURE_NAMES,
        description: "CICIDS2017-compatible flow features",
    },
    FeatureRange {
        source: FeatureSource::Layer234,
        start: dims::L234_START,
        end: dims::L234_END,
        names: L234_FEATURE_NAMES,
        description: "Layer 2/3/4 packet-based features",
    },
    FeatureRange {
        source: FeatureSource::Extra34,
        start: dims::EXTRA34_START,
        end: dims::EXTRA34_END,
        names: EXTRA34_FEATURE_NAMES,
        description: "Extra Layer 3/4 attack features (fragment, spoof, ICMP, TCP)",
    },
    FeatureRange {
        source: FeatureSource::Wireless,
        start: dims::WIRELESS_START,
        end: dims::WIRELESS_END,
        names: WIRELESS_FEATURE_NAMES,
        description: "802.11 wireless attack features",
    },
];

/// ML Flow feature names (39 features)
pub static ML_FEATURE_NAMES: &[&str] = &[
    // Basic flow features (0-6)
    "ml_duration_ms",
    "ml_protocol_type",
    "ml_src_bytes",
    "ml_dst_bytes",
    "ml_total_packets",
    "ml_src_packets",
    "ml_dst_packets",
    // Packet size statistics (7-10)
    "ml_avg_packet_size",
    "ml_min_packet_size",
    "ml_max_packet_size",
    "ml_std_packet_size",
    // Byte rate features (11-14)
    "ml_bytes_per_second",
    "ml_packets_per_second",
    "ml_src_bytes_per_second",
    "ml_dst_bytes_per_second",
    // TCP flag features (15-23)
    "ml_syn_count",
    "ml_ack_count",
    "ml_fin_count",
    "ml_rst_count",
    "ml_psh_count",
    "ml_urg_count",
    "ml_syn_rate",
    "ml_fin_rate",
    "ml_rst_rate",
    // Inter-arrival time features (24-27)
    "ml_iat_mean",
    "ml_iat_std",
    "ml_iat_min",
    "ml_iat_max",
    // Flow direction features (28-29)
    "ml_fwd_bwd_ratio",
    "ml_bytes_ratio",
    // Connection features (30-33)
    "ml_same_dst_count",
    "ml_same_src_count",
    "ml_same_srv_count",
    "ml_diff_srv_count",
    // Protocol flags (34-36)
    "ml_is_tcp",
    "ml_is_udp",
    "ml_is_icmp",
    // Port-based features (37-38)
    "ml_dst_port_category",
    "ml_is_well_known_port",
];

/// Layer234 feature names (88 features)
pub static L234_FEATURE_NAMES: &[&str] = &[
    // Port features (0-3)
    "l234_port_entropy",
    "l234_unique_port_count",
    "l234_min_port",
    "l234_max_port",
    // Timing features (4-7)
    "l234_mean_interval",
    "l234_interval_variance",
    "l234_burst_ratio",
    "l234_duration",
    // Target features (8-11)
    "l234_unique_dst_ips",
    "l234_ip_entropy",
    "l234_sequential_ip_ratio",
    "l234_subnet_spread",
    // TCP flag features (12-15)
    "l234_syn_ratio",
    "l234_synack_ratio",
    "l234_rst_ratio",
    "l234_fin_ratio",
    // TCP connection features (16-19)
    "l234_conn_success_rate",
    "l234_half_open_ratio",
    "l234_handshake_complete",
    "l234_rst_after_syn",
    // TCP behavior features (20-23)
    "l234_auth_port_ratio",
    "l234_single_port_concentration",
    "l234_xmas_scan",
    "l234_null_scan",
    // UDP pattern features (24-27)
    "l234_udp_response_ratio",
    "l234_icmp_unreachable_ratio",
    "l234_payload_variance",
    "l234_empty_payload_ratio",
    // UDP service features (28-31)
    "l234_dns_ratio",
    "l234_ntp_ratio",
    "l234_ssdp_ratio",
    "l234_other_services_ratio",
    // UDP amplification features (32-35)
    "l234_request_response_ratio",
    "l234_reflection_score",
    "l234_amplification_factor",
    "l234_spoof_likelihood",
    // ICMP type features (36-39)
    "l234_echo_request_ratio",
    "l234_echo_reply_ratio",
    "l234_unreachable_ratio",
    "l234_time_exceeded_ratio",
    // ICMP pattern features (40-43)
    "l234_ping_sweep_score",
    "l234_traceroute_score",
    "l234_ttl_variance",
    "l234_icmp_code_entropy",
    // ICMP timing features (44-47)
    "l234_ping_regularity",
    "l234_sweep_speed",
    "l234_host_discovery_rate",
    "l234_response_rate",
    // TLS features (48-51)
    "l234_tls_ratio",
    "l234_client_hello_ratio",
    "l234_handshake_ratio",
    "l234_unique_ja3_ratio",
    // TLS version features (52-55)
    "l234_tls10_ratio",
    "l234_tls11_ratio",
    "l234_tls12plus_ratio",
    "l234_version_diversity",
    // TLS SNI features (56-59)
    "l234_sni_present_ratio",
    "l234_unique_sni_ratio",
    "l234_unique_ja3_hash_ratio",
    "l234_server_hello_ratio",
    // TLS behavior features (60-63)
    "l234_tls_timing_regularity",
    "l234_tls_connections_per_sec",
    "l234_unique_tls_dests",
    "l234_failed_tls_ratio",
    // DoS rate features (64-71)
    "l234_packets_per_second",
    "l234_bytes_per_second",
    "l234_connections_per_second",
    "l234_half_open_at_volume",
    "l234_tcp_flood_score",
    "l234_udp_flood_score",
    "l234_icmp_flood_score",
    "l234_conn_exhaustion_score",
    // ARP features (72-75)
    "l234_arp_request_ratio",
    "l234_gratuitous_arp_ratio",
    "l234_mac_ip_changes",
    "l234_ips_per_mac",
    // DHCP features (76-79)
    "l234_dhcp_discover_ratio",
    "l234_unique_dhcp_macs",
    "l234_unique_dhcp_servers",
    "l234_dhcp_request_rate",
    // ICMP tunnel features (80-83)
    "l234_icmp_avg_payload_size",
    "l234_icmp_payload_entropy",
    "l234_echo_asymmetry",
    "l234_icmp_timing_regularity",
    // IPv6 RA features (84-87)
    "l234_ra_packets_per_sec",
    "l234_unique_router_sources",
    "l234_ra_burst_ratio",
    "l234_non_link_local_ratio",
];

/// Extra34 feature names (16 features)
pub static EXTRA34_FEATURE_NAMES: &[&str] = &[
    // Fragmentation features (0-3)
    "extra34_fragment_rate",
    "extra34_overlap_ratio",
    "extra34_tiny_frag_ratio",
    "extra34_oversized_ratio",
    // IP spoofing features (4-7)
    "extra34_bogon_ratio",
    "extra34_martian_ratio",
    "extra34_land_attacks",
    "extra34_spoof_score",
    // ICMP attack features (8-11)
    "extra34_icmp_redirect_rate",
    "extra34_icmp_quench_rate",
    "extra34_icmp_unreachable_rate",
    "extra34_icmp_ttl_exceeded_rate",
    // TCP session attack features (12-15)
    "extra34_rst_injection_rate",
    "extra34_hijack_score",
    "extra34_synack_reflection_rate",
    "extra34_session_anomaly_score",
];

/// Wireless feature names (16 features)
pub static WIRELESS_FEATURE_NAMES: &[&str] = &[
    // Deauth/Disassoc features (0-3)
    "wifi_deauth_rate",
    "wifi_disassoc_rate",
    "wifi_mgmt_flood_score",
    "wifi_dos_score",
    // Evil twin/Fake AP features (4-7)
    "wifi_evil_twin_score",
    "wifi_fake_ap_count",
    "wifi_ssid_anomaly",
    "wifi_signal_anomaly",
    // Karma/Beacon features (8-11)
    "wifi_karma_score",
    "wifi_beacon_flood_rate",
    "wifi_probe_flood_rate",
    "wifi_auth_flood_rate",
    // Credential capture features (12-15)
    "wifi_pmkid_capture_count",
    "wifi_handshake_capture_count",
    "wifi_krack_score",
    "wifi_credential_risk",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_ranges_contiguous() {
        let mut prev_end = 0;
        for range in FEATURE_RANGES {
            assert_eq!(range.start, prev_end, "Feature ranges must be contiguous");
            assert_eq!(range.names.len(), range.end - range.start,
                "Feature name count must match range size for {:?}", range.source);
            prev_end = range.end;
        }
        assert_eq!(prev_end, super::super::UNIFIED_DIM);
    }
}
