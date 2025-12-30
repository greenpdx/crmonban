//! # Extra Layer 2-4 Infrastructure Attack Detection
//!
//! This module provides detection for advanced infrastructure attacks targeting
//! network protocols at Layers 2-4. These attacks typically target routing,
//! switching, and discovery protocols.
//!
//! ## Attacks Detected
//!
//! | Attack | Layer | Protocol | Detection Method |
//! |--------|-------|----------|------------------|
//! | BGP Hijacking | 3-4 | BGP (TCP 179) | AS path anomalies, prefix hijacking |
//! | STP Root Bridge Attack | 2 | STP/RSTP (BPDU) | Priority manipulation, TC floods |
//! | CDP Spoofing | 2 | CDP (Cisco) | Fake device announcements |
//! | LLDP Spoofing | 2 | LLDP (IEEE 802.1AB) | Fake neighbor discovery |
//! | OSPF Injection | 3 | OSPF (IP proto 89) | LSA injection, DR manipulation |
//! | RIP Poisoning | 3 | RIP (UDP 520) | Route injection, hop count manipulation |
//! | GRE Tunnel Detection | 3 | GRE (IP proto 47) | Unauthorized encapsulation |
//! | VXLAN Tunnel Detection | 3 | VXLAN (UDP 4789) | Unauthorized overlay traffic |
//! | 802.1X Bypass | 2 | EAPoL | MAB bypass, hub behind port |
//!
//! ## Feature Gating
//!
//! This module is only compiled when the `extra234` feature is enabled:
//!
//! ```toml
//! [dependencies]
//! crmonban = { version = "0.1", features = ["extra234"] }
//! ```

pub mod bgp;
pub mod discovery;
pub mod dot1x;
pub mod routing;
pub mod stp;
pub mod tunnel;

// Re-export all types for convenience
pub use bgp::{BgpMessage, BgpMsgType, BgpStateTracker, BgpUpdate, PathAttribute};
pub use discovery::{CdpPacket, CdpTlv, DiscoveryTracker, LldpPacket, LldpTlv};
pub use dot1x::{Dot1xTracker, EapCode, EapPacket, EapolPacket, EapolType};
pub use routing::{OspfPacket, OspfType, RipEntry, RipPacket, RoutingTracker};
pub use stp::{BpduPacket, BpduType, BridgeId, StpTracker};
pub use tunnel::{GreHeader, TunnelTracker, VxlanHeader};

/// Feature vector indices for extra234 features (88-111)
pub mod indices {
    // BGP features (88-91)
    pub const BGP_UPDATE_RATE: usize = 88;
    pub const BGP_WITHDRAWAL_RATIO: usize = 89;
    pub const BGP_AS_PATH_LENGTH: usize = 90;
    pub const BGP_UNKNOWN_AS_RATIO: usize = 91;

    // STP features (92-95)
    pub const STP_BPDU_RATE: usize = 92;
    pub const STP_ROOT_CHANGES: usize = 93;
    pub const STP_TC_RATIO: usize = 94;
    pub const STP_PRIORITY_ZERO: usize = 95;

    // CDP/LLDP features (96-99)
    pub const DISCOVERY_PACKET_RATE: usize = 96;
    pub const DISCOVERY_UNIQUE_DEVICES: usize = 97;
    pub const DISCOVERY_NEW_DEVICE_RATIO: usize = 98;
    pub const DISCOVERY_TLV_DIVERSITY: usize = 99;

    // OSPF/RIP features (100-103)
    pub const ROUTING_HELLO_RATE: usize = 100;
    pub const ROUTING_NEW_NEIGHBOR_RATIO: usize = 101;
    pub const ROUTING_METRIC_ANOMALY: usize = 102;
    pub const ROUTING_LSA_FLOOD: usize = 103;

    // GRE/VXLAN features (104-107)
    pub const TUNNEL_PACKET_RATIO: usize = 104;
    pub const TUNNEL_UNIQUE_ENDPOINTS: usize = 105;
    pub const TUNNEL_EXTERNAL_RATIO: usize = 106;
    pub const TUNNEL_VNI_DIVERSITY: usize = 107;

    // 802.1X features (108-111)
    pub const DOT1X_EAP_RATE: usize = 108;
    pub const DOT1X_MACS_PER_PORT: usize = 109;
    pub const DOT1X_START_RATIO: usize = 110;
    pub const DOT1X_SUCCESS_WITHOUT_AUTH: usize = 111;
}

/// Extended vector dimension when extra234 is enabled
pub const EXTENDED_VECTOR_DIM: usize = 112;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_indices() {
        // Verify indices are contiguous and within bounds
        assert_eq!(indices::BGP_UPDATE_RATE, 88);
        assert_eq!(indices::DOT1X_SUCCESS_WITHOUT_AUTH, 111);
        assert!(indices::DOT1X_SUCCESS_WITHOUT_AUTH < EXTENDED_VECTOR_DIM);
    }
}
