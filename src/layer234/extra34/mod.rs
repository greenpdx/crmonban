//! Extra Layer 3-4 Attack Detection Module
//!
//! This module provides detection for advanced Layer 3-4 attacks:
//! - IP fragmentation attacks (Teardrop, Ping of Death, fragment floods)
//! - IP spoofing (bogon/martian addresses)
//! - ICMP attacks (redirect, source quench)
//! - TCP attacks (RST injection, session hijacking)
//! - Land attack

pub mod fragmentation;
pub mod spoofing;
pub mod icmp_attacks;
pub mod tcp_attacks;

pub use fragmentation::{FragmentTracker, FragmentState};
pub use spoofing::{BogonChecker, BogonConfig};
pub use icmp_attacks::IcmpAttackDetector;
pub use tcp_attacks::TcpAttackTracker;

// ═══════════════════════════════════════════════════════════════════════════════
// Feature Vector Indices (112-127)
// ═══════════════════════════════════════════════════════════════════════════════

/// Fragmentation features (112-115)
pub const FRAG_RATE: usize = 112;
pub const FRAG_OVERLAP_RATIO: usize = 113;
pub const FRAG_INCOMPLETE_RATIO: usize = 114;
pub const FRAG_TINY_RATIO: usize = 115;

/// Spoofing features (116-119)
pub const SPOOF_BOGON_RATIO: usize = 116;
pub const SPOOF_MARTIAN_RATIO: usize = 117;
pub const SPOOF_TTL_ANOMALY: usize = 118;
pub const SPOOF_LAND_DETECTED: usize = 119;

/// ICMP attack features (120-123)
pub const ICMP_REDIRECT_RATE: usize = 120;
pub const ICMP_QUENCH_RATE: usize = 121;
pub const ICMP_UNREACHABLE_RATE: usize = 122;
pub const ICMP_TTL_EXCEEDED_RATE: usize = 123;

/// TCP attack features (124-127)
pub const TCP_RST_RATIO: usize = 124;
pub const TCP_SEQ_ANOMALY: usize = 125;
pub const TCP_SYNACK_REFLECTION: usize = 126;
pub const TCP_WINDOW_ANOMALY: usize = 127;

/// Total feature count for extra34
pub const EXTRA34_FEATURE_COUNT: usize = 16;

/// Starting index for extra34 features
pub const EXTRA34_FEATURE_START: usize = 112;
