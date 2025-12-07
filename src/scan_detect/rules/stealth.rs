//! Stealth Scan Detection Rules
//!
//! Detects various stealth port scanning techniques from Nmap:
//! - NULL scan (-sN): No flags set
//! - FIN scan (-sF): FIN flag only
//! - Xmas scan (-sX): FIN+PSH+URG flags
//! - Maimon scan (-sM): FIN+ACK flags
//! - ACK scan (-sA): ACK without prior connection
//! - Window scan (-sW): ACK with RST response analysis

use super::{DetectionRule, EvaluationContext, RuleCategory, RuleResult};

/// TCP flags for pattern matching
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlagSet {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

impl TcpFlagSet {
    /// Check if this is a NULL scan (no flags)
    pub fn is_null(&self) -> bool {
        !self.syn && !self.ack && !self.fin && !self.rst && !self.psh && !self.urg
    }

    /// Check if this is a FIN scan (FIN only)
    pub fn is_fin_only(&self) -> bool {
        !self.syn && !self.ack && self.fin && !self.rst && !self.psh && !self.urg
    }

    /// Check if this is an Xmas scan (FIN+PSH+URG)
    pub fn is_xmas(&self) -> bool {
        !self.syn && !self.ack && self.fin && !self.rst && self.psh && self.urg
    }

    /// Check if this is a Maimon scan (FIN+ACK)
    pub fn is_maimon(&self) -> bool {
        !self.syn && self.ack && self.fin && !self.rst && !self.psh && !self.urg
    }

    /// Check if this is an ACK-only probe (potential ACK scan)
    pub fn is_ack_only(&self) -> bool {
        !self.syn && self.ack && !self.fin && !self.rst && !self.psh && !self.urg
    }

    /// Check if flags are invalid for TCP state machine
    pub fn is_invalid(&self) -> bool {
        // SYN+FIN is invalid
        if self.syn && self.fin {
            return true;
        }
        // SYN+RST is invalid (except in rare cases)
        if self.syn && self.rst {
            return true;
        }
        false
    }
}

/// STEALTH1: NULL Scan Detection
/// Score: +4.0 (high confidence attack)
pub struct NullScanRule;

impl DetectionRule for NullScanRule {
    fn id(&self) -> &str { "STEALTH1" }
    fn name(&self) -> &str { "NULL Scan Detection" }
    fn category(&self) -> RuleCategory { RuleCategory::Protocol }
    fn default_weight(&self) -> f32 { 4.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let flags = ctx.tcp_flags()?;

        if flags.is_null() {
            // Count NULL packets from this source
            let null_count = ctx.behavior.stealth_scan_counts.get("null").copied().unwrap_or(0);

            let score = if null_count >= 10 {
                4.0 // Confirmed NULL scan
            } else if null_count >= 3 {
                2.5 // Likely NULL scan
            } else {
                1.5 // Single NULL packet (could be noise)
            };

            return Some(RuleResult {
                rule_id: self.id().to_string(),
                score_delta: score,
                confidence: if null_count >= 5 { 0.95 } else { 0.7 },
                evidence: format!("NULL scan packet (no flags) - {} total", null_count + 1),
                tags: vec!["null-scan".into(), "stealth".into(), "rfc793-exploit".into()],
            });
        }

        None
    }
}

/// STEALTH2: FIN Scan Detection
/// Score: +3.5
pub struct FinScanRule;

impl DetectionRule for FinScanRule {
    fn id(&self) -> &str { "STEALTH2" }
    fn name(&self) -> &str { "FIN Scan Detection" }
    fn category(&self) -> RuleCategory { RuleCategory::Protocol }
    fn default_weight(&self) -> f32 { 3.5 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let flags = ctx.tcp_flags()?;

        if flags.is_fin_only() {
            // Check if there's an existing connection for this port
            let has_connection = ctx.behavior.connections.contains_key(&ctx.dst_port.unwrap_or(0));

            if !has_connection {
                let fin_count = ctx.behavior.stealth_scan_counts.get("fin").copied().unwrap_or(0);

                let score = if fin_count >= 10 {
                    3.5
                } else if fin_count >= 3 {
                    2.0
                } else {
                    1.0
                };

                return Some(RuleResult {
                    rule_id: self.id().to_string(),
                    score_delta: score,
                    confidence: if fin_count >= 5 { 0.9 } else { 0.6 },
                    evidence: format!("FIN scan packet (FIN only, no prior connection) - {} total", fin_count + 1),
                    tags: vec!["fin-scan".into(), "stealth".into()],
                });
            }
        }

        None
    }
}

/// STEALTH3: Xmas Scan Detection
/// Score: +4.5 (very suspicious)
pub struct XmasScanRule;

impl DetectionRule for XmasScanRule {
    fn id(&self) -> &str { "STEALTH3" }
    fn name(&self) -> &str { "Xmas Scan Detection" }
    fn category(&self) -> RuleCategory { RuleCategory::Protocol }
    fn default_weight(&self) -> f32 { 4.5 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let flags = ctx.tcp_flags()?;

        if flags.is_xmas() {
            let xmas_count = ctx.behavior.stealth_scan_counts.get("xmas").copied().unwrap_or(0);

            // Xmas scans are very suspicious even with one packet
            let score = if xmas_count >= 5 {
                4.5
            } else if xmas_count >= 2 {
                3.5
            } else {
                2.5
            };

            return Some(RuleResult {
                rule_id: self.id().to_string(),
                score_delta: score,
                confidence: 0.95, // Very high confidence - this is almost never legitimate
                evidence: format!("Xmas scan packet (FIN+PSH+URG) - {} total", xmas_count + 1),
                tags: vec!["xmas-scan".into(), "stealth".into(), "high-confidence".into()],
            });
        }

        None
    }
}

/// STEALTH4: Maimon Scan Detection
/// Score: +3.0
pub struct MaimonScanRule;

impl DetectionRule for MaimonScanRule {
    fn id(&self) -> &str { "STEALTH4" }
    fn name(&self) -> &str { "Maimon Scan Detection" }
    fn category(&self) -> RuleCategory { RuleCategory::Protocol }
    fn default_weight(&self) -> f32 { 3.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let flags = ctx.tcp_flags()?;

        if flags.is_maimon() {
            let has_connection = ctx.behavior.connections.contains_key(&ctx.dst_port.unwrap_or(0));

            if !has_connection {
                let maimon_count = ctx.behavior.stealth_scan_counts.get("maimon").copied().unwrap_or(0);

                let score = if maimon_count >= 10 {
                    3.0
                } else if maimon_count >= 3 {
                    2.0
                } else {
                    1.0
                };

                return Some(RuleResult {
                    rule_id: self.id().to_string(),
                    score_delta: score,
                    confidence: if maimon_count >= 5 { 0.85 } else { 0.5 },
                    evidence: format!("Maimon scan packet (FIN+ACK, no prior connection) - {} total", maimon_count + 1),
                    tags: vec!["maimon-scan".into(), "stealth".into()],
                });
            }
        }

        None
    }
}

/// STEALTH5: ACK Scan Detection
/// Score: +2.0 (firewall mapping, not direct port scan)
pub struct AckScanRule;

impl DetectionRule for AckScanRule {
    fn id(&self) -> &str { "STEALTH5" }
    fn name(&self) -> &str { "ACK Scan Detection" }
    fn category(&self) -> RuleCategory { RuleCategory::Protocol }
    fn default_weight(&self) -> f32 { 2.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let flags = ctx.tcp_flags()?;

        if flags.is_ack_only() {
            let has_connection = ctx.behavior.connections.contains_key(&ctx.dst_port.unwrap_or(0));

            // ACK without connection is suspicious
            if !has_connection {
                let ack_only_count = ctx.behavior.stealth_scan_counts.get("ack_only").copied().unwrap_or(0);

                // Need more evidence for ACK scans since they're less definitive
                if ack_only_count >= 5 {
                    let unique_ports = ctx.behavior.connections.len();

                    let score = if unique_ports >= 20 && ack_only_count >= 20 {
                        2.5 // High confidence ACK scan
                    } else if unique_ports >= 10 {
                        1.5
                    } else {
                        0.5 // Could be retransmission
                    };

                    return Some(RuleResult {
                        rule_id: self.id().to_string(),
                        score_delta: score,
                        confidence: if ack_only_count >= 20 { 0.8 } else { 0.4 },
                        evidence: format!("ACK scan pattern ({} ACK-only packets to {} ports)",
                            ack_only_count + 1, unique_ports),
                        tags: vec!["ack-scan".into(), "firewall-mapping".into()],
                    });
                }
            }
        }

        None
    }
}

/// STEALTH6: Invalid TCP Flag Combinations
/// Score: +3.0
pub struct InvalidFlagsRule;

impl DetectionRule for InvalidFlagsRule {
    fn id(&self) -> &str { "STEALTH6" }
    fn name(&self) -> &str { "Invalid TCP Flags Detection" }
    fn category(&self) -> RuleCategory { RuleCategory::Protocol }
    fn default_weight(&self) -> f32 { 3.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let flags = ctx.tcp_flags()?;

        if flags.is_invalid() {
            let detail = if flags.syn && flags.fin {
                "SYN+FIN (impossible combination)"
            } else if flags.syn && flags.rst {
                "SYN+RST (reset of non-existent connection)"
            } else {
                "invalid flag combination"
            };

            return Some(RuleResult {
                rule_id: self.id().to_string(),
                score_delta: 3.0,
                confidence: 0.98, // Very high - these should never occur
                evidence: format!("Invalid TCP flags: {}", detail),
                tags: vec!["invalid-flags".into(), "protocol-violation".into()],
            });
        }

        None
    }
}

/// STEALTH7: Mixed Stealth Scan Detection
/// Score: +5.0 (using multiple techniques)
pub struct MixedStealthScanRule;

impl DetectionRule for MixedStealthScanRule {
    fn id(&self) -> &str { "STEALTH7" }
    fn name(&self) -> &str { "Mixed Stealth Scan Detection" }
    fn category(&self) -> RuleCategory { RuleCategory::Custom }
    fn default_weight(&self) -> f32 { 5.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let counts = &ctx.behavior.stealth_scan_counts;

        // Count how many different stealth techniques are being used
        let techniques_used: Vec<&str> = ["null", "fin", "xmas", "maimon", "ack_only"]
            .iter()
            .filter(|&&t| counts.get(t).copied().unwrap_or(0) >= 3)
            .copied()
            .collect();

        if techniques_used.len() >= 2 {
            let score = match techniques_used.len() {
                2 => 3.0,
                3 => 4.0,
                _ => 5.0, // 4+ techniques is extremely suspicious
            };

            return Some(RuleResult {
                rule_id: self.id().to_string(),
                score_delta: score,
                confidence: 0.95,
                evidence: format!("Multiple stealth scan techniques: {:?}", techniques_used),
                tags: vec!["mixed-stealth".into(), "evasion-attempt".into(), "high-threat".into()],
            });
        }

        None
    }
}

/// Get all stealth scan detection rules
pub fn stealth_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(NullScanRule),
        Box::new(FinScanRule),
        Box::new(XmasScanRule),
        Box::new(MaimonScanRule),
        Box::new(AckScanRule),
        Box::new(InvalidFlagsRule),
        Box::new(MixedStealthScanRule),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_flags_null() {
        let flags = TcpFlagSet {
            syn: false, ack: false, fin: false, rst: false, psh: false, urg: false
        };
        assert!(flags.is_null());
        assert!(!flags.is_fin_only());
        assert!(!flags.is_xmas());
    }

    #[test]
    fn test_tcp_flags_fin_only() {
        let flags = TcpFlagSet {
            syn: false, ack: false, fin: true, rst: false, psh: false, urg: false
        };
        assert!(!flags.is_null());
        assert!(flags.is_fin_only());
    }

    #[test]
    fn test_tcp_flags_xmas() {
        let flags = TcpFlagSet {
            syn: false, ack: false, fin: true, rst: false, psh: true, urg: true
        };
        assert!(flags.is_xmas());
    }

    #[test]
    fn test_tcp_flags_maimon() {
        let flags = TcpFlagSet {
            syn: false, ack: true, fin: true, rst: false, psh: false, urg: false
        };
        assert!(flags.is_maimon());
    }

    #[test]
    fn test_tcp_flags_invalid() {
        // SYN+FIN is invalid
        let syn_fin = TcpFlagSet {
            syn: true, ack: false, fin: true, rst: false, psh: false, urg: false
        };
        assert!(syn_fin.is_invalid());

        // SYN+RST is invalid
        let syn_rst = TcpFlagSet {
            syn: true, ack: false, fin: false, rst: true, psh: false, urg: false
        };
        assert!(syn_rst.is_invalid());
    }
}
