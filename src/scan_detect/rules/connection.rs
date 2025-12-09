//! Connection-based detection rules (R1-R16)
//!
//! These rules analyze TCP connection behavior to detect scanning.

use std::time::Duration;
use super::{DetectionRule, EvaluationContext, RuleCategory, RuleResult};

/// R1: Half-open SYN to different port
/// Triggered when a SYN is sent but handshake doesn't complete
pub struct HalfOpenSynRule;

impl DetectionRule for HalfOpenSynRule {
    fn id(&self) -> &str { "R1" }
    fn name(&self) -> &str { "Half-open SYN" }
    fn category(&self) -> RuleCategory { RuleCategory::Connection }
    fn default_weight(&self) -> f32 { 1.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        // Only trigger on SYN packets
        if !ctx.is_syn {
            return None;
        }

        // Check if this flow doesn't already have a completed connection
        let flow_key = ctx.flow_key()?;
        if ctx.behavior.is_flow_completed(&flow_key) {
            return None;
        }

        // Count existing half-open connections
        let half_open = ctx.behavior.half_open_count();

        if half_open >= 1 {
            let weight = ctx.config.weights.half_open_syn;
            Some(RuleResult::new(
                self.id(),
                weight,
                &format!("SYN to port {} ({} half-open)", flow_key.dst_port, half_open + 1),
            ).with_tag("half-open"))
        } else {
            None
        }
    }
}

/// R2: SYN to targeted/sensitive port
/// Bonus score for scanning commonly targeted ports
pub struct TargetedPortRule;

impl DetectionRule for TargetedPortRule {
    fn id(&self) -> &str { "R2" }
    fn name(&self) -> &str { "Targeted port bonus" }
    fn category(&self) -> RuleCategory { RuleCategory::Connection }
    fn default_weight(&self) -> f32 { 0.5 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if !ctx.is_syn {
            return None;
        }

        let port = ctx.current_port?;

        if ctx.is_targeted_port() {
            let weight = ctx.config.weights.targeted_port_bonus;
            Some(RuleResult::new(
                self.id(),
                weight,
                &format!("SYN to targeted port {}", port),
            ).with_tag("targeted-port"))
        } else {
            None
        }
    }
}

/// R3: Sequential port scanning
/// Detects scanning ports in sequence (N, N+1, N+2...)
pub struct SequentialScanRule;

impl DetectionRule for SequentialScanRule {
    fn id(&self) -> &str { "R3" }
    fn name(&self) -> &str { "Sequential scan" }
    fn category(&self) -> RuleCategory { RuleCategory::Connection }
    fn default_weight(&self) -> f32 { 2.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        // Need at least 3 sequential ports
        if ctx.behavior.has_sequential_pattern(3) {
            let weight = ctx.config.weights.sequential_scan;
            Some(RuleResult::new(
                self.id(),
                weight,
                "Sequential port scanning detected",
            ).with_tag("sequential-scan"))
        } else {
            None
        }
    }
}

/// R4: Rapid SYN rate
/// Detects high rate of SYN packets (>10/sec)
pub struct RapidSynRateRule;

impl DetectionRule for RapidSynRateRule {
    fn id(&self) -> &str { "R4" }
    fn name(&self) -> &str { "Rapid SYN rate" }
    fn category(&self) -> RuleCategory { RuleCategory::Connection }
    fn default_weight(&self) -> f32 { 3.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let rate = ctx.behavior.syn_rate(Duration::from_secs(10));

        if rate > 10.0 {
            let weight = ctx.config.weights.rapid_rate;
            Some(RuleResult::new(
                self.id(),
                weight,
                &format!("Rapid SYN rate: {:.1}/sec", rate),
            ).with_tag("rapid-scan"))
        } else if rate > 5.0 {
            // Moderate rate gets partial score
            let weight = ctx.config.weights.rapid_rate * 0.5;
            Some(RuleResult::new(
                self.id(),
                weight,
                &format!("Elevated SYN rate: {:.1}/sec", rate),
            ).with_tag("elevated-rate"))
        } else {
            None
        }
    }
}

/// R5: SYN to closed port (RST received)
/// Detects probing of ports that respond with RST
pub struct ClosedPortRstRule;

impl DetectionRule for ClosedPortRstRule {
    fn id(&self) -> &str { "R5" }
    fn name(&self) -> &str { "Closed port RST" }
    fn category(&self) -> RuleCategory { RuleCategory::Connection }
    fn default_weight(&self) -> f32 { 0.5 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if !ctx.is_rst {
            return None;
        }

        let flow_key = ctx.flow_key()?;

        // Check if this was a half-open connection that got RST
        if let Some(conn) = ctx.behavior.get_connection(&flow_key) {
            if conn.state == super::super::behavior::ConnectionState::HalfOpen {
                let weight = ctx.config.weights.closed_port_rst;
                return Some(RuleResult::new(
                    self.id(),
                    weight,
                    &format!("RST received for port {}", flow_key.dst_port),
                ).with_tag("closed-port"));
            }
        }

        None
    }
}

/// R6: Scanner fingerprint match
/// Detects known scanner tool signatures (nmap, masscan, etc.)
pub struct ScannerFingerprintRule;

impl DetectionRule for ScannerFingerprintRule {
    fn id(&self) -> &str { "R6" }
    fn name(&self) -> &str { "Scanner fingerprint" }
    fn category(&self) -> RuleCategory { RuleCategory::Connection }
    fn default_weight(&self) -> f32 { 5.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        // Check TCP options for scanner signatures
        let options = ctx.tcp_options?;

        // nmap default: MSS, NOP, WScale, NOP, NOP, Timestamp
        // This is a simplified check - real implementation would be more thorough
        if is_nmap_signature(options) {
            let weight = ctx.config.weights.scanner_fingerprint;
            return Some(RuleResult::new(
                self.id(),
                weight,
                "nmap scanner fingerprint detected",
            ).with_tags(vec!["scanner".into(), "nmap".into()]));
        }

        // masscan signature: minimal options
        if is_masscan_signature(options) {
            let weight = ctx.config.weights.scanner_fingerprint;
            return Some(RuleResult::new(
                self.id(),
                weight,
                "masscan scanner fingerprint detected",
            ).with_tags(vec!["scanner".into(), "masscan".into()]));
        }

        None
    }
}

/// R7: Unusual TTL values
/// Detects TTL values that don't match common OS defaults
pub struct UnusualTtlRule;

impl DetectionRule for UnusualTtlRule {
    fn id(&self) -> &str { "R7" }
    fn name(&self) -> &str { "Unusual TTL" }
    fn category(&self) -> RuleCategory { RuleCategory::Connection }
    fn default_weight(&self) -> f32 { 1.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let ttl = ctx.ttl?;

        // Common OS TTL defaults: 64 (Linux), 128 (Windows), 255 (Cisco/network devices)
        // Unusual values might indicate TTL manipulation
        let is_unusual = !matches!(ttl, 60..=68 | 124..=132 | 250..=255);

        if is_unusual {
            let weight = ctx.config.weights.unusual_ttl;
            Some(RuleResult::new(
                self.id(),
                weight,
                &format!("Unusual TTL value: {}", ttl),
            ).with_tag("unusual-ttl"))
        } else {
            None
        }
    }
}

/// R8: TCP options fingerprint mismatch
/// Detects TCP options that don't match claimed OS
pub struct TcpOptionsMismatchRule;

impl DetectionRule for TcpOptionsMismatchRule {
    fn id(&self) -> &str { "R8" }
    fn name(&self) -> &str { "TCP options mismatch" }
    fn category(&self) -> RuleCategory { RuleCategory::Connection }
    fn default_weight(&self) -> f32 { 1.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let ttl = ctx.ttl?;
        let _options = ctx.tcp_options?;

        // Check for TTL/options mismatch
        // Linux TTL 64 with Windows-style options, etc.
        // This is a simplified check

        // Linux typically has TTL 64 and specific option ordering
        // Windows typically has TTL 128 and different options
        let appears_linux = ttl >= 60 && ttl <= 68;
        let appears_windows = ttl >= 124 && ttl <= 132;

        if appears_linux || appears_windows {
            // TODO: Compare options to expected for this OS
            // For now, we don't have enough info
            None
        } else {
            None
        }
    }
}

/// R10: Completed TCP handshake (reduces score)
pub struct CompletedHandshakeRule;

impl DetectionRule for CompletedHandshakeRule {
    fn id(&self) -> &str { "R10" }
    fn name(&self) -> &str { "Completed handshake" }
    fn category(&self) -> RuleCategory { RuleCategory::Connection }
    fn default_weight(&self) -> f32 { -2.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        // Only trigger when we see the completing ACK
        if !ctx.is_ack || ctx.is_syn {
            return None;
        }

        let flow_key = ctx.flow_key()?;

        // Check if we have a half-open connection on this flow that's completing
        if let Some(conn) = ctx.behavior.get_connection(&flow_key) {
            if conn.state == super::super::behavior::ConnectionState::HalfOpen
                || conn.state == super::super::behavior::ConnectionState::SynReceived
            {
                let weight = ctx.config.weights.completed_handshake;
                return Some(RuleResult::new(
                    self.id(),
                    weight,
                    &format!("Handshake completed on port {}", flow_key.dst_port),
                ).with_tag("legitimate"));
            }
        }

        None
    }
}

/// R11: Data exchanged after handshake (reduces score)
pub struct DataExchangedRule;

impl DetectionRule for DataExchangedRule {
    fn id(&self) -> &str { "R11" }
    fn name(&self) -> &str { "Data exchanged" }
    fn category(&self) -> RuleCategory { RuleCategory::Connection }
    fn default_weight(&self) -> f32 { -1.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        // Check for payload data
        if ctx.payload_size == 0 {
            return None;
        }

        let flow_key = ctx.flow_key()?;

        // Check if connection is established
        if let Some(conn) = ctx.behavior.get_connection(&flow_key) {
            if conn.state == super::super::behavior::ConnectionState::Established
                || conn.state == super::super::behavior::ConnectionState::Active
            {
                let weight = ctx.config.weights.data_exchanged;
                return Some(RuleResult::new(
                    self.id(),
                    weight,
                    &format!("Data exchanged on port {} ({} bytes)", flow_key.dst_port, ctx.payload_size),
                ).with_tag("legitimate"));
            }
        }

        None
    }
}

/// R12: TLS handshake completed (reduces score)
pub struct TlsCompletedRule;

impl DetectionRule for TlsCompletedRule {
    fn id(&self) -> &str { "R12" }
    fn name(&self) -> &str { "TLS completed" }
    fn category(&self) -> RuleCategory { RuleCategory::Connection }
    fn default_weight(&self) -> f32 { -2.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let flow_key = ctx.flow_key()?;

        // Check if protocol detected is TLS
        if let Some(conn) = ctx.behavior.get_connection(&flow_key) {
            if let Some(ref proto) = conn.protocol {
                if proto == "tls" || proto == "ssl" {
                    let weight = ctx.config.weights.tls_completed;
                    return Some(RuleResult::new(
                        self.id(),
                        weight,
                        &format!("TLS handshake completed on port {}", flow_key.dst_port),
                    ).with_tag("legitimate"));
                }
            }
        }

        None
    }
}

/// R13: HTTP request after connect (reduces score)
pub struct HttpRequestRule;

impl DetectionRule for HttpRequestRule {
    fn id(&self) -> &str { "R13" }
    fn name(&self) -> &str { "HTTP request" }
    fn category(&self) -> RuleCategory { RuleCategory::Connection }
    fn default_weight(&self) -> f32 { -1.5 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let flow_key = ctx.flow_key()?;

        // Check if protocol detected is HTTP
        if let Some(conn) = ctx.behavior.get_connection(&flow_key) {
            if let Some(ref proto) = conn.protocol {
                if proto == "http" || proto == "https" {
                    let weight = ctx.config.weights.http_request;
                    return Some(RuleResult::new(
                        self.id(),
                        weight,
                        &format!("HTTP request on port {}", flow_key.dst_port),
                    ).with_tag("legitimate"));
                }
            }
        }

        None
    }
}

// Helper functions for scanner fingerprinting

fn is_nmap_signature(_options: &[u8]) -> bool {
    // TODO: Implement proper TCP options parsing and nmap detection
    // nmap default SYN has specific TCP options pattern
    false
}

fn is_masscan_signature(_options: &[u8]) -> bool {
    // TODO: Implement proper masscan detection
    // masscan has minimal TCP options
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::scan_detect::behavior::{FlowKey, SourceBehavior};
    use crate::scan_detect::config::ScanDetectConfig;

    fn test_context<'a>(
        behavior: &'a SourceBehavior,
        config: &'a ScanDetectConfig,
    ) -> EvaluationContext<'a> {
        EvaluationContext::new(behavior.src_ip, behavior, config)
    }

    fn make_flow_key(src_port: u16, dst_ip: IpAddr, dst_port: u16) -> FlowKey {
        FlowKey::new(src_port, dst_ip, dst_port)
    }

    #[test]
    fn test_half_open_syn_rule() {
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut behavior = SourceBehavior::new(src_ip);
        let config = ScanDetectConfig::default();

        // First SYN - no rule trigger (need at least 1 existing half-open)
        behavior.record_syn(make_flow_key(50000, dst_ip, 22));
        let ctx = test_context(&behavior, &config)
            .with_src_port(50001)
            .with_dst_ip(dst_ip)
            .with_port(80)
            .with_syn();

        let rule = HalfOpenSynRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "R1");
    }

    #[test]
    fn test_targeted_port_rule() {
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let behavior = SourceBehavior::new(src_ip);
        let config = ScanDetectConfig::default();

        // SYN to targeted port (SSH)
        let ctx = test_context(&behavior, &config)
            .with_src_port(50000)
            .with_dst_ip(dst_ip)
            .with_port(22)
            .with_syn();

        let rule = TargetedPortRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
        assert_eq!(result.unwrap().rule_id, "R2");

        // SYN to non-targeted port
        let ctx = test_context(&behavior, &config)
            .with_src_port(50001)
            .with_dst_ip(dst_ip)
            .with_port(12345)
            .with_syn();

        let result = rule.evaluate(&ctx);
        assert!(result.is_none());
    }

    #[test]
    fn test_sequential_scan_rule() {
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut behavior = SourceBehavior::new(src_ip);
        let config = ScanDetectConfig::default();

        // Record sequential ports
        for port in 100..=102 {
            behavior.record_syn(make_flow_key(50000 + port, dst_ip, port));
        }

        let ctx = test_context(&behavior, &config);
        let rule = SequentialScanRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_completed_handshake_rule() {
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut behavior = SourceBehavior::new(src_ip);
        let config = ScanDetectConfig::default();

        let flow_80 = make_flow_key(50000, dst_ip, 80);

        // Record SYN
        behavior.record_syn(flow_80);

        // ACK completing handshake (same flow)
        let ctx = test_context(&behavior, &config)
            .with_src_port(50000)
            .with_dst_ip(dst_ip)
            .with_port(80)
            .with_ack();

        let rule = CompletedHandshakeRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
        // Should be negative (reduces score)
        assert!(result.unwrap().score_delta < 0.0);
    }
}
