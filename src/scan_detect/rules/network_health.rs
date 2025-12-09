//! Network health detection rules (N1-N3)
//!
//! These rules analyze global network health to distinguish attacks from network issues.

use super::{DetectionRule, EvaluationContext, RuleCategory, RuleResult};

/// Network health context for rules
#[derive(Debug, Clone, Default)]
pub struct NetworkHealthContext {
    /// Total tracked sources
    pub total_sources: usize,
    /// Sources with only half-open connections
    pub sources_half_open_only: usize,
    /// Global half-open ratio
    pub half_open_ratio: f32,
    /// Is network health suspect?
    pub is_suspect: bool,
    /// Recent verification failures
    pub verification_failures: u32,
}

/// N1: Global half-open anomaly
/// If many sources have only half-open connections, might be network issue
pub struct GlobalHalfOpenRule;

impl DetectionRule for GlobalHalfOpenRule {
    fn id(&self) -> &str { "N1" }
    fn name(&self) -> &str { "Global half-open anomaly" }
    fn category(&self) -> RuleCategory { RuleCategory::NetworkHealth }
    fn default_weight(&self) -> f32 { -2.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref health) = ctx.network_health {
            // If >80% of sources have only half-open, reduce individual scores
            if health.half_open_ratio > 0.8 && health.total_sources > 10 {
                return Some(RuleResult::new(
                    self.id(),
                    -2.0, // Reduce score since this might be network issue
                    &format!("Global half-open anomaly ({:.0}% of {} sources)",
                             health.half_open_ratio * 100.0, health.total_sources),
                ).with_tag("network-issue"));
            }
        }
        None
    }
}

/// N2: Single source anomaly (most traffic from one IP)
/// If one source is responsible for most suspicious activity
pub struct SingleSourceAnomalyRule;

impl DetectionRule for SingleSourceAnomalyRule {
    fn id(&self) -> &str { "N2" }
    fn name(&self) -> &str { "Single source anomaly" }
    fn category(&self) -> RuleCategory { RuleCategory::NetworkHealth }
    fn default_weight(&self) -> f32 { 1.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        // This rule would check if this IP has significantly more activity
        // than the average. For now, we check if the source has many ports.
        let unique_ports = ctx.behavior.unique_ports().len();

        if unique_ports > 50 {
            // Source is very active
            return Some(RuleResult::new(
                self.id(),
                1.0,
                &format!("High port diversity: {} unique ports", unique_ports),
            ).with_tag("high-activity"));
        }

        None
    }
}

/// N3: Verification failure pattern
/// If nmap verification fails, reduce confidence
pub struct VerificationFailureRule;

impl DetectionRule for VerificationFailureRule {
    fn id(&self) -> &str { "N3" }
    fn name(&self) -> &str { "Verification failed" }
    fn category(&self) -> RuleCategory { RuleCategory::NetworkHealth }
    fn default_weight(&self) -> f32 { -1.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        // Check if this source has failed verification
        if ctx.behavior.verified {
            if let Some(ref result) = ctx.behavior.verification_result {
                if !result.probe_success {
                    return Some(RuleResult::new(
                        self.id(),
                        -1.0,
                        &format!("Verification failed: {}", result.details),
                    ).with_tag("verification-failed"));
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::scan_detect::behavior::{SourceBehavior, FlowKey};
    use crate::scan_detect::config::ScanDetectConfig;

    fn test_context<'a>(
        behavior: &'a SourceBehavior,
        config: &'a ScanDetectConfig,
    ) -> EvaluationContext<'a> {
        EvaluationContext::new(behavior.src_ip, behavior, config)
    }

    #[test]
    fn test_global_half_open_rule() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let behavior = SourceBehavior::new(ip);
        let config = ScanDetectConfig::default();

        let mut ctx = test_context(&behavior, &config);
        ctx.network_health = Some(NetworkHealthContext {
            total_sources: 20,
            half_open_ratio: 0.9,
            ..Default::default()
        });

        let rule = GlobalHalfOpenRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
        assert!(result.unwrap().score_delta < 0.0); // Should reduce score
    }

    #[test]
    fn test_single_source_anomaly_rule() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let mut behavior = SourceBehavior::new(ip);
        let config = ScanDetectConfig::default();

        // Record many ports
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for port in 1..=60 {
            behavior.record_syn(FlowKey {
                src_port: 50000,
                dst_ip,
                dst_port: port,
            });
        }

        let ctx = test_context(&behavior, &config);

        let rule = SingleSourceAnomalyRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }
}
