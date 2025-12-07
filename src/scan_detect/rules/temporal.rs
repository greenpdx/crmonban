//! Temporal/time-based detection rules (T1-T7)
//!
//! These rules analyze timing patterns to add context to scan detection.

use std::time::Duration;
use super::{DetectionRule, EvaluationContext, RuleCategory, RuleResult};

/// T1: Off-hours activity
/// Scanning during non-business hours (00:00-06:00 local time)
pub struct OffHoursRule;

impl DetectionRule for OffHoursRule {
    fn id(&self) -> &str { "T1" }
    fn name(&self) -> &str { "Off-hours activity" }
    fn category(&self) -> RuleCategory { RuleCategory::Temporal }
    fn default_weight(&self) -> f32 { 1.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(hour) = ctx.current_hour {
            // Off-hours: midnight to 6am
            if hour < 6 {
                return Some(RuleResult::new(
                    self.id(),
                    ctx.config.weights.off_hours,
                    &format!("Activity during off-hours ({}:00)", hour),
                ).with_tag("off-hours"));
            }
        }
        None
    }
}

/// T2: Business hours activity (reduces score)
/// Legitimate activity during normal business hours
pub struct BusinessHoursRule;

impl DetectionRule for BusinessHoursRule {
    fn id(&self) -> &str { "T2" }
    fn name(&self) -> &str { "Business hours" }
    fn category(&self) -> RuleCategory { RuleCategory::Temporal }
    fn default_weight(&self) -> f32 { -0.5 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(hour) = ctx.current_hour {
            // Business hours: 9am to 5pm
            if (9..=17).contains(&hour) {
                // Only reduce if also weekday
                if let Some(dow) = ctx.day_of_week {
                    if (1..=5).contains(&dow) {
                        return Some(RuleResult::new(
                            self.id(),
                            ctx.config.weights.business_hours,
                            "Activity during business hours",
                        ).with_tag("business-hours"));
                    }
                }
            }
        }
        None
    }
}

/// T3: Burst after silence
/// Sudden activity after long period of no connections
pub struct BurstAfterSilenceRule;

impl DetectionRule for BurstAfterSilenceRule {
    fn id(&self) -> &str { "T3" }
    fn name(&self) -> &str { "Burst after silence" }
    fn category(&self) -> RuleCategory { RuleCategory::Temporal }
    fn default_weight(&self) -> f32 { 1.5 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        // Check if there was a long gap before recent activity
        let duration = ctx.behavior.duration();
        let syn_rate = ctx.behavior.syn_rate(Duration::from_secs(10));

        // If source has been tracked for a while (>5 min) but high recent activity
        if duration > Duration::from_secs(300) && syn_rate > 5.0 {
            // Check for gap in activity - if we have recent SYNs but old first_seen
            // This suggests a burst after silence
            let recent_syn_count = ctx.behavior.syn_timestamps.len();
            let expected_rate = recent_syn_count as f32 / duration.as_secs_f32();

            if expected_rate < 0.1 && syn_rate > 1.0 {
                return Some(RuleResult::new(
                    self.id(),
                    ctx.config.weights.burst_after_silence,
                    &format!("Burst activity (rate {:.1}/s) after silence", syn_rate),
                ).with_tag("burst"));
            }
        }
        None
    }
}

/// T4: Consistent timing (automated scanning)
/// Regular interval between connections suggests automation
pub struct ConsistentTimingRule;

impl DetectionRule for ConsistentTimingRule {
    fn id(&self) -> &str { "T4" }
    fn name(&self) -> &str { "Consistent timing" }
    fn category(&self) -> RuleCategory { RuleCategory::Temporal }
    fn default_weight(&self) -> f32 { 2.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let timestamps = &ctx.behavior.syn_timestamps;

        if timestamps.len() < 5 {
            return None;
        }

        // Calculate intervals between SYNs
        let intervals: Vec<Duration> = timestamps
            .iter()
            .zip(timestamps.iter().skip(1))
            .map(|(a, b)| b.duration_since(*a))
            .collect();

        if intervals.is_empty() {
            return None;
        }

        // Calculate mean and variance
        let mean_nanos: f64 = intervals.iter().map(|d| d.as_nanos() as f64).sum::<f64>()
            / intervals.len() as f64;

        if mean_nanos == 0.0 {
            return None;
        }

        let variance: f64 = intervals.iter()
            .map(|d| {
                let diff = d.as_nanos() as f64 - mean_nanos;
                diff * diff
            })
            .sum::<f64>() / intervals.len() as f64;

        let std_dev = variance.sqrt();
        let coefficient_of_variation = std_dev / mean_nanos;

        // Very consistent timing (CV < 0.3) suggests automation
        if coefficient_of_variation < 0.3 && mean_nanos > 1_000_000.0 {
            return Some(RuleResult::new(
                self.id(),
                ctx.config.weights.consistent_timing,
                &format!("Consistent timing pattern (CV={:.2})", coefficient_of_variation),
            ).with_tags(vec!["automation".into(), "consistent-timing".into()]));
        }

        None
    }
}

/// T5: Weekend activity
/// Business-targeted scanning on weekends
pub struct WeekendActivityRule;

impl DetectionRule for WeekendActivityRule {
    fn id(&self) -> &str { "T5" }
    fn name(&self) -> &str { "Weekend activity" }
    fn category(&self) -> RuleCategory { RuleCategory::Temporal }
    fn default_weight(&self) -> f32 { 0.5 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(dow) = ctx.day_of_week {
            // Weekend: 0=Sunday, 6=Saturday
            if dow == 0 || dow == 6 {
                // Extra suspicious if targeting business ports
                if ctx.is_targeted_port() {
                    return Some(RuleResult::new(
                        self.id(),
                        ctx.config.weights.weekend_activity,
                        "Business port scanning on weekend",
                    ).with_tag("weekend"));
                }
            }
        }
        None
    }
}

/// T6: Holiday period activity
/// Scanning during known holiday periods (needs external data)
pub struct HolidayPeriodRule;

impl DetectionRule for HolidayPeriodRule {
    fn id(&self) -> &str { "T6" }
    fn name(&self) -> &str { "Holiday period" }
    fn category(&self) -> RuleCategory { RuleCategory::Temporal }
    fn default_weight(&self) -> f32 { 1.0 }

    fn evaluate(&self, _ctx: &EvaluationContext) -> Option<RuleResult> {
        // TODO: Implement holiday detection
        // Would need access to calendar data
        None
    }
}

/// T7: Rapid succession ports
/// Multiple ports scanned in very rapid succession (< 100ms apart)
pub struct RapidSuccessionRule;

impl DetectionRule for RapidSuccessionRule {
    fn id(&self) -> &str { "T7" }
    fn name(&self) -> &str { "Rapid succession" }
    fn category(&self) -> RuleCategory { RuleCategory::Temporal }
    fn default_weight(&self) -> f32 { 2.5 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        let timestamps = &ctx.behavior.syn_timestamps;

        if timestamps.len() < 3 {
            return None;
        }

        // Check for rapid succession (multiple SYNs < 100ms apart)
        let recent: Vec<_> = timestamps.iter().rev().take(10).collect();
        let mut rapid_count = 0;

        for i in 1..recent.len() {
            if let Some(duration) = recent[i-1].checked_duration_since(*recent[i]) {
                if duration < Duration::from_millis(100) {
                    rapid_count += 1;
                }
            }
        }

        if rapid_count >= 3 {
            return Some(RuleResult::new(
                self.id(),
                ctx.config.weights.consistent_timing, // Reuse this weight
                &format!("{} rapid succession SYNs (<100ms apart)", rapid_count),
            ).with_tags(vec!["rapid".into(), "scanner".into()]));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::scan_detect::behavior::SourceBehavior;
    use crate::scan_detect::config::ScanDetectConfig;

    fn test_context<'a>(
        behavior: &'a SourceBehavior,
        config: &'a ScanDetectConfig,
    ) -> EvaluationContext<'a> {
        EvaluationContext::new(behavior.src_ip, behavior, config)
    }

    #[test]
    fn test_off_hours_rule() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let behavior = SourceBehavior::new(ip);
        let config = ScanDetectConfig::default();

        let mut ctx = test_context(&behavior, &config);
        ctx.current_hour = Some(3); // 3am

        let rule = OffHoursRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_business_hours_rule() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let behavior = SourceBehavior::new(ip);
        let config = ScanDetectConfig::default();

        let mut ctx = test_context(&behavior, &config);
        ctx.current_hour = Some(10); // 10am
        ctx.day_of_week = Some(3); // Wednesday

        let rule = BusinessHoursRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
        assert!(result.unwrap().score_delta < 0.0); // Should reduce score
    }

    #[test]
    fn test_weekend_activity_rule() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let behavior = SourceBehavior::new(ip);
        let config = ScanDetectConfig::default();

        let mut ctx = test_context(&behavior, &config);
        ctx.day_of_week = Some(0); // Sunday
        ctx.current_port = Some(22); // SSH (targeted port)

        let rule = WeekendActivityRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }
}
