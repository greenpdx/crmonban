//! Reputation-based detection rules (REP1-REP10)
//!
//! These rules use threat intelligence feeds and local reputation data.

use std::collections::HashSet;
use std::net::IpAddr;
use super::{DetectionRule, EvaluationContext, RuleCategory, RuleResult};

/// Reputation data for an IP address
#[derive(Debug, Clone, Default)]
pub struct ReputationData {
    /// AbuseIPDB confidence score (0-100)
    pub abuseipdb_score: Option<u8>,
    /// Number of AbuseIPDB reports
    pub abuseipdb_reports: Option<u32>,
    /// Is listed in Spamhaus
    pub in_spamhaus: bool,
    /// Is listed in Emerging Threats
    pub in_emerging_threats: bool,
    /// Seen in honeypot
    pub seen_in_honeypot: bool,
    /// Previously banned by this system
    pub previously_banned: bool,
    /// Is whitelisted
    pub is_whitelisted: bool,
    /// Is partner/vendor IP
    pub is_partner_vendor: bool,
    /// Custom threat intel feeds (feed_name -> listed)
    pub custom_feeds: Vec<String>,
}

/// Trait for reputation lookups
pub trait ReputationProvider: Send + Sync {
    /// Look up reputation for an IP
    fn lookup(&self, ip: IpAddr) -> ReputationData;

    /// Check if IP is whitelisted
    fn is_whitelisted(&self, ip: IpAddr) -> bool;

    /// Record a ban for future lookups
    fn record_ban(&self, ip: IpAddr);
}

/// Null implementation when no reputation data is available
pub struct NullReputationProvider;

impl ReputationProvider for NullReputationProvider {
    fn lookup(&self, _ip: IpAddr) -> ReputationData {
        ReputationData::default()
    }

    fn is_whitelisted(&self, _ip: IpAddr) -> bool {
        false
    }

    fn record_ban(&self, _ip: IpAddr) {}
}

/// Simple in-memory whitelist/blacklist provider
pub struct SimpleReputationProvider {
    whitelist: HashSet<IpAddr>,
    previous_bans: HashSet<IpAddr>,
}

impl SimpleReputationProvider {
    pub fn new() -> Self {
        Self {
            whitelist: HashSet::new(),
            previous_bans: HashSet::new(),
        }
    }

    pub fn add_whitelist(&mut self, ip: IpAddr) {
        self.whitelist.insert(ip);
    }
}

impl Default for SimpleReputationProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationProvider for SimpleReputationProvider {
    fn lookup(&self, ip: IpAddr) -> ReputationData {
        ReputationData {
            is_whitelisted: self.whitelist.contains(&ip),
            previously_banned: self.previous_bans.contains(&ip),
            ..Default::default()
        }
    }

    fn is_whitelisted(&self, ip: IpAddr) -> bool {
        self.whitelist.contains(&ip)
    }

    fn record_ban(&self, _ip: IpAddr) {
        // Would need interior mutability for this
    }
}

/// REP1: AbuseIPDB low confidence (25-50%)
pub struct AbuseIpDbLowRule;

impl DetectionRule for AbuseIpDbLowRule {
    fn id(&self) -> &str { "REP1" }
    fn name(&self) -> &str { "AbuseIPDB low confidence" }
    fn category(&self) -> RuleCategory { RuleCategory::Reputation }
    fn default_weight(&self) -> f32 { 3.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref rep) = ctx.reputation_data {
            if let Some(score) = rep.abuseipdb_score {
                if (25..=50).contains(&score) {
                    return Some(RuleResult::new(
                        self.id(),
                        ctx.config.weights.abuseipdb_low,
                        &format!("AbuseIPDB score: {}%", score),
                    ).with_tag("abuseipdb"));
                }
            }
        }
        None
    }
}

/// REP2: AbuseIPDB high confidence (>50%)
pub struct AbuseIpDbHighRule;

impl DetectionRule for AbuseIpDbHighRule {
    fn id(&self) -> &str { "REP2" }
    fn name(&self) -> &str { "AbuseIPDB high confidence" }
    fn category(&self) -> RuleCategory { RuleCategory::Reputation }
    fn default_weight(&self) -> f32 { 5.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref rep) = ctx.reputation_data {
            if let Some(score) = rep.abuseipdb_score {
                if score > 50 {
                    return Some(RuleResult::new(
                        self.id(),
                        ctx.config.weights.abuseipdb_high,
                        &format!("AbuseIPDB high score: {}%", score),
                    ).with_tags(vec!["abuseipdb".into(), "known-bad".into()]));
                }
            }
        }
        None
    }
}

/// REP3: Spamhaus listing
pub struct SpamhausRule;

impl DetectionRule for SpamhausRule {
    fn id(&self) -> &str { "REP3" }
    fn name(&self) -> &str { "Spamhaus listing" }
    fn category(&self) -> RuleCategory { RuleCategory::Reputation }
    fn default_weight(&self) -> f32 { 4.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref rep) = ctx.reputation_data {
            if rep.in_spamhaus {
                return Some(RuleResult::new(
                    self.id(),
                    ctx.config.weights.spamhaus,
                    "Listed in Spamhaus",
                ).with_tags(vec!["spamhaus".into(), "known-bad".into()]));
            }
        }
        None
    }
}

/// REP4: Emerging Threats listing
pub struct EmergingThreatsRule;

impl DetectionRule for EmergingThreatsRule {
    fn id(&self) -> &str { "REP4" }
    fn name(&self) -> &str { "Emerging Threats" }
    fn category(&self) -> RuleCategory { RuleCategory::Reputation }
    fn default_weight(&self) -> f32 { 3.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref rep) = ctx.reputation_data {
            if rep.in_emerging_threats {
                return Some(RuleResult::new(
                    self.id(),
                    ctx.config.weights.emerging_threats,
                    "Listed in Emerging Threats",
                ).with_tag("emerging-threats"));
            }
        }
        None
    }
}

/// REP5: Seen in honeypot
pub struct HoneypotRule;

impl DetectionRule for HoneypotRule {
    fn id(&self) -> &str { "REP5" }
    fn name(&self) -> &str { "Honeypot hit" }
    fn category(&self) -> RuleCategory { RuleCategory::Reputation }
    fn default_weight(&self) -> f32 { 4.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref rep) = ctx.reputation_data {
            if rep.seen_in_honeypot {
                return Some(RuleResult::new(
                    self.id(),
                    ctx.config.weights.honeypot,
                    "Previously seen in honeypot",
                ).with_tags(vec!["honeypot".into(), "scanner".into()]));
            }
        }
        None
    }
}

/// REP6: Previously banned
pub struct PreviousBanRule;

impl DetectionRule for PreviousBanRule {
    fn id(&self) -> &str { "REP6" }
    fn name(&self) -> &str { "Previously banned" }
    fn category(&self) -> RuleCategory { RuleCategory::Reputation }
    fn default_weight(&self) -> f32 { 2.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref rep) = ctx.reputation_data {
            if rep.previously_banned {
                return Some(RuleResult::new(
                    self.id(),
                    ctx.config.weights.previous_ban,
                    "Previously banned by this system",
                ).with_tag("repeat-offender"));
            }
        }
        None
    }
}

/// REP7: Whitelisted IP (major score reduction)
pub struct WhitelistRule;

impl DetectionRule for WhitelistRule {
    fn id(&self) -> &str { "REP7" }
    fn name(&self) -> &str { "Whitelisted" }
    fn category(&self) -> RuleCategory { RuleCategory::Reputation }
    fn default_weight(&self) -> f32 { -5.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref rep) = ctx.reputation_data {
            if rep.is_whitelisted {
                return Some(RuleResult::new(
                    self.id(),
                    ctx.config.weights.whitelist,
                    "Whitelisted IP",
                ).with_tag("whitelisted"));
            }
        }
        None
    }
}

/// REP8: Partner/vendor IP (score reduction)
pub struct PartnerVendorRule;

impl DetectionRule for PartnerVendorRule {
    fn id(&self) -> &str { "REP8" }
    fn name(&self) -> &str { "Partner/vendor IP" }
    fn category(&self) -> RuleCategory { RuleCategory::Reputation }
    fn default_weight(&self) -> f32 { -3.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref rep) = ctx.reputation_data {
            if rep.is_partner_vendor {
                return Some(RuleResult::new(
                    self.id(),
                    ctx.config.weights.partner_vendor,
                    "Known partner/vendor IP",
                ).with_tag("partner"));
            }
        }
        None
    }
}

/// REP9: Custom threat intel feed match
pub struct CustomFeedRule {
    #[allow(dead_code)]
    feed_name: String,
}

impl CustomFeedRule {
    pub fn new(feed_name: &str) -> Self {
        Self {
            feed_name: feed_name.to_string(),
        }
    }
}

impl DetectionRule for CustomFeedRule {
    fn id(&self) -> &str { "REP9" }
    fn name(&self) -> &str { "Custom feed match" }
    fn category(&self) -> RuleCategory { RuleCategory::Reputation }
    fn default_weight(&self) -> f32 { 3.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref rep) = ctx.reputation_data {
            if !rep.custom_feeds.is_empty() {
                let feeds = rep.custom_feeds.join(", ");
                return Some(RuleResult::new(
                    self.id(),
                    3.0, // Default weight for custom feeds
                    &format!("Listed in custom feeds: {}", feeds),
                ).with_tag("custom-feed"));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use crate::scan_detect::behavior::SourceBehavior;
    use crate::scan_detect::config::ScanDetectConfig;

    fn test_context<'a>(
        behavior: &'a SourceBehavior,
        config: &'a ScanDetectConfig,
    ) -> EvaluationContext<'a> {
        EvaluationContext::new(behavior.src_ip, behavior, config)
    }

    #[test]
    fn test_abuseipdb_high_rule() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let behavior = SourceBehavior::new(ip);
        let config = ScanDetectConfig::default();

        let mut ctx = test_context(&behavior, &config);
        ctx.reputation_data = Some(ReputationData {
            abuseipdb_score: Some(75),
            ..Default::default()
        });

        let rule = AbuseIpDbHighRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
        assert!(result.unwrap().score_delta > 0.0);
    }

    #[test]
    fn test_whitelist_rule() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let behavior = SourceBehavior::new(ip);
        let config = ScanDetectConfig::default();

        let mut ctx = test_context(&behavior, &config);
        ctx.reputation_data = Some(ReputationData {
            is_whitelisted: true,
            ..Default::default()
        });

        let rule = WhitelistRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
        assert!(result.unwrap().score_delta < 0.0); // Should reduce score
    }

    #[test]
    fn test_previous_ban_rule() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let behavior = SourceBehavior::new(ip);
        let config = ScanDetectConfig::default();

        let mut ctx = test_context(&behavior, &config);
        ctx.reputation_data = Some(ReputationData {
            previously_banned: true,
            ..Default::default()
        });

        let rule = PreviousBanRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
        assert!(result.unwrap().tags.contains(&"repeat-offender".to_string()));
    }
}
