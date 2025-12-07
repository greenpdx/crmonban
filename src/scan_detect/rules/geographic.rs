//! Geographic and ASN-based detection rules (G1-G8)
//!
//! These rules use GeoIP data to add context to scan detection.

use std::net::IpAddr;
use std::sync::Arc;
use super::{DetectionRule, EvaluationContext, RuleCategory, RuleResult};

/// GeoIP information for an IP address
#[derive(Debug, Clone, Default)]
pub struct GeoInfo {
    /// Country code (ISO 3166-1 alpha-2)
    pub country_code: Option<String>,
    /// ASN number
    pub asn: Option<u32>,
    /// ASN organization name
    pub asn_org: Option<String>,
    /// Is this a known VPN/proxy?
    pub is_vpn: bool,
    /// Is this a Tor exit node?
    pub is_tor_exit: bool,
    /// Is this a datacenter IP?
    pub is_datacenter: bool,
    /// Is this a residential IP?
    pub is_residential: bool,
    /// Is this known scanner infrastructure?
    pub is_known_scanner: bool,
}

/// Trait for GeoIP lookups
pub trait GeoIpProvider: Send + Sync {
    /// Look up geo info for an IP
    fn lookup(&self, ip: IpAddr) -> GeoInfo;
}

/// Null implementation when no GeoIP database is available
pub struct NullGeoIpProvider;

impl GeoIpProvider for NullGeoIpProvider {
    fn lookup(&self, _ip: IpAddr) -> GeoInfo {
        GeoInfo::default()
    }
}

/// High-risk countries for scanning activity
const HIGH_RISK_COUNTRIES: &[&str] = &[
    "CN", "RU", "KP", "IR", "SY",
];

/// Known VPN/proxy ASNs
const VPN_ASNS: &[u32] = &[
    // NordVPN, ExpressVPN, etc. - placeholder values
    9009,   // M247
    60068,  // CDN77
    62904,  // Eonix
];

/// Known hosting/datacenter ASNs
const DATACENTER_ASNS: &[u32] = &[
    // Major cloud providers
    16509,  // Amazon
    15169,  // Google
    8075,   // Microsoft
    13335,  // Cloudflare
    14618,  // Amazon
    16276,  // OVH
    24940,  // Hetzner
    63949,  // Linode
    14061,  // DigitalOcean
    20473,  // Vultr
];

/// G1: Known VPN/proxy ASN
pub struct VpnAsnRule {
    #[allow(dead_code)]
    provider: Arc<dyn GeoIpProvider>,
}

impl VpnAsnRule {
    pub fn new(provider: Arc<dyn GeoIpProvider>) -> Self {
        Self { provider }
    }
}

impl DetectionRule for VpnAsnRule {
    fn id(&self) -> &str { "G1" }
    fn name(&self) -> &str { "VPN/Proxy ASN" }
    fn category(&self) -> RuleCategory { RuleCategory::Geographic }
    fn default_weight(&self) -> f32 { 1.5 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        // Check if IP has geo_info with VPN flag
        if let Some(ref geo) = ctx.geo_info {
            if geo.is_vpn {
                return Some(RuleResult::new(
                    self.id(),
                    ctx.config.weights.vpn_asn,
                    &format!("VPN/Proxy ASN detected: {:?}", geo.asn_org),
                ).with_tag("vpn"));
            }

            // Check known VPN ASNs
            if let Some(asn) = geo.asn {
                if VPN_ASNS.contains(&asn) {
                    return Some(RuleResult::new(
                        self.id(),
                        ctx.config.weights.vpn_asn,
                        &format!("Known VPN ASN: {}", asn),
                    ).with_tag("vpn"));
                }
            }
        }
        None
    }
}

/// G2: High-risk country
pub struct HighRiskCountryRule;

impl DetectionRule for HighRiskCountryRule {
    fn id(&self) -> &str { "G2" }
    fn name(&self) -> &str { "High-risk country" }
    fn category(&self) -> RuleCategory { RuleCategory::Geographic }
    fn default_weight(&self) -> f32 { 1.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref geo) = ctx.geo_info {
            if let Some(ref cc) = geo.country_code {
                if HIGH_RISK_COUNTRIES.contains(&cc.as_str()) {
                    return Some(RuleResult::new(
                        self.id(),
                        ctx.config.weights.high_risk_country,
                        &format!("High-risk country: {}", cc),
                    ).with_tag("high-risk-country"));
                }
            }
        }
        None
    }
}

/// G3: Residential IP scanning business ports
pub struct ResidentialScanRule;

impl DetectionRule for ResidentialScanRule {
    fn id(&self) -> &str { "G3" }
    fn name(&self) -> &str { "Residential IP scanning" }
    fn category(&self) -> RuleCategory { RuleCategory::Geographic }
    fn default_weight(&self) -> f32 { 1.5 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref geo) = ctx.geo_info {
            if geo.is_residential && ctx.is_targeted_port() {
                return Some(RuleResult::new(
                    self.id(),
                    ctx.config.weights.residential_scan,
                    "Residential IP scanning targeted ports",
                ).with_tags(vec!["residential".into(), "suspicious".into()]));
            }
        }
        None
    }
}

/// G4: Datacenter IP bonus
pub struct DatacenterIpRule;

impl DetectionRule for DatacenterIpRule {
    fn id(&self) -> &str { "G4" }
    fn name(&self) -> &str { "Datacenter IP" }
    fn category(&self) -> RuleCategory { RuleCategory::Geographic }
    fn default_weight(&self) -> f32 { 0.5 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref geo) = ctx.geo_info {
            if geo.is_datacenter {
                return Some(RuleResult::new(
                    self.id(),
                    ctx.config.weights.datacenter_ip,
                    &format!("Datacenter IP: {:?}", geo.asn_org),
                ).with_tag("datacenter"));
            }

            // Check known datacenter ASNs
            if let Some(asn) = geo.asn {
                if DATACENTER_ASNS.contains(&asn) {
                    return Some(RuleResult::new(
                        self.id(),
                        ctx.config.weights.datacenter_ip,
                        &format!("Known datacenter ASN: {}", asn),
                    ).with_tag("datacenter"));
                }
            }
        }
        None
    }
}

/// G5: Same ASN/country as targets (reduces score)
pub struct SameNetworkRule;

impl DetectionRule for SameNetworkRule {
    fn id(&self) -> &str { "G5" }
    fn name(&self) -> &str { "Same network as target" }
    fn category(&self) -> RuleCategory { RuleCategory::Geographic }
    fn default_weight(&self) -> f32 { -1.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref geo) = ctx.geo_info {
            if let Some(ref target_geo) = ctx.target_geo_info {
                // Same ASN
                if geo.asn.is_some() && geo.asn == target_geo.asn {
                    return Some(RuleResult::new(
                        self.id(),
                        ctx.config.weights.same_network,
                        "Source and target in same ASN",
                    ).with_tag("same-network"));
                }
            }
        }
        None
    }
}

/// G7: Known scanner infrastructure
pub struct KnownScannerRule;

impl DetectionRule for KnownScannerRule {
    fn id(&self) -> &str { "G7" }
    fn name(&self) -> &str { "Known scanner infrastructure" }
    fn category(&self) -> RuleCategory { RuleCategory::Geographic }
    fn default_weight(&self) -> f32 { 5.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref geo) = ctx.geo_info {
            if geo.is_known_scanner {
                return Some(RuleResult::new(
                    self.id(),
                    ctx.config.weights.known_scanner,
                    "Known scanner infrastructure",
                ).with_tags(vec!["scanner".into(), "known-bad".into()]));
            }
        }
        None
    }
}

/// G8: Tor exit node
pub struct TorExitRule;

impl DetectionRule for TorExitRule {
    fn id(&self) -> &str { "G8" }
    fn name(&self) -> &str { "Tor exit node" }
    fn category(&self) -> RuleCategory { RuleCategory::Geographic }
    fn default_weight(&self) -> f32 { 2.0 }

    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult> {
        if let Some(ref geo) = ctx.geo_info {
            if geo.is_tor_exit {
                return Some(RuleResult::new(
                    self.id(),
                    ctx.config.weights.tor_exit,
                    "Tor exit node detected",
                ).with_tag("tor"));
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
    fn test_high_risk_country_rule() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let behavior = SourceBehavior::new(ip);
        let config = ScanDetectConfig::default();

        let mut ctx = test_context(&behavior, &config);
        ctx.geo_info = Some(GeoInfo {
            country_code: Some("CN".to_string()),
            ..Default::default()
        });

        let rule = HighRiskCountryRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
        assert!(result.unwrap().tags.contains(&"high-risk-country".to_string()));
    }

    #[test]
    fn test_datacenter_ip_rule() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let behavior = SourceBehavior::new(ip);
        let config = ScanDetectConfig::default();

        let mut ctx = test_context(&behavior, &config);
        ctx.geo_info = Some(GeoInfo {
            asn: Some(16509), // Amazon
            ..Default::default()
        });

        let rule = DatacenterIpRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
    }

    #[test]
    fn test_tor_exit_rule() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let behavior = SourceBehavior::new(ip);
        let config = ScanDetectConfig::default();

        let mut ctx = test_context(&behavior, &config);
        ctx.geo_info = Some(GeoInfo {
            is_tor_exit: true,
            ..Default::default()
        });

        let rule = TorExitRule;
        let result = rule.evaluate(&ctx);
        assert!(result.is_some());
        assert!(result.unwrap().tags.contains(&"tor".to_string()));
    }
}
