//! Detection rules for probabilistic scan detection
//!
//! Rules are evaluated against source IP behavior and return score adjustments.

pub mod connection;
pub mod geographic;
pub mod network_health;
pub mod reputation;
pub mod stealth;
pub mod temporal;

pub use geographic::GeoInfo;
pub use network_health::NetworkHealthContext;
pub use reputation::ReputationData;

use std::net::IpAddr;
use std::time::Instant;

use super::behavior::SourceBehavior;
use super::config::ScanDetectConfig;

/// Rule categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleCategory {
    /// Connection-based rules (R1-R16)
    Connection,
    /// Geographic/ASN rules (G1-G8)
    Geographic,
    /// Time-based rules (T1-T7)
    Temporal,
    /// Protocol-specific rules (P1-P54)
    Protocol,
    /// Reputation rules (REP1-REP10)
    Reputation,
    /// Network health rules (N1-N3)
    NetworkHealth,
    /// Custom TOML rules
    Custom,
    /// WASM plugin rules
    Wasm,
}

/// Result from evaluating a rule
#[derive(Debug, Clone)]
pub struct RuleResult {
    /// Rule ID that generated this result
    pub rule_id: String,
    /// Score adjustment (positive = more suspicious, negative = less suspicious)
    pub score_delta: f32,
    /// Confidence in this result (0.0 - 1.0)
    pub confidence: f32,
    /// Evidence/reason for this result
    pub evidence: String,
    /// Tags to add to the source IP
    pub tags: Vec<String>,
}

impl RuleResult {
    pub fn new(rule_id: &str, score_delta: f32, evidence: &str) -> Self {
        Self {
            rule_id: rule_id.to_string(),
            score_delta,
            confidence: 1.0,
            evidence: evidence.to_string(),
            tags: Vec::new(),
        }
    }

    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence;
        self
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_tag(mut self, tag: &str) -> Self {
        self.tags.push(tag.to_string());
        self
    }
}

/// Context provided to rules for evaluation
pub struct EvaluationContext<'a> {
    /// Source IP being evaluated
    pub src_ip: IpAddr,
    /// Current behavior data for this IP
    pub behavior: &'a SourceBehavior,
    /// Configuration
    pub config: &'a ScanDetectConfig,
    /// Current timestamp
    pub timestamp: Instant,
    /// Current port being processed (if any)
    pub current_port: Option<u16>,
    /// Is this a SYN packet?
    pub is_syn: bool,
    /// Is this a SYN-ACK packet?
    pub is_syn_ack: bool,
    /// Is this an ACK packet?
    pub is_ack: bool,
    /// Is this a RST packet?
    pub is_rst: bool,
    /// Is this a FIN packet?
    pub is_fin: bool,
    /// Is this a PSH packet?
    pub is_psh: bool,
    /// Is this a URG packet?
    pub is_urg: bool,
    /// Packet payload size
    pub payload_size: usize,
    /// Destination port (alias for current_port for clarity)
    pub dst_port: Option<u16>,
    /// TTL value (if available)
    pub ttl: Option<u8>,
    /// TCP options (if available)
    pub tcp_options: Option<&'a [u8]>,
    /// GeoIP info for source IP
    pub geo_info: Option<GeoInfo>,
    /// GeoIP info for target/destination
    pub target_geo_info: Option<GeoInfo>,
    /// Current hour (0-23) for temporal rules
    pub current_hour: Option<u8>,
    /// Day of week (0=Sunday, 6=Saturday) for temporal rules
    pub day_of_week: Option<u8>,
    /// Reputation data for source IP
    pub reputation_data: Option<ReputationData>,
    /// Network health context for N1-N3 rules
    pub network_health: Option<NetworkHealthContext>,
}

impl<'a> EvaluationContext<'a> {
    pub fn new(
        src_ip: IpAddr,
        behavior: &'a SourceBehavior,
        config: &'a ScanDetectConfig,
    ) -> Self {
        Self {
            src_ip,
            behavior,
            config,
            timestamp: Instant::now(),
            current_port: None,
            is_syn: false,
            is_syn_ack: false,
            is_ack: false,
            is_rst: false,
            is_fin: false,
            is_psh: false,
            is_urg: false,
            payload_size: 0,
            dst_port: None,
            ttl: None,
            tcp_options: None,
            geo_info: None,
            target_geo_info: None,
            current_hour: None,
            day_of_week: None,
            reputation_data: None,
            network_health: None,
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.current_port = Some(port);
        self.dst_port = Some(port);
        self
    }

    pub fn with_syn(mut self) -> Self {
        self.is_syn = true;
        self
    }

    pub fn with_syn_ack(mut self) -> Self {
        self.is_syn_ack = true;
        self
    }

    pub fn with_ack(mut self) -> Self {
        self.is_ack = true;
        self
    }

    pub fn with_rst(mut self) -> Self {
        self.is_rst = true;
        self
    }

    pub fn with_fin(mut self) -> Self {
        self.is_fin = true;
        self
    }

    pub fn with_psh(mut self) -> Self {
        self.is_psh = true;
        self
    }

    pub fn with_urg(mut self) -> Self {
        self.is_urg = true;
        self
    }

    /// Get TCP flags as a TcpFlagSet for stealth scan detection
    pub fn tcp_flags(&self) -> Option<stealth::TcpFlagSet> {
        Some(stealth::TcpFlagSet {
            syn: self.is_syn,
            ack: self.is_ack,
            fin: self.is_fin,
            rst: self.is_rst,
            psh: self.is_psh,
            urg: self.is_urg,
        })
    }

    pub fn with_payload(mut self, size: usize) -> Self {
        self.payload_size = size;
        self
    }

    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn with_tcp_options(mut self, options: &'a [u8]) -> Self {
        self.tcp_options = Some(options);
        self
    }

    /// Check if current port is a targeted port
    pub fn is_targeted_port(&self) -> bool {
        self.current_port
            .map(|p| self.config.targeted_ports.contains(&p))
            .unwrap_or(false)
    }
}

/// Trait for detection rules
pub trait DetectionRule: Send + Sync {
    /// Unique identifier for this rule
    fn id(&self) -> &str;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Rule category
    fn category(&self) -> RuleCategory;

    /// Default weight for this rule (can be overridden in config)
    fn default_weight(&self) -> f32;

    /// Evaluate the rule against current context
    /// Returns None if rule doesn't apply, Some(RuleResult) if it does
    fn evaluate(&self, ctx: &EvaluationContext) -> Option<RuleResult>;

    /// Check if this rule is enabled
    fn is_enabled(&self, config: &ScanDetectConfig) -> bool {
        !config.is_rule_disabled(self.id())
    }
}

/// Registry of all detection rules
pub struct RuleRegistry {
    rules: Vec<Box<dyn DetectionRule>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Create registry with all built-in rules
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();

        // Add connection rules
        registry.register(Box::new(connection::HalfOpenSynRule));
        registry.register(Box::new(connection::TargetedPortRule));
        registry.register(Box::new(connection::SequentialScanRule));
        registry.register(Box::new(connection::RapidSynRateRule));
        registry.register(Box::new(connection::ClosedPortRstRule));
        registry.register(Box::new(connection::CompletedHandshakeRule));
        registry.register(Box::new(connection::DataExchangedRule));

        // Add stealth scan detection rules
        for rule in stealth::stealth_rules() {
            registry.register(rule);
        }

        registry
    }

    /// Register a new rule
    pub fn register(&mut self, rule: Box<dyn DetectionRule>) {
        self.rules.push(rule);
    }

    /// Evaluate all enabled rules
    pub fn evaluate_all(&self, ctx: &EvaluationContext) -> Vec<RuleResult> {
        self.rules
            .iter()
            .filter(|rule| rule.is_enabled(ctx.config))
            .filter_map(|rule| rule.evaluate(ctx))
            .collect()
    }

    /// Get rules by category
    pub fn get_by_category(&self, category: RuleCategory) -> Vec<&dyn DetectionRule> {
        self.rules
            .iter()
            .filter(|r| r.category() == category)
            .map(|r| r.as_ref())
            .collect()
    }

    /// Get rule by ID
    pub fn get_by_id(&self, id: &str) -> Option<&dyn DetectionRule> {
        self.rules.iter().find(|r| r.id() == id).map(|r| r.as_ref())
    }

    /// Get all rules
    pub fn all(&self) -> &[Box<dyn DetectionRule>] {
        &self.rules
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rule_result() {
        let result = RuleResult::new("R1", 1.0, "Test evidence")
            .with_confidence(0.8)
            .with_tag("test");

        assert_eq!(result.rule_id, "R1");
        assert_eq!(result.score_delta, 1.0);
        assert_eq!(result.confidence, 0.8);
        assert_eq!(result.tags, vec!["test"]);
    }

    #[test]
    fn test_registry() {
        let registry = RuleRegistry::with_builtins();
        assert!(!registry.all().is_empty());

        // Check we have connection rules
        let conn_rules = registry.get_by_category(RuleCategory::Connection);
        assert!(!conn_rules.is_empty());
    }

    #[test]
    fn test_evaluation_context() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let behavior = SourceBehavior::new(ip);
        let config = ScanDetectConfig::default();

        let ctx = EvaluationContext::new(ip, &behavior, &config)
            .with_port(22)
            .with_syn();

        assert!(ctx.is_targeted_port());
        assert!(ctx.is_syn);
        assert_eq!(ctx.current_port, Some(22));
    }
}
