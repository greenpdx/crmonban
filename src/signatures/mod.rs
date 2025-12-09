//! Signature-based detection engine
//!
//! Provides Suricata/Snort-compatible rule parsing and matching.
//!
//! # Features
//!
//! - Full Suricata rule syntax support
//! - Aho-Corasick multi-pattern pre-filtering
//! - PCRE regex matching
//! - HTTP, DNS, TLS protocol-specific keywords
//! - Flow tracking and state matching
//! - Threshold and rate limiting
//!
//! # Example
//!
//! ```ignore
//! use crmonban::signatures::{SignatureEngine, SignatureConfig};
//!
//! let config = SignatureConfig::default();
//! let mut engine = SignatureEngine::new(config)?;
//!
//! // Load rules
//! engine.load_rules_file("/etc/crmonban/rules/local.rules")?;
//!
//! // Match against packet
//! let matches = engine.match_packet(&packet_data, &flow_context)?;
//! ```

pub mod ast;
pub mod parser;
pub mod matcher;
pub mod loader;
pub mod storage;

pub use ast::*;
pub use parser::{parse_rule, apply_content_modifiers, ParseError};
pub use matcher::{
    SignatureEngine, MatchResult, PatternMatcher,
    // New API types
    FlowState, ProtocolContext, HttpContext, DnsContext, TlsContext, SshContext, SmtpContext,
    // Legacy type (kept for backward compatibility)
    PacketContext,
};
pub use loader::{RuleLoader, RuleSet, RuleSource};
pub use storage::{SignatureStorage, SignatureSet, SignatureSetMetadata, StorageStats, SIGNATURE_DATA_DIR};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Configuration for the signature engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureConfig {
    /// Enable signature engine
    pub enabled: bool,

    /// Rule file paths
    pub rule_files: Vec<PathBuf>,

    /// Rule directories to scan
    pub rule_dirs: Vec<PathBuf>,

    /// Persistent storage directory for compiled signatures
    pub storage_dir: PathBuf,

    /// Load signatures from persistent storage on startup
    pub load_from_storage: bool,

    /// Save loaded signatures to persistent storage
    pub save_to_storage: bool,

    /// Variables for rule substitution
    pub variables: HashMap<String, String>,

    /// Maximum rules to load (0 = unlimited)
    pub max_rules: usize,

    /// Enable multi-pattern pre-filtering (Aho-Corasick)
    pub prefilter_enabled: bool,

    /// Minimum pattern length for prefilter
    pub prefilter_min_length: usize,

    /// Enable PCRE matching
    pub pcre_enabled: bool,

    /// PCRE match limit
    pub pcre_match_limit: u32,

    /// Enable flow tracking for stateful rules
    pub flow_tracking: bool,

    /// Enable threshold tracking
    pub threshold_tracking: bool,

    /// Number of matcher worker threads
    pub worker_threads: usize,

    /// Rule reload on file change
    pub auto_reload: bool,

    /// Classification config file
    pub classification_file: Option<PathBuf>,

    /// Reference config file
    pub reference_config: Option<PathBuf>,

    /// Suppression rules file
    pub suppression_file: Option<PathBuf>,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rule_files: Vec::new(),
            rule_dirs: vec![PathBuf::from("/etc/crmonban/rules")],
            storage_dir: PathBuf::from(SIGNATURE_DATA_DIR),
            load_from_storage: true,
            save_to_storage: true,
            variables: default_variables(),
            max_rules: 0,
            prefilter_enabled: true,
            prefilter_min_length: 4,
            pcre_enabled: true,
            pcre_match_limit: 10000,
            flow_tracking: true,
            threshold_tracking: true,
            worker_threads: 4,
            auto_reload: true,
            classification_file: None,
            reference_config: None,
            suppression_file: None,
        }
    }
}

/// Default rule variables
fn default_variables() -> HashMap<String, String> {
    let mut vars = HashMap::new();
    vars.insert("HOME_NET".into(), "any".into());
    vars.insert("EXTERNAL_NET".into(), "any".into());
    vars.insert("HTTP_SERVERS".into(), "$HOME_NET".into());
    vars.insert("SMTP_SERVERS".into(), "$HOME_NET".into());
    vars.insert("SQL_SERVERS".into(), "$HOME_NET".into());
    vars.insert("DNS_SERVERS".into(), "$HOME_NET".into());
    vars.insert("TELNET_SERVERS".into(), "$HOME_NET".into());
    vars.insert("AIM_SERVERS".into(), "any".into());
    vars.insert("DC_SERVERS".into(), "$HOME_NET".into());
    vars.insert("DNP3_SERVER".into(), "$HOME_NET".into());
    vars.insert("DNP3_CLIENT".into(), "$HOME_NET".into());
    vars.insert("MODBUS_CLIENT".into(), "$HOME_NET".into());
    vars.insert("MODBUS_SERVER".into(), "$HOME_NET".into());
    vars.insert("ENIP_CLIENT".into(), "$HOME_NET".into());
    vars.insert("ENIP_SERVER".into(), "$HOME_NET".into());

    // Port variables
    vars.insert("HTTP_PORTS".into(), "80,81,311,383,591,593,901,1220,1414,1741,1830,2301,2381,2809,3037,3128,3702,4343,4848,5250,6988,7000,7001,7144,7145,7510,7777,7779,8000,8008,8014,8028,8080,8085,8088,8090,8118,8123,8180,8181,8243,8280,8300,8800,8888,8899,9000,9060,9080,9090,9091,9443,9999,11371,34443,34444,41080,50002,55555".into());
    vars.insert("SHELLCODE_PORTS".into(), "!80".into());
    vars.insert("ORACLE_PORTS".into(), "1521".into());
    vars.insert("SSH_PORTS".into(), "22".into());
    vars.insert("DNP3_PORTS".into(), "20000".into());
    vars.insert("MODBUS_PORTS".into(), "502".into());
    vars.insert("FILE_DATA_PORTS".into(), "$HTTP_PORTS,110,143".into());
    vars.insert("FTP_PORTS".into(), "21".into());
    vars.insert("GENEVE_PORTS".into(), "6081".into());
    vars.insert("VXLAN_PORTS".into(), "4789".into());
    vars.insert("TEREDO_PORTS".into(), "3544".into());

    vars
}

/// Statistics about loaded rules
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleStats {
    /// Total rules loaded
    pub total_rules: usize,
    /// Rules by action
    pub by_action: HashMap<String, usize>,
    /// Rules by protocol
    pub by_protocol: HashMap<String, usize>,
    /// Rules with content patterns
    pub with_content: usize,
    /// Rules with PCRE
    pub with_pcre: usize,
    /// Rules with flow keywords
    pub with_flow: usize,
    /// Disabled rules
    pub disabled: usize,
    /// Parse errors
    pub parse_errors: usize,
    /// Fast patterns extracted
    pub fast_patterns: usize,
    /// Source files
    pub source_files: Vec<String>,
}

impl RuleStats {
    pub fn add_rule(&mut self, rule: &Rule) {
        self.total_rules += 1;

        *self.by_action.entry(rule.action.to_string()).or_insert(0) += 1;
        *self.by_protocol.entry(rule.protocol.to_string()).or_insert(0) += 1;

        if rule.has_content() {
            self.with_content += 1;
        }

        if rule.options.iter().any(|o| matches!(o, RuleOption::Pcre(_))) {
            self.with_pcre += 1;
        }

        if rule.flow_flags().is_some() {
            self.with_flow += 1;
        }

        if !rule.enabled {
            self.disabled += 1;
        }

        if rule.fast_pattern().is_some() {
            self.fast_patterns += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SignatureConfig::default();
        assert!(config.enabled);
        assert!(config.prefilter_enabled);
        assert!(config.variables.contains_key("HOME_NET"));
    }

    #[test]
    fn test_rule_stats() {
        let mut stats = RuleStats::default();
        let rule = Rule::default();
        stats.add_rule(&rule);

        assert_eq!(stats.total_rules, 1);
    }
}
