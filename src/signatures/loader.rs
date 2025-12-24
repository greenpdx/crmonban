//! Rule file loading and management
//!
//! Supports loading rules from:
//! - Local files
//! - Directories (recursive)
//! - URLs (for rule updates)
//! - Suricata-update style rule sources

use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use tracing::{error, info, warn};

use super::ast::Rule;
use super::parser::{apply_content_modifiers, parse_rule, ParseError};
use super::{RuleStats, SignatureConfig};

/// Rule source type
#[derive(Debug, Clone)]
pub enum RuleSource {
    /// Local file path
    File(PathBuf),
    /// Directory containing .rules files
    Directory(PathBuf),
    /// Remote URL
    Url(String),
    /// Inline rule string
    Inline(String),
}

/// Loaded rule set
#[derive(Debug, Clone)]
pub struct RuleSet {
    /// Rules by SID
    pub rules: HashMap<u32, Rule>,
    /// Statistics
    pub stats: RuleStats,
    /// Parse errors
    pub errors: Vec<(String, ParseError)>,
    /// Source files loaded
    pub sources: Vec<String>,
}

impl Default for RuleSet {
    fn default() -> Self {
        Self {
            rules: HashMap::new(),
            stats: RuleStats::default(),
            errors: Vec::new(),
            sources: Vec::new(),
        }
    }
}

impl RuleSet {
    /// Add a rule to the set
    pub fn add_rule(&mut self, mut rule: Rule) {
        // Apply content modifiers
        rule = apply_content_modifiers(rule);

        // Generate ID if not set
        if rule.id == 0 {
            rule.id = rule.sid;
        }

        self.stats.add_rule(&rule);
        self.rules.insert(rule.sid, rule);
    }

    /// Merge another rule set into this one
    pub fn merge(&mut self, other: RuleSet) {
        for (sid, rule) in other.rules {
            self.rules.insert(sid, rule);
        }
        self.errors.extend(other.errors);
        self.sources.extend(other.sources);

        // Recalculate stats
        self.stats = RuleStats::default();
        for rule in self.rules.values() {
            self.stats.add_rule(rule);
        }
    }

    /// Get enabled rules
    pub fn enabled_rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.values().filter(|r| r.enabled)
    }

    /// Get rule by SID
    pub fn get(&self, sid: u32) -> Option<&Rule> {
        self.rules.get(&sid)
    }

    /// Get mutable rule by SID
    pub fn get_mut(&mut self, sid: u32) -> Option<&mut Rule> {
        self.rules.get_mut(&sid)
    }

    /// Disable rule by SID
    pub fn disable(&mut self, sid: u32) {
        if let Some(rule) = self.rules.get_mut(&sid) {
            rule.enabled = false;
        }
    }

    /// Enable rule by SID
    pub fn enable(&mut self, sid: u32) {
        if let Some(rule) = self.rules.get_mut(&sid) {
            rule.enabled = true;
        }
    }
}

/// Rule loader
pub struct RuleLoader {
    /// Configuration
    config: SignatureConfig,
    /// Variable substitution map
    variables: HashMap<String, String>,
    /// Disabled SIDs (from disable.conf)
    disabled_sids: Vec<u32>,
    /// Enabled SIDs (from enable.conf)
    enabled_sids: Vec<u32>,
    /// SID modifications
    #[allow(dead_code)]
    sid_modifications: HashMap<u32, Vec<String>>,
    /// Classification priorities (classtype -> priority)
    classifications: HashMap<String, ClassificationInfo>,
}

impl RuleLoader {
    /// Create new rule loader
    pub fn new(config: SignatureConfig) -> Self {
        Self {
            variables: config.variables.clone(),
            config,
            disabled_sids: Vec::new(),
            enabled_sids: Vec::new(),
            sid_modifications: HashMap::new(),
            classifications: HashMap::new(),
        }
    }

    /// Load classification.config and store classifications
    pub fn load_classifications(&mut self, path: &Path) -> Result<(), std::io::Error> {
        self.classifications = self.load_classification_config(path)?;
        Ok(())
    }

    /// Get priority for a classtype
    pub fn get_priority_for_classtype(&self, classtype: &str) -> u8 {
        self.classifications
            .get(classtype)
            .map(|c| c.priority)
            .unwrap_or(3)
    }

    /// Check if a rule should be included based on layer/classtype filters
    /// Returns true if rule should be loaded, false if it should be skipped
    fn should_include_rule(&self, rule: &Rule) -> bool {
        // Check protocol exclusions
        if !self.config.excluded_protocols.is_empty() {
            let proto_str = rule.protocol.to_string();
            if self.config.excluded_protocols.iter().any(|p| p.eq_ignore_ascii_case(&proto_str)) {
                return false;
            }
        }

        // Check classtype exclusions
        if let Some(ref classtype) = rule.classtype {
            if self.config.excluded_classtypes.iter().any(|c| c.eq_ignore_ascii_case(classtype)) {
                return false;
            }
        }

        // Check classtype inclusions (if specified, only allow these)
        if !self.config.included_classtypes.is_empty() {
            if let Some(ref classtype) = rule.classtype {
                if !self.config.included_classtypes.iter().any(|c| c.eq_ignore_ascii_case(classtype)) {
                    return false;
                }
            } else {
                // No classtype and we have inclusion list - skip
                return false;
            }
        }

        true
    }

    /// Load all configured rules
    pub fn load_all(&mut self) -> Result<RuleSet, std::io::Error> {
        let mut ruleset = RuleSet::default();

        // Load from configured files
        for file in &self.config.rule_files.clone() {
            match self.load_file(file) {
                Ok(rules) => ruleset.merge(rules),
                Err(e) => {
                    error!("Failed to load rule file {:?}: {}", file, e);
                }
            }
        }

        // Load from configured directories
        for dir in &self.config.rule_dirs.clone() {
            match self.load_directory(dir) {
                Ok(rules) => ruleset.merge(rules),
                Err(e) => {
                    error!("Failed to load rule directory {:?}: {}", dir, e);
                }
            }
        }

        // Apply enable/disable lists
        self.apply_sid_lists(&mut ruleset);

        Ok(ruleset)
    }

    /// Load rules from a single file
    pub fn load_file(&self, path: &Path) -> Result<RuleSet, std::io::Error> {
        let mut ruleset = RuleSet::default();

        let file = fs::File::open(path)?;
        let reader = BufReader::new(file);
        let file_path = path.to_string_lossy().to_string();

        ruleset.sources.push(file_path.clone());

        let mut line_num = 0;
        let mut continued_line = String::new();

        for line in reader.lines() {
            line_num += 1;
            let line = line?;
            let trimmed = line.trim();

            // Handle line continuation
            if trimmed.ends_with('\\') {
                continued_line.push_str(&trimmed[..trimmed.len() - 1]);
                continue;
            }

            let full_line = if continued_line.is_empty() {
                trimmed.to_string()
            } else {
                continued_line.push_str(trimmed);
                std::mem::take(&mut continued_line)
            };

            // Skip empty lines and comments
            if full_line.is_empty() || full_line.starts_with('#') {
                continue;
            }

            // Check for disabled rule (starts with #)
            let (enabled, rule_text) = if full_line.starts_with("# alert")
                || full_line.starts_with("# drop")
                || full_line.starts_with("# reject")
                || full_line.starts_with("# pass")
                || full_line.starts_with("# log")
            {
                (false, &full_line[2..])
            } else {
                (true, full_line.as_str())
            };

            // Substitute variables
            let rule_text = self.substitute_variables(rule_text);

            // Parse rule
            match parse_rule(&rule_text) {
                Ok(mut rule) => {
                    rule.enabled = enabled;
                    rule.source_file = Some(file_path.clone());
                    rule.source_line = Some(line_num);
                    // Apply classification-based priority if rule doesn't have explicit priority
                    // and has a classtype
                    if rule.priority == 3 {
                        if let Some(ref classtype) = rule.classtype {
                            rule.priority = self.get_priority_for_classtype(classtype);
                        }
                    }

                    // Check layer/classtype filters
                    if self.should_include_rule(&rule) {
                        ruleset.add_rule(rule);
                    }
                }
                Err(mut e) => {
                    e.line = Some(line_num);
                    ruleset.errors.push((file_path.clone(), e));
                    ruleset.stats.parse_errors += 1;
                }
            }
        }

        info!(
            "Loaded {} rules from {} ({} errors)",
            ruleset.rules.len(),
            path.display(),
            ruleset.errors.len()
        );

        Ok(ruleset)
    }

    /// Load rules from a directory
    pub fn load_directory(&self, dir: &Path) -> Result<RuleSet, std::io::Error> {
        let mut ruleset = RuleSet::default();

        if !dir.exists() {
            warn!("Rule directory does not exist: {:?}", dir);
            return Ok(ruleset);
        }

        // Find all .rules files
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "rules" {
                        match self.load_file(&path) {
                            Ok(rules) => ruleset.merge(rules),
                            Err(e) => {
                                error!("Failed to load {:?}: {}", path, e);
                            }
                        }
                    }
                }
            } else if path.is_dir() {
                // Recursive directory loading
                match self.load_directory(&path) {
                    Ok(rules) => ruleset.merge(rules),
                    Err(e) => {
                        error!("Failed to load directory {:?}: {}", path, e);
                    }
                }
            }
        }

        Ok(ruleset)
    }

    /// Load rules from URL (async)
    pub async fn load_url(&self, url: &str) -> Result<RuleSet, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();
        let response = client.get(url).send().await?;
        let text = response.text().await?;

        let mut ruleset = RuleSet::default();
        ruleset.sources.push(url.to_string());

        for (line_num, line) in text.lines().enumerate() {
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let rule_text = self.substitute_variables(trimmed);

            match parse_rule(&rule_text) {
                Ok(mut rule) => {
                    rule.source_file = Some(url.to_string());
                    rule.source_line = Some(line_num as u32 + 1);
                    ruleset.add_rule(rule);
                }
                Err(mut e) => {
                    e.line = Some(line_num as u32 + 1);
                    ruleset.errors.push((url.to_string(), e));
                    ruleset.stats.parse_errors += 1;
                }
            }
        }

        info!("Loaded {} rules from URL: {}", ruleset.rules.len(), url);

        Ok(ruleset)
    }

    /// Parse rules from inline string
    pub fn load_inline(&self, rules_text: &str, source_name: &str) -> RuleSet {
        let mut ruleset = RuleSet::default();
        ruleset.sources.push(source_name.to_string());

        for (line_num, line) in rules_text.lines().enumerate() {
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let rule_text = self.substitute_variables(trimmed);

            match parse_rule(&rule_text) {
                Ok(mut rule) => {
                    rule.source_file = Some(source_name.to_string());
                    rule.source_line = Some(line_num as u32 + 1);
                    ruleset.add_rule(rule);
                }
                Err(mut e) => {
                    e.line = Some(line_num as u32 + 1);
                    ruleset.errors.push((source_name.to_string(), e));
                    ruleset.stats.parse_errors += 1;
                }
            }
        }

        ruleset
    }

    /// Substitute variables in rule text
    fn substitute_variables(&self, text: &str) -> String {
        let mut result = text.to_string();

        for (name, value) in &self.variables {
            let var_pattern = format!("${}", name);
            result = result.replace(&var_pattern, value);
        }

        result
    }

    /// Load disable.conf file
    pub fn load_disable_conf(&mut self, path: &Path) -> Result<(), std::io::Error> {
        if !path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(path)?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Parse SID or SID range
            if let Ok(sid) = trimmed.parse::<u32>() {
                self.disabled_sids.push(sid);
            } else if trimmed.contains(':') {
                let parts: Vec<&str> = trimmed.split(':').collect();
                if parts.len() == 2 {
                    if let (Ok(start), Ok(end)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                        for sid in start..=end {
                            self.disabled_sids.push(sid);
                        }
                    }
                }
            }
        }

        info!("Loaded {} disabled SIDs from {:?}", self.disabled_sids.len(), path);
        Ok(())
    }

    /// Load enable.conf file
    pub fn load_enable_conf(&mut self, path: &Path) -> Result<(), std::io::Error> {
        if !path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(path)?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Ok(sid) = trimmed.parse::<u32>() {
                self.enabled_sids.push(sid);
            }
        }

        info!("Loaded {} enabled SIDs from {:?}", self.enabled_sids.len(), path);
        Ok(())
    }

    /// Apply SID enable/disable lists to ruleset
    fn apply_sid_lists(&self, ruleset: &mut RuleSet) {
        // Apply disables
        for sid in &self.disabled_sids {
            ruleset.disable(*sid);
        }

        // Apply enables (overrides disables)
        for sid in &self.enabled_sids {
            ruleset.enable(*sid);
        }
    }

    /// Set a variable value
    pub fn set_variable(&mut self, name: &str, value: &str) {
        self.variables.insert(name.to_string(), value.to_string());
    }

    /// Get variable value
    pub fn get_variable(&self, name: &str) -> Option<&String> {
        self.variables.get(name)
    }

    /// Load classification.config file
    pub fn load_classification_config(&self, path: &Path) -> Result<HashMap<String, ClassificationInfo>, std::io::Error> {
        let mut classifications = HashMap::new();

        if !path.exists() {
            return Ok(classifications);
        }

        let content = fs::read_to_string(path)?;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Format: config classification: name, description, priority
            if trimmed.starts_with("config classification:") {
                let rest = &trimmed[22..].trim();
                let parts: Vec<&str> = rest.splitn(3, ',').collect();
                if parts.len() >= 3 {
                    let name = parts[0].trim().to_string();
                    let description = parts[1].trim().to_string();
                    let priority: u8 = parts[2].trim().parse().unwrap_or(3);

                    classifications.insert(name.clone(), ClassificationInfo {
                        name,
                        description,
                        priority,
                    });
                }
            }
        }

        info!("Loaded {} classifications from {:?}", classifications.len(), path);
        Ok(classifications)
    }
}

/// Classification information
#[derive(Debug, Clone)]
pub struct ClassificationInfo {
    pub name: String,
    pub description: String,
    pub priority: u8,
}

/// Rule update source configuration
#[derive(Debug, Clone)]
pub struct RuleUpdateSource {
    /// Source name
    pub name: String,
    /// URL template
    pub url: String,
    /// Requires subscription/key
    pub requires_auth: bool,
    /// License type
    pub license: String,
}

/// Known rule sources
pub fn known_rule_sources() -> Vec<RuleUpdateSource> {
    vec![
        RuleUpdateSource {
            name: "et/open".to_string(),
            url: "https://rules.emergingthreats.net/open/suricata-%VERSION%/emerging.rules.tar.gz".to_string(),
            requires_auth: false,
            license: "BSD".to_string(),
        },
        RuleUpdateSource {
            name: "et/pro".to_string(),
            url: "https://rules.emergingthreatspro.com/%OINKCODE%/suricata-%VERSION%/etpro.rules.tar.gz".to_string(),
            requires_auth: true,
            license: "Commercial".to_string(),
        },
        RuleUpdateSource {
            name: "oisf/trafficid".to_string(),
            url: "https://openinfosecfoundation.org/rules/trafficid/trafficid.rules".to_string(),
            requires_auth: false,
            license: "MIT".to_string(),
        },
        RuleUpdateSource {
            name: "ptresearch/attackdetection".to_string(),
            url: "https://raw.githubusercontent.com/ptresearch/AttackDetection/master/pt.rules.tar.gz".to_string(),
            requires_auth: false,
            license: "Custom".to_string(),
        },
        RuleUpdateSource {
            name: "sslbl/ssl-fp-blacklist".to_string(),
            url: "https://sslbl.abuse.ch/blacklist/sslblacklist.rules".to_string(),
            requires_auth: false,
            license: "Non-Commercial".to_string(),
        },
        RuleUpdateSource {
            name: "sslbl/ja3-fingerprints".to_string(),
            url: "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules".to_string(),
            requires_auth: false,
            license: "Non-Commercial".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variable_substitution() {
        let config = SignatureConfig::default();
        let loader = RuleLoader::new(config);

        let text = "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS";
        let result = loader.substitute_variables(text);

        assert!(!result.contains("$HOME_NET"));
        assert!(!result.contains("$EXTERNAL_NET"));
    }

    #[test]
    fn test_load_inline() {
        let config = SignatureConfig::default();
        let loader = RuleLoader::new(config);

        let rules_text = r#"
alert tcp any any -> any 80 (msg:"Test HTTP"; sid:1000001; rev:1;)
alert tcp any any -> any 443 (msg:"Test HTTPS"; sid:1000002; rev:1;)
        "#;

        let ruleset = loader.load_inline(rules_text, "test");

        assert_eq!(ruleset.rules.len(), 2);
        assert!(ruleset.get(1000001).is_some());
        assert!(ruleset.get(1000002).is_some());
    }

    #[test]
    fn test_ruleset_enable_disable() {
        let config = SignatureConfig::default();
        let loader = RuleLoader::new(config);

        let rules_text = r#"
alert tcp any any -> any 80 (msg:"Test"; sid:1000001; rev:1;)
        "#;

        let mut ruleset = loader.load_inline(rules_text, "test");

        assert!(ruleset.get(1000001).unwrap().enabled);

        ruleset.disable(1000001);
        assert!(!ruleset.get(1000001).unwrap().enabled);

        ruleset.enable(1000001);
        assert!(ruleset.get(1000001).unwrap().enabled);
    }
}
