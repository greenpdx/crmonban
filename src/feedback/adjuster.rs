//! Parameter adjuster for automatic detection tuning
//!
//! Generates and applies configuration changes based on feedback analysis results.
//! Enforces safe bounds to prevent overly aggressive adjustments.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use super::analyzer::{ModuleStats, SafeBounds};

/// Configuration for the parameter adjuster
#[derive(Debug, Clone)]
pub struct AdjusterConfig {
    /// Safe bounds for adjustments
    pub safe_bounds: SafeBounds,
    /// Adjustment strategy
    pub strategy: AdjustmentStrategy,
    /// Dry run mode (don't actually apply changes)
    pub dry_run: bool,
}

impl Default for AdjusterConfig {
    fn default() -> Self {
        Self {
            safe_bounds: SafeBounds::default(),
            strategy: AdjustmentStrategy::Conservative,
            dry_run: true,
        }
    }
}

/// Adjustment strategy determining how aggressive changes are
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdjustmentStrategy {
    /// Small adjustments (5-10%)
    Conservative,
    /// Medium adjustments (10-20%)
    Moderate,
    /// Large adjustments (up to 30%)
    Aggressive,
}

impl AdjustmentStrategy {
    /// Get the maximum adjustment factor for this strategy
    pub fn max_adjustment(&self) -> f32 {
        match self {
            AdjustmentStrategy::Conservative => 0.10,
            AdjustmentStrategy::Moderate => 0.20,
            AdjustmentStrategy::Aggressive => 0.30,
        }
    }

    /// Get the base adjustment step
    pub fn base_step(&self) -> f32 {
        match self {
            AdjustmentStrategy::Conservative => 0.02,
            AdjustmentStrategy::Moderate => 0.05,
            AdjustmentStrategy::Aggressive => 0.10,
        }
    }
}

impl std::fmt::Display for AdjustmentStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdjustmentStrategy::Conservative => write!(f, "conservative"),
            AdjustmentStrategy::Moderate => write!(f, "moderate"),
            AdjustmentStrategy::Aggressive => write!(f, "aggressive"),
        }
    }
}

/// Direction of adjustment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdjustmentDirection {
    /// Increase the threshold/value
    Increase,
    /// Decrease the threshold/value
    Decrease,
}

impl std::fmt::Display for AdjustmentDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdjustmentDirection::Increase => write!(f, "increase"),
            AdjustmentDirection::Decrease => write!(f, "decrease"),
        }
    }
}

/// A configuration change to apply
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChange {
    /// Config path (e.g., "layer234.brute_force.auth_port_threshold")
    pub path: String,
    /// Direction of change
    pub direction: AdjustmentDirection,
    /// Amount of change (absolute or percentage depending on context)
    pub amount: f32,
    /// Current value
    pub current_value: f32,
    /// New value after adjustment
    pub new_value: f32,
    /// Reason for the change
    pub reason: String,
    /// Was this change applied?
    pub applied: bool,
}

impl ConfigChange {
    /// Format as human-readable string
    pub fn to_string_pretty(&self) -> String {
        format!(
            "{}: {:.3} → {:.3} ({} by {:.1}%) - {}",
            self.path,
            self.current_value,
            self.new_value,
            self.direction,
            self.amount * 100.0,
            self.reason
        )
    }
}

/// Parameter adjuster for automatic tuning
pub struct ParameterAdjuster {
    config: AdjusterConfig,
}

impl ParameterAdjuster {
    /// Create a new parameter adjuster with default config
    pub fn new() -> Self {
        Self {
            config: AdjusterConfig::default(),
        }
    }

    /// Create with custom config
    pub fn with_config(config: AdjusterConfig) -> Self {
        Self { config }
    }

    /// Set the adjustment strategy
    pub fn with_strategy(mut self, strategy: AdjustmentStrategy) -> Self {
        self.config.strategy = strategy;
        self
    }

    /// Set dry run mode
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.config.dry_run = dry_run;
        self
    }

    /// Generate recommended changes based on module stats
    pub fn recommend(&self, per_module: &HashMap<String, ModuleStats>) -> Vec<ConfigChange> {
        let mut changes = Vec::new();

        for (module, stats) in per_module {
            match module.as_str() {
                "layer234" => changes.extend(self.recommend_layer234(stats)),
                "http_detect" => changes.extend(self.recommend_http_detect(stats)),
                "signatures" => changes.extend(self.recommend_signatures(stats)),
                _ => {}
            }
        }

        changes
    }

    /// Generate layer234 recommendations
    fn recommend_layer234(&self, stats: &ModuleStats) -> Vec<ConfigChange> {
        let mut changes = Vec::new();
        let step = self.config.strategy.base_step();

        // High FP rate → increase thresholds
        if stats.fp_rate > 0.05 {
            let severity = if stats.fp_rate > 0.10 { 2.0 } else { 1.0 };
            let adjustment = (step * severity).min(self.config.strategy.max_adjustment());

            // Check which type of FP is dominant
            let has_brute_force_fp = stats
                .top_fp_patterns
                .iter()
                .any(|(p, _)| p.to_lowercase().contains("brute"));
            let has_scan_fp = stats
                .top_fp_patterns
                .iter()
                .any(|(p, _)| p.to_lowercase().contains("scan"));

            if has_brute_force_fp {
                changes.push(self.create_change(
                    "layer234.brute_force.auth_port_threshold",
                    AdjustmentDirection::Increase,
                    adjustment,
                    0.50, // Default value
                    &format!("FP rate {:.1}% for brute force", stats.fp_rate * 100.0),
                ));
            }

            if has_scan_fp {
                changes.push(self.create_change(
                    "layer234.scan.signature_threshold",
                    AdjustmentDirection::Increase,
                    adjustment,
                    0.85, // Default value
                    &format!("FP rate {:.1}% for scan detection", stats.fp_rate * 100.0),
                ));
            }
        }

        // High FN rate → decrease thresholds
        if stats.fn_rate > 0.10 {
            let severity = if stats.fn_rate > 0.20 { 2.0 } else { 1.0 };
            let adjustment = (step * severity).min(self.config.strategy.max_adjustment());

            // Check which attacks are being missed
            let missing_brute_force = stats
                .missed_attacks
                .iter()
                .any(|(a, _)| a.to_lowercase().contains("brute"));
            let missing_scan = stats
                .missed_attacks
                .iter()
                .any(|(a, _)| a.to_lowercase().contains("scan"));

            if missing_brute_force {
                changes.push(self.create_change(
                    "layer234.brute_force.auth_port_threshold",
                    AdjustmentDirection::Decrease,
                    adjustment,
                    0.50,
                    &format!("FN rate {:.1}% - missing brute force attacks", stats.fn_rate * 100.0),
                ));
            }

            if missing_scan {
                changes.push(self.create_change(
                    "layer234.scan.signature_threshold",
                    AdjustmentDirection::Decrease,
                    adjustment,
                    0.85,
                    &format!("FN rate {:.1}% - missing scan attacks", stats.fn_rate * 100.0),
                ));
            }
        }

        changes
    }

    /// Generate http_detect recommendations
    fn recommend_http_detect(&self, stats: &ModuleStats) -> Vec<ConfigChange> {
        let mut changes = Vec::new();
        let step = self.config.strategy.base_step();

        // High FP rate
        if stats.fp_rate > 0.05 {
            let adjustment = step.min(self.config.strategy.max_adjustment());

            // Recommend reducing sensitivity for noisy patterns
            for (pattern, count) in stats.top_fp_patterns.iter().take(3) {
                if *count > 10 {
                    changes.push(ConfigChange {
                        path: format!("http_detect.patterns.{}.enabled", pattern.to_lowercase().replace(' ', "_")),
                        direction: AdjustmentDirection::Decrease,
                        amount: adjustment,
                        current_value: 1.0,
                        new_value: 0.0,
                        reason: format!("Pattern '{}' caused {} false positives", pattern, count),
                        applied: false,
                    });
                }
            }
        }

        // High FN rate - recommend enabling more patterns
        if stats.fn_rate > 0.10 {
            for (attack_type, count) in stats.missed_attacks.iter().take(3) {
                if *count > 5 {
                    changes.push(ConfigChange {
                        path: format!("http_detect.patterns.{}", attack_type.to_lowercase().replace(' ', "_")),
                        direction: AdjustmentDirection::Increase,
                        amount: step,
                        current_value: 0.0,
                        new_value: 1.0,
                        reason: format!("Missed {} {} attacks", count, attack_type),
                        applied: false,
                    });
                }
            }
        }

        changes
    }

    /// Generate signatures recommendations
    fn recommend_signatures(&self, stats: &ModuleStats) -> Vec<ConfigChange> {
        let mut changes = Vec::new();

        // If missing many attacks, recommend reviewing excluded classtypes
        if stats.fn_rate > 0.15 {
            let missed_total: u64 = stats.missed_attacks.iter().map(|(_, c)| c).sum();

            if missed_total > 50 {
                changes.push(ConfigChange {
                    path: "signatures.excluded_classtypes".to_string(),
                    direction: AdjustmentDirection::Decrease,
                    amount: 0.0, // Not a numeric adjustment
                    current_value: 0.0,
                    new_value: 0.0,
                    reason: format!(
                        "Missing {} attacks - review excluded classtypes",
                        missed_total
                    ),
                    applied: false,
                });
            }
        }

        // If high FP rate, recommend adding exclusions
        if stats.fp_rate > 0.10 {
            for (pattern, count) in stats.top_fp_patterns.iter().take(2) {
                changes.push(ConfigChange {
                    path: "signatures.excluded_classtypes".to_string(),
                    direction: AdjustmentDirection::Increase,
                    amount: 0.0,
                    current_value: 0.0,
                    new_value: 0.0,
                    reason: format!(
                        "Consider excluding '{}' ({} false positives)",
                        pattern, count
                    ),
                    applied: false,
                });
            }
        }

        changes
    }

    /// Create a configuration change with safe bounds enforcement
    fn create_change(
        &self,
        path: &str,
        direction: AdjustmentDirection,
        amount: f32,
        current_value: f32,
        reason: &str,
    ) -> ConfigChange {
        let bounds = &self.config.safe_bounds;

        // Calculate new value
        let raw_new_value = match direction {
            AdjustmentDirection::Increase => current_value + (current_value * amount),
            AdjustmentDirection::Decrease => current_value - (current_value * amount),
        };

        // Enforce safe bounds
        let new_value = raw_new_value
            .max(bounds.min_threshold)
            .min(bounds.max_threshold);

        // Check if adjustment exceeds max allowed
        let actual_change = (new_value - current_value).abs() / current_value;
        let clamped = actual_change > bounds.max_adjustment_pct;

        ConfigChange {
            path: path.to_string(),
            direction,
            amount: if clamped { bounds.max_adjustment_pct } else { amount },
            current_value,
            new_value,
            reason: if clamped {
                format!("{} (clamped to safe bounds)", reason)
            } else {
                reason.to_string()
            },
            applied: false,
        }
    }

    /// Apply changes to a TOML config file
    ///
    /// Note: This uses simple regex-based replacement. For complex changes,
    /// consider using `toml_edit` crate for proper TOML manipulation.
    pub fn apply_to_file(&self, changes: &mut [ConfigChange], config_path: &Path) -> anyhow::Result<()> {
        if self.config.dry_run {
            info!("Dry run mode - changes not applied");
            return Ok(());
        }

        // Read existing config
        let mut content = fs::read_to_string(config_path)?;

        for change in changes.iter_mut() {
            match self.apply_single_change(&mut content, change) {
                Ok(true) => {
                    change.applied = true;
                    info!("Applied: {}", change.to_string_pretty());
                }
                Ok(false) => {
                    warn!("Could not find setting to modify: {}", change.path);
                }
                Err(e) => {
                    warn!("Failed to apply {}: {}", change.path, e);
                }
            }
        }

        // Write back
        fs::write(config_path, content)?;

        Ok(())
    }

    /// Apply a single change using regex replacement
    fn apply_single_change(
        &self,
        content: &mut String,
        change: &ConfigChange,
    ) -> anyhow::Result<bool> {
        use regex::Regex;

        // Extract the setting name from the path (last component)
        let parts: Vec<&str> = change.path.split('.').collect();
        let setting_name = parts.last().ok_or_else(|| anyhow::anyhow!("Invalid path"))?;

        // Build a regex to find the setting
        // Match patterns like: setting_name = 0.50  or  setting_name = 0.5
        let pattern = format!(r"(?m)^(\s*{}\s*=\s*)[\d.]+", regex::escape(setting_name));
        let re = Regex::new(&pattern)?;

        if re.is_match(content) {
            let replacement = format!("${{1}}{:.3}", change.new_value);
            *content = re.replace(content, replacement.as_str()).to_string();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Generate a summary of proposed changes
    pub fn summarize_changes(changes: &[ConfigChange]) -> String {
        use std::fmt::Write;
        let mut out = String::new();

        if changes.is_empty() {
            return "No changes recommended.".to_string();
        }

        writeln!(out, "Proposed Changes ({}):", changes.len()).unwrap();
        writeln!(out, "─────────────────────────────────────────────").unwrap();

        for change in changes {
            let status = if change.applied { "✓" } else { "○" };
            writeln!(out, "{} {}", status, change.to_string_pretty()).unwrap();
        }

        out
    }
}

impl Default for ParameterAdjuster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_stats(fp_rate: f64, fn_rate: f64) -> ModuleStats {
        ModuleStats {
            module: "test".to_string(),
            true_positives: 90,
            false_positives: (100.0 * fp_rate) as u64,
            false_negatives: (100.0 * fn_rate) as u64,
            fp_rate,
            fn_rate,
            top_fp_patterns: vec![("brute_force".to_string(), 50)],
            missed_attacks: vec![("scan".to_string(), 30)],
        }
    }

    #[test]
    fn test_conservative_adjustment() {
        let adjuster = ParameterAdjuster::new()
            .with_strategy(AdjustmentStrategy::Conservative);

        let change = adjuster.create_change(
            "test.threshold",
            AdjustmentDirection::Increase,
            0.05,
            0.50,
            "test",
        );

        assert!(change.new_value > change.current_value);
        assert!(change.new_value <= 0.95); // Max threshold
    }

    #[test]
    fn test_safe_bounds_min() {
        let adjuster = ParameterAdjuster::new();

        let change = adjuster.create_change(
            "test.threshold",
            AdjustmentDirection::Decrease,
            0.90, // Try to decrease by 90%
            0.50,
            "test",
        );

        // Should be clamped to min_threshold (0.3)
        assert!(change.new_value >= 0.3);
    }

    #[test]
    fn test_safe_bounds_max() {
        let adjuster = ParameterAdjuster::new();

        let change = adjuster.create_change(
            "test.threshold",
            AdjustmentDirection::Increase,
            0.90, // Try to increase by 90%
            0.90,
            "test",
        );

        // Should be clamped to max_threshold (0.95)
        assert!(change.new_value <= 0.95);
    }

    #[test]
    fn test_layer234_high_fp() {
        let adjuster = ParameterAdjuster::new();

        let mut stats_map = HashMap::new();
        stats_map.insert("layer234".to_string(), make_stats(0.15, 0.05));

        let changes = adjuster.recommend(&stats_map);

        // Should recommend increasing thresholds
        assert!(!changes.is_empty());
        assert!(changes.iter().any(|c| c.direction == AdjustmentDirection::Increase));
    }

    #[test]
    fn test_layer234_high_fn() {
        let adjuster = ParameterAdjuster::new();

        let mut stats = make_stats(0.02, 0.25);
        stats.missed_attacks = vec![("brute_force".to_string(), 50)];

        let mut stats_map = HashMap::new();
        stats_map.insert("layer234".to_string(), stats);

        let changes = adjuster.recommend(&stats_map);

        // Should recommend decreasing thresholds
        assert!(!changes.is_empty());
        assert!(changes.iter().any(|c| c.direction == AdjustmentDirection::Decrease));
    }

    #[test]
    fn test_change_summary() {
        let changes = vec![
            ConfigChange {
                path: "test.threshold".to_string(),
                direction: AdjustmentDirection::Increase,
                amount: 0.05,
                current_value: 0.50,
                new_value: 0.525,
                reason: "High FP rate".to_string(),
                applied: true,
            },
        ];

        let summary = ParameterAdjuster::summarize_changes(&changes);
        assert!(summary.contains("test.threshold"));
        assert!(summary.contains("✓"));
    }
}
