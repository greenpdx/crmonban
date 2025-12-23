//! WASM Plugin loading and execution
//!
//! Provides the ability to load and execute WASM plugins for custom detection.
//! Also supports native Rust plugins via the RustPlugin trait.

use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::core::Packet;
use super::types::{StageContext, WasmResult};

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Path to the WASM file
    pub path: PathBuf,
    /// Plugin ID (optional, derived from filename if not set)
    pub id: Option<String>,
    /// Is plugin enabled?
    pub enabled: bool,
    /// Maximum execution time (milliseconds)
    pub timeout_ms: u64,
    /// Maximum memory (bytes)
    pub max_memory_bytes: u64,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::new(),
            id: None,
            enabled: true,
            timeout_ms: 100,
            max_memory_bytes: 16 * 1024 * 1024, // 16MB
        }
    }
}

impl PluginConfig {
    /// Create config for a WASM file path
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            ..Default::default()
        }
    }

    /// Set plugin ID
    pub fn with_id(mut self, id: &str) -> Self {
        self.id = Some(id.to_string());
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }

    /// Set enabled state
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// Plugin error types
#[derive(Debug)]
pub enum PluginError {
    /// Failed to load WASM file
    LoadError(String),
    /// Failed to compile WASM
    CompileError(String),
    /// Failed to instantiate WASM module
    InstantiationError(String),
    /// Execution error
    ExecutionError(String),
    /// Timeout exceeded
    Timeout,
    /// Memory limit exceeded
    MemoryExceeded,
    /// Invalid plugin interface
    InvalidInterface(String),
    /// Plugin not found
    NotFound(String),
}

impl std::fmt::Display for PluginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginError::LoadError(e) => write!(f, "Load error: {}", e),
            PluginError::CompileError(e) => write!(f, "Compile error: {}", e),
            PluginError::InstantiationError(e) => write!(f, "Instantiation error: {}", e),
            PluginError::ExecutionError(e) => write!(f, "Execution error: {}", e),
            PluginError::Timeout => write!(f, "Execution timeout"),
            PluginError::MemoryExceeded => write!(f, "Memory limit exceeded"),
            PluginError::InvalidInterface(e) => write!(f, "Invalid interface: {}", e),
            PluginError::NotFound(e) => write!(f, "Plugin not found: {}", e),
        }
    }
}

impl std::error::Error for PluginError {}

/// Loaded WASM plugin
///
/// Note: Full WASM support requires the wasmtime crate.
/// This is a stub structure that shows the interface.
#[allow(dead_code)]
pub struct WasmPlugin {
    /// Plugin ID
    id: String,
    /// Plugin config
    config: PluginConfig,
    /// When plugin was loaded
    loaded_at: Instant,
    /// When plugin was last modified (for hot-reload)
    last_modified: Option<std::time::SystemTime>,
    /// Rule ID from plugin
    rule_id: String,
    /// Rule name from plugin
    rule_name: String,
    /// Default weight from plugin
    default_weight: f32,
}

impl WasmPlugin {
    /// Load a WASM plugin from configuration
    ///
    /// Note: Full implementation requires wasmtime crate.
    /// This is a stub that shows the interface.
    pub fn load(_config: PluginConfig) -> Result<Self, PluginError> {
        Err(PluginError::LoadError(
            "WASM support requires the 'wasm' feature. Add wasmtime dependency.".into()
        ))
    }

    /// Create a mock plugin for testing
    #[cfg(test)]
    pub fn mock(id: &str, weight: f32) -> Self {
        Self {
            id: id.to_string(),
            config: PluginConfig::default(),
            loaded_at: Instant::now(),
            last_modified: None,
            rule_id: id.to_string(),
            rule_name: format!("Mock {}", id),
            default_weight: weight,
        }
    }

    /// Get plugin ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Get rule ID
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    /// Get rule name
    pub fn rule_name(&self) -> &str {
        &self.rule_name
    }

    /// Get default weight
    pub fn default_weight(&self) -> f32 {
        self.default_weight
    }

    /// Check if plugin needs reload (file changed)
    pub fn needs_reload(&self) -> bool {
        if let Ok(metadata) = std::fs::metadata(&self.config.path) {
            if let Ok(modified) = metadata.modified() {
                if let Some(last) = self.last_modified {
                    return modified > last;
                }
            }
        }
        false
    }

    /// Evaluate the plugin with packet and stage context
    ///
    /// Note: Full implementation requires wasmtime crate.
    pub fn evaluate(
        &self,
        _packet: &Packet,
        _context: &StageContext,
    ) -> Result<Option<WasmResult>, PluginError> {
        // Stub implementation
        Ok(None)
    }
}

/// Trait for implementing custom plugins in pure Rust
///
/// This allows creating detection plugins without WASM, which is useful
/// for testing and for plugins that need tight integration with the engine.
pub trait RustPlugin: Send + Sync {
    /// Plugin rule ID
    fn rule_id(&self) -> &str;

    /// Plugin rule name
    fn rule_name(&self) -> &str;

    /// Default weight for scoring
    fn default_weight(&self) -> f32;

    /// Evaluate the plugin against a packet with stage context
    fn evaluate(
        &self,
        packet: &Packet,
        context: &StageContext,
    ) -> Option<WasmResult>;
}

/// Example Rust plugin for testing - detects high port diversity
#[allow(dead_code)]
pub struct PortDiversityPlugin;

impl RustPlugin for PortDiversityPlugin {
    fn rule_id(&self) -> &str { "RUST_PORT_DIVERSITY" }
    fn rule_name(&self) -> &str { "Port Diversity Detector" }
    fn default_weight(&self) -> f32 { 1.0 }

    fn evaluate(
        &self,
        _packet: &Packet,
        context: &StageContext,
    ) -> Option<WasmResult> {
        // Check scan detection results for high port count
        if let Some(ref scan) = context.scan {
            if scan.ports_scanned > 100 {
                return Some(WasmResult::new(
                    self.rule_id(),
                    2.0,
                    &format!("Excessive port diversity: {} ports scanned", scan.ports_scanned),
                ).with_tags(vec!["port-scan".into(), "recon".into()]));
            }
        }
        None
    }
}

/// Example Rust plugin - combines multiple detection signals
#[allow(dead_code)]
pub struct MultiSignalPlugin;

impl RustPlugin for MultiSignalPlugin {
    fn rule_id(&self) -> &str { "RUST_MULTI_SIGNAL" }
    fn rule_name(&self) -> &str { "Multi-Signal Correlator" }
    fn default_weight(&self) -> f32 { 2.0 }

    fn evaluate(
        &self,
        _packet: &Packet,
        context: &StageContext,
    ) -> Option<WasmResult> {
        let mut signals = 0;
        let mut evidence = Vec::new();

        // Check for scan detection
        if context.scan.is_some() {
            signals += 1;
            evidence.push("scan_detected");
        }

        // Check for threat intel hit
        if !context.intel.is_empty() {
            signals += 1;
            evidence.push("threat_intel_match");
        }

        // Check for signature matches
        if !context.signatures.is_empty() {
            signals += 1;
            evidence.push("signature_match");
        }

        // Alert on multiple signals from same source
        if signals >= 2 {
            return Some(WasmResult::new(
                self.rule_id(),
                signals as f32 * 2.0,
                &format!("Multiple detection signals: {}", evidence.join(", ")),
            )
            .with_confidence(0.9)
            .with_tags(vec!["multi-signal".into(), "high-confidence".into()]));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::core::IpProtocol;

    fn make_test_packet() -> Packet {
        Packet::new(
            0,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpProtocol::Tcp,
            "lo",
        )
    }

    #[test]
    fn test_plugin_config() {
        let config = PluginConfig::new("/tmp/test.wasm")
            .with_id("test_plugin")
            .with_timeout(50);

        assert_eq!(config.id, Some("test_plugin".to_string()));
        assert_eq!(config.timeout_ms, 50);
        assert!(config.enabled);
    }

    #[test]
    fn test_port_diversity_plugin() {
        let plugin = PortDiversityPlugin;
        let packet = make_test_packet();

        // Without scan info - no detection
        let ctx = StageContext::new();
        let result = plugin.evaluate(&packet, &ctx);
        assert!(result.is_none());

        // With high port scan - should detect
        let ctx = StageContext::new().with_scan(super::super::types::ScanInfo {
            scan_type: "syn_scan".to_string(),
            confidence: 0.9,
            ports_scanned: 150,
            half_open: 50,
            sequential_pattern: true,
        });
        let result = plugin.evaluate(&packet, &ctx);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.plugin_id, "RUST_PORT_DIVERSITY");
        assert!(result.tags.contains(&"port-scan".to_string()));
    }

    #[test]
    fn test_multi_signal_plugin() {
        let plugin = MultiSignalPlugin;
        let packet = make_test_packet();

        // Single signal - no detection
        let ctx = StageContext::new().with_scan(super::super::types::ScanInfo {
            scan_type: "syn_scan".to_string(),
            confidence: 0.9,
            ports_scanned: 50,
            half_open: 10,
            sequential_pattern: false,
        });
        let result = plugin.evaluate(&packet, &ctx);
        assert!(result.is_none());

        // Multiple signals - should detect
        let ctx = StageContext::new()
            .with_scan(super::super::types::ScanInfo {
                scan_type: "syn_scan".to_string(),
                confidence: 0.9,
                ports_scanned: 50,
                half_open: 10,
                sequential_pattern: false,
            })
            .with_intel(vec![super::super::types::IntelInfo {
                ioc_type: "ip".to_string(),
                ioc_value: "192.168.1.100".to_string(),
                source: "test_feed".to_string(),
                category: "malware".to_string(),
                severity: "high".to_string(),
            }]);
        let result = plugin.evaluate(&packet, &ctx);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.plugin_id, "RUST_MULTI_SIGNAL");
        assert!(result.score_delta >= 4.0); // 2 signals * 2.0
    }
}
