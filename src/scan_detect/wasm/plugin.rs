//! WASM Plugin loading and execution
//!
//! This module provides the ability to load and execute WASM plugins
//! for custom detection rules. Requires the `wasm` feature to be enabled.

use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::types::{PacketInfo, BehaviorInfo, WasmRuleResult};

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
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            ..Default::default()
        }
    }

    pub fn with_id(mut self, id: &str) -> Self {
        self.id = Some(id.to_string());
        self
    }

    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
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
    // Note: Actual wasmtime runtime would be here with `wasm` feature
    // For now this is a stub structure
}

impl WasmPlugin {
    /// Load a WASM plugin from configuration
    ///
    /// Note: Full implementation requires wasmtime crate.
    /// This is a stub that shows the interface.
    pub fn load(_config: PluginConfig) -> Result<Self, PluginError> {
        // Stub implementation - real version would use wasmtime
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

    /// Evaluate the plugin with given context
    ///
    /// Note: Full implementation requires wasmtime crate.
    pub fn evaluate(
        &self,
        _packet: &PacketInfo,
        _behavior: &BehaviorInfo,
    ) -> Result<Option<WasmRuleResult>, PluginError> {
        // Stub implementation
        Ok(None)
    }
}

/// Trait for implementing custom WASM-like plugins in pure Rust
/// This allows testing the plugin interface without actual WASM
pub trait RustPlugin: Send + Sync {
    /// Plugin rule ID
    fn rule_id(&self) -> &str;
    /// Plugin rule name
    fn rule_name(&self) -> &str;
    /// Default weight
    fn default_weight(&self) -> f32;
    /// Evaluate the plugin
    fn evaluate(
        &self,
        packet: &PacketInfo,
        behavior: &BehaviorInfo,
    ) -> Option<WasmRuleResult>;
}

/// Example Rust plugin for testing
#[allow(dead_code)]
pub struct ExampleRustPlugin;

impl RustPlugin for ExampleRustPlugin {
    fn rule_id(&self) -> &str { "RUST_EXAMPLE" }
    fn rule_name(&self) -> &str { "Example Rust Plugin" }
    fn default_weight(&self) -> f32 { 1.0 }

    fn evaluate(
        &self,
        packet: &PacketInfo,
        behavior: &BehaviorInfo,
    ) -> Option<WasmRuleResult> {
        // Example: Flag sources with >100 unique ports
        if behavior.unique_ports > 100 {
            return Some(WasmRuleResult::new(
                self.rule_id(),
                2.0,
                &format!("Excessive port diversity: {} ports", behavior.unique_ports),
            ).with_tags(vec!["port-scan".into()]));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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
    fn test_rust_plugin() {
        let plugin = ExampleRustPlugin;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let packet = PacketInfo::from_ip(ip, 80);

        // With low port count
        let behavior = BehaviorInfo {
            unique_ports: 10,
            ..Default::default()
        };
        let result = plugin.evaluate(&packet, &behavior);
        assert!(result.is_none());

        // With high port count
        let behavior = BehaviorInfo {
            unique_ports: 150,
            ..Default::default()
        };
        let result = plugin.evaluate(&packet, &behavior);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.rule_id, "RUST_EXAMPLE");
    }
}
