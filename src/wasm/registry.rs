//! Plugin Registry with Hot-Reload Support
//!
//! Manages loading, registration, and hot-reloading of WASM and Rust plugins.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn, error};

use crate::core::Packet;
use super::plugin::{WasmPlugin, PluginConfig, PluginError, RustPlugin};
use super::types::{StageContext, WasmResult};

/// Plugin registry that manages loading and hot-reloading of plugins
pub struct PluginRegistry {
    /// Loaded WASM plugins
    wasm_plugins: HashMap<String, WasmPlugin>,
    /// Rust plugins (native, no WASM)
    rust_plugins: HashMap<String, Arc<dyn RustPlugin>>,
    /// Plugin directory for hot-reload
    plugin_dir: Option<PathBuf>,
    /// Last reload check
    last_reload_check: Instant,
    /// Reload check interval
    reload_interval: Duration,
}

impl PluginRegistry {
    /// Create new empty registry
    pub fn new() -> Self {
        Self {
            wasm_plugins: HashMap::new(),
            rust_plugins: HashMap::new(),
            plugin_dir: None,
            last_reload_check: Instant::now(),
            reload_interval: Duration::from_secs(5),
        }
    }

    /// Create registry with plugin directory for hot-reload
    pub fn with_plugin_dir(dir: impl AsRef<Path>) -> Self {
        Self {
            plugin_dir: Some(dir.as_ref().to_path_buf()),
            ..Self::new()
        }
    }

    /// Set reload check interval
    pub fn set_reload_interval(&mut self, interval: Duration) {
        self.reload_interval = interval;
    }

    /// Register a Rust plugin
    pub fn register_rust_plugin(&mut self, plugin: Arc<dyn RustPlugin>) {
        let id = plugin.rule_id().to_string();
        info!("Registering Rust plugin: {} ({})", id, plugin.rule_name());
        self.rust_plugins.insert(id, plugin);
    }

    /// Load a WASM plugin
    pub fn load_wasm_plugin(&mut self, config: PluginConfig) -> Result<(), PluginError> {
        let plugin = WasmPlugin::load(config)?;
        let id = plugin.id().to_string();
        info!("Loaded WASM plugin: {} ({})", id, plugin.rule_name());
        self.wasm_plugins.insert(id, plugin);
        Ok(())
    }

    /// Load all plugins from directory
    pub fn load_from_dir(&mut self, dir: impl AsRef<Path>) -> Vec<PluginError> {
        let dir = dir.as_ref();
        let mut errors = Vec::new();

        if !dir.exists() {
            warn!("Plugin directory does not exist: {:?}", dir);
            return errors;
        }

        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.extension().map(|e| e == "wasm").unwrap_or(false) {
                        let config = PluginConfig::new(&path);
                        if let Err(e) = self.load_wasm_plugin(config) {
                            warn!("Failed to load plugin {:?}: {}", path, e);
                            errors.push(e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to read plugin directory: {}", e);
                errors.push(PluginError::LoadError(e.to_string()));
            }
        }

        self.plugin_dir = Some(dir.to_path_buf());
        errors
    }

    /// Check for and reload modified plugins
    pub fn check_reload(&mut self) {
        if self.last_reload_check.elapsed() < self.reload_interval {
            return;
        }
        self.last_reload_check = Instant::now();

        let to_reload: Vec<String> = self.wasm_plugins
            .iter()
            .filter(|(_, p)| p.needs_reload())
            .map(|(id, _)| id.clone())
            .collect();

        for id in to_reload {
            if let Some(_plugin) = self.wasm_plugins.get(&id) {
                let config = PluginConfig::new(&format!("{}.wasm", id))
                    .with_id(&id);

                match WasmPlugin::load(config) {
                    Ok(new_plugin) => {
                        info!("Hot-reloaded plugin: {}", id);
                        self.wasm_plugins.insert(id, new_plugin);
                    }
                    Err(e) => {
                        error!("Failed to reload plugin {}: {}", id, e);
                    }
                }
            }
        }

        // Check for new plugins in directory
        if let Some(ref dir) = self.plugin_dir {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.extension().map(|e| e == "wasm").unwrap_or(false) {
                        let id = path.file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("unknown")
                            .to_string();

                        if !self.wasm_plugins.contains_key(&id) {
                            let config = PluginConfig::new(&path).with_id(&id);
                            if let Err(e) = self.load_wasm_plugin(config) {
                                debug!("Could not load new plugin {:?}: {}", path, e);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Evaluate all plugins against a packet with stage context
    pub fn evaluate_all(
        &self,
        packet: &Packet,
        context: &StageContext,
    ) -> Vec<WasmResult> {
        let mut results = Vec::new();

        // Evaluate Rust plugins
        for plugin in self.rust_plugins.values() {
            if let Some(result) = plugin.evaluate(packet, context) {
                results.push(result);
            }
        }

        // Evaluate WASM plugins
        for plugin in self.wasm_plugins.values() {
            match plugin.evaluate(packet, context) {
                Ok(Some(result)) => results.push(result),
                Ok(None) => {}
                Err(e) => {
                    debug!("Plugin {} evaluation error: {}", plugin.id(), e);
                }
            }
        }

        results
    }

    /// Get number of loaded plugins
    pub fn plugin_count(&self) -> usize {
        self.wasm_plugins.len() + self.rust_plugins.len()
    }

    /// Get all plugin IDs
    pub fn plugin_ids(&self) -> Vec<String> {
        let mut ids: Vec<_> = self.wasm_plugins.keys().cloned().collect();
        ids.extend(self.rust_plugins.keys().cloned());
        ids
    }

    /// Check if a specific plugin is loaded
    pub fn has_plugin(&self, id: &str) -> bool {
        self.wasm_plugins.contains_key(id) || self.rust_plugins.contains_key(id)
    }

    /// Remove a plugin by ID
    pub fn remove_plugin(&mut self, id: &str) -> bool {
        self.wasm_plugins.remove(id).is_some() || self.rust_plugins.remove(id).is_some()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Hot-reloader that runs in background
pub struct HotReloader {
    registry: Arc<RwLock<PluginRegistry>>,
    interval: Duration,
    running: bool,
}

impl HotReloader {
    /// Create a new hot-reloader
    pub fn new(registry: Arc<RwLock<PluginRegistry>>, interval: Duration) -> Self {
        Self {
            registry,
            interval,
            running: false,
        }
    }

    /// Start hot-reload loop (blocks current thread)
    pub fn run(&mut self) {
        self.running = true;
        info!("Hot-reloader started with interval {:?}", self.interval);

        while self.running {
            std::thread::sleep(self.interval);

            if let Ok(mut registry) = self.registry.write() {
                registry.check_reload();
            }
        }
    }

    /// Stop the hot-reloader
    pub fn stop(&mut self) {
        self.running = false;
    }

    /// Check if running
    pub fn is_running(&self) -> bool {
        self.running
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::plugin::PortDiversityPlugin;
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
    fn test_registry_new() {
        let registry = PluginRegistry::new();
        assert_eq!(registry.plugin_count(), 0);
    }

    #[test]
    fn test_register_rust_plugin() {
        let mut registry = PluginRegistry::new();
        registry.register_rust_plugin(Arc::new(PortDiversityPlugin));
        assert_eq!(registry.plugin_count(), 1);
        assert!(registry.plugin_ids().contains(&"RUST_PORT_DIVERSITY".to_string()));
        assert!(registry.has_plugin("RUST_PORT_DIVERSITY"));
    }

    #[test]
    fn test_evaluate_plugins() {
        let mut registry = PluginRegistry::new();
        registry.register_rust_plugin(Arc::new(PortDiversityPlugin));

        let packet = make_test_packet();
        let context = StageContext::new()
            .with_scan(super::super::types::ScanInfo {
                scan_type: "syn_scan".to_string(),
                confidence: 0.9,
                ports_scanned: 150, // High enough to trigger
                half_open: 50,
                sequential_pattern: true,
            });

        let results = registry.evaluate_all(&packet, &context);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].plugin_id, "RUST_PORT_DIVERSITY");
    }

    #[test]
    fn test_remove_plugin() {
        let mut registry = PluginRegistry::new();
        registry.register_rust_plugin(Arc::new(PortDiversityPlugin));
        assert!(registry.has_plugin("RUST_PORT_DIVERSITY"));

        let removed = registry.remove_plugin("RUST_PORT_DIVERSITY");
        assert!(removed);
        assert!(!registry.has_plugin("RUST_PORT_DIVERSITY"));
    }
}
