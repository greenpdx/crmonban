//! Standalone WASM Plugin Framework
//!
//! Provides WASM/Rust plugin support that can be used by any pipeline stage.
//! Plugins receive packets and stage-aware context, returning detection results.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          WasmEngine                                     │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │  PluginRegistry          StageContext Builder       Result Aggregator   │
//! │       ↓                         ↓                          ↓            │
//! │  WASM Plugins            Packet + Context              WasmResults      │
//! │  Rust Plugins                                                           │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use crmonban::wasm::{WasmEngine, StageContext};
//!
//! let mut engine = WasmEngine::new();
//! engine.register_default_plugins();
//!
//! // In pipeline stage
//! let context = StageContext::new()
//!     .with_stage(PipelineStage::WasmPlugins)
//!     .with_scan(scan_info);
//!
//! let results = engine.process(&packet, &context);
//! for result in results {
//!     // Handle detection results
//! }
//! ```

mod plugin;
mod registry;
mod types;

pub use plugin::{WasmPlugin, PluginConfig, PluginError, RustPlugin};
pub use plugin::{PortDiversityPlugin, MultiSignalPlugin};
pub use registry::{PluginRegistry, HotReloader};
pub use types::{
    StageContext, WasmResult,
    FlowInfo, ScanInfo, DoSInfo, BruteForceInfo,
    SignatureInfo, IntelInfo, ProtocolInfo,
    HttpInfo, DnsInfo, TlsInfo,
};

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::core::event::{DetectionEvent, DetectionType, Severity};
use crate::core::packet::Packet;

/// WASM Engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmConfig {
    /// Enable WASM plugin processing
    pub enabled: bool,
    /// Plugin directory path
    pub plugin_dir: Option<String>,
    /// Enable hot-reload of plugins
    pub hot_reload: bool,
    /// Hot-reload check interval (seconds)
    pub reload_interval_secs: u64,
    /// Register default built-in plugins
    pub register_defaults: bool,
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            plugin_dir: None,
            hot_reload: true,
            reload_interval_secs: 5,
            register_defaults: true,
        }
    }
}

/// Main WASM engine that processes packets through registered plugins
pub struct WasmEngine {
    /// Configuration
    config: WasmConfig,
    /// Plugin registry
    registry: PluginRegistry,
    /// Packets processed
    packets_processed: u64,
    /// Results generated
    results_generated: u64,
}

impl WasmEngine {
    /// Create a new WASM engine with default configuration
    pub fn new() -> Self {
        Self::with_config(WasmConfig::default())
    }

    /// Create a new WASM engine with custom configuration
    pub fn with_config(config: WasmConfig) -> Self {
        let mut registry = if let Some(ref dir) = config.plugin_dir {
            PluginRegistry::with_plugin_dir(dir)
        } else {
            PluginRegistry::new()
        };

        // Register default plugins if enabled
        if config.register_defaults {
            registry.register_rust_plugin(Arc::new(PortDiversityPlugin));
            registry.register_rust_plugin(Arc::new(MultiSignalPlugin));
        }

        Self {
            config,
            registry,
            packets_processed: 0,
            results_generated: 0,
        }
    }

    /// Register a Rust plugin
    pub fn register_plugin(&mut self, plugin: Arc<dyn RustPlugin>) {
        self.registry.register_rust_plugin(plugin);
    }

    /// Load WASM plugins from a directory
    pub fn load_plugins_from_dir(&mut self, dir: impl AsRef<Path>) -> Vec<PluginError> {
        self.registry.load_from_dir(dir)
    }

    /// Process a packet through all plugins
    pub fn process(&mut self, packet: &Packet, context: &StageContext) -> Vec<WasmResult> {
        if !self.config.enabled {
            return Vec::new();
        }

        self.packets_processed += 1;

        // Check for hot-reload if enabled
        if self.config.hot_reload {
            self.registry.check_reload();
        }

        let results = self.registry.evaluate_all(packet, context);
        self.results_generated += results.len() as u64;

        if !results.is_empty() {
            debug!(
                "WASM plugins generated {} results for {} -> {}",
                results.len(),
                packet.src_ip(),
                packet.dst_ip()
            );
        }

        results
    }

    /// Convert WASM results to detection events
    pub fn results_to_events(&self, packet: &Packet, results: &[WasmResult]) -> Vec<DetectionEvent> {
        results
            .iter()
            .filter_map(|r| {
                // Only generate events for results with detection types
                let detection_type = r.detection_type.clone()
                    .unwrap_or(DetectionType::Custom(format!("wasm:{}", r.plugin_id)));

                // Map score to severity
                let severity = if r.score_delta >= 8.0 {
                    Severity::Critical
                } else if r.score_delta >= 5.0 {
                    Severity::High
                } else if r.score_delta >= 3.0 {
                    Severity::Medium
                } else if r.score_delta >= 1.0 {
                    Severity::Low
                } else {
                    Severity::Info
                };

                Some(
                    DetectionEvent::new(
                        detection_type,
                        severity,
                        packet.src_ip(),
                        packet.dst_ip(),
                        r.evidence.clone(),
                    )
                    .with_detector(&format!("wasm:{}", r.plugin_id))
                    .with_confidence(r.confidence)
                    .with_ports(packet.src_port(), packet.dst_port())
                )
            })
            .collect()
    }

    /// Get engine statistics
    pub fn stats(&self) -> WasmStats {
        WasmStats {
            enabled: self.config.enabled,
            plugin_count: self.registry.plugin_count(),
            packets_processed: self.packets_processed,
            results_generated: self.results_generated,
        }
    }

    /// Get plugin count
    pub fn plugin_count(&self) -> usize {
        self.registry.plugin_count()
    }

    /// Get plugin IDs
    pub fn plugin_ids(&self) -> Vec<String> {
        self.registry.plugin_ids()
    }

    /// Check if enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Enable or disable the engine
    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;
    }

    /// Get mutable access to registry (for advanced usage)
    pub fn registry_mut(&mut self) -> &mut PluginRegistry {
        &mut self.registry
    }
}

impl Default for WasmEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// WASM engine statistics
#[derive(Debug, Clone, Default)]
pub struct WasmStats {
    /// Is engine enabled
    pub enabled: bool,
    /// Number of loaded plugins
    pub plugin_count: usize,
    /// Packets processed
    pub packets_processed: u64,
    /// Results generated
    pub results_generated: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::core::packet::IpProtocol;

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
    fn test_wasm_engine_new() {
        let engine = WasmEngine::new();
        assert!(engine.is_enabled());
        // Default plugins should be registered
        assert!(engine.plugin_count() >= 2);
    }

    #[test]
    fn test_wasm_engine_disabled() {
        let config = WasmConfig {
            enabled: false,
            ..Default::default()
        };
        let mut engine = WasmEngine::with_config(config);

        let packet = make_test_packet();
        let context = StageContext::new();
        let results = engine.process(&packet, &context);
        assert!(results.is_empty());
    }

    #[test]
    fn test_wasm_engine_process() {
        let mut engine = WasmEngine::new();

        let packet = make_test_packet();
        let context = StageContext::new()
            .with_scan(ScanInfo {
                scan_type: "syn_scan".to_string(),
                confidence: 0.9,
                ports_scanned: 150, // High enough to trigger PortDiversityPlugin
                half_open: 50,
                sequential_pattern: true,
            });

        let results = engine.process(&packet, &context);
        assert!(!results.is_empty());

        let stats = engine.stats();
        assert_eq!(stats.packets_processed, 1);
        assert!(stats.results_generated > 0);
    }

    #[test]
    fn test_wasm_engine_to_events() {
        let engine = WasmEngine::new();
        let packet = make_test_packet();

        let results = vec![
            WasmResult::new("TEST", 5.0, "Test detection")
                .with_confidence(0.9),
        ];

        let events = engine.results_to_events(&packet, &results);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, Severity::High);
    }

    #[test]
    fn test_wasm_config_default() {
        let config = WasmConfig::default();
        assert!(config.enabled);
        assert!(config.hot_reload);
        assert!(config.register_defaults);
    }
}
