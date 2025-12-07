//! WASM Plugin Framework for Custom Detection Rules
//!
//! Allows loading WebAssembly plugins for custom scan detection logic.
//! Plugins are sandboxed and can be hot-reloaded at runtime.
//!
//! # Plugin Interface (WIT)
//!
//! ```wit
//! interface scan-detect {
//!     record packet-info {
//!         src-ip-v4: option<u32>,
//!         src-ip-v6: option<list<u8>>,
//!         dst-port: u16,
//!         is-syn: bool,
//!         is-ack: bool,
//!         is-rst: bool,
//!         payload-size: u32,
//!         ttl: option<u8>,
//!     }
//!
//!     record behavior-info {
//!         half-open-count: u32,
//!         completed-count: u32,
//!         unique-ports: u32,
//!         syn-rate: f32,
//!         current-score: f32,
//!     }
//!
//!     record rule-result {
//!         rule-id: string,
//!         score-delta: f32,
//!         confidence: f32,
//!         evidence: string,
//!         tags: list<string>,
//!     }
//!
//!     evaluate: func(packet: packet-info, behavior: behavior-info) -> option<rule-result>
//!
//!     rule-id: func() -> string
//!     rule-name: func() -> string
//!     default-weight: func() -> f32
//! }
//! ```

mod plugin;
mod registry;
mod types;

pub use plugin::{WasmPlugin, PluginConfig, PluginError};
pub use registry::{PluginRegistry, HotReloader};
pub use types::{PacketInfo, BehaviorInfo, WasmRuleResult};
