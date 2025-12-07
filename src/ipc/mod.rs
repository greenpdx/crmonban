//! Inter-process communication for crmonban components
//!
//! Uses Unix sockets for real-time event streaming between:
//! - Main daemon (server/broadcaster)
//! - Display server (client/subscriber)

pub mod client;
pub mod display;
pub mod messages;
pub mod server;

pub use client::{connect_with_retry, IpcClient};
pub use display::DisplayProcess;
pub use messages::*;
pub use server::{IpcRequest, IpcServer};

/// Default socket path
pub const DEFAULT_SOCKET_PATH: &str = "/run/crmonban/events.sock";

/// Protocol version for compatibility checking
pub const PROTOCOL_VERSION: u8 = 1;
