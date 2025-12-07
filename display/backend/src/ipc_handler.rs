//! IPC handler for receiving real-time events from the daemon
//!
//! Connects to the daemon via Unix socket and broadcasts events to WebSocket clients.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crmonban::ipc::{connect_with_retry, IpcClient, IpcMessage};

/// IPC connection handler
pub struct IpcHandler {
    /// Socket path
    socket_path: Option<String>,
    /// Broadcast channel for WebSocket clients
    broadcast_tx: broadcast::Sender<IpcMessage>,
}

impl IpcHandler {
    /// Create a new IPC handler
    pub fn new(socket_path: Option<String>) -> Self {
        let (broadcast_tx, _) = broadcast::channel(256);
        Self {
            socket_path,
            broadcast_tx,
        }
    }

    /// Get a receiver for WebSocket broadcasts
    pub fn subscribe(&self) -> broadcast::Receiver<IpcMessage> {
        self.broadcast_tx.subscribe()
    }

    /// Get the broadcast sender
    pub fn sender(&self) -> broadcast::Sender<IpcMessage> {
        self.broadcast_tx.clone()
    }

    /// Start the IPC connection with auto-reconnect
    pub async fn run(self: Arc<Self>) {
        loop {
            if let Err(e) = self.connect_and_receive().await {
                error!("IPC connection error: {}", e);
            }

            // Wait before reconnecting
            warn!("IPC disconnected, reconnecting in 5 seconds...");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    }

    /// Connect to daemon and receive events
    async fn connect_and_receive(&self) -> anyhow::Result<()> {
        let socket_path = self.socket_path.as_deref();

        info!(
            "Connecting to daemon IPC at {}",
            socket_path.unwrap_or(crmonban::ipc::DEFAULT_SOCKET_PATH)
        );

        let mut client = connect_with_retry(
            socket_path,
            "crmonban-display",
            10,
            Duration::from_secs(2),
        )
        .await?;

        info!("Connected to daemon IPC");

        // Get the event receiver
        let mut event_rx = client
            .receiver()
            .ok_or_else(|| anyhow::anyhow!("No receiver available"))?;

        // Forward events to WebSocket broadcast
        while let Some(msg) = event_rx.recv().await {
            // Log important events
            match &msg {
                IpcMessage::Event(e) => {
                    info!("Security event: {} from {} (severity {})",
                          e.event_type, e.src_ip, e.severity);
                }
                IpcMessage::Ban(b) => {
                    info!("Ban {}: {}", b.action, b.ip);
                }
                IpcMessage::Scan(s) => {
                    info!("Scan detected: {} score={:.1}", s.src_ip, s.score);
                }
                IpcMessage::Metrics(_) => {
                    // Don't log metrics (too frequent)
                }
                _ => {}
            }

            // Broadcast to WebSocket clients
            // Ignore errors (no subscribers)
            let _ = self.broadcast_tx.send(msg);
        }

        Err(anyhow::anyhow!("IPC connection closed"))
    }
}

/// Start the IPC handler as a background task
pub fn start_ipc_handler(socket_path: Option<String>) -> Arc<IpcHandler> {
    let handler = Arc::new(IpcHandler::new(socket_path));
    let handler_clone = handler.clone();

    tokio::spawn(async move {
        handler_clone.run().await;
    });

    handler
}
