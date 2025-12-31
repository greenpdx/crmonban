//! IPC server for broadcasting events to display clients
//!
//! Uses Unix domain sockets with a pub/sub model:
//! - Server listens on a socket
//! - Clients connect and send Hello
//! - Server broadcasts events to all connected clients
//! - Clients can send request messages, server forwards to handler

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use super::messages::*;
use super::{DEFAULT_SOCKET_PATH, PROTOCOL_VERSION};

/// Connected client info
#[allow(dead_code)]
struct Client {
    id: String,
    connected_at: Instant,
    subscriptions: Vec<String>,
}

/// Request from client with response channel
pub struct IpcRequest {
    /// The request message
    pub message: IpcMessage,
    /// Channel to send response back
    pub response_tx: oneshot::Sender<IpcMessage>,
}

/// IPC server for event broadcasting
pub struct IpcServer {
    /// Socket path
    socket_path: PathBuf,
    /// Broadcast channel for events
    broadcast_tx: broadcast::Sender<IpcMessage>,
    /// Connected clients
    clients: Arc<RwLock<HashMap<u64, Client>>>,
    /// Server start time
    start_time: Instant,
    /// Shutdown signal
    shutdown_tx: Option<mpsc::Sender<()>>,
    /// Request handler channel (for daemon to receive requests)
    request_tx: mpsc::Sender<IpcRequest>,
    /// Request receiver (held by daemon)
    request_rx: Option<mpsc::Receiver<IpcRequest>>,
}

impl IpcServer {
    /// Create a new IPC server
    pub fn new(socket_path: Option<&Path>) -> Self {
        let (broadcast_tx, _) = broadcast::channel(1024);
        let (request_tx, request_rx) = mpsc::channel(64);

        Self {
            socket_path: socket_path
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH)),
            broadcast_tx,
            clients: Arc::new(RwLock::new(HashMap::new())),
            start_time: Instant::now(),
            shutdown_tx: None,
            request_tx,
            request_rx: Some(request_rx),
        }
    }

    /// Get the broadcast sender for publishing events
    pub fn sender(&self) -> broadcast::Sender<IpcMessage> {
        self.broadcast_tx.clone()
    }

    /// Broadcast an event to all clients
    pub fn broadcast(&self, msg: IpcMessage) {
        // Ignore errors (no subscribers)
        let _ = self.broadcast_tx.send(msg);
    }

    /// Get number of connected clients
    pub async fn client_count(&self) -> usize {
        self.clients.read().await.len()
    }

    /// Take the request receiver (daemon will use this to handle requests)
    pub fn take_request_receiver(&mut self) -> Option<mpsc::Receiver<IpcRequest>> {
        self.request_rx.take()
    }

    /// Get request sender clone (for passing to client handlers)
    pub fn request_sender(&self) -> mpsc::Sender<IpcRequest> {
        self.request_tx.clone()
    }

    /// Start the IPC server
    pub async fn start(&mut self) -> anyhow::Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = self.socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Remove existing socket
        let _ = tokio::fs::remove_file(&self.socket_path).await;

        let listener = UnixListener::bind(&self.socket_path)?;
        info!("IPC server listening on {:?}", self.socket_path);

        // Set socket permissions (readable by group)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o660);
            std::fs::set_permissions(&self.socket_path, perms)?;
        }

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        let clients = self.clients.clone();
        let broadcast_tx = self.broadcast_tx.clone();
        let request_tx = self.request_tx.clone();
        let start_time = self.start_time;

        tokio::spawn(async move {
            let mut client_id_counter: u64 = 0;

            loop {
                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, _addr)) => {
                                client_id_counter += 1;
                                let id = client_id_counter;
                                let clients = clients.clone();
                                let mut rx = broadcast_tx.subscribe();
                                let req_tx = request_tx.clone();
                                let start = start_time;

                                tokio::spawn(async move {
                                    if let Err(e) = handle_client(id, stream, &mut rx, clients, start, req_tx).await {
                                        debug!("Client {} disconnected: {}", id, e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Failed to accept connection: {}", e);
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("IPC server shutting down");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop the server
    pub async fn stop(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(()).await;
        }
        // Cleanup socket
        let _ = tokio::fs::remove_file(&self.socket_path).await;
    }
}

/// Check if a message is a request that needs handling
fn is_request_message(msg: &IpcMessage) -> bool {
    matches!(
        msg,
        IpcMessage::GetBans(_)
            | IpcMessage::GetStats
            | IpcMessage::GetIntel(_)
            | IpcMessage::GetEvents(_)
            | IpcMessage::GetStatus
            | IpcMessage::GetConfig
            | IpcMessage::Action(_)
    )
}

/// Handle a connected client
async fn handle_client(
    id: u64,
    mut stream: UnixStream,
    rx: &mut broadcast::Receiver<IpcMessage>,
    clients: Arc<RwLock<HashMap<u64, Client>>>,
    start_time: Instant,
    request_tx: mpsc::Sender<IpcRequest>,
) -> anyhow::Result<()> {
    debug!("Client {} connected", id);

    // Read Hello message
    let hello = read_message(&mut stream).await?;

    let client_info = match hello {
        IpcMessage::Hello(h) => {
            if h.version != PROTOCOL_VERSION {
                warn!("Client {} has incompatible protocol version {}", id, h.version);
            }
            Client {
                id: h.client_id,
                connected_at: Instant::now(),
                subscriptions: h.subscriptions,
            }
        }
        _ => {
            return Err(anyhow::anyhow!("Expected Hello message"));
        }
    };

    // Send Welcome
    let active_bans = 0; // TODO: Get from daemon state
    let welcome = IpcMessage::Welcome(WelcomeMessage {
        version: PROTOCOL_VERSION,
        uptime_secs: start_time.elapsed().as_secs(),
        active_bans,
        events_processed: 0,
    });

    send_message(&mut stream, &welcome).await?;

    // Register client
    clients.write().await.insert(id, client_info);
    info!("Client {} registered", id);

    // Event forwarding loop
    let mut ping_interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            // Forward broadcast events to client
            result = rx.recv() => {
                match result {
                    Ok(msg) => {
                        if let Err(e) = send_message(&mut stream, &msg).await {
                            debug!("Failed to send to client {}: {}", id, e);
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("Client {} lagged {} messages", id, n);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            // Handle incoming messages
            result = read_message(&mut stream) => {
                match result {
                    Ok(IpcMessage::Ping) => {
                        send_message(&mut stream, &IpcMessage::Pong).await?;
                    }
                    Ok(msg) if is_request_message(&msg) => {
                        // Forward request to daemon and wait for response
                        let (response_tx, response_rx) = oneshot::channel();
                        let request = IpcRequest {
                            message: msg,
                            response_tx,
                        };

                        if request_tx.send(request).await.is_ok() {
                            // Wait for response with timeout
                            match tokio::time::timeout(Duration::from_secs(30), response_rx).await {
                                Ok(Ok(response)) => {
                                    if let Err(e) = send_message(&mut stream, &response).await {
                                        debug!("Failed to send response to client {}: {}", id, e);
                                        break;
                                    }
                                }
                                Ok(Err(_)) => {
                                    // Response channel closed
                                    let error = IpcMessage::Error(ErrorResponse {
                                        request_id: None,
                                        code: "INTERNAL_ERROR".to_string(),
                                        message: "Request handler closed".to_string(),
                                    });
                                    let _ = send_message(&mut stream, &error).await;
                                }
                                Err(_) => {
                                    // Timeout
                                    let error = IpcMessage::Error(ErrorResponse {
                                        request_id: None,
                                        code: "TIMEOUT".to_string(),
                                        message: "Request timed out".to_string(),
                                    });
                                    let _ = send_message(&mut stream, &error).await;
                                }
                            }
                        } else {
                            let error = IpcMessage::Error(ErrorResponse {
                                request_id: None,
                                code: "UNAVAILABLE".to_string(),
                                message: "Request handler not available".to_string(),
                            });
                            let _ = send_message(&mut stream, &error).await;
                        }
                    }
                    Ok(_) => {
                        // Ignore other messages from client
                    }
                    Err(e) => {
                        debug!("Client {} read error: {}", id, e);
                        break;
                    }
                }
            }
            // Send periodic ping
            _ = ping_interval.tick() => {
                if let Err(e) = send_message(&mut stream, &IpcMessage::Ping).await {
                    debug!("Client {} ping failed: {}", id, e);
                    break;
                }
            }
        }
    }

    // Unregister client
    clients.write().await.remove(&id);
    info!("Client {} disconnected", id);

    Ok(())
}

/// Read a message from the stream
async fn read_message(stream: &mut UnixStream) -> anyhow::Result<IpcMessage> {
    // Read 4-byte length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 1024 * 1024 {
        return Err(anyhow::anyhow!("Message too large: {} bytes", len));
    }

    // Read payload
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    Ok(IpcMessage::from_json(&buf)?)
}

/// Send a message to the stream
async fn send_message(stream: &mut UnixStream, msg: &IpcMessage) -> anyhow::Result<()> {
    let wire = msg.to_wire()?;
    stream.write_all(&wire).await?;
    Ok(())
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        // Cleanup socket synchronously
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ipc_server_creation() {
        let server = IpcServer::new(Some(Path::new("/tmp/test_crmonban.sock")));
        assert_eq!(server.client_count().await, 0);
    }
}
