//! IPC server for broadcasting events to display clients
//!
//! Supports both Unix domain sockets and TCP with mTLS:
//! - Server listens on a Unix socket (local) and optionally TCP (remote)
//! - Clients connect and send Hello
//! - Server broadcasts events to all connected clients
//! - Clients can send request messages, server forwards to handler
//! - TCP connections require mTLS with client certificate verification

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot, RwLock};
use tokio::time::Instant;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use super::messages::*;
use super::{DEFAULT_SOCKET_PATH, PROTOCOL_VERSION};

/// Connected client info
#[allow(dead_code)]
struct Client {
    id: String,
    connected_at: Instant,
    subscriptions: Vec<String>,
    /// Whether this client connected via TCP (remote)
    is_remote: bool,
}

/// Request from client with response channel
pub struct IpcRequest {
    /// The request message
    pub message: IpcMessage,
    /// Channel to send response back
    pub response_tx: oneshot::Sender<IpcMessage>,
}

/// TLS configuration for remote connections
#[derive(Clone)]
pub struct TlsConfig {
    /// Server certificate path
    pub cert_path: PathBuf,
    /// Server private key path
    pub key_path: PathBuf,
    /// CA certificate path for client verification
    pub ca_path: PathBuf,
    /// Whether to require client certificates
    pub require_client_cert: bool,
}

impl TlsConfig {
    /// Build a TLS acceptor from this configuration
    pub fn build_acceptor(&self) -> anyhow::Result<TlsAcceptor> {
        // Load server certificate
        let cert_file = File::open(&self.cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()?;

        // Load server private key
        let key_file = File::open(&self.key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)?
            .ok_or_else(|| anyhow::anyhow!("No private key found in {}", self.key_path.display()))?;

        // Load CA certificate for client verification
        let ca_file = File::open(&self.ca_path)?;
        let mut ca_reader = BufReader::new(ca_file);
        let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()?;

        let mut root_store = RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert)?;
        }

        // Build client verifier
        let client_verifier = if self.require_client_cert {
            WebPkiClientVerifier::builder(Arc::new(root_store)).build()?
        } else {
            WebPkiClientVerifier::builder(Arc::new(root_store))
                .allow_unauthenticated()
                .build()?
        };

        // Build server config
        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, PrivateKeyDer::from(key))?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }
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
    /// Optional TCP bind address
    tcp_addr: Option<SocketAddr>,
    /// Optional TLS configuration
    tls_config: Option<TlsConfig>,
}

impl IpcServer {
    /// Create a new IPC server (Unix socket only)
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
            tcp_addr: None,
            tls_config: None,
        }
    }

    /// Create a new IPC server with TCP+mTLS support
    pub fn with_tls(
        socket_path: Option<&Path>,
        tcp_addr: Option<SocketAddr>,
        tls_config: Option<TlsConfig>,
    ) -> Self {
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
            tcp_addr,
            tls_config,
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

        let unix_listener = UnixListener::bind(&self.socket_path)?;
        info!("IPC server listening on Unix socket: {:?}", self.socket_path);

        // Set socket permissions (readable by group)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o660);
            std::fs::set_permissions(&self.socket_path, perms)?;
        }

        // Optionally start TCP listener with TLS
        let tcp_listener = if let Some(addr) = self.tcp_addr {
            let listener = TcpListener::bind(addr).await?;
            info!("IPC server listening on TCP: {}", addr);
            Some(listener)
        } else {
            None
        };

        let tls_acceptor = if let Some(ref config) = self.tls_config {
            let acceptor = config.build_acceptor()?;
            info!("TLS enabled for remote connections (client cert required: {})", config.require_client_cert);
            Some(acceptor)
        } else {
            None
        };

        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        let clients = self.clients.clone();
        let broadcast_tx = self.broadcast_tx.clone();
        let request_tx = self.request_tx.clone();
        let start_time = self.start_time;

        // Spawn Unix socket listener task
        let clients_unix = clients.clone();
        let broadcast_tx_unix = broadcast_tx.clone();
        let request_tx_unix = request_tx.clone();
        let (unix_shutdown_tx, mut unix_shutdown_rx) = mpsc::channel::<()>(1);

        tokio::spawn(async move {
            let mut client_id_counter: u64 = 0;

            loop {
                tokio::select! {
                    result = unix_listener.accept() => {
                        match result {
                            Ok((stream, _addr)) => {
                                client_id_counter += 1;
                                let id = client_id_counter;
                                let clients = clients_unix.clone();
                                let mut rx = broadcast_tx_unix.subscribe();
                                let req_tx = request_tx_unix.clone();
                                let start = start_time;

                                tokio::spawn(async move {
                                    if let Err(e) = handle_unix_client(id, stream, &mut rx, clients, start, req_tx).await {
                                        debug!("Unix client {} disconnected: {}", id, e);
                                    }
                                });
                            }
                            Err(e) => {
                                error!("Failed to accept Unix connection: {}", e);
                            }
                        }
                    }
                    _ = unix_shutdown_rx.recv() => {
                        info!("Unix socket listener shutting down");
                        break;
                    }
                }
            }
        });

        // Spawn TCP listener task if enabled
        if let Some(tcp_listener) = tcp_listener {
            let clients_tcp = clients.clone();
            let broadcast_tx_tcp = broadcast_tx.clone();
            let request_tx_tcp = request_tx.clone();
            let tls_acceptor = tls_acceptor.clone();

            tokio::spawn(async move {
                let mut client_id_counter: u64 = 1_000_000; // Start at 1M to distinguish from Unix clients

                loop {
                    match tcp_listener.accept().await {
                        Ok((stream, addr)) => {
                            client_id_counter += 1;
                            let id = client_id_counter;
                            let clients = clients_tcp.clone();
                            let mut rx = broadcast_tx_tcp.subscribe();
                            let req_tx = request_tx_tcp.clone();
                            let start = start_time;
                            let acceptor = tls_acceptor.clone();

                            tokio::spawn(async move {
                                // Require TLS for TCP connections
                                if let Some(acceptor) = acceptor {
                                    match acceptor.accept(stream).await {
                                        Ok(tls_stream) => {
                                            info!("TCP client {} connected from {} with TLS", id, addr);
                                            if let Err(e) = handle_tcp_client(id, tls_stream, &mut rx, clients, start, req_tx).await {
                                                debug!("TCP client {} disconnected: {}", id, e);
                                            }
                                        }
                                        Err(e) => {
                                            warn!("TLS handshake failed for {}: {}", addr, e);
                                        }
                                    }
                                } else {
                                    error!("TCP connection from {} rejected: TLS not configured", addr);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Failed to accept TCP connection: {}", e);
                        }
                    }
                }
            });
        }

        // Main shutdown handler
        tokio::spawn(async move {
            shutdown_rx.recv().await;
            let _ = unix_shutdown_tx.send(()).await;
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

/// Handle a Unix socket client
async fn handle_unix_client(
    id: u64,
    stream: UnixStream,
    rx: &mut broadcast::Receiver<IpcMessage>,
    clients: Arc<RwLock<HashMap<u64, Client>>>,
    start_time: Instant,
    request_tx: mpsc::Sender<IpcRequest>,
) -> anyhow::Result<()> {
    handle_client_generic(id, stream, rx, clients, start_time, request_tx, false).await
}

/// Handle a TCP+TLS client
async fn handle_tcp_client(
    id: u64,
    stream: TlsStream<TcpStream>,
    rx: &mut broadcast::Receiver<IpcMessage>,
    clients: Arc<RwLock<HashMap<u64, Client>>>,
    start_time: Instant,
    request_tx: mpsc::Sender<IpcRequest>,
) -> anyhow::Result<()> {
    handle_client_generic(id, stream, rx, clients, start_time, request_tx, true).await
}

/// Generic client handler for any stream type
async fn handle_client_generic<S>(
    id: u64,
    mut stream: S,
    rx: &mut broadcast::Receiver<IpcMessage>,
    clients: Arc<RwLock<HashMap<u64, Client>>>,
    start_time: Instant,
    request_tx: mpsc::Sender<IpcRequest>,
    is_remote: bool,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    debug!("Client {} connected (remote: {})", id, is_remote);

    // Read Hello message
    let hello = read_message_generic(&mut stream).await?;

    let client_info = match hello {
        IpcMessage::Hello(h) => {
            if h.version != PROTOCOL_VERSION {
                warn!("Client {} has incompatible protocol version {}", id, h.version);
            }
            Client {
                id: h.client_id,
                connected_at: Instant::now(),
                subscriptions: h.subscriptions,
                is_remote,
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

    send_message_generic(&mut stream, &welcome).await?;

    // Register client
    clients.write().await.insert(id, client_info);
    info!("Client {} registered (remote: {})", id, is_remote);

    // Event forwarding loop
    let mut ping_interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            // Forward broadcast events to client
            result = rx.recv() => {
                match result {
                    Ok(msg) => {
                        if let Err(e) = send_message_generic(&mut stream, &msg).await {
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
            result = read_message_generic(&mut stream) => {
                match result {
                    Ok(IpcMessage::Ping) => {
                        send_message_generic(&mut stream, &IpcMessage::Pong).await?;
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
                                    if let Err(e) = send_message_generic(&mut stream, &response).await {
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
                                    let _ = send_message_generic(&mut stream, &error).await;
                                }
                                Err(_) => {
                                    // Timeout
                                    let error = IpcMessage::Error(ErrorResponse {
                                        request_id: None,
                                        code: "TIMEOUT".to_string(),
                                        message: "Request timed out".to_string(),
                                    });
                                    let _ = send_message_generic(&mut stream, &error).await;
                                }
                            }
                        } else {
                            let error = IpcMessage::Error(ErrorResponse {
                                request_id: None,
                                code: "UNAVAILABLE".to_string(),
                                message: "Request handler not available".to_string(),
                            });
                            let _ = send_message_generic(&mut stream, &error).await;
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
                if let Err(e) = send_message_generic(&mut stream, &IpcMessage::Ping).await {
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

/// Read a message from a Unix stream
async fn read_message(stream: &mut UnixStream) -> anyhow::Result<IpcMessage> {
    read_message_generic(stream).await
}

/// Send a message to a Unix stream
async fn send_message(stream: &mut UnixStream, msg: &IpcMessage) -> anyhow::Result<()> {
    send_message_generic(stream, msg).await
}

/// Read a message from any async stream
async fn read_message_generic<S>(stream: &mut S) -> anyhow::Result<IpcMessage>
where
    S: AsyncRead + Unpin,
{
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

/// Send a message to any async stream
async fn send_message_generic<S>(stream: &mut S, msg: &IpcMessage) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
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
