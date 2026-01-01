//! IPC client for connecting to the daemon
//!
//! Supports both Unix sockets (local) and TCP+TLS (remote) connections.
//! Used by the display server to receive real-time events.

use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::mpsc;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

use super::messages::*;
use super::{DEFAULT_SOCKET_PATH, PROTOCOL_VERSION};

/// IPC client for receiving events from the daemon
pub struct IpcClient {
    /// Socket path
    socket_path: String,
    /// Event receiver
    event_rx: Option<mpsc::Receiver<IpcMessage>>,
    /// Shutdown sender
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl IpcClient {
    /// Create a new IPC client
    pub fn new(socket_path: Option<&str>) -> Self {
        Self {
            socket_path: socket_path
                .unwrap_or(DEFAULT_SOCKET_PATH)
                .to_string(),
            event_rx: None,
            shutdown_tx: None,
        }
    }

    /// Connect to the daemon
    pub async fn connect(&mut self, client_id: &str) -> anyhow::Result<()> {
        info!("Connecting to IPC server at {}", self.socket_path);

        let mut stream = UnixStream::connect(&self.socket_path).await?;

        // Send Hello
        let hello = IpcMessage::Hello(HelloMessage {
            version: PROTOCOL_VERSION,
            client_id: client_id.to_string(),
            subscriptions: vec![], // Subscribe to all
        });
        send_message(&mut stream, &hello).await?;

        // Wait for Welcome
        let welcome = read_message(&mut stream).await?;
        match welcome {
            IpcMessage::Welcome(w) => {
                info!(
                    "Connected to daemon (uptime: {}s, bans: {}, events: {})",
                    w.uptime_secs, w.active_bans, w.events_processed
                );
            }
            _ => {
                return Err(anyhow::anyhow!("Expected Welcome message"));
            }
        }

        // Create channels
        let (event_tx, event_rx) = mpsc::channel(256);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        self.event_rx = Some(event_rx);
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn receiver task
        let socket_path = self.socket_path.clone();
        tokio::spawn(async move {
            if let Err(e) = receive_loop(stream, event_tx, &mut shutdown_rx).await {
                error!("IPC receive loop error: {}", e);
            }
            info!("IPC client disconnected from {}", socket_path);
        });

        Ok(())
    }

    /// Get the event receiver
    pub fn receiver(&mut self) -> Option<mpsc::Receiver<IpcMessage>> {
        self.event_rx.take()
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.shutdown_tx.is_some()
    }

    /// Disconnect
    pub async fn disconnect(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
        self.event_rx = None;
    }
}

/// Receive loop for handling incoming messages
async fn receive_loop(
    mut stream: UnixStream,
    event_tx: mpsc::Sender<IpcMessage>,
    shutdown_rx: &mut mpsc::Receiver<()>,
) -> anyhow::Result<()> {
    let mut ping_interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            result = read_message(&mut stream) => {
                match result {
                    Ok(msg) => {
                        match &msg {
                            IpcMessage::Ping => {
                                // Respond with Pong
                                if let Err(e) = send_message(&mut stream, &IpcMessage::Pong).await {
                                    warn!("Failed to send Pong: {}", e);
                                }
                            }
                            IpcMessage::Pong => {
                                // Heartbeat response, ignore
                                debug!("Received Pong");
                            }
                            _ => {
                                // Forward to receiver
                                if event_tx.send(msg).await.is_err() {
                                    // Receiver dropped
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("IPC read error: {}", e);
                        break;
                    }
                }
            }
            _ = ping_interval.tick() => {
                // Send periodic ping
                if let Err(e) = send_message(&mut stream, &IpcMessage::Ping).await {
                    warn!("Failed to send Ping: {}", e);
                    break;
                }
            }
            _ = shutdown_rx.recv() => {
                info!("IPC client shutting down");
                break;
            }
        }
    }

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

/// Convenience function to connect with retry
pub async fn connect_with_retry(
    socket_path: Option<&str>,
    client_id: &str,
    max_retries: u32,
    retry_delay: Duration,
) -> anyhow::Result<IpcClient> {
    let mut client = IpcClient::new(socket_path);
    let mut retries = 0;

    loop {
        match client.connect(client_id).await {
            Ok(()) => return Ok(client),
            Err(e) => {
                retries += 1;
                if retries >= max_retries {
                    return Err(anyhow::anyhow!(
                        "Failed to connect after {} retries: {}",
                        max_retries,
                        e
                    ));
                }
                warn!(
                    "Failed to connect to IPC (attempt {}/{}): {}",
                    retries, max_retries, e
                );
                tokio::time::sleep(retry_delay).await;
            }
        }
    }
}

/// TLS configuration for remote IPC client
#[derive(Clone)]
pub struct TlsClientConfig {
    /// Client certificate path
    pub cert_path: PathBuf,
    /// Client private key path
    pub key_path: PathBuf,
    /// CA certificate path (to verify server)
    pub ca_path: PathBuf,
    /// Server hostname for verification
    pub server_name: String,
}

impl TlsClientConfig {
    /// Build a TLS connector from this configuration
    pub fn build_connector(&self) -> anyhow::Result<TlsConnector> {
        // Load client certificate
        let cert_file = File::open(&self.cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()?;

        // Load client private key
        let key_file = File::open(&self.key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let key = rustls_pemfile::private_key(&mut key_reader)?
            .ok_or_else(|| anyhow::anyhow!("No private key found in {}", self.key_path.display()))?;

        // Load CA certificate
        let ca_file = File::open(&self.ca_path)?;
        let mut ca_reader = BufReader::new(ca_file);
        let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
            .collect::<Result<Vec<_>, _>>()?;

        let mut root_store = RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(cert)?;
        }

        // Build client config
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, PrivateKeyDer::from(key))?;

        Ok(TlsConnector::from(Arc::new(config)))
    }
}

/// IPC client for remote connections via TCP+TLS
pub struct TlsIpcClient {
    /// Remote address
    addr: SocketAddr,
    /// TLS configuration
    tls_config: TlsClientConfig,
    /// Event receiver
    event_rx: Option<mpsc::Receiver<IpcMessage>>,
    /// Shutdown sender
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl TlsIpcClient {
    /// Create a new TLS IPC client
    pub fn new(addr: SocketAddr, tls_config: TlsClientConfig) -> Self {
        Self {
            addr,
            tls_config,
            event_rx: None,
            shutdown_tx: None,
        }
    }

    /// Connect to the remote daemon
    pub async fn connect(&mut self, client_id: &str) -> anyhow::Result<()> {
        info!("Connecting to remote IPC at {} via TLS", self.addr);

        // Connect TCP
        let tcp_stream = TcpStream::connect(self.addr).await?;

        // Wrap with TLS
        let connector = self.tls_config.build_connector()?;
        let server_name = ServerName::try_from(self.tls_config.server_name.clone())?;
        let mut stream = connector.connect(server_name, tcp_stream).await?;

        // Send Hello
        let hello = IpcMessage::Hello(HelloMessage {
            version: PROTOCOL_VERSION,
            client_id: client_id.to_string(),
            subscriptions: vec![],
        });
        send_message_generic(&mut stream, &hello).await?;

        // Wait for Welcome
        let welcome = read_message_generic(&mut stream).await?;
        match welcome {
            IpcMessage::Welcome(w) => {
                info!(
                    "Connected to remote daemon at {} (uptime: {}s, bans: {})",
                    self.addr, w.uptime_secs, w.active_bans
                );
            }
            _ => {
                return Err(anyhow::anyhow!("Expected Welcome message"));
            }
        }

        // Create channels
        let (event_tx, event_rx) = mpsc::channel(256);
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        self.event_rx = Some(event_rx);
        self.shutdown_tx = Some(shutdown_tx);

        // Spawn receiver task
        let addr = self.addr;
        tokio::spawn(async move {
            if let Err(e) = receive_loop_generic(stream, event_tx, &mut shutdown_rx).await {
                error!("Remote IPC receive loop error: {}", e);
            }
            info!("Remote IPC client disconnected from {}", addr);
        });

        Ok(())
    }

    /// Get the event receiver
    pub fn receiver(&mut self) -> Option<mpsc::Receiver<IpcMessage>> {
        self.event_rx.take()
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.shutdown_tx.is_some()
    }

    /// Disconnect
    pub async fn disconnect(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
        self.event_rx = None;
    }
}

/// Generic receive loop for any stream type
async fn receive_loop_generic<S>(
    mut stream: S,
    event_tx: mpsc::Sender<IpcMessage>,
    shutdown_rx: &mut mpsc::Receiver<()>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ping_interval = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            result = read_message_generic(&mut stream) => {
                match result {
                    Ok(msg) => {
                        match &msg {
                            IpcMessage::Ping => {
                                if let Err(e) = send_message_generic(&mut stream, &IpcMessage::Pong).await {
                                    warn!("Failed to send Pong: {}", e);
                                }
                            }
                            IpcMessage::Pong => {
                                debug!("Received Pong");
                            }
                            _ => {
                                if event_tx.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("IPC read error: {}", e);
                        break;
                    }
                }
            }
            _ = ping_interval.tick() => {
                if let Err(e) = send_message_generic(&mut stream, &IpcMessage::Ping).await {
                    warn!("Failed to send Ping: {}", e);
                    break;
                }
            }
            _ = shutdown_rx.recv() => {
                info!("IPC client shutting down");
                break;
            }
        }
    }

    Ok(())
}

/// Read a message from any async stream
async fn read_message_generic<S>(stream: &mut S) -> anyhow::Result<IpcMessage>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 1024 * 1024 {
        return Err(anyhow::anyhow!("Message too large: {} bytes", len));
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = IpcClient::new(None);
        assert_eq!(client.socket_path, DEFAULT_SOCKET_PATH);
        assert!(!client.is_connected());
    }
}
