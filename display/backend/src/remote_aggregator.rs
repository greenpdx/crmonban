//! Remote aggregator for connecting to multiple crmonban instances
//!
//! Allows the frontend to display aggregated data from multiple
//! crmonban daemons running on different hosts via mTLS.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{error, info, warn};

use crmonban::ipc::{
    BanInfo, IpcMessage, MetricsUpdate, StatsResponse, StatusResponse, TlsClientConfig,
    TlsIpcClient,
};

/// Configuration for a remote crmonban host
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemoteHostConfig {
    /// Display name for this host
    pub name: String,
    /// Remote address (host:port)
    pub address: String,
    /// Path to client certificate
    pub client_cert: PathBuf,
    /// Path to client private key
    pub client_key: PathBuf,
    /// Path to CA certificate for verifying server
    pub ca_cert: PathBuf,
    /// Server name for TLS verification
    #[serde(default)]
    pub server_name: Option<String>,
    /// Whether this host is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Connection status for a remote host
#[derive(Debug, Clone, Serialize)]
pub struct HostStatus {
    /// Host name
    pub name: String,
    /// Host address
    pub address: String,
    /// Connection state
    pub connected: bool,
    /// Last successful connection time
    pub last_connected: Option<i64>,
    /// Last error message
    pub last_error: Option<String>,
    /// Latest metrics from this host
    pub metrics: Option<MetricsUpdate>,
    /// Latest status from this host
    pub status: Option<StatusResponse>,
}

/// Active connection to a remote host
struct RemoteConnection {
    /// Host configuration
    config: RemoteHostConfig,
    /// TLS IPC client
    client: TlsIpcClient,
    /// Status tracking
    status: HostStatus,
    /// Shutdown sender
    shutdown_tx: mpsc::Sender<()>,
}

/// Remote aggregator manages connections to multiple crmonban instances
pub struct RemoteAggregator {
    /// Local host name (this instance)
    local_name: String,
    /// Remote host configurations
    configs: Vec<RemoteHostConfig>,
    /// Active connections (keyed by host name)
    connections: RwLock<HashMap<String, Arc<RwLock<RemoteConnection>>>>,
    /// Broadcast channel for aggregated events
    event_tx: broadcast::Sender<(String, IpcMessage)>,
    /// Cached metrics per host
    metrics_cache: Arc<RwLock<HashMap<String, MetricsUpdate>>>,
    /// Cached status per host
    status_cache: Arc<RwLock<HashMap<String, StatusResponse>>>,
}

impl RemoteAggregator {
    /// Create a new remote aggregator
    pub fn new(local_name: String, configs: Vec<RemoteHostConfig>) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            local_name,
            configs,
            connections: RwLock::new(HashMap::new()),
            event_tx,
            metrics_cache: Arc::new(RwLock::new(HashMap::new())),
            status_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the local host name
    pub fn local_name(&self) -> &str {
        &self.local_name
    }

    /// Subscribe to aggregated events from all hosts
    pub fn subscribe(&self) -> broadcast::Receiver<(String, IpcMessage)> {
        self.event_tx.subscribe()
    }

    /// Connect to all configured remote hosts
    pub async fn connect_all(&self) -> Vec<(String, Result<(), String>)> {
        let mut results = Vec::new();

        for config in &self.configs {
            if !config.enabled {
                continue;
            }

            let result = self.connect_host(config.clone()).await;
            results.push((config.name.clone(), result));
        }

        results
    }

    /// Connect to a single remote host
    async fn connect_host(&self, config: RemoteHostConfig) -> Result<(), String> {
        let name = config.name.clone();
        info!("Connecting to remote host: {} at {}", name, config.address);

        // Parse address
        let addr: SocketAddr = config
            .address
            .parse()
            .map_err(|e| format!("Invalid address: {}", e))?;

        // Determine server name for TLS
        let server_name = config
            .server_name
            .clone()
            .unwrap_or_else(|| config.address.split(':').next().unwrap_or("localhost").to_string());

        // Build TLS config
        let tls_config = TlsClientConfig {
            cert_path: config.client_cert.clone(),
            key_path: config.client_key.clone(),
            ca_path: config.ca_cert.clone(),
            server_name,
        };

        // Create client
        let mut client = TlsIpcClient::new(addr, tls_config);

        // Connect
        client
            .connect(&format!("display-{}", self.local_name))
            .await
            .map_err(|e| format!("Connection failed: {}", e))?;

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

        // Create connection state
        let status = HostStatus {
            name: name.clone(),
            address: config.address.clone(),
            connected: true,
            last_connected: Some(chrono::Utc::now().timestamp()),
            last_error: None,
            metrics: None,
            status: None,
        };

        let connection = Arc::new(RwLock::new(RemoteConnection {
            config: config.clone(),
            client,
            status,
            shutdown_tx,
        }));

        // Store connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(name.clone(), connection.clone());
        }

        // Spawn receiver task
        let event_tx = self.event_tx.clone();
        let metrics_cache = self.metrics_cache.clone();
        let status_cache = self.status_cache.clone();
        let host_name = name.clone();

        tokio::spawn(async move {
            Self::receive_loop(
                host_name,
                connection,
                event_tx,
                metrics_cache,
                status_cache,
                shutdown_rx,
            )
            .await;
        });

        info!("Connected to remote host: {}", name);
        Ok(())
    }

    /// Receive loop for a single remote host
    async fn receive_loop(
        host_name: String,
        connection: Arc<RwLock<RemoteConnection>>,
        event_tx: broadcast::Sender<(String, IpcMessage)>,
        metrics_cache: Arc<RwLock<HashMap<String, MetricsUpdate>>>,
        status_cache: Arc<RwLock<HashMap<String, StatusResponse>>>,
        mut shutdown_rx: mpsc::Receiver<()>,
    ) {
        let mut event_rx = {
            let mut conn = connection.write().await;
            match conn.client.receiver() {
                Some(rx) => rx,
                None => {
                    error!("No receiver for host {}", host_name);
                    return;
                }
            }
        };

        loop {
            tokio::select! {
                msg = event_rx.recv() => {
                    match msg {
                        Some(ipc_msg) => {
                            // Update caches based on message type
                            match &ipc_msg {
                                IpcMessage::Metrics(m) => {
                                    let mut cache = metrics_cache.write().await;
                                    cache.insert(host_name.clone(), m.clone());
                                }
                                IpcMessage::StatusResponse(s) => {
                                    let mut cache = status_cache.write().await;
                                    cache.insert(host_name.clone(), s.clone());
                                }
                                _ => {}
                            }

                            // Forward to subscribers
                            let _ = event_tx.send((host_name.clone(), ipc_msg));
                        }
                        None => {
                            warn!("Remote host {} disconnected", host_name);
                            let mut conn = connection.write().await;
                            conn.status.connected = false;
                            conn.status.last_error = Some("Connection closed".to_string());
                            break;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutting down connection to {}", host_name);
                    break;
                }
            }
        }
    }

    /// Disconnect from a specific host
    pub async fn disconnect_host(&self, name: &str) {
        let mut connections = self.connections.write().await;
        if let Some(conn) = connections.remove(name) {
            let mut conn = conn.write().await;
            conn.client.disconnect().await;
            info!("Disconnected from remote host: {}", name);
        }
    }

    /// Disconnect from all hosts
    pub async fn disconnect_all(&self) {
        let mut connections = self.connections.write().await;
        for (name, conn) in connections.drain() {
            let mut conn = conn.write().await;
            conn.client.disconnect().await;
            info!("Disconnected from remote host: {}", name);
        }
    }

    /// Get status of all remote hosts
    pub async fn get_host_statuses(&self) -> Vec<HostStatus> {
        let connections = self.connections.read().await;
        let mut statuses = Vec::new();

        // Add configured but not connected hosts
        for config in &self.configs {
            if !config.enabled {
                continue;
            }

            if let Some(conn) = connections.get(&config.name) {
                let conn = conn.read().await;
                statuses.push(conn.status.clone());
            } else {
                statuses.push(HostStatus {
                    name: config.name.clone(),
                    address: config.address.clone(),
                    connected: false,
                    last_connected: None,
                    last_error: Some("Not connected".to_string()),
                    metrics: None,
                    status: None,
                });
            }
        }

        statuses
    }

    /// Get aggregated metrics from all connected hosts
    pub async fn get_aggregated_metrics(&self) -> HashMap<String, MetricsUpdate> {
        self.metrics_cache.read().await.clone()
    }

    /// Get aggregated bans from all connected hosts
    pub async fn get_aggregated_bans(
        &self,
        _include_expired: bool,
        _limit: Option<u32>,
    ) -> HashMap<String, Vec<BanInfo>> {
        let connections = self.connections.read().await;
        let mut results = HashMap::new();

        for (name, _conn) in connections.iter() {
            // Request bans from each host
            // TODO: Implement request/response pattern
            // For now, return cached data or empty
            results.insert(name.clone(), Vec::new());
        }

        results
    }

    /// Get aggregated stats from all connected hosts
    pub async fn get_aggregated_stats(&self) -> HashMap<String, StatsResponse> {
        let connections = self.connections.read().await;
        let mut results = HashMap::new();

        for (name, _conn) in connections.iter() {
            // TODO: Implement request/response pattern
            results.insert(
                name.clone(),
                StatsResponse {
                    request_id: None,
                    total_bans: 0,
                    active_bans: 0,
                    total_events: 0,
                    events_today: 0,
                    events_this_hour: 0,
                    events_by_service: Vec::new(),
                    top_countries: Vec::new(),
                    top_asns: Vec::new(),
                },
            );
        }

        results
    }

    /// Check if any remote hosts are configured
    pub fn has_remote_hosts(&self) -> bool {
        self.configs.iter().any(|c| c.enabled)
    }

    /// Get number of connected hosts
    pub async fn connected_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Reconnect to a disconnected host
    pub async fn reconnect_host(&self, name: &str) -> Result<(), String> {
        // Find config
        let config = self
            .configs
            .iter()
            .find(|c| c.name == name)
            .cloned()
            .ok_or_else(|| format!("Unknown host: {}", name))?;

        // Disconnect first if connected
        self.disconnect_host(name).await;

        // Reconnect
        self.connect_host(config).await
    }

    /// Start auto-reconnect background task
    pub fn start_auto_reconnect(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;

                // Check each configured host
                for config in &self.configs {
                    if !config.enabled {
                        continue;
                    }

                    let connected = {
                        let connections = self.connections.read().await;
                        connections.contains_key(&config.name)
                    };

                    if !connected {
                        info!("Auto-reconnecting to {}", config.name);
                        if let Err(e) = self.connect_host(config.clone()).await {
                            warn!("Auto-reconnect to {} failed: {}", config.name, e);
                        }
                    }
                }
            }
        });
    }
}

/// Aggregated overview combining local and remote data
#[derive(Debug, Clone, Serialize)]
pub struct AggregatedOverview {
    /// Data per host
    pub hosts: Vec<HostOverview>,
    /// Combined totals
    pub totals: OverviewTotals,
}

/// Overview data for a single host
#[derive(Debug, Clone, Serialize)]
pub struct HostOverview {
    /// Host name
    pub name: String,
    /// Whether this is the local host
    pub is_local: bool,
    /// Whether connected
    pub connected: bool,
    /// Active bans on this host
    pub active_bans: u64,
    /// Events today on this host
    pub events_today: u64,
    /// Packets per second
    pub packets_per_sec: f64,
    /// Events per second
    pub events_per_sec: f64,
}

/// Combined totals across all hosts
#[derive(Debug, Clone, Serialize)]
pub struct OverviewTotals {
    /// Total hosts
    pub total_hosts: usize,
    /// Connected hosts
    pub connected_hosts: usize,
    /// Total active bans across all hosts
    pub total_active_bans: u64,
    /// Total events today across all hosts
    pub total_events_today: u64,
    /// Combined packets per second
    pub total_packets_per_sec: f64,
    /// Combined events per second
    pub total_events_per_sec: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregator_creation() {
        let configs = vec![RemoteHostConfig {
            name: "test-host".to_string(),
            address: "192.168.1.1:3002".to_string(),
            client_cert: PathBuf::from("/etc/crmonban/client.crt"),
            client_key: PathBuf::from("/etc/crmonban/client.key"),
            ca_cert: PathBuf::from("/etc/crmonban/ca.crt"),
            server_name: None,
            enabled: true,
        }];

        let aggregator = RemoteAggregator::new("local".to_string(), configs);
        assert!(aggregator.has_remote_hosts());
        assert_eq!(aggregator.local_name(), "local");
    }
}
