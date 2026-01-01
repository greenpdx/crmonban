use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sqlx::SqlitePool;
use tokio::sync::broadcast;
use tracing::info;

use crmonban::ipc::IpcMessage;

use crate::ipc_handler::IpcHandler;
use crate::models::RealtimeEvent;
use crate::remote_aggregator::{RemoteAggregator, RemoteHostConfig};

pub struct AppState {
    pub db: SqlitePool,
    pub event_tx: broadcast::Sender<RealtimeEvent>,
    pub ipc_handler: Arc<IpcHandler>,
    pub remote_aggregator: Arc<RemoteAggregator>,
}

impl AppState {
    pub async fn new() -> anyhow::Result<Self> {
        let db_path = std::env::var("CRMONBAN_DB")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "sqlite:///var/lib/crmonban/crmonban.db".to_string());

        let socket_path = std::env::var("CRMONBAN_SOCKET").ok();

        let db = SqlitePool::connect(&db_path).await?;
        let (event_tx, _) = broadcast::channel(1000);

        // Start IPC handler for local daemon
        let ipc_handler = crate::ipc_handler::start_ipc_handler(socket_path);

        // Load remote host configuration
        let local_name = std::env::var("CRMONBAN_LOCAL_NAME")
            .unwrap_or_else(|_| hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "local".to_string()));

        let remote_configs = Self::load_remote_configs();
        let remote_aggregator = Arc::new(RemoteAggregator::new(local_name, remote_configs));

        // Start auto-reconnect for remote hosts
        if remote_aggregator.has_remote_hosts() {
            info!("Starting remote aggregator with auto-reconnect");
            remote_aggregator.clone().start_auto_reconnect(Duration::from_secs(30));

            // Connect to all configured hosts
            let aggregator = remote_aggregator.clone();
            tokio::spawn(async move {
                let results = aggregator.connect_all().await;
                for (name, result) in results {
                    match result {
                        Ok(()) => info!("Connected to remote host: {}", name),
                        Err(e) => tracing::warn!("Failed to connect to {}: {}", name, e),
                    }
                }
            });
        }

        Ok(Self {
            db,
            event_tx,
            ipc_handler,
            remote_aggregator,
        })
    }

    /// Load remote host configurations from environment or config file
    fn load_remote_configs() -> Vec<RemoteHostConfig> {
        // Try to load from config file first
        if let Ok(config_path) = std::env::var("CRMONBAN_REMOTE_CONFIG") {
            if let Ok(content) = std::fs::read_to_string(&config_path) {
                if let Ok(configs) = serde_json::from_str::<Vec<RemoteHostConfig>>(&content) {
                    return configs;
                }
            }
        }

        // Fall back to environment-based configuration
        // Format: CRMONBAN_REMOTE_HOSTS="name1:addr1,name2:addr2"
        // with CRMONBAN_REMOTE_CERT, CRMONBAN_REMOTE_KEY, CRMONBAN_REMOTE_CA
        let mut configs = Vec::new();

        if let Ok(hosts) = std::env::var("CRMONBAN_REMOTE_HOSTS") {
            let cert_path = std::env::var("CRMONBAN_REMOTE_CERT")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/crmonban/client.crt"));
            let key_path = std::env::var("CRMONBAN_REMOTE_KEY")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/crmonban/client.key"));
            let ca_path = std::env::var("CRMONBAN_REMOTE_CA")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/crmonban/ca.crt"));

            for host in hosts.split(',') {
                let parts: Vec<&str> = host.trim().split(':').collect();
                if parts.len() >= 2 {
                    let name = parts[0].to_string();
                    let address = if parts.len() == 3 {
                        format!("{}:{}", parts[1], parts[2])
                    } else {
                        format!("{}:3002", parts[1])
                    };

                    configs.push(RemoteHostConfig {
                        name,
                        address,
                        client_cert: cert_path.clone(),
                        client_key: key_path.clone(),
                        ca_cert: ca_path.clone(),
                        server_name: None,
                        enabled: true,
                    });
                }
            }
        }

        configs
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RealtimeEvent> {
        self.event_tx.subscribe()
    }

    /// Subscribe to IPC events from the daemon
    pub fn subscribe_ipc(&self) -> broadcast::Receiver<IpcMessage> {
        self.ipc_handler.subscribe()
    }

    /// Subscribe to aggregated events from all remote hosts
    pub fn subscribe_remote(&self) -> broadcast::Receiver<(String, IpcMessage)> {
        self.remote_aggregator.subscribe()
    }

    /// Check if remote hosts are configured
    pub fn has_remote_hosts(&self) -> bool {
        self.remote_aggregator.has_remote_hosts()
    }
}
