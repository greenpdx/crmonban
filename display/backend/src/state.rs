use std::sync::Arc;

use sqlx::SqlitePool;
use tokio::sync::broadcast;

use crmonban::ipc::IpcMessage;

use crate::ipc_handler::IpcHandler;
use crate::models::RealtimeEvent;

pub struct AppState {
    pub db: SqlitePool,
    pub event_tx: broadcast::Sender<RealtimeEvent>,
    pub ipc_handler: Arc<IpcHandler>,
}

impl AppState {
    pub async fn new() -> anyhow::Result<Self> {
        let db_path = std::env::var("CRMONBAN_DB")
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "sqlite:///var/lib/crmonban/crmonban.db".to_string());

        let socket_path = std::env::var("CRMONBAN_SOCKET").ok();

        let db = SqlitePool::connect(&db_path).await?;
        let (event_tx, _) = broadcast::channel(1000);

        // Start IPC handler
        let ipc_handler = crate::ipc_handler::start_ipc_handler(socket_path);

        Ok(Self {
            db,
            event_tx,
            ipc_handler,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RealtimeEvent> {
        self.event_tx.subscribe()
    }

    /// Subscribe to IPC events from the daemon
    pub fn subscribe_ipc(&self) -> broadcast::Receiver<IpcMessage> {
        self.ipc_handler.subscribe()
    }
}
