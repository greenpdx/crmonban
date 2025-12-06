use sqlx::SqlitePool;
use tokio::sync::broadcast;

use crate::models::RealtimeEvent;

pub struct AppState {
    pub db: SqlitePool,
    pub event_tx: broadcast::Sender<RealtimeEvent>,
}

impl AppState {
    pub async fn new() -> anyhow::Result<Self> {
        let db_path = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite:///var/lib/crmonban/crmonban.db".to_string());

        let db = SqlitePool::connect(&db_path).await?;
        let (event_tx, _) = broadcast::channel(1000);

        Ok(Self { db, event_tx })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RealtimeEvent> {
        self.event_tx.subscribe()
    }
}
