use std::sync::Arc;
use axum::{extract::State, Json};
use crate::{models::OverviewStats, state::AppState};

pub async fn get_overview(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "stats": {
            "active_bans": 42,
            "events_today": 1523,
            "events_hour": 89,
            "packets_per_sec": 12500.0,
            "events_per_sec": 2.3,
            "worker_utilization": 0.45
        },
        "threat_level": "medium",
        "top_threats": [
            {"type": "BruteForce", "count": 45},
            {"type": "PortScan", "count": 23},
            {"type": "ExploitAttempt", "count": 12}
        ],
        "recent_incidents": []
    }))
}

pub async fn get_stats(
    State(_state): State<Arc<AppState>>,
) -> Json<OverviewStats> {
    Json(OverviewStats {
        active_bans: 42,
        events_today: 1523,
        events_hour: 89,
        packets_per_sec: 12500.0,
        events_per_sec: 2.3,
        worker_utilization: 0.45,
        threat_level: "medium".to_string(),
    })
}
