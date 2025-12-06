use std::sync::Arc;
use axum::{extract::{State, Query}, Json};
use crate::{models::PaginationQuery, state::AppState};

pub async fn list_bans(
    State(_state): State<Arc<AppState>>,
    Query(_params): Query<PaginationQuery>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "bans": [],
        "total": 0
    }))
}

pub async fn active_bans(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "bans": [],
        "count": 0
    }))
}

pub async fn ban_stats(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "total_bans": 1234,
        "active_bans": 42,
        "bans_today": 15,
        "by_source": [
            {"source": "ssh", "count": 500},
            {"source": "nginx", "count": 300}
        ],
        "by_duration": []
    }))
}
