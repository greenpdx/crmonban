use std::sync::Arc;
use axum::{extract::{State, Query}, Json};
use crate::{models::PaginationQuery, state::AppState};

pub async fn get_status(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "running": true,
        "pid": 1234,
        "uptime_secs": 86400,
        "active_bans": 42,
        "monitored_services": ["ssh", "nginx", "postfix"]
    }))
}

pub async fn get_config(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "general": {},
        "port_scan": {},
        "dpi": {},
        "dns": {}
    }))
}

pub async fn activity_log(
    State(_state): State<Arc<AppState>>,
    Query(_params): Query<PaginationQuery>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "activities": [],
        "total": 0
    }))
}
