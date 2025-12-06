use std::sync::Arc;
use axum::{extract::{State, Query}, Json};
use crate::{models::PaginationQuery, state::AppState};

pub async fn list_scans(
    State(_state): State<Arc<AppState>>,
    Query(_params): Query<PaginationQuery>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "scans": [],
        "total": 0
    }))
}

pub async fn top_ports(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ports": [
            {"port": 22, "count": 450},
            {"port": 80, "count": 320},
            {"port": 443, "count": 280},
            {"port": 3389, "count": 150}
        ]
    }))
}
