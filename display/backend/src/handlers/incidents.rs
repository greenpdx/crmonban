use std::sync::Arc;
use axum::{extract::{State, Path, Query}, Json};
use crate::{models::PaginationQuery, state::AppState};

pub async fn list_incidents(
    State(_state): State<Arc<AppState>>,
    Query(_params): Query<PaginationQuery>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "incidents": [],
        "total": 0
    }))
}

pub async fn get_incident(
    State(_state): State<Arc<AppState>>,
    Path(_id): Path<String>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({}))
}

pub async fn get_timeline(
    State(_state): State<Arc<AppState>>,
    Path(_id): Path<String>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "events": [],
        "attack_chain": null
    }))
}
