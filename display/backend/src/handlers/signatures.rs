use std::sync::Arc;
use axum::{extract::{State, Query}, Json};
use crate::{models::PaginationQuery, state::AppState};

pub async fn list_rules(
    State(_state): State<Arc<AppState>>,
    Query(_params): Query<PaginationQuery>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "rules": [],
        "total": 0
    }))
}

pub async fn match_stats(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "total_matches": 0,
        "by_rule": [],
        "by_classtype": [],
        "by_priority": []
    }))
}
