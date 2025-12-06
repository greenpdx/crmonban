use std::sync::Arc;
use axum::{extract::{State, Query}, Json};
use crate::{models::TimeRangeQuery, state::AppState};

pub async fn live_metrics(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "pps": 12500,
        "eps": 2.3,
        "bps": 125000000,
        "active_flows": 4521,
        "worker_util": 0.45,
        "flow_hit_rate": 0.92
    }))
}

pub async fn history(
    State(_state): State<Arc<AppState>>,
    Query(_params): Query<TimeRangeQuery>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "pps": [],
        "eps": [],
        "interval": "1m"
    }))
}
