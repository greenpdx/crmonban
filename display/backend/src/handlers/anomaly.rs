use std::sync::Arc;
use axum::{extract::State, Json};
use crate::state::AppState;

pub async fn get_scores(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "current_score": 0.23,
        "threshold": 0.7,
        "history": []
    }))
}

pub async fn get_features(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    // Spider chart data for feature importance
    Json(serde_json::json!({
        "labels": [
            "flow_duration", "fwd_packets", "bwd_packets",
            "fwd_bytes", "bwd_bytes", "flow_rate",
            "iat_mean", "pkt_size_mean"
        ],
        "current": [0.3, 0.5, 0.4, 0.6, 0.5, 0.2, 0.8, 0.4],
        "baseline": [0.2, 0.3, 0.3, 0.4, 0.4, 0.2, 0.5, 0.3]
    }))
}

pub async fn get_baseline(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "sample_count": 10000,
        "features": {}
    }))
}
