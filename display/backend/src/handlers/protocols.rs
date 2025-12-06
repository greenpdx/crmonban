use std::sync::Arc;
use axum::{extract::State, Json};
use crate::state::AppState;

pub async fn distribution(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "protocols": [
            {"name": "TCP", "count": 8500},
            {"name": "UDP", "count": 3200},
            {"name": "ICMP", "count": 150}
        ],
        "applications": [
            {"name": "HTTP", "count": 4500},
            {"name": "HTTPS", "count": 3000},
            {"name": "DNS", "count": 2800},
            {"name": "SSH", "count": 400}
        ]
    }))
}

pub async fn dns_stats(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "query_types": [],
        "response_codes": [],
        "top_domains": []
    }))
}

pub async fn http_stats(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "methods": [],
        "status_codes": [],
        "top_paths": [],
        "top_user_agents": []
    }))
}

pub async fn tls_stats(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "versions": [],
        "cipher_suites": [],
        "ja3_fingerprints": []
    }))
}
