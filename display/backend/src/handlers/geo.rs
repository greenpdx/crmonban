use std::sync::Arc;
use axum::{extract::{State, Path}, Json};
use crate::state::AppState;

pub async fn get_map_data(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "points": [
            {"lat": 39.9, "lon": 116.4, "count": 150, "country": "CN"},
            {"lat": 55.7, "lon": 37.6, "count": 89, "country": "RU"},
            {"lat": 37.5, "lon": -122.0, "count": 45, "country": "US"}
        ]
    }))
}

pub async fn top_countries(
    State(_state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "countries": [
            {"code": "CN", "name": "China", "count": 150},
            {"code": "RU", "name": "Russia", "count": 89},
            {"code": "US", "name": "United States", "count": 45}
        ]
    }))
}

pub async fn get_intel(
    State(_state): State<Arc<AppState>>,
    Path(_ip): Path<String>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "ip": "",
        "geo": {},
        "asn": {},
        "reputation": {},
        "whois": {}
    }))
}
