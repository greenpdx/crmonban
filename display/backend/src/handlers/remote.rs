//! Handlers for remote host management and aggregated data

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;

use crate::remote_aggregator::{AggregatedOverview, HostOverview, OverviewTotals};
use crate::state::AppState;

/// Query parameters for aggregation
#[derive(Debug, Deserialize)]
pub struct AggregateQuery {
    /// Include remote hosts in response
    #[serde(default = "default_true")]
    pub include_remote: bool,
}

fn default_true() -> bool {
    true
}

/// Get status of all remote hosts
pub async fn list_remote_hosts(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let statuses = state.remote_aggregator.get_host_statuses().await;
    let connected = state.remote_aggregator.connected_count().await;

    Json(serde_json::json!({
        "local_name": state.remote_aggregator.local_name(),
        "remote_hosts": statuses,
        "connected_count": connected,
        "total_count": statuses.len()
    }))
}

/// Reconnect to a specific remote host
pub async fn reconnect_host(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Json<serde_json::Value> {
    match state.remote_aggregator.reconnect_host(&name).await {
        Ok(()) => Json(serde_json::json!({
            "success": true,
            "message": format!("Reconnected to {}", name)
        })),
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": e
        })),
    }
}

/// Get aggregated overview from all hosts
pub async fn aggregated_overview(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AggregateQuery>,
) -> Json<AggregatedOverview> {
    let mut hosts = Vec::new();
    let mut total_bans = 0u64;
    let total_events = 0u64;
    let mut total_pps = 0.0f64;
    let mut total_eps = 0.0f64;
    let mut connected_count = 0usize;

    // Add local host
    // TODO: Get actual local metrics from IPC handler
    hosts.push(HostOverview {
        name: state.remote_aggregator.local_name().to_string(),
        is_local: true,
        connected: true, // Local is always "connected"
        active_bans: 0,
        events_today: 0,
        packets_per_sec: 0.0,
        events_per_sec: 0.0,
    });
    connected_count += 1;

    // Add remote hosts if requested
    if params.include_remote && state.has_remote_hosts() {
        let metrics = state.remote_aggregator.get_aggregated_metrics().await;
        let statuses = state.remote_aggregator.get_host_statuses().await;

        for status in statuses {
            let is_connected = status.connected;
            if is_connected {
                connected_count += 1;
            }

            let (active_bans, events_today, pps, eps) = if let Some(m) = metrics.get(&status.name) {
                (m.active_bans, 0, m.packets_per_sec, m.events_per_sec)
            } else {
                (0, 0, 0.0, 0.0)
            };

            total_bans += active_bans;
            total_pps += pps;
            total_eps += eps;

            hosts.push(HostOverview {
                name: status.name,
                is_local: false,
                connected: is_connected,
                active_bans,
                events_today,
                packets_per_sec: pps,
                events_per_sec: eps,
            });
        }
    }

    let host_count = hosts.len();

    Json(AggregatedOverview {
        hosts,
        totals: OverviewTotals {
            total_hosts: host_count,
            connected_hosts: connected_count,
            total_active_bans: total_bans,
            total_events_today: total_events,
            total_packets_per_sec: total_pps,
            total_events_per_sec: total_eps,
        },
    })
}

/// Get aggregated bans from all hosts
pub async fn aggregated_bans(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AggregateQuery>,
) -> Json<serde_json::Value> {
    let mut all_bans = Vec::new();

    // TODO: Get local bans from database

    // Get remote bans if requested
    if params.include_remote && state.has_remote_hosts() {
        let remote_bans = state
            .remote_aggregator
            .get_aggregated_bans(false, Some(100))
            .await;

        for (host, bans) in remote_bans {
            for ban in bans {
                all_bans.push(serde_json::json!({
                    "host": host,
                    "ip": ban.ip.to_string(),
                    "reason": ban.reason,
                    "source": ban.source,
                    "created_at": ban.created_at,
                    "expires_at": ban.expires_at,
                    "ban_count": ban.ban_count,
                }));
            }
        }
    }

    Json(serde_json::json!({
        "bans": all_bans,
        "total": all_bans.len()
    }))
}

/// Get aggregated metrics from all hosts
pub async fn aggregated_metrics(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let metrics = state.remote_aggregator.get_aggregated_metrics().await;

    let hosts: Vec<serde_json::Value> = metrics
        .iter()
        .map(|(name, m)| {
            serde_json::json!({
                "host": name,
                "packets_per_sec": m.packets_per_sec,
                "events_per_sec": m.events_per_sec,
                "active_connections": m.active_connections,
                "active_bans": m.active_bans,
                "cpu_usage": m.cpu_usage,
                "memory_bytes": m.memory_bytes,
                "bytes_in_per_sec": m.bytes_in_per_sec,
                "bytes_out_per_sec": m.bytes_out_per_sec,
            })
        })
        .collect();

    Json(serde_json::json!({
        "hosts": hosts,
        "timestamp": chrono::Utc::now().timestamp()
    }))
}
