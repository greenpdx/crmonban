use std::net::SocketAddr;
use std::sync::Arc;

use axum::{routing::get, Router};
use tower_http::cors::{Any, CorsLayer};
use tower_http::compression::CompressionLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod api;
mod handlers;
mod ipc_handler;
mod models;
mod state;

use state::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let state = Arc::new(AppState::new().await?);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        // Overview
        .route("/api/overview", get(handlers::overview::get_overview))
        .route("/api/overview/stats", get(handlers::overview::get_stats))
        // Real-time metrics
        .route("/api/metrics/live", get(handlers::metrics::live_metrics))
        .route("/api/metrics/history", get(handlers::metrics::history))
        // Events
        .route("/api/events", get(handlers::events::list_events))
        .route("/api/events/{id}", get(handlers::events::get_event))
        .route("/api/events/stream", get(handlers::events::event_stream))
        // Flows
        .route("/api/flows", get(handlers::flows::list_flows))
        .route("/api/flows/{id}", get(handlers::flows::get_flow))
        .route("/api/flows/{id}/stats", get(handlers::flows::get_flow_stats))
        // Anomaly/ML
        .route("/api/anomaly/scores", get(handlers::anomaly::get_scores))
        .route("/api/anomaly/features", get(handlers::anomaly::get_features))
        .route("/api/anomaly/baseline", get(handlers::anomaly::get_baseline))
        // Geo/Intel
        .route("/api/geo/map", get(handlers::geo::get_map_data))
        .route("/api/geo/countries", get(handlers::geo::top_countries))
        .route("/api/intel/{ip}", get(handlers::geo::get_intel))
        // Bans
        .route("/api/bans", get(handlers::bans::list_bans))
        .route("/api/bans/active", get(handlers::bans::active_bans))
        .route("/api/bans/stats", get(handlers::bans::ban_stats))
        // Incidents
        .route("/api/incidents", get(handlers::incidents::list_incidents))
        .route("/api/incidents/{id}", get(handlers::incidents::get_incident))
        .route("/api/incidents/{id}/timeline", get(handlers::incidents::get_timeline))
        // Protocols
        .route("/api/protocols/distribution", get(handlers::protocols::distribution))
        .route("/api/protocols/dns", get(handlers::protocols::dns_stats))
        .route("/api/protocols/http", get(handlers::protocols::http_stats))
        .route("/api/protocols/tls", get(handlers::protocols::tls_stats))
        // Signatures
        .route("/api/signatures", get(handlers::signatures::list_rules))
        .route("/api/signatures/matches", get(handlers::signatures::match_stats))
        // Scans
        .route("/api/scans", get(handlers::scans::list_scans))
        .route("/api/scans/ports", get(handlers::scans::top_ports))
        // System
        .route("/api/system/status", get(handlers::system::get_status))
        .route("/api/system/config", get(handlers::system::get_config))
        .route("/api/system/activity", get(handlers::system::activity_log))
        // WebSocket for real-time
        .route("/ws", get(handlers::websocket::ws_handler))
        .layer(cors)
        .layer(CompressionLayer::new())
        .with_state(state);

    let port: u16 = std::env::var("CRMONBAN_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(3001);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Dashboard API listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
