use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeEvent {
    pub event_type: String,
    pub data: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct OverviewStats {
    pub active_bans: u64,
    pub events_today: u64,
    pub events_hour: u64,
    pub packets_per_sec: f64,
    pub events_per_sec: f64,
    pub worker_utilization: f64,
    pub threat_level: String,
}

#[derive(Debug, Serialize)]
pub struct TimeSeriesPoint {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
}

#[derive(Debug, Serialize)]
pub struct CategoryCount {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct GeoPoint {
    pub lat: f64,
    pub lon: f64,
    pub count: u64,
    pub country: String,
}

#[derive(Debug, Serialize)]
pub struct EventSummary {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub severity: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct FlowSummary {
    pub id: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub state: String,
    pub packets: u64,
    pub bytes: u64,
    pub risk_score: f32,
}

#[derive(Debug, Serialize)]
pub struct RadarData {
    pub labels: Vec<String>,
    pub values: Vec<f32>,
}

#[derive(Debug, Serialize)]
pub struct IncidentSummary {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub priority: String,
    pub status: String,
    pub event_count: usize,
    pub start_time: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct BanSummary {
    pub ip: String,
    pub reason: String,
    pub source: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub ban_count: u32,
}

#[derive(Debug, Serialize)]
pub struct SystemStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub uptime_secs: u64,
    pub active_bans: u64,
    pub monitored_services: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TimeRangeQuery {
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}
