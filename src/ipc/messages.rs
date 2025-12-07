//! IPC message types for daemon-display communication
//!
//! Wire format: [4 bytes: length (big-endian)][JSON payload]

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Message envelope with type discrimination
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum IpcMessage {
    /// Handshake from client
    Hello(HelloMessage),
    /// Handshake response from server
    Welcome(WelcomeMessage),
    /// Real-time metrics update
    Metrics(MetricsUpdate),
    /// Security event (attack detected)
    Event(SecurityEvent),
    /// Ban added/removed
    Ban(BanEvent),
    /// Scan detection alert
    Scan(ScanEvent),
    /// Flow update
    Flow(FlowEvent),
    /// System status change
    System(SystemEvent),
    /// Heartbeat (keep-alive)
    Ping,
    /// Heartbeat response
    Pong,

    // === Request/Response Messages ===

    /// Request: Get list of active bans
    GetBans(GetBansRequest),
    /// Response: List of bans
    BansResponse(BansResponse),

    /// Request: Get attack statistics
    GetStats,
    /// Response: Statistics
    StatsResponse(StatsResponse),

    /// Request: Get intelligence for an IP
    GetIntel(GetIntelRequest),
    /// Response: IP intelligence
    IntelResponse(IntelResponse),

    /// Request: Get recent events
    GetEvents(GetEventsRequest),
    /// Response: List of events
    EventsResponse(EventsResponse),

    /// Request: Get daemon status
    GetStatus,
    /// Response: Daemon status
    StatusResponse(StatusResponse),

    /// Request: Get configuration
    GetConfig,
    /// Response: Configuration
    ConfigResponse(ConfigResponse),

    /// Request: Perform action (ban/unban)
    Action(ActionRequest),
    /// Response: Action result
    ActionResponse(ActionResponse),

    /// Error response
    Error(ErrorResponse),
}

/// Client hello message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    /// Protocol version
    pub version: u8,
    /// Client identifier
    pub client_id: String,
    /// Subscriptions (empty = all)
    pub subscriptions: Vec<String>,
}

/// Server welcome message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeMessage {
    /// Protocol version
    pub version: u8,
    /// Server uptime in seconds
    pub uptime_secs: u64,
    /// Current active ban count
    pub active_bans: u64,
    /// Events processed
    pub events_processed: u64,
}

/// Real-time metrics update (sent every second)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsUpdate {
    /// Timestamp (Unix epoch millis)
    pub timestamp: i64,
    /// Packets per second
    pub packets_per_sec: f64,
    /// Events per second
    pub events_per_sec: f64,
    /// Active connections
    pub active_connections: u64,
    /// Active bans
    pub active_bans: u64,
    /// CPU usage (0.0 - 1.0)
    pub cpu_usage: f32,
    /// Memory usage bytes
    pub memory_bytes: u64,
    /// Bytes per second (in)
    pub bytes_in_per_sec: u64,
    /// Bytes per second (out)
    pub bytes_out_per_sec: u64,
}

/// Security event (attack detected)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Event ID
    pub id: String,
    /// Timestamp
    pub timestamp: i64,
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination port
    pub dst_port: Option<u16>,
    /// Service name
    pub service: String,
    /// Event type (e.g., "ssh_brute_force")
    pub event_type: String,
    /// Severity (1-10)
    pub severity: u8,
    /// Description
    pub description: String,
    /// Was IP banned?
    pub banned: bool,
}

/// Ban event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanEvent {
    /// Action: "add" or "remove"
    pub action: String,
    /// IP address
    pub ip: IpAddr,
    /// Reason (for add)
    pub reason: Option<String>,
    /// Source (monitor, manual, scan, etc.)
    pub source: Option<String>,
    /// Duration in seconds (None = permanent)
    pub duration_secs: Option<u32>,
    /// Timestamp
    pub timestamp: i64,
}

/// Scan detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanEvent {
    /// Source IP
    pub src_ip: IpAddr,
    /// Classification (suspicious, probable_scan, confirmed, etc.)
    pub classification: String,
    /// Score
    pub score: f32,
    /// Unique ports scanned
    pub ports_scanned: u32,
    /// Scan type (syn, stealth, null, xmas, etc.)
    pub scan_type: Option<String>,
    /// Top triggered rules
    pub top_rules: Vec<String>,
    /// Timestamp
    pub timestamp: i64,
}

/// Flow event (new flow, flow closed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEvent {
    /// Action: "new", "update", "closed"
    pub action: String,
    /// Flow ID
    pub flow_id: String,
    /// Source IP
    pub src_ip: IpAddr,
    /// Source port
    pub src_port: u16,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Destination port
    pub dst_port: u16,
    /// Protocol (tcp, udp, icmp)
    pub protocol: String,
    /// Bytes transferred
    pub bytes: u64,
    /// Packets
    pub packets: u64,
    /// Application protocol detected
    pub app_protocol: Option<String>,
    /// Timestamp
    pub timestamp: i64,
}

/// System event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemEvent {
    /// Event type: "started", "stopping", "config_reload", etc.
    pub event_type: String,
    /// Details
    pub details: Option<String>,
    /// Timestamp
    pub timestamp: i64,
}

// === Request/Response Types ===

/// Request: Get bans with optional filters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBansRequest {
    /// Request ID for correlation
    pub request_id: String,
    /// Filter by IP (optional)
    pub ip_filter: Option<String>,
    /// Include expired bans
    #[serde(default)]
    pub include_expired: bool,
    /// Limit results
    pub limit: Option<u32>,
}

/// Response: List of bans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BansResponse {
    /// Request ID for correlation
    pub request_id: String,
    /// List of bans
    pub bans: Vec<BanInfo>,
    /// Total count (may be more than returned if limited)
    pub total: u64,
}

/// Ban information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanInfo {
    /// IP address
    pub ip: IpAddr,
    /// Reason for ban
    pub reason: String,
    /// Source of ban
    pub source: String,
    /// Created timestamp
    pub created_at: i64,
    /// Expires timestamp (None = permanent)
    pub expires_at: Option<i64>,
    /// Number of times banned
    pub ban_count: u32,
    /// Country (if known)
    pub country: Option<String>,
    /// ASN (if known)
    pub asn: Option<String>,
}

/// Response: Statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsResponse {
    /// Request ID for correlation
    pub request_id: Option<String>,
    /// Total bans ever
    pub total_bans: u64,
    /// Currently active bans
    pub active_bans: u64,
    /// Total events recorded
    pub total_events: u64,
    /// Events in last 24 hours
    pub events_today: u64,
    /// Events in last hour
    pub events_this_hour: u64,
    /// Events by service
    pub events_by_service: Vec<(String, u64)>,
    /// Top countries by attacks
    pub top_countries: Vec<(String, u64)>,
    /// Top ASNs by attacks
    pub top_asns: Vec<(String, u64)>,
}

/// Request: Get intel for IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetIntelRequest {
    /// Request ID for correlation
    pub request_id: String,
    /// IP address to look up
    pub ip: String,
    /// Force refresh (don't use cache)
    #[serde(default)]
    pub refresh: bool,
}

/// Response: IP intelligence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelResponse {
    /// Request ID for correlation
    pub request_id: String,
    /// IP address
    pub ip: String,
    /// GeoIP info
    pub geo: Option<GeoInfo>,
    /// WHOIS info
    pub whois: Option<WhoisInfo>,
    /// Reverse DNS
    pub rdns: Option<String>,
    /// Threat score (0-100)
    pub threat_score: Option<u8>,
    /// Abuse reports
    pub abuse_reports: Option<u32>,
    /// Open ports (from Shodan if available)
    pub open_ports: Vec<u16>,
    /// Tags/categories
    pub tags: Vec<String>,
    /// Last updated
    pub last_updated: Option<i64>,
}

/// GeoIP information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub timezone: Option<String>,
}

/// WHOIS information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisInfo {
    pub asn: Option<String>,
    pub org: Option<String>,
    pub isp: Option<String>,
    pub cidr: Option<String>,
    pub abuse_email: Option<String>,
}

/// Request: Get recent events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetEventsRequest {
    /// Request ID for correlation
    pub request_id: String,
    /// Maximum events to return
    #[serde(default = "default_events_limit")]
    pub limit: u32,
    /// Offset for pagination
    #[serde(default)]
    pub offset: u32,
    /// Filter by service
    pub service: Option<String>,
    /// Filter by event type
    pub event_type: Option<String>,
    /// Filter by IP
    pub ip: Option<String>,
    /// Since timestamp (Unix millis)
    pub since: Option<i64>,
}

fn default_events_limit() -> u32 {
    100
}

/// Response: List of events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsResponse {
    /// Request ID for correlation
    pub request_id: String,
    /// List of events
    pub events: Vec<EventInfo>,
    /// Total count
    pub total: u64,
    /// Has more
    pub has_more: bool,
}

/// Event information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInfo {
    /// Event ID
    pub id: String,
    /// Timestamp
    pub timestamp: i64,
    /// Source IP
    pub ip: IpAddr,
    /// Service
    pub service: String,
    /// Event type
    pub event_type: String,
    /// Details
    pub details: Option<String>,
    /// Resulted in ban
    pub banned: bool,
}

/// Response: Daemon status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Request ID for correlation
    pub request_id: Option<String>,
    /// Daemon is running
    pub running: bool,
    /// Process ID
    pub pid: u32,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Active bans count
    pub active_bans: u64,
    /// Events processed
    pub events_processed: u64,
    /// Monitored services
    pub monitored_services: Vec<String>,
    /// Connected IPC clients
    pub ipc_clients: u64,
    /// Memory usage bytes
    pub memory_bytes: u64,
    /// CPU usage (0.0 - 1.0)
    pub cpu_usage: f32,
}

/// Response: Configuration summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigResponse {
    /// Request ID for correlation
    pub request_id: Option<String>,
    /// Configured services
    pub services: Vec<ServiceSummary>,
    /// Port scan detection enabled
    pub port_scan_enabled: bool,
    /// DPI enabled
    pub dpi_enabled: bool,
    /// D-Bus enabled
    pub dbus_enabled: bool,
    /// Default ban duration
    pub default_ban_duration: i64,
    /// Auto intel gathering
    pub auto_intel: bool,
}

/// Service configuration summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSummary {
    pub name: String,
    pub enabled: bool,
    pub log_path: String,
    pub max_failures: u32,
    pub find_time: u64,
    pub ban_time: i64,
}

/// Request: Perform action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRequest {
    /// Request ID for correlation
    pub request_id: String,
    /// Action type
    pub action: ActionType,
}

/// Action types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "params")]
pub enum ActionType {
    /// Ban an IP
    Ban {
        ip: IpAddr,
        reason: String,
        duration_secs: Option<i64>,
    },
    /// Unban an IP
    Unban { ip: IpAddr },
    /// Add to whitelist
    Whitelist { ip: IpAddr, comment: Option<String> },
    /// Remove from whitelist
    UnWhitelist { ip: IpAddr },
    /// Refresh intel for IP
    RefreshIntel { ip: String },
}

/// Response: Action result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResponse {
    /// Request ID for correlation
    pub request_id: String,
    /// Success
    pub success: bool,
    /// Message
    pub message: String,
}

/// Error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Request ID for correlation
    pub request_id: Option<String>,
    /// Error code
    pub code: String,
    /// Error message
    pub message: String,
}

impl IpcMessage {
    /// Serialize to wire format: [4-byte length][JSON]
    pub fn to_wire(&self) -> Result<Vec<u8>, serde_json::Error> {
        let json = serde_json::to_vec(self)?;
        let len = json.len() as u32;
        let mut wire = Vec::with_capacity(4 + json.len());
        wire.extend_from_slice(&len.to_be_bytes());
        wire.extend(json);
        Ok(wire)
    }

    /// Deserialize from JSON bytes (without length prefix)
    pub fn from_json(data: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_format() {
        let msg = IpcMessage::Ping;
        let wire = msg.to_wire().unwrap();

        // First 4 bytes are length
        let len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
        assert_eq!(len, wire.len() - 4);

        // Deserialize payload
        let parsed = IpcMessage::from_json(&wire[4..]).unwrap();
        assert!(matches!(parsed, IpcMessage::Ping));
    }

    #[test]
    fn test_metrics_serialization() {
        let metrics = MetricsUpdate {
            timestamp: 1234567890,
            packets_per_sec: 1000.5,
            events_per_sec: 10.2,
            active_connections: 42,
            active_bans: 5,
            cpu_usage: 0.25,
            memory_bytes: 1024 * 1024 * 100,
            bytes_in_per_sec: 10000,
            bytes_out_per_sec: 5000,
        };

        let msg = IpcMessage::Metrics(metrics);
        let wire = msg.to_wire().unwrap();
        let parsed = IpcMessage::from_json(&wire[4..]).unwrap();

        if let IpcMessage::Metrics(m) = parsed {
            assert_eq!(m.packets_per_sec, 1000.5);
            assert_eq!(m.active_bans, 5);
        } else {
            panic!("Expected Metrics");
        }
    }
}
