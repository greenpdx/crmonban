//! Batched database writer for high-performance detection event logging
//!
//! Accumulates detection events in memory and flushes to database periodically
//! to minimize I/O overhead while maintaining audit trail.
//!
//! Uses the canonical `core::event::DetectionEvent` type from the packet engine.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use rusqlite::params;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::Database;

// Re-export the canonical event types from core
#[cfg(feature = "flow-tracking")]
pub use crate::core::event::{DetectionEvent, DetectionType, Severity};

/// Aggregated statistics for a time interval
#[derive(Debug, Clone, Default)]
pub struct IntervalStats {
    pub timestamp: DateTime<Utc>,
    pub interval_secs: u32,
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub signature_matches: u64,
    pub ml_anomalies: u64,
    pub port_scan_alerts: u64,
    pub brute_force_alerts: u64,
    pub threat_intel_hits: u64,
    pub flows_tracked: u64,
    pub latency_sum_us: u64,
    pub latency_count: u64,
    pub latency_max_us: u64,
}

impl IntervalStats {
    pub fn new(interval_secs: u32) -> Self {
        Self {
            timestamp: Utc::now(),
            interval_secs,
            ..Default::default()
        }
    }

    pub fn avg_latency_us(&self) -> f64 {
        if self.latency_count == 0 {
            0.0
        } else {
            self.latency_sum_us as f64 / self.latency_count as f64
        }
    }

    pub fn record_latency(&mut self, latency_us: u64) {
        self.latency_sum_us += latency_us;
        self.latency_count += 1;
        if latency_us > self.latency_max_us {
            self.latency_max_us = latency_us;
        }
    }
}

/// Flow record for forensic logging
#[derive(Debug, Clone)]
pub struct FlowRecord {
    pub flow_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub packets_fwd: u64,
    pub packets_bwd: u64,
    pub bytes_fwd: u64,
    pub bytes_bwd: u64,
    pub flags: Option<String>,
    pub state: Option<String>,
    pub app_protocol: Option<String>,
    pub detection_flags: Option<String>,
}

/// Configuration for the batched writer
#[derive(Debug, Clone)]
pub struct BatchedWriterConfig {
    /// Maximum events to buffer before forcing a flush
    pub max_buffer_size: usize,
    /// Maximum time between flushes
    pub flush_interval: Duration,
    /// Stats aggregation interval
    pub stats_interval: Duration,
    /// Whether to log flow records
    pub log_flows: bool,
    /// Minimum severity to log (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)
    pub min_severity: u8,
}

impl Default for BatchedWriterConfig {
    fn default() -> Self {
        Self {
            max_buffer_size: 1000,
            flush_interval: Duration::from_secs(5),
            stats_interval: Duration::from_secs(60),
            log_flows: false,
            min_severity: 2, // Medium
        }
    }
}

/// Message types for the writer channel
enum WriterMessage {
    #[cfg(feature = "flow-tracking")]
    Event(DetectionEvent),
    Stats(IntervalStats),
    Flow(FlowRecord),
    Flush,
    Shutdown,
}

/// Handle to send events to the batched writer
#[derive(Clone)]
pub struct BatchedWriterHandle {
    tx: mpsc::Sender<WriterMessage>,
    config: Arc<BatchedWriterConfig>,
    // Real-time counters (atomic for fast access)
    packets_processed: Arc<AtomicU64>,
    bytes_processed: Arc<AtomicU64>,
    events_buffered: Arc<AtomicU64>,
    flushes_completed: Arc<AtomicU64>,
}

impl BatchedWriterHandle {
    /// Record a detection event (non-blocking)
    #[cfg(feature = "flow-tracking")]
    pub fn record_event(&self, event: DetectionEvent) {
        // Convert Severity enum to u8 for comparison
        let severity_val = event.severity as u8;
        if severity_val >= self.config.min_severity {
            self.events_buffered.fetch_add(1, Ordering::Relaxed);
            let _ = self.tx.try_send(WriterMessage::Event(event));
        }
    }

    /// Record aggregated stats (non-blocking)
    pub fn record_stats(&self, stats: IntervalStats) {
        let _ = self.tx.try_send(WriterMessage::Stats(stats));
    }

    /// Record a completed flow (non-blocking)
    pub fn record_flow(&self, flow: FlowRecord) {
        if self.config.log_flows {
            let _ = self.tx.try_send(WriterMessage::Flow(flow));
        }
    }

    /// Force an immediate flush
    pub async fn flush(&self) {
        let _ = self.tx.send(WriterMessage::Flush).await;
    }

    /// Shutdown the writer gracefully
    pub async fn shutdown(&self) {
        let _ = self.tx.send(WriterMessage::Shutdown).await;
    }

    /// Increment packet counter
    pub fn inc_packets(&self, count: u64) {
        self.packets_processed.fetch_add(count, Ordering::Relaxed);
    }

    /// Increment bytes counter
    pub fn inc_bytes(&self, bytes: u64) {
        self.bytes_processed.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Get current packet count
    pub fn packets_processed(&self) -> u64 {
        self.packets_processed.load(Ordering::Relaxed)
    }

    /// Get current bytes count
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed.load(Ordering::Relaxed)
    }

    /// Get events buffered count
    pub fn events_buffered(&self) -> u64 {
        self.events_buffered.load(Ordering::Relaxed)
    }

    /// Get flush count
    pub fn flushes_completed(&self) -> u64 {
        self.flushes_completed.load(Ordering::Relaxed)
    }
}

/// Batched database writer
pub struct BatchedWriter {
    db: Database,
    config: BatchedWriterConfig,
    #[cfg(feature = "flow-tracking")]
    event_buffer: VecDeque<DetectionEvent>,
    stats_buffer: VecDeque<IntervalStats>,
    flow_buffer: VecDeque<FlowRecord>,
    last_flush: Instant,
    running: Arc<AtomicBool>,
    flushes_completed: Arc<AtomicU64>,
    events_buffered: Arc<AtomicU64>,
}

impl BatchedWriter {
    /// Create a new batched writer with the given configuration
    pub fn new(db: Database, config: BatchedWriterConfig) -> Self {
        Self {
            db,
            config,
            #[cfg(feature = "flow-tracking")]
            event_buffer: VecDeque::with_capacity(1000),
            stats_buffer: VecDeque::with_capacity(60),
            flow_buffer: VecDeque::with_capacity(1000),
            last_flush: Instant::now(),
            running: Arc::new(AtomicBool::new(true)),
            flushes_completed: Arc::new(AtomicU64::new(0)),
            events_buffered: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Start the batched writer, returns a handle for sending events
    pub fn start(db: Database, config: BatchedWriterConfig) -> BatchedWriterHandle {
        let (tx, rx) = mpsc::channel(10000);

        let packets_processed = Arc::new(AtomicU64::new(0));
        let bytes_processed = Arc::new(AtomicU64::new(0));
        let events_buffered = Arc::new(AtomicU64::new(0));
        let flushes_completed = Arc::new(AtomicU64::new(0));

        let config_arc = Arc::new(config.clone());

        let handle = BatchedWriterHandle {
            tx,
            config: config_arc,
            packets_processed,
            bytes_processed,
            events_buffered: events_buffered.clone(),
            flushes_completed: flushes_completed.clone(),
        };

        let mut writer = Self::new(db, config);
        writer.events_buffered = events_buffered;
        writer.flushes_completed = flushes_completed;

        // Spawn the writer task
        tokio::spawn(async move {
            writer.run(rx).await;
        });

        handle
    }

    /// Main run loop
    async fn run(&mut self, mut rx: mpsc::Receiver<WriterMessage>) {
        let mut flush_interval = tokio::time::interval(self.config.flush_interval);

        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        #[cfg(feature = "flow-tracking")]
                        Some(WriterMessage::Event(event)) => {
                            self.event_buffer.push_back(event);
                            if self.event_buffer.len() >= self.config.max_buffer_size {
                                self.flush();
                            }
                        }
                        Some(WriterMessage::Stats(stats)) => {
                            self.stats_buffer.push_back(stats);
                        }
                        Some(WriterMessage::Flow(flow)) => {
                            self.flow_buffer.push_back(flow);
                            if self.flow_buffer.len() >= self.config.max_buffer_size {
                                self.flush();
                            }
                        }
                        Some(WriterMessage::Flush) => {
                            self.flush();
                        }
                        Some(WriterMessage::Shutdown) | None => {
                            info!("Batched writer shutting down, flushing remaining events");
                            self.flush();
                            break;
                        }
                    }
                }
                _ = flush_interval.tick() => {
                    if self.has_pending_data() {
                        self.flush();
                    }
                }
            }
        }

        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if there's any pending data to flush
    fn has_pending_data(&self) -> bool {
        #[cfg(feature = "flow-tracking")]
        let has_events = !self.event_buffer.is_empty();
        #[cfg(not(feature = "flow-tracking"))]
        let has_events = false;

        has_events || !self.stats_buffer.is_empty() || !self.flow_buffer.is_empty()
    }

    /// Flush all buffered data to database
    fn flush(&mut self) {
        #[cfg(feature = "flow-tracking")]
        let event_count = self.event_buffer.len();
        #[cfg(not(feature = "flow-tracking"))]
        let event_count = 0usize;

        let stats_count = self.stats_buffer.len();
        let flow_count = self.flow_buffer.len();

        if event_count == 0 && stats_count == 0 && flow_count == 0 {
            return;
        }

        let start = Instant::now();

        // Flush events
        if event_count > 0 {
            if let Err(e) = self.flush_events() {
                error!("Failed to flush detection events: {}", e);
            }
        }

        // Flush stats
        if stats_count > 0 {
            if let Err(e) = self.flush_stats() {
                error!("Failed to flush detection stats: {}", e);
            }
        }

        // Flush flows
        if flow_count > 0 {
            if let Err(e) = self.flush_flows() {
                error!("Failed to flush flow records: {}", e);
            }
        }

        let elapsed = start.elapsed();
        self.flushes_completed.fetch_add(1, Ordering::Relaxed);
        self.events_buffered.fetch_sub(event_count as u64, Ordering::Relaxed);
        self.last_flush = Instant::now();

        debug!(
            "Flushed {} events, {} stats, {} flows in {:?}",
            event_count, stats_count, flow_count, elapsed
        );
    }

    /// Flush detection events to database
    #[cfg(feature = "flow-tracking")]
    fn flush_events(&mut self) -> anyhow::Result<()> {
        let conn = self.db.lock()?;

        let mut stmt = conn.prepare_cached(
            "INSERT INTO detection_events (timestamp, detection_type, src_ip, dst_ip, src_port, dst_port, protocol, severity, rule_id, rule_name, score, details, raw_packet_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )?;

        conn.execute("BEGIN TRANSACTION", [])?;

        while let Some(event) = self.event_buffer.pop_front() {
            // Serialize message and extra details as JSON
            let details_json = serde_json::json!({
                "message": event.message,
                "detector": event.detector,
                "confidence": event.confidence,
                "classtype": event.classtype,
                "mitre_attack": event.mitre_attack,
                "cve": event.cve,
                "action": event.action.to_string(),
            });

            if let Err(e) = stmt.execute(params![
                event.timestamp.to_rfc3339(),
                event.event_type.to_string(),
                event.src_ip.to_string(),
                Some(event.dst_ip.to_string()),
                event.src_port,
                event.dst_port,
                event.protocol,
                event.severity.to_string(),
                event.rule_id.map(|id| id.to_string()),
                event.rule_name,
                event.confidence as f64,
                details_json.to_string(),
                event.id.to_string(), // Use event UUID as "raw_packet_hash" for correlation
            ]) {
                warn!("Failed to insert detection event: {}", e);
            }
        }

        conn.execute("COMMIT", [])?;
        Ok(())
    }

    /// Flush detection events to database (no-op when flow-tracking is disabled)
    #[cfg(not(feature = "flow-tracking"))]
    fn flush_events(&mut self) -> anyhow::Result<()> {
        // No events to flush when flow-tracking is disabled
        Ok(())
    }

    /// Flush stats to database
    fn flush_stats(&mut self) -> anyhow::Result<()> {
        let conn = self.db.lock()?;

        let mut stmt = conn.prepare_cached(
            "INSERT INTO detection_stats (timestamp, interval_secs, packets_processed, bytes_processed, signature_matches, ml_anomalies, port_scan_alerts, brute_force_alerts, threat_intel_hits, flows_tracked, avg_latency_us, max_latency_us) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )?;

        conn.execute("BEGIN TRANSACTION", [])?;

        while let Some(stats) = self.stats_buffer.pop_front() {
            if let Err(e) = stmt.execute(params![
                stats.timestamp.to_rfc3339(),
                stats.interval_secs,
                stats.packets_processed,
                stats.bytes_processed,
                stats.signature_matches,
                stats.ml_anomalies,
                stats.port_scan_alerts,
                stats.brute_force_alerts,
                stats.threat_intel_hits,
                stats.flows_tracked,
                stats.avg_latency_us(),
                stats.latency_max_us,
            ]) {
                warn!("Failed to insert detection stats: {}", e);
            }
        }

        conn.execute("COMMIT", [])?;
        Ok(())
    }

    /// Flush flow records to database
    fn flush_flows(&mut self) -> anyhow::Result<()> {
        let conn = self.db.lock()?;

        let mut stmt = conn.prepare_cached(
            "INSERT INTO flow_records (flow_id, start_time, end_time, src_ip, dst_ip, src_port, dst_port, protocol, packets_fwd, packets_bwd, bytes_fwd, bytes_bwd, flags, state, app_protocol, detection_flags) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )?;

        conn.execute("BEGIN TRANSACTION", [])?;

        while let Some(flow) = self.flow_buffer.pop_front() {
            if let Err(e) = stmt.execute(params![
                flow.flow_id,
                flow.start_time.to_rfc3339(),
                flow.end_time.map(|t| t.to_rfc3339()),
                flow.src_ip.to_string(),
                flow.dst_ip.to_string(),
                flow.src_port,
                flow.dst_port,
                flow.protocol,
                flow.packets_fwd,
                flow.packets_bwd,
                flow.bytes_fwd,
                flow.bytes_bwd,
                flow.flags,
                flow.state,
                flow.app_protocol,
                flow.detection_flags,
            ]) {
                warn!("Failed to insert flow record: {}", e);
            }
        }

        conn.execute("COMMIT", [])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interval_stats() {
        let mut stats = IntervalStats::new(60);
        stats.record_latency(100);
        stats.record_latency(200);
        stats.record_latency(300);

        assert_eq!(stats.latency_count, 3);
        assert_eq!(stats.avg_latency_us(), 200.0);
        assert_eq!(stats.latency_max_us, 300);
    }

    #[test]
    fn test_config_default() {
        let config = BatchedWriterConfig::default();
        assert_eq!(config.max_buffer_size, 1000);
        assert_eq!(config.min_severity, 2); // Medium
        assert!(!config.log_flows);
    }
}
