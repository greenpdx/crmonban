//! Feedback daemon for continuous detection tuning
//!
//! Runs a background loop that periodically:
//! 1. Parses service logs to extract ground truth events
//! 2. Loads detection events from the crmonban database
//! 3. Correlates and computes accuracy metrics
//! 4. Auto-adjusts detection parameters (if enabled)
//! 5. Generates periodic reports

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use notify::{Config as NotifyConfig, Event, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::database::Database;

use super::adjuster::{AdjusterConfig, AdjustmentStrategy, ConfigChange, ParameterAdjuster};
use super::analyzer::{FeedbackAnalyzer, FeedbackConfig, FeedbackReport, SafeBounds};
use super::correlation::DetectionEvent;
use super::log_parsers::{LogEvent, LogParser, NginxAccessParser, PostfixParser, Service, SshdLogParser};

/// Configuration for the feedback daemon
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// How often to run analysis (default: 1 hour)
    pub analysis_interval: Duration,
    /// Log file paths by service type
    pub log_paths: HashMap<Service, PathBuf>,
    /// Path to crmonban database
    pub database_path: PathBuf,
    /// Path to crmonban config (for applying changes)
    pub config_path: Option<PathBuf>,
    /// Enable automatic parameter adjustment
    pub auto_adjust: bool,
    /// Dry run mode (don't apply changes)
    pub dry_run: bool,
    /// Adjustment strategy
    pub strategy: AdjustmentStrategy,
    /// FP rate threshold for alerts
    pub fp_threshold: f64,
    /// FN rate threshold for alerts
    pub fn_threshold: f64,
    /// Directory to write reports
    pub report_dir: Option<PathBuf>,
    /// Safe bounds for adjustments
    pub safe_bounds: SafeBounds,
    /// Analysis window for each cycle
    pub analysis_window: Duration,
    /// Notify on significant changes
    pub notify_on_change: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        let mut log_paths = HashMap::new();
        log_paths.insert(Service::Sshd, PathBuf::from("/var/log/auth.log"));
        log_paths.insert(Service::NginxAccess, PathBuf::from("/var/log/nginx/access.log"));
        log_paths.insert(Service::Postfix, PathBuf::from("/var/log/mail.log"));

        Self {
            analysis_interval: Duration::from_secs(3600), // 1 hour
            log_paths,
            database_path: PathBuf::from("/var/lib/crmonban/crmonban.db"),
            config_path: None,
            auto_adjust: false,
            dry_run: true,
            strategy: AdjustmentStrategy::Conservative,
            fp_threshold: 0.05,
            fn_threshold: 0.10,
            report_dir: None,
            safe_bounds: SafeBounds::default(),
            analysis_window: Duration::from_secs(24 * 3600), // 24 hours
            notify_on_change: true,
        }
    }
}

/// State for tracking log file positions
struct LogFileState {
    path: PathBuf,
    position: u64,
    parser: Box<dyn LogParser>,
}

impl LogFileState {
    fn new(path: PathBuf, parser: Box<dyn LogParser>) -> Self {
        Self {
            path,
            position: 0,
            parser,
        }
    }

    /// Read new events from the log file
    fn read_new_events(&mut self) -> anyhow::Result<Vec<LogEvent>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        // Handle log rotation
        if file_size < self.position {
            info!("Log file {} rotated, resetting position", self.path.display());
            self.position = 0;
        }

        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(self.position))?;

        let mut events = Vec::new();
        let mut line = String::new();

        while reader.read_line(&mut line)? > 0 {
            if let Some(event) = self.parser.parse_line(&line) {
                events.push(event);
            }
            line.clear();
        }

        self.position = reader.stream_position()?;
        Ok(events)
    }

    /// Read all events within a time window (for initial analysis)
    fn read_events_in_window(&mut self, window: Duration) -> anyhow::Result<Vec<LogEvent>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let cutoff = Utc::now() - chrono::Duration::from_std(window)?;

        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);

        let mut events = Vec::new();

        for line_result in reader.lines() {
            let line = line_result?;
            if let Some(event) = self.parser.parse_line(&line) {
                if event.timestamp >= cutoff {
                    events.push(event);
                }
            }
        }

        // Update position to end of file
        self.position = File::open(&self.path)?.metadata()?.len();

        Ok(events)
    }
}

/// Feedback daemon state
pub struct FeedbackDaemon {
    config: DaemonConfig,
    log_states: Vec<LogFileState>,
    analyzer: FeedbackAnalyzer,
    adjuster: ParameterAdjuster,
    /// Accumulated log events since last analysis
    event_buffer: Vec<LogEvent>,
    /// Last analysis time
    last_analysis: Option<Instant>,
    /// Applied changes history
    change_history: Vec<ChangeRecord>,
    /// Shutdown channel
    shutdown_rx: Option<mpsc::Receiver<()>>,
}

/// Record of an applied change
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeRecord {
    pub timestamp: DateTime<Utc>,
    pub change: ConfigChange,
    pub trigger: String,
}

impl FeedbackDaemon {
    /// Create a new feedback daemon
    pub fn new(config: DaemonConfig) -> Self {
        // Create log file states with parsers
        let mut log_states = Vec::new();

        for (service, path) in &config.log_paths {
            let parser: Box<dyn LogParser> = match service {
                Service::Sshd => Box::new(SshdLogParser::new()),
                Service::NginxAccess => Box::new(NginxAccessParser::new()),
                Service::NginxError => Box::new(super::log_parsers::NginxErrorParser::new()),
                Service::Postfix => Box::new(PostfixParser::new()),
                Service::Dovecot => Box::new(PostfixParser::new()), // Use postfix parser as fallback
                Service::Custom => continue, // Skip custom services for now
            };

            if path.exists() {
                log_states.push(LogFileState::new(path.clone(), parser));
                info!("Monitoring {} at {}", service, path.display());
            } else {
                warn!("Log file not found: {}", path.display());
            }
        }

        // Create analyzer
        let feedback_config = FeedbackConfig {
            analysis_window: config.analysis_window,
            time_tolerance: Duration::from_secs(5),
            min_samples: 50,
            fp_threshold: config.fp_threshold,
            fn_threshold: config.fn_threshold,
            auto_adjust: config.auto_adjust,
            safe_bounds: config.safe_bounds.clone(),
        };
        let analyzer = FeedbackAnalyzer::new(feedback_config);

        // Create adjuster
        let adjuster_config = AdjusterConfig {
            safe_bounds: config.safe_bounds.clone(),
            strategy: config.strategy,
            dry_run: config.dry_run,
        };
        let adjuster = ParameterAdjuster::with_config(adjuster_config);

        Self {
            config,
            log_states,
            analyzer,
            adjuster,
            event_buffer: Vec::new(),
            last_analysis: None,
            change_history: Vec::new(),
            shutdown_rx: None,
        }
    }

    /// Set the shutdown receiver
    pub fn with_shutdown(mut self, rx: mpsc::Receiver<()>) -> Self {
        self.shutdown_rx = Some(rx);
        self
    }

    /// Run the daemon
    pub async fn run(&mut self) -> anyhow::Result<()> {
        info!("Starting feedback daemon");
        info!(
            "Analysis interval: {:?}, Auto-adjust: {}, Dry-run: {}",
            self.config.analysis_interval, self.config.auto_adjust, self.config.dry_run
        );

        // Do initial analysis with full window
        if let Err(e) = self.run_initial_analysis().await {
            warn!("Initial analysis failed: {}", e);
        }

        // Set up file watcher
        let (watcher_tx, mut watcher_rx) = mpsc::channel::<Result<Event, notify::Error>>(100);

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = watcher_tx.blocking_send(res);
            },
            NotifyConfig::default(),
        )?;

        // Watch parent directories of log files
        let mut watched_dirs = std::collections::HashSet::new();
        for state in &self.log_states {
            if let Some(parent) = state.path.parent() {
                if watched_dirs.insert(parent.to_path_buf()) {
                    if parent.exists() {
                        watcher.watch(parent, RecursiveMode::NonRecursive)?;
                        debug!("Watching directory: {}", parent.display());
                    }
                }
            }
        }

        let mut analysis_timer = tokio::time::interval(self.config.analysis_interval);
        let mut poll_timer = tokio::time::interval(Duration::from_secs(30));

        info!("Feedback daemon started, entering main loop");

        loop {
            tokio::select! {
                // Handle file change events
                Some(res) = watcher_rx.recv() => {
                    match res {
                        Ok(event) => {
                            self.handle_file_event(&event);
                        }
                        Err(e) => {
                            error!("File watcher error: {}", e);
                        }
                    }
                }

                // Periodic polling for new log entries
                _ = poll_timer.tick() => {
                    self.poll_log_files();
                }

                // Periodic analysis
                _ = analysis_timer.tick() => {
                    if let Err(e) = self.run_analysis().await {
                        error!("Analysis failed: {}", e);
                    }
                }

                // Handle shutdown
                Some(_) = async {
                    if let Some(ref mut rx) = self.shutdown_rx {
                        rx.recv().await
                    } else {
                        std::future::pending::<Option<()>>().await
                    }
                } => {
                    info!("Shutdown signal received");
                    break;
                }
            }
        }

        info!("Feedback daemon stopped");
        Ok(())
    }

    /// Handle a file change event
    fn handle_file_event(&mut self, event: &Event) {
        for state in &mut self.log_states {
            let dominated = event.paths.iter().any(|p| {
                p.ends_with(state.path.file_name().unwrap_or_default())
            });

            if dominated {
                match state.read_new_events() {
                    Ok(events) => {
                        debug!(
                            "Read {} new events from {}",
                            events.len(),
                            state.path.display()
                        );
                        self.event_buffer.extend(events);
                    }
                    Err(e) => {
                        error!("Error reading {}: {}", state.path.display(), e);
                    }
                }
            }
        }
    }

    /// Poll all log files for new events
    fn poll_log_files(&mut self) {
        for state in &mut self.log_states {
            match state.read_new_events() {
                Ok(events) => {
                    if !events.is_empty() {
                        debug!(
                            "Polled {} new events from {}",
                            events.len(),
                            state.path.display()
                        );
                        self.event_buffer.extend(events);
                    }
                }
                Err(e) => {
                    error!("Error polling {}: {}", state.path.display(), e);
                }
            }
        }
    }

    /// Run initial analysis with full analysis window
    async fn run_initial_analysis(&mut self) -> anyhow::Result<()> {
        info!("Running initial analysis with {:?} window", self.config.analysis_window);

        // Read events from all log files within the analysis window
        let mut all_events = Vec::new();
        for state in &mut self.log_states {
            match state.read_events_in_window(self.config.analysis_window) {
                Ok(events) => {
                    info!(
                        "Read {} events from {} for initial analysis",
                        events.len(),
                        state.path.display()
                    );
                    all_events.extend(events);
                }
                Err(e) => {
                    warn!("Error reading {}: {}", state.path.display(), e);
                }
            }
        }

        // Load detection events
        let detections = self.load_detections()?;

        // Run analysis
        let report = self.analyzer.analyze(&all_events, &detections)?;
        self.handle_report(&report).await?;

        self.last_analysis = Some(Instant::now());

        Ok(())
    }

    /// Run periodic analysis
    async fn run_analysis(&mut self) -> anyhow::Result<()> {
        let event_count = self.event_buffer.len();
        info!("Running periodic analysis with {} buffered events", event_count);

        // Load detection events
        let detections = self.load_detections()?;

        // Run analysis
        let report = self.analyzer.analyze(&self.event_buffer, &detections)?;
        self.handle_report(&report).await?;

        // Clear buffer
        self.event_buffer.clear();
        self.last_analysis = Some(Instant::now());

        Ok(())
    }

    /// Load detection events from database
    fn load_detections(&self) -> anyhow::Result<Vec<DetectionEvent>> {
        if !self.config.database_path.exists() {
            warn!("Database not found: {}", self.config.database_path.display());
            return Ok(Vec::new());
        }

        let db = Database::open(&self.config.database_path)?;

        // Calculate time window
        let end_time = Utc::now();
        let window_duration = chrono::Duration::from_std(self.config.analysis_window)?;
        let start_time = end_time - window_duration;

        // Get recent activity as proxy for detection events
        let activity = db.get_recent_activity(10000)?;

        let events: Vec<DetectionEvent> = activity
            .into_iter()
            .filter(|a| a.timestamp >= start_time && a.timestamp <= end_time)
            .filter_map(|a| {
                // Only include ban events as "detections"
                if !matches!(a.action, crate::models::ActivityAction::Ban) {
                    return None;
                }

                let ip = a.ip?;

                Some(DetectionEvent {
                    id: a.id.map(|i| i.to_string()).unwrap_or_default(),
                    timestamp: a.timestamp,
                    src_ip: ip,
                    dst_ip: None,
                    detection_type: infer_detection_type(&a.details),
                    module: infer_module(&a.details),
                    confidence: 0.9,
                    severity: 5,
                    rule_id: None,
                    details: HashMap::new(),
                })
            })
            .collect();

        info!("Loaded {} detection events from database", events.len());
        Ok(events)
    }

    /// Handle analysis report
    async fn handle_report(&mut self, report: &FeedbackReport) -> anyhow::Result<()> {
        // Log summary
        info!(
            "Analysis complete: Precision={:.1}%, Recall={:.1}%, F1={:.1}%",
            report.summary.precision * 100.0,
            report.summary.recall * 100.0,
            report.summary.f1_score * 100.0
        );

        // Check thresholds
        let fp_exceeded = report.summary.fp_rate > self.config.fp_threshold;
        let fn_exceeded = report.summary.fn_rate > self.config.fn_threshold;

        if fp_exceeded {
            warn!(
                "FP rate ({:.1}%) exceeds threshold ({:.1}%)",
                report.summary.fp_rate * 100.0,
                self.config.fp_threshold * 100.0
            );
        }

        if fn_exceeded {
            warn!(
                "FN rate ({:.1}%) exceeds threshold ({:.1}%)",
                report.summary.fn_rate * 100.0,
                self.config.fn_threshold * 100.0
            );
        }

        // Save report if report_dir is configured
        if let Some(ref report_dir) = self.config.report_dir {
            self.save_report(report, report_dir)?;
        }

        // Handle auto-adjustment
        if self.config.auto_adjust && (fp_exceeded || fn_exceeded) {
            self.handle_auto_adjust(report)?;
        }

        Ok(())
    }

    /// Save report to file
    fn save_report(&self, report: &FeedbackReport, report_dir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(report_dir)?;

        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let filename = format!("feedback_report_{}.json", timestamp);
        let path = report_dir.join(filename);

        let json = report.to_json();
        std::fs::write(&path, json)?;

        info!("Report saved to {}", path.display());
        Ok(())
    }

    /// Handle automatic parameter adjustment
    fn handle_auto_adjust(&mut self, report: &FeedbackReport) -> anyhow::Result<()> {
        let mut changes = self.adjuster.recommend(&report.per_module);

        if changes.is_empty() {
            info!("No parameter adjustments recommended");
            return Ok(());
        }

        info!("Recommended {} parameter adjustments", changes.len());
        info!("{}", ParameterAdjuster::summarize_changes(&changes));

        if let Some(ref config_path) = self.config.config_path {
            if !self.config.dry_run {
                self.adjuster.apply_to_file(&mut changes, config_path)?;

                // Record changes
                for change in &changes {
                    if change.applied {
                        self.change_history.push(ChangeRecord {
                            timestamp: Utc::now(),
                            change: change.clone(),
                            trigger: format!(
                                "FP={:.1}%, FN={:.1}%",
                                report.summary.fp_rate * 100.0,
                                report.summary.fn_rate * 100.0
                            ),
                        });
                    }
                }

                info!("Applied {} changes to {}",
                    changes.iter().filter(|c| c.applied).count(),
                    config_path.display()
                );
            } else {
                info!("Dry run - changes not applied");
            }
        } else {
            info!("No config path configured - changes not applied");
        }

        Ok(())
    }

    /// Get change history
    pub fn change_history(&self) -> &[ChangeRecord] {
        &self.change_history
    }

    /// Get current event buffer size
    pub fn buffer_size(&self) -> usize {
        self.event_buffer.len()
    }

    /// Get time since last analysis
    pub fn time_since_analysis(&self) -> Option<Duration> {
        self.last_analysis.map(|t| t.elapsed())
    }
}

/// Infer detection type from activity details
fn infer_detection_type(details: &str) -> String {
    let lower = details.to_lowercase();

    if lower.contains("brute") || lower.contains("auth") || lower.contains("password") {
        "brute_force".to_string()
    } else if lower.contains("scan") || lower.contains("port") {
        "scan".to_string()
    } else if lower.contains("http") || lower.contains("web") || lower.contains("sql") {
        "web_attack".to_string()
    } else if lower.contains("dos") || lower.contains("flood") {
        "dos".to_string()
    } else {
        "unknown".to_string()
    }
}

/// Infer detection module from activity details
fn infer_module(details: &str) -> String {
    let lower = details.to_lowercase();

    if lower.contains("http") || lower.contains("nginx") || lower.contains("web") {
        "http_detect".to_string()
    } else if lower.contains("signature") || lower.contains("rule") {
        "signatures".to_string()
    } else {
        "layer234".to_string()
    }
}

/// Builder for daemon configuration
pub struct DaemonConfigBuilder {
    config: DaemonConfig,
}

impl DaemonConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: DaemonConfig::default(),
        }
    }

    pub fn analysis_interval(mut self, interval: Duration) -> Self {
        self.config.analysis_interval = interval;
        self
    }

    pub fn log_path(mut self, service: Service, path: PathBuf) -> Self {
        self.config.log_paths.insert(service, path);
        self
    }

    pub fn database_path(mut self, path: PathBuf) -> Self {
        self.config.database_path = path;
        self
    }

    pub fn config_path(mut self, path: PathBuf) -> Self {
        self.config.config_path = Some(path);
        self
    }

    pub fn auto_adjust(mut self, enabled: bool) -> Self {
        self.config.auto_adjust = enabled;
        self
    }

    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.config.dry_run = enabled;
        self
    }

    pub fn strategy(mut self, strategy: AdjustmentStrategy) -> Self {
        self.config.strategy = strategy;
        self
    }

    pub fn fp_threshold(mut self, threshold: f64) -> Self {
        self.config.fp_threshold = threshold;
        self
    }

    pub fn fn_threshold(mut self, threshold: f64) -> Self {
        self.config.fn_threshold = threshold;
        self
    }

    pub fn report_dir(mut self, path: PathBuf) -> Self {
        self.config.report_dir = Some(path);
        self
    }

    pub fn analysis_window(mut self, window: Duration) -> Self {
        self.config.analysis_window = window;
        self
    }

    pub fn build(self) -> DaemonConfig {
        self.config
    }
}

impl Default for DaemonConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_config_builder() {
        let config = DaemonConfigBuilder::new()
            .analysis_interval(Duration::from_secs(1800))
            .auto_adjust(true)
            .dry_run(false)
            .fp_threshold(0.03)
            .build();

        assert_eq!(config.analysis_interval, Duration::from_secs(1800));
        assert!(config.auto_adjust);
        assert!(!config.dry_run);
        assert_eq!(config.fp_threshold, 0.03);
    }

    #[test]
    fn test_infer_detection_type() {
        assert_eq!(infer_detection_type("brute force attack"), "brute_force");
        assert_eq!(infer_detection_type("port scan detected"), "scan");
        assert_eq!(infer_detection_type("SQL injection attempt"), "web_attack");
        assert_eq!(infer_detection_type("something else"), "unknown");
    }

    #[test]
    fn test_infer_module() {
        assert_eq!(infer_module("HTTP request blocked"), "http_detect");
        assert_eq!(infer_module("signature match: sid 1234"), "signatures");
        assert_eq!(infer_module("SSH brute force"), "layer234");
    }
}
