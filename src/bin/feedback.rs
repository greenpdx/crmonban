//! Feedback analysis CLI tool
//!
//! Analyzes service logs against crmonban detections to measure accuracy
//! and generate tuning recommendations.
//!
//! Usage:
//!   crmonban-feedback analyze [OPTIONS]
//!   crmonban-feedback status
//!   crmonban-feedback apply --config <PATH>
//!
//! Examples:
//!   # Analyze last 24 hours
//!   crmonban-feedback analyze --window 24 -o report.md
//!
//!   # Analyze with auto-adjustment in dry-run mode
//!   crmonban-feedback analyze --auto-adjust --dry-run
//!
//!   # Apply recommended changes to config
//!   crmonban-feedback apply --config /etc/crmonban/crmonban.toml

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use clap::{Parser, Subcommand};
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use crmonban::database::Database;
use crmonban::feedback::{
    AdjusterConfig, AdjustmentStrategy, DaemonConfig, FeedbackAnalyzer,
    FeedbackConfig, FeedbackDaemon, NginxAccessParser, ParameterAdjuster, PostfixParser,
    SafeBounds, Service, SshdLogParser,
};
use crmonban::feedback::correlation::DetectionEvent;

#[derive(Parser)]
#[command(name = "crmonban-feedback")]
#[command(about = "Log-based feedback system for detection tuning")]
#[command(version)]
struct Cli {
    /// Verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze logs vs detections, generate report
    Analyze {
        /// Analysis window in hours (default: 24)
        #[arg(short, long, default_value = "24")]
        window: u64,

        /// Output report file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format: text, json, markdown (default: text)
        #[arg(short, long, default_value = "text")]
        format: String,

        /// Path to auth.log (sshd)
        #[arg(long, default_value = "/var/log/auth.log")]
        auth_log: PathBuf,

        /// Path to nginx access log
        #[arg(long, default_value = "/var/log/nginx/access.log")]
        nginx_access: PathBuf,

        /// Path to mail.log (postfix)
        #[arg(long)]
        mail_log: Option<PathBuf>,

        /// Path to crmonban database
        #[arg(long, default_value = "/var/lib/crmonban/crmonban.db")]
        database: PathBuf,

        /// Enable automatic parameter adjustment
        #[arg(long)]
        auto_adjust: bool,

        /// Dry run mode (don't apply changes)
        #[arg(long)]
        dry_run: bool,

        /// Adjustment strategy: conservative, moderate, aggressive
        #[arg(long, default_value = "conservative")]
        strategy: String,

        /// Path to crmonban config (for applying changes)
        #[arg(long)]
        config: Option<PathBuf>,

        /// FP rate threshold for alerts (percentage)
        #[arg(long, default_value = "5.0")]
        fp_threshold: f64,

        /// FN rate threshold for alerts (percentage)
        #[arg(long, default_value = "10.0")]
        fn_threshold: f64,
    },

    /// Run continuous feedback daemon
    Daemon {
        /// Analysis interval in minutes (default: 60)
        #[arg(short, long, default_value = "60")]
        interval: u64,

        /// Path to auth.log (sshd)
        #[arg(long, default_value = "/var/log/auth.log")]
        auth_log: PathBuf,

        /// Path to nginx access log
        #[arg(long, default_value = "/var/log/nginx/access.log")]
        nginx_access: PathBuf,

        /// Path to mail.log (postfix)
        #[arg(long)]
        mail_log: Option<PathBuf>,

        /// Path to crmonban database
        #[arg(long, default_value = "/var/lib/crmonban/crmonban.db")]
        database: PathBuf,

        /// Path to crmonban config (for applying changes)
        #[arg(long)]
        config: Option<PathBuf>,

        /// Enable automatic parameter adjustment
        #[arg(long)]
        auto_adjust: bool,

        /// Dry run mode (don't apply changes)
        #[arg(long)]
        dry_run: bool,

        /// Adjustment strategy: conservative, moderate, aggressive
        #[arg(long, default_value = "conservative")]
        strategy: String,

        /// FP rate threshold for alerts (percentage)
        #[arg(long, default_value = "5.0")]
        fp_threshold: f64,

        /// FN rate threshold for alerts (percentage)
        #[arg(long, default_value = "10.0")]
        fn_threshold: f64,

        /// Directory to write periodic reports
        #[arg(long)]
        report_dir: Option<PathBuf>,

        /// Analysis window in hours (default: 24)
        #[arg(long, default_value = "24")]
        window: u64,
    },

    /// Show current detection accuracy stats
    Status {
        /// Path to crmonban database
        #[arg(long, default_value = "/var/lib/crmonban/crmonban.db")]
        database: PathBuf,
    },

    /// Apply recommended changes to config
    Apply {
        /// Path to crmonban config file
        #[arg(short, long)]
        config: PathBuf,

        /// Dry run mode (show changes without applying)
        #[arg(long)]
        dry_run: bool,

        /// Changes file (JSON with recommended changes)
        #[arg(short, long)]
        changes: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let level = match cli.verbose {
        0 => Level::WARN,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set tracing subscriber")?;

    match cli.command {
        Commands::Analyze {
            window,
            output,
            format,
            auth_log,
            nginx_access,
            mail_log,
            database,
            auto_adjust,
            dry_run,
            strategy,
            config,
            fp_threshold,
            fn_threshold,
        } => {
            run_analyze(
                window,
                output,
                format,
                auth_log,
                nginx_access,
                mail_log,
                database,
                auto_adjust,
                dry_run,
                strategy,
                config,
                fp_threshold,
                fn_threshold,
            )
        }
        Commands::Daemon {
            interval,
            auth_log,
            nginx_access,
            mail_log,
            database,
            config,
            auto_adjust,
            dry_run,
            strategy,
            fp_threshold,
            fn_threshold,
            report_dir,
            window,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(run_daemon(
                interval,
                auth_log,
                nginx_access,
                mail_log,
                database,
                config,
                auto_adjust,
                dry_run,
                strategy,
                fp_threshold,
                fn_threshold,
                report_dir,
                window,
            ))
        }
        Commands::Status { database } => run_status(database),
        Commands::Apply {
            config,
            dry_run,
            changes,
        } => run_apply(config, dry_run, changes),
    }
}

fn run_analyze(
    window: u64,
    output: Option<PathBuf>,
    format: String,
    auth_log: PathBuf,
    nginx_access: PathBuf,
    mail_log: Option<PathBuf>,
    database: PathBuf,
    auto_adjust: bool,
    dry_run: bool,
    strategy: String,
    config: Option<PathBuf>,
    fp_threshold: f64,
    fn_threshold: f64,
) -> Result<()> {
    info!("Starting feedback analysis...");
    info!("Analysis window: {} hours", window);

    // Create analyzer config
    let feedback_config = FeedbackConfig {
        analysis_window: Duration::from_secs(window * 3600),
        time_tolerance: Duration::from_secs(5),
        min_samples: 50,
        fp_threshold: fp_threshold / 100.0,
        fn_threshold: fn_threshold / 100.0,
        auto_adjust,
        safe_bounds: SafeBounds::default(),
    };

    // Create analyzer with parsers
    let mut analyzer = FeedbackAnalyzer::new(feedback_config);
    analyzer.add_parser(Box::new(SshdLogParser::new()));
    analyzer.add_parser(Box::new(NginxAccessParser::new()));
    analyzer.add_parser(Box::new(PostfixParser::new()));

    // Parse log files
    let mut log_paths: Vec<&Path> = Vec::new();
    if auth_log.exists() {
        log_paths.push(&auth_log);
        info!("Including auth.log: {}", auth_log.display());
    } else {
        warn!("Auth log not found: {}", auth_log.display());
    }

    if nginx_access.exists() {
        log_paths.push(&nginx_access);
        info!("Including nginx access log: {}", nginx_access.display());
    } else {
        warn!("Nginx access log not found: {}", nginx_access.display());
    }

    if let Some(ref mail) = mail_log {
        if mail.exists() {
            log_paths.push(mail);
            info!("Including mail.log: {}", mail.display());
        }
    }

    if log_paths.is_empty() {
        anyhow::bail!("No log files found to analyze");
    }

    let log_events = analyzer.parse_log_files(&log_paths)?;
    info!("Parsed {} log events", log_events.len());

    // Load detection events from database
    let detections = load_detections(&database, window)?;
    info!("Loaded {} detection events", detections.len());

    // Run analysis
    let report = analyzer.analyze(&log_events, &detections)?;

    // Format and output report
    let report_text = match format.as_str() {
        "json" => report.to_json(),
        "markdown" | "md" => report.to_markdown(),
        _ => report.to_text(),
    };

    if let Some(output_path) = output {
        std::fs::write(&output_path, &report_text)?;
        info!("Report written to: {}", output_path.display());
    } else {
        println!("{}", report_text);
    }

    // Handle auto-adjustment
    if auto_adjust {
        let adj_strategy = match strategy.as_str() {
            "moderate" => AdjustmentStrategy::Moderate,
            "aggressive" => AdjustmentStrategy::Aggressive,
            _ => AdjustmentStrategy::Conservative,
        };

        let adjuster_config = AdjusterConfig {
            safe_bounds: SafeBounds::default(),
            strategy: adj_strategy,
            dry_run,
        };

        let adjuster = ParameterAdjuster::with_config(adjuster_config);
        let mut changes = adjuster.recommend(&report.per_module);

        if !changes.is_empty() {
            println!("\n{}", ParameterAdjuster::summarize_changes(&changes));

            if let Some(config_path) = config {
                if !dry_run {
                    adjuster.apply_to_file(&mut changes, &config_path)?;
                    info!("Changes applied to: {}", config_path.display());
                } else {
                    info!("Dry run - changes not applied");
                }

                // Save changes to JSON for later application
                let changes_json = serde_json::to_string_pretty(&changes)?;
                let changes_path = config_path.with_extension("changes.json");
                std::fs::write(&changes_path, changes_json)?;
                info!("Changes saved to: {}", changes_path.display());
            }
        }
    }

    // Print summary
    println!("\nAnalysis complete:");
    println!("  Precision: {:.1}%", report.summary.precision * 100.0);
    println!("  Recall:    {:.1}%", report.summary.recall * 100.0);
    println!("  F1 Score:  {:.1}%", report.summary.f1_score * 100.0);

    if report.summary.fp_rate > fp_threshold / 100.0 {
        println!(
            "  WARNING: FP rate ({:.1}%) exceeds threshold ({:.1}%)",
            report.summary.fp_rate * 100.0,
            fp_threshold
        );
    }

    if report.summary.fn_rate > fn_threshold / 100.0 {
        println!(
            "  WARNING: FN rate ({:.1}%) exceeds threshold ({:.1}%)",
            report.summary.fn_rate * 100.0,
            fn_threshold
        );
    }

    Ok(())
}

async fn run_daemon(
    interval: u64,
    auth_log: PathBuf,
    nginx_access: PathBuf,
    mail_log: Option<PathBuf>,
    database: PathBuf,
    config: Option<PathBuf>,
    auto_adjust: bool,
    dry_run: bool,
    strategy: String,
    fp_threshold: f64,
    fn_threshold: f64,
    report_dir: Option<PathBuf>,
    window: u64,
) -> Result<()> {
    info!("Starting feedback daemon...");

    // Build log paths
    let mut log_paths = HashMap::new();
    if auth_log.exists() {
        log_paths.insert(Service::Sshd, auth_log.clone());
        info!("Monitoring auth.log: {}", auth_log.display());
    }
    if nginx_access.exists() {
        log_paths.insert(Service::NginxAccess, nginx_access.clone());
        info!("Monitoring nginx access log: {}", nginx_access.display());
    }
    if let Some(ref mail) = mail_log {
        if mail.exists() {
            log_paths.insert(Service::Postfix, mail.clone());
            info!("Monitoring mail.log: {}", mail.display());
        }
    }

    if log_paths.is_empty() {
        anyhow::bail!("No log files found to monitor");
    }

    // Parse strategy
    let adj_strategy = match strategy.as_str() {
        "moderate" => AdjustmentStrategy::Moderate,
        "aggressive" => AdjustmentStrategy::Aggressive,
        _ => AdjustmentStrategy::Conservative,
    };

    // Build daemon config
    let daemon_config = DaemonConfig {
        analysis_interval: Duration::from_secs(interval * 60),
        log_paths,
        database_path: database,
        config_path: config,
        auto_adjust,
        dry_run,
        strategy: adj_strategy,
        fp_threshold: fp_threshold / 100.0,
        fn_threshold: fn_threshold / 100.0,
        report_dir,
        safe_bounds: SafeBounds::default(),
        analysis_window: Duration::from_secs(window * 3600),
        notify_on_change: true,
    };

    // Create and run daemon
    let mut daemon = FeedbackDaemon::new(daemon_config);

    // Set up signal handler for graceful shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);

    // Handle Ctrl+C
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        if let Ok(()) = tokio::signal::ctrl_c().await {
            info!("Received Ctrl+C, initiating shutdown...");
            let _ = shutdown_tx_clone.send(()).await;
        }
    });

    daemon = daemon.with_shutdown(shutdown_rx);

    // Run the daemon
    daemon.run().await?;

    info!("Feedback daemon stopped");
    Ok(())
}

fn run_status(database: PathBuf) -> Result<()> {
    if !database.exists() {
        anyhow::bail!("Database not found: {}", database.display());
    }

    let db = Database::open(&database)?;

    // Get recent stats
    let stats = db.get_stats()?;

    println!("Detection Status");
    println!("────────────────────────────────");
    println!("Total bans:        {}", stats.total_bans);
    println!("Active bans:       {}", stats.active_bans);
    println!("Total events:      {}", stats.total_events);
    println!("Events today:      {}", stats.events_today);
    println!("Events this hour:  {}", stats.events_this_hour);

    if !stats.events_by_service.is_empty() {
        println!("\nEvents by service:");
        for (service, count) in &stats.events_by_service {
            println!("  {:15} {:>6}", service, count);
        }
    }

    Ok(())
}

fn run_apply(config: PathBuf, dry_run: bool, changes_path: PathBuf) -> Result<()> {
    if !config.exists() {
        anyhow::bail!("Config file not found: {}", config.display());
    }

    if !changes_path.exists() {
        anyhow::bail!("Changes file not found: {}", changes_path.display());
    }

    // Load changes
    let changes_json = std::fs::read_to_string(&changes_path)?;
    let mut changes: Vec<crmonban::feedback::ConfigChange> = serde_json::from_str(&changes_json)?;

    if changes.is_empty() {
        println!("No changes to apply.");
        return Ok(());
    }

    println!("Changes to apply:");
    println!("{}", ParameterAdjuster::summarize_changes(&changes));

    if dry_run {
        println!("\nDry run mode - no changes applied.");
        return Ok(());
    }

    // Apply changes
    let adjuster_config = AdjusterConfig {
        safe_bounds: SafeBounds::default(),
        strategy: AdjustmentStrategy::Conservative,
        dry_run: false,
    };

    let adjuster = ParameterAdjuster::with_config(adjuster_config);
    adjuster.apply_to_file(&mut changes, &config)?;

    let applied_count = changes.iter().filter(|c| c.applied).count();
    println!("\nApplied {} of {} changes to {}", applied_count, changes.len(), config.display());

    Ok(())
}

/// Load detection events from the crmonban database
fn load_detections(database: &Path, window_hours: u64) -> Result<Vec<DetectionEvent>> {
    if !database.exists() {
        warn!("Database not found: {}", database.display());
        return Ok(Vec::new());
    }

    let db = Database::open(database)?;

    // Calculate time window
    let end_time = Utc::now();
    let start_time = end_time - chrono::Duration::hours(window_hours as i64);

    // Query detection events
    // Note: This is a simplified implementation - in production you'd have
    // a proper query method on Database
    let events = query_detection_events(&db, start_time, end_time)?;

    Ok(events)
}

/// Query detection events from database
/// This is a placeholder - implement actual database query based on your schema
fn query_detection_events(
    db: &Database,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
) -> Result<Vec<DetectionEvent>> {
    // Get recent activity as a proxy for detection events
    // In production, you'd query the detection_events table directly
    let activity = db.get_recent_activity(10000)?;

    let events: Vec<DetectionEvent> = activity
        .into_iter()
        .filter(|a| a.timestamp >= start_time && a.timestamp <= end_time)
        .filter_map(|a| {
            // Only include ban events as "detections"
            if !matches!(a.action, crmonban::models::ActivityAction::Ban) {
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

    Ok(events)
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
