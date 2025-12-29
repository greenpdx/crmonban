//! Detection Feedback - Analyze detection logs and generate improvement recommendations
//!
//! Reads detection logs from the database and generates feedback reports with
//! recommendations for improving detection accuracy.
//!
//! Run with: cargo run --bin detection_feedback --release -- analyze

use std::path::Path;
use std::time::Duration;

use crmonban::testing::{
    FeedbackAnalyzer, FeedbackConfig, FeedbackReport, DetectionEventRecord,
};
use chrono::{DateTime, Utc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut command: Option<String> = None;
    let mut db_path: Option<String> = None;
    let mut output_file: Option<String> = None;
    let mut window_hours = 24u64;
    let mut format = "text";
    let mut fp_threshold = 0.05f64;
    let mut min_samples = 100u64;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "analyze" | "report" | "suggest" => {
                command = Some(args[i].clone());
            }
            "--database" | "-d" => {
                if i + 1 < args.len() {
                    db_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    output_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--window" | "-w" => {
                if i + 1 < args.len() {
                    window_hours = args[i + 1].parse().unwrap_or(24);
                    i += 1;
                }
            }
            "--format" => {
                if i + 1 < args.len() {
                    format = match args[i + 1].to_lowercase().as_str() {
                        "json" => "json",
                        "markdown" | "md" => "markdown",
                        _ => "text",
                    };
                    i += 1;
                }
            }
            "--fp-threshold" => {
                if i + 1 < args.len() {
                    fp_threshold = args[i + 1].parse().unwrap_or(0.05);
                    i += 1;
                }
            }
            "--min-samples" => {
                if i + 1 < args.len() {
                    min_samples = args[i + 1].parse().unwrap_or(100);
                    i += 1;
                }
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let command = command.unwrap_or_else(|| "analyze".to_string());

    println!("Detection Feedback Analyzer");
    println!("===========================\n");

    let config = FeedbackConfig {
        analysis_window: Duration::from_secs(window_hours * 3600),
        min_samples,
        fp_rate_threshold: fp_threshold,
        low_detection_threshold: 0.80,
        alert_fatigue_threshold: 100,
    };

    match command.as_str() {
        "analyze" => {
            run_analysis(db_path, config, output_file.as_deref(), format)?;
        }
        "report" => {
            run_analysis(db_path, config, output_file.as_deref(), "markdown")?;
        }
        "suggest" => {
            run_suggestions(db_path, config)?;
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            eprintln!("Use --help for usage information.");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn run_analysis(
    db_path: Option<String>,
    config: FeedbackConfig,
    output_file: Option<&str>,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Save config values for printing before moving config
    let analysis_window_hours = config.analysis_window.as_secs() / 3600;
    let fp_threshold_pct = config.fp_rate_threshold * 100.0;

    let analyzer = if let Some(path) = db_path {
        println!("Database: {}", path);
        FeedbackAnalyzer::new(config).with_database(&path)
    } else {
        // Try default paths
        let default_paths = [
            "/var/lib/crmonban/crmonban.db",
            "./crmonban.db",
            "data/crmonban.db",
        ];

        let mut found_analyzer = None;
        for path in default_paths {
            if Path::new(path).exists() {
                println!("Database: {}", path);
                found_analyzer = Some(FeedbackAnalyzer::new(config.clone()).with_database(path));
                break;
            }
        }

        match found_analyzer {
            Some(a) => a,
            None => {
                println!("No database found, running demo with synthetic events...\n");
                return run_demo_analysis(config, output_file, format);
            }
        }
    };

    println!("Analysis window: {} hours", analysis_window_hours);
    println!("FP threshold: {:.1}%", fp_threshold_pct);
    println!();

    let report = analyzer.analyze_from_database()?;
    output_report(&report, format, output_file)
}

fn run_demo_analysis(
    config: FeedbackConfig,
    output_file: Option<&str>,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = FeedbackAnalyzer::new(config);

    // Create demo events simulating various detection scenarios
    let now = Utc::now();
    let events: Vec<DetectionEventRecord> = generate_demo_events(now);

    let start = now - chrono::Duration::hours(24);
    let report = analyzer.analyze_events(events, start, now)?;

    println!("Demo Analysis Results");
    println!("---------------------\n");

    output_report(&report, format, output_file)
}

fn generate_demo_events(now: DateTime<Utc>) -> Vec<DetectionEventRecord> {
    let mut events = Vec::new();

    // Port scan events - some FPs
    for i in 0..50 {
        events.push(DetectionEventRecord {
            id: format!("scan_{}", i),
            timestamp: now - chrono::Duration::minutes(i as i64 * 5),
            src_ip: "192.168.1.100".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            detection_type: "port_scan".to_string(),
            severity: "medium".to_string(),
            confidence: 0.85,
            detector: Some("layer234".to_string()),
            rule_id: Some("SCAN001".to_string()),
            marked_fp: i % 10 == 0, // 10% FP rate
        });
    }

    // Brute force events - higher FP rate
    for i in 0..30 {
        events.push(DetectionEventRecord {
            id: format!("brute_{}", i),
            timestamp: now - chrono::Duration::minutes(i as i64 * 3),
            src_ip: "192.168.1.101".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            detection_type: "brute_force".to_string(),
            severity: "high".to_string(),
            confidence: 0.78,
            detector: Some("layer234".to_string()),
            rule_id: Some("BRUTE001".to_string()),
            marked_fp: i % 5 == 0, // 20% FP rate
        });
    }

    // DoS events
    for i in 0..20 {
        events.push(DetectionEventRecord {
            id: format!("dos_{}", i),
            timestamp: now - chrono::Duration::minutes(i as i64 * 2),
            src_ip: "192.168.1.102".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            detection_type: "dos".to_string(),
            severity: "critical".to_string(),
            confidence: 0.92,
            detector: Some("layer234".to_string()),
            rule_id: Some("DOS001".to_string()),
            marked_fp: i % 20 == 0, // 5% FP rate
        });
    }

    // High-volume source (alert fatigue)
    for i in 0..150 {
        events.push(DetectionEventRecord {
            id: format!("fatigue_{}", i),
            timestamp: now - chrono::Duration::seconds(i as i64 * 30),
            src_ip: "10.10.10.10".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            detection_type: "network_scan".to_string(),
            severity: "low".to_string(),
            confidence: 0.65,
            detector: Some("layer234".to_string()),
            rule_id: Some("SCAN002".to_string()),
            marked_fp: false,
        });
    }

    events
}

fn run_suggestions(
    db_path: Option<String>,
    config: FeedbackConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating configuration suggestions...\n");

    let analyzer = if let Some(path) = db_path {
        FeedbackAnalyzer::new(config).with_database(&path)
    } else {
        // Demo mode
        let demo_config = FeedbackConfig {
            min_samples: 5,
            ..config
        };
        return run_demo_suggestions(demo_config);
    };

    let report = analyzer.analyze_from_database()?;

    if report.config_changes.is_empty() {
        println!("No configuration changes suggested.");
        println!("Your current configuration appears to be well-tuned.");
    } else {
        println!("Suggested Configuration Changes:");
        println!("--------------------------------\n");

        for (i, change) in report.config_changes.iter().enumerate() {
            println!("{}. {}", i + 1, change.path);
            println!("   Current: {}", change.current_value);
            println!("   Suggested: {}", change.suggested_value);
            println!("   Reason: {}\n", change.reason);
        }

        println!("\nTo apply these changes, update your config.toml file.");
    }

    Ok(())
}

fn run_demo_suggestions(config: FeedbackConfig) -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = FeedbackAnalyzer::new(config);
    let now = Utc::now();
    let events = generate_demo_events(now);
    let start = now - chrono::Duration::hours(24);

    let report = analyzer.analyze_events(events, start, now)?;

    if report.config_changes.is_empty() {
        println!("No configuration changes suggested based on demo data.");
    } else {
        println!("Demo Suggestions (based on synthetic data):");
        println!("-------------------------------------------\n");

        for (i, change) in report.config_changes.iter().enumerate() {
            println!("{}. {}", i + 1, change.path);
            println!("   Current: {}", change.current_value);
            println!("   Suggested: {}", change.suggested_value);
            println!("   Reason: {}\n", change.reason);
        }
    }

    Ok(())
}

fn output_report(
    report: &FeedbackReport,
    format: &str,
    output_file: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = match format {
        "json" => report.to_json(),
        "markdown" => report.to_markdown(),
        _ => {
            // Text format - summarized
            let mut text = String::new();
            text.push_str(&format!("Analysis Period: {} to {}\n",
                report.analysis_start.format("%Y-%m-%d %H:%M"),
                report.analysis_end.format("%Y-%m-%d %H:%M")));
            text.push_str(&format!("Total Events: {}\n\n", report.total_events));

            if !report.findings.is_empty() {
                text.push_str("FINDINGS:\n");
                for (i, f) in report.findings.iter().enumerate() {
                    text.push_str(&format!("  {}. {:?}: {}\n", i + 1, f.finding_type, f.details));
                }
                text.push('\n');
            }

            if !report.recommendations.is_empty() {
                text.push_str("RECOMMENDATIONS:\n");
                for (i, r) in report.recommendations.iter().enumerate() {
                    text.push_str(&format!("  {}. [{}] {}\n", i + 1, r.priority, r.description));
                    text.push_str(&format!("     Action: {}\n", r.action));
                }
                text.push('\n');
            }

            if !report.top_sources.is_empty() {
                text.push_str("TOP ALERT SOURCES:\n");
                for src in report.top_sources.iter().take(5) {
                    text.push_str(&format!("  {} - {} alerts ({:?})\n",
                        src.ip, src.alert_count, src.detection_types));
                }
            }

            text
        }
    };

    if let Some(path) = output_file {
        std::fs::write(path, &content)?;
        println!("Report written to: {}", path);
    } else {
        println!("{}", content);
    }

    Ok(())
}

fn print_help() {
    println!("Detection Feedback Analyzer - Improve detection based on log analysis\n");
    println!("USAGE:");
    println!("  detection_feedback <COMMAND> [OPTIONS]\n");
    println!("COMMANDS:");
    println!("  analyze    Analyze detection logs (default)");
    println!("  report     Generate full markdown report");
    println!("  suggest    Show suggested config changes only\n");
    println!("OPTIONS:");
    println!("  -d, --database <PATH>   Database path");
    println!("  -o, --output <FILE>     Output report file");
    println!("  -w, --window <HOURS>    Analysis window in hours (default: 24)");
    println!("  --format <FMT>          Output format: text, json, markdown");
    println!("  --fp-threshold <RATE>   FP rate threshold (default: 0.05)");
    println!("  --min-samples <N>       Minimum samples for analysis (default: 100)");
    println!("  -h, --help              Show this help\n");
    println!("EXAMPLES:");
    println!("  # Analyze last 24 hours");
    println!("  detection_feedback analyze\n");
    println!("  # Generate markdown report for last 48 hours");
    println!("  detection_feedback report -w 48 -o feedback.md\n");
    println!("  # Get config suggestions");
    println!("  detection_feedback suggest -d /var/lib/crmonban/crmonban.db\n");
    println!("If no database is specified, the tool will:");
    println!("  1. Try /var/lib/crmonban/crmonban.db");
    println!("  2. Try ./crmonban.db");
    println!("  3. Run in demo mode with synthetic data");
}
