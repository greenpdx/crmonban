use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::net::IpAddr;
use std::path::PathBuf;
use tabled::{Table, Tabled};

use crmonban::config::Config;
use crmonban::dbus::DbusClient;
use crmonban::intel::format_intel;
use crmonban::models::BanSource;
use crmonban::{Crmonban, Daemon};

#[derive(Parser)]
#[command(name = "crmonban")]
#[command(author, version, about = "nftables-based intrusion prevention system")]
#[command(propagate_version = true)]
pub struct Cli {
    /// Path to configuration file
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Enable debug logging
    #[arg(short, long, global = true)]
    pub debug: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the monitoring daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },

    /// Stop the monitoring daemon
    Stop,

    /// Show daemon status
    Status,

    /// Ban an IP address
    Ban {
        /// IP address to ban
        ip: IpAddr,

        /// Ban duration in seconds (0 = permanent)
        #[arg(short, long, default_value = "3600")]
        duration: i64,

        /// Reason for the ban
        #[arg(short, long, default_value = "Manual ban")]
        reason: String,
    },

    /// Unban an IP address
    Unban {
        /// IP address to unban
        ip: IpAddr,
    },

    /// List active bans
    List {
        /// Output format (table, json, simple)
        #[arg(short, long, default_value = "table")]
        format: String,
    },

    /// Gather and show intelligence for an IP
    Intel {
        /// IP address to investigate
        ip: String,

        /// Force refresh (don't use cached data)
        #[arg(short, long)]
        refresh: bool,

        /// Output as JSON
        #[arg(short, long)]
        json: bool,
    },

    /// Manage whitelist
    Whitelist {
        #[command(subcommand)]
        action: WhitelistAction,
    },

    /// Show recent activity logs
    Logs {
        /// Number of entries to show
        #[arg(short, long, default_value = "20")]
        limit: u32,
    },

    /// Show attack statistics
    Stats,

    /// Initialize nftables configuration
    Init,

    /// Flush all bans (dangerous!)
    Flush {
        /// Confirm the action
        #[arg(long)]
        yes: bool,
    },

    /// Generate default configuration file
    GenConfig {
        /// Output path (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
pub enum WhitelistAction {
    /// Add IP to whitelist
    Add {
        /// IP address to whitelist
        ip: IpAddr,

        /// Comment/reason
        #[arg(short, long)]
        comment: Option<String>,
    },

    /// Remove IP from whitelist
    Remove {
        /// IP address to remove
        ip: IpAddr,
    },

    /// List whitelisted IPs
    List,
}

/// Table row for ban list
#[derive(Tabled)]
struct BanRow {
    #[tabled(rename = "IP")]
    ip: String,
    #[tabled(rename = "Reason")]
    reason: String,
    #[tabled(rename = "Source")]
    source: String,
    #[tabled(rename = "Expires")]
    expires: String,
    #[tabled(rename = "Count")]
    count: u32,
}

/// Table row for whitelist
#[derive(Tabled)]
struct WhitelistRow {
    #[tabled(rename = "IP")]
    ip: String,
    #[tabled(rename = "Comment")]
    comment: String,
    #[tabled(rename = "Added")]
    added: String,
}

/// Table row for activity log
#[derive(Tabled)]
struct ActivityRow {
    #[tabled(rename = "Time")]
    time: String,
    #[tabled(rename = "Action")]
    action: String,
    #[tabled(rename = "IP")]
    ip: String,
    #[tabled(rename = "Details")]
    details: String,
}

pub async fn run_command(cli: Cli) -> Result<()> {
    let config = match &cli.config {
        Some(path) => Config::load(path)?,
        None => Config::load_or_default()?,
    };

    match cli.command {
        Commands::Start { foreground } => cmd_start(config, foreground).await,
        Commands::Stop => cmd_stop(config).await,
        Commands::Status => cmd_status(config).await,
        Commands::Ban {
            ip,
            duration,
            reason,
        } => cmd_ban(config, ip, duration, reason).await,
        Commands::Unban { ip } => cmd_unban(config, ip).await,
        Commands::List { format } => cmd_list(config, format).await,
        Commands::Intel { ip, refresh, json } => cmd_intel(config, ip, refresh, json).await,
        Commands::Whitelist { action } => cmd_whitelist(config, action).await,
        Commands::Logs { limit } => cmd_logs(config, limit).await,
        Commands::Stats => cmd_stats(config).await,
        Commands::Init => cmd_init(config).await,
        Commands::Flush { yes } => cmd_flush(config, yes).await,
        Commands::GenConfig { output } => cmd_gen_config(output),
    }
}

async fn cmd_start(config: Config, foreground: bool) -> Result<()> {
    if !foreground {
        // Check if already running
        let pid_path = config.pid_path();
        if pid_path.exists() {
            let pid_str = std::fs::read_to_string(&pid_path)?;
            if let Ok(pid) = pid_str.trim().parse::<u32>() {
                // Check if process is still running
                let proc_path = format!("/proc/{}", pid);
                if std::path::Path::new(&proc_path).exists() {
                    anyhow::bail!("Daemon already running with PID {}", pid);
                }
            }
        }

        println!("Starting crmonban daemon...");

        // Daemonize
        let daemonize = daemonize::Daemonize::new()
            .pid_file(&pid_path)
            .chown_pid_file(true)
            .working_directory("/");

        match daemonize.start() {
            Ok(_) => {
                // We're now in the daemon process
            }
            Err(e) => {
                anyhow::bail!("Failed to daemonize: {}", e);
            }
        }
    } else {
        println!("Starting crmonban in foreground mode...");
    }

    let crmonban = Crmonban::new(config)?;
    let mut daemon = Daemon::new(crmonban);

    // Handle signals
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");
    };

    tokio::select! {
        result = daemon.run() => {
            result?;
        }
        _ = shutdown_signal => {
            println!("\nShutting down...");
            daemon.shutdown().await;
        }
    }

    Ok(())
}

async fn cmd_stop(config: Config) -> Result<()> {
    let pid_path = config.pid_path();

    if !pid_path.exists() {
        println!("Daemon is not running (no PID file found)");
        return Ok(());
    }

    let pid_str = std::fs::read_to_string(&pid_path)?;
    let pid: i32 = pid_str
        .trim()
        .parse()
        .context("Invalid PID in pid file")?;

    // Send SIGTERM
    unsafe {
        if libc::kill(pid, libc::SIGTERM) == 0 {
            println!("Sent stop signal to daemon (PID {})", pid);
            std::fs::remove_file(&pid_path)?;
        } else {
            println!("Failed to send signal to PID {} (process may have exited)", pid);
            std::fs::remove_file(&pid_path)?;
        }
    }

    Ok(())
}

async fn cmd_status(config: Config) -> Result<()> {
    // Try D-Bus first for richer status information
    if config.dbus.enabled {
        if let Ok(client) = DbusClient::connect().await {
            if client.is_daemon_available().await {
                match client.status().await {
                    Ok(status) => {
                        println!("{}", "Daemon Status: RUNNING".green().bold());
                        println!("PID:              {}", status.pid);
                        println!("Uptime:           {}s", status.uptime_secs);
                        println!("Active bans:      {}", status.active_bans);
                        println!("Events processed: {}", status.events_processed);
                        if !status.monitored_services.is_empty() {
                            println!(
                                "Monitoring:       {}",
                                status.monitored_services.join(", ")
                            );
                        }
                        println!("{}", "(via D-Bus)".dimmed());
                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!("{}", format!("D-Bus error: {}", e).yellow());
                    }
                }
            }
        }
    }

    // Fall back to PID file check
    let pid_path = config.pid_path();

    if pid_path.exists() {
        let pid_str = std::fs::read_to_string(&pid_path)?;
        if let Ok(pid) = pid_str.trim().parse::<u32>() {
            let proc_path = format!("/proc/{}", pid);
            if std::path::Path::new(&proc_path).exists() {
                println!("{}", "Daemon Status: RUNNING".green().bold());
                println!("PID: {}", pid);

                // Show some stats
                let crmonban = Crmonban::new(config)?;
                let bans = crmonban.list_bans()?;
                println!("Active bans: {}", bans.len());

                return Ok(());
            }
        }
    }

    println!("{}", "Daemon Status: STOPPED".red().bold());
    Ok(())
}

async fn cmd_ban(config: Config, ip: IpAddr, duration: i64, reason: String) -> Result<()> {
    let crmonban = Crmonban::new(config)?;

    let duration_opt = if duration == 0 {
        None
    } else {
        Some(duration)
    };

    crmonban.ban(ip, reason.clone(), BanSource::Manual, duration_opt)?;

    println!(
        "{} {} ({})",
        "Banned:".green().bold(),
        ip,
        if duration == 0 {
            "permanent".to_string()
        } else {
            format!("{}s", duration)
        }
    );

    Ok(())
}

async fn cmd_unban(config: Config, ip: IpAddr) -> Result<()> {
    let crmonban = Crmonban::new(config)?;

    if crmonban.unban(&ip)? {
        println!("{} {}", "Unbanned:".green().bold(), ip);
    } else {
        println!("{} {} was not banned", "Note:".yellow().bold(), ip);
    }

    Ok(())
}

async fn cmd_list(config: Config, format: String) -> Result<()> {
    let crmonban = Crmonban::new(config)?;
    let bans = crmonban.list_bans()?;

    if bans.is_empty() {
        println!("No active bans");
        return Ok(());
    }

    match format.as_str() {
        "json" => {
            println!("{}", serde_json::to_string_pretty(&bans)?);
        }
        "simple" => {
            for ban in &bans {
                println!("{}", ban.ip);
            }
        }
        _ => {
            let rows: Vec<BanRow> = bans
                .iter()
                .map(|b| BanRow {
                    ip: b.ip.to_string(),
                    reason: b.reason.clone(),
                    source: b.source.to_string(),
                    expires: b
                        .expires_at
                        .map(|e| e.format("%Y-%m-%d %H:%M").to_string())
                        .unwrap_or_else(|| "never".to_string()),
                    count: b.ban_count,
                })
                .collect();

            println!("{}", Table::new(rows));
        }
    }

    Ok(())
}

async fn cmd_intel(config: Config, ip: String, refresh: bool, json: bool) -> Result<()> {
    let crmonban = Crmonban::new(config)?;

    // Check cache first
    let intel = if !refresh {
        if let Some(cached) = crmonban.get_cached_intel(&ip)? {
            println!("{}", "(Using cached data)".dimmed());
            cached
        } else {
            println!("Gathering intelligence for {}...", ip);
            crmonban.gather_and_save_intel(&ip).await?
        }
    } else {
        println!("Gathering fresh intelligence for {}...", ip);
        crmonban.gather_and_save_intel(&ip).await?
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&intel)?);
    } else {
        println!("\n{}", format_intel(&intel));
    }

    Ok(())
}

async fn cmd_whitelist(config: Config, action: WhitelistAction) -> Result<()> {
    let crmonban = Crmonban::new(config)?;

    match action {
        WhitelistAction::Add { ip, comment } => {
            crmonban.whitelist_add(ip, comment)?;
            println!("{} {} to whitelist", "Added".green().bold(), ip);
        }
        WhitelistAction::Remove { ip } => {
            if crmonban.whitelist_remove(&ip)? {
                println!("{} {} from whitelist", "Removed".green().bold(), ip);
            } else {
                println!("{} {} was not in whitelist", "Note:".yellow().bold(), ip);
            }
        }
        WhitelistAction::List => {
            let entries = crmonban.whitelist_list()?;

            if entries.is_empty() {
                println!("Whitelist is empty");
                return Ok(());
            }

            let rows: Vec<WhitelistRow> = entries
                .iter()
                .map(|e| WhitelistRow {
                    ip: e.ip.to_string(),
                    comment: e.comment.clone().unwrap_or_default(),
                    added: e.created_at.format("%Y-%m-%d %H:%M").to_string(),
                })
                .collect();

            println!("{}", Table::new(rows));
        }
    }

    Ok(())
}

async fn cmd_logs(config: Config, limit: u32) -> Result<()> {
    let crmonban = Crmonban::new(config)?;
    let logs = crmonban.get_activity(limit)?;

    if logs.is_empty() {
        println!("No activity logs");
        return Ok(());
    }

    let rows: Vec<ActivityRow> = logs
        .iter()
        .map(|l| ActivityRow {
            time: l.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),
            action: l.action.to_string(),
            ip: l.ip.map(|i| i.to_string()).unwrap_or_default(),
            details: l.details.clone(),
        })
        .collect();

    println!("{}", Table::new(rows));
    Ok(())
}

async fn cmd_stats(config: Config) -> Result<()> {
    let crmonban = Crmonban::new(config)?;
    let stats = crmonban.get_stats()?;

    println!("{}", "=== crmonban Statistics ===".bold());
    println!();
    println!("Total bans (all time): {}", stats.total_bans);
    println!(
        "Active bans:          {}",
        stats.active_bans.to_string().yellow()
    );
    println!("Total events:         {}", stats.total_events);
    println!(
        "Events today:         {}",
        stats.events_today.to_string().cyan()
    );
    println!(
        "Events (last hour):   {}",
        stats.events_this_hour.to_string().cyan()
    );

    if !stats.events_by_service.is_empty() {
        println!("\n{}", "Events by Service:".bold());
        for (service, count) in &stats.events_by_service {
            println!("  {}: {}", service, count);
        }
    }

    if !stats.top_countries.is_empty() {
        println!("\n{}", "Top Countries:".bold());
        for (country, count) in &stats.top_countries {
            println!("  {}: {}", country, count);
        }
    }

    if !stats.top_asns.is_empty() {
        println!("\n{}", "Top ASNs:".bold());
        for (asn, count) in &stats.top_asns {
            println!("  {}: {}", asn, count);
        }
    }

    Ok(())
}

async fn cmd_init(config: Config) -> Result<()> {
    let crmonban = Crmonban::new(config)?;
    crmonban.init_firewall()?;
    println!("{}", "nftables configuration initialized".green().bold());
    Ok(())
}

async fn cmd_flush(config: Config, yes: bool) -> Result<()> {
    if !yes {
        println!(
            "{}",
            "WARNING: This will remove ALL bans!".red().bold()
        );
        println!("Run with --yes to confirm");
        return Ok(());
    }

    let crmonban = Crmonban::new(config)?;
    crmonban.flush_all()?;
    println!("{}", "All bans have been flushed".yellow().bold());
    Ok(())
}

fn cmd_gen_config(output: Option<PathBuf>) -> Result<()> {
    let config = Config::default();
    let toml_str = toml::to_string_pretty(&config)?;

    match output {
        Some(path) => {
            std::fs::write(&path, &toml_str)?;
            println!("Configuration written to {}", path.display());
        }
        None => {
            println!("{}", toml_str);
        }
    }

    Ok(())
}
