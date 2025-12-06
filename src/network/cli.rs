//! CLI commands for network scanning

use std::net::IpAddr;
use clap::{Args, Subcommand};
use anyhow::Result;
use colored::Colorize;
use tabled::{Table, Tabled};

use crate::network::{ScanConfig, ScanRequest, ScanActions, ScanTrigger};

#[cfg(feature = "scan")]
use crate::network::scan::ScanRunner;

#[derive(Args)]
pub struct ScanCommand {
    #[command(subcommand)]
    pub command: ScanSubcommand,
}

#[derive(Subcommand)]
pub enum ScanSubcommand {
    /// Scan a target IP with all available tools
    Run {
        /// Target IP address
        target: IpAddr,
        /// Run Nmap port scan
        #[arg(long, default_value = "true")]
        nmap: bool,
        /// Run Nmap vulnerability scripts
        #[arg(long)]
        nmap_vuln: bool,
        /// Run Ettercap ARP check
        #[arg(long)]
        ettercap: bool,
        /// Run Metasploit auxiliary scans
        #[arg(long)]
        msf: bool,
        /// Run Burp if web server detected
        #[arg(long)]
        burp: bool,
        /// Use commercial tools (requires scan-commercial feature)
        #[arg(long)]
        commercial: bool,
    },
    /// Run single tool scan
    Tool {
        /// Tool name: nmap, ettercap, metasploit, burp
        tool: String,
        /// Target IP address
        target: IpAddr,
    },
    /// List available scanning tools
    List,
    /// Show scan configuration
    Config,
    /// Run Nessus scan (commercial, requires explicit flag)
    #[cfg(feature = "scan-commercial")]
    Nessus {
        /// Target IP address
        target: IpAddr,
        /// Scan policy
        #[arg(long, default_value = "advanced")]
        policy: String,
    },
    /// Run Acunetix scan (commercial, requires explicit flag)
    #[cfg(feature = "scan-commercial")]
    Acunetix {
        /// Target IP address
        target: IpAddr,
    },
}

#[derive(Tabled)]
struct ToolStatus {
    tool: String,
    available: String,
    description: String,
}

#[derive(Tabled)]
struct FindingRow {
    severity: String,
    title: String,
    port: String,
    cve: String,
}

pub fn handle_scan_command(cmd: ScanCommand, config: ScanConfig) -> Result<()> {
    match cmd.command {
        ScanSubcommand::Run {
            target,
            nmap,
            nmap_vuln,
            ettercap,
            msf,
            burp,
            commercial,
        } => {
            run_scan(target, ScanActions {
                nmap_scan: nmap,
                nmap_vuln,
                ettercap_arp_check: ettercap,
                msf_aux_scan: msf,
                burp_if_web: burp,
                use_commercial: commercial,
            }, config)?;
        }
        ScanSubcommand::Tool { tool, target } => {
            run_single_tool(&tool, target, config)?;
        }
        ScanSubcommand::List => {
            list_tools(config)?;
        }
        ScanSubcommand::Config => {
            show_config(config)?;
        }
        #[cfg(feature = "scan-commercial")]
        ScanSubcommand::Nessus { target, policy } => {
            run_nessus(target, &policy, config)?;
        }
        #[cfg(feature = "scan-commercial")]
        ScanSubcommand::Acunetix { target } => {
            run_acunetix(target, config)?;
        }
    }
    Ok(())
}

#[cfg(feature = "scan")]
fn run_scan(target: IpAddr, actions: ScanActions, config: ScanConfig) -> Result<()> {
    println!("{}", format!("Scanning {} ...", target).cyan().bold());

    let runner = ScanRunner::new(config);
    let request = ScanRequest {
        target,
        reason: "Manual CLI scan".into(),
        trigger: ScanTrigger::Manual,
        actions,
    };

    let results = runner.run(request);

    for result in &results {
        println!("\n{} {}", "Tool:".bold(), result.tool.green());
        println!("{} {}", "Success:".bold(), if result.success { "Yes".green() } else { "No".red() });

        if result.findings.is_empty() {
            println!("  No findings");
        } else {
            let rows: Vec<FindingRow> = result.findings.iter().map(|f| {
                let sev_str = format!("{:?}", f.severity);
                FindingRow {
                    severity: match f.severity {
                        crate::network::FindingSeverity::Critical => sev_str.red().to_string(),
                        crate::network::FindingSeverity::High => sev_str.bright_red().to_string(),
                        crate::network::FindingSeverity::Medium => sev_str.yellow().to_string(),
                        crate::network::FindingSeverity::Low => sev_str.blue().to_string(),
                        crate::network::FindingSeverity::Info => sev_str.white().to_string(),
                    },
                    title: f.title.clone(),
                    port: f.port.map(|p| p.to_string()).unwrap_or("-".into()),
                    cve: f.cve.clone().unwrap_or("-".into()),
                }
            }).collect();

            println!("{}", Table::new(rows));
        }
    }

    // Summary
    let all_findings = ScanRunner::aggregate_findings(&results);
    let critical = all_findings.iter().filter(|f| f.severity == crate::network::FindingSeverity::Critical).count();
    let high = all_findings.iter().filter(|f| f.severity == crate::network::FindingSeverity::High).count();

    println!("\n{}", "Summary".bold().underline());
    println!("Total findings: {}", all_findings.len());
    if critical > 0 {
        println!("{}: {}", "Critical".red().bold(), critical);
    }
    if high > 0 {
        println!("{}: {}", "High".bright_red().bold(), high);
    }

    Ok(())
}

#[cfg(feature = "scan")]
fn run_single_tool(tool: &str, target: IpAddr, config: ScanConfig) -> Result<()> {
    println!("{}", format!("Running {} on {} ...", tool, target).cyan().bold());

    let runner = ScanRunner::new(config);
    let result = runner.run_tool(target, tool)?;

    println!("{} {}", "Success:".bold(), if result.success { "Yes".green() } else { "No".red() });
    println!("{} findings", result.findings.len());

    for finding in &result.findings {
        let sev = format!("{:?}", finding.severity);
        println!("  [{}] {}", sev, finding.title);
        if let Some(ref rem) = finding.remediation {
            println!("    Remediation: {}", rem);
        }
    }

    Ok(())
}

#[cfg(feature = "scan")]
fn list_tools(config: ScanConfig) -> Result<()> {
    let tools_config = config.tools.clone();
    let runner = ScanRunner::new(config);
    let available = runner.available_tools();

    let tools = vec![
        ToolStatus {
            tool: "nmap".into(),
            available: if available.contains(&"nmap") { "✓".green().to_string() } else { "✗".red().to_string() },
            description: "Network discovery and port scanning".into(),
        },
        ToolStatus {
            tool: "ettercap".into(),
            available: if available.contains(&"ettercap") { "✓".green().to_string() } else { "✗".red().to_string() },
            description: "ARP/MITM analysis".into(),
        },
        ToolStatus {
            tool: "metasploit".into(),
            available: if available.contains(&"metasploit") { "✓".green().to_string() } else { "✗".red().to_string() },
            description: "Vulnerability validation".into(),
        },
        ToolStatus {
            tool: "burp".into(),
            available: if available.contains(&"burp") { "✓".green().to_string() } else { "✗".red().to_string() },
            description: "Web application testing".into(),
        },
    ];

    println!("{}", "Available Scanning Tools".bold().underline());
    println!("{}", Table::new(tools));

    #[cfg(feature = "scan-commercial")]
    {
        use crate::network::scan_commercial::CommercialScanRunner;
        let commercial = CommercialScanRunner::new(&tools_config);
        let commercial_available = commercial.available();

        println!("\n{}", "Commercial Tools".bold().underline());
        let commercial_tools = vec![
            ToolStatus {
                tool: "nessus".into(),
                available: if commercial_available.contains(&"nessus") { "✓".green().to_string() } else { "✗".red().to_string() },
                description: "Vulnerability scanner (requires license)".into(),
            },
            ToolStatus {
                tool: "acunetix".into(),
                available: if commercial_available.contains(&"acunetix") { "✓".green().to_string() } else { "✗".red().to_string() },
                description: "Web vulnerability scanner (requires license)".into(),
            },
        ];
        println!("{}", Table::new(commercial_tools));
    }

    Ok(())
}

fn show_config(config: ScanConfig) -> Result<()> {
    println!("{}", "Scan Configuration".bold().underline());
    println!("Auto-scan enabled: {}", if config.auto_scan { "Yes".green() } else { "No".yellow() });
    println!("Triggers: {:?}", config.triggers);
    println!("\n{}", "Default Actions".bold());
    println!("  Nmap scan: {}", config.actions.nmap_scan);
    println!("  Nmap vuln scripts: {}", config.actions.nmap_vuln);
    println!("  Ettercap ARP check: {}", config.actions.ettercap_arp_check);
    println!("  Metasploit aux: {}", config.actions.msf_aux_scan);
    println!("  Burp if web: {}", config.actions.burp_if_web);
    println!("  Use commercial: {}", config.actions.use_commercial);
    Ok(())
}

#[cfg(feature = "scan-commercial")]
fn run_nessus(target: IpAddr, policy: &str, config: ScanConfig) -> Result<()> {
    use crate::network::scan_commercial::{NessusScanner, CommercialScanner};

    println!("{}", format!("Running Nessus scan on {} with policy '{}'", target, policy).cyan().bold());

    let nessus_path = config.tools.nessus_cli.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Nessus CLI path not configured"))?;

    let scanner = NessusScanner::new(nessus_path);
    if !scanner.is_configured() {
        anyhow::bail!("Nessus is not properly configured");
    }

    let result = scanner.vuln_scan(target, policy)?;
    println!("{} findings", result.findings.len());

    for finding in &result.findings {
        println!("  [{:?}] {}", finding.severity, finding.title);
    }

    Ok(())
}

#[cfg(feature = "scan-commercial")]
fn run_acunetix(target: IpAddr, config: ScanConfig) -> Result<()> {
    use crate::network::scan_commercial::{AcunetixScanner, CommercialScanner};

    println!("{}", format!("Running Acunetix scan on {}", target).cyan().bold());

    let acunetix_path = config.tools.acunetix_cli.as_ref()
        .ok_or_else(|| anyhow::anyhow!("Acunetix CLI path not configured"))?;

    let scanner = AcunetixScanner::new(acunetix_path);
    if !scanner.is_configured() {
        anyhow::bail!("Acunetix is not properly configured");
    }

    let result = scanner.scan(target)?;
    println!("{} findings", result.findings.len());

    for finding in &result.findings {
        println!("  [{:?}] {}", finding.severity, finding.title);
    }

    Ok(())
}

#[cfg(not(feature = "scan"))]
fn run_scan(_target: IpAddr, _actions: ScanActions, _config: ScanConfig) -> Result<()> {
    anyhow::bail!("Scanning feature not enabled. Compile with --features scan")
}

#[cfg(not(feature = "scan"))]
fn run_single_tool(_tool: &str, _target: IpAddr, _config: ScanConfig) -> Result<()> {
    anyhow::bail!("Scanning feature not enabled. Compile with --features scan")
}

#[cfg(not(feature = "scan"))]
fn list_tools(_config: ScanConfig) -> Result<()> {
    anyhow::bail!("Scanning feature not enabled. Compile with --features scan")
}
