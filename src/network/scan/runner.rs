//! Scan orchestration and automation

use std::net::IpAddr;
use anyhow::Result;
use tracing::{info, warn};

use crate::network::{ScanConfig, ScanRequest, ScanResult, ScanTrigger, Finding};
use super::{Scanner, NmapScanner, EttercapScanner, MetasploitScanner, BurpScanner};

/// Orchestrates scanning based on config
pub struct ScanRunner {
    config: ScanConfig,
    nmap: NmapScanner,
    ettercap: EttercapScanner,
    metasploit: MetasploitScanner,
    burp: BurpScanner,
}

impl ScanRunner {
    pub fn new(config: ScanConfig) -> Self {
        let nmap = NmapScanner::new(&config.tools, config.actions.nmap_vuln);
        let ettercap = EttercapScanner::new(&config.tools, "eth0");
        let metasploit = MetasploitScanner::new(&config.tools);
        let burp = BurpScanner::new(&config.tools);

        Self { config, nmap, ettercap, metasploit, burp }
    }

    /// Check if scan should trigger based on event
    pub fn should_scan(&self, trigger: &ScanTrigger) -> bool {
        if !self.config.auto_scan {
            return false;
        }
        self.config.triggers.iter().any(|t| std::mem::discriminant(t) == std::mem::discriminant(trigger))
    }

    /// Run full scan based on config
    pub fn run(&self, request: ScanRequest) -> Vec<ScanResult> {
        info!("Starting scan of {} - trigger: {:?}", request.target, request.trigger);

        let mut results = Vec::new();
        let actions = &request.actions;

        // Nmap scan
        if actions.nmap_scan {
            match self.nmap.scan(request.target) {
                Ok(result) => {
                    info!("Nmap found {} findings", result.findings.len());
                    results.push(result);
                }
                Err(e) => warn!("Nmap scan failed: {}", e),
            }
        }

        // Ettercap ARP check
        if actions.ettercap_arp_check {
            match self.ettercap.scan(request.target) {
                Ok(result) => {
                    info!("Ettercap found {} findings", result.findings.len());
                    results.push(result);
                }
                Err(e) => warn!("Ettercap scan failed: {}", e),
            }
        }

        // Metasploit auxiliary
        if actions.msf_aux_scan {
            match self.metasploit.scan(request.target) {
                Ok(result) => {
                    info!("Metasploit found {} findings", result.findings.len());
                    results.push(result);
                }
                Err(e) => warn!("Metasploit scan failed: {}", e),
            }
        }

        // Burp if web detected
        if actions.burp_if_web {
            let web_ports = BurpScanner::detect_web_services(request.target);
            if !web_ports.is_empty() {
                info!("Web services detected on {:?}, running Burp", web_ports);
                match self.burp.scan(request.target) {
                    Ok(result) => {
                        info!("Burp found {} findings", result.findings.len());
                        results.push(result);
                    }
                    Err(e) => warn!("Burp scan failed: {}", e),
                }
            }
        }

        results
    }

    /// Run single tool scan
    pub fn run_tool(&self, target: IpAddr, tool: &str) -> Result<ScanResult> {
        match tool {
            "nmap" => self.nmap.scan(target),
            "ettercap" => self.ettercap.scan(target),
            "metasploit" | "msf" => self.metasploit.scan(target),
            "burp" => self.burp.scan(target),
            _ => anyhow::bail!("Unknown tool: {}", tool),
        }
    }

    /// Get all findings sorted by severity
    pub fn aggregate_findings(results: &[ScanResult]) -> Vec<&Finding> {
        let mut all: Vec<_> = results.iter().flat_map(|r| &r.findings).collect();
        all.sort_by(|a, b| {
            let sev_order = |s: &crate::network::FindingSeverity| match s {
                crate::network::FindingSeverity::Critical => 0,
                crate::network::FindingSeverity::High => 1,
                crate::network::FindingSeverity::Medium => 2,
                crate::network::FindingSeverity::Low => 3,
                crate::network::FindingSeverity::Info => 4,
            };
            sev_order(&a.severity).cmp(&sev_order(&b.severity))
        });
        all
    }

    /// Check available tools
    pub fn available_tools(&self) -> Vec<&'static str> {
        let mut tools = Vec::new();
        if self.nmap.is_available() { tools.push("nmap"); }
        if self.ettercap.is_available() { tools.push("ettercap"); }
        if self.metasploit.is_available() { tools.push("metasploit"); }
        if self.burp.is_available() { tools.push("burp"); }
        tools
    }
}

impl Default for ScanRunner {
    fn default() -> Self {
        Self::new(ScanConfig::default())
    }
}
