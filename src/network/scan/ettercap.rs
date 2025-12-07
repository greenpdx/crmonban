//! Ettercap ARP/MITM analysis

use std::net::IpAddr;
use std::process::Command;
use anyhow::{Result, Context};
use tracing::info;

use crate::network::{ScanResult, Finding, FindingSeverity, ToolPaths};
use super::Scanner;

pub struct EttercapScanner {
    binary: String,
    interface: String,
}

impl EttercapScanner {
    pub fn new(tools: &ToolPaths, interface: &str) -> Self {
        Self {
            binary: tools.ettercap.clone(),
            interface: interface.to_string(),
        }
    }

    /// Check for ARP poisoning
    pub fn arp_check(&self, target: IpAddr, gateway: IpAddr) -> Result<ScanResult> {
        info!("Running Ettercap ARP check: {} via {}", target, gateway);

        // Run in text mode, quiet, just detect
        let output = Command::new(&self.binary)
            .args([
                "-T",           // Text mode
                "-q",           // Quiet
                "-i", &self.interface,
                "-M", "arp:remote",
                &format!("/{}/", gateway),
                &format!("/{}/", target),
            ])
            .output()
            .context("Failed to run ettercap")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let findings = self.parse_output(&stdout, &stderr);

        Ok(ScanResult {
            target,
            tool: "ettercap".into(),
            success: output.status.success(),
            findings,
            raw_output: Some(format!("{}\n{}", stdout, stderr)),
        })
    }

    /// Passive ARP monitoring
    pub fn passive_monitor(&self, duration_secs: u32) -> Result<Vec<Finding>> {
        info!("Running passive ARP monitor for {}s", duration_secs);

        let output = Command::new(&self.binary)
            .args([
                "-T",
                "-q",
                "-i", &self.interface,
                "-w", "/tmp/ettercap_dump.pcap",
            ])
            .output()
            .context("Failed to run ettercap passive")?;

        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(self.detect_anomalies(&stderr))
    }

    fn parse_output(&self, stdout: &str, stderr: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let combined = format!("{}\n{}", stdout, stderr);

        // Check for ARP poisoning indicators
        if combined.contains("ARP poisoning") || combined.contains("MITM") {
            findings.push(Finding {
                severity: FindingSeverity::Critical,
                title: "ARP Poisoning Detected".into(),
                description: "Active ARP spoofing attack in progress".into(),
                port: None,
                cve: None,
                remediation: Some("Enable Dynamic ARP Inspection (DAI), use static ARP entries".into()),
            });
        }

        // Check for duplicate MAC addresses
        if combined.contains("duplicate") || combined.contains("conflict") {
            findings.push(Finding {
                severity: FindingSeverity::High,
                title: "MAC Address Conflict".into(),
                description: "Duplicate MAC addresses detected on network".into(),
                port: None,
                cve: None,
                remediation: Some("Investigate conflicting devices".into()),
            });
        }

        findings
    }

    fn detect_anomalies(&self, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if output.contains("Unified sniffing") {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                title: "Network Monitoring Active".into(),
                description: "Passive network analysis completed".into(),
                port: None,
                cve: None,
                remediation: None,
            });
        }

        findings
    }
}

impl Scanner for EttercapScanner {
    fn name(&self) -> &'static str { "ettercap" }

    fn scan(&self, target: IpAddr) -> Result<ScanResult> {
        // Default gateway detection would go here
        let gateway: IpAddr = "192.168.1.1".parse().unwrap();
        self.arp_check(target, gateway)
    }

    fn is_available(&self) -> bool {
        Command::new(&self.binary)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}
