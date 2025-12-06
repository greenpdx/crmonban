//! Nessus vulnerability scanner integration
//!
//! Commercial tool - only used when explicitly configured.

use std::net::IpAddr;
use std::process::Command;
use anyhow::{Result, Context};
use tracing::{info, warn};

use crate::network::{ScanResult, Finding, FindingSeverity};
use super::CommercialScanner;

pub struct NessusScanner {
    cli_path: String,
    api_url: Option<String>,
    api_key: Option<String>,
}

impl NessusScanner {
    pub fn new(cli_path: &str) -> Self {
        Self {
            cli_path: cli_path.to_string(),
            api_url: std::env::var("NESSUS_API_URL").ok(),
            api_key: std::env::var("NESSUS_API_KEY").ok(),
        }
    }

    /// Run full vulnerability scan
    pub fn vuln_scan(&self, target: IpAddr, policy: &str) -> Result<ScanResult> {
        info!("Running Nessus scan on {} with policy {}", target, policy);

        // Nessus CLI scan
        let output = Command::new(&self.cli_path)
            .args([
                "scan",
                "--target", &target.to_string(),
                "--policy", policy,
                "--format", "json",
                "--output", "/tmp/nessus_report.json",
            ])
            .output()
            .context("Failed to run Nessus CLI")?;

        let findings = self.parse_report("/tmp/nessus_report.json")?;

        Ok(ScanResult {
            target,
            tool: "nessus".into(),
            success: output.status.success(),
            findings,
            raw_output: Some(String::from_utf8_lossy(&output.stdout).to_string()),
        })
    }

    /// Run compliance audit
    pub fn compliance_scan(&self, target: IpAddr, benchmark: &str) -> Result<ScanResult> {
        info!("Running Nessus compliance audit: {} on {}", benchmark, target);

        let output = Command::new(&self.cli_path)
            .args([
                "audit",
                "--target", &target.to_string(),
                "--benchmark", benchmark,
                "--format", "json",
            ])
            .output()
            .context("Failed to run Nessus compliance")?;

        let findings = self.parse_compliance(&String::from_utf8_lossy(&output.stdout));

        Ok(ScanResult {
            target,
            tool: "nessus-compliance".into(),
            success: output.status.success(),
            findings,
            raw_output: Some(String::from_utf8_lossy(&output.stdout).to_string()),
        })
    }

    fn parse_report(&self, path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        if let Ok(content) = std::fs::read_to_string(path) {
            // Parse Nessus JSON - simplified
            // Real impl would use serde_json with proper structs

            // Example parsing for CVE findings
            for line in content.lines() {
                if line.contains("\"severity\":") {
                    let severity = if line.contains("\"4\"") || line.contains("Critical") {
                        FindingSeverity::Critical
                    } else if line.contains("\"3\"") || line.contains("High") {
                        FindingSeverity::High
                    } else if line.contains("\"2\"") || line.contains("Medium") {
                        FindingSeverity::Medium
                    } else if line.contains("\"1\"") || line.contains("Low") {
                        FindingSeverity::Low
                    } else {
                        FindingSeverity::Info
                    };

                    findings.push(Finding {
                        severity,
                        title: "Nessus Finding".into(),
                        description: line.trim().to_string(),
                        port: None,
                        cve: self.extract_cve(line),
                        remediation: None,
                    });
                }
            }
        }

        Ok(findings)
    }

    fn parse_compliance(&self, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for line in output.lines() {
            if line.contains("FAILED") {
                findings.push(Finding {
                    severity: FindingSeverity::Medium,
                    title: "Compliance Failure".into(),
                    description: line.trim().to_string(),
                    port: None,
                    cve: None,
                    remediation: Some("Review compliance benchmark requirements".into()),
                });
            }
        }

        findings
    }

    fn extract_cve(&self, line: &str) -> Option<String> {
        if let Some(start) = line.find("CVE-") {
            let rest = &line[start..];
            let end = rest.find(|c: char| !c.is_alphanumeric() && c != '-').unwrap_or(rest.len());
            Some(rest[..end].to_string())
        } else {
            None
        }
    }
}

impl CommercialScanner for NessusScanner {
    fn name(&self) -> &'static str { "nessus" }

    fn scan(&self, target: IpAddr) -> Result<ScanResult> {
        self.vuln_scan(target, "advanced")
    }

    fn is_configured(&self) -> bool {
        std::path::Path::new(&self.cli_path).exists() || self.api_url.is_some()
    }

    fn license_valid(&self) -> bool {
        // Would check license status via API
        self.is_configured()
    }
}
