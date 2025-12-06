//! Nmap network scanner integration

use std::net::IpAddr;
use std::process::Command;
use anyhow::{Result, Context};
use tracing::{info, debug, warn};

use crate::network::{ScanResult, Finding, FindingSeverity, ToolPaths};
use super::Scanner;

pub struct NmapScanner {
    binary: String,
    /// Run vulnerability scripts
    vuln_scan: bool,
}

impl NmapScanner {
    pub fn new(tools: &ToolPaths, vuln_scan: bool) -> Self {
        Self {
            binary: tools.nmap.clone(),
            vuln_scan,
        }
    }

    /// Quick port scan
    pub fn port_scan(&self, target: IpAddr) -> Result<ScanResult> {
        info!("Running Nmap port scan on {}", target);

        let output = Command::new(&self.binary)
            .args(["-sS", "-sV", "-O", "-T4", "--top-ports", "1000", "-oX", "-"])
            .arg(target.to_string())
            .output()
            .context("Failed to run nmap")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let findings = self.parse_xml_output(&stdout);

        Ok(ScanResult {
            target,
            tool: "nmap".into(),
            success: output.status.success(),
            findings,
            raw_output: Some(stdout.to_string()),
        })
    }

    /// Vulnerability script scan
    pub fn vuln_scan(&self, target: IpAddr) -> Result<ScanResult> {
        info!("Running Nmap vuln scripts on {}", target);

        let output = Command::new(&self.binary)
            .args(["--script", "vuln", "-oX", "-"])
            .arg(target.to_string())
            .output()
            .context("Failed to run nmap vuln scan")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let findings = self.parse_vuln_output(&stdout);

        Ok(ScanResult {
            target,
            tool: "nmap-vuln".into(),
            success: output.status.success(),
            findings,
            raw_output: Some(stdout.to_string()),
        })
    }

    fn parse_xml_output(&self, xml: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Simple parsing - production would use proper XML parser
        for line in xml.lines() {
            if line.contains("<port ") && line.contains("state=\"open\"") {
                if let Some(port) = self.extract_port(line) {
                    findings.push(Finding {
                        severity: FindingSeverity::Info,
                        title: format!("Open port {}", port),
                        description: format!("Port {} is open", port),
                        port: Some(port),
                        cve: None,
                        remediation: None,
                    });
                }
            }
        }
        findings
    }

    fn parse_vuln_output(&self, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for line in output.lines() {
            if line.contains("VULNERABLE") || line.contains("CVE-") {
                let cve = self.extract_cve(line);
                findings.push(Finding {
                    severity: if cve.is_some() { FindingSeverity::High } else { FindingSeverity::Medium },
                    title: "Vulnerability detected".into(),
                    description: line.trim().to_string(),
                    port: None,
                    cve,
                    remediation: Some("Apply security patches".into()),
                });
            }
        }
        findings
    }

    fn extract_port(&self, line: &str) -> Option<u16> {
        line.split("portid=\"")
            .nth(1)?
            .split('"')
            .next()?
            .parse()
            .ok()
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

impl Scanner for NmapScanner {
    fn name(&self) -> &'static str { "nmap" }

    fn scan(&self, target: IpAddr) -> Result<ScanResult> {
        let mut result = self.port_scan(target)?;

        if self.vuln_scan {
            let vuln_result = self.vuln_scan(target)?;
            result.findings.extend(vuln_result.findings);
        }

        Ok(result)
    }

    fn is_available(&self) -> bool {
        Command::new(&self.binary)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}
