//! Acunetix web vulnerability scanner integration
//!
//! Commercial tool - only used when explicitly configured.

use std::net::IpAddr;
use std::process::Command;
use anyhow::{Result, Context};
use tracing::{info, warn};

use crate::network::{ScanResult, Finding, FindingSeverity};
use super::CommercialScanner;

pub struct AcunetixScanner {
    cli_path: String,
    api_url: Option<String>,
    api_key: Option<String>,
}

impl AcunetixScanner {
    pub fn new(cli_path: &str) -> Self {
        Self {
            cli_path: cli_path.to_string(),
            api_url: std::env::var("ACUNETIX_API_URL").ok(),
            api_key: std::env::var("ACUNETIX_API_KEY").ok(),
        }
    }

    /// Full web application scan
    pub fn web_scan(&self, target: IpAddr, port: u16, https: bool) -> Result<ScanResult> {
        let scheme = if https { "https" } else { "http" };
        let url = format!("{}://{}:{}/", scheme, target, port);

        info!("Running Acunetix scan on {}", url);

        let output = Command::new(&self.cli_path)
            .args([
                "scan",
                "--url", &url,
                "--profile", "full",
                "--format", "json",
                "--output", "/tmp/acunetix_report.json",
            ])
            .output()
            .context("Failed to run Acunetix")?;

        let findings = self.parse_report("/tmp/acunetix_report.json")?;

        Ok(ScanResult {
            target,
            tool: "acunetix".into(),
            success: output.status.success(),
            findings,
            raw_output: Some(String::from_utf8_lossy(&output.stdout).to_string()),
        })
    }

    /// Network security audit
    pub fn network_audit(&self, target: IpAddr) -> Result<ScanResult> {
        info!("Running Acunetix network audit on {}", target);

        let output = Command::new(&self.cli_path)
            .args([
                "network-scan",
                "--target", &target.to_string(),
                "--format", "json",
            ])
            .output()
            .context("Failed to run Acunetix network scan")?;

        let findings = self.parse_network_output(&String::from_utf8_lossy(&output.stdout));

        Ok(ScanResult {
            target,
            tool: "acunetix-network".into(),
            success: output.status.success(),
            findings,
            raw_output: Some(String::from_utf8_lossy(&output.stdout).to_string()),
        })
    }

    fn parse_report(&self, path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        if let Ok(content) = std::fs::read_to_string(path) {
            // OWASP Top 10 detection
            let vulns = [
                ("SQL Injection", FindingSeverity::Critical, "Use parameterized queries"),
                ("Cross-site Scripting", FindingSeverity::High, "Encode output, use CSP"),
                ("XSS", FindingSeverity::High, "Encode output, use CSP"),
                ("CSRF", FindingSeverity::Medium, "Use anti-CSRF tokens"),
                ("Path Traversal", FindingSeverity::High, "Validate and sanitize paths"),
                ("Command Injection", FindingSeverity::Critical, "Avoid shell commands, sanitize input"),
                ("SSRF", FindingSeverity::High, "Validate URLs, use allowlist"),
                ("XXE", FindingSeverity::High, "Disable external entities"),
                ("Insecure Deserialization", FindingSeverity::Critical, "Use safe serialization"),
                ("Security Misconfiguration", FindingSeverity::Medium, "Review security headers"),
            ];

            for (vuln_name, severity, remediation) in vulns {
                if content.contains(vuln_name) {
                    findings.push(Finding {
                        severity,
                        title: vuln_name.to_string(),
                        description: format!("{} vulnerability detected", vuln_name),
                        port: None,
                        cve: None,
                        remediation: Some(remediation.to_string()),
                    });
                }
            }
        }

        Ok(findings)
    }

    fn parse_network_output(&self, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Parse network audit results
        if output.contains("open port") || output.contains("service detected") {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                title: "Network Services Detected".into(),
                description: "Network audit completed".into(),
                port: None,
                cve: None,
                remediation: None,
            });
        }

        if output.contains("vulnerable") || output.contains("outdated") {
            findings.push(Finding {
                severity: FindingSeverity::High,
                title: "Vulnerable Service".into(),
                description: "Outdated or vulnerable service detected".into(),
                port: None,
                cve: None,
                remediation: Some("Update to latest version".into()),
            });
        }

        findings
    }

    /// Detect web ports on target
    pub fn detect_web_ports(target: IpAddr) -> Vec<(u16, bool)> {
        use std::net::{TcpStream, SocketAddr};
        use std::time::Duration;

        let ports = [(80, false), (443, true), (8080, false), (8443, true)];
        let mut found = Vec::new();

        for (port, https) in ports {
            let addr = SocketAddr::new(target, port);
            if TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok() {
                found.push((port, https));
            }
        }
        found
    }
}

impl CommercialScanner for AcunetixScanner {
    fn name(&self) -> &'static str { "acunetix" }

    fn scan(&self, target: IpAddr) -> Result<ScanResult> {
        // Detect web ports first
        let web_ports = Self::detect_web_ports(target);

        if let Some((port, https)) = web_ports.first() {
            self.web_scan(target, *port, *https)
        } else {
            // No web ports, run network audit
            self.network_audit(target)
        }
    }

    fn is_configured(&self) -> bool {
        std::path::Path::new(&self.cli_path).exists() || self.api_url.is_some()
    }

    fn license_valid(&self) -> bool {
        self.is_configured()
    }
}
