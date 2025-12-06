//! Burp Suite integration (if web server detected)

use std::net::IpAddr;
use std::process::Command;
use anyhow::{Result, Context, bail};
use tracing::{info, warn};

use crate::network::{ScanResult, Finding, FindingSeverity, ToolPaths};
use super::Scanner;

pub struct BurpScanner {
    binary: Option<String>,
    api_url: Option<String>,
    api_key: Option<String>,
}

impl BurpScanner {
    pub fn new(tools: &ToolPaths) -> Self {
        Self {
            binary: tools.burp_cli.clone(),
            api_url: std::env::var("BURP_API_URL").ok(),
            api_key: std::env::var("BURP_API_KEY").ok(),
        }
    }

    /// Check if target has web services
    pub fn detect_web_services(target: IpAddr) -> Vec<u16> {
        let web_ports = [80, 443, 8080, 8443, 8000, 3000, 5000];
        let mut found = Vec::new();

        for port in web_ports {
            if Self::check_port(target, port) {
                found.push(port);
            }
        }
        found
    }

    fn check_port(target: IpAddr, port: u16) -> bool {
        use std::net::{TcpStream, SocketAddr};
        use std::time::Duration;

        let addr = SocketAddr::new(target, port);
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok()
    }

    /// Scan web application
    pub fn scan_web(&self, target: IpAddr, port: u16, https: bool) -> Result<ScanResult> {
        let scheme = if https { "https" } else { "http" };
        let url = format!("{}://{}:{}/", scheme, target, port);

        info!("Running Burp scan on {}", url);

        if let Some(ref binary) = self.binary {
            self.scan_with_cli(target, &url, binary)
        } else if self.api_url.is_some() {
            self.scan_with_api(target, &url)
        } else {
            bail!("No Burp CLI or API configured")
        }
    }

    fn scan_with_cli(&self, target: IpAddr, url: &str, binary: &str) -> Result<ScanResult> {
        let output = Command::new(binary)
            .args(["--scan", url, "--output", "/tmp/burp_report.json"])
            .output()
            .context("Failed to run Burp CLI")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let findings = self.parse_report("/tmp/burp_report.json")?;

        Ok(ScanResult {
            target,
            tool: "burp".into(),
            success: output.status.success(),
            findings,
            raw_output: Some(stdout.to_string()),
        })
    }

    fn scan_with_api(&self, target: IpAddr, url: &str) -> Result<ScanResult> {
        // API-based scanning would use reqwest/curl
        warn!("Burp API scanning not yet implemented");

        Ok(ScanResult {
            target,
            tool: "burp-api".into(),
            success: false,
            findings: vec![],
            raw_output: Some("API scanning not implemented".into()),
        })
    }

    fn parse_report(&self, path: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Parse Burp JSON report
        if let Ok(content) = std::fs::read_to_string(path) {
            // Simple parsing - production would use serde_json
            if content.contains("SQL injection") {
                findings.push(Finding {
                    severity: FindingSeverity::Critical,
                    title: "SQL Injection".into(),
                    description: "SQL injection vulnerability detected".into(),
                    port: None,
                    cve: None,
                    remediation: Some("Use parameterized queries".into()),
                });
            }
            if content.contains("Cross-site scripting") || content.contains("XSS") {
                findings.push(Finding {
                    severity: FindingSeverity::High,
                    title: "Cross-Site Scripting (XSS)".into(),
                    description: "XSS vulnerability detected".into(),
                    port: None,
                    cve: None,
                    remediation: Some("Encode output, use CSP".into()),
                });
            }
        }

        Ok(findings)
    }
}

impl Scanner for BurpScanner {
    fn name(&self) -> &'static str { "burp" }

    fn scan(&self, target: IpAddr) -> Result<ScanResult> {
        let web_ports = Self::detect_web_services(target);

        if web_ports.is_empty() {
            return Ok(ScanResult {
                target,
                tool: "burp".into(),
                success: true,
                findings: vec![Finding {
                    severity: FindingSeverity::Info,
                    title: "No Web Services".into(),
                    description: "No web services detected on common ports".into(),
                    port: None,
                    cve: None,
                    remediation: None,
                }],
                raw_output: None,
            });
        }

        // Scan first detected web port
        let port = web_ports[0];
        let https = port == 443 || port == 8443;
        self.scan_web(target, port, https)
    }

    fn is_available(&self) -> bool {
        self.binary.is_some() || self.api_url.is_some()
    }
}
