//! Metasploit Framework integration

use std::net::IpAddr;
use std::process::Command;
use anyhow::{Result, Context};
use tracing::info;

use crate::network::{ScanResult, Finding, FindingSeverity, ToolPaths};
use super::Scanner;

pub struct MetasploitScanner {
    binary: String,
}

impl MetasploitScanner {
    pub fn new(tools: &ToolPaths) -> Self {
        Self {
            binary: tools.msfconsole.clone(),
        }
    }

    /// Run auxiliary scanner modules
    pub fn aux_scan(&self, target: IpAddr) -> Result<ScanResult> {
        info!("Running Metasploit auxiliary scans on {}", target);

        let script = format!(r#"
use auxiliary/scanner/portscan/tcp
set RHOSTS {}
set THREADS 10
run
use auxiliary/scanner/smb/smb_version
set RHOSTS {}
run
use auxiliary/scanner/ssh/ssh_version
set RHOSTS {}
run
exit
"#, target, target, target);

        let output = self.run_script(&script)?;
        let findings = self.parse_output(&output);

        Ok(ScanResult {
            target,
            tool: "metasploit".into(),
            success: true,
            findings,
            raw_output: Some(output),
        })
    }

    /// Check specific vulnerability
    pub fn check_vuln(&self, target: IpAddr, module: &str) -> Result<ScanResult> {
        info!("Checking {} for vulnerability: {}", target, module);

        let script = format!(r#"
use {}
set RHOSTS {}
check
exit
"#, module, target);

        let output = self.run_script(&script)?;
        let findings = self.parse_vuln_check(&output, module);

        Ok(ScanResult {
            target,
            tool: "metasploit-check".into(),
            success: true,
            findings,
            raw_output: Some(output),
        })
    }

    /// Run resource script
    pub fn run_resource(&self, target: IpAddr, resource_file: &str) -> Result<ScanResult> {
        let output = Command::new(&self.binary)
            .args(["-q", "-r", resource_file])
            .env("RHOSTS", target.to_string())
            .output()
            .context("Failed to run msfconsole")?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let findings = self.parse_output(&stdout);

        Ok(ScanResult {
            target,
            tool: "metasploit-resource".into(),
            success: output.status.success(),
            findings,
            raw_output: Some(stdout),
        })
    }

    fn run_script(&self, script: &str) -> Result<String> {
        let child = Command::new(&self.binary)
            .args(["-q", "-x", script])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("Failed to spawn msfconsole")?;

        let output = child.wait_with_output()?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn parse_output(&self, output: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for line in output.lines() {
            // Detect open ports
            if line.contains("TCP OPEN") || line.contains("- open") {
                findings.push(Finding {
                    severity: FindingSeverity::Info,
                    title: "Service Detected".into(),
                    description: line.trim().to_string(),
                    port: self.extract_port(line),
                    cve: None,
                    remediation: None,
                });
            }

            // Detect SMB/SSH versions
            if line.contains("SMB") || line.contains("SSH") {
                if line.contains("vulnerable") || line.contains("outdated") {
                    findings.push(Finding {
                        severity: FindingSeverity::High,
                        title: "Vulnerable Service Version".into(),
                        description: line.trim().to_string(),
                        port: self.extract_port(line),
                        cve: None,
                        remediation: Some("Update service to latest version".into()),
                    });
                }
            }
        }

        findings
    }

    fn parse_vuln_check(&self, output: &str, module: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if output.contains("appears to be vulnerable") || output.contains("is vulnerable") {
            findings.push(Finding {
                severity: FindingSeverity::Critical,
                title: format!("Vulnerable: {}", module),
                description: "Target is vulnerable to this exploit".into(),
                port: None,
                cve: self.extract_cve_from_module(module),
                remediation: Some("Apply vendor patches immediately".into()),
            });
        } else if output.contains("safe") || output.contains("not vulnerable") {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                title: format!("Not Vulnerable: {}", module),
                description: "Target does not appear vulnerable".into(),
                port: None,
                cve: None,
                remediation: None,
            });
        }

        findings
    }

    fn extract_port(&self, line: &str) -> Option<u16> {
        // Extract port from formats like ":22" or "port 22"
        for word in line.split_whitespace() {
            if let Some(port_str) = word.strip_prefix(':') {
                if let Ok(port) = port_str.parse() {
                    return Some(port);
                }
            }
            if word.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(port) = word.parse::<u16>() {
                    if port > 0 {
                        return Some(port);
                    }
                }
            }
        }
        None
    }

    fn extract_cve_from_module(&self, module: &str) -> Option<String> {
        // Many MSF modules have CVE in name
        if module.contains("cve_") {
            let parts: Vec<&str> = module.split('/').collect();
            for part in parts {
                if part.starts_with("cve_") {
                    return Some(part.replace("_", "-").to_uppercase());
                }
            }
        }
        None
    }
}

impl Scanner for MetasploitScanner {
    fn name(&self) -> &'static str { "metasploit" }

    fn scan(&self, target: IpAddr) -> Result<ScanResult> {
        self.aux_scan(target)
    }

    fn is_available(&self) -> bool {
        Command::new(&self.binary)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}
