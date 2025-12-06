//! Scan automation configuration

use std::net::IpAddr;
use serde::{Deserialize, Serialize};

/// Automated scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Enable automated scanning on incidents
    pub auto_scan: bool,
    /// Triggers that initiate scans
    pub triggers: Vec<ScanTrigger>,
    /// Default scan actions
    pub actions: ScanActions,
    /// Tool paths
    pub tools: ToolPaths,
}

/// What triggers an automated scan
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanTrigger {
    /// Scan on any ban
    OnBan,
    /// Scan on high/critical severity
    OnHighSeverity,
    /// Scan on exploit attempt detection
    OnExploitAttempt,
    /// Scan on port scan detection
    OnPortScan,
    /// Scan on lateral movement detection
    OnLateralMovement,
    /// Manual trigger only
    Manual,
}

/// Actions to perform per scan type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanActions {
    /// Run Nmap port/service scan
    pub nmap_scan: bool,
    /// Run Nmap vulnerability scripts
    pub nmap_vuln: bool,
    /// Check for ARP poisoning with Ettercap
    pub ettercap_arp_check: bool,
    /// Run Metasploit auxiliary scanners
    pub msf_aux_scan: bool,
    /// Run Burp scan if web server detected
    pub burp_if_web: bool,
    /// Use commercial tools (requires scan-commercial feature)
    pub use_commercial: bool,
}

/// Tool binary paths
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPaths {
    pub nmap: String,
    pub ettercap: String,
    pub msfconsole: String,
    pub burp_cli: Option<String>,
    /// Nessus CLI path (only used with scan-commercial feature)
    #[serde(default)]
    pub nessus_cli: Option<String>,
    /// Acunetix CLI path (only used with scan-commercial feature)
    #[serde(default)]
    pub acunetix_cli: Option<String>,
}

/// Scan request
#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub target: IpAddr,
    pub reason: String,
    pub trigger: ScanTrigger,
    pub actions: ScanActions,
}

/// Scan result
#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub target: IpAddr,
    pub tool: String,
    pub success: bool,
    pub findings: Vec<Finding>,
    pub raw_output: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub port: Option<u16>,
    pub cve: Option<String>,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            auto_scan: false,
            triggers: vec![ScanTrigger::Manual],
            actions: ScanActions::default(),
            tools: ToolPaths::default(),
        }
    }
}

impl Default for ScanActions {
    fn default() -> Self {
        Self {
            nmap_scan: true,
            nmap_vuln: false,
            ettercap_arp_check: false,
            msf_aux_scan: false,
            burp_if_web: false,
            use_commercial: false,
        }
    }
}

impl Default for ToolPaths {
    fn default() -> Self {
        Self {
            nmap: "nmap".into(),
            ettercap: "ettercap".into(),
            msfconsole: "msfconsole".into(),
            burp_cli: None,
            nessus_cli: None,
            acunetix_cli: None,
        }
    }
}
