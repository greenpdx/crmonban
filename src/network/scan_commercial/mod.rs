//! Commercial scanning tools (Nessus, Acunetix)
//!
//! Only used when explicitly requested via config.

mod nessus;
mod acunetix;

pub use nessus::NessusScanner;
pub use acunetix::AcunetixScanner;

use std::net::IpAddr;
use crate::network::{ScanResult, ToolPaths};

/// Commercial scanner trait
pub trait CommercialScanner: Send + Sync {
    fn name(&self) -> &'static str;
    fn scan(&self, target: IpAddr) -> anyhow::Result<ScanResult>;
    fn is_configured(&self) -> bool;
    fn license_valid(&self) -> bool;
}

/// Commercial scan runner
pub struct CommercialScanRunner {
    nessus: Option<NessusScanner>,
    acunetix: Option<AcunetixScanner>,
}

impl CommercialScanRunner {
    pub fn new(tools: &ToolPaths) -> Self {
        let nessus = tools.nessus_cli.as_ref().map(|p| NessusScanner::new(p));
        let acunetix = tools.acunetix_cli.as_ref().map(|p| AcunetixScanner::new(p));

        Self { nessus, acunetix }
    }

    /// Run Nessus if configured
    pub fn run_nessus(&self, target: IpAddr) -> Option<anyhow::Result<ScanResult>> {
        self.nessus.as_ref().map(|n| n.scan(target))
    }

    /// Run Acunetix if configured
    pub fn run_acunetix(&self, target: IpAddr) -> Option<anyhow::Result<ScanResult>> {
        self.acunetix.as_ref().map(|a| a.scan(target))
    }

    /// Check which commercial tools are available
    pub fn available(&self) -> Vec<&'static str> {
        let mut tools = Vec::new();
        if self.nessus.as_ref().map(|n| n.is_configured()).unwrap_or(false) {
            tools.push("nessus");
        }
        if self.acunetix.as_ref().map(|a| a.is_configured()).unwrap_or(false) {
            tools.push("acunetix");
        }
        tools
    }
}
