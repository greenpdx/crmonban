//! Free/open-source network scanning tools
//!
//! - Nmap: Network discovery and port scanning
//! - Ettercap: ARP/MITM analysis
//! - Metasploit: Vulnerability validation
//! - Burp Suite: Web application testing (if web detected)

mod nmap;
mod ettercap;
mod metasploit;
mod burp;
mod runner;

pub use nmap::NmapScanner;
pub use ettercap::EttercapScanner;
pub use metasploit::MetasploitScanner;
pub use burp::BurpScanner;
pub use runner::ScanRunner;

use std::net::IpAddr;
use crate::network::{ScanRequest, ScanResult, ScanActions, ToolPaths};

/// Trait for all scanners
pub trait Scanner: Send + Sync {
    fn name(&self) -> &'static str;
    fn scan(&self, target: IpAddr) -> anyhow::Result<ScanResult>;
    fn is_available(&self) -> bool;
}
