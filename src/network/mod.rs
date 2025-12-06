//! Network scanning and analysis
//!
//! Features:
//! - `scan`: Nmap, Ettercap, Metasploit, Burp (free)
//! - `scan-commercial`: Nessus, Acunetix (commercial)

#[cfg(feature = "scan")]
pub mod scan;

#[cfg(feature = "scan-commercial")]
pub mod scan_commercial;

mod config;
pub mod cli;

pub use config::*;
