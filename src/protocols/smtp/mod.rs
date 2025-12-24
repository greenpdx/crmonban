//! SMTP protocol analyzer module
//!
//! Provides SMTP parsing and security analysis for email traffic.
//!
//! # Security Detections
//!
//! - Spam detection (subject patterns, excessive recipients)
//! - Phishing detection (subject patterns, domain spoofing, typosquatting)
//! - Email spoofing (SPF/DKIM/DMARC failures)
//! - Open relay abuse detection
//! - Authentication brute force attacks
//! - Malware attachment detection (dangerous file extensions)
//! - Mass mailer detection
//! - Header anomaly detection

pub mod parser;
pub mod analyzer;

pub use parser::{SmtpParser, SmtpCommand, SmtpResponse, SmtpParserState};
pub use analyzer::SmtpAnalyzer;
