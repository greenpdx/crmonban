//! SMB/CIFS protocol parser and matcher
//!
//! Provides parsing and detection for SMB1, SMB2, and SMB3 protocols.
//!
//! # Features
//!
//! - SMB version detection (SMB1/2.0/2.1/3.0/3.0.2/3.1.1)
//! - Session and authentication tracking
//! - Tree connect and file operation parsing
//! - Named pipe access detection
//! - NTLMSSP authentication parsing
//!
//! # Security Detection
//!
//! - SMB1 usage (legacy, vulnerable)
//! - Authentication brute force
//! - Lateral movement (admin share, PsExec)
//! - Ransomware activity patterns
//! - Suspicious named pipe access
//!
//! # Suricata Keywords
//!
//! The following sticky buffers are available for rule matching:
//!
//! - `smb.share` - Share path being accessed
//! - `smb.named_pipe` - Named pipe being accessed
//! - `smb.command` - SMB command type
//! - `smb.status` - NT status code
//! - `smb.filename` - File being accessed
//! - `smb.version` - Negotiated SMB version
//! - `smb.ntlmssp_user` - NTLMSSP username
//! - `smb.ntlmssp_domain` - NTLMSSP domain
//!
//! # Example Rules
//!
//! ```text
//! alert smb any any -> any any (msg:"SMB Admin share access"; smb.share; content:"ADMIN$"; sid:1000001;)
//! alert smb any any -> any any (msg:"PsExec pipe access"; smb.named_pipe; content:"\\PIPE\\svcctl"; sid:1000002;)
//! ```

mod types;
mod state;
mod parser;
mod match_;

pub use types::*;
pub use state::SmbState;
pub use parser::SmbParser;
pub use match_::SmbMatcher;

use crate::protocols::{ProtocolRegistration, ProtocolParser};
use crate::signatures::ast::Protocol;

/// SMB Suricata keywords
pub const SMB_KEYWORDS: &[&str] = &[
    "smb.share",
    "smb.named_pipe",
    "smb.command",
    "smb.status",
    "smb.filename",
    "smb.version",
    "smb.ntlmssp_user",
    "smb.ntlmssp_domain",
    "smb.dialects",
    "smb.ioctl",
];

/// Register SMB protocol
pub fn registration() -> ProtocolRegistration {
    ProtocolRegistration {
        name: "smb",
        protocol: Protocol::Smb,
        tcp_ports: &[445, 139],
        udp_ports: &[],
        create_parser: || Box::new(SmbParser::new()),
        priority: 50,
        keywords: SMB_KEYWORDS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Direction;

    #[test]
    fn test_registration() {
        let reg = registration();
        assert_eq!(reg.name, "smb");
        assert_eq!(reg.protocol, Protocol::Smb);
        assert_eq!(reg.tcp_ports, &[445, 139]);
        assert!(reg.keywords.contains(&"smb.share"));
    }

    #[test]
    fn test_parser_creation() {
        let reg = registration();
        let parser = (reg.create_parser)();
        assert_eq!(parser.name(), "smb");
        assert_eq!(parser.protocol(), Protocol::Smb);
    }

    #[test]
    fn test_smb2_probe() {
        let parser = SmbParser::new();

        // SMB2 header
        let smb2 = b"\xFESMB@\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(parser.probe(smb2, Direction::ToServer), 100);

        // With NetBIOS header
        let nb_smb2 = b"\x00\x00\x00\x40\xFESMB@\x00\x00\x00";
        assert_eq!(parser.probe(nb_smb2, Direction::ToServer), 100);

        // Random data
        let random = b"hello world this is not smb";
        assert_eq!(parser.probe(random, Direction::ToServer), 0);
    }
}
