//! Protocol type definitions
//!
//! Contains application layer protocol definitions used for protocol detection.

use serde::{Deserialize, Serialize};

/// Application layer protocol (auto-detected or by port)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum AppProtocol {
    #[default]
    Unknown,
    Http,
    Https,
    Dns,
    Ssh,
    Ftp,
    FtpData,
    Smtp,
    Pop3,
    Imap,
    Smb,
    Mysql,
    Postgres,
    Redis,
    Mongodb,
    Ldap,
    Rdp,
    Vnc,
    Telnet,
    Sip,
    Ntp,
    Dhcp,
    Snmp,
}

impl AppProtocol {
    /// Guess protocol from well-known port
    pub fn from_port(port: u16, proto: crate::core::packet::IpProtocol) -> Self {
        use crate::core::packet::IpProtocol;
        match (proto, port) {
            (IpProtocol::Tcp, 80) => AppProtocol::Http,
            (IpProtocol::Tcp, 443) => AppProtocol::Https,
            (IpProtocol::Tcp, 8080) => AppProtocol::Http,
            (IpProtocol::Tcp, 8443) => AppProtocol::Https,
            (IpProtocol::Udp, 53) | (IpProtocol::Tcp, 53) => AppProtocol::Dns,
            (IpProtocol::Tcp, 22) => AppProtocol::Ssh,
            (IpProtocol::Tcp, 21) => AppProtocol::Ftp,
            (IpProtocol::Tcp, 20) => AppProtocol::FtpData,
            (IpProtocol::Tcp, 25) | (IpProtocol::Tcp, 587) | (IpProtocol::Tcp, 465) => AppProtocol::Smtp,
            (IpProtocol::Tcp, 110) | (IpProtocol::Tcp, 995) => AppProtocol::Pop3,
            (IpProtocol::Tcp, 143) | (IpProtocol::Tcp, 993) => AppProtocol::Imap,
            (IpProtocol::Tcp, 445) | (IpProtocol::Tcp, 139) => AppProtocol::Smb,
            (IpProtocol::Tcp, 3306) => AppProtocol::Mysql,
            (IpProtocol::Tcp, 5432) => AppProtocol::Postgres,
            (IpProtocol::Tcp, 6379) => AppProtocol::Redis,
            (IpProtocol::Tcp, 27017) => AppProtocol::Mongodb,
            (IpProtocol::Tcp, 389) | (IpProtocol::Tcp, 636) => AppProtocol::Ldap,
            (IpProtocol::Tcp, 3389) => AppProtocol::Rdp,
            (IpProtocol::Tcp, 5900..=5909) => AppProtocol::Vnc,
            (IpProtocol::Tcp, 23) => AppProtocol::Telnet,
            (IpProtocol::Udp, 5060) | (IpProtocol::Tcp, 5060) => AppProtocol::Sip,
            (IpProtocol::Udp, 123) => AppProtocol::Ntp,
            (IpProtocol::Udp, 67) | (IpProtocol::Udp, 68) => AppProtocol::Dhcp,
            (IpProtocol::Udp, 161) | (IpProtocol::Udp, 162) => AppProtocol::Snmp,
            _ => AppProtocol::Unknown,
        }
    }
}

impl std::fmt::Display for AppProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppProtocol::Unknown => write!(f, "unknown"),
            AppProtocol::Http => write!(f, "http"),
            AppProtocol::Https => write!(f, "https"),
            AppProtocol::Dns => write!(f, "dns"),
            AppProtocol::Ssh => write!(f, "ssh"),
            AppProtocol::Ftp => write!(f, "ftp"),
            AppProtocol::FtpData => write!(f, "ftp-data"),
            AppProtocol::Smtp => write!(f, "smtp"),
            AppProtocol::Pop3 => write!(f, "pop3"),
            AppProtocol::Imap => write!(f, "imap"),
            AppProtocol::Smb => write!(f, "smb"),
            AppProtocol::Mysql => write!(f, "mysql"),
            AppProtocol::Postgres => write!(f, "postgres"),
            AppProtocol::Redis => write!(f, "redis"),
            AppProtocol::Mongodb => write!(f, "mongodb"),
            AppProtocol::Ldap => write!(f, "ldap"),
            AppProtocol::Rdp => write!(f, "rdp"),
            AppProtocol::Vnc => write!(f, "vnc"),
            AppProtocol::Telnet => write!(f, "telnet"),
            AppProtocol::Sip => write!(f, "sip"),
            AppProtocol::Ntp => write!(f, "ntp"),
            AppProtocol::Dhcp => write!(f, "dhcp"),
            AppProtocol::Snmp => write!(f, "snmp"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::packet::IpProtocol;

    #[test]
    fn test_app_protocol_from_port() {
        assert_eq!(AppProtocol::from_port(80, IpProtocol::Tcp), AppProtocol::Http);
        assert_eq!(AppProtocol::from_port(443, IpProtocol::Tcp), AppProtocol::Https);
        assert_eq!(AppProtocol::from_port(53, IpProtocol::Udp), AppProtocol::Dns);
        assert_eq!(AppProtocol::from_port(22, IpProtocol::Tcp), AppProtocol::Ssh);
        assert_eq!(AppProtocol::from_port(12345, IpProtocol::Tcp), AppProtocol::Unknown);
    }

    #[test]
    fn test_app_protocol_display() {
        assert_eq!(format!("{}", AppProtocol::Http), "http");
        assert_eq!(format!("{}", AppProtocol::Https), "https");
        assert_eq!(format!("{}", AppProtocol::Unknown), "unknown");
    }

    #[test]
    fn test_app_protocol_default() {
        assert_eq!(AppProtocol::default(), AppProtocol::Unknown);
    }
}
