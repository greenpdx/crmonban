//! SSH protocol types

pub use crmonban_types::protocols::{
    SshEvent, SshAuthMethod, SshNegotiatedAlgorithms, SshVersionInfo, HasshFingerprint,
};

/// SSH Suricata keywords supported
pub const SSH_KEYWORDS: &[&str] = &[
    "ssh.proto",
    "ssh.protoversion",
    "ssh.software",
    "ssh.softwareversion",
    "ssh.hassh",
    "ssh.hassh.server",
    "ssh.hassh.string",
    "ssh.hassh.server.string",
];

/// Known malicious HASSH fingerprints
pub const SUSPICIOUS_HASSH: &[&str] = &[
    // Common attack tools
    "ec7378c1a92f5a8dde7e8b7a1ddf33d1", // Metasploit
];

/// Suspicious SSH software patterns
pub const SUSPICIOUS_SOFTWARE: &[&str] = &[
    "libssh", // Often used in scanners
    "paramiko", // Python SSH library, common in scripts
    "putty", // While legitimate, used by attackers
];

/// Common brute force usernames
pub const COMMON_BRUTE_USERNAMES: &[&str] = &[
    "root", "admin", "administrator", "test", "user", "guest",
    "oracle", "postgres", "mysql", "ftp", "backup", "ubuntu",
    "pi", "ec2-user", "centos", "deploy", "git", "jenkins",
];
