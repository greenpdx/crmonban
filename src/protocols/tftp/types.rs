//! TFTP protocol types
pub const TFTP_KEYWORDS: &[&str] = &["tftp.file", "tftp.opcode", "tftp.mode", "tftp.block", "tftp.error"];

pub const TFTP_OPCODES: &[(u16, &str)] = &[
    (1, "RRQ"), (2, "WRQ"), (3, "DATA"), (4, "ACK"), (5, "ERROR"), (6, "OACK"),
];

pub const SUSPICIOUS_EXTENSIONS: &[&str] = &[".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh", ".py"];
