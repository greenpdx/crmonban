//! FTP protocol types
pub const FTP_KEYWORDS: &[&str] = &["ftp.command", "ftp.command_data", "ftpdata.command"];

pub const FTP_COMMANDS: &[&str] = &[
    "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN", "PORT", "PASV",
    "TYPE", "STRU", "MODE", "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR",
    "RNTO", "ABOR", "DELE", "RMD", "MKD", "PWD", "LIST", "NLST", "SITE", "SYST",
    "STAT", "HELP", "NOOP", "FEAT", "SIZE", "MDTM", "EPRT", "EPSV",
];

pub const SUSPICIOUS_COMMANDS: &[&str] = &["SITE EXEC", "SITE CHMOD", "SITE CPWD"];
