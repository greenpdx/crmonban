//! SMTP protocol types and Suricata keywords

pub use crate::types::protocols::{
    SmtpEvent, SmtpAuthMechanism, SmtpTransaction, SmtpHeaders, SmtpAttachment, EmailAddress,
};

/// SMTP Suricata keywords supported
pub const SMTP_KEYWORDS: &[&str] = &[
    // File data keywords
    "file.data",
    "file.name",
    // SMTP specific
    "smtp.mail_from",
    "smtp.rcpt_to",
    "smtp.helo",
    // Header keywords
    "smtp.from",
    "smtp.to",
    "smtp.subject",
    "smtp.message_id",
    "smtp.reply_to",
    "smtp.x_mailer",
    "smtp.received",
    // Content keywords
    "smtp.body",
    "smtp.headers",
];

/// Dangerous file extensions for attachments
pub const DANGEROUS_EXTENSIONS: &[&str] = &[
    // Executables
    "exe", "scr", "pif", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "msi", "msp", "hta", "cpl", "msc", "jar", "gadget", "inf",
    "reg", "scf", "lnk", "pcd", "shs",
    // Scripts
    "py", "pl", "rb", "sh", "bash", "php",
    // Office macros
    "docm", "xlsm", "pptm", "dotm", "xlam", "ppam",
    // Archives (often used to hide malware)
    "zip", "rar", "7z", "ace", "iso", "img",
];

/// Suspicious sender domains (free email services often used for attacks)
pub const SUSPICIOUS_FREE_MAIL_DOMAINS: &[&str] = &[
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "tempmail.com", "throwaway.email", "yopmail.com",
];

/// Known bad TLDs
pub const SUSPICIOUS_TLDS: &[&str] = &[
    ".xyz", ".top", ".work", ".click", ".loan", ".gq", ".cf", ".tk", ".ml", ".ga",
    ".pw", ".cc", ".ws", ".bid", ".trade", ".date", ".racing", ".review", ".stream",
    ".download", ".win", ".accountant",
];

/// Phishing brand impersonation patterns
pub const PHISHING_BRAND_PATTERNS: &[&str] = &[
    "paypa1", "paypai", "app1e", "amaz0n", "micros0ft", "g00gle",
    "faceb00k", "linkedln", "twltter", "netfllx", "dr0pbox",
];

/// SMTP response code categories
pub mod response_codes {
    pub const SERVICE_READY: u16 = 220;
    pub const SERVICE_CLOSING: u16 = 221;
    pub const AUTH_SUCCESS: u16 = 235;
    pub const OK: u16 = 250;
    pub const AUTH_CONTINUE: u16 = 334;
    pub const START_MAIL: u16 = 354;
    pub const SERVICE_UNAVAILABLE: u16 = 421;
    pub const AUTH_FAILED: u16 = 535;
    pub const TRANSACTION_FAILED: u16 = 554;
}
