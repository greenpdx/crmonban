//! DNS protocol types
//!
//! Local types for DNS parsing and detection.

pub use crmonban_types::{DnsMessage, DnsQuery, DnsAnswer, DnsRecordType, DnsRdata};

/// DNS Suricata keywords supported
pub const DNS_KEYWORDS: &[&str] = &[
    "dns.query",
    "dns.opcode",
    "dns.rrname",
    "dns.rrtype",
    "dns.rcode",
];

/// Suspicious domain patterns for DNS detection
pub const SUSPICIOUS_TLD: &[&str] = &[
    ".tk", ".ml", ".ga", ".cf", ".gq",  // Free TLDs often abused
    ".top", ".xyz", ".loan", ".work",    // High-abuse TLDs
    ".onion",                             // Tor
];

/// Known DGA patterns (partial list)
pub const DGA_KEYWORDS: &[&str] = &[
    "dyndns", "no-ip", "afraid.org",
];

/// Response code meanings
pub const RCODE_NAMES: &[(&str, u8)] = &[
    ("NOERROR", 0),
    ("FORMERR", 1),
    ("SERVFAIL", 2),
    ("NXDOMAIN", 3),
    ("NOTIMP", 4),
    ("REFUSED", 5),
];
