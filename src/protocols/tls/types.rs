//! TLS protocol types

pub use crate::types::Ja3Fingerprint;
use serde::{Deserialize, Serialize};

/// TLS Suricata keywords supported
pub const TLS_KEYWORDS: &[&str] = &[
    "tls.sni",
    "tls.cert_subject",
    "tls.cert_issuer",
    "tls.cert_serial",
    "tls.cert_fingerprint",
    "tls.version",
    "tls.ciphers",
    "ja3.hash",
    "ja3.string",
    "ja3s.hash",
    "ja3s.string",
];

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TlsVersion(pub u16);

impl TlsVersion {
    pub const SSL30: TlsVersion = TlsVersion(0x0300);
    pub const TLS10: TlsVersion = TlsVersion(0x0301);
    pub const TLS11: TlsVersion = TlsVersion(0x0302);
    pub const TLS12: TlsVersion = TlsVersion(0x0303);
    pub const TLS13: TlsVersion = TlsVersion(0x0304);
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0x0300 => write!(f, "SSLv3"),
            0x0301 => write!(f, "TLSv1.0"),
            0x0302 => write!(f, "TLSv1.1"),
            0x0303 => write!(f, "TLSv1.2"),
            0x0304 => write!(f, "TLSv1.3"),
            _ => write!(f, "Unknown(0x{:04x})", self.0),
        }
    }
}

/// TLS handshake data
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsHandshake {
    pub version: TlsVersion,
    pub sni: Option<String>,
    pub ja3: Option<Ja3Fingerprint>,
    pub ja3s: Option<Ja3Fingerprint>,
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    pub signature_algorithms: Vec<u16>,
}

/// TLS record types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsRecordType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
    Unknown(u8),
}

impl From<u8> for TlsRecordType {
    fn from(val: u8) -> Self {
        match val {
            20 => TlsRecordType::ChangeCipherSpec,
            21 => TlsRecordType::Alert,
            22 => TlsRecordType::Handshake,
            23 => TlsRecordType::ApplicationData,
            24 => TlsRecordType::Heartbeat,
            other => TlsRecordType::Unknown(other),
        }
    }
}

/// TLS handshake types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsHandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
    Unknown(u8),
}

impl From<u8> for TlsHandshakeType {
    fn from(val: u8) -> Self {
        match val {
            1 => TlsHandshakeType::ClientHello,
            2 => TlsHandshakeType::ServerHello,
            11 => TlsHandshakeType::Certificate,
            12 => TlsHandshakeType::ServerKeyExchange,
            13 => TlsHandshakeType::CertificateRequest,
            14 => TlsHandshakeType::ServerHelloDone,
            15 => TlsHandshakeType::CertificateVerify,
            16 => TlsHandshakeType::ClientKeyExchange,
            20 => TlsHandshakeType::Finished,
            other => TlsHandshakeType::Unknown(other),
        }
    }
}

/// Known malicious JA3 hashes
pub const SUSPICIOUS_JA3: &[&str] = &[
    "e7d705a3286e19ea42f587b344ee6865", // Cobalt Strike
    "51c64c77e60f3980eea90869b68c58a8", // Metasploit
];
