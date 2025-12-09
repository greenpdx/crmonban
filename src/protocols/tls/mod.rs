//! TLS protocol analyzer with JA3/JA3S fingerprinting
//!
//! Parses TLS handshakes and extracts fingerprints for client/server identification.

use serde::{Deserialize, Serialize};

use crate::core::flow::Flow;
use crate::core::packet::{Direction, Packet};
use super::{TlsConfig, ProtocolAnalyzer, ProtocolEvent, TlsEvent};

/// JA3 fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja3Fingerprint {
    /// Raw JA3 string
    pub string: String,
    /// MD5 hash of the string
    pub hash: String,
}

impl Default for Ja3Fingerprint {
    fn default() -> Self {
        Self {
            string: String::new(),
            hash: String::new(),
        }
    }
}

/// TLS version
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for TlsHandshake {
    fn default() -> Self {
        Self {
            version: TlsVersion::TLS12,
            sni: None,
            ja3: None,
            ja3s: None,
            cipher_suites: Vec::new(),
            extensions: Vec::new(),
            supported_versions: Vec::new(),
            supported_groups: Vec::new(),
            ec_point_formats: Vec::new(),
            signature_algorithms: Vec::new(),
        }
    }
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

/// TLS protocol analyzer
pub struct TlsAnalyzer {
    config: TlsConfig,
}

impl TlsAnalyzer {
    pub fn new(config: TlsConfig) -> Self {
        Self { config }
    }

    /// Parse TLS record layer
    fn parse_record<'a>(&self, payload: &'a [u8]) -> Option<(TlsRecordType, TlsVersion, &'a [u8])> {
        if payload.len() < 5 {
            return None;
        }

        let record_type = TlsRecordType::from(payload[0]);
        let version = TlsVersion(u16::from_be_bytes([payload[1], payload[2]]));
        let length = u16::from_be_bytes([payload[3], payload[4]]) as usize;

        if payload.len() < 5 + length {
            return None;
        }

        Some((record_type, version, &payload[5..5 + length]))
    }

    /// Parse ClientHello and extract JA3
    fn parse_client_hello(&self, data: &[u8]) -> Option<TlsHandshake> {
        if data.len() < 38 {
            return None;
        }

        // Handshake type (1) + length (3) + version (2) + random (32)
        let handshake_type = TlsHandshakeType::from(data[0]);
        if handshake_type != TlsHandshakeType::ClientHello {
            return None;
        }

        let mut handshake = TlsHandshake::default();
        handshake.version = TlsVersion(u16::from_be_bytes([data[4], data[5]]));

        let mut offset = 38; // Skip to session ID

        // Session ID length
        if offset >= data.len() {
            return Some(handshake);
        }
        let session_id_len = data[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher suites
        if offset + 2 > data.len() {
            return Some(handshake);
        }
        let cipher_suites_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if offset + cipher_suites_len > data.len() {
            return Some(handshake);
        }

        for i in (0..cipher_suites_len).step_by(2) {
            let suite = u16::from_be_bytes([data[offset + i], data[offset + i + 1]]);
            // Filter out GREASE values for JA3
            if !Self::is_grease(suite) {
                handshake.cipher_suites.push(suite);
            }
        }
        offset += cipher_suites_len;

        // Compression methods
        if offset >= data.len() {
            return Some(handshake);
        }
        let compression_len = data[offset] as usize;
        offset += 1 + compression_len;

        // Extensions
        if offset + 2 > data.len() {
            return Some(handshake);
        }
        let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let extensions_end = offset + extensions_len;
        while offset + 4 <= extensions_end && offset + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + ext_len > data.len() {
                break;
            }

            // Filter out GREASE
            if !Self::is_grease(ext_type) {
                handshake.extensions.push(ext_type);
            }

            // Parse specific extensions
            let ext_data = &data[offset..offset + ext_len];
            match ext_type {
                0 => {
                    // SNI
                    handshake.sni = self.parse_sni_extension(ext_data);
                }
                10 => {
                    // Supported groups
                    handshake.supported_groups = self.parse_supported_groups(ext_data);
                }
                11 => {
                    // EC point formats
                    handshake.ec_point_formats = self.parse_ec_point_formats(ext_data);
                }
                13 => {
                    // Signature algorithms
                    handshake.signature_algorithms = self.parse_signature_algorithms(ext_data);
                }
                43 => {
                    // Supported versions
                    handshake.supported_versions = self.parse_supported_versions(ext_data);
                }
                _ => {}
            }

            offset += ext_len;
        }

        // Compute JA3
        if self.config.ja3_enabled {
            handshake.ja3 = Some(self.compute_ja3(&handshake));
        }

        Some(handshake)
    }

    /// Parse ServerHello and extract JA3S
    fn parse_server_hello(&self, data: &[u8]) -> Option<(TlsVersion, u16, Ja3Fingerprint)> {
        if data.len() < 38 {
            return None;
        }

        let handshake_type = TlsHandshakeType::from(data[0]);
        if handshake_type != TlsHandshakeType::ServerHello {
            return None;
        }

        let version = TlsVersion(u16::from_be_bytes([data[4], data[5]]));

        let mut offset = 38; // Skip to session ID

        // Session ID length
        if offset >= data.len() {
            return None;
        }
        let session_id_len = data[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher suite (2 bytes)
        if offset + 2 > data.len() {
            return None;
        }
        let cipher_suite = u16::from_be_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Compression method (1 byte)
        if offset >= data.len() {
            return None;
        }
        offset += 1;

        // Extensions
        let mut extensions = Vec::new();
        if offset + 2 <= data.len() {
            let extensions_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            let extensions_end = offset + extensions_len;
            while offset + 4 <= extensions_end && offset + 4 <= data.len() {
                let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let ext_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
                offset += 4;

                if !Self::is_grease(ext_type) {
                    extensions.push(ext_type);
                }

                offset += ext_len;
            }
        }

        // Compute JA3S
        let ja3s = if self.config.ja3s_enabled {
            self.compute_ja3s(version, cipher_suite, &extensions)
        } else {
            Ja3Fingerprint::default()
        };

        Some((version, cipher_suite, ja3s))
    }

    /// Parse SNI extension
    fn parse_sni_extension(&self, data: &[u8]) -> Option<String> {
        if data.len() < 5 {
            return None;
        }

        // SNI list length (2) + type (1) + name length (2)
        let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + name_len {
            return None;
        }

        String::from_utf8(data[5..5 + name_len].to_vec()).ok()
    }

    /// Parse supported groups extension
    fn parse_supported_groups(&self, data: &[u8]) -> Vec<u16> {
        let mut groups = Vec::new();
        if data.len() < 2 {
            return groups;
        }

        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        for i in (2..2 + len).step_by(2) {
            if i + 1 < data.len() {
                let group = u16::from_be_bytes([data[i], data[i + 1]]);
                if !Self::is_grease(group) {
                    groups.push(group);
                }
            }
        }

        groups
    }

    /// Parse EC point formats extension
    fn parse_ec_point_formats(&self, data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }

        let len = data[0] as usize;
        data[1..].iter().take(len).copied().collect()
    }

    /// Parse signature algorithms extension
    fn parse_signature_algorithms(&self, data: &[u8]) -> Vec<u16> {
        let mut algos = Vec::new();
        if data.len() < 2 {
            return algos;
        }

        let len = u16::from_be_bytes([data[0], data[1]]) as usize;
        for i in (2..2 + len).step_by(2) {
            if i + 1 < data.len() {
                algos.push(u16::from_be_bytes([data[i], data[i + 1]]));
            }
        }

        algos
    }

    /// Parse supported versions extension
    fn parse_supported_versions(&self, data: &[u8]) -> Vec<u16> {
        let mut versions = Vec::new();
        if data.is_empty() {
            return versions;
        }

        let len = data[0] as usize;
        for i in (1..1 + len).step_by(2) {
            if i + 1 < data.len() {
                let version = u16::from_be_bytes([data[i], data[i + 1]]);
                if !Self::is_grease(version) {
                    versions.push(version);
                }
            }
        }

        versions
    }

    /// Compute JA3 fingerprint from ClientHello
    fn compute_ja3(&self, handshake: &TlsHandshake) -> Ja3Fingerprint {
        // JA3 = SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats

        let version = handshake.version.0;
        let ciphers = handshake.cipher_suites
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let extensions = handshake.extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let groups = handshake.supported_groups
            .iter()
            .map(|g| g.to_string())
            .collect::<Vec<_>>()
            .join("-");
        let formats = handshake.ec_point_formats
            .iter()
            .map(|f| f.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let ja3_string = format!("{},{},{},{},{}", version, ciphers, extensions, groups, formats);
        let hash = format!("{:x}", md5::compute(&ja3_string));

        Ja3Fingerprint {
            string: ja3_string,
            hash,
        }
    }

    /// Compute JA3S fingerprint from ServerHello
    fn compute_ja3s(&self, version: TlsVersion, cipher_suite: u16, extensions: &[u16]) -> Ja3Fingerprint {
        // JA3S = SSLVersion,Cipher,Extensions

        let exts = extensions
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let ja3s_string = format!("{},{},{}", version.0, cipher_suite, exts);
        let hash = format!("{:x}", md5::compute(&ja3s_string));

        Ja3Fingerprint {
            string: ja3s_string,
            hash,
        }
    }

    /// Check if value is GREASE (to be filtered from JA3)
    fn is_grease(val: u16) -> bool {
        // GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, etc.
        (val & 0x0f0f) == 0x0a0a
    }
}

impl ProtocolAnalyzer for TlsAnalyzer {
    fn name(&self) -> &'static str {
        "tls"
    }

    fn detect(&self, payload: &[u8], port: u16) -> bool {
        if !self.config.enabled {
            return false;
        }

        // Check for TLS record header
        if payload.len() >= 5 {
            let record_type = payload[0];
            let version = u16::from_be_bytes([payload[1], payload[2]]);

            // Valid TLS record type and version
            if record_type == 22 { // Handshake
                if version >= 0x0300 && version <= 0x0304 {
                    return true;
                }
                // Some clients send 0x0301 in record layer even for TLS 1.3
                if version == 0x0301 {
                    return true;
                }
            }
        }

        // Check port
        self.config.ports.contains(&port)
    }

    fn parse(&self, packet: &Packet, flow: &mut Flow) -> Option<ProtocolEvent> {
        if !self.config.enabled || packet.payload().is_empty() {
            return None;
        }

        // Parse TLS record
        let (record_type, _version, record_data) = self.parse_record(&packet.payload())?;

        if record_type != TlsRecordType::Handshake {
            return None;
        }

        if record_data.is_empty() {
            return None;
        }

        let handshake_type = TlsHandshakeType::from(record_data[0]);

        match (handshake_type, packet.direction) {
            (TlsHandshakeType::ClientHello, Direction::ToServer | Direction::Unknown) => {
                let handshake = self.parse_client_hello(record_data)?;

                // Store in flow
                if let Some(ref sni) = handshake.sni {
                    flow.set_app_data("tls.sni", serde_json::json!(sni));
                }
                if let Some(ref ja3) = handshake.ja3 {
                    flow.set_app_data("tls.ja3_hash", serde_json::json!(&ja3.hash));
                    flow.set_app_data("tls.ja3_string", serde_json::json!(&ja3.string));
                }

                Some(ProtocolEvent::Tls(TlsEvent::ClientHello {
                    sni: handshake.sni.clone(),
                    ja3: handshake.ja3.clone().unwrap_or_default(),
                    versions: handshake.supported_versions.clone(),
                    cipher_suites: handshake.cipher_suites.clone(),
                }))
            }
            (TlsHandshakeType::ServerHello, Direction::ToClient | Direction::Unknown) => {
                let (version, cipher_suite, ja3s) = self.parse_server_hello(record_data)?;

                flow.set_app_data("tls.version", serde_json::json!(version.to_string()));
                flow.set_app_data("tls.ja3s_hash", serde_json::json!(&ja3s.hash));

                Some(ProtocolEvent::Tls(TlsEvent::ServerHello {
                    ja3s,
                    version: version.0,
                    cipher_suite,
                }))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_detection() {
        let config = TlsConfig::default();
        let analyzer = TlsAnalyzer::new(config);

        // TLS 1.2 ClientHello record header
        let tls_header = [22, 0x03, 0x01, 0x00, 0x05];
        assert!(analyzer.detect(&tls_header, 443));
    }

    #[test]
    fn test_grease_detection() {
        assert!(TlsAnalyzer::is_grease(0x0a0a));
        assert!(TlsAnalyzer::is_grease(0x1a1a));
        assert!(TlsAnalyzer::is_grease(0x2a2a));
        assert!(!TlsAnalyzer::is_grease(0x0035)); // AES-256
    }

    #[test]
    fn test_ja3_computation() {
        let config = TlsConfig::default();
        let analyzer = TlsAnalyzer::new(config);

        let handshake = TlsHandshake {
            version: TlsVersion::TLS12,
            cipher_suites: vec![0xc02c, 0xc02b, 0x009f],
            extensions: vec![0, 11, 10, 35],
            supported_groups: vec![29, 23],
            ec_point_formats: vec![0],
            ..Default::default()
        };

        let ja3 = analyzer.compute_ja3(&handshake);
        assert!(!ja3.hash.is_empty());
        assert!(ja3.string.contains("771")); // TLS 1.2 = 0x0303 = 771
    }
}
