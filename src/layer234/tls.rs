//! TLS handshake detection and SNI parsing

use std::str;

/// TLS record content types
pub const TLS_HANDSHAKE: u8 = 0x16;
pub const TLS_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const TLS_ALERT: u8 = 0x15;
pub const TLS_APPLICATION_DATA: u8 = 0x17;

/// TLS handshake types
pub const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
pub const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
pub const HANDSHAKE_CERTIFICATE: u8 = 0x0B;
pub const HANDSHAKE_SERVER_KEY_EXCHANGE: u8 = 0x0C;
pub const HANDSHAKE_CLIENT_KEY_EXCHANGE: u8 = 0x10;
pub const HANDSHAKE_FINISHED: u8 = 0x14;

/// TLS extension types
pub const EXT_SERVER_NAME: u16 = 0x0000;
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002B;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000D;
pub const EXT_SUPPORTED_GROUPS: u16 = 0x000A;

#[derive(Clone, Debug, Default)]
pub struct TlsInfo {
    /// Is this a TLS record?
    pub is_tls: bool,
    /// TLS record type (handshake, alert, etc.)
    pub record_type: u8,
    /// TLS version from record layer (0x0301 = TLS 1.0, 0x0303 = TLS 1.2)
    pub record_version: u16,
    /// Handshake type if this is a handshake record
    pub handshake_type: Option<u8>,
    /// Client Hello specific info
    pub client_hello: Option<ClientHelloInfo>,
    /// Is this likely a TLS probe/scan?
    pub is_probe: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ClientHelloInfo {
    /// TLS version from ClientHello
    pub client_version: u16,
    /// Server Name Indication (SNI)
    pub sni: Option<String>,
    /// Number of cipher suites offered
    pub cipher_suite_count: u16,
    /// Number of extensions
    pub extension_count: u16,
    /// Supported TLS versions (from extension)
    pub supported_versions: Vec<u16>,
    /// Has GREASE values (indicates real browser vs scanner)
    pub has_grease: bool,
    /// JA3 fingerprint components (simplified)
    pub ja3_version: u16,
    pub ja3_cipher_count: u16,
    pub ja3_extension_count: u16,
}

/// Parse TLS record from TCP payload
pub fn parse_tls(payload: &[u8]) -> Option<TlsInfo> {
    if payload.len() < 5 {
        return None;
    }

    let content_type = payload[0];

    // Check if this looks like a TLS record
    if !matches!(content_type, TLS_HANDSHAKE | TLS_CHANGE_CIPHER_SPEC | TLS_ALERT | TLS_APPLICATION_DATA) {
        return None;
    }

    let version = u16::from_be_bytes([payload[1], payload[2]]);

    // Valid TLS versions: 0x0300 (SSL 3.0) through 0x0304 (TLS 1.3)
    if !(0x0300..=0x0304).contains(&version) && version != 0x0301 {
        return None;
    }

    let record_length = u16::from_be_bytes([payload[3], payload[4]]) as usize;

    // Sanity check on length
    if record_length > 16384 + 2048 || payload.len() < 5 + record_length.min(payload.len() - 5) {
        return None;
    }

    let mut info = TlsInfo {
        is_tls: true,
        record_type: content_type,
        record_version: version,
        handshake_type: None,
        client_hello: None,
        is_probe: false,
    };

    // Parse handshake if present
    if content_type == TLS_HANDSHAKE && payload.len() > 5 {
        let handshake_data = &payload[5..];
        if !handshake_data.is_empty() {
            info.handshake_type = Some(handshake_data[0]);

            if handshake_data[0] == HANDSHAKE_CLIENT_HELLO {
                info.client_hello = parse_client_hello(handshake_data);

                // Detect potential TLS probe/scan
                if let Some(ref ch) = info.client_hello {
                    info.is_probe = detect_tls_probe(ch);
                }
            }
        }
    }

    Some(info)
}

/// Parse ClientHello message
fn parse_client_hello(data: &[u8]) -> Option<ClientHelloInfo> {
    if data.len() < 38 {
        return None;
    }

    // Skip handshake type (1) + length (3)
    let mut pos = 4;

    // Client version (2 bytes)
    if pos + 2 > data.len() {
        return None;
    }
    let client_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    // Random (32 bytes)
    pos += 32;

    // Session ID
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let cipher_suite_count = (cipher_suites_len / 2) as u16;

    // Check for GREASE in cipher suites
    let mut has_grease = false;
    let cipher_data = &data[pos..pos.min(data.len())];
    for i in (0..cipher_suites_len.min(cipher_data.len())).step_by(2) {
        if i + 1 < cipher_data.len() {
            let suite = u16::from_be_bytes([cipher_data[i], cipher_data[i + 1]]);
            if is_grease_value(suite) {
                has_grease = true;
                break;
            }
        }
    }

    pos += cipher_suites_len;

    // Compression methods
    if pos >= data.len() {
        return None;
    }
    let compression_len = data[pos] as usize;
    pos += 1 + compression_len;

    // Extensions
    if pos + 2 > data.len() {
        return Some(ClientHelloInfo {
            client_version,
            sni: None,
            cipher_suite_count,
            extension_count: 0,
            supported_versions: Vec::new(),
            has_grease,
            ja3_version: client_version,
            ja3_cipher_count: cipher_suite_count,
            ja3_extension_count: 0,
        });
    }

    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let mut info = ClientHelloInfo {
        client_version,
        sni: None,
        cipher_suite_count,
        extension_count: 0,
        supported_versions: Vec::new(),
        has_grease,
        ja3_version: client_version,
        ja3_cipher_count: cipher_suite_count,
        ja3_extension_count: 0,
    };

    // Parse extensions
    let ext_end = pos + extensions_len.min(data.len() - pos);
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        info.extension_count += 1;

        if pos + ext_len > data.len() {
            break;
        }

        match ext_type {
            EXT_SERVER_NAME => {
                info.sni = parse_sni(&data[pos..pos + ext_len]);
            }
            EXT_SUPPORTED_VERSIONS => {
                info.supported_versions = parse_supported_versions(&data[pos..pos + ext_len]);
            }
            _ => {}
        }

        pos += ext_len;
    }

    info.ja3_extension_count = info.extension_count;

    Some(info)
}

/// Parse SNI extension
fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // SNI list length (2 bytes)
    let _list_len = u16::from_be_bytes([data[0], data[1]]);

    // Name type (1 byte) - should be 0x00 for hostname
    if data[2] != 0x00 {
        return None;
    }

    // Name length (2 bytes)
    let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;

    if data.len() < 5 + name_len {
        return None;
    }

    // Extract hostname
    str::from_utf8(&data[5..5 + name_len])
        .ok()
        .map(|s| s.to_lowercase())
}

/// Parse supported_versions extension
fn parse_supported_versions(data: &[u8]) -> Vec<u16> {
    let mut versions = Vec::new();

    if data.is_empty() {
        return versions;
    }

    let len = data[0] as usize;
    let mut pos = 1;

    while pos + 2 <= data.len() && pos < 1 + len {
        let version = u16::from_be_bytes([data[pos], data[pos + 1]]);
        if !is_grease_value(version) {
            versions.push(version);
        }
        pos += 2;
    }

    versions
}

/// Check if value is a GREASE value (used by real browsers)
fn is_grease_value(value: u16) -> bool {
    // GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
    let high = (value >> 8) as u8;
    let low = (value & 0xff) as u8;
    high == low && (high & 0x0f) == 0x0a
}

/// Detect if ClientHello looks like a scanner/probe
fn detect_tls_probe(ch: &ClientHelloInfo) -> bool {
    // Scanners often have telltale signs:

    // Very few cipher suites (real browsers have many)
    if ch.cipher_suite_count < 5 {
        return true;
    }

    // No GREASE (real browsers use GREASE)
    if !ch.has_grease && ch.cipher_suite_count > 10 {
        // Might be a scanner trying to look normal
    }

    // Very few extensions
    if ch.extension_count < 3 {
        return true;
    }

    // Old TLS version without supported_versions extension
    if ch.client_version < 0x0303 && ch.supported_versions.is_empty() {
        return true;
    }

    false
}

/// TLS version to string
pub fn version_string(version: u16) -> &'static str {
    match version {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_non_tls() {
        let data = b"GET / HTTP/1.1\r\n";
        assert!(parse_tls(data).is_none());
    }

    #[test]
    fn test_tls_detection() {
        // Minimal TLS ClientHello header
        let data = [
            0x16, // Handshake
            0x03, 0x01, // TLS 1.0
            0x00, 0x05, // Length
            0x01, // ClientHello
            0x00, 0x00, 0x01, // Length
            0x00, // Data
        ];

        let info = parse_tls(&data);
        assert!(info.is_some());
        let info = info.unwrap();
        assert!(info.is_tls);
        assert_eq!(info.record_type, TLS_HANDSHAKE);
        assert_eq!(info.handshake_type, Some(HANDSHAKE_CLIENT_HELLO));
    }

    #[test]
    fn test_grease_detection() {
        assert!(is_grease_value(0x0a0a));
        assert!(is_grease_value(0x1a1a));
        assert!(is_grease_value(0xfafa));
        assert!(!is_grease_value(0x0001));
        assert!(!is_grease_value(0x1234));
    }
}
