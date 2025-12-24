//! TLS protocol state

use std::any::Any;
use crate::protocols::ProtocolStateData;
use super::types::*;

/// Per-flow TLS state
#[derive(Debug, Default)]
pub struct TlsState {
    pub version: Option<TlsVersion>,
    pub sni: Option<String>,
    pub ja3_hash: Option<String>,
    pub ja3s_hash: Option<String>,
    pub cipher_suite: Option<u16>,
    pub client_hello_seen: bool,
    pub server_hello_seen: bool,
    pub handshake_complete: bool,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub suspicious_ja3: bool,
    pub bytes_encrypted: u64,
}

impl TlsState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_client_hello(&mut self, handshake: &TlsHandshake) {
        self.client_hello_seen = true;
        self.sni = handshake.sni.clone();
        if let Some(ref ja3) = handshake.ja3 {
            self.ja3_hash = Some(ja3.hash.clone());
            // Check against known suspicious JA3
            for suspicious in SUSPICIOUS_JA3 {
                if ja3.hash == *suspicious {
                    self.suspicious_ja3 = true;
                    break;
                }
            }
        }
    }

    pub fn record_server_hello(&mut self, version: TlsVersion, cipher: u16, ja3s_hash: &str) {
        self.server_hello_seen = true;
        self.version = Some(version);
        self.cipher_suite = Some(cipher);
        self.ja3s_hash = Some(ja3s_hash.to_string());
    }
}

impl ProtocolStateData for TlsState {
    fn as_any(&self) -> &dyn Any { self }
    fn as_any_mut(&mut self) -> &mut dyn Any { self }
}
