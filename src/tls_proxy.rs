use anyhow::{anyhow, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, error, info, warn};

use crate::config::TlsProxyConfig;
use crate::dpi::DpiEngine;
use crate::monitor::MonitorEvent;

/// CA certificate and key for signing
/// Stores PEM strings so we can recreate KeyPair as needed (KeyPair isn't Clone)
/// Also stores CA params for creating Issuer
pub struct CertificateAuthority {
    cert_pem: String,
    cert_der: Vec<u8>,
    key_pem: String,
    ca_params: CertificateParams,
}

impl CertificateAuthority {
    /// Create or load a CA
    pub fn new(config: &TlsProxyConfig) -> Result<Self> {
        // Check if CA cert/key paths are specified and exist
        if let (Some(cert_path), Some(key_path)) = (&config.ca_cert_path, &config.ca_key_path) {
            if Path::new(cert_path).exists() && Path::new(key_path).exists() {
                return Self::load(cert_path, key_path);
            }
        }

        // Generate new CA
        let ca = Self::generate(config)?;

        // Save if paths specified
        if let (Some(cert_path), Some(key_path)) = (&config.ca_cert_path, &config.ca_key_path) {
            ca.save(cert_path, key_path)?;
        }

        Ok(ca)
    }

    /// Generate a new CA certificate
    fn generate(config: &TlsProxyConfig) -> Result<Self> {
        info!("Generating new CA certificate");

        let mut params = CertificateParams::default();

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, &config.ca_common_name);
        dn.push(DnType::OrganizationName, &config.ca_organization);
        params.distinguished_name = dn;

        // CA settings
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        // Validity
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = params.not_before + Duration::days(config.ca_validity_days as i64);

        // Generate key pair
        let key_pair = KeyPair::generate()?;
        let key_pem = key_pair.serialize_pem();

        // Generate certificate
        let cert = params.self_signed(&key_pair)?;
        let cert_pem = cert.pem();
        let cert_der = cert.der().to_vec();

        info!("CA certificate generated: {}", config.ca_common_name);

        Ok(Self {
            cert_pem,
            cert_der,
            key_pem,
            ca_params: params,
        })
    }

    /// Load CA from files
    fn load(cert_path: &str, key_path: &str) -> Result<Self> {
        info!("Loading CA certificate from {}", cert_path);

        let cert_pem = fs::read_to_string(cert_path)
            .with_context(|| format!("Failed to read CA cert: {}", cert_path))?;
        let key_pem = fs::read_to_string(key_path)
            .with_context(|| format!("Failed to read CA key: {}", key_path))?;

        // Parse the certificate DER from PEM
        let pem_data = pem::parse(&cert_pem)
            .map_err(|e| anyhow!("Failed to parse CA cert PEM: {}", e))?;
        let cert_der = pem_data.contents().to_vec();

        // Parse the certificate to extract the CA params
        let (_, x509_cert) = x509_parser::parse_x509_certificate(&cert_der)
            .map_err(|e| anyhow!("Failed to parse CA certificate: {:?}", e))?;

        // Reconstruct CertificateParams from the loaded certificate
        let mut ca_params = CertificateParams::default();

        // Extract distinguished name
        let mut dn = DistinguishedName::new();
        for rdn in x509_cert.subject().iter_rdn() {
            for attr in rdn.iter() {
                if let Ok(s) = attr.as_str() {
                    let oid = attr.attr_type();
                    if oid == &x509_parser::oid_registry::OID_X509_COMMON_NAME {
                        dn.push(DnType::CommonName, s);
                    } else if oid == &x509_parser::oid_registry::OID_X509_ORGANIZATION_NAME {
                        dn.push(DnType::OrganizationName, s);
                    }
                }
            }
        }
        ca_params.distinguished_name = dn;

        // Set CA settings
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        Ok(Self {
            cert_pem,
            cert_der,
            key_pem,
            ca_params,
        })
    }

    /// Save CA to files
    fn save(&self, cert_path: &str, key_path: &str) -> Result<()> {
        // Create directories if needed
        if let Some(parent) = Path::new(cert_path).parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = Path::new(key_path).parent() {
            fs::create_dir_all(parent)?;
        }

        // Write cert
        fs::write(cert_path, &self.cert_pem)?;
        info!("CA certificate saved to {}", cert_path);

        // Write key (with restricted permissions)
        fs::write(key_path, &self.key_pem)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
        }
        info!("CA key saved to {}", key_path);

        Ok(())
    }

    /// Get CA certificate in DER format for client trust
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// Get CA certificate in PEM format
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// Generate a certificate for a specific domain
    pub fn generate_cert_for_domain(
        &self,
        domain: &str,
        validity_days: u32,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        debug!("Generating certificate for domain: {}", domain);

        let mut params = CertificateParams::default();

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        params.distinguished_name = dn;

        // Subject alternative names
        params.subject_alt_names = vec![SanType::DnsName(domain.try_into()?)];

        // End-entity certificate settings
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        // Validity
        params.not_before = OffsetDateTime::now_utc();
        params.not_after = params.not_before + Duration::days(validity_days as i64);

        // Generate key pair for this cert
        let key_pair = KeyPair::generate()?;

        // Load CA key pair for signing
        let ca_key_pair = KeyPair::from_pem(&self.key_pem)?;

        // Create issuer from stored CA params
        let issuer = Issuer::from_params(&self.ca_params, ca_key_pair);

        // Sign the certificate
        let cert = params.signed_by(&key_pair, &issuer)?;

        Ok((cert.der().to_vec(), key_pair.serialize_der()))
    }
}

/// Certificate cache for generated certificates
pub struct CertCache {
    cache_dir: PathBuf,
    memory_cache: RwLock<HashMap<String, (Vec<u8>, Vec<u8>)>>,
    ca: Arc<CertificateAuthority>,
    validity_days: u32,
}

impl CertCache {
    pub fn new(cache_dir: &str, ca: Arc<CertificateAuthority>, validity_days: u32) -> Result<Self> {
        let path = PathBuf::from(cache_dir);
        fs::create_dir_all(&path)?;

        Ok(Self {
            cache_dir: path,
            memory_cache: RwLock::new(HashMap::new()),
            ca,
            validity_days,
        })
    }

    /// Get or create certificate for domain
    pub async fn get_cert(&self, domain: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        // Check memory cache first
        {
            let cache = self.memory_cache.read().await;
            if let Some(entry) = cache.get(domain) {
                return Ok(entry.clone());
            }
        }

        // Check disk cache
        let cert_path = self.cache_dir.join(format!("{}.crt", domain));
        let key_path = self.cache_dir.join(format!("{}.key", domain));

        if cert_path.exists() && key_path.exists() {
            let cert_der = fs::read(&cert_path)?;
            let key_der = fs::read(&key_path)?;

            // Add to memory cache
            let mut cache = self.memory_cache.write().await;
            cache.insert(domain.to_string(), (cert_der.clone(), key_der.clone()));

            return Ok((cert_der, key_der));
        }

        // Generate new certificate
        let (cert_der, key_der) = self.ca.generate_cert_for_domain(domain, self.validity_days)?;

        // Save to disk
        fs::write(&cert_path, &cert_der)?;
        fs::write(&key_path, &key_der)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
        }

        // Add to memory cache
        {
            let mut cache = self.memory_cache.write().await;
            cache.insert(domain.to_string(), (cert_der.clone(), key_der.clone()));
        }

        Ok((cert_der, key_der))
    }
}

/// Extract SNI from ClientHello
fn extract_sni(client_hello: &[u8]) -> Option<String> {
    // TLS record header: type(1) + version(2) + length(2)
    if client_hello.len() < 5 {
        return None;
    }

    // Check for handshake record (0x16)
    if client_hello[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([client_hello[3], client_hello[4]]) as usize;
    if client_hello.len() < 5 + record_len {
        return None;
    }

    let handshake = &client_hello[5..5 + record_len];

    // Handshake header: type(1) + length(3)
    if handshake.is_empty() || handshake[0] != 0x01 {
        // Not ClientHello
        return None;
    }

    // Skip: type(1) + length(3) + version(2) + random(32) + session_id_len(1) + session_id
    let mut pos = 1 + 3 + 2 + 32;
    if pos >= handshake.len() {
        return None;
    }

    let session_id_len = handshake[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites length (2 bytes)
    if pos + 2 > handshake.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;

    // Compression methods length (1 byte)
    if pos >= handshake.len() {
        return None;
    }
    let compression_len = handshake[pos] as usize;
    pos += 1 + compression_len;

    // Extensions length (2 bytes)
    if pos + 2 > handshake.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > handshake.len() {
        return None;
    }

    // Parse extensions to find SNI (type 0x0000)
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 && pos + ext_len <= extensions_end {
            // SNI extension
            // Format: list_len(2) + name_type(1) + name_len(2) + name
            if ext_len >= 5 {
                let name_type = handshake[pos + 2];
                if name_type == 0x00 {
                    // hostname
                    let name_len =
                        u16::from_be_bytes([handshake[pos + 3], handshake[pos + 4]]) as usize;
                    if pos + 5 + name_len <= extensions_end {
                        let name = &handshake[pos + 5..pos + 5 + name_len];
                        return String::from_utf8(name.to_vec()).ok();
                    }
                }
            }
        }

        pos += ext_len;
    }

    None
}

/// TLS interception proxy
pub struct TlsProxy {
    config: TlsProxyConfig,
    ca: Arc<CertificateAuthority>,
    cert_cache: Arc<CertCache>,
    dpi_engine: Option<Arc<tokio::sync::Mutex<DpiEngine>>>,
    event_tx: mpsc::Sender<MonitorEvent>,
}

impl TlsProxy {
    /// Create a new TLS proxy
    pub fn new(
        config: TlsProxyConfig,
        dpi_engine: Option<Arc<tokio::sync::Mutex<DpiEngine>>>,
        event_tx: mpsc::Sender<MonitorEvent>,
    ) -> Result<Self> {
        let ca = Arc::new(CertificateAuthority::new(&config)?);
        let cert_cache = Arc::new(CertCache::new(
            &config.cert_cache_dir,
            ca.clone(),
            config.cert_validity_days,
        )?);

        info!(
            "TLS proxy initialized, CA: {}",
            config.ca_common_name
        );

        Ok(Self {
            config,
            ca,
            cert_cache,
            dpi_engine,
            event_tx,
        })
    }

    /// Get CA certificate PEM for client installation
    pub fn ca_cert_pem(&self) -> &str {
        self.ca.cert_pem()
    }

    /// Run the proxy
    pub async fn run(&self) -> Result<()> {
        let addr = format!("{}:{}", self.config.listen_addr, self.config.listen_port);
        let listener = TcpListener::bind(&addr).await?;

        info!("TLS proxy listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let config = self.config.clone();
                    let cert_cache = self.cert_cache.clone();
                    let dpi_engine = self.dpi_engine.clone();
                    let event_tx = self.event_tx.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            stream,
                            peer_addr.ip(),
                            config,
                            cert_cache,
                            dpi_engine,
                            event_tx,
                        )
                        .await
                        {
                            debug!("Connection error from {}: {}", peer_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    }
}

/// Handle a single proxied connection
async fn handle_connection(
    client_stream: TcpStream,
    client_ip: IpAddr,
    config: TlsProxyConfig,
    cert_cache: Arc<CertCache>,
    dpi_engine: Option<Arc<tokio::sync::Mutex<DpiEngine>>>,
    event_tx: mpsc::Sender<MonitorEvent>,
) -> Result<()> {
    // Read initial bytes to peek at ClientHello
    let mut peek_buf = vec![0u8; 1024];
    let n = client_stream.peek(&mut peek_buf).await?;
    if n == 0 {
        return Ok(());
    }

    // Extract SNI from ClientHello
    let sni = extract_sni(&peek_buf[..n]);
    let domain = match sni {
        Some(d) => d,
        None => {
            warn!("No SNI found in ClientHello from {}", client_ip);
            return Ok(());
        }
    };

    debug!("TLS connection from {} to {}", client_ip, domain);

    // Check bypass list
    if config.bypass_domains.iter().any(|d| domain.ends_with(d)) {
        debug!("Bypassing domain: {}", domain);
        // TODO: Implement passthrough
        return Ok(());
    }

    // Get or generate certificate for this domain
    let (cert_der, key_der) = cert_cache.get_cert(&domain).await?;

    // Create server config for client connection
    let cert = CertificateDer::from(cert_der);
    let key = PrivateKeyDer::try_from(key_der)
        .map_err(|e| anyhow!("Failed to parse private key: {}", e))?;

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Accept TLS from client
    let mut client_tls = acceptor.accept(client_stream).await?;

    // Connect to upstream server
    let upstream_addr = format!("{}:443", domain);
    let upstream_stream = TcpStream::connect(&upstream_addr).await?;

    // Create client config for upstream connection
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(domain.clone())?;
    let mut upstream_tls = connector.connect(server_name, upstream_stream).await?;

    // Proxy data between client and upstream, inspecting along the way
    let mut client_buf = vec![0u8; 8192];
    let mut upstream_buf = vec![0u8; 8192];

    loop {
        tokio::select! {
            // Data from client -> inspect -> send to upstream
            result = client_tls.read(&mut client_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = &client_buf[..n];

                        // Inspect decrypted data
                        if config.inspect_decrypted {
                            if let Some(ref engine) = dpi_engine {
                                let threats = {
                                    let eng = engine.lock().await;
                                    eng.inspect_payload(data)
                                };
                                if !threats.is_empty() {
                                    let threat_names: Vec<_> = threats.iter()
                                        .map(|t| t.rule_name.as_str())
                                        .collect();
                                    warn!(
                                        "DPI threat in decrypted traffic from {} to {}: {:?}",
                                        client_ip, domain, threat_names
                                    );

                                    // Send ban event
                                    let _ = event_tx.send(MonitorEvent::Ban {
                                        ip: client_ip,
                                        service: "tls_proxy".to_string(),
                                        reason: format!("DPI (decrypted): {}", threat_names.join(", ")),
                                        duration_secs: 7200,
                                    }).await;

                                    // Drop connection
                                    break;
                                }
                            }
                        }

                        // Forward to upstream
                        upstream_tls.write_all(data).await?;
                    }
                    Err(e) => {
                        debug!("Client read error: {}", e);
                        break;
                    }
                }
            }

            // Data from upstream -> inspect -> send to client
            result = upstream_tls.read(&mut upstream_buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = &upstream_buf[..n];

                        // Inspect decrypted response
                        if config.inspect_decrypted {
                            if let Some(ref engine) = dpi_engine {
                                let threats = {
                                    let eng = engine.lock().await;
                                    eng.inspect_payload(data)
                                };
                                if !threats.is_empty() {
                                    warn!(
                                        "DPI threat in decrypted response from {} to {}: {:?}",
                                        domain, client_ip,
                                        threats.iter().map(|t| &t.rule_name).collect::<Vec<_>>()
                                    );
                                    // Don't ban client for malicious server response
                                    // but could log/alert
                                }
                            }
                        }

                        // Forward to client
                        client_tls.write_all(data).await?;
                    }
                    Err(e) => {
                        debug!("Upstream read error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Start the TLS proxy
pub async fn start_tls_proxy(
    config: TlsProxyConfig,
    dpi_engine: Option<Arc<tokio::sync::Mutex<DpiEngine>>>,
    event_tx: mpsc::Sender<MonitorEvent>,
) -> Result<()> {
    if !config.enabled {
        info!("TLS proxy is disabled");
        return Ok(());
    }

    let proxy = TlsProxy::new(config, dpi_engine, event_tx)?;
    proxy.run().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sni_extraction() {
        // Example ClientHello with SNI "example.com"
        // Total handshake content: 4 (handshake header) + 2 (version) + 32 (random) + 1 (session_id_len)
        //   + 2 (cipher_suites_len) + 2 (cipher_suites) + 1 (compression_len) + 1 (compression)
        //   + 2 (extensions_len) + 16 (extension) = 63 bytes (0x3f)
        // Handshake length (3 bytes): 59 bytes after handshake type (0x00003b)
        let client_hello: Vec<u8> = vec![
            0x16, 0x03, 0x01, 0x00, 0x3f, // TLS record header (type=handshake, version=1.0, len=63)
            0x01, 0x00, 0x00, 0x3b, // Handshake header (ClientHello, len=59)
            0x03, 0x03, // Version TLS 1.2
            // 32 bytes random
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // Session ID length: 0
            0x00, 0x02, // Cipher suites length: 2
            0x00, 0xff, // Cipher suite: TLS_EMPTY_RENEGOTIATION_INFO_SCSV
            0x01, // Compression methods length: 1
            0x00, // Compression method: null
            0x00, 0x10, // Extensions length: 16
            // SNI extension (16 bytes total)
            0x00, 0x00, // Extension type: SNI
            0x00, 0x0c, // Extension length: 12
            0x00, 0x0a, // SNI list length: 10
            0x00, // Name type: hostname
            0x00, 0x07, // Name length: 7
            b't', b'e', b's', b't', b'.', b'i', b'o',
        ];

        let sni = extract_sni(&client_hello);
        assert_eq!(sni, Some("test.io".to_string()));
    }

    #[test]
    fn test_sni_extraction_no_sni() {
        // Minimal ClientHello without SNI
        let client_hello: Vec<u8> = vec![
            0x16, 0x03, 0x01, 0x00, 0x2f,
            0x01, 0x00, 0x00, 0x2b,
            0x03, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00,
            0x00, 0x02, 0x00, 0xff,
            0x01, 0x00,
            0x00, 0x00, // No extensions
        ];

        let sni = extract_sni(&client_hello);
        assert_eq!(sni, None);
    }
}
