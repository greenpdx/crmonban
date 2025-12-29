//! NFQUEUE Reader - Capture packets via nftables NFQUEUE
//!
//! Captures network traffic queued by nftables and processes through layer234.
//! Requires root privileges and nftables rules to queue packets.
//!
//! Setup:
//!   sudo ./scripts/setup-nftables.sh start
//!
//! Run with:
//!   sudo cargo run --example nfqueue_reader --release -- -q 0
//!
//! Cleanup:
//!   sudo ./scripts/setup-nftables.sh stop
//!
//! Note: This example is Linux-specific.

#[cfg(target_os = "linux")]
mod linux {
    use crmonban::layer234::{Config, DetectorBuilder, DetectionEvent, DetectionType, DetectionSubType, PacketAnalysis, parse_ip_packet, NetVecError};
    use nfq::{Queue, Verdict};
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::fs::{File, OpenOptions};
    use std::io::{BufWriter, Write};
    use std::net::IpAddr;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    use tokio::sync::Mutex;
    use uuid::Uuid;
    use serde::Serialize;
    use serde_json;
    use chrono;
    use hex;

    pub struct CaptureStats {
        pub packets: usize,
        pub bytes: usize,
        pub errors: usize,
        start_time: Instant,
        last_packets: usize,
        last_bytes: usize,
        last_print: Instant,
    }

    impl CaptureStats {
        pub fn new() -> Self {
            Self {
                packets: 0,
                bytes: 0,
                errors: 0,
                start_time: Instant::now(),
                last_packets: 0,
                last_bytes: 0,
                last_print: Instant::now(),
            }
        }

        pub fn maybe_print_interval(&mut self) {
            if self.last_print.elapsed() >= Duration::from_secs(5) {
                let pps = (self.packets - self.last_packets) / 5;
                let bps = (self.bytes - self.last_bytes) / 5;

                eprintln!(
                    "[STATS] Packets: {} (+{}/s) | Bytes: {:.2}MB (+{:.2}MB/s) | Errors: {}",
                    self.packets,
                    pps,
                    self.bytes as f64 / 1_000_000.0,
                    bps as f64 / 1_000_000.0,
                    self.errors
                );

                self.last_packets = self.packets;
                self.last_bytes = self.bytes;
                self.last_print = Instant::now();
            }
        }

        pub fn print_final(&self) {
            let elapsed = self.start_time.elapsed();
            println!("\n{}", "=".repeat(60));
            println!("CAPTURE SUMMARY");
            println!("{}", "=".repeat(60));
            println!("Duration:      {:.2?}", elapsed);
            println!("Packets:       {}", self.packets);
            println!("Bytes:         {:.2} MB", self.bytes as f64 / 1_000_000.0);
            println!("Errors:        {}", self.errors);
            if elapsed.as_secs() > 0 {
                println!(
                    "Avg rate:      {:.0} pps",
                    self.packets as f64 / elapsed.as_secs_f64()
                );
                println!(
                    "Avg bandwidth: {:.2} Mbps",
                    (self.bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0
                );
            }
        }
    }

    fn print_detection(event: &DetectionEvent) {
        let threat_desc = format_detection_type(&event.event_type, &event.subtype);

        println!(
            "\x1b[1m[ALERT]\x1b[0m {} | {} | conf={:.0}%",
            event.src_ip,
            threat_desc,
            event.confidence * 100.0,
        );
        if !event.message.is_empty() {
            println!("         {}", event.message);
        }
    }

    fn format_detection_type(event_type: &DetectionType, subtype: &DetectionSubType) -> String {
        match (event_type, subtype) {
            (DetectionType::PortScan, DetectionSubType::Scan(scan)) => {
                format!("\x1b[31mPORT_SCAN\x1b[0m ({})", scan)
            }
            (DetectionType::NetworkScan, DetectionSubType::Scan(scan)) => {
                format!("\x1b[31mNETWORK_SCAN\x1b[0m ({})", scan)
            }
            (DetectionType::BruteForce, _) => "\x1b[31mBRUTE_FORCE\x1b[0m".to_string(),
            (DetectionType::AnomalyDetection, _) => "\x1b[33mANOMALY\x1b[0m".to_string(),
            (DetectionType::DoS, DetectionSubType::Dos(dos)) => {
                format!("\x1b[31mDOS\x1b[0m ({})", dos)
            }
            _ => format!("\x1b[31m{}\x1b[0m", event_type),
        }
    }

    fn get_event_type_name(event_type: &DetectionType) -> &'static str {
        match event_type {
            DetectionType::PortScan => "port_scan",
            DetectionType::NetworkScan => "network_scan",
            DetectionType::BruteForce => "brute_force",
            DetectionType::AnomalyDetection => "anomaly",
            DetectionType::DoS => "dos",
            _ => "unknown",
        }
    }

    /// Check if an event should be filtered based on allowlist
    fn is_allowed(event: &DetectionEvent, allowlist: &HashSet<(IpAddr, Option<u16>)>) -> bool {
        // Check if source IP is fully allowlisted (any port)
        if allowlist.contains(&(event.src_ip, None)) {
            return true;
        }

        // Check port-specific allowlist entries
        // For BRUTE_FORCE, check if it's targeting an allowed port based on dst_port
        if event.event_type == DetectionType::BruteForce {
            if let Some(port) = event.dst_port {
                if allowlist.contains(&(event.src_ip, Some(port))) {
                    return true;
                }
            }
        }

        false
    }

    // =============================================================================
    // HTTP Extraction
    // =============================================================================

    #[derive(Clone, Debug, Serialize)]
    pub struct HttpInfo {
        pub method: String,
        pub path: String,
        pub host: Option<String>,
        pub full_url: String,
    }

    /// Extract HTTP request info from TCP payload
    fn extract_http_info(payload: &[u8]) -> Option<HttpInfo> {
        let text = std::str::from_utf8(payload).ok()?;

        // Match: GET /path?query HTTP/1.x or POST /path HTTP/1.x etc.
        let first_line = text.lines().next()?;
        let parts: Vec<&str> = first_line.split_whitespace().collect();

        if parts.len() < 2 {
            return None;
        }

        let method = parts[0];
        if !["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"].contains(&method) {
            return None;
        }

        let path = parts[1].to_string();

        // Extract Host header
        let host = text
            .lines()
            .find(|l| l.to_lowercase().starts_with("host:"))
            .map(|l| l[5..].trim().to_string());

        // Build full URL
        let full_url = match &host {
            Some(h) => format!("http://{}{}", h, path),
            None => path.clone(),
        };

        Some(HttpInfo {
            method: method.to_string(),
            path,
            host,
            full_url,
        })
    }

    // =============================================================================
    // Packet Buffer for Alert Linking
    // =============================================================================

    #[derive(Clone, Debug, Serialize)]
    pub struct BufferedPacket {
        pub timestamp_ns: u64,
        pub source_ip: IpAddr,
        pub dest_ip: IpAddr,
        pub source_port: Option<u16>,
        pub dest_port: Option<u16>,
        pub protocol: String,
        pub http_info: Option<HttpInfo>,
        pub tls_sni: Option<String>,
        pub payload_preview: Option<String>,
        pub payload_len: usize,
    }

    pub struct PacketRingBuffer {
        buffers: HashMap<IpAddr, VecDeque<BufferedPacket>>,
        max_per_ip: usize,
        max_age_ns: u64,
    }

    impl PacketRingBuffer {
        pub fn new(max_per_ip: usize, max_age_secs: u64) -> Self {
            Self {
                buffers: HashMap::new(),
                max_per_ip,
                max_age_ns: max_age_secs * 1_000_000_000,
            }
        }

        pub fn add(&mut self, packet: BufferedPacket) {
            let buffer = self.buffers.entry(packet.source_ip).or_insert_with(VecDeque::new);

            // Remove old packets
            let now = packet.timestamp_ns;
            while let Some(front) = buffer.front() {
                if now.saturating_sub(front.timestamp_ns) > self.max_age_ns {
                    buffer.pop_front();
                } else {
                    break;
                }
            }

            // Add new packet
            buffer.push_back(packet);

            // Limit size
            while buffer.len() > self.max_per_ip {
                buffer.pop_front();
            }
        }

        pub fn get_recent(&self, ip: &IpAddr) -> Vec<BufferedPacket> {
            self.buffers.get(ip).map(|b| b.iter().cloned().collect()).unwrap_or_default()
        }
    }

    // =============================================================================
    // Log Entry Types
    // =============================================================================

    #[derive(Serialize)]
    struct AlertLogEntry {
        alert_id: String,
        timestamp: String,
        timestamp_ns: u64,
        source_ip: IpAddr,
        target_ips: Vec<IpAddr>,
        detection_type: String,
        subtype: String,
        message: String,
        confidence: f32,
        rule_name: Option<String>,
    }

    #[derive(Serialize)]
    struct PacketLogEntry {
        alert_id: Option<String>,
        timestamp_ns: u64,
        source_ip: IpAddr,
        dest_ip: IpAddr,
        source_port: Option<u16>,
        dest_port: Option<u16>,
        protocol: String,
        http_method: Option<String>,
        http_url: Option<String>,
        http_host: Option<String>,
        tls_sni: Option<String>,
        payload_hex: Option<String>,
        payload_len: usize,
        detection_type: Option<String>,
        confidence: Option<f32>,
    }

    // =============================================================================
    // Logger
    // =============================================================================

    pub struct Logger {
        alert_writer: Option<BufWriter<File>>,
        packet_writer: Option<BufWriter<File>>,
        log_all_http: bool,
        include_payload_hex: bool,
        #[allow(dead_code)]
        max_payload_bytes: usize,
    }

    impl Logger {
        pub fn new(config: &Config) -> std::io::Result<Self> {
            let alert_writer = if config.logging.enabled && config.logging.json.enabled {
                let path = Path::new(&config.logging.json.path);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                Some(BufWriter::new(file))
            } else {
                None
            };

            let packet_writer = if config.packet_log.enabled {
                let path = Path::new(&config.packet_log.path);
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                Some(BufWriter::new(file))
            } else {
                None
            };

            Ok(Self {
                alert_writer,
                packet_writer,
                log_all_http: config.packet_log.log_all_http,
                include_payload_hex: config.packet_log.include_payload_hex,
                max_payload_bytes: config.packet_log.max_payload_bytes,
            })
        }

        pub fn log_alert(&mut self, event: &DetectionEvent, alert_id: Uuid) -> std::io::Result<()> {
            if let Some(ref mut writer) = self.alert_writer {
                let timestamp_ns = event.timestamp.timestamp_nanos_opt().unwrap_or(0) as u64;
                let entry = AlertLogEntry {
                    alert_id: alert_id.to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    timestamp_ns,
                    source_ip: event.src_ip,
                    target_ips: event.target_ips.clone(),
                    detection_type: format!("{}", event.event_type),
                    subtype: format!("{}", event.subtype),
                    message: event.message.clone(),
                    confidence: event.confidence,
                    rule_name: event.rule_name.clone(),
                };
                serde_json::to_writer(&mut *writer, &entry)?;
                writeln!(writer)?;
                writer.flush()?;
            }
            Ok(())
        }

        pub fn log_packet(&mut self, packet: &BufferedPacket, alert_id: Option<Uuid>, event: Option<&DetectionEvent>) -> std::io::Result<()> {
            if let Some(ref mut writer) = self.packet_writer {
                let payload_hex = if self.include_payload_hex {
                    packet.payload_preview.clone()
                } else {
                    None
                };

                let entry = PacketLogEntry {
                    alert_id: alert_id.map(|id| id.to_string()),
                    timestamp_ns: packet.timestamp_ns,
                    source_ip: packet.source_ip,
                    dest_ip: packet.dest_ip,
                    source_port: packet.source_port,
                    dest_port: packet.dest_port,
                    protocol: packet.protocol.clone(),
                    http_method: packet.http_info.as_ref().map(|h| h.method.clone()),
                    http_url: packet.http_info.as_ref().map(|h| h.full_url.clone()),
                    http_host: packet.http_info.as_ref().and_then(|h| h.host.clone()),
                    tls_sni: packet.tls_sni.clone(),
                    payload_hex,
                    payload_len: packet.payload_len,
                    detection_type: event.map(|e| format!("{}", e.event_type)),
                    confidence: event.map(|e| e.confidence),
                };
                serde_json::to_writer(&mut *writer, &entry)?;
                writeln!(writer)?;
                writer.flush()?;
            }
            Ok(())
        }

        pub fn log_http_only(&mut self, packet: &BufferedPacket) -> std::io::Result<()> {
            if self.log_all_http && packet.http_info.is_some() {
                self.log_packet(packet, None, None)?;
            }
            Ok(())
        }
    }

    // =============================================================================
    // Email Alert Manager
    // =============================================================================

    use lettre::{
        message::header::ContentType,
        transport::smtp::authentication::Credentials,
        AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    };
    use lettre::transport::smtp::client::{Tls, TlsParameters};

    #[derive(Clone)]
    struct SmtpSettings {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        from: String,
        tls: String,
    }

    impl SmtpSettings {
        fn from_config(config: &crmonban::layer234::config::SmtpConfig) -> Self {
            // Config already has env overrides applied via Config::apply_env_overrides()
            Self {
                host: config.host.clone(),
                port: config.port,
                username: config.username.clone(),
                password: config.password.clone(),
                from: config.from.clone(),
                tls: config.tls.clone(),
            }
        }
    }

    pub struct EmailAlertManager {
        enabled: bool,
        smtp_settings: SmtpSettings,
        config: crmonban::layer234::config::EmailAlertConfig,
        digest_buffer: Arc<Mutex<Vec<(Uuid, DetectionEvent)>>>,
        emails_sent_this_hour: Arc<Mutex<(u32, Instant)>>,
    }

    impl EmailAlertManager {
        pub fn new(alerts_config: &crmonban::layer234::config::AlertsConfig) -> Self {
            Self {
                enabled: alerts_config.enabled && alerts_config.email.enabled,
                smtp_settings: SmtpSettings::from_config(&alerts_config.smtp),
                config: alerts_config.email.clone(),
                digest_buffer: Arc::new(Mutex::new(Vec::new())),
                emails_sent_this_hour: Arc::new(Mutex::new((0, Instant::now()))),
            }
        }

        async fn build_transport(&self) -> Result<AsyncSmtpTransport<Tokio1Executor>, Box<dyn std::error::Error + Send + Sync>> {
            let mut builder = AsyncSmtpTransport::<Tokio1Executor>::relay(&self.smtp_settings.host)?
                .port(self.smtp_settings.port);

            // Add credentials if provided
            if let (Some(user), Some(pass)) = (&self.smtp_settings.username, &self.smtp_settings.password) {
                builder = builder.credentials(Credentials::new(user.clone(), pass.clone()));
            }

            // Configure TLS
            let tls_params = TlsParameters::new(self.smtp_settings.host.clone())?;
            builder = match self.smtp_settings.tls.as_str() {
                "tls" => builder.tls(Tls::Wrapper(tls_params)),
                "starttls" => builder.tls(Tls::Required(tls_params)),
                _ => builder.tls(Tls::None),
            };

            Ok(builder.build())
        }

        async fn can_send_email(&self) -> bool {
            let mut guard = self.emails_sent_this_hour.lock().await;
            let (count, last_reset) = &mut *guard;

            // Reset counter if an hour has passed
            if last_reset.elapsed() >= Duration::from_secs(3600) {
                *count = 0;
                *last_reset = Instant::now();
            }

            if *count >= self.config.max_emails_per_hour {
                return false;
            }

            *count += 1;
            true
        }

        fn should_send_immediate(&self, event: &DetectionEvent) -> bool {
            if !self.config.immediate_enabled {
                return false;
            }
            if event.confidence < self.config.immediate_min_confidence {
                return false;
            }
            let type_name = get_event_type_name(&event.event_type);
            self.config.immediate_threat_types.iter().any(|t| t == type_name)
        }

        pub async fn handle_event(&self, event: DetectionEvent, alert_id: Uuid) {
            if !self.enabled {
                return;
            }

            if self.should_send_immediate(&event) {
                if let Err(e) = self.send_immediate_alert(&event, alert_id).await {
                    eprintln!("Failed to send immediate alert email: {}", e);
                }
            }

            // Always buffer for digest if enabled
            if self.config.digest_enabled && event.confidence >= self.config.digest_min_confidence {
                let mut buffer = self.digest_buffer.lock().await;
                buffer.push((alert_id, event));
            }
        }

        async fn send_immediate_alert(&self, event: &DetectionEvent, alert_id: Uuid) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if !self.can_send_email().await {
                eprintln!("Rate limit reached, skipping immediate alert email");
                return Ok(());
            }

            let type_name = get_event_type_name(&event.event_type);
            let subject = format!("[ALERT] {} from {}", type_name, event.src_ip);
            let body = format!(
                "LAYER2DETECT ALERT\n\
                 ==================\n\n\
                 Alert ID: {}\n\
                 Time: {}\n\
                 Source IP: {}\n\
                 Detection Type: {} ({})\n\
                 Confidence: {:.1}%\n\
                 Rule: {}\n\n\
                 Message:\n{}\n",
                alert_id,
                chrono::Utc::now().to_rfc3339(),
                event.src_ip,
                event.event_type,
                event.subtype,
                event.confidence * 100.0,
                event.rule_name.as_deref().unwrap_or("(heuristic)"),
                event.message,
            );

            self.send_email(&subject, &body).await
        }

        pub async fn send_digest(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if !self.enabled || !self.config.digest_enabled {
                return Ok(());
            }

            let events: Vec<(Uuid, DetectionEvent)> = {
                let mut buffer = self.digest_buffer.lock().await;
                std::mem::take(&mut *buffer)
            };

            if events.is_empty() {
                return Ok(());
            }

            if !self.can_send_email().await {
                eprintln!("Rate limit reached, skipping digest email ({} events buffered)", events.len());
                // Put events back
                let mut buffer = self.digest_buffer.lock().await;
                buffer.extend(events);
                return Ok(());
            }

            // Group by detection type
            let mut by_type: HashMap<String, Vec<&(Uuid, DetectionEvent)>> = HashMap::new();
            for evt in &events {
                let type_name = format!("{}", evt.1.event_type);
                by_type.entry(type_name).or_default().push(evt);
            }

            let subject = format!("[layer234] {} alerts in last {} seconds",
                events.len(), self.config.digest_interval_secs);

            let mut body = format!(
                "LAYER2DETECT DIGEST\n\
                 ====================\n\n\
                 Time: {}\n\
                 Total Alerts: {}\n\n\
                 Summary by Threat Type:\n",
                chrono::Utc::now().to_rfc3339(),
                events.len(),
            );

            for (threat_type, evts) in &by_type {
                body.push_str(&format!("  - {}: {} alerts\n", threat_type, evts.len()));
            }

            body.push_str("\n\nDetailed Alerts:\n");
            body.push_str(&"=".repeat(40));
            body.push('\n');

            for (alert_id, event) in &events {
                body.push_str(&format!(
                    "\n[{}] {} | {} | conf={:.0}%\n  Rule: {}\n",
                    alert_id,
                    event.src_ip,
                    event.event_type,
                    event.confidence * 100.0,
                    event.rule_name.as_deref().unwrap_or("(heuristic)"),
                ));
            }

            self.send_email(&subject, &body).await
        }

        async fn send_email(&self, subject: &str, body: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if self.config.recipients.is_empty() {
                eprintln!("No email recipients configured");
                return Ok(());
            }

            let transport = self.build_transport().await?;

            for recipient in &self.config.recipients {
                let email = Message::builder()
                    .from(self.smtp_settings.from.parse()?)
                    .to(recipient.parse()?)
                    .subject(subject)
                    .header(ContentType::TEXT_PLAIN)
                    .body(body.to_string())?;

                transport.send(email).await?;
            }

            Ok(())
        }

        /// Send a test email to verify SMTP configuration (works even if alerts disabled)
        pub async fn send_test_email(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if self.config.recipients.is_empty() {
                return Err("No email recipients configured in [alerts.email].recipients".into());
            }

            println!("SMTP Configuration:");
            println!("  Host: {}:{}", self.smtp_settings.host, self.smtp_settings.port);
            println!("  From: {}", self.smtp_settings.from);
            println!("  TLS: {}", self.smtp_settings.tls);
            println!("  Auth: {}", if self.smtp_settings.username.is_some() { "yes" } else { "no" });
            println!("  Recipients: {:?}", self.config.recipients);
            if !self.enabled {
                println!("  Note: Email alerts currently DISABLED in config");
            }
            println!();

            let subject = "[layer234] Test Email";
            let body = format!(
                "LAYER2DETECT TEST EMAIL\n\
                 ========================\n\n\
                 This is a test email to verify your SMTP configuration.\n\n\
                 Time: {}\n\
                 Host: {}\n\n\
                 If you received this email, your configuration is working correctly.\n\
                 \n\
                 Email alerts enabled: {}\n",
                chrono::Utc::now().to_rfc3339(),
                gethostname::gethostname().to_string_lossy(),
                if self.enabled { "YES" } else { "NO - enable in config.toml" },
            );

            println!("Sending test email...");
            self.send_email_direct(subject, &body).await?;
            println!("✓ Test email sent successfully!");

            Ok(())
        }

        /// Send email directly (bypasses enabled check, for testing)
        async fn send_email_direct(&self, subject: &str, body: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if self.config.recipients.is_empty() {
                return Err("No email recipients configured".into());
            }

            let transport = self.build_transport().await?;

            for recipient in &self.config.recipients {
                let email = Message::builder()
                    .from(self.smtp_settings.from.parse()?)
                    .to(recipient.parse()?)
                    .subject(subject)
                    .header(ContentType::TEXT_PLAIN)
                    .body(body.to_string())?;

                transport.send(email).await?;
            }

            Ok(())
        }

        pub async fn run_digest_loop(self: Arc<Self>, running: Arc<AtomicBool>) {
            let interval = Duration::from_secs(self.config.digest_interval_secs);
            let mut last_digest = Instant::now();

            while running.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(1)).await;

                if last_digest.elapsed() >= interval {
                    if let Err(e) = self.send_digest().await {
                        eprintln!("Failed to send digest email: {}", e);
                    }
                    last_digest = Instant::now();
                }
            }

            // Send final digest on shutdown
            if let Err(e) = self.send_digest().await {
                eprintln!("Failed to send final digest email: {}", e);
            }
        }
    }

    // =============================================================================
    // Command Executor
    // =============================================================================

    use tokio::process::Command;
    use tokio::io::AsyncWriteExt;

    pub struct CommandExecutor {
        enabled: bool,
        command: String,
        workdir: Option<String>,
        timeout_secs: u64,
        threat_types: Vec<String>,
        min_confidence: f32,
        env_vars: Option<HashMap<String, String>>,
    }

    impl CommandExecutor {
        pub fn new(config: &crmonban::layer234::config::CommandAlertConfig) -> Self {
            Self {
                enabled: config.enabled,
                command: config.command.clone(),
                workdir: config.workdir.clone(),
                timeout_secs: config.timeout_secs,
                threat_types: config.threat_types.clone(),
                min_confidence: config.min_confidence,
                env_vars: config.env_vars.clone(),
            }
        }

        fn should_execute(&self, event: &DetectionEvent) -> bool {
            if !self.enabled {
                return false;
            }
            if event.confidence < self.min_confidence {
                return false;
            }
            if self.threat_types.is_empty() {
                return true; // Execute for all detection types
            }
            let type_name = get_event_type_name(&event.event_type);
            self.threat_types.iter().any(|t| t == type_name)
        }

        pub async fn maybe_execute(&self, event: &DetectionEvent, alert_id: Uuid) {
            if !self.should_execute(event) {
                return;
            }

            if let Err(e) = self.execute(event, alert_id).await {
                eprintln!("Failed to execute alert command: {}", e);
            }
        }

        async fn execute(&self, event: &DetectionEvent, alert_id: Uuid) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let event_json = serde_json::to_string(event)?;
            let timestamp_ns = event.timestamp.timestamp_nanos_opt().unwrap_or(0);

            let mut cmd = Command::new(&self.command);

            if let Some(workdir) = &self.workdir {
                cmd.current_dir(workdir);
            }

            // Set environment variables from event
            cmd.env("L2D_ALERT_ID", alert_id.to_string());
            cmd.env("L2D_SOURCE_IP", event.src_ip.to_string());
            cmd.env("L2D_DETECTION_TYPE", format!("{}", event.event_type));
            cmd.env("L2D_CONFIDENCE", event.confidence.to_string());
            cmd.env("L2D_TIMESTAMP", timestamp_ns.to_string());
            cmd.env("L2D_EVENT_JSON", &event_json);

            if let Some(rule) = &event.rule_name {
                cmd.env("L2D_RULE_NAME", rule);
            }

            // Add custom env vars from config
            if let Some(env_vars) = &self.env_vars {
                for (key, value) in env_vars {
                    cmd.env(key, value);
                }
            }

            cmd.stdin(std::process::Stdio::piped());
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::piped());

            let mut child = cmd.spawn()?;

            // Write JSON to stdin
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(event_json.as_bytes()).await?;
            }

            // Wait with timeout
            let timeout = Duration::from_secs(self.timeout_secs);
            match tokio::time::timeout(timeout, child.wait()).await {
                Ok(Ok(status)) => {
                    if !status.success() {
                        eprintln!("Alert command exited with status: {}", status);
                    }
                }
                Ok(Err(e)) => {
                    eprintln!("Alert command failed: {}", e);
                }
                Err(_) => {
                    eprintln!("Alert command timed out after {}s, killing", self.timeout_secs);
                    let _ = child.kill().await;
                }
            }

            Ok(())
        }
    }

    // =============================================================================
    // Packet Info Extraction Helper
    // =============================================================================

    fn create_buffered_packet(
        payload: &[u8],
        timestamp_ns: u64,
        max_payload_bytes: usize,
    ) -> Option<BufferedPacket> {
        // Parse IP packet
        use etherparse::SlicedPacket;

        let sliced = SlicedPacket::from_ip(payload).ok()?;

        let (source_ip, dest_ip) = match &sliced.net {
            Some(etherparse::NetSlice::Ipv4(ipv4)) => {
                let h = ipv4.header();
                (
                    IpAddr::V4(h.source_addr()),
                    IpAddr::V4(h.destination_addr()),
                )
            }
            Some(etherparse::NetSlice::Ipv6(ipv6)) => {
                let h = ipv6.header();
                (
                    IpAddr::V6(h.source_addr()),
                    IpAddr::V6(h.destination_addr()),
                )
            }
            _ => return None,
        };

        // Get payload based on transport type
        let (protocol, source_port, dest_port, app_payload): (String, Option<u16>, Option<u16>, Vec<u8>) = match &sliced.transport {
            Some(etherparse::TransportSlice::Tcp(tcp)) => {
                // Calculate payload offset and extract
                let tcp_header_len = tcp.slice().len();
                let ip_payload = match &sliced.net {
                    Some(etherparse::NetSlice::Ipv4(ipv4)) => {
                        let total_len = ipv4.header().total_len() as usize;
                        let ip_header_len = ipv4.header().ihl() as usize * 4;
                        if total_len > ip_header_len + tcp_header_len {
                            payload.get(ip_header_len + tcp_header_len..total_len.min(payload.len()))
                                .map(|s| s.to_vec())
                                .unwrap_or_default()
                        } else {
                            Vec::new()
                        }
                    }
                    Some(etherparse::NetSlice::Ipv6(ipv6)) => {
                        let ip_header_len = 40; // Fixed IPv6 header
                        let plen = ipv6.header().payload_length() as usize;
                        if plen > tcp_header_len {
                            payload.get(ip_header_len + tcp_header_len..ip_header_len + plen.min(payload.len() - ip_header_len))
                                .map(|s| s.to_vec())
                                .unwrap_or_default()
                        } else {
                            Vec::new()
                        }
                    }
                    _ => Vec::new(),
                };
                ("TCP".to_string(), Some(tcp.source_port()), Some(tcp.destination_port()), ip_payload)
            }
            Some(etherparse::TransportSlice::Udp(udp)) => {
                // UDP payload is easier - just after UDP header
                let udp_payload = udp.payload().to_vec();
                ("UDP".to_string(), Some(udp.source_port()), Some(udp.destination_port()), udp_payload)
            }
            Some(etherparse::TransportSlice::Icmpv4(_)) => {
                ("ICMP".to_string(), None, None, Vec::new())
            }
            Some(etherparse::TransportSlice::Icmpv6(_)) => {
                ("ICMPv6".to_string(), None, None, Vec::new())
            }
            _ => ("OTHER".to_string(), None, None, Vec::new()),
        };

        // Extract HTTP info
        let http_info = if protocol == "TCP" && !app_payload.is_empty() {
            extract_http_info(&app_payload)
        } else {
            None
        };

        // Extract TLS SNI (simple check for TLS ClientHello)
        let tls_sni = if protocol == "TCP" && app_payload.len() > 5 {
            extract_tls_sni(&app_payload)
        } else {
            None
        };

        // Payload preview
        let payload_preview = if !app_payload.is_empty() {
            let len = app_payload.len().min(max_payload_bytes);
            Some(hex::encode(&app_payload[..len]))
        } else {
            None
        };

        Some(BufferedPacket {
            timestamp_ns,
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            protocol,
            http_info,
            tls_sni,
            payload_preview,
            payload_len: app_payload.len(),
        })
    }

    /// Simple TLS SNI extraction from ClientHello
    fn extract_tls_sni(payload: &[u8]) -> Option<String> {
        // Check for TLS handshake (content type 0x16, version, handshake type 0x01)
        if payload.len() < 44 {
            return None;
        }
        if payload[0] != 0x16 {
            return None; // Not TLS handshake
        }

        // Skip to handshake type
        if payload.get(5)? != &0x01 {
            return None; // Not ClientHello
        }

        // Try to find SNI extension (this is a simplified parser)
        // Full parsing would require following the TLS record structure
        let sni_marker = b"\x00\x00"; // SNI extension type
        if let Some(pos) = payload.windows(2).position(|w| w == sni_marker) {
            // Look for hostname after the extension header
            if pos + 9 < payload.len() {
                let name_len_pos = pos + 7;
                if name_len_pos + 2 < payload.len() {
                    let name_len = ((payload[name_len_pos] as usize) << 8) | (payload[name_len_pos + 1] as usize);
                    let name_start = name_len_pos + 2;
                    if name_start + name_len <= payload.len() {
                        if let Ok(sni) = std::str::from_utf8(&payload[name_start..name_start + name_len]) {
                            if sni.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
                                return Some(sni.to_string());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Send a test email to verify SMTP configuration (no root required)
    pub async fn test_email(config_file: Option<String>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("layer234 - Test Email");
        println!("=========================\n");

        // Load config
        let config = match config_file {
            Some(path) => {
                println!("Config: {}", path);
                Config::from_file(&path)?
            }
            None => {
                if std::path::Path::new("config.toml").exists() {
                    println!("Config: config.toml");
                    Config::from_file("config.toml")?
                } else {
                    println!("Config: built-in defaults");
                    Config::default()
                }
            }
        };

        let email_manager = EmailAlertManager::new(&config.alerts);
        email_manager.send_test_email().await?;

        Ok(())
    }

    pub async fn run(
        queue_num: u16,
        config_file: Option<String>,
        allowlist: HashSet<(IpAddr, Option<u16>)>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        println!("layer234 NFQUEUE Reader");
        println!("===========================\n");

        if !allowlist.is_empty() {
            println!("Allowlist: {:?}", allowlist.iter().collect::<Vec<_>>());
        }

        // Check for root
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("Error: This program requires root privileges.");
            eprintln!(
                "Run with: sudo cargo run --example nfqueue_reader --release -- -q {}",
                queue_num
            );
            std::process::exit(1);
        }

        // Load config
        let config = match config_file {
            Some(path) => {
                println!("Config: {}", path);
                Config::from_file(&path)?
            }
            None => {
                if std::path::Path::new("config.toml").exists() {
                    println!("Config: config.toml");
                    Config::from_file("config.toml")?
                } else {
                    println!("Config: built-in defaults");
                    Config::default()
                }
            }
        };

        // Create detector
        let mut detector = DetectorBuilder::from_config(&config).build_with_config(&config)?;

        println!("Signatures: {}", detector.signature_count());
        println!("Queue: {}", queue_num);

        // Initialize logger
        let logger = Arc::new(Mutex::new(Logger::new(&config)?));
        if config.logging.enabled && config.logging.json.enabled {
            println!("Alert log: {}", config.logging.json.path);
        }
        if config.packet_log.enabled {
            println!("Packet log: {}", config.packet_log.path);
        }

        // Create packet ring buffer (120 second window, 1000 packets per IP)
        let packet_buffer = Arc::new(Mutex::new(PacketRingBuffer::new(1000, 120)));
        let max_payload_bytes = config.packet_log.max_payload_bytes;

        // Initialize email alert manager
        let email_manager = Arc::new(EmailAlertManager::new(&config.alerts));
        if config.alerts.enabled && config.alerts.email.enabled {
            println!("Email alerts: enabled (digest every {}s)", config.alerts.email.digest_interval_secs);
            if !config.alerts.email.recipients.is_empty() {
                println!("  Recipients: {:?}", config.alerts.email.recipients);
            }
        }

        // Initialize command executor
        let command_executor = Arc::new(CommandExecutor::new(&config.alerts.command));
        if config.alerts.command.enabled {
            println!("Command on alert: {}", config.alerts.command.command);
        }

        // Open NFQUEUE
        let mut queue = Queue::open()?;
        queue.bind(queue_num)?;

        println!("\nStarting capture... (Press Ctrl+C to stop)");
        println!("Make sure nftables rules are set up:");
        println!("  sudo ./scripts/setup-nftables.sh start\n");

        // Set up signal handler for clean shutdown
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        ctrlc::set_handler(move || {
            println!("\nReceived Ctrl+C, stopping...");
            running_clone.store(false, Ordering::Relaxed);
        })?;

        // Start email digest background task
        let email_manager_digest = Arc::clone(&email_manager);
        let running_digest = Arc::clone(&running);
        let digest_task = tokio::spawn(async move {
            email_manager_digest.run_digest_loop(running_digest).await;
        });

        // Detection handler (with allowlist filtering, logging, email alerts, and command execution)
        let mut rx = detector.detection_stream();
        let logger_clone = Arc::clone(&logger);
        let packet_buffer_clone = Arc::clone(&packet_buffer);
        let email_manager_clone = Arc::clone(&email_manager);
        let command_executor_clone = Arc::clone(&command_executor);
        let detection_handler = tokio::spawn(async move {
            while let Ok(event) = rx.recv().await {
                // Skip alerts from allowlisted IP:port combinations
                if is_allowed(&event, &allowlist) {
                    continue;
                }

                // Generate alert ID
                let alert_id = Uuid::new_v4();

                // Log the alert
                {
                    let mut logger_guard = logger_clone.lock().await;
                    if let Err(e) = logger_guard.log_alert(&event, alert_id) {
                        eprintln!("Failed to log alert: {}", e);
                    }

                    // Log associated packets from buffer
                    let buffer_guard = packet_buffer_clone.lock().await;
                    let related_packets = buffer_guard.get_recent(&event.src_ip);
                    for pkt in &related_packets {
                        if let Err(e) = logger_guard.log_packet(pkt, Some(alert_id), Some(&event)) {
                            eprintln!("Failed to log packet: {}", e);
                        }
                    }
                }

                // Send email alert (immediate or buffer for digest)
                email_manager_clone.handle_event(event.clone(), alert_id).await;

                // Execute command if configured
                command_executor_clone.maybe_execute(&event, alert_id).await;

                // Console output
                print_detection(&event);
            }
        });

        // Stats tracking
        let mut stats = CaptureStats::new();

        // Main capture loop
        while running.load(Ordering::Relaxed) {
            match queue.recv() {
                Ok(mut msg) => {
                    let payload = msg.get_payload();
                    let len = payload.len();

                    stats.packets += 1;
                    stats.bytes += len;

                    let timestamp_ns = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos() as u64;

                    // Create buffered packet for logging
                    if let Some(buffered_pkt) = create_buffered_packet(payload, timestamp_ns, max_payload_bytes) {
                        // Log HTTP immediately (before adding to buffer, to avoid duplicates)
                        if buffered_pkt.http_info.is_some() || buffered_pkt.tls_sni.is_some() {
                            let mut logger_guard = logger.lock().await;
                            let _ = logger_guard.log_http_only(&buffered_pkt);
                        }

                        // Add to ring buffer
                        let mut buffer_guard = packet_buffer.lock().await;
                        buffer_guard.add(buffered_pkt);
                    }

                    // Process packet through detector
                    // Note: NFQUEUE gives us IP packets (no ethernet header)
                    match parse_ip_packet(payload, timestamp_ns) {
                        Ok(packet) => {
                            let mut analysis = PacketAnalysis::new(packet);
                            detector.process(&mut analysis).await;
                        }
                        Err(NetVecError::NoIpLayer) => {
                            // Skip non-IP packets
                        }
                        Err(_) => {
                            stats.errors += 1;
                        }
                    }

                    // Accept the packet (let it continue through the network stack)
                    msg.set_verdict(Verdict::Accept);
                    queue.verdict(msg)?;

                    // Periodic stats
                    stats.maybe_print_interval();
                }
                Err(e) => {
                    // Check if we should exit
                    if !running.load(Ordering::Relaxed) {
                        break;
                    }
                    eprintln!("Queue receive error: {}", e);
                    stats.errors += 1;
                }
            }
        }

        println!("\nShutting down...");
        detector.flush().await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(detector);
        let _ = detection_handler.await;

        // Wait for digest task to send final email
        println!("Sending final email digest...");
        let _ = digest_task.await;

        stats.print_final();
        Ok(())
    }
}

#[cfg(target_os = "linux")]
use linux::{run, test_email};

#[cfg(not(target_os = "linux"))]
async fn run(
    _queue_num: u16,
    _config_file: Option<String>,
    _allowlist: std::collections::HashSet<(std::net::IpAddr, Option<u16>)>,
) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("Error: This example is Linux-only.");
    eprintln!("It requires nftables/netfilter queue support.");
    std::process::exit(1);
}

#[cfg(not(target_os = "linux"))]
async fn test_email(_config_file: Option<String>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    eprintln!("Error: This example is Linux-only.");
    std::process::exit(1);
}

fn main() {
    use std::collections::HashSet;
    use std::net::IpAddr;
    use daemonize::Daemonize;
    use std::fs::File;

    // Load .env file FIRST (before any config loading)
    // This loads .env vars into the process environment
    match dotenvy::dotenv() {
        Ok(path) => eprintln!("Loaded .env from: {}", path.display()),
        Err(e) => {
            if !e.not_found() {
                eprintln!("Warning: .env error: {}", e);
            }
            // .env not found is fine, will use config.toml values
        }
    }

    let args: Vec<String> = std::env::args().collect();
    let mut queue_num: u16 = 0;
    let mut config_file: Option<String> = None;
    let mut allowlist: HashSet<(IpAddr, Option<u16>)> = HashSet::new();
    let mut do_test_email = false;
    let mut do_daemon = false;
    let mut pid_file: Option<String> = None;
    let mut log_file: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--queue" | "-q" => {
                if i + 1 < args.len() {
                    queue_num = args[i + 1].parse().unwrap_or(0);
                    i += 1;
                }
            }
            "--config" | "-c" => {
                if i + 1 < args.len() {
                    config_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--allowlist" | "-a" => {
                // Format: IP or IP:PORT (e.g., 192.168.1.100 or 192.168.1.100:22)
                if i + 1 < args.len() {
                    let arg = &args[i + 1];
                    if let Some((ip_str, port_str)) = arg.split_once(':') {
                        if let (Ok(ip), Ok(port)) = (ip_str.parse::<IpAddr>(), port_str.parse::<u16>()) {
                            allowlist.insert((ip, Some(port)));
                        } else {
                            eprintln!("Warning: Invalid IP:PORT format: {}", arg);
                        }
                    } else if let Ok(ip) = arg.parse::<IpAddr>() {
                        allowlist.insert((ip, None)); // All ports for this IP
                    } else {
                        eprintln!("Warning: Invalid IP address: {}", arg);
                    }
                    i += 1;
                }
            }
            "--test-email" => {
                do_test_email = true;
            }
            "--daemon" | "-d" => {
                do_daemon = true;
            }
            "--pid-file" => {
                if i + 1 < args.len() {
                    pid_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--log-file" => {
                if i + 1 < args.len() {
                    log_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("NFQUEUE Reader - Packet capture via nftables queue\n");
                println!("Usage: nfqueue_reader [OPTIONS]\n");
                println!("Options:");
                println!("  -q, --queue <NUM>       Queue number (default: 0)");
                println!("  -c, --config <FILE>     Config file (default: config.toml)");
                println!("  -a, --allowlist <SPEC>  IP or IP:PORT to exclude from alerts");
                println!("  -d, --daemon            Run as daemon (background)");
                println!("  --pid-file <FILE>       PID file path (default: /var/run/layer234.pid)");
                println!("  --log-file <FILE>       Log file for daemon output");
                println!("  --test-email            Send a test email and exit (no root required)");
                println!("  -h, --help              Show this help");
                println!("\nAllowlist formats:");
                println!("  -a 192.168.1.100        Exclude all traffic from this IP");
                println!("  -a 192.168.1.100:22     Exclude SSH traffic from this IP only");
                println!("\nDaemon mode:");
                println!("  sudo ./layer234 -d --pid-file /var/run/layer234.pid");
                println!("\nSetup:");
                println!("  1. Start nftables queue: sudo ./scripts/setup-nftables.sh start");
                println!("  2. Run detector:         sudo ./layer234 -c config.toml");
                println!("  3. Stop queue when done: sudo ./scripts/setup-nftables.sh stop");
                println!("\nTest email:");
                println!("  ./layer234 --test-email");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    // Daemonize if requested
    if do_daemon {
        let pid_path = pid_file.unwrap_or_else(|| "/var/run/layer234.pid".to_string());

        let mut daemon = Daemonize::new()
            .pid_file(&pid_path)
            .chown_pid_file(true)
            .working_directory("/");

        if let Some(log_path) = &log_file {
            let stdout = File::create(log_path).expect("Failed to create log file");
            let stderr = stdout.try_clone().expect("Failed to clone log file");
            daemon = daemon.stdout(stdout).stderr(stderr);
        }

        match daemon.start() {
            Ok(_) => {
                // Successfully daemonized
            }
            Err(e) => {
                eprintln!("Error daemonizing: {}", e);
                std::process::exit(1);
            }
        }
    }

    let rt = tokio::runtime::Runtime::new().unwrap();

    if do_test_email {
        if let Err(e) = rt.block_on(test_email(config_file)) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    } else {
        if let Err(e) = rt.block_on(run(queue_num, config_file, allowlist)) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
