//! SMTP protocol analyzer
//!
//! Detects spam, phishing, authentication attacks, and other email security threats.

use crate::protocols::{ProtocolAnalyzer, SmtpConfig};
use crate::protocols::smtp::parser::{SmtpParser, SmtpCommand};
use crate::types::{Flow, Packet, ProtocolEvent, DetectionType};
use crate::types::protocols::{
    SmtpEvent, SmtpTransaction, EmailAddress,
    spam_patterns::{SPAM_SUBJECT_PATTERNS, PHISHING_SUBJECT_PATTERNS},
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

/// SMTP analyzer for email security monitoring
pub struct SmtpAnalyzer {
    config: SmtpConfig,
    /// Client-side parser (keyed by flow ID)
    client_parsers: RwLock<HashMap<u64, SmtpParser>>,
    /// Server-side parser (keyed by flow ID)
    server_parsers: RwLock<HashMap<u64, SmtpParser>>,
    /// Auth attempt tracking for brute force detection (IP -> attempts)
    auth_attempts: RwLock<HashMap<IpAddr, AuthTracker>>,
    /// Mail volume tracking for mass mailer detection (IP -> count)
    mail_volume: RwLock<HashMap<IpAddr, MailVolumeTracker>>,
    /// Open relay test tracking
    relay_tests: RwLock<HashMap<IpAddr, RelayTestTracker>>,
}

/// Track authentication attempts per IP
#[derive(Debug)]
struct AuthTracker {
    attempts: Vec<(Instant, bool)>, // (timestamp, success)
    usernames: Vec<String>,
}

impl AuthTracker {
    fn new() -> Self {
        Self {
            attempts: Vec::new(),
            usernames: Vec::new(),
        }
    }

    fn add_attempt(&mut self, success: bool, username: Option<&str>) {
        let now = Instant::now();
        self.attempts.push((now, success));
        if let Some(u) = username {
            if !self.usernames.contains(&u.to_string()) {
                self.usernames.push(u.to_string());
            }
        }
    }

    fn failed_attempts_in_window(&self, window: Duration) -> u32 {
        let cutoff = Instant::now() - window;
        self.attempts.iter()
            .filter(|(ts, success)| *ts > cutoff && !success)
            .count() as u32
    }

    fn cleanup(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.attempts.retain(|(ts, _)| *ts > cutoff);
    }
}

/// Track mail volume per IP for mass mailer detection
#[derive(Debug)]
struct MailVolumeTracker {
    /// Timestamps of sent emails
    timestamps: Vec<Instant>,
    /// Unique recipients seen
    unique_recipients: Vec<String>,
}

impl MailVolumeTracker {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
            unique_recipients: Vec::new(),
        }
    }

    fn add_mail(&mut self, recipients: &[String]) {
        self.timestamps.push(Instant::now());
        for rcpt in recipients {
            if !self.unique_recipients.contains(rcpt) {
                self.unique_recipients.push(rcpt.clone());
            }
        }
    }

    fn mails_in_window(&self, window: Duration) -> u32 {
        let cutoff = Instant::now() - window;
        self.timestamps.iter().filter(|ts| **ts > cutoff).count() as u32
    }

    fn unique_recipient_count(&self) -> usize {
        self.unique_recipients.len()
    }

    fn cleanup(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.timestamps.retain(|ts| *ts > cutoff);
    }
}

/// Track potential open relay testing
#[derive(Debug)]
struct RelayTestTracker {
    /// External domains used in MAIL FROM
    from_domains: Vec<String>,
    /// External domains used in RCPT TO
    to_domains: Vec<String>,
    /// Timestamp of first test
    first_seen: Instant,
}

impl RelayTestTracker {
    fn new() -> Self {
        Self {
            from_domains: Vec::new(),
            to_domains: Vec::new(),
            first_seen: Instant::now(),
        }
    }
}

impl SmtpAnalyzer {
    /// Create new SMTP analyzer with configuration
    pub fn new(config: SmtpConfig) -> Self {
        Self {
            config,
            client_parsers: RwLock::new(HashMap::new()),
            server_parsers: RwLock::new(HashMap::new()),
            auth_attempts: RwLock::new(HashMap::new()),
            mail_volume: RwLock::new(HashMap::new()),
            relay_tests: RwLock::new(HashMap::new()),
        }
    }

    /// Analyze a mail transaction for security threats
    pub fn analyze_transaction(
        &self,
        transaction: &SmtpTransaction,
        src_ip: IpAddr,
    ) -> Vec<DetectionType> {
        let mut detections = Vec::new();

        // Check for spam indicators
        if let Some(spam) = self.check_spam(transaction) {
            detections.push(spam);
        }

        // Check for phishing indicators
        if let Some(phishing) = self.check_phishing(transaction) {
            detections.push(phishing);
        }

        // Check for spoofing
        if let Some(spoofing) = self.check_spoofing(transaction) {
            detections.push(spoofing);
        }

        // Check for malware attachments
        for attachment in &transaction.attachments {
            if attachment.is_dangerous {
                detections.push(DetectionType::SmtpMalwareAttachment);
                break;
            }
        }

        // Check for suspicious sender
        if let Some(suspicious) = self.check_suspicious_sender(transaction) {
            detections.push(suspicious);
        }

        // Check header anomalies
        if let Some(anomaly) = self.check_header_anomalies(transaction) {
            detections.push(anomaly);
        }

        // Track mail volume for mass mailer detection
        if self.config.detect_mass_mailer {
            if let Some(mass_mailer) = self.check_mass_mailer(src_ip, transaction) {
                detections.push(mass_mailer);
            }
        }

        detections
    }

    /// Check for spam indicators in email
    fn check_spam(&self, transaction: &SmtpTransaction) -> Option<DetectionType> {
        if let Some(ref subject) = transaction.headers.subject {
            let lower = subject.to_lowercase();
            for pattern in SPAM_SUBJECT_PATTERNS {
                if lower.contains(pattern) {
                    debug!("Spam subject pattern detected: {}", pattern);
                    return Some(DetectionType::SmtpSpam);
                }
            }
        }

        // Check for excessive recipients (common in spam)
        if transaction.rcpt_to.len() > 50 {
            return Some(DetectionType::SmtpSpam);
        }

        None
    }

    /// Check for phishing indicators
    fn check_phishing(&self, transaction: &SmtpTransaction) -> Option<DetectionType> {
        let headers = &transaction.headers;

        // Check subject for phishing patterns
        if let Some(ref subject) = headers.subject {
            let lower = subject.to_lowercase();
            for pattern in PHISHING_SUBJECT_PATTERNS {
                if lower.contains(pattern) {
                    debug!("Phishing subject pattern detected: {}", pattern);
                    return Some(DetectionType::SmtpPhishing);
                }
            }
        }

        // Check for mismatched From header vs envelope sender
        if let Some(ref header_from) = headers.from {
            if let Some(header_email) = EmailAddress::parse(header_from) {
                if let Some(envelope_email) = EmailAddress::parse(&transaction.mail_from) {
                    if header_email.domain.to_lowercase() != envelope_email.domain.to_lowercase() {
                        debug!("Potential phishing: header From domain ({}) != envelope from ({})",
                               header_email.domain, envelope_email.domain);
                        return Some(DetectionType::SmtpPhishing);
                    }
                }
            }
        }

        // Check for suspicious From domain (typosquatting)
        if let Some(ref from) = headers.from {
            if let Some(email) = EmailAddress::parse(from) {
                if email.is_suspicious_domain() {
                    debug!("Suspicious sender domain detected: {}", email.domain);
                    return Some(DetectionType::SmtpPhishing);
                }
            }
        }

        None
    }

    /// Check for email spoofing
    fn check_spoofing(&self, transaction: &SmtpTransaction) -> Option<DetectionType> {
        let headers = &transaction.headers;

        // Check authentication results
        let spf_fail = headers.spf_result.as_ref()
            .map(|r| r.to_lowercase().contains("fail"))
            .unwrap_or(false);

        // Check DKIM - use has_dkim flag (no dkim means it could be spoofed)
        let dkim_missing = !headers.has_dkim;

        let dmarc_fail = headers.dmarc_result.as_ref()
            .map(|r| r.to_lowercase().contains("fail"))
            .unwrap_or(false);

        // If DMARC fails, definitely spoofing
        if dmarc_fail {
            return Some(DetectionType::SmtpSpoofing);
        }

        // If SPF fails and no DKIM, likely spoofing
        if spf_fail && dkim_missing {
            return Some(DetectionType::SmtpSpoofing);
        }

        // Check for obvious From header manipulation
        if let Some(ref from) = headers.from {
            // Display name doesn't match email domain
            if let Some(email) = EmailAddress::parse(from) {
                if let Some((display_name, _)) = from.split_once('<') {
                    let display_lower = display_name.to_lowercase();
                    // Check if display name contains a different domain
                    if display_lower.contains("@") && !display_lower.contains(&email.domain.to_lowercase()) {
                        return Some(DetectionType::SmtpSpoofing);
                    }
                }
            }
        }

        None
    }

    /// Check for suspicious sender patterns
    fn check_suspicious_sender(&self, transaction: &SmtpTransaction) -> Option<DetectionType> {
        // Parse the envelope sender
        if let Some(mail_from) = EmailAddress::parse(&transaction.mail_from) {
            // Check for suspicious TLDs
            if mail_from.is_suspicious_domain() {
                return Some(DetectionType::SmtpSuspiciousSender);
            }

            // Check for suspicious local parts (random strings)
            if self.is_random_looking(&mail_from.local_part) {
                return Some(DetectionType::SmtpSuspiciousSender);
            }
        }

        None
    }

    /// Check if string looks randomly generated
    fn is_random_looking(&self, s: &str) -> bool {
        if s.len() < 8 {
            return false;
        }

        // Count character type transitions
        let mut transitions = 0;
        let mut last_type: Option<CharType> = None;

        for c in s.chars() {
            let current_type = if c.is_ascii_digit() {
                CharType::Digit
            } else if c.is_ascii_lowercase() {
                CharType::Lower
            } else if c.is_ascii_uppercase() {
                CharType::Upper
            } else {
                CharType::Other
            };

            if let Some(last) = last_type {
                if last != current_type {
                    transitions += 1;
                }
            }
            last_type = Some(current_type);
        }

        // High number of transitions relative to length suggests random string
        let ratio = transitions as f32 / s.len() as f32;
        ratio > 0.5 && s.len() >= 12
    }

    /// Check for header anomalies
    fn check_header_anomalies(&self, transaction: &SmtpTransaction) -> Option<DetectionType> {
        let headers = &transaction.headers;

        // Check for missing essential headers
        if headers.from.is_none() || headers.date.is_none() {
            return Some(DetectionType::SmtpHeaderAnomaly);
        }

        // Check for excessive Received headers (possible relay abuse)
        if headers.received.len() > 20 {
            return Some(DetectionType::SmtpHeaderAnomaly);
        }

        None
    }

    /// Check for mass mailer activity
    fn check_mass_mailer(&self, src_ip: IpAddr, transaction: &SmtpTransaction) -> Option<DetectionType> {
        let mut volume = self.mail_volume.write().ok()?;
        let tracker = volume.entry(src_ip).or_insert_with(MailVolumeTracker::new);

        // Add this mail's recipients
        tracker.add_mail(&transaction.rcpt_to);

        // Check thresholds
        let window = Duration::from_secs(self.config.mass_mailer_window_secs);
        let mail_count = tracker.mails_in_window(window);
        let recipient_count = tracker.unique_recipient_count();

        // Cleanup old entries
        tracker.cleanup(window);

        if mail_count > self.config.mass_mailer_threshold
            || recipient_count > self.config.mass_mailer_recipient_threshold as usize
        {
            warn!("Mass mailer detected from {}: {} mails, {} unique recipients",
                  src_ip, mail_count, recipient_count);
            return Some(DetectionType::SmtpMassMailer);
        }

        None
    }

    /// Handle authentication attempt
    pub fn handle_auth_attempt(
        &self,
        src_ip: IpAddr,
        success: bool,
        username: Option<&str>,
    ) -> Option<DetectionType> {
        if !self.config.detect_auth_brute_force {
            return None;
        }

        let mut attempts = self.auth_attempts.write().ok()?;
        let tracker = attempts.entry(src_ip).or_insert_with(AuthTracker::new);

        tracker.add_attempt(success, username);

        let window = Duration::from_secs(self.config.auth_brute_force_window_secs);
        let failed = tracker.failed_attempts_in_window(window);

        // Cleanup old entries
        tracker.cleanup(window);

        if failed >= self.config.auth_brute_force_threshold {
            warn!("SMTP auth brute force detected from {}: {} failed attempts",
                  src_ip, failed);
            return Some(DetectionType::SmtpAuthBruteForce);
        }

        None
    }

    /// Check for open relay abuse
    pub fn check_open_relay(
        &self,
        src_ip: IpAddr,
        mail_from: &str,
        rcpt_to: &[String],
        local_domains: &[String],
    ) -> Option<DetectionType> {
        if !self.config.detect_open_relay {
            return None;
        }

        // Parse sender and get domain
        let from_domain = EmailAddress::parse(mail_from)
            .map(|e| e.domain.to_lowercase());

        // Check if sender domain is external
        let from_external = from_domain
            .as_ref()
            .map(|d| !local_domains.iter().any(|ld| d.eq_ignore_ascii_case(ld)))
            .unwrap_or(true);

        // Check if all recipients are external
        let all_recipients_external = rcpt_to.iter().all(|r| {
            EmailAddress::parse(r)
                .map(|e| !local_domains.iter().any(|d| e.domain.eq_ignore_ascii_case(d)))
                .unwrap_or(true)
        });

        // If from external and to external, this is relay attempt
        if from_external && all_recipients_external && !rcpt_to.is_empty() {
            warn!("Potential open relay abuse from {}: {} -> {:?}",
                  src_ip, mail_from, rcpt_to);
            return Some(DetectionType::SmtpOpenRelay);
        }

        None
    }

    /// Get or create client parser for flow
    fn get_client_parser(&self, flow_id: u64) -> SmtpParser {
        let parsers = self.client_parsers.read().unwrap();
        if let Some(parser) = parsers.get(&flow_id) {
            // Can't clone parser easily, just create new one
        }
        drop(parsers);
        SmtpParser::new(true)
    }

    /// Store client parser
    fn store_client_parser(&self, flow_id: u64, parser: SmtpParser) {
        let mut parsers = self.client_parsers.write().unwrap();
        parsers.insert(flow_id, parser);
    }

    /// Get or create server parser for flow
    fn get_server_parser(&self, flow_id: u64) -> SmtpParser {
        SmtpParser::new(false)
    }

    /// Store server parser
    fn store_server_parser(&self, flow_id: u64, parser: SmtpParser) {
        let mut parsers = self.server_parsers.write().unwrap();
        parsers.insert(flow_id, parser);
    }

    /// Cleanup old flow state
    pub fn cleanup_flow(&self, flow_id: u64) {
        if let Ok(mut parsers) = self.client_parsers.write() {
            parsers.remove(&flow_id);
        }
        if let Ok(mut parsers) = self.server_parsers.write() {
            parsers.remove(&flow_id);
        }
    }
}

/// Character type for randomness detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CharType {
    Digit,
    Lower,
    Upper,
    Other,
}

/// Check if IP is private/internal
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
            // Note: is_unique_local() is unstable, checking manually
            || {
                let segments = ipv6.segments();
                (segments[0] & 0xfe00) == 0xfc00 // fc00::/7
            }
        }
    }
}

impl ProtocolAnalyzer for SmtpAnalyzer {
    fn name(&self) -> &'static str {
        "SMTP"
    }

    fn detect(&self, payload: &[u8], port: u16) -> bool {
        // Check common SMTP ports
        if self.config.ports.contains(&port) {
            return true;
        }

        // Fall back to content detection
        SmtpParser::is_smtp(payload)
    }

    fn parse(&self, packet: &Packet, _flow: &mut Flow) -> Option<ProtocolEvent> {
        let payload = packet.payload();
        if payload.is_empty() {
            return None;
        }

        let dst_port = packet.dst_port();
        let is_to_server = dst_port == 25
            || dst_port == 587
            || dst_port == 465
            || self.config.ports.contains(&dst_port);

        if is_to_server {
            // Client -> Server (commands)
            let mut parser = SmtpParser::new(true);

            if let Some(cmd) = parser.parse_command(payload) {
                let is_ehlo = matches!(cmd, SmtpCommand::Ehlo(_));
                let event = match cmd {
                    SmtpCommand::Ehlo(hostname) | SmtpCommand::Helo(hostname) => {
                        Some(SmtpEvent::Connect {
                            client_hostname: hostname,
                            server_banner: None,
                            capabilities: Vec::new(),
                            is_esmtp: is_ehlo,
                        })
                    }
                    SmtpCommand::Auth { mechanism, .. } => {
                        Some(SmtpEvent::Auth {
                            mechanism,
                            username: None,
                            success: false, // Will be updated on response
                        })
                    }
                    SmtpCommand::StartTls => None, // Will generate on response
                    _ => None,
                };

                if let Some(e) = event {
                    return Some(ProtocolEvent::Smtp(e));
                }
            }
        } else {
            // Server -> Client (responses)
            let mut parser = SmtpParser::new(false);

            if let Some(response) = parser.parse_response(payload) {
                let event = match response.code {
                    220 => {
                        // Server greeting
                        Some(SmtpEvent::Connect {
                            client_hostname: String::new(),
                            server_banner: Some(response.message.clone()),
                            capabilities: Vec::new(),
                            is_esmtp: response.message.to_uppercase().contains("ESMTP"),
                        })
                    }
                    235 => {
                        // Auth success
                        let src_ip = packet.src_ip();
                        self.handle_auth_attempt(src_ip, true, None);
                        Some(SmtpEvent::Auth {
                            mechanism: crate::types::protocols::SmtpAuthMechanism::Unknown("unknown".into()),
                            username: None,
                            success: true,
                        })
                    }
                    535 => {
                        // Auth failure
                        let src_ip = packet.src_ip();
                        self.handle_auth_attempt(src_ip, false, None);
                        Some(SmtpEvent::Auth {
                            mechanism: crate::types::protocols::SmtpAuthMechanism::Unknown("unknown".into()),
                            username: None,
                            success: false,
                        })
                    }
                    code if code >= 400 => {
                        Some(SmtpEvent::Error {
                            code,
                            message: response.message,
                            command: None,
                        })
                    }
                    _ => None,
                };

                if let Some(e) = event {
                    return Some(ProtocolEvent::Smtp(e));
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::protocols::{SmtpHeaders, SmtpAttachment};

    fn test_config() -> SmtpConfig {
        SmtpConfig::default()
    }

    #[test]
    fn test_spam_detection_by_subject() {
        let analyzer = SmtpAnalyzer::new(test_config());

        let transaction = SmtpTransaction {
            mail_from: "sender@example.com".to_string(),
            rcpt_to: vec!["rcpt@example.com".to_string()],
            recipient_count: 1,
            headers: SmtpHeaders {
                subject: Some("CONGRATULATIONS! You've won a FREE iPhone!!!".to_string()),
                from: Some("sender@example.com".to_string()),
                date: Some("Mon, 1 Jan 2024 00:00:00 +0000".to_string()),
                ..Default::default()
            },
            message_size: Some(100),
            has_attachments: false,
            attachments: vec![],
            timestamp: None,
            rejected: false,
            rejection_reason: None,
        };

        let detections = analyzer.analyze_transaction(
            &transaction,
            "192.168.1.1".parse().unwrap(),
        );

        assert!(detections.contains(&DetectionType::SmtpSpam));
    }

    #[test]
    fn test_phishing_detection() {
        let analyzer = SmtpAnalyzer::new(test_config());

        let transaction = SmtpTransaction {
            mail_from: "sender@example.com".to_string(),
            rcpt_to: vec!["rcpt@example.com".to_string()],
            recipient_count: 1,
            headers: SmtpHeaders {
                subject: Some("Your account has been suspended - verify immediately".to_string()),
                from: Some("sender@example.com".to_string()),
                date: Some("Mon, 1 Jan 2024 00:00:00 +0000".to_string()),
                ..Default::default()
            },
            message_size: Some(100),
            has_attachments: false,
            attachments: vec![],
            timestamp: None,
            rejected: false,
            rejection_reason: None,
        };

        let detections = analyzer.analyze_transaction(
            &transaction,
            "192.168.1.1".parse().unwrap(),
        );

        assert!(detections.contains(&DetectionType::SmtpPhishing));
    }

    #[test]
    fn test_malware_attachment_detection() {
        let analyzer = SmtpAnalyzer::new(test_config());

        let transaction = SmtpTransaction {
            mail_from: "sender@example.com".to_string(),
            rcpt_to: vec!["rcpt@example.com".to_string()],
            recipient_count: 1,
            headers: SmtpHeaders {
                from: Some("sender@example.com".to_string()),
                date: Some("Mon, 1 Jan 2024 00:00:00 +0000".to_string()),
                ..Default::default()
            },
            message_size: Some(100),
            has_attachments: true,
            attachments: vec![
                SmtpAttachment {
                    filename: "invoice.exe".to_string(),
                    content_type: "application/octet-stream".to_string(),
                    size: 1024,
                    extension: Some("exe".to_string()),
                    is_dangerous: true,
                    hash: None,
                },
            ],
            timestamp: None,
            rejected: false,
            rejection_reason: None,
        };

        let detections = analyzer.analyze_transaction(
            &transaction,
            "192.168.1.1".parse().unwrap(),
        );

        assert!(detections.contains(&DetectionType::SmtpMalwareAttachment));
    }

    #[test]
    fn test_spoofing_detection() {
        let analyzer = SmtpAnalyzer::new(test_config());

        let transaction = SmtpTransaction {
            mail_from: "sender@example.com".to_string(),
            rcpt_to: vec!["rcpt@example.com".to_string()],
            recipient_count: 1,
            headers: SmtpHeaders {
                from: Some("sender@example.com".to_string()),
                date: Some("Mon, 1 Jan 2024 00:00:00 +0000".to_string()),
                spf_result: Some("fail".to_string()),
                has_dkim: false, // no DKIM signature
                ..Default::default()
            },
            message_size: Some(100),
            has_attachments: false,
            attachments: vec![],
            timestamp: None,
            rejected: false,
            rejection_reason: None,
        };

        let detections = analyzer.analyze_transaction(
            &transaction,
            "192.168.1.1".parse().unwrap(),
        );

        assert!(detections.contains(&DetectionType::SmtpSpoofing));
    }

    #[test]
    fn test_auth_brute_force_detection() {
        let config = SmtpConfig {
            auth_brute_force_threshold: 3,
            auth_brute_force_window_secs: 60,
            detect_auth_brute_force: true,
            ..Default::default()
        };
        let analyzer = SmtpAnalyzer::new(config);
        let src_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // First two attempts shouldn't trigger
        assert!(analyzer.handle_auth_attempt(src_ip, false, Some("user1")).is_none());
        assert!(analyzer.handle_auth_attempt(src_ip, false, Some("user2")).is_none());

        // Third should trigger brute force detection
        let detection = analyzer.handle_auth_attempt(src_ip, false, Some("user3"));
        assert_eq!(detection, Some(DetectionType::SmtpAuthBruteForce));
    }

    #[test]
    fn test_open_relay_detection() {
        let config = SmtpConfig {
            detect_open_relay: true,
            ..Default::default()
        };
        let analyzer = SmtpAnalyzer::new(config);

        let local_domains = vec!["mycompany.com".to_string()];
        let src_ip: IpAddr = "203.0.113.1".parse().unwrap();

        // External -> External (relay abuse)
        let mail_from = "sender@external.com";
        let rcpt_to = vec!["recipient@another-external.com".to_string()];

        let detection = analyzer.check_open_relay(src_ip, mail_from, &rcpt_to, &local_domains);
        assert_eq!(detection, Some(DetectionType::SmtpOpenRelay));

        // External -> Internal (legitimate incoming mail)
        let rcpt_to_internal = vec!["user@mycompany.com".to_string()];
        let detection = analyzer.check_open_relay(src_ip, mail_from, &rcpt_to_internal, &local_domains);
        assert!(detection.is_none());
    }

    #[test]
    fn test_is_smtp() {
        assert!(SmtpParser::is_smtp(b"220 mail.example.com ESMTP Postfix\r\n"));
        assert!(SmtpParser::is_smtp(b"EHLO localhost\r\n"));
        assert!(SmtpParser::is_smtp(b"MAIL FROM:<test@example.com>\r\n"));
        assert!(!SmtpParser::is_smtp(b"GET / HTTP/1.1\r\n"));
    }
}
