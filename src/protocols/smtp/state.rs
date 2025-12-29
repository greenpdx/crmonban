//! SMTP per-flow state

use std::any::Any;
use std::time::Instant;

use crate::protocols::traits::ProtocolStateData;
use crate::types::protocols::{SmtpAuthMechanism, SmtpHeaders};

/// SMTP per-flow state
#[derive(Debug)]
pub struct SmtpState {
    /// Server banner
    pub server_banner: Option<String>,
    /// Client hostname (from EHLO/HELO)
    pub client_hostname: Option<String>,
    /// Server capabilities
    pub capabilities: Vec<String>,
    /// Is ESMTP (extended SMTP)
    pub is_esmtp: bool,
    /// Using TLS
    pub using_tls: bool,
    /// Current envelope sender
    pub mail_from: Option<String>,
    /// Current recipients
    pub rcpt_to: Vec<String>,
    /// Current message headers
    pub headers: Option<SmtpHeaders>,
    /// Message body size
    pub body_size: usize,
    /// Has attachments
    pub has_attachments: bool,
    /// Dangerous attachments detected
    pub dangerous_attachments: Vec<String>,
    /// Authentication mechanism used
    pub auth_mechanism: Option<SmtpAuthMechanism>,
    /// Authenticated username
    pub auth_username: Option<String>,
    /// Authentication successful
    pub auth_success: Option<bool>,
    /// Authentication failures in this flow
    pub auth_failures: u32,
    /// Transaction count
    pub transaction_count: u32,
    /// Total recipients count
    pub total_recipients: u32,
    /// Spam indicators detected
    pub spam_indicators: Vec<String>,
    /// Phishing indicators detected
    pub phishing_indicators: Vec<String>,
    /// Spoofing detected
    pub spoofing_detected: bool,
    /// Connection start time
    pub start_time: Instant,
    /// Last activity
    pub last_activity: Instant,
    /// Errors encountered
    pub errors: Vec<(u16, String)>,
}

impl SmtpState {
    /// Create new SMTP state
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            server_banner: None,
            client_hostname: None,
            capabilities: Vec::new(),
            is_esmtp: false,
            using_tls: false,
            mail_from: None,
            rcpt_to: Vec::new(),
            headers: None,
            body_size: 0,
            has_attachments: false,
            dangerous_attachments: Vec::new(),
            auth_mechanism: None,
            auth_username: None,
            auth_success: None,
            auth_failures: 0,
            transaction_count: 0,
            total_recipients: 0,
            spam_indicators: Vec::new(),
            phishing_indicators: Vec::new(),
            spoofing_detected: false,
            start_time: now,
            last_activity: now,
            errors: Vec::new(),
        }
    }

    /// Record server greeting
    pub fn record_greeting(&mut self, banner: &str) {
        self.server_banner = Some(banner.to_string());
        self.is_esmtp = banner.to_uppercase().contains("ESMTP");
        self.last_activity = Instant::now();
    }

    /// Record EHLO/HELO
    pub fn record_helo(&mut self, hostname: &str, is_esmtp: bool) {
        self.client_hostname = Some(hostname.to_string());
        self.is_esmtp = is_esmtp;
        self.last_activity = Instant::now();
    }

    /// Record capability
    pub fn add_capability(&mut self, capability: &str) {
        if !self.capabilities.contains(&capability.to_string()) {
            self.capabilities.push(capability.to_string());
        }
    }

    /// Record STARTTLS
    pub fn record_starttls(&mut self, success: bool) {
        self.using_tls = success;
        self.last_activity = Instant::now();
    }

    /// Record AUTH start
    pub fn record_auth_start(&mut self, mechanism: SmtpAuthMechanism) {
        self.auth_mechanism = Some(mechanism);
        self.last_activity = Instant::now();
    }

    /// Record AUTH result
    pub fn record_auth_result(&mut self, success: bool, username: Option<&str>) {
        self.auth_success = Some(success);
        if let Some(u) = username {
            self.auth_username = Some(u.to_string());
        }
        if !success {
            self.auth_failures += 1;
        }
        self.last_activity = Instant::now();
    }

    /// Start new mail transaction
    pub fn start_transaction(&mut self, mail_from: &str) {
        self.mail_from = Some(mail_from.to_string());
        self.rcpt_to.clear();
        self.headers = None;
        self.body_size = 0;
        self.has_attachments = false;
        self.dangerous_attachments.clear();
        self.spam_indicators.clear();
        self.phishing_indicators.clear();
        self.spoofing_detected = false;
        self.last_activity = Instant::now();
    }

    /// Add recipient
    pub fn add_recipient(&mut self, rcpt: &str) {
        self.rcpt_to.push(rcpt.to_string());
        self.total_recipients += 1;
        self.last_activity = Instant::now();
    }

    /// Record message headers
    pub fn record_headers(&mut self, headers: SmtpHeaders) {
        self.headers = Some(headers);
        self.last_activity = Instant::now();
    }

    /// Complete transaction
    pub fn complete_transaction(&mut self) {
        self.transaction_count += 1;
        self.last_activity = Instant::now();
    }

    /// Record dangerous attachment
    pub fn add_dangerous_attachment(&mut self, filename: &str) {
        self.dangerous_attachments.push(filename.to_string());
        self.has_attachments = true;
    }

    /// Record spam indicator
    pub fn add_spam_indicator(&mut self, indicator: &str) {
        if !self.spam_indicators.contains(&indicator.to_string()) {
            self.spam_indicators.push(indicator.to_string());
        }
    }

    /// Record phishing indicator
    pub fn add_phishing_indicator(&mut self, indicator: &str) {
        if !self.phishing_indicators.contains(&indicator.to_string()) {
            self.phishing_indicators.push(indicator.to_string());
        }
    }

    /// Record error
    pub fn record_error(&mut self, code: u16, message: &str) {
        self.errors.push((code, message.to_string()));
        self.last_activity = Instant::now();
    }

    /// Reset for new transaction (RSET command)
    pub fn reset_transaction(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
        self.headers = None;
        self.body_size = 0;
        self.has_attachments = false;
        self.dangerous_attachments.clear();
        self.spam_indicators.clear();
        self.phishing_indicators.clear();
        self.spoofing_detected = false;
        self.last_activity = Instant::now();
    }

    /// Check if this looks like brute force
    pub fn is_brute_force(&self, threshold: u32) -> bool {
        self.auth_failures >= threshold
    }

    /// Check if this is high volume
    pub fn is_high_volume(&self, tx_threshold: u32, rcpt_threshold: u32) -> bool {
        self.transaction_count >= tx_threshold || self.total_recipients >= rcpt_threshold
    }
}

impl Default for SmtpState {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolStateData for SmtpState {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_state_creation() {
        let state = SmtpState::new();
        assert!(state.server_banner.is_none());
        assert_eq!(state.auth_failures, 0);
        assert_eq!(state.transaction_count, 0);
    }

    #[test]
    fn test_transaction_lifecycle() {
        let mut state = SmtpState::new();

        state.start_transaction("sender@example.com");
        assert_eq!(state.mail_from, Some("sender@example.com".to_string()));

        state.add_recipient("rcpt1@example.com");
        state.add_recipient("rcpt2@example.com");
        assert_eq!(state.rcpt_to.len(), 2);

        state.complete_transaction();
        assert_eq!(state.transaction_count, 1);
    }

    #[test]
    fn test_auth_tracking() {
        let mut state = SmtpState::new();

        state.record_auth_result(false, Some("user1"));
        state.record_auth_result(false, Some("user2"));
        state.record_auth_result(false, Some("user3"));

        assert_eq!(state.auth_failures, 3);
        assert!(state.is_brute_force(3));
    }
}
