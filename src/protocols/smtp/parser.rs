//! SMTP protocol parser
//!
//! Parses SMTP commands and responses to extract mail transaction events.

use crmonban_types::protocols::{
    SmtpEvent, SmtpAuthMechanism, SmtpTransaction, SmtpHeaders,
    SmtpAttachment, EmailAddress,
};
use tracing::{debug, trace};
use std::collections::HashMap;

/// SMTP command types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpCommand {
    Ehlo(String),
    Helo(String),
    Auth { mechanism: SmtpAuthMechanism, initial_response: Option<String> },
    StartTls,
    MailFrom { address: String, parameters: HashMap<String, String> },
    RcptTo { address: String, parameters: HashMap<String, String> },
    Data,
    Rset,
    Vrfy(String),
    Expn(String),
    Noop,
    Quit,
    AuthContinuation(String),
    Unknown { command: String, args: String },
}

/// SMTP response
#[derive(Debug, Clone)]
pub struct SmtpResponse {
    pub code: u16,
    pub enhanced_code: Option<String>,
    pub message: String,
    pub is_multiline: bool,
}

impl SmtpResponse {
    /// Check if response indicates success (2xx)
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// Check if response indicates temporary failure (4xx)
    pub fn is_temporary_failure(&self) -> bool {
        (400..500).contains(&self.code)
    }

    /// Check if response indicates permanent failure (5xx)
    pub fn is_permanent_failure(&self) -> bool {
        (500..600).contains(&self.code)
    }

    /// Check if response is ready for data (354)
    pub fn is_ready_for_data(&self) -> bool {
        self.code == 354
    }
}

/// Parser state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpParserState {
    /// Waiting for server greeting
    Initial,
    /// After greeting, waiting for EHLO/HELO
    Connected,
    /// After EHLO/HELO success
    Greeted,
    /// In AUTH sequence
    Authenticating,
    /// After successful AUTH
    Authenticated,
    /// In mail transaction (after MAIL FROM)
    InTransaction,
    /// After RCPT TO
    HasRecipients,
    /// Receiving DATA
    ReceivingData,
    /// Connection closed
    Closed,
}

/// SMTP parser for extracting protocol events
#[derive(Debug)]
pub struct SmtpParser {
    /// Current parser state
    state: SmtpParserState,
    /// Is this parsing client traffic?
    is_client: bool,
    /// Server capabilities from EHLO response
    capabilities: Vec<String>,
    /// Current transaction being built
    current_transaction: Option<TransactionBuilder>,
    /// Data buffer for DATA command
    data_buffer: Vec<u8>,
    /// Last command sent (for correlating responses)
    last_command: Option<SmtpCommand>,
    /// Current auth username
    auth_username: Option<String>,
    /// Current auth mechanism
    auth_mechanism: Option<SmtpAuthMechanism>,
}

/// Builder for SMTP transaction
#[derive(Debug, Default)]
struct TransactionBuilder {
    mail_from: String,
    mail_from_params: HashMap<String, String>,
    rcpt_to: Vec<String>,
    headers: SmtpHeaders,
    body_size: usize,
    attachments: Vec<SmtpAttachment>,
}

impl SmtpParser {
    /// Create new SMTP parser
    pub fn new(is_client: bool) -> Self {
        Self {
            state: SmtpParserState::Initial,
            is_client,
            capabilities: Vec::new(),
            current_transaction: None,
            data_buffer: Vec::new(),
            last_command: None,
            auth_username: None,
            auth_mechanism: None,
        }
    }

    /// Check if payload looks like SMTP
    pub fn is_smtp(payload: &[u8]) -> bool {
        // Check for server greeting (220)
        if payload.starts_with(b"220 ") || payload.starts_with(b"220-") {
            return true;
        }

        // Check for common SMTP commands
        let cmd_prefixes = [
            b"EHLO ".as_slice(),
            b"HELO ".as_slice(),
            b"MAIL FROM:".as_slice(),
            b"RCPT TO:".as_slice(),
            b"DATA\r\n".as_slice(),
            b"AUTH ".as_slice(),
            b"STARTTLS\r\n".as_slice(),
            b"QUIT\r\n".as_slice(),
            b"RSET\r\n".as_slice(),
        ];

        let upper = payload.to_ascii_uppercase();
        for prefix in &cmd_prefixes {
            if upper.starts_with(prefix) {
                return true;
            }
        }

        // Check for SMTP response codes
        if payload.len() >= 3 {
            if let Ok(s) = std::str::from_utf8(&payload[..3]) {
                if let Ok(code) = s.parse::<u16>() {
                    if (200..600).contains(&code) {
                        if payload.len() >= 4 {
                            let sep = payload[3];
                            if sep == b' ' || sep == b'-' || sep == b'\r' {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        false
    }

    /// Parse client command
    pub fn parse_command(&mut self, payload: &[u8]) -> Option<SmtpCommand> {
        // Handle DATA content
        if self.state == SmtpParserState::ReceivingData {
            return self.handle_data_content(payload);
        }

        let line = std::str::from_utf8(payload).ok()?;
        let line = line.trim_end_matches(|c| c == '\r' || c == '\n');

        if line.is_empty() {
            return None;
        }

        // Parse command
        let upper = line.to_uppercase();
        let cmd = if upper.starts_with("EHLO ") {
            let hostname = line[5..].trim().to_string();
            Some(SmtpCommand::Ehlo(hostname))
        } else if upper.starts_with("HELO ") {
            let hostname = line[5..].trim().to_string();
            Some(SmtpCommand::Helo(hostname))
        } else if upper.starts_with("AUTH ") {
            self.parse_auth_command(&line[5..])
        } else if upper == "STARTTLS" {
            Some(SmtpCommand::StartTls)
        } else if upper.starts_with("MAIL FROM:") {
            self.parse_mail_from(&line[10..])
        } else if upper.starts_with("RCPT TO:") {
            self.parse_rcpt_to(&line[8..])
        } else if upper == "DATA" {
            Some(SmtpCommand::Data)
        } else if upper == "RSET" {
            Some(SmtpCommand::Rset)
        } else if upper.starts_with("VRFY ") {
            Some(SmtpCommand::Vrfy(line[5..].trim().to_string()))
        } else if upper.starts_with("EXPN ") {
            Some(SmtpCommand::Expn(line[5..].trim().to_string()))
        } else if upper == "NOOP" {
            Some(SmtpCommand::Noop)
        } else if upper == "QUIT" {
            Some(SmtpCommand::Quit)
        } else if self.state == SmtpParserState::Authenticating {
            // Auth continuation (base64 encoded)
            Some(SmtpCommand::AuthContinuation(line.to_string()))
        } else {
            // Unknown command
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            Some(SmtpCommand::Unknown {
                command: parts[0].to_string(),
                args: parts.get(1).unwrap_or(&"").to_string(),
            })
        };

        if let Some(ref c) = cmd {
            self.last_command = Some(c.clone());
        }

        cmd
    }

    /// Parse AUTH command
    fn parse_auth_command(&mut self, args: &str) -> Option<SmtpCommand> {
        let parts: Vec<&str> = args.splitn(2, ' ').collect();
        let mechanism_str = parts[0].to_uppercase();

        let mechanism = match mechanism_str.as_str() {
            "PLAIN" => SmtpAuthMechanism::Plain,
            "LOGIN" => SmtpAuthMechanism::Login,
            "CRAM-MD5" => SmtpAuthMechanism::CramMd5,
            "DIGEST-MD5" => SmtpAuthMechanism::DigestMd5,
            "NTLM" => SmtpAuthMechanism::Ntlm,
            "GSSAPI" => SmtpAuthMechanism::GssApi,
            "XOAUTH2" => SmtpAuthMechanism::XOAuth2,
            other => SmtpAuthMechanism::Unknown(other.to_string()),
        };

        self.auth_mechanism = Some(mechanism.clone());
        self.state = SmtpParserState::Authenticating;

        let initial_response = parts.get(1).map(|s| s.to_string());

        // Try to extract username from PLAIN auth initial response
        if mechanism == SmtpAuthMechanism::Plain {
            if let Some(ref resp) = initial_response {
                self.auth_username = self.decode_plain_username(resp);
            }
        }

        Some(SmtpCommand::Auth { mechanism, initial_response })
    }

    /// Decode username from PLAIN auth (base64 of \0username\0password)
    fn decode_plain_username(&self, b64: &str) -> Option<String> {
        let decoded = base64_decode(b64.trim())?;
        // Format: \0username\0password
        let parts: Vec<&[u8]> = decoded.splitn(3, |&b| b == 0).collect();
        if parts.len() >= 2 {
            std::str::from_utf8(parts[1]).ok().map(|s| s.to_string())
        } else {
            None
        }
    }

    /// Parse MAIL FROM command
    fn parse_mail_from(&mut self, args: &str) -> Option<SmtpCommand> {
        let (address, params) = self.parse_address_and_params(args)?;

        // Start new transaction
        let mut builder = TransactionBuilder::default();
        builder.mail_from = address.clone();
        builder.mail_from_params = params.clone();
        self.current_transaction = Some(builder);
        self.state = SmtpParserState::InTransaction;

        Some(SmtpCommand::MailFrom { address, parameters: params })
    }

    /// Parse RCPT TO command
    fn parse_rcpt_to(&mut self, args: &str) -> Option<SmtpCommand> {
        let (address, params) = self.parse_address_and_params(args)?;

        // Add recipient to current transaction
        if let Some(ref mut builder) = self.current_transaction {
            builder.rcpt_to.push(address.clone());
        }
        self.state = SmtpParserState::HasRecipients;

        Some(SmtpCommand::RcptTo { address, parameters: params })
    }

    /// Parse address and optional parameters from MAIL FROM/RCPT TO
    fn parse_address_and_params(&self, args: &str) -> Option<(String, HashMap<String, String>)> {
        let args = args.trim();

        // Find address in angle brackets or without
        let (address, rest): (String, &str) = if args.starts_with('<') {
            if let Some(end) = args.find('>') {
                (args[1..end].to_string(), args[end + 1..].trim())
            } else {
                (args[1..].to_string(), "")
            }
        } else {
            // Address might be space-delimited
            let parts: Vec<&str> = args.splitn(2, ' ').collect();
            (parts[0].to_string(), parts.get(1).copied().unwrap_or(""))
        };

        // Parse parameters
        let mut params = HashMap::new();
        for param in rest.split_whitespace() {
            if let Some((key, value)) = param.split_once('=') {
                params.insert(key.to_uppercase(), value.to_string());
            }
        }

        Some((address, params))
    }

    /// Handle DATA content
    fn handle_data_content(&mut self, payload: &[u8]) -> Option<SmtpCommand> {
        // Check for end of data marker (. on line by itself)
        if payload == b".\r\n" || payload == b".\n" {
            // Parse the accumulated data
            self.parse_message_data();
            self.state = SmtpParserState::Greeted;
            return None;
        }

        // Accumulate data
        self.data_buffer.extend_from_slice(payload);
        None
    }

    /// Parse accumulated message data
    fn parse_message_data(&mut self) {
        let data = std::mem::take(&mut self.data_buffer);

        // Parse content first (before borrowing current_transaction mutably)
        let (headers, attachments) = if let Ok(content) = std::str::from_utf8(&data) {
            (self.parse_headers(content), self.extract_attachments(content))
        } else {
            (SmtpHeaders::default(), Vec::new())
        };

        if let Some(ref mut builder) = self.current_transaction {
            builder.body_size = data.len();
            builder.headers = headers;
            builder.attachments = attachments;
        }
    }

    /// Parse email headers
    fn parse_headers(&self, content: &str) -> SmtpHeaders {
        let mut headers = SmtpHeaders::default();

        // Split headers from body
        let header_section = if let Some(pos) = content.find("\r\n\r\n") {
            &content[..pos]
        } else if let Some(pos) = content.find("\n\n") {
            &content[..pos]
        } else {
            content
        };

        // Unfold headers (join lines starting with whitespace)
        let unfolded = self.unfold_headers(header_section);

        for line in unfolded.lines() {
            if let Some((name, value)) = line.split_once(':') {
                let name_lower = name.trim().to_lowercase();
                let value = value.trim().to_string();

                // Store in all_headers
                headers.all_headers.insert(name.trim().to_string(), value.clone());

                match name_lower.as_str() {
                    "from" => headers.from = Some(value),
                    "to" => {
                        // Parse comma-separated recipients
                        for addr in value.split(',') {
                            headers.to.push(addr.trim().to_string());
                        }
                    }
                    "cc" => {
                        for addr in value.split(',') {
                            headers.cc.push(addr.trim().to_string());
                        }
                    }
                    "subject" => headers.subject = Some(value),
                    "message-id" => headers.message_id = Some(value),
                    "reply-to" => headers.reply_to = Some(value),
                    "date" => headers.date = Some(value),
                    "received" => headers.received.push(value),
                    "x-mailer" | "user-agent" => headers.mailer = Some(value),
                    "return-path" => headers.return_path = Some(value),
                    "content-type" => headers.content_type = Some(value),
                    "dkim-signature" => headers.has_dkim = true,
                    "authentication-results" => {
                        self.parse_auth_results(&value, &mut headers);
                    }
                    _ => {}
                }
            }
        }

        headers
    }

    /// Unfold header lines (join continuation lines)
    fn unfold_headers(&self, header_section: &str) -> String {
        let mut result = String::new();
        for line in header_section.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Continuation line
                result.push(' ');
                result.push_str(line.trim());
            } else {
                if !result.is_empty() {
                    result.push('\n');
                }
                result.push_str(line);
            }
        }
        result
    }

    /// Parse Authentication-Results header
    fn parse_auth_results(&self, value: &str, headers: &mut SmtpHeaders) {
        let lower = value.to_lowercase();

        // Extract SPF result
        if let Some(spf_start) = lower.find("spf=") {
            let spf_part = &value[spf_start + 4..];
            if let Some(end) = spf_part.find(|c: char| c.is_whitespace() || c == ';') {
                headers.spf_result = Some(spf_part[..end].to_string());
            } else {
                headers.spf_result = Some(spf_part.to_string());
            }
        }

        // Extract DKIM result - set has_dkim flag
        if lower.contains("dkim=pass") {
            headers.has_dkim = true;
        }

        // Extract DMARC result
        if let Some(dmarc_start) = lower.find("dmarc=") {
            let dmarc_part = &value[dmarc_start + 6..];
            if let Some(end) = dmarc_part.find(|c: char| c.is_whitespace() || c == ';') {
                headers.dmarc_result = Some(dmarc_part[..end].to_string());
            } else {
                headers.dmarc_result = Some(dmarc_part.to_string());
            }
        }
    }

    /// Extract attachments from MIME content
    fn extract_attachments(&self, content: &str) -> Vec<SmtpAttachment> {
        let mut attachments = Vec::new();

        // Find Content-Type boundary for multipart
        let boundary = self.find_mime_boundary(content);

        if let Some(boundary) = boundary {
            // Parse multipart message
            let parts: Vec<&str> = content.split(&format!("--{}", boundary)).collect();

            for part in parts.iter().skip(1) {
                if part.starts_with("--") {
                    // End marker
                    continue;
                }

                // Parse part headers
                let (part_headers, _body) = if let Some(pos) = part.find("\r\n\r\n") {
                    (&part[..pos], &part[pos + 4..])
                } else if let Some(pos) = part.find("\n\n") {
                    (&part[..pos], &part[pos + 2..])
                } else {
                    continue;
                };

                // Extract filename and content type
                let mut filename = None;
                let mut content_type = None;
                let mut size = 0;

                for line in part_headers.lines() {
                    let lower = line.to_lowercase();
                    if lower.starts_with("content-type:") {
                        content_type = Some(line[13..].trim().to_string());
                    } else if lower.starts_with("content-disposition:") {
                        // Look for filename
                        if let Some(fname_start) = lower.find("filename=") {
                            let fname_part = &line[fname_start + 9..];
                            filename = self.extract_quoted_value(fname_part);
                        }
                    }
                }

                // Only add if it's an attachment (has filename)
                if let Some(fname) = filename {
                    let extension = fname.rsplit('.').next()
                        .map(|e| e.to_lowercase());
                    let is_dangerous = SmtpAttachment::check_dangerous_extension(&fname);

                    attachments.push(SmtpAttachment {
                        filename: fname,
                        content_type: content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                        size,
                        extension,
                        is_dangerous,
                        hash: None,
                    });
                }
            }
        }

        attachments
    }

    /// Find MIME boundary from Content-Type header
    fn find_mime_boundary(&self, content: &str) -> Option<String> {
        let lower = content.to_lowercase();
        if let Some(ct_start) = lower.find("content-type:") {
            let ct_line_end = lower[ct_start..].find('\n').unwrap_or(lower.len() - ct_start);
            let ct_value = &content[ct_start..ct_start + ct_line_end];

            if let Some(boundary_start) = ct_value.to_lowercase().find("boundary=") {
                let boundary_part = &ct_value[ct_start + boundary_start + 9 - ct_start..];
                return self.extract_quoted_value(boundary_part);
            }
        }
        None
    }

    /// Extract value that might be quoted
    fn extract_quoted_value(&self, s: &str) -> Option<String> {
        let s = s.trim();
        if s.starts_with('"') {
            if let Some(end) = s[1..].find('"') {
                return Some(s[1..end + 1].to_string());
            }
        }
        // Unquoted value ends at semicolon, whitespace, or end
        let end = s.find(|c: char| c == ';' || c.is_whitespace()).unwrap_or(s.len());
        if end > 0 {
            Some(s[..end].to_string())
        } else {
            None
        }
    }

    /// Parse server response
    pub fn parse_response(&mut self, payload: &[u8]) -> Option<SmtpResponse> {
        let line = std::str::from_utf8(payload).ok()?;

        // Response format: code[ -]text
        if line.len() < 3 {
            return None;
        }

        let code: u16 = line[..3].parse().ok()?;
        let is_multiline = line.len() > 3 && line.as_bytes()[3] == b'-';

        let message = if line.len() > 4 {
            line[4..].trim().to_string()
        } else {
            String::new()
        };

        // Extract enhanced status code (e.g., 2.0.0)
        let enhanced_code = if message.len() >= 5 {
            let parts: Vec<&str> = message.splitn(2, ' ').collect();
            if parts[0].chars().filter(|&c| c == '.').count() == 2 {
                Some(parts[0].to_string())
            } else {
                None
            }
        } else {
            None
        };

        // Update state based on response
        self.handle_response_state(code, &message);

        Some(SmtpResponse {
            code,
            enhanced_code,
            message,
            is_multiline,
        })
    }

    /// Update parser state based on response
    fn handle_response_state(&mut self, code: u16, message: &str) {
        match (&self.state, code) {
            (SmtpParserState::Initial, 220) => {
                self.state = SmtpParserState::Connected;
            }
            (SmtpParserState::Connected, 250) => {
                // EHLO/HELO successful
                self.state = SmtpParserState::Greeted;
                // Extract capabilities from 250 response
                self.capabilities.push(message.to_string());
            }
            (SmtpParserState::Authenticating, 235) => {
                // Auth successful
                self.state = SmtpParserState::Authenticated;
            }
            (SmtpParserState::Authenticating, 334) => {
                // Auth continuation required
                // Stay in authenticating state
            }
            (SmtpParserState::Authenticating, code) if code >= 400 => {
                // Auth failed
                self.state = SmtpParserState::Greeted;
            }
            (SmtpParserState::HasRecipients, 354) => {
                // Ready for DATA
                self.state = SmtpParserState::ReceivingData;
            }
            (_, 221) => {
                // Quit acknowledged
                self.state = SmtpParserState::Closed;
            }
            _ => {}
        }
    }

    /// Get current state
    pub fn state(&self) -> &SmtpParserState {
        &self.state
    }

    /// Get server capabilities
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Check if ESMTP is supported
    pub fn is_esmtp(&self) -> bool {
        !self.capabilities.is_empty()
    }

    /// Build SmtpEvent from current transaction
    pub fn build_transaction_event(&mut self) -> Option<SmtpEvent> {
        let builder = self.current_transaction.take()?;
        let recipient_count = builder.rcpt_to.len();
        let has_attachments = !builder.attachments.is_empty();

        let transaction = SmtpTransaction {
            mail_from: builder.mail_from,
            rcpt_to: builder.rcpt_to,
            recipient_count,
            headers: builder.headers,
            message_size: if builder.body_size > 0 { Some(builder.body_size) } else { None },
            has_attachments,
            attachments: builder.attachments,
            timestamp: Some(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)),
            rejected: false,
            rejection_reason: None,
        };

        Some(SmtpEvent::MailTransaction(transaction))
    }

    /// Build auth event
    pub fn build_auth_event(&mut self, success: bool) -> Option<SmtpEvent> {
        let mechanism = self.auth_mechanism.take()?;
        let username = self.auth_username.take();

        Some(SmtpEvent::Auth {
            mechanism,
            username,
            success,
        })
    }

    /// Build connect event
    pub fn build_connect_event(&self, banner: &str, hostname: Option<String>) -> SmtpEvent {
        SmtpEvent::Connect {
            client_hostname: hostname.unwrap_or_default(),
            server_banner: Some(banner.to_string()),
            capabilities: self.capabilities.clone(),
            is_esmtp: self.is_esmtp(),
        }
    }

    /// Build StartTLS event
    pub fn build_starttls_event(success: bool) -> SmtpEvent {
        SmtpEvent::StartTls { success }
    }

    /// Build error event
    pub fn build_error_event(code: u16, message: &str, command: Option<String>) -> SmtpEvent {
        SmtpEvent::Error {
            code,
            message: message.to_string(),
            command,
        }
    }

    /// Reset for new transaction
    pub fn reset_transaction(&mut self) {
        self.current_transaction = None;
        self.data_buffer.clear();
        if self.state != SmtpParserState::Initial && self.state != SmtpParserState::Connected {
            self.state = SmtpParserState::Greeted;
        }
    }
}

/// Simple base64 decoder
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const DECODE_TABLE: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];

    let input = input.trim();
    if input.is_empty() {
        return Some(Vec::new());
    }

    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits_collected = 0;

    for c in input.bytes() {
        if c == b'=' {
            break;
        }

        let value = if c < 128 {
            DECODE_TABLE[c as usize]
        } else {
            -1
        };

        if value < 0 {
            // Skip whitespace
            if c == b' ' || c == b'\n' || c == b'\r' || c == b'\t' {
                continue;
            }
            return None;
        }

        buffer = (buffer << 6) | (value as u32);
        bits_collected += 6;

        if bits_collected >= 8 {
            bits_collected -= 8;
            output.push(((buffer >> bits_collected) & 0xFF) as u8);
        }
    }

    Some(output)
}

/// Common SMTP response codes
pub mod response_codes {
    /// System status
    pub const SYSTEM_STATUS: u16 = 211;
    /// Help message
    pub const HELP: u16 = 214;
    /// Service ready
    pub const SERVICE_READY: u16 = 220;
    /// Service closing
    pub const SERVICE_CLOSING: u16 = 221;
    /// Authentication successful
    pub const AUTH_SUCCESS: u16 = 235;
    /// Requested action okay
    pub const OK: u16 = 250;
    /// User not local, will forward
    pub const WILL_FORWARD: u16 = 251;
    /// Cannot verify user, will attempt delivery
    pub const CANNOT_VERIFY: u16 = 252;
    /// AUTH continuation
    pub const AUTH_CONTINUE: u16 = 334;
    /// Start mail input
    pub const START_MAIL: u16 = 354;
    /// Service not available
    pub const SERVICE_UNAVAILABLE: u16 = 421;
    /// Mailbox unavailable (temporary)
    pub const MAILBOX_UNAVAILABLE_TEMP: u16 = 450;
    /// Local error in processing
    pub const LOCAL_ERROR: u16 = 451;
    /// Insufficient storage
    pub const INSUFFICIENT_STORAGE: u16 = 452;
    /// Server unable to accommodate parameters
    pub const UNABLE_PARAMS: u16 = 455;
    /// Command not recognized
    pub const COMMAND_NOT_RECOGNIZED: u16 = 500;
    /// Syntax error in parameters
    pub const SYNTAX_ERROR: u16 = 501;
    /// Command not implemented
    pub const NOT_IMPLEMENTED: u16 = 502;
    /// Bad sequence of commands
    pub const BAD_SEQUENCE: u16 = 503;
    /// Command parameter not implemented
    pub const PARAM_NOT_IMPLEMENTED: u16 = 504;
    /// Authentication required
    pub const AUTH_REQUIRED: u16 = 530;
    /// Authentication mechanism too weak
    pub const AUTH_TOO_WEAK: u16 = 534;
    /// Authentication credentials invalid
    pub const AUTH_INVALID: u16 = 535;
    /// Encryption required
    pub const ENCRYPTION_REQUIRED: u16 = 538;
    /// Mailbox unavailable (permanent)
    pub const MAILBOX_UNAVAILABLE: u16 = 550;
    /// User not local
    pub const USER_NOT_LOCAL: u16 = 551;
    /// Exceeded storage allocation
    pub const EXCEEDED_STORAGE: u16 = 552;
    /// Mailbox name not allowed
    pub const MAILBOX_NOT_ALLOWED: u16 = 553;
    /// Transaction failed
    pub const TRANSACTION_FAILED: u16 = 554;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_smtp() {
        assert!(SmtpParser::is_smtp(b"220 mail.example.com ESMTP\r\n"));
        assert!(SmtpParser::is_smtp(b"EHLO client.example.com\r\n"));
        assert!(SmtpParser::is_smtp(b"MAIL FROM:<sender@example.com>\r\n"));
        assert!(SmtpParser::is_smtp(b"250 OK\r\n"));
        assert!(!SmtpParser::is_smtp(b"GET / HTTP/1.1\r\n"));
        assert!(!SmtpParser::is_smtp(b"SSH-2.0-OpenSSH"));
    }

    #[test]
    fn test_parse_ehlo() {
        let mut parser = SmtpParser::new(true);
        let cmd = parser.parse_command(b"EHLO client.example.com\r\n");
        assert!(matches!(cmd, Some(SmtpCommand::Ehlo(h)) if h == "client.example.com"));
    }

    #[test]
    fn test_parse_mail_from() {
        let mut parser = SmtpParser::new(true);
        let cmd = parser.parse_command(b"MAIL FROM:<sender@example.com>\r\n");
        assert!(matches!(cmd, Some(SmtpCommand::MailFrom { address, .. }) if address == "sender@example.com"));
    }

    #[test]
    fn test_parse_mail_from_with_params() {
        let mut parser = SmtpParser::new(true);
        let cmd = parser.parse_command(b"MAIL FROM:<sender@example.com> SIZE=1024 BODY=8BITMIME\r\n");
        if let Some(SmtpCommand::MailFrom { address, parameters }) = cmd {
            assert_eq!(address, "sender@example.com");
            assert_eq!(parameters.get("SIZE"), Some(&"1024".to_string()));
            assert_eq!(parameters.get("BODY"), Some(&"8BITMIME".to_string()));
        } else {
            panic!("Expected MailFrom command");
        }
    }

    #[test]
    fn test_parse_rcpt_to() {
        let mut parser = SmtpParser::new(true);
        // First need MAIL FROM
        parser.parse_command(b"MAIL FROM:<sender@example.com>\r\n");
        let cmd = parser.parse_command(b"RCPT TO:<recipient@example.com>\r\n");
        assert!(matches!(cmd, Some(SmtpCommand::RcptTo { address, .. }) if address == "recipient@example.com"));
    }

    #[test]
    fn test_parse_auth() {
        let mut parser = SmtpParser::new(true);
        let cmd = parser.parse_command(b"AUTH PLAIN dGVzdAB0ZXN0AHRlc3Q=\r\n");
        if let Some(SmtpCommand::Auth { mechanism, initial_response }) = cmd {
            assert_eq!(mechanism, SmtpAuthMechanism::Plain);
            assert!(initial_response.is_some());
        } else {
            panic!("Expected Auth command");
        }
    }

    #[test]
    fn test_parse_response() {
        let mut parser = SmtpParser::new(false);

        let resp = parser.parse_response(b"250 OK\r\n");
        assert!(resp.is_some());
        let resp = resp.unwrap();
        assert_eq!(resp.code, 250);
        assert!(resp.is_success());
        assert!(!resp.is_multiline);

        let resp = parser.parse_response(b"250-SIZE 10485760\r\n");
        assert!(resp.is_some());
        let resp = resp.unwrap();
        assert!(resp.is_multiline);

        let resp = parser.parse_response(b"535 5.7.8 Authentication failed\r\n");
        assert!(resp.is_some());
        let resp = resp.unwrap();
        assert_eq!(resp.code, 535);
        assert!(resp.is_permanent_failure());
        assert_eq!(resp.enhanced_code, Some("5.7.8".to_string()));
    }

    #[test]
    fn test_parse_headers() {
        let parser = SmtpParser::new(true);
        let content = "From: sender@example.com\r\n\
                      To: recipient@example.com\r\n\
                      Subject: Test Subject\r\n\
                      Message-ID: <123@example.com>\r\n\
                      X-Mailer: TestMailer 1.0\r\n\
                      \r\n\
                      Body content here";

        let headers = parser.parse_headers(content);
        assert_eq!(headers.from, Some("sender@example.com".to_string()));
        assert_eq!(headers.to, vec!["recipient@example.com".to_string()]);
        assert_eq!(headers.subject, Some("Test Subject".to_string()));
        assert_eq!(headers.message_id, Some("<123@example.com>".to_string()));
        assert_eq!(headers.mailer, Some("TestMailer 1.0".to_string()));
    }

    #[test]
    fn test_state_transitions() {
        let mut parser = SmtpParser::new(true);
        assert_eq!(*parser.state(), SmtpParserState::Initial);

        parser.parse_response(b"220 mail.example.com ESMTP\r\n");
        assert_eq!(*parser.state(), SmtpParserState::Connected);

        parser.parse_command(b"EHLO client.example.com\r\n");
        parser.parse_response(b"250 OK\r\n");
        assert_eq!(*parser.state(), SmtpParserState::Greeted);
    }
}
