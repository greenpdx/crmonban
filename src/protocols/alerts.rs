//! Protocol alert types and parse results
//!
//! Defines the result types for protocol parsing and alert generation.

use std::collections::HashMap;

use crmonban_types::DetectionType;
use crate::core::Severity;
use super::traits::Transaction;

/// Result of a parse operation
#[derive(Debug)]
pub enum ParseResult {
    /// Transaction completed successfully
    Complete(Transaction),

    /// Need more data to complete parsing
    /// Parser should be called again with more data
    Incomplete,

    /// This is not the expected protocol
    /// Detection should try other protocols
    NotThisProtocol,

    /// Fatal parse error
    /// Generates alert and flow should be closed
    Fatal {
        /// Alert to generate
        alert: ProtocolAlert,
        /// Error details
        error: ParseError,
    },
}

impl ParseResult {
    /// Create a complete result with transaction
    pub fn complete(tx: Transaction) -> Self {
        Self::Complete(tx)
    }

    /// Create an incomplete result (need more data)
    pub fn incomplete() -> Self {
        Self::Incomplete
    }

    /// Create a "not this protocol" result
    pub fn not_this_protocol() -> Self {
        Self::NotThisProtocol
    }

    /// Create a fatal error result
    pub fn fatal(error: ParseError, msg: impl Into<String>) -> Self {
        Self::Fatal {
            alert: ProtocolAlert::from_error(&error, msg),
            error,
        }
    }

    /// Check if result is complete
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete(_))
    }

    /// Check if result indicates need for more data
    pub fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete)
    }

    /// Check if this is a fatal error
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Fatal { .. })
    }
}

/// Protocol-generated alert
#[derive(Debug, Clone)]
pub struct ProtocolAlert {
    /// Signature ID (0 for protocol-generated alerts)
    pub sid: u32,

    /// Alert message
    pub msg: String,

    /// Detection type for correlation
    pub detection_type: DetectionType,

    /// Severity level
    pub severity: Severity,

    /// Rule classification (if from rule)
    pub classtype: Option<String>,

    /// Additional metadata
    pub metadata: HashMap<String, String>,

    /// Match information (buffer, offset, length)
    pub match_info: Option<MatchInfo>,
}

impl ProtocolAlert {
    /// Create new alert
    pub fn new(
        msg: impl Into<String>,
        detection_type: DetectionType,
        severity: Severity,
    ) -> Self {
        Self {
            sid: 0,
            msg: msg.into(),
            detection_type,
            severity,
            classtype: None,
            metadata: HashMap::new(),
            match_info: None,
        }
    }

    /// Create alert from rule match
    pub fn from_rule(
        sid: u32,
        msg: impl Into<String>,
        detection_type: DetectionType,
        severity: Severity,
        classtype: Option<String>,
    ) -> Self {
        Self {
            sid,
            msg: msg.into(),
            detection_type,
            severity,
            classtype,
            metadata: HashMap::new(),
            match_info: None,
        }
    }

    /// Create alert from parse error
    pub fn from_error(error: &ParseError, msg: impl Into<String>) -> Self {
        let detection_type = match error {
            ParseError::BufferOverflow { .. } => DetectionType::Overflow,
            ParseError::ProtocolViolation(_) => DetectionType::ProtocolAnomaly,
            _ => DetectionType::ProtocolAnomaly,
        };

        Self {
            sid: 0,
            msg: msg.into(),
            detection_type,
            severity: Severity::High,
            classtype: Some("protocol-command-decode".to_string()),
            metadata: HashMap::from([
                ("error_type".to_string(), error.type_name().to_string()),
                ("error_detail".to_string(), error.to_string()),
            ]),
            match_info: None,
        }
    }

    /// Set signature ID
    pub fn with_sid(mut self, sid: u32) -> Self {
        self.sid = sid;
        self
    }

    /// Set classtype
    pub fn with_classtype(mut self, classtype: impl Into<String>) -> Self {
        self.classtype = Some(classtype.into());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Set match info
    pub fn with_match_info(mut self, info: MatchInfo) -> Self {
        self.match_info = Some(info);
        self
    }
}

/// Match information for alerts
#[derive(Debug, Clone)]
pub struct MatchInfo {
    /// Buffer name where match occurred (e.g., "smb.share")
    pub buffer: &'static str,

    /// Offset in buffer where match started
    pub offset: usize,

    /// Length of matched content
    pub length: usize,

    /// Matched content (truncated if large)
    pub matched: Vec<u8>,
}

impl MatchInfo {
    /// Create new match info
    pub fn new(buffer: &'static str, offset: usize, length: usize, matched: Vec<u8>) -> Self {
        // Truncate matched content if too large
        let matched = if matched.len() > 256 {
            matched[..256].to_vec()
        } else {
            matched
        };

        Self {
            buffer,
            offset,
            length,
            matched,
        }
    }

    /// Create from buffer slice
    pub fn from_slice(buffer: &'static str, offset: usize, data: &[u8]) -> Self {
        Self::new(buffer, offset, data.len(), data.to_vec())
    }
}

/// Parse error types
#[derive(Debug, Clone)]
pub enum ParseError {
    /// Invalid protocol data format
    InvalidData(String),

    /// Unexpected message type
    UnexpectedMessage {
        expected: String,
        got: String,
    },

    /// Protocol specification violation
    ProtocolViolation(String),

    /// Buffer overflow attempt detected
    BufferOverflow {
        max: usize,
        attempted: usize,
    },

    /// Incomplete data (normally not fatal, but can be in some contexts)
    Incomplete,

    /// Internal parser error
    Internal(String),

    /// Unsupported protocol version
    UnsupportedVersion(String),

    /// Authentication error
    AuthError(String),

    /// Encoding error (e.g., invalid UTF-8)
    EncodingError(String),
}

impl ParseError {
    /// Get error type name
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::InvalidData(_) => "invalid_data",
            Self::UnexpectedMessage { .. } => "unexpected_message",
            Self::ProtocolViolation(_) => "protocol_violation",
            Self::BufferOverflow { .. } => "buffer_overflow",
            Self::Incomplete => "incomplete",
            Self::Internal(_) => "internal",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::AuthError(_) => "auth_error",
            Self::EncodingError(_) => "encoding_error",
        }
    }

    /// Check if this is a security-relevant error
    pub fn is_security_relevant(&self) -> bool {
        matches!(
            self,
            Self::BufferOverflow { .. }
                | Self::ProtocolViolation(_)
        )
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidData(msg) => write!(f, "Invalid data: {}", msg),
            Self::UnexpectedMessage { expected, got } => {
                write!(f, "Unexpected message: expected {}, got {}", expected, got)
            }
            Self::ProtocolViolation(msg) => write!(f, "Protocol violation: {}", msg),
            Self::BufferOverflow { max, attempted } => {
                write!(f, "Buffer overflow: max {} bytes, attempted {}", max, attempted)
            }
            Self::Incomplete => write!(f, "Incomplete data"),
            Self::Internal(msg) => write!(f, "Internal error: {}", msg),
            Self::UnsupportedVersion(ver) => write!(f, "Unsupported version: {}", ver),
            Self::AuthError(msg) => write!(f, "Authentication error: {}", msg),
            Self::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

/// Convert priority to severity
pub fn priority_to_severity(priority: u8) -> Severity {
    match priority {
        1 => Severity::Critical,
        2 => Severity::High,
        3 => Severity::Medium,
        _ => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_result() {
        let tx = Transaction::new(1, "test");
        let result = ParseResult::complete(tx);
        assert!(result.is_complete());

        let result = ParseResult::incomplete();
        assert!(result.is_incomplete());

        let result = ParseResult::fatal(
            ParseError::InvalidData("test".to_string()),
            "Test error"
        );
        assert!(result.is_fatal());
    }

    #[test]
    fn test_protocol_alert() {
        let alert = ProtocolAlert::new(
            "Test alert",
            DetectionType::ProtocolAnomaly,
            Severity::Medium,
        )
        .with_metadata("key", "value")
        .with_classtype("test-class");

        assert_eq!(alert.msg, "Test alert");
        assert_eq!(alert.metadata.get("key"), Some(&"value".to_string()));
        assert_eq!(alert.classtype, Some("test-class".to_string()));
    }

    #[test]
    fn test_match_info_truncation() {
        let large_data: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        let info = MatchInfo::new("test", 0, large_data.len(), large_data);

        // Should be truncated to 256 bytes
        assert_eq!(info.matched.len(), 256);
    }

    #[test]
    fn test_parse_error_display() {
        let err = ParseError::BufferOverflow { max: 100, attempted: 500 };
        assert!(err.to_string().contains("100"));
        assert!(err.to_string().contains("500"));
        assert!(err.is_security_relevant());
    }
}
