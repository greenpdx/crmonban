//! Data Privacy and Sanitization
//!
//! Sanitizes sensitive data before sending to cloud LLM providers.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::RwLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::config::PrivacyConfig;

/// Data sanitizer for LLM prompts
pub struct DataSanitizer {
    config: PrivacyConfig,
    /// Compiled regex patterns
    patterns: SanitizationPatterns,
    /// IP address mapping for consistent replacement
    ip_map: RwLock<IpMapping>,
    /// Hostname mapping
    hostname_map: RwLock<HostnameMapping>,
}

/// Compiled regex patterns for sanitization
struct SanitizationPatterns {
    /// IPv4 address pattern
    ipv4: Regex,
    /// IPv6 address pattern
    ipv6: Regex,
    /// MAC address pattern
    mac: Regex,
    /// Email address pattern
    email: Regex,
    /// Hostname/FQDN pattern
    hostname: Regex,
    /// API key/token pattern
    api_key: Regex,
    /// Password pattern in URLs
    password_url: Regex,
    /// Bearer token pattern
    bearer_token: Regex,
    /// AWS access key pattern
    aws_key: Regex,
    /// Private key pattern
    private_key: Regex,
}

impl SanitizationPatterns {
    fn new() -> Self {
        Self {
            ipv4: Regex::new(r"\b(\d{1,3}\.){3}\d{1,3}\b").unwrap(),
            ipv6: Regex::new(r"\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b([0-9a-fA-F]{1,4}:){1,7}:\b|\b:([0-9a-fA-F]{1,4}:){1,7}\b").unwrap(),
            mac: Regex::new(r"\b([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b").unwrap(),
            email: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(),
            hostname: Regex::new(r"\b[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+\b").unwrap(),
            api_key: Regex::new(r#"(?i)(api[_-]?key|apikey|api_secret|secret_key|access_token)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?"#).unwrap(),
            password_url: Regex::new(r"://([^:]+):([^@]+)@").unwrap(),
            bearer_token: Regex::new(r"(?i)bearer\s+[a-zA-Z0-9._-]+").unwrap(),
            aws_key: Regex::new(r"(?i)(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}").unwrap(),
            private_key: Regex::new(r"-----BEGIN[A-Z ]*PRIVATE KEY-----").unwrap(),
        }
    }
}

/// IP address mapping for consistent anonymization
struct IpMapping {
    /// Internal IP to anonymized mapping
    mapping: std::collections::HashMap<String, String>,
    /// Counter for generating anonymous IPs
    counter: u32,
}

impl IpMapping {
    fn new() -> Self {
        Self {
            mapping: std::collections::HashMap::new(),
            counter: 1,
        }
    }

    fn get_or_create(&mut self, ip: &str, is_internal: bool) -> String {
        if let Some(mapped) = self.mapping.get(ip) {
            return mapped.clone();
        }

        let mapped = if is_internal {
            format!("INTERNAL-HOST-{}", self.counter)
        } else {
            format!("EXTERNAL-HOST-{}", self.counter)
        };
        self.counter += 1;
        self.mapping.insert(ip.to_string(), mapped.clone());
        mapped
    }
}

/// Hostname mapping for consistent anonymization
struct HostnameMapping {
    mapping: std::collections::HashMap<String, String>,
    counter: u32,
}

impl HostnameMapping {
    fn new() -> Self {
        Self {
            mapping: std::collections::HashMap::new(),
            counter: 1,
        }
    }

    fn get_or_create(&mut self, hostname: &str) -> String {
        if let Some(mapped) = self.mapping.get(hostname) {
            return mapped.clone();
        }

        let mapped = format!("server-{}.example.com", self.counter);
        self.counter += 1;
        self.mapping.insert(hostname.to_string(), mapped.clone());
        mapped
    }
}

/// Sanitization result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationResult {
    /// Sanitized text
    pub text: String,
    /// Number of IPs sanitized
    pub ips_sanitized: usize,
    /// Number of hostnames sanitized
    pub hostnames_sanitized: usize,
    /// Number of credentials sanitized
    pub credentials_sanitized: usize,
    /// Number of emails sanitized
    pub emails_sanitized: usize,
    /// Warnings about potential data leakage
    pub warnings: Vec<String>,
}

impl DataSanitizer {
    /// Create a new data sanitizer
    pub fn new(config: PrivacyConfig) -> Self {
        Self {
            config,
            patterns: SanitizationPatterns::new(),
            ip_map: RwLock::new(IpMapping::new()),
            hostname_map: RwLock::new(HostnameMapping::new()),
        }
    }

    /// Sanitize text for cloud LLM
    pub fn sanitize(&self, text: &str) -> SanitizationResult {
        let mut result = text.to_string();
        let mut ips_sanitized = 0;
        let mut hostnames_sanitized = 0;
        let mut credentials_sanitized = 0;
        let mut emails_sanitized = 0;
        let mut warnings = Vec::new();

        // Always sanitize credentials regardless of config
        let (sanitized, count) = self.sanitize_credentials(&result);
        result = sanitized;
        credentials_sanitized = count;

        // Sanitize based on config
        if self.config.sanitize_internal_ips {
            let (sanitized, count) = self.sanitize_ips(&result);
            result = sanitized;
            ips_sanitized = count;
        }

        if self.config.sanitize_hostnames {
            let (sanitized, count) = self.sanitize_hostnames(&result);
            result = sanitized;
            hostnames_sanitized = count;
        }

        // Sanitize emails using the email regex pattern (part of credentials)
        // Note: emails are sanitized as part of redact_patterns in config

        // Check for potential data leakage
        if self.patterns.private_key.is_match(&result) {
            warnings.push("Potential private key detected in text".to_string());
        }

        if self.patterns.aws_key.is_match(&result) {
            warnings.push("Potential AWS access key detected".to_string());
        }

        // Check for custom redact patterns from config
        for pattern in &self.config.redact_patterns {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(&result) {
                    result = re.replace_all(&result, "[REDACTED]").to_string();
                }
            }
        }

        SanitizationResult {
            text: result,
            ips_sanitized,
            hostnames_sanitized,
            credentials_sanitized,
            emails_sanitized,
            warnings,
        }
    }

    /// Sanitize IP addresses
    fn sanitize_ips(&self, text: &str) -> (String, usize) {
        let mut result = text.to_string();
        let mut count = 0;

        // Find all IPv4 addresses
        let ipv4_matches: Vec<String> = self.patterns.ipv4
            .find_iter(text)
            .map(|m| m.as_str().to_string())
            .collect();

        for ip_str in ipv4_matches {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let is_internal = self.is_internal_ip(&ip);

                // Only sanitize internal IPs if configured, always sanitize if local_only
                if is_internal || self.config.local_only {
                    if let Ok(mut map) = self.ip_map.write() {
                        let replacement = map.get_or_create(&ip_str, is_internal);
                        result = result.replace(&ip_str, &replacement);
                        count += 1;
                    }
                }
            }
        }

        // Find all IPv6 addresses (always sanitize for privacy)
        let ipv6_matches: Vec<String> = self.patterns.ipv6
            .find_iter(&result)
            .map(|m| m.as_str().to_string())
            .collect();

        for ip_str in ipv6_matches {
            if let Ok(mut map) = self.ip_map.write() {
                let replacement = map.get_or_create(&ip_str, true);
                result = result.replace(&ip_str, &replacement);
                count += 1;
            }
        }

        (result, count)
    }

    /// Check if IP is internal/private
    fn is_internal_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                // RFC 1918 private ranges
                ipv4.is_private() ||
                ipv4.is_loopback() ||
                ipv4.is_link_local() ||
                // Check custom internal ranges
                self.config.internal_ranges.iter().any(|range| {
                    self.ip_in_cidr(&IpAddr::V4(*ipv4), range)
                })
            }
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() ||
                // ULA (Unique Local Address)
                (ipv6.segments()[0] & 0xfe00) == 0xfc00
            }
        }
    }

    /// Check if IP is in CIDR range
    fn ip_in_cidr(&self, ip: &IpAddr, cidr: &str) -> bool {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return false;
        }

        let Ok(network) = parts[0].parse::<IpAddr>() else {
            return false;
        };

        let Ok(prefix_len) = parts[1].parse::<u8>() else {
            return false;
        };

        match (ip, network) {
            (IpAddr::V4(ip), IpAddr::V4(net)) => {
                let mask = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
                (u32::from(*ip) & mask) == (u32::from(net) & mask)
            }
            (IpAddr::V6(ip), IpAddr::V6(net)) => {
                let mask = if prefix_len == 0 { 0 } else { !0u128 << (128 - prefix_len) };
                (u128::from(*ip) & mask) == (u128::from(net) & mask)
            }
            _ => false,
        }
    }

    /// Sanitize hostnames
    fn sanitize_hostnames(&self, text: &str) -> (String, usize) {
        let mut result = text.to_string();
        let mut count = 0;

        // Whitelist common public domains
        let public_domains: HashSet<&str> = [
            "google.com", "microsoft.com", "amazon.com", "cloudflare.com",
            "github.com", "stackoverflow.com", "example.com", "localhost",
        ].into_iter().collect();

        let hostname_matches: Vec<String> = self.patterns.hostname
            .find_iter(text)
            .map(|m| m.as_str().to_string())
            .collect();

        for hostname in hostname_matches {
            // Skip public domains
            if public_domains.iter().any(|d| hostname.ends_with(d)) {
                continue;
            }

            // Skip if it looks like a version number or IP
            if hostname.chars().all(|c| c.is_ascii_digit() || c == '.') {
                continue;
            }

            if let Ok(mut map) = self.hostname_map.write() {
                let replacement = map.get_or_create(&hostname);
                result = result.replace(&hostname, &replacement);
                count += 1;
            }
        }

        (result, count)
    }

    /// Sanitize email addresses
    fn sanitize_emails(&self, text: &str) -> (String, usize) {
        let mut count = 0;
        let result = self.patterns.email.replace_all(text, |_caps: &regex::Captures| {
            count += 1;
            "user@example.com"
        }).to_string();

        (result, count)
    }

    /// Sanitize credentials and secrets
    fn sanitize_credentials(&self, text: &str) -> (String, usize) {
        let mut result = text.to_string();
        let mut count = 0;

        // API keys
        if self.patterns.api_key.is_match(&result) {
            result = self.patterns.api_key.replace_all(&result, "$1=[REDACTED]").to_string();
            count += 1;
        }

        // Password in URLs
        if self.patterns.password_url.is_match(&result) {
            result = self.patterns.password_url.replace_all(&result, "://[REDACTED]:[REDACTED]@").to_string();
            count += 1;
        }

        // Bearer tokens
        if self.patterns.bearer_token.is_match(&result) {
            result = self.patterns.bearer_token.replace_all(&result, "Bearer [REDACTED]").to_string();
            count += 1;
        }

        // AWS keys
        if self.patterns.aws_key.is_match(&result) {
            result = self.patterns.aws_key.replace_all(&result, "[AWS_KEY_REDACTED]").to_string();
            count += 1;
        }

        // MAC addresses (can be sensitive)
        if self.patterns.mac.is_match(&result) {
            result = self.patterns.mac.replace_all(&result, "XX:XX:XX:XX:XX:XX").to_string();
            count += 1;
        }

        (result, count)
    }

    /// Reset IP and hostname mappings (for testing)
    pub fn reset_mappings(&self) {
        if let Ok(mut map) = self.ip_map.write() {
            *map = IpMapping::new();
        }
        if let Ok(mut map) = self.hostname_map.write() {
            *map = HostnameMapping::new();
        }
    }

    /// Check if data should be sent to cloud
    pub fn should_use_cloud(&self) -> bool {
        !self.config.local_only
    }

    /// Get sanitization summary
    pub fn get_summary(&self, result: &SanitizationResult) -> String {
        format!(
            "Sanitized: {} IPs, {} hostnames, {} credentials, {} emails",
            result.ips_sanitized,
            result.hostnames_sanitized,
            result.credentials_sanitized,
            result.emails_sanitized
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PrivacyConfig {
        PrivacyConfig {
            local_only: false,
            sanitize_internal_ips: true,
            sanitize_hostnames: true,
            sanitize_usernames: true,
            internal_ranges: vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()],
            redact_patterns: vec![
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b".to_string(),
            ],
        }
    }

    #[test]
    fn test_ip_sanitization() {
        let sanitizer = DataSanitizer::new(test_config());

        let text = "Connection from 192.168.1.100 to 8.8.8.8";
        let result = sanitizer.sanitize(text);

        assert!(result.text.contains("INTERNAL-HOST"));
        assert!(result.text.contains("8.8.8.8")); // Public IP not sanitized
        assert_eq!(result.ips_sanitized, 1);
    }

    #[test]
    fn test_consistent_mapping() {
        let sanitizer = DataSanitizer::new(test_config());

        let text1 = "Host 192.168.1.100 connected";
        let text2 = "Host 192.168.1.100 disconnected";

        let result1 = sanitizer.sanitize(text1);
        let result2 = sanitizer.sanitize(text2);

        // Same IP should get same replacement
        let replacement1: String = result1.text.split_whitespace()
            .find(|s| s.starts_with("INTERNAL"))
            .unwrap_or("")
            .to_string();
        let replacement2: String = result2.text.split_whitespace()
            .find(|s| s.starts_with("INTERNAL"))
            .unwrap_or("")
            .to_string();

        assert_eq!(replacement1, replacement2);
    }

    #[test]
    fn test_credential_sanitization() {
        let sanitizer = DataSanitizer::new(test_config());

        let text = "api_key=sk-abc123xyz789 and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let result = sanitizer.sanitize(text);

        assert!(!result.text.contains("sk-abc123xyz789"));
        assert!(!result.text.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
        assert!(result.text.contains("[REDACTED]"));
    }

    #[test]
    fn test_email_sanitization() {
        let sanitizer = DataSanitizer::new(test_config());

        let text = "User admin@company.internal logged in";
        let result = sanitizer.sanitize(text);

        assert!(!result.text.contains("admin@company.internal"));
        assert!(result.text.contains("user@example.com"));
    }

    #[test]
    fn test_hostname_sanitization() {
        let sanitizer = DataSanitizer::new(test_config());

        let text = "Connection to internal-server.corp.local";
        let result = sanitizer.sanitize(text);

        assert!(!result.text.contains("internal-server.corp.local"));
        assert!(result.text.contains("example.com"));
    }

    #[test]
    fn test_url_password_sanitization() {
        let sanitizer = DataSanitizer::new(test_config());

        let text = "Connected to mysql://root:secretpass@database:3306";
        let result = sanitizer.sanitize(text);

        assert!(!result.text.contains("secretpass"));
        assert!(result.text.contains("[REDACTED]"));
    }
}
