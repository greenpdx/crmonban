//! Signature payload provider
//!
//! Parses NIDS rules and extracts content patterns to generate
//! packets that will trigger signature matches.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use regex::Regex;

/// Extracted rule info for packet generation
#[derive(Debug, Clone)]
pub struct RuleInfo {
    pub sid: u32,
    pub msg: String,
    pub protocol: String,
    pub dst_port: Option<u16>,
    pub contents: Vec<Vec<u8>>,
    pub is_established: bool,
    pub category: String,
}

/// Category of attack for mapping rules to attack types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttackCategory {
    SqlInjection,
    Xss,
    CommandInjection,
    PathTraversal,
    BruteForce,
    Malware,
    Exploit,
    Scan,
    Dos,
    Dns,
    Web,
    Other,
}

impl AttackCategory {
    pub fn from_rule(msg: &str, dst_port: Option<u16>) -> Self {
        let msg_lower = msg.to_lowercase();

        if msg_lower.contains("sql injection") || msg_lower.contains("sqli") {
            AttackCategory::SqlInjection
        } else if msg_lower.contains("xss") || msg_lower.contains("cross-site") {
            AttackCategory::Xss
        } else if msg_lower.contains("command injection") || msg_lower.contains("rce") || msg_lower.contains("code execution") {
            AttackCategory::CommandInjection
        } else if msg_lower.contains("directory traversal") || msg_lower.contains("path traversal") || msg_lower.contains("..") {
            AttackCategory::PathTraversal
        } else if msg_lower.contains("brute") || msg_lower.contains("login attempt") || msg_lower.contains("authentication") {
            AttackCategory::BruteForce
        } else if msg_lower.contains("malware") || msg_lower.contains("trojan") || msg_lower.contains("backdoor") {
            AttackCategory::Malware
        } else if msg_lower.contains("exploit") || msg_lower.contains("overflow") || msg_lower.contains("shellcode") {
            AttackCategory::Exploit
        } else if msg_lower.contains("scan") || msg_lower.contains("probe") || msg_lower.contains("reconnaissance") {
            AttackCategory::Scan
        } else if msg_lower.contains("dos") || msg_lower.contains("flood") || msg_lower.contains("denial") {
            AttackCategory::Dos
        } else if msg_lower.contains("dns") || dst_port == Some(53) {
            AttackCategory::Dns
        } else if dst_port == Some(80) || dst_port == Some(443) || dst_port == Some(8080) {
            AttackCategory::Web
        } else {
            AttackCategory::Other
        }
    }
}

/// Signature payload provider that loads content patterns from NIDS rules
pub struct SignatureProvider {
    rules: Vec<RuleInfo>,
    by_category: HashMap<AttackCategory, Vec<usize>>,
    by_port: HashMap<u16, Vec<usize>>,
}

impl SignatureProvider {
    /// Create a new provider by parsing rules from a directory
    pub fn from_rules_dir(dir: &str, max_rules: usize) -> anyhow::Result<Self> {
        let rules = parse_rules_dir(dir, max_rules, true)?;
        let mut by_category: HashMap<AttackCategory, Vec<usize>> = HashMap::new();
        let mut by_port: HashMap<u16, Vec<usize>> = HashMap::new();

        for (idx, rule) in rules.iter().enumerate() {
            let category = AttackCategory::from_rule(&rule.msg, rule.dst_port);
            by_category.entry(category).or_default().push(idx);

            if let Some(port) = rule.dst_port {
                by_port.entry(port).or_default().push(idx);
            }
        }

        Ok(Self {
            rules,
            by_category,
            by_port,
        })
    }

    /// Get the number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get a random payload for a specific attack category
    pub fn get_payload_for_category(&self, category: AttackCategory, rng: &mut impl rand::Rng) -> Option<Vec<u8>> {
        let indices = self.by_category.get(&category)?;
        if indices.is_empty() {
            return None;
        }

        let idx = indices[rng.gen_range(0..indices.len())];
        let rule = &self.rules[idx];

        // Combine all content patterns
        let mut payload = Vec::new();
        for content in &rule.contents {
            payload.extend_from_slice(content);
            if !payload.is_empty() {
                payload.push(b' ');
            }
        }

        if payload.is_empty() {
            None
        } else {
            Some(payload)
        }
    }

    /// Get a random payload for a specific port
    pub fn get_payload_for_port(&self, port: u16, rng: &mut impl rand::Rng) -> Option<Vec<u8>> {
        let indices = self.by_port.get(&port)?;
        if indices.is_empty() {
            return None;
        }

        let idx = indices[rng.gen_range(0..indices.len())];
        let rule = &self.rules[idx];

        let mut payload = Vec::new();
        for content in &rule.contents {
            payload.extend_from_slice(content);
            if !payload.is_empty() {
                payload.push(b' ');
            }
        }

        if payload.is_empty() {
            None
        } else {
            Some(payload)
        }
    }

    /// Get all rules for a category (for iteration)
    pub fn get_rules_for_category(&self, category: AttackCategory) -> Vec<&RuleInfo> {
        self.by_category
            .get(&category)
            .map(|indices| indices.iter().map(|&i| &self.rules[i]).collect())
            .unwrap_or_default()
    }

    /// Get a random rule for any category
    pub fn get_random_rule(&self, rng: &mut impl rand::Rng) -> Option<&RuleInfo> {
        if self.rules.is_empty() {
            return None;
        }
        Some(&self.rules[rng.gen_range(0..self.rules.len())])
    }

    /// Build payload from a specific rule
    pub fn build_payload(&self, rule: &RuleInfo) -> Vec<u8> {
        let mut payload = Vec::new();
        for content in &rule.contents {
            payload.extend_from_slice(content);
            if !payload.is_empty() {
                payload.push(b' ');
            }
        }
        payload
    }
}

/// Parse rules directory and extract content patterns
fn parse_rules_dir(dir: &str, max_rules: usize, include_established: bool) -> anyhow::Result<Vec<RuleInfo>> {
    let mut rules = Vec::new();
    let path = Path::new(dir);

    if !path.exists() {
        anyhow::bail!("Rules directory not found: {}", dir);
    }

    // Regex patterns for parsing rules
    let sid_re = Regex::new(r"sid:(\d+)")?;
    let msg_re = Regex::new(r#"msg:"([^"]+)""#)?;
    let content_re = Regex::new(r#"content:"([^"]+)""#)?;
    let content_hex_re = Regex::new(r#"content:\|([^|]+)\|"#)?;
    let flow_re = Regex::new(r"flow:([^;]+)")?;
    let header_re = Regex::new(r"^alert\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\(")?;

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_path = entry.path();
        let category = file_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        if file_path.extension().map(|e| e == "rules").unwrap_or(false) {
            let content = fs::read_to_string(&file_path)?;

            for line in content.lines() {
                if rules.len() >= max_rules {
                    break;
                }

                let line = line.trim();
                if !line.starts_with("alert ") {
                    continue;
                }

                // Parse the header
                let header_caps = match header_re.captures(line) {
                    Some(caps) => caps,
                    None => continue,
                };

                let protocol = header_caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let protocol = match protocol {
                    "tcp" | "http" => "tcp",
                    "udp" => "udp",
                    _ => continue,
                };

                let dst_port_str = header_caps.get(5).map(|m| m.as_str()).unwrap_or("any");
                let dst_port: Option<u16> = dst_port_str.parse().ok();

                if dst_port.is_none() {
                    continue;
                }

                let sid = match sid_re.captures(line) {
                    Some(caps) => caps.get(1).unwrap().as_str().parse().unwrap_or(0),
                    None => continue,
                };

                let msg = msg_re
                    .captures(line)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                // Extract content patterns
                let mut contents = Vec::new();

                for caps in content_re.captures_iter(line) {
                    if let Some(m) = caps.get(1) {
                        let bytes = unescape_content(m.as_str());
                        if bytes.len() >= 4 {
                            contents.push(bytes);
                        }
                    }
                }

                for caps in content_hex_re.captures_iter(line) {
                    if let Some(m) = caps.get(1) {
                        if let Some(bytes) = parse_hex_content(m.as_str()) {
                            if bytes.len() >= 4 {
                                contents.push(bytes);
                            }
                        }
                    }
                }

                if contents.is_empty() {
                    continue;
                }

                let is_established = flow_re
                    .captures(line)
                    .map(|c| c.get(1).unwrap().as_str().contains("established"))
                    .unwrap_or(false);

                // Skip established rules unless explicitly included
                if is_established && !include_established {
                    continue;
                }

                rules.push(RuleInfo {
                    sid,
                    msg,
                    protocol: protocol.to_string(),
                    dst_port,
                    contents,
                    is_established,
                    category: category.clone(),
                });
            }
        }

        if rules.len() >= max_rules {
            break;
        }
    }

    Ok(rules)
}

/// Unescape content string
fn unescape_content(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('r') => result.push(b'\r'),
                Some('n') => result.push(b'\n'),
                Some('t') => result.push(b'\t'),
                Some('\\') => result.push(b'\\'),
                Some('"') => result.push(b'"'),
                Some('x') => {
                    let mut hex = String::new();
                    if let Some(&c1) = chars.peek() {
                        if c1.is_ascii_hexdigit() {
                            hex.push(chars.next().unwrap());
                            if let Some(&c2) = chars.peek() {
                                if c2.is_ascii_hexdigit() {
                                    hex.push(chars.next().unwrap());
                                }
                            }
                        }
                    }
                    if let Ok(b) = u8::from_str_radix(&hex, 16) {
                        result.push(b);
                    }
                }
                Some(c) => result.push(c as u8),
                None => {}
            }
        } else {
            result.push(c as u8);
        }
    }

    result
}

/// Parse hex content like "00 01 02 03"
fn parse_hex_content(s: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();

    for part in s.split_whitespace() {
        if let Ok(b) = u8::from_str_radix(part, 16) {
            result.push(b);
        } else {
            return None;
        }
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unescape_content() {
        assert_eq!(unescape_content("hello"), b"hello".to_vec());
        assert_eq!(unescape_content("hello\\r\\n"), b"hello\r\n".to_vec());
        assert_eq!(unescape_content("\\x00\\x01"), vec![0x00, 0x01]);
    }

    #[test]
    fn test_parse_hex_content() {
        assert_eq!(parse_hex_content("00 01 02"), Some(vec![0, 1, 2]));
        assert_eq!(parse_hex_content("FF"), Some(vec![255]));
        assert_eq!(parse_hex_content("GG"), None);
    }

    #[test]
    fn test_attack_category() {
        assert_eq!(
            AttackCategory::from_rule("SQL Injection attempt", Some(80)),
            AttackCategory::SqlInjection
        );
        assert_eq!(
            AttackCategory::from_rule("XSS in parameter", Some(80)),
            AttackCategory::Xss
        );
        assert_eq!(
            AttackCategory::from_rule("DNS query", Some(53)),
            AttackCategory::Dns
        );
    }
}
