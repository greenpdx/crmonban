// CR Monban - Optimized Detection Rules Engine
// Detection rules for web application attack patterns
// Uses Aho-Corasick for O(n) multi-pattern matching

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::Regex;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::fs;

// Re-export types from crmonban-types
pub use crate::types::Severity;
pub use crate::types::DetectionAction as Action;

/// Extension trait to provide score() method for Severity
pub trait SeverityScore {
    fn score(&self) -> u32;
}

impl SeverityScore for Severity {
    #[inline]
    fn score(&self) -> u32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 5,
            Severity::High => 10,
            Severity::Critical => 20,
        }
    }
}

/// Extension trait to provide priority() method for Action
pub trait ActionPriority {
    fn priority(&self) -> u8;
}

impl ActionPriority for Action {
    #[inline]
    fn priority(&self) -> u8 {
        match self {
            Action::Drop | Action::Reject | Action::Ban => 4,
            Action::RateLimit => 3,
            Action::Alert => 2,
            Action::Log | Action::Allow => 1,
        }
    }
}

/// Pattern category with detection rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternCategory {
    pub severity: Severity,
    pub action: Action,
    pub description: String,
    pub patterns: Vec<String>,
    pub regex: Vec<String>,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub max_requests: u32,
    pub window_seconds: u64,
    pub penalty_seconds: u64,
}

/// Complete attack pattern database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPatternDb {
    pub version: String,
    pub last_updated: String,
    pub patterns: HashMap<String, PatternCategory>,
    pub rate_limits: HashMap<String, RateLimit>,
}

/// Metadata for each pattern (indexed by pattern ID from AC automaton)
struct PatternMetadata {
    category_idx: usize,
    original_pattern: String,
}

/// Category metadata for fast lookup
struct CategoryMetadata {
    name: String,
    severity: Severity,
    action: Action,
    is_critical: bool,
}

/// Compiled regex with category index
struct CompiledRegex {
    regex: Regex,
    category_idx: usize,
}

/// Detection result with details
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub detected: bool,
    pub category: String,
    pub severity: Severity,
    pub action: Action,
    pub matched_pattern: String,
    pub score: u32,
    pub description: String,
}

/// Optimized detection engine using Aho-Corasick
pub struct DetectionEngine {
    /// Single Aho-Corasick automaton for ALL string patterns (pre-lowercased)
    ac_automaton: AhoCorasick,

    /// Metadata indexed by pattern ID from AC automaton
    pattern_metadata: Vec<PatternMetadata>,

    /// Category metadata for fast lookup
    categories: Vec<CategoryMetadata>,

    /// Compiled regex patterns (applied only if needed)
    regex_patterns: Vec<CompiledRegex>,

    /// Scanner user-agent patterns (separate AC for headers)
    scanner_ac: Option<AhoCorasick>,
    scanner_patterns: Vec<String>,
    scanner_category_idx: Option<usize>,

    /// Original database for compatibility
    db: AttackPatternDb,
}

impl DetectionEngine {
    /// Get access to the pattern database
    pub fn get_db(&self) -> &AttackPatternDb {
        &self.db
    }
}

impl DetectionEngine {
    /// Load attack patterns from JSON file
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = fs::read_to_string(path)?;
        let db: AttackPatternDb = serde_json::from_str(&data)?;

        Self::compile_optimized(db)
    }

    /// Compile all patterns into optimized data structures
    fn compile_optimized(db: AttackPatternDb) -> Result<Self, Box<dyn std::error::Error>> {
        let mut all_patterns: Vec<String> = Vec::with_capacity(400);
        let mut pattern_metadata: Vec<PatternMetadata> = Vec::with_capacity(400);
        let mut categories: Vec<CategoryMetadata> = Vec::new();
        let mut regex_patterns: Vec<CompiledRegex> = Vec::with_capacity(60);

        let mut scanner_patterns: Vec<String> = Vec::new();
        let mut scanner_category_idx: Option<usize> = None;

        for (category_name, pattern_cat) in &db.patterns {
            let cat_idx = categories.len();
            let is_critical = pattern_cat.severity == Severity::Critical;

            categories.push(CategoryMetadata {
                name: category_name.clone(),
                severity: pattern_cat.severity,
                action: pattern_cat.action.clone(),
                is_critical,
            });

            // Special handling for scanner user-agents (separate AC automaton)
            if category_name == "scanner_user_agents" {
                scanner_category_idx = Some(cat_idx);
                for pattern in &pattern_cat.patterns {
                    scanner_patterns.push(pattern.to_lowercase());
                }
            }

            // Pre-lowercase ALL string patterns at compile time
            for pattern in &pattern_cat.patterns {
                let lowercased = pattern.to_lowercase();
                all_patterns.push(lowercased);
                pattern_metadata.push(PatternMetadata {
                    category_idx: cat_idx,
                    original_pattern: pattern.clone(),
                });
            }

            // Compile regex patterns with case-insensitive flag
            for regex_str in &pattern_cat.regex {
                let case_insensitive = format!("(?i){}", regex_str);
                match Regex::new(&case_insensitive) {
                    Ok(re) => {
                        regex_patterns.push(CompiledRegex {
                            regex: re,
                            category_idx: cat_idx,
                        });
                    }
                    Err(e) => {
                        eprintln!("Failed to compile regex '{}' in category '{}': {}",
                                 regex_str, category_name, e);
                    }
                }
            }
        }

        // Sort regex patterns: Critical+Block first for early exit
        regex_patterns.sort_by(|a, b| {
            let cat_a = &categories[a.category_idx];
            let cat_b = &categories[b.category_idx];
            let priority_a = (cat_a.is_critical, cat_a.action.priority());
            let priority_b = (cat_b.is_critical, cat_b.action.priority());
            priority_b.cmp(&priority_a)
        });

        // Build Aho-Corasick automaton with leftmost-first matching
        let ac_automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostFirst)
            .build(&all_patterns)?;

        // Build scanner AC automaton if we have scanner patterns
        let scanner_ac = if !scanner_patterns.is_empty() {
            Some(AhoCorasickBuilder::new()
                .match_kind(MatchKind::LeftmostFirst)
                .build(&scanner_patterns)?)
        } else {
            None
        };

        Ok(DetectionEngine {
            ac_automaton,
            pattern_metadata,
            categories,
            regex_patterns,
            scanner_ac,
            scanner_patterns,
            scanner_category_idx,
            db,
        })
    }

    /// Scan a URL path for attack patterns - O(n) with Aho-Corasick
    pub fn scan_url(&self, url: &str) -> Vec<DetectionResult> {
        self.scan_url_with_options(url, false, false).0
    }

    /// Optimized scan with early exit option
    /// Returns (results, should_block)
    fn scan_url_with_options(
        &self,
        url: &str,
        early_exit: bool,
        skip_regex: bool,
    ) -> (Vec<DetectionResult>, bool) {
        // Single lowercase conversion for entire input
        let url_lower = url.to_lowercase();

        // Pre-allocate for typical case (0-4 detections)
        let mut results: SmallVec<[DetectionResult; 4]> = SmallVec::new();
        let mut should_block = false;
        let mut found_critical_block = false;

        // Use Aho-Corasick for O(n) multi-pattern matching
        for mat in self.ac_automaton.find_iter(&url_lower) {
            let pattern_id = mat.pattern().as_usize();
            let metadata = &self.pattern_metadata[pattern_id];
            let category = &self.categories[metadata.category_idx];

            if matches!(category.action, Action::Drop | Action::Reject | Action::Ban) {
                should_block = true;
                if category.is_critical {
                    found_critical_block = true;
                }
            }

            results.push(DetectionResult {
                detected: true,
                category: category.name.clone(),
                severity: category.severity,
                action: category.action.clone(),
                matched_pattern: metadata.original_pattern.clone(),
                score: category.severity.score(),
                description: format!("Pattern '{}' detected in URL", metadata.original_pattern),
            });

            // Early exit: stop scanning if we found a Critical+Block
            if early_exit && found_critical_block {
                return (results.into_vec(), true);
            }
        }

        // Only apply regex if no blocking match found yet (or not skipping)
        if !skip_regex && !(early_exit && should_block) {
            for compiled in &self.regex_patterns {
                if compiled.regex.is_match(url) {
                    let category = &self.categories[compiled.category_idx];

                    if matches!(category.action, Action::Drop) {
                        should_block = true;
                    }

                    results.push(DetectionResult {
                        detected: true,
                        category: category.name.clone(),
                        severity: category.severity,
                        action: category.action.clone(),
                        matched_pattern: compiled.regex.as_str().to_string(),
                        score: category.severity.score(),
                        description: "Regex pattern matched in URL".to_string(),
                    });

                    // Early exit for critical+block regex match
                    if early_exit && category.is_critical && matches!(category.action, Action::Drop) {
                        return (results.into_vec(), true);
                    }
                }
            }
        }

        (results.into_vec(), should_block)
    }

    /// Scan HTTP headers for attack patterns - optimized for common headers
    pub fn scan_headers(&self, headers: &HashMap<String, String>) -> Vec<DetectionResult> {
        let mut results = Vec::new();

        // Check User-Agent for scanner signatures using dedicated AC automaton
        if let Some(ua) = headers.get("user-agent").or_else(|| headers.get("User-Agent")) {
            self.scan_user_agent(ua, &mut results);
        }

        // Check Cookie header for injection attempts
        if let Some(cookie) = headers.get("cookie").or_else(|| headers.get("Cookie")) {
            // Use optimized scan with early exit
            let (cookie_results, _) = self.scan_url_with_options(cookie, true, false);
            results.extend(cookie_results);
        }

        // Check Referer for suspicious patterns
        if let Some(referer) = headers.get("referer").or_else(|| headers.get("Referer")) {
            let (referer_results, _) = self.scan_url_with_options(referer, true, false);
            results.extend(referer_results);
        }

        results
    }

    /// Optimized User-Agent scanning with dedicated AC automaton
    fn scan_user_agent(&self, ua: &str, results: &mut Vec<DetectionResult>) {
        if let (Some(scanner_ac), Some(cat_idx)) = (&self.scanner_ac, self.scanner_category_idx) {
            let ua_lower = ua.to_lowercase();
            let category = &self.categories[cat_idx];

            for mat in scanner_ac.find_iter(&ua_lower) {
                let pattern_idx = mat.pattern().as_usize();
                let pattern = &self.scanner_patterns[pattern_idx];

                results.push(DetectionResult {
                    detected: true,
                    category: category.name.clone(),
                    severity: category.severity,
                    action: category.action.clone(),
                    matched_pattern: pattern.clone(),
                    score: category.severity.score(),
                    description: format!("Scanner user-agent detected: {}", pattern),
                });
            }
        }
    }

    /// Calculate total threat score
    #[inline]
    pub fn calculate_threat_score(&self, results: &[DetectionResult]) -> u32 {
        results.iter().map(|r| r.score).sum()
    }

    /// Get recommended action based on detections
    pub fn get_recommended_action(&self, results: &[DetectionResult]) -> Option<Action> {
        results.iter()
            .map(|r| &r.action)
            .max_by_key(|a| a.priority())
            .cloned()
    }

    /// Scan complete HTTP request - optimized with early exit
    pub fn scan_request(&self,
                        method: &str,
                        url: &str,
                        headers: &HashMap<String, String>,
                        body: Option<&str>) -> ScanReport {
        let mut all_results = Vec::new();

        // Scan URL with early exit enabled
        let (url_results, should_block) = self.scan_url_with_options(url, true, false);
        all_results.extend(url_results);

        // Skip further scanning if we already have a critical block
        if !should_block {
            // Scan headers
            all_results.extend(self.scan_headers(headers));

            // Scan body for POST/PUT requests
            if let Some(body_content) = body {
                if method == "POST" || method == "PUT" {
                    let (body_results, _) = self.scan_url_with_options(body_content, true, false);
                    all_results.extend(body_results);
                }
            }
        }

        let threat_score = self.calculate_threat_score(&all_results);
        let recommended_action = self.get_recommended_action(&all_results);

        ScanReport {
            detections: all_results,
            threat_score,
            recommended_action,
        }
    }

    /// Fast scan - returns only the verdict without full details
    /// Use this for maximum performance when you just need block/allow
    pub fn scan_request_fast(&self,
                             _method: &str,
                             url: &str,
                             headers: &HashMap<String, String>,
                             _body: Option<&str>) -> FastScanResult {
        let url_lower = url.to_lowercase();
        let mut threat_score: u32 = 0;
        let mut max_action = None;
        let mut detection_count: u32 = 0;

        // Check URL with AC automaton
        for mat in self.ac_automaton.find_iter(&url_lower) {
            let pattern_id = mat.pattern().as_usize();
            let metadata = &self.pattern_metadata[pattern_id];
            let category = &self.categories[metadata.category_idx];

            detection_count += 1;
            threat_score += category.severity.score();

            if max_action.as_ref().map_or(true, |a: &Action| category.action.priority() > a.priority()) {
                max_action = Some(category.action.clone());
            }

            // Early exit on critical block
            if category.is_critical && matches!(category.action, Action::Drop) {
                return FastScanResult {
                    should_block: true,
                    threat_score,
                    detection_count,
                };
            }
        }

        // Quick regex check only if no block yet
        if !matches!(max_action, Some(Action::Drop)) {
            for compiled in &self.regex_patterns {
                if compiled.regex.is_match(url) {
                    let category = &self.categories[compiled.category_idx];
                    detection_count += 1;
                    threat_score += category.severity.score();

                    if matches!(category.action, Action::Drop) {
                        return FastScanResult {
                            should_block: true,
                            threat_score,
                            detection_count,
                        };
                    }
                }
            }
        }

        // Check User-Agent
        if let (Some(scanner_ac), Some(cat_idx)) = (&self.scanner_ac, self.scanner_category_idx) {
            if let Some(ua) = headers.get("user-agent").or_else(|| headers.get("User-Agent")) {
                let ua_lower = ua.to_lowercase();
                let category = &self.categories[cat_idx];

                for _ in scanner_ac.find_iter(&ua_lower) {
                    detection_count += 1;
                    threat_score += category.severity.score();

                    if max_action.as_ref().map_or(true, |a| category.action.priority() > a.priority()) {
                        max_action = Some(category.action.clone());
                    }
                }
            }
        }

        FastScanResult {
            should_block: matches!(max_action, Some(Action::Drop)),
            threat_score,
            detection_count,
        }
    }
}

/// Fast scan result for high-performance path
#[derive(Debug, Clone)]
pub struct FastScanResult {
    pub should_block: bool,
    pub threat_score: u32,
    pub detection_count: u32,
}

/// Complete scan report
#[derive(Debug, Clone)]
pub struct ScanReport {
    pub detections: Vec<DetectionResult>,
    pub threat_score: u32,
    pub recommended_action: Option<Action>,
}

impl ScanReport {
    /// Check if request should be blocked
    #[inline]
    pub fn should_block(&self) -> bool {
        matches!(self.recommended_action, Some(Action::Drop))
    }

    /// Check if rate limiting should be applied
    #[inline]
    pub fn should_rate_limit(&self) -> bool {
        matches!(self.recommended_action, Some(Action::RateLimit))
    }

    /// Get all critical detections
    pub fn critical_detections(&self) -> Vec<&DetectionResult> {
        self.detections
            .iter()
            .filter(|d| d.severity == Severity::Critical)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_traversal_detection() {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());

        let engine = DetectionEngine::from_file("data/http_detect/attack_patterns.json")
            .expect("Failed to load patterns");

        // Test various path traversal attempts
        let test_urls = vec![
            "/../../../../etc/passwd",
            "/cgi-bin/../../../etc/passwd",
            "/test.php?file=../../../etc/passwd",
            "/images/..%2f..%2f..%2fetc%2fpasswd",
        ];

        for url in test_urls {
            let report = engine.scan_request("GET", url, &headers, None);
            assert!(report.detections.len() > 0, "Failed to detect: {}", url);
            assert!(report.should_block(), "Should block: {}", url);
        }
    }

    #[test]
    fn test_web_shell_detection() {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "curl/7.68.0".to_string());

        let engine = DetectionEngine::from_file("data/http_detect/attack_patterns.json")
            .expect("Failed to load patterns");

        let test_urls = vec![
            "/uploads/c99.php",
            "/images/shell.php",
            "/tmp/r57.php",
        ];

        for url in test_urls {
            let report = engine.scan_request("GET", url, &headers, None);
            assert!(report.detections.len() > 0, "Failed to detect: {}", url);
            assert!(report.should_block());
        }
    }

    #[test]
    fn test_sql_injection_detection() {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());

        let engine = DetectionEngine::from_file("data/http_detect/attack_patterns.json")
            .expect("Failed to load patterns");

        let test_urls = vec![
            "/product.php?id=1' or '1'='1",
            "/search.php?q=admin'--",
            "/user.php?id=1 union select null",
        ];

        for url in test_urls {
            let report = engine.scan_request("GET", url, &headers, None);
            assert!(report.detections.len() > 0, "Failed to detect: {}", url);
            assert!(report.should_block());
        }
    }

    #[test]
    fn test_scanner_user_agent_detection() {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "nikto/2.1.6".to_string());

        let engine = DetectionEngine::from_file("data/http_detect/attack_patterns.json")
            .expect("Failed to load patterns");

        let report = engine.scan_request("GET", "/", &headers, None);
        assert!(report.detections.len() > 0);
        assert!(report.should_rate_limit());
    }

    #[test]
    fn test_benign_request() {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());

        let engine = DetectionEngine::from_file("data/http_detect/attack_patterns.json")
            .expect("Failed to load patterns");

        let report = engine.scan_request("GET", "/about", &headers, None);
        assert_eq!(report.detections.len(), 0);
        assert!(!report.should_block());
    }

    #[test]
    fn test_fast_scan() {
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());

        let engine = DetectionEngine::from_file("data/http_detect/attack_patterns.json")
            .expect("Failed to load patterns");

        // Malicious URL
        let result = engine.scan_request_fast("GET", "/../../../../etc/passwd", &headers, None);
        assert!(result.should_block);
        assert!(result.detection_count > 0);

        // Benign URL
        let result = engine.scan_request_fast("GET", "/about", &headers, None);
        assert!(!result.should_block);
        assert_eq!(result.detection_count, 0);
    }
}
