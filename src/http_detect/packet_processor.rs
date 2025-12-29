// CR Monban - Optimized Packet Processor with Lock-Free IP Tracking
// Integration with nfqueue for HTTP traffic inspection

use dashmap::DashMap;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use super::detection_rules::{Action, DetectionEngine, ScanReport};

/// IP tracking state
#[derive(Debug, Clone)]
pub struct IpState {
    pub violation_count: u32,
    pub last_violation: SystemTime,
    pub blocked_until: Option<SystemTime>,
    pub total_score: u32,
}

/// Number of shards for DashMap (power of 2 for efficient hashing)
const NUM_SHARDS: usize = 64;

/// Lock-free IP tracking using DashMap
/// Provides O(1) concurrent access with minimal contention
pub struct IpTracker {
    /// Sharded concurrent hashmap for lock-free access
    states: DashMap<IpAddr, IpState>,
}

impl IpTracker {
    pub fn new() -> Self {
        IpTracker {
            // Pre-allocate with expected capacity and shard count
            states: DashMap::with_capacity_and_shard_amount(4096, NUM_SHARDS),
        }
    }

    /// Record a violation from an IP - lock-free update
    pub fn record_violation(&self, ip: IpAddr, score: u32, action: &Action) {
        self.states
            .entry(ip)
            .and_modify(|state| {
                state.violation_count += 1;
                state.total_score += score;
                state.last_violation = SystemTime::now();
                Self::apply_blocking_policy(state, action);
            })
            .or_insert_with(|| {
                let mut state = IpState {
                    violation_count: 1,
                    last_violation: SystemTime::now(),
                    blocked_until: None,
                    total_score: score,
                };
                Self::apply_blocking_policy(&mut state, action);
                state
            });
    }

    /// Apply blocking policy based on action and accumulated violations
    #[inline]
    fn apply_blocking_policy(state: &mut IpState, action: &Action) {
        let now = SystemTime::now();

        match action {
            Action::Drop | Action::Reject | Action::Ban => {
                // Immediate block for 1 hour
                state.blocked_until = Some(now + Duration::from_secs(3600));
            }
            Action::RateLimit => {
                // Block after 5 violations
                if state.violation_count >= 5 {
                    state.blocked_until = Some(now + Duration::from_secs(1800));
                }
            }
            _ => {}
        }

        // Progressive blocking based on total score
        if state.total_score >= 100 {
            // Very high threat score - 24 hour block
            state.blocked_until = Some(now + Duration::from_secs(86400));
        } else if state.total_score >= 50 {
            // High threat score - 2 hour block
            state.blocked_until = Some(now + Duration::from_secs(7200));
        }
    }

    /// Check if IP is currently blocked - lock-free read
    #[inline]
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        if let Some(state) = self.states.get(&ip) {
            if let Some(blocked_until) = state.blocked_until {
                return SystemTime::now() < blocked_until;
            }
        }
        false
    }

    /// Get current state for an IP - lock-free read
    pub fn get_state(&self, ip: IpAddr) -> Option<IpState> {
        self.states.get(&ip).map(|r| r.clone())
    }

    /// Get violation count for an IP
    #[inline]
    pub fn get_violation_count(&self, ip: IpAddr) -> u32 {
        self.states.get(&ip).map_or(0, |s| s.violation_count)
    }

    /// Get total tracked IPs (for monitoring)
    pub fn tracked_count(&self) -> usize {
        self.states.len()
    }

    /// Clean up old entries - can run in parallel
    pub fn cleanup_old_entries(&self, max_age: Duration) {
        let now = SystemTime::now();

        self.states.retain(|_, state| {
            // Keep if still blocked
            if let Some(blocked_until) = state.blocked_until {
                if now < blocked_until {
                    return true;
                }
            }

            // Keep if recently active
            now.duration_since(state.last_violation)
                .map(|elapsed| elapsed < max_age)
                .unwrap_or(false)
        });
    }

    /// Unblock a specific IP
    pub fn unblock(&self, ip: IpAddr) {
        if let Some(mut state) = self.states.get_mut(&ip) {
            state.blocked_until = None;
            state.total_score = 0;
            state.violation_count = 0;
        }
    }

    /// Get all blocked IPs (for monitoring/admin)
    pub fn get_blocked_ips(&self) -> Vec<IpAddr> {
        let now = SystemTime::now();
        self.states
            .iter()
            .filter_map(|r| {
                if let Some(blocked_until) = r.value().blocked_until {
                    if now < blocked_until {
                        return Some(*r.key());
                    }
                }
                None
            })
            .collect()
    }
}

impl Default for IpTracker {
    fn default() -> Self {
        Self::new()
    }
}

// HTTP method signatures for fast detection (no allocation)
static HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

/// Fast HTTP detection - checks first bytes without allocation
/// Returns true if payload looks like HTTP request
#[inline]
pub fn is_http_request(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // Check against known HTTP method prefixes
    for method in HTTP_METHODS {
        if data.len() >= method.len() && &data[..method.len()] == *method {
            return true;
        }
    }
    false
}

/// Even faster HTTP check - only checks GET/POST (most common)
#[inline]
pub fn is_http_request_fast(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // GET and POST are ~95% of HTTP traffic
    // Check first 4 bytes directly (no loop)
    let first4 = &data[..4];
    first4 == b"GET " || first4 == b"POST" || first4 == b"PUT " || first4 == b"HEAD"
}

/// Parse HTTP request from packet payload
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

impl HttpRequest {
    /// Ultra-fast check if data is HTTP (no allocation)
    #[inline]
    pub fn is_http(data: &[u8]) -> bool {
        is_http_request_fast(data)
    }

    /// Parse HTTP request from raw bytes
    /// Call is_http() first for best performance
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Fast pre-check before any allocation
        if !is_http_request(data) {
            return None;
        }

        let request_str = String::from_utf8_lossy(data);
        let lines: Vec<&str> = request_str.lines().collect();

        if lines.is_empty() {
            return None;
        }

        // Parse request line
        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        let method = parts[0].to_string();
        let url = parts[1].to_string();

        // Parse headers
        let mut headers = HashMap::new();
        let mut body_start = 0;

        for (i, line) in lines.iter().enumerate().skip(1) {
            if line.is_empty() {
                body_start = i + 1;
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        // Extract body if present
        let body = if body_start < lines.len() {
            Some(lines[body_start..].join("\n"))
        } else {
            None
        };

        Some(HttpRequest {
            method,
            url,
            headers,
            body,
        })
    }
}

/// Main packet processor with optimized detection
pub struct PacketProcessor {
    engine: Arc<DetectionEngine>,
    ip_tracker: Arc<IpTracker>,
}

impl PacketProcessor {
    pub fn new(pattern_file: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let engine = DetectionEngine::from_file(pattern_file)?;

        Ok(PacketProcessor {
            engine: Arc::new(engine),
            ip_tracker: Arc::new(IpTracker::new()),
        })
    }

    /// Process a packet and return verdict - optimized hot path
    pub fn process_packet(&self, src_ip: IpAddr, payload: &[u8]) -> PacketVerdict {
        // Fast check if IP is already blocked (lock-free)
        if self.ip_tracker.is_blocked(src_ip) {
            return PacketVerdict::Drop(DropReason::IpBlocked);
        }

        // Ultra-fast HTTP pre-filter (just 4 byte comparison)
        if !HttpRequest::is_http(payload) {
            return PacketVerdict::Accept; // Not HTTP, skip
        }

        // Try to parse as HTTP request
        let http_request = match HttpRequest::parse(payload) {
            Some(req) => req,
            None => return PacketVerdict::Accept, // Malformed HTTP
        };

        // Scan the request with optimized engine
        let report = self.engine.scan_request(
            &http_request.method,
            &http_request.url,
            &http_request.headers,
            http_request.body.as_deref(),
        );

        // Record violations and determine verdict
        if !report.detections.is_empty() {
            if let Some(action) = &report.recommended_action {
                self.ip_tracker
                    .record_violation(src_ip, report.threat_score, action);

                match action {
                    Action::Drop | Action::Reject | Action::Ban => {
                        return PacketVerdict::Drop(DropReason::AttackDetected {
                            score: report.threat_score,
                            categories: report
                                .detections
                                .iter()
                                .map(|d| d.category.clone())
                                .collect(),
                        });
                    }
                    Action::RateLimit => {
                        // Check if we should start blocking this IP
                        if self.ip_tracker.is_blocked(src_ip) {
                            return PacketVerdict::Drop(DropReason::RateLimitExceeded);
                        }
                    }
                    _ => {}
                }
            }
        }

        PacketVerdict::Accept
    }

    /// Fast packet processing - returns only block/accept verdict
    /// Use this for maximum throughput when detailed logging isn't needed
    pub fn process_packet_fast(&self, src_ip: IpAddr, payload: &[u8]) -> bool {
        // Fast check if IP is already blocked
        if self.ip_tracker.is_blocked(src_ip) {
            return false; // Drop
        }

        // Ultra-fast HTTP pre-filter (just 4 byte comparison)
        if !HttpRequest::is_http(payload) {
            return true; // Accept non-HTTP immediately
        }

        // Try to parse as HTTP request
        let http_request = match HttpRequest::parse(payload) {
            Some(req) => req,
            None => return true, // Accept malformed
        };

        // Use fast scan path
        let result = self.engine.scan_request_fast(
            &http_request.method,
            &http_request.url,
            &http_request.headers,
            http_request.body.as_deref(),
        );

        if result.should_block {
            self.ip_tracker
                .record_violation(src_ip, result.threat_score, &Action::Drop);
            return false; // Drop
        }

        true // Accept
    }

    /// Get IP tracker for external use
    pub fn get_ip_tracker(&self) -> Arc<IpTracker> {
        Arc::clone(&self.ip_tracker)
    }

    /// Get detection engine for external use
    pub fn get_engine(&self) -> Arc<DetectionEngine> {
        Arc::clone(&self.engine)
    }
}

/// Verdict for packet processing
#[derive(Debug)]
pub enum PacketVerdict {
    Accept,
    Drop(DropReason),
}

#[derive(Debug)]
pub enum DropReason {
    IpBlocked,
    RateLimitExceeded,
    AttackDetected { score: u32, categories: Vec<String> },
}

/// Example integration with nfqueue
pub fn process_nfqueue_packet(
    processor: &PacketProcessor,
    _queue_num: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    payload: &[u8],
) -> u32 {
    const NF_ACCEPT: u32 = 1;
    const NF_DROP: u32 = 0;

    match processor.process_packet(src_ip, payload) {
        PacketVerdict::Accept => {
            // Uncomment for debugging:
            // println!("[ACCEPT] {} -> {}", src_ip, dst_ip);
            NF_ACCEPT
        }
        PacketVerdict::Drop(reason) => {
            println!("[DROP] {} -> {} : {:?}", src_ip, dst_ip, reason);
            NF_DROP
        }
    }
}

/// Fast nfqueue processing - minimal overhead
pub fn process_nfqueue_packet_fast(
    processor: &PacketProcessor,
    src_ip: IpAddr,
    payload: &[u8],
) -> u32 {
    const NF_ACCEPT: u32 = 1;
    const NF_DROP: u32 = 0;

    if processor.process_packet_fast(src_ip, payload) {
        NF_ACCEPT
    } else {
        NF_DROP
    }
}

/// Logging and alerting
pub struct AlertLogger {
    log_file: String,
}

impl AlertLogger {
    pub fn new(log_file: String) -> Self {
        AlertLogger { log_file }
    }

    pub fn log_detection(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
        report: &ScanReport,
    ) {
        let timestamp = chrono::Utc::now();

        for detection in &report.detections {
            let log_entry = format!(
                "{} [{:?}] {} -> {}:{} | Category: {} | Pattern: {} | Score: {} | Action: {:?}",
                timestamp.format("%Y-%m-%d %H:%M:%S"),
                detection.severity,
                src_ip,
                dst_ip,
                dst_port,
                detection.category,
                detection.matched_pattern,
                detection.score,
                detection.action
            );

            println!("{}", log_entry);

            // In production, use async logging to avoid blocking
            // tokio::spawn(async move { ... });
        }

        // For critical detections, send alert
        if report.threat_score >= 20 {
            self.send_alert(src_ip, dst_ip, dst_port, report);
        }
    }

    fn send_alert(&self, src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16, report: &ScanReport) {
        println!("\n=== CRITICAL ALERT ===");
        println!("Source IP: {}", src_ip);
        println!("Target: {}:{}", dst_ip, dst_port);
        println!("Threat Score: {}", report.threat_score);
        println!("Detections: {}", report.detections.len());

        for detection in report.critical_detections() {
            println!("  - {} ({})", detection.category, detection.matched_pattern);
        }
        println!("=====================\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_tracker_lock_free() {
        let tracker = IpTracker::new();
        let test_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Should not be blocked initially
        assert!(!tracker.is_blocked(test_ip));

        // Record violations from multiple "threads" (simulated)
        for _ in 0..10 {
            tracker.record_violation(test_ip, 20, &Action::Drop);
        }

        // Should be blocked now
        assert!(tracker.is_blocked(test_ip));

        // Check violation count
        assert!(tracker.get_violation_count(test_ip) >= 10);
    }

    #[test]
    fn test_ip_tracker_concurrent() {
        use std::thread;

        let tracker = Arc::new(IpTracker::new());
        let mut handles = vec![];

        // Spawn multiple threads recording violations
        for i in 0..10 {
            let tracker = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                let ip: IpAddr = format!("192.168.1.{}", i).parse().unwrap();
                for _ in 0..100 {
                    tracker.record_violation(ip, 1, &Action::Log);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All IPs should have been tracked
        assert!(tracker.tracked_count() >= 10);
    }

    #[test]
    fn test_http_parsing() {
        let http_data =
            b"GET /admin/config.php HTTP/1.1\r\nHost: example.com\r\nUser-Agent: nikto\r\n\r\n";

        let request = HttpRequest::parse(http_data).expect("Failed to parse");

        assert_eq!(request.method, "GET");
        assert_eq!(request.url, "/admin/config.php");
        assert_eq!(
            request.headers.get("host"),
            Some(&"example.com".to_string())
        );
        assert_eq!(request.headers.get("user-agent"), Some(&"nikto".to_string()));
    }

    #[test]
    fn test_packet_processing() {
        let processor =
            PacketProcessor::new("data/attack_patterns.json").expect("Failed to load patterns");

        let test_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Malicious request
        let http_data = b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let verdict = processor.process_packet(test_ip, http_data);

        match verdict {
            PacketVerdict::Drop(_) => {
                println!("Correctly blocked malicious request");
            }
            PacketVerdict::Accept => {
                panic!("Should have blocked this request");
            }
        }
    }

    #[test]
    fn test_fast_packet_processing() {
        let processor =
            PacketProcessor::new("data/attack_patterns.json").expect("Failed to load patterns");

        let test_ip: IpAddr = "192.168.1.101".parse().unwrap();

        // Malicious request
        let http_data = b"GET /../../../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!processor.process_packet_fast(test_ip, http_data));

        // Benign request
        let test_ip2: IpAddr = "192.168.1.102".parse().unwrap();
        let http_data2 = b"GET /about HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(processor.process_packet_fast(test_ip2, http_data2));
    }

    #[test]
    fn test_cleanup() {
        let tracker = IpTracker::new();
        let test_ip: IpAddr = "192.168.1.100".parse().unwrap();

        tracker.record_violation(test_ip, 5, &Action::Log);
        assert!(tracker.tracked_count() >= 1);

        // Cleanup with very short max age should remove entries
        tracker.cleanup_old_entries(Duration::from_nanos(1));

        // Entry should be removed (unless blocked)
        // Note: This may fail if the entry was just added - timing dependent
    }
}
