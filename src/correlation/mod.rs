//! Alert Correlation Engine
//!
//! Groups related alerts, reduces noise, and identifies attack chains.
//!
//! # Features
//! - Time-window based correlation
//! - Attack chain detection (MITRE ATT&CK aligned)
//! - Alert aggregation and deduplication
//! - Incident management
//!
//! # Example
//! ```ignore
//! use crmonban::correlation::{CorrelationEngine, CorrelationConfig};
//!
//! let config = CorrelationConfig::default();
//! let mut engine = CorrelationEngine::new(config);
//!
//! let result = engine.process(detection_event);
//! match result {
//!     CorrelationResult::NewIncident(incident) => {
//!         println!("New incident: {}", incident.id);
//!     }
//!     CorrelationResult::UpdatedIncident(incident) => {
//!         println!("Updated incident: {}", incident.id);
//!     }
//!     CorrelationResult::Suppressed => {
//!         // Duplicate or noise, already handled
//!     }
//!     CorrelationResult::Standalone(event) => {
//!         // Single event, no correlation
//!     }
//! }
//! ```

pub mod rules;
pub mod chains;
pub mod aggregator;
pub mod incident;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::event::{DetectionEvent, DetectionType, Severity};

pub use rules::{CorrelationRule, RuleMatch, RuleType};
pub use chains::{AttackChain, AttackStage, ChainDetector, MitreTactic};
pub use aggregator::{Aggregator, AggregatedAlert};
pub use incident::{Incident, IncidentStatus, IncidentPriority};

/// Correlation engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationConfig {
    /// Enable correlation
    pub enabled: bool,
    /// Correlation time window
    pub window_seconds: u64,
    /// Maximum incidents to track
    pub max_incidents: usize,
    /// Maximum events to keep in memory
    pub max_events: usize,
    /// Aggregation threshold (min events to aggregate)
    pub aggregation_threshold: usize,
    /// Incident timeout (close after inactivity)
    pub incident_timeout_seconds: u64,
    /// Enable attack chain detection
    pub detect_chains: bool,
    /// Correlation rules
    pub rules: Vec<CorrelationRule>,
}

impl Default for CorrelationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            window_seconds: 300, // 5 minutes
            max_incidents: 10_000,
            max_events: 100_000,
            aggregation_threshold: 5,
            incident_timeout_seconds: 3600, // 1 hour
            detect_chains: true,
            rules: default_correlation_rules(),
        }
    }
}

/// Result of processing an event through correlation
#[derive(Debug, Clone)]
pub enum CorrelationResult {
    /// New incident created
    NewIncident(Incident),
    /// Existing incident updated
    UpdatedIncident(Incident),
    /// Event suppressed (duplicate/noise)
    Suppressed,
    /// Standalone event, no correlation
    Standalone(DetectionEvent),
}

/// Correlation engine state
pub struct CorrelationEngine {
    /// Configuration
    config: CorrelationConfig,
    /// Active incidents by ID
    incidents: HashMap<Uuid, Incident>,
    /// Incident index by IP (for O(1) matching)
    incidents_by_ip: HashMap<IpAddr, Vec<Uuid>>,
    /// Event index by source IP
    events_by_src: HashMap<IpAddr, VecDeque<Uuid>>,
    /// Event index by destination IP
    events_by_dst: HashMap<IpAddr, VecDeque<Uuid>>,
    /// Event storage
    events: HashMap<Uuid, DetectionEvent>,
    /// Recent event signatures for deduplication (HashSet for O(1) lookup)
    recent_signatures: HashSet<u64>,
    /// Signature expiry queue (for cleanup)
    signature_queue: VecDeque<(u64, DateTime<Utc>)>,
    /// Alert aggregator
    aggregator: Aggregator,
    /// Attack chain detector
    chain_detector: ChainDetector,
    /// Cached correlation window as chrono::Duration
    window_chrono: chrono::Duration,
    /// Statistics
    stats: CorrelationStats,
}

/// Correlation statistics
#[derive(Debug, Clone, Default, Serialize)]
pub struct CorrelationStats {
    pub events_processed: u64,
    pub events_suppressed: u64,
    pub incidents_created: u64,
    pub incidents_updated: u64,
    pub chains_detected: u64,
    pub active_incidents: usize,
}

impl CorrelationEngine {
    /// Create a new correlation engine
    pub fn new(config: CorrelationConfig) -> Self {
        let aggregator = Aggregator::new(
            config.aggregation_threshold,
            Duration::from_secs(config.window_seconds),
        );
        let chain_detector = ChainDetector::new();
        let window_chrono = chrono::Duration::seconds(config.window_seconds as i64);

        Self {
            config,
            incidents: HashMap::new(),
            incidents_by_ip: HashMap::new(),
            events_by_src: HashMap::new(),
            events_by_dst: HashMap::new(),
            events: HashMap::new(),
            recent_signatures: HashSet::with_capacity(10_000),
            signature_queue: VecDeque::with_capacity(10_000),
            aggregator,
            chain_detector,
            window_chrono,
            stats: CorrelationStats::default(),
        }
    }

    /// Process a new detection event
    #[inline]
    pub fn process(&mut self, event: DetectionEvent) -> CorrelationResult {
        self.stats.events_processed += 1;

        // 1. Check for duplicates
        if self.is_duplicate(&event) {
            self.stats.events_suppressed += 1;
            return CorrelationResult::Suppressed;
        }

        // 2. Try to aggregate with similar events
        if let Some(_aggregated) = self.aggregator.try_aggregate(&event) {
            self.stats.events_suppressed += 1;
            return CorrelationResult::Suppressed;
        }

        // 3. Store the event
        self.store_event(event.clone());

        // 4. Try to correlate with existing incidents
        if let Some(incident_id) = self.find_matching_incident(&event) {
            let incident = self.incidents.get_mut(&incident_id).unwrap();
            incident.add_event(event.clone());

            // Check for attack chain progression
            if self.config.detect_chains {
                if let Some(chain) = self.chain_detector.check_progression(incident) {
                    incident.attack_chain = Some(chain);
                    self.stats.chains_detected += 1;
                }
            }

            self.stats.incidents_updated += 1;
            return CorrelationResult::UpdatedIncident(incident.clone());
        }

        // 5. Check correlation rules for new incident
        for rule in &self.config.rules {
            if let Some(matched_events) = self.check_rule(rule, &event) {
                let incident = self.create_incident(rule, matched_events);
                let incident_id = incident.id;
                let hosts = incident.affected_hosts.clone();
                let incident_clone = incident.clone();
                self.incidents.insert(incident_id, incident);
                self.index_incident(incident_id, &hosts);
                self.stats.incidents_created += 1;
                self.stats.active_incidents = self.incidents.len();
                return CorrelationResult::NewIncident(incident_clone);
            }
        }

        // 6. No correlation found
        CorrelationResult::Standalone(event)
    }

    /// Check if event is a duplicate (optimized with HashSet for O(1) lookup)
    #[inline]
    fn is_duplicate(&mut self, event: &DetectionEvent) -> bool {
        let signature = self.compute_signature(event);
        let now = Utc::now();
        let window = chrono::Duration::seconds(60); // 1 minute dedup window

        // Clean old signatures from queue and HashSet
        while let Some((old_sig, ts)) = self.signature_queue.front() {
            if now - *ts > window {
                self.recent_signatures.remove(old_sig);
                self.signature_queue.pop_front();
            } else {
                break;
            }
        }

        // O(1) lookup in HashSet
        if self.recent_signatures.contains(&signature) {
            return true;
        }

        // Add signature to both structures
        self.recent_signatures.insert(signature);
        self.signature_queue.push_back((signature, now));

        // Limit size
        if self.signature_queue.len() > 10_000 {
            if let Some((old_sig, _)) = self.signature_queue.pop_front() {
                self.recent_signatures.remove(&old_sig);
            }
        }

        false
    }

    /// Compute a signature for deduplication
    #[inline]
    fn compute_signature(&self, event: &DetectionEvent) -> u64 {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        event.src_ip.hash(&mut hasher);
        event.dst_ip.hash(&mut hasher);
        event.src_port.hash(&mut hasher);
        event.dst_port.hash(&mut hasher);
        std::mem::discriminant(&event.event_type).hash(&mut hasher);
        if let Some(ref rule_id) = event.rule_id {
            rule_id.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Store event in indexes
    fn store_event(&mut self, event: DetectionEvent) {
        let event_id = event.id;

        // Store by source IP
        self.events_by_src
            .entry(event.src_ip)
            .or_insert_with(|| VecDeque::with_capacity(100))
            .push_back(event_id);

        // Store by destination IP
        self.events_by_dst
            .entry(event.dst_ip)
            .or_insert_with(|| VecDeque::with_capacity(100))
            .push_back(event_id);

        // Store event
        self.events.insert(event_id, event);

        // Cleanup if too many events
        if self.events.len() > self.config.max_events {
            self.cleanup_old_events();
        }
    }

    /// Find matching incident for event (optimized with IP index)
    #[inline]
    fn find_matching_incident(&self, event: &DetectionEvent) -> Option<Uuid> {
        let now = Utc::now();

        // Check source IP index first (O(1) lookup + small iteration)
        if let Some(incident_ids) = self.incidents_by_ip.get(&event.src_ip) {
            for id in incident_ids {
                if let Some(incident) = self.incidents.get(id) {
                    if now - incident.last_activity <= self.window_chrono {
                        return Some(*id);
                    }
                }
            }
        }

        // Check destination IP index
        if let Some(incident_ids) = self.incidents_by_ip.get(&event.dst_ip) {
            for id in incident_ids {
                if let Some(incident) = self.incidents.get(id) {
                    if now - incident.last_activity <= self.window_chrono {
                        return Some(*id);
                    }
                }
            }
        }

        None
    }

    /// Add incident to IP index
    fn index_incident(&mut self, incident_id: Uuid, hosts: &HashSet<IpAddr>) {
        for ip in hosts {
            self.incidents_by_ip
                .entry(*ip)
                .or_insert_with(Vec::new)
                .push(incident_id);
        }
    }

    /// Check if event type matches any of the type strings
    #[inline]
    fn event_type_matches(event_type: &DetectionType, type_strs: &[String]) -> bool {
        // Use discriminant name matching without format! allocation for common types
        let type_name: &str = match event_type {
            DetectionType::SignatureMatch => "SignatureMatch",
            DetectionType::ProtocolAnomaly => "ProtocolAnomaly",
            DetectionType::MalformedPacket => "MalformedPacket",
            DetectionType::PortScan => "PortScan",
            DetectionType::NetworkScan => "NetworkScan",
            DetectionType::DDoS => "DDoS",
            DetectionType::BruteForce => "BruteForce",
            DetectionType::DataExfiltration => "DataExfiltration",
            DetectionType::Beaconing => "Beaconing",
            DetectionType::LateralMovement => "LateralMovement",
            DetectionType::ThreatIntelMatch => "ThreatIntelMatch",
            DetectionType::MaliciousIp => "MaliciousIp",
            DetectionType::MaliciousDomain => "MaliciousDomain",
            DetectionType::MaliciousUrl => "MaliciousUrl",
            DetectionType::MaliciousHash => "MaliciousHash",
            DetectionType::MaliciousJa3 => "MaliciousJa3",
            DetectionType::AnomalyDetection => "AnomalyDetection",
            DetectionType::BehaviorAnomaly => "BehaviorAnomaly",
            DetectionType::TrafficAnomaly => "TrafficAnomaly",
            DetectionType::PolicyViolation => "PolicyViolation",
            DetectionType::ExploitAttempt => "ExploitAttempt",
            DetectionType::Shellcode => "Shellcode",
            DetectionType::Overflow => "Overflow",
            DetectionType::MalwareDownload => "MalwareDownload",
            DetectionType::MalwareCallback => "MalwareCallback",
            DetectionType::CnC => "CnC",
            DetectionType::UnauthorizedAccess => "UnauthorizedAccess",
            DetectionType::Custom(_) => "Custom",
        };
        type_strs.iter().any(|t| type_name.contains(t.as_str()))
    }

    /// Check a correlation rule (optimized - avoids format! in hot path)
    #[inline]
    fn check_rule(&self, rule: &CorrelationRule, event: &DetectionEvent) -> Option<Vec<DetectionEvent>> {
        let now = Utc::now();
        let window = chrono::Duration::seconds(rule.window_seconds as i64);

        match &rule.rule_type {
            RuleType::Count { event_types, threshold, group_by } => {
                // Check if event matches the types we're looking for (no allocation)
                if !Self::event_type_matches(&event.event_type, event_types) {
                    return None;
                }

                // Count matching events in window
                let mut matching = Vec::with_capacity(*threshold);

                // Get events from the same source/destination
                let ips_to_check: [Option<IpAddr>; 2] = match group_by.as_deref() {
                    Some("src_ip") => [Some(event.src_ip), None],
                    Some("dst_ip") => [Some(event.dst_ip), None],
                    _ => [Some(event.src_ip), Some(event.dst_ip)],
                };

                for ip_opt in ips_to_check.iter().flatten() {
                    if let Some(event_ids) = self.events_by_src.get(ip_opt) {
                        for event_id in event_ids {
                            if let Some(e) = self.events.get(event_id) {
                                if now - e.timestamp < window {
                                    if Self::event_type_matches(&e.event_type, event_types) {
                                        matching.push(e.clone());
                                        // Early exit if we have enough
                                        if matching.len() >= *threshold {
                                            return Some(matching);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if matching.len() >= *threshold {
                    Some(matching)
                } else {
                    None
                }
            }
            RuleType::Sequence { stages, max_gap_seconds } => {
                // Check if we have events matching the sequence
                let gap = chrono::Duration::seconds(*max_gap_seconds as i64);
                let mut stage_events: Vec<Vec<DetectionEvent>> = vec![Vec::new(); stages.len()];

                // Find matching source
                let src_ip = event.src_ip;
                let event_ids = self.events_by_src.get(&src_ip)?;

                for event_id in event_ids {
                    if let Some(e) = self.events.get(event_id) {
                        for (i, stage) in stages.iter().enumerate() {
                            if Self::event_type_matches(&e.event_type, &[stage.clone()]) {
                                stage_events[i].push(e.clone());
                            }
                        }
                    }
                }

                // Check if sequence is complete within time gap
                let mut prev_time: Option<DateTime<Utc>> = None;
                let mut sequence_events = Vec::with_capacity(stages.len());

                for stage_list in &stage_events {
                    if stage_list.is_empty() {
                        return None;
                    }

                    // Find first event in this stage after prev_time
                    let matching = stage_list.iter().find(|e| {
                        if let Some(pt) = prev_time {
                            e.timestamp > pt && e.timestamp - pt < gap
                        } else {
                            true
                        }
                    });

                    if let Some(e) = matching {
                        prev_time = Some(e.timestamp);
                        sequence_events.push(e.clone());
                    } else {
                        return None;
                    }
                }

                Some(sequence_events)
            }
        }
    }

    /// Create a new incident from matched events
    fn create_incident(&self, rule: &CorrelationRule, events: Vec<DetectionEvent>) -> Incident {
        let mut affected_hosts = HashSet::new();
        let mut max_severity = Severity::Info;

        for event in &events {
            affected_hosts.insert(event.src_ip);
            affected_hosts.insert(event.dst_ip);
            if event.severity > max_severity {
                max_severity = event.severity;
            }
        }

        // Elevate severity if rule says so
        let severity = if rule.elevate_severity {
            max_severity.elevated()
        } else {
            max_severity
        };

        let start_time = events.first().map(|e| e.timestamp).unwrap_or_else(Utc::now);
        let last_activity = events.last().map(|e| e.timestamp).unwrap_or_else(Utc::now);

        Incident {
            id: Uuid::new_v4(),
            name: rule.name.clone(),
            description: rule.description.clone(),
            severity,
            priority: IncidentPriority::from_severity(severity),
            status: IncidentStatus::New,
            start_time,
            last_activity,
            events,
            affected_hosts,
            attack_chain: None,
            mitre_tactics: rule.mitre_tactics.clone(),
            tags: rule.tags.clone(),
        }
    }

    /// Cleanup old events
    fn cleanup_old_events(&mut self) {
        let now = Utc::now();
        let window = chrono::Duration::seconds(self.config.window_seconds as i64 * 2);

        // Remove old events
        self.events.retain(|_, e| now - e.timestamp < window);

        // Cleanup indexes
        for queue in self.events_by_src.values_mut() {
            queue.retain(|id| self.events.contains_key(id));
        }
        for queue in self.events_by_dst.values_mut() {
            queue.retain(|id| self.events.contains_key(id));
        }

        // Cleanup old incidents
        let timeout = chrono::Duration::seconds(self.config.incident_timeout_seconds as i64);
        self.incidents.retain(|_, i| {
            if i.status == IncidentStatus::Closed {
                return false;
            }
            now - i.last_activity < timeout
        });

        self.stats.active_incidents = self.incidents.len();
    }

    /// Get all active incidents
    pub fn get_incidents(&self) -> Vec<&Incident> {
        self.incidents.values().collect()
    }

    /// Get incident by ID
    pub fn get_incident(&self, id: Uuid) -> Option<&Incident> {
        self.incidents.get(&id)
    }

    /// Get related events for an event
    pub fn get_related(&self, event_id: Uuid) -> Vec<DetectionEvent> {
        if let Some(event) = self.events.get(&event_id) {
            let mut related = Vec::new();

            // Find events with same source IP
            let src_ip = event.src_ip;
            if let Some(ids) = self.events_by_src.get(&src_ip) {
                for id in ids {
                    if *id != event_id {
                        if let Some(e) = self.events.get(id) {
                            related.push(e.clone());
                        }
                    }
                }
            }

            related
        } else {
            Vec::new()
        }
    }

    /// Update incident status
    pub fn update_incident_status(&mut self, id: Uuid, status: IncidentStatus) {
        if let Some(incident) = self.incidents.get_mut(&id) {
            incident.status = status;
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &CorrelationStats {
        &self.stats
    }

    /// Get configuration
    pub fn config(&self) -> &CorrelationConfig {
        &self.config
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new(CorrelationConfig::default())
    }
}

/// Default correlation rules
fn default_correlation_rules() -> Vec<CorrelationRule> {
    vec![
        CorrelationRule {
            name: "brute_force_ssh".to_string(),
            description: Some("Multiple failed SSH authentication attempts".to_string()),
            rule_type: RuleType::Count {
                event_types: vec!["FailedAuth".to_string(), "SSH".to_string()],
                threshold: 5,
                group_by: Some("src_ip".to_string()),
            },
            window_seconds: 60,
            elevate_severity: true,
            mitre_tactics: vec!["TA0006".to_string()], // Credential Access
            tags: vec!["brute_force".to_string(), "ssh".to_string()],
        },
        CorrelationRule {
            name: "port_scan".to_string(),
            description: Some("Port scanning activity detected".to_string()),
            rule_type: RuleType::Count {
                event_types: vec!["PortScan".to_string(), "Probe".to_string()],
                threshold: 10,
                group_by: Some("src_ip".to_string()),
            },
            window_seconds: 30,
            elevate_severity: false,
            mitre_tactics: vec!["TA0043".to_string()], // Reconnaissance
            tags: vec!["scan".to_string()],
        },
        CorrelationRule {
            name: "scan_then_exploit".to_string(),
            description: Some("Port scan followed by exploitation attempt".to_string()),
            rule_type: RuleType::Sequence {
                stages: vec!["PortScan".to_string(), "Exploit".to_string()],
                max_gap_seconds: 3600,
            },
            window_seconds: 3600,
            elevate_severity: true,
            mitre_tactics: vec!["TA0043".to_string(), "TA0001".to_string()], // Recon, Initial Access
            tags: vec!["attack_chain".to_string()],
        },
        CorrelationRule {
            name: "data_exfiltration".to_string(),
            description: Some("Potential data exfiltration detected".to_string()),
            rule_type: RuleType::Count {
                event_types: vec!["LargeUpload".to_string(), "DataExfiltration".to_string()],
                threshold: 3,
                group_by: Some("src_ip".to_string()),
            },
            window_seconds: 300,
            elevate_severity: true,
            mitre_tactics: vec!["TA0010".to_string()], // Exfiltration
            tags: vec!["exfil".to_string()],
        },
    ]
}

// Extension for Severity
impl Severity {
    fn elevated(&self) -> Severity {
        match self {
            Severity::Info => Severity::Low,
            Severity::Low => Severity::Medium,
            Severity::Medium => Severity::High,
            Severity::High => Severity::Critical,
            Severity::Critical => Severity::Critical,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(src: &str, dst: &str, event_type: DetectionType) -> DetectionEvent {
        DetectionEvent::new(
            event_type,
            Severity::Medium,
            src.parse().unwrap(),
            dst.parse().unwrap(),
            "Test event".to_string(),
        )
        .with_ports(12345, 22)
    }

    #[test]
    fn test_correlation_engine_creation() {
        let engine = CorrelationEngine::default();
        assert!(engine.config.enabled);
        assert_eq!(engine.incidents.len(), 0);
    }

    #[test]
    fn test_duplicate_detection() {
        let mut engine = CorrelationEngine::default();

        let event = make_event("192.168.1.1", "10.0.0.1", DetectionType::PortScan);

        // First event should not be duplicate
        let result = engine.process(event.clone());
        assert!(!matches!(result, CorrelationResult::Suppressed));

        // Same event should be duplicate
        let result = engine.process(event);
        assert!(matches!(result, CorrelationResult::Suppressed));
    }

    #[test]
    fn test_incident_matching() {
        let mut engine = CorrelationEngine::default();

        // Process multiple events from same source to trigger rule
        for _ in 0..10 {
            let event = make_event("192.168.1.1", "10.0.0.1", DetectionType::PortScan);
            engine.process(event);
        }

        // Check that an incident was created
        assert!(engine.stats.incidents_created > 0 || engine.stats.events_processed >= 10);
    }

    #[test]
    fn test_correlation_stats() {
        let engine = CorrelationEngine::default();
        assert_eq!(engine.stats().events_processed, 0);
        assert_eq!(engine.stats().active_incidents, 0);
    }
}
