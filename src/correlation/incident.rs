//! Incident management
//!
//! Groups related events into incidents for investigation.

use std::collections::HashSet;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::chains::AttackChain;
use crate::core::{DetectionEvent, Severity};

/// Status of an incident
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncidentStatus {
    /// Newly created
    New,
    /// Under investigation
    Investigating,
    /// Escalated to higher tier
    Escalated,
    /// Confirmed as true positive
    Confirmed,
    /// Closed as false positive
    FalsePositive,
    /// Closed, mitigated
    Mitigated,
    /// Closed, resolved
    Closed,
}

impl IncidentStatus {
    /// Check if incident is active
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            IncidentStatus::New | IncidentStatus::Investigating | IncidentStatus::Escalated
        )
    }

    /// Check if incident is closed
    pub fn is_closed(&self) -> bool {
        matches!(
            self,
            IncidentStatus::FalsePositive | IncidentStatus::Mitigated | IncidentStatus::Closed
        )
    }

    /// Get status string
    pub fn as_str(&self) -> &'static str {
        match self {
            IncidentStatus::New => "new",
            IncidentStatus::Investigating => "investigating",
            IncidentStatus::Escalated => "escalated",
            IncidentStatus::Confirmed => "confirmed",
            IncidentStatus::FalsePositive => "false_positive",
            IncidentStatus::Mitigated => "mitigated",
            IncidentStatus::Closed => "closed",
        }
    }
}

impl Default for IncidentStatus {
    fn default() -> Self {
        IncidentStatus::New
    }
}

/// Priority of an incident
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum IncidentPriority {
    /// Low priority (P4)
    Low,
    /// Medium priority (P3)
    Medium,
    /// High priority (P2)
    High,
    /// Critical priority (P1)
    Critical,
}

impl IncidentPriority {
    /// Create from severity
    pub fn from_severity(severity: Severity) -> Self {
        match severity {
            Severity::Info | Severity::Low => IncidentPriority::Low,
            Severity::Medium => IncidentPriority::Medium,
            Severity::High => IncidentPriority::High,
            Severity::Critical => IncidentPriority::Critical,
        }
    }

    /// Get SLA response time in minutes
    pub fn response_sla_minutes(&self) -> u32 {
        match self {
            IncidentPriority::Critical => 15,
            IncidentPriority::High => 60,
            IncidentPriority::Medium => 240,
            IncidentPriority::Low => 1440, // 24 hours
        }
    }

    /// Get as P-level string
    pub fn as_str(&self) -> &'static str {
        match self {
            IncidentPriority::Critical => "P1",
            IncidentPriority::High => "P2",
            IncidentPriority::Medium => "P3",
            IncidentPriority::Low => "P4",
        }
    }
}

impl Default for IncidentPriority {
    fn default() -> Self {
        IncidentPriority::Medium
    }
}

/// A security incident grouping related events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    /// Unique incident ID
    pub id: Uuid,
    /// Incident name/title
    pub name: String,
    /// Incident description
    pub description: Option<String>,
    /// Overall severity
    pub severity: Severity,
    /// Priority level
    pub priority: IncidentPriority,
    /// Current status
    pub status: IncidentStatus,
    /// When incident started
    pub start_time: DateTime<Utc>,
    /// Last activity time
    pub last_activity: DateTime<Utc>,
    /// Events in this incident
    pub events: Vec<DetectionEvent>,
    /// Affected hosts (IPs)
    pub affected_hosts: HashSet<IpAddr>,
    /// Detected attack chain
    pub attack_chain: Option<AttackChain>,
    /// MITRE ATT&CK tactics observed
    pub mitre_tactics: Vec<String>,
    /// Tags
    pub tags: Vec<String>,
}

impl Incident {
    /// Create a new incident
    pub fn new(name: String, first_event: DetectionEvent) -> Self {
        let mut affected_hosts = HashSet::new();
        affected_hosts.insert(first_event.src_ip);
        affected_hosts.insert(first_event.dst_ip);

        Self {
            id: Uuid::new_v4(),
            name,
            description: None,
            severity: first_event.severity,
            priority: IncidentPriority::from_severity(first_event.severity),
            status: IncidentStatus::New,
            start_time: first_event.timestamp,
            last_activity: first_event.timestamp,
            events: vec![first_event],
            affected_hosts,
            attack_chain: None,
            mitre_tactics: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Add an event to the incident
    pub fn add_event(&mut self, event: DetectionEvent) {
        // Update affected hosts
        self.affected_hosts.insert(event.src_ip);
        self.affected_hosts.insert(event.dst_ip);

        // Update severity if higher
        if event.severity > self.severity {
            self.severity = event.severity;
            self.priority = IncidentPriority::from_severity(self.severity);
        }

        // Update last activity
        self.last_activity = event.timestamp;

        // Add event
        self.events.push(event);
    }

    /// Get incident duration
    pub fn duration(&self) -> chrono::Duration {
        self.last_activity - self.start_time
    }

    /// Get event count
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Check if incident is active
    pub fn is_active(&self) -> bool {
        self.status.is_active()
    }

    /// Get unique source IPs
    pub fn source_ips(&self) -> HashSet<IpAddr> {
        self.events
            .iter()
            .map(|e| e.src_ip)
            .collect()
    }

    /// Get unique destination IPs
    pub fn destination_ips(&self) -> HashSet<IpAddr> {
        self.events
            .iter()
            .map(|e| e.dst_ip)
            .collect()
    }

    /// Get time since last activity
    pub fn idle_time(&self) -> chrono::Duration {
        Utc::now() - self.last_activity
    }

    /// Add a tag
    pub fn add_tag(&mut self, tag: &str) {
        if !self.tags.contains(&tag.to_string()) {
            self.tags.push(tag.to_string());
        }
    }

    /// Check if has a specific tag
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }

    /// Get summary string
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} - {} events, {} hosts affected, {} severity",
            self.priority.as_str(),
            self.name,
            self.events.len(),
            self.affected_hosts.len(),
            self.severity,
        )
    }
}

impl Default for Incident {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "Unknown Incident".to_string(),
            description: None,
            severity: Severity::Medium,
            priority: IncidentPriority::Medium,
            status: IncidentStatus::New,
            start_time: Utc::now(),
            last_activity: Utc::now(),
            events: Vec::new(),
            affected_hosts: HashSet::new(),
            attack_chain: None,
            mitre_tactics: Vec::new(),
            tags: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::DetectionType;

    fn make_event(severity: Severity) -> DetectionEvent {
        DetectionEvent::new(
            DetectionType::PortScan,
            severity,
            "192.168.1.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "Test event".to_string(),
        )
        .with_ports(12345, 22)
    }

    #[test]
    fn test_incident_creation() {
        let event = make_event(Severity::Medium);
        let incident = Incident::new("Test Incident".to_string(), event);

        assert_eq!(incident.name, "Test Incident");
        assert_eq!(incident.status, IncidentStatus::New);
        assert_eq!(incident.events.len(), 1);
        assert_eq!(incident.affected_hosts.len(), 2);
    }

    #[test]
    fn test_incident_add_event() {
        let event1 = make_event(Severity::Low);
        let mut incident = Incident::new("Test".to_string(), event1);

        let event2 = make_event(Severity::High);
        incident.add_event(event2);

        assert_eq!(incident.events.len(), 2);
        assert_eq!(incident.severity, Severity::High);
        assert_eq!(incident.priority, IncidentPriority::High);
    }

    #[test]
    fn test_incident_status() {
        assert!(IncidentStatus::New.is_active());
        assert!(IncidentStatus::Investigating.is_active());
        assert!(!IncidentStatus::Closed.is_active());
        assert!(IncidentStatus::Closed.is_closed());
    }

    #[test]
    fn test_incident_priority() {
        assert_eq!(
            IncidentPriority::from_severity(Severity::Critical),
            IncidentPriority::Critical
        );
        assert_eq!(
            IncidentPriority::from_severity(Severity::Low),
            IncidentPriority::Low
        );
    }

    #[test]
    fn test_incident_tags() {
        let event = make_event(Severity::Medium);
        let mut incident = Incident::new("Test".to_string(), event);

        incident.add_tag("ssh");
        incident.add_tag("brute_force");
        incident.add_tag("ssh"); // Duplicate

        assert_eq!(incident.tags.len(), 2);
        assert!(incident.has_tag("ssh"));
        assert!(!incident.has_tag("unknown"));
    }
}
