//! Attack chain detection
//!
//! Detects multi-stage attacks aligned with MITRE ATT&CK framework.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::incident::Incident;
use crate::core::event::DetectionType;

/// MITRE ATT&CK Tactic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MitreTactic {
    /// Reconnaissance (TA0043)
    Reconnaissance,
    /// Resource Development (TA0042)
    ResourceDevelopment,
    /// Initial Access (TA0001)
    InitialAccess,
    /// Execution (TA0002)
    Execution,
    /// Persistence (TA0003)
    Persistence,
    /// Privilege Escalation (TA0004)
    PrivilegeEscalation,
    /// Defense Evasion (TA0005)
    DefenseEvasion,
    /// Credential Access (TA0006)
    CredentialAccess,
    /// Discovery (TA0007)
    Discovery,
    /// Lateral Movement (TA0008)
    LateralMovement,
    /// Collection (TA0009)
    Collection,
    /// Command and Control (TA0011)
    CommandAndControl,
    /// Exfiltration (TA0010)
    Exfiltration,
    /// Impact (TA0040)
    Impact,
}

impl MitreTactic {
    /// Get tactic ID
    pub fn id(&self) -> &'static str {
        match self {
            MitreTactic::Reconnaissance => "TA0043",
            MitreTactic::ResourceDevelopment => "TA0042",
            MitreTactic::InitialAccess => "TA0001",
            MitreTactic::Execution => "TA0002",
            MitreTactic::Persistence => "TA0003",
            MitreTactic::PrivilegeEscalation => "TA0004",
            MitreTactic::DefenseEvasion => "TA0005",
            MitreTactic::CredentialAccess => "TA0006",
            MitreTactic::Discovery => "TA0007",
            MitreTactic::LateralMovement => "TA0008",
            MitreTactic::Collection => "TA0009",
            MitreTactic::CommandAndControl => "TA0011",
            MitreTactic::Exfiltration => "TA0010",
            MitreTactic::Impact => "TA0040",
        }
    }

    /// Get tactic name
    pub fn name(&self) -> &'static str {
        match self {
            MitreTactic::Reconnaissance => "Reconnaissance",
            MitreTactic::ResourceDevelopment => "Resource Development",
            MitreTactic::InitialAccess => "Initial Access",
            MitreTactic::Execution => "Execution",
            MitreTactic::Persistence => "Persistence",
            MitreTactic::PrivilegeEscalation => "Privilege Escalation",
            MitreTactic::DefenseEvasion => "Defense Evasion",
            MitreTactic::CredentialAccess => "Credential Access",
            MitreTactic::Discovery => "Discovery",
            MitreTactic::LateralMovement => "Lateral Movement",
            MitreTactic::Collection => "Collection",
            MitreTactic::CommandAndControl => "Command and Control",
            MitreTactic::Exfiltration => "Exfiltration",
            MitreTactic::Impact => "Impact",
        }
    }

    /// Get typical order in kill chain (lower = earlier)
    pub fn order(&self) -> u8 {
        match self {
            MitreTactic::Reconnaissance => 1,
            MitreTactic::ResourceDevelopment => 2,
            MitreTactic::InitialAccess => 3,
            MitreTactic::Execution => 4,
            MitreTactic::Persistence => 5,
            MitreTactic::PrivilegeEscalation => 6,
            MitreTactic::DefenseEvasion => 7,
            MitreTactic::CredentialAccess => 8,
            MitreTactic::Discovery => 9,
            MitreTactic::LateralMovement => 10,
            MitreTactic::Collection => 11,
            MitreTactic::CommandAndControl => 12,
            MitreTactic::Exfiltration => 13,
            MitreTactic::Impact => 14,
        }
    }

    /// Map detection type to potential tactic
    pub fn from_detection_type(dt: &DetectionType) -> Option<Self> {
        match dt {
            // Reconnaissance
            DetectionType::PortScan | DetectionType::NetworkScan => {
                Some(MitreTactic::Reconnaissance)
            }
            // Initial Access / Exploitation
            DetectionType::ExploitAttempt | DetectionType::Overflow | DetectionType::Shellcode => {
                Some(MitreTactic::InitialAccess)
            }
            DetectionType::SignatureMatch | DetectionType::ProtocolAnomaly => {
                Some(MitreTactic::InitialAccess)
            }
            // Credential Access
            DetectionType::BruteForce => {
                Some(MitreTactic::CredentialAccess)
            }
            // Execution / Malware
            DetectionType::MalwareDownload | DetectionType::MalwareCallback => {
                Some(MitreTactic::Execution)
            }
            // Command and Control
            DetectionType::CnC | DetectionType::Beaconing => {
                Some(MitreTactic::CommandAndControl)
            }
            // Exfiltration
            DetectionType::DataExfiltration => {
                Some(MitreTactic::Exfiltration)
            }
            // Impact
            DetectionType::DDoS => Some(MitreTactic::Impact),
            // Lateral Movement
            DetectionType::LateralMovement => Some(MitreTactic::LateralMovement),
            // Policy / Access
            DetectionType::UnauthorizedAccess | DetectionType::PolicyViolation => {
                Some(MitreTactic::PrivilegeEscalation)
            }
            // Threat Intel matches
            DetectionType::ThreatIntelMatch | DetectionType::MaliciousIp |
            DetectionType::MaliciousDomain | DetectionType::MaliciousUrl |
            DetectionType::MaliciousHash | DetectionType::MaliciousJa3 => {
                Some(MitreTactic::CommandAndControl)
            }
            // Anomalies
            DetectionType::AnomalyDetection | DetectionType::BehaviorAnomaly |
            DetectionType::TrafficAnomaly | DetectionType::MalformedPacket => None,
            // Custom
            DetectionType::Custom(_) => None,
        }
    }
}

/// A stage in an attack chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStage {
    /// Tactic for this stage
    pub tactic: MitreTactic,
    /// When this stage was first observed
    pub first_seen: DateTime<Utc>,
    /// When this stage was last seen
    pub last_seen: DateTime<Utc>,
    /// Number of events in this stage
    pub event_count: usize,
    /// Confidence level (0.0-1.0)
    pub confidence: f32,
}

/// An identified attack chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackChain {
    /// Chain name (e.g., "APT-like intrusion")
    pub name: String,
    /// Stages in the chain
    pub stages: Vec<AttackStage>,
    /// Overall confidence
    pub confidence: f32,
    /// How far through the kill chain
    pub progression: f32,
    /// Chain start time
    pub start_time: DateTime<Utc>,
    /// Most recent activity
    pub last_activity: DateTime<Utc>,
}

impl AttackChain {
    /// Get the current stage
    pub fn current_stage(&self) -> Option<&AttackStage> {
        self.stages.last()
    }

    /// Get the highest tactic reached
    pub fn highest_tactic(&self) -> Option<MitreTactic> {
        self.stages.iter().map(|s| s.tactic).max_by_key(|t| t.order())
    }

    /// Check if chain includes exfiltration or impact
    pub fn is_severe(&self) -> bool {
        self.stages.iter().any(|s| {
            matches!(
                s.tactic,
                MitreTactic::Exfiltration | MitreTactic::Impact | MitreTactic::CommandAndControl
            )
        })
    }
}

/// Attack chain detector
pub struct ChainDetector {
    /// Known chain patterns
    patterns: Vec<ChainPattern>,
}

/// A pattern for detecting attack chains
struct ChainPattern {
    name: String,
    required_tactics: Vec<MitreTactic>,
    optional_tactics: Vec<MitreTactic>,
    min_stages: usize,
    description: String,
}

impl ChainDetector {
    /// Create a new chain detector
    pub fn new() -> Self {
        Self {
            patterns: default_patterns(),
        }
    }

    /// Check if incident shows attack chain progression
    pub fn check_progression(&self, incident: &Incident) -> Option<AttackChain> {
        // Extract tactics from incident events
        let mut tactic_events: HashMap<MitreTactic, Vec<DateTime<Utc>>> = HashMap::new();

        for event in &incident.events {
            if let Some(tactic) = MitreTactic::from_detection_type(&event.event_type) {
                tactic_events
                    .entry(tactic)
                    .or_insert_with(Vec::new)
                    .push(event.timestamp);
            }
        }

        if tactic_events.is_empty() {
            return None;
        }

        // Find best matching pattern
        let mut best_match: Option<(AttackChain, f32)> = None;

        for pattern in &self.patterns {
            if let Some((chain, score)) = self.match_pattern(pattern, &tactic_events) {
                if best_match.as_ref().map(|(_, s)| *s < score).unwrap_or(true) {
                    best_match = Some((chain, score));
                }
            }
        }

        best_match.map(|(chain, _)| chain)
    }

    /// Match a pattern against observed tactics
    fn match_pattern(
        &self,
        pattern: &ChainPattern,
        tactic_events: &HashMap<MitreTactic, Vec<DateTime<Utc>>>,
    ) -> Option<(AttackChain, f32)> {
        // Check minimum required tactics
        let mut matched_required = 0;
        for tactic in &pattern.required_tactics {
            if tactic_events.contains_key(tactic) {
                matched_required += 1;
            }
        }

        // Need at least min_stages of required tactics
        if matched_required < pattern.min_stages {
            return None;
        }

        // Build stages
        let mut stages: Vec<AttackStage> = Vec::new();

        for tactic in &pattern.required_tactics {
            if let Some(timestamps) = tactic_events.get(tactic) {
                let first_seen = *timestamps.iter().min()?;
                let last_seen = *timestamps.iter().max()?;

                stages.push(AttackStage {
                    tactic: *tactic,
                    first_seen,
                    last_seen,
                    event_count: timestamps.len(),
                    confidence: 0.8,
                });
            }
        }

        // Add optional tactics that were observed
        for tactic in &pattern.optional_tactics {
            if let Some(timestamps) = tactic_events.get(tactic) {
                let first_seen = *timestamps.iter().min()?;
                let last_seen = *timestamps.iter().max()?;

                stages.push(AttackStage {
                    tactic: *tactic,
                    first_seen,
                    last_seen,
                    event_count: timestamps.len(),
                    confidence: 0.6,
                });
            }
        }

        // Sort by tactic order
        stages.sort_by_key(|s| s.tactic.order());

        if stages.is_empty() {
            return None;
        }

        // Calculate confidence
        let required_match_ratio = matched_required as f32 / pattern.required_tactics.len() as f32;
        let confidence = (required_match_ratio * 0.7 + 0.3).min(1.0);

        // Calculate progression through kill chain
        let max_order = stages.iter().map(|s| s.tactic.order()).max().unwrap_or(1);
        let progression = max_order as f32 / 14.0; // 14 total tactics

        let start_time = stages.iter().map(|s| s.first_seen).min()?;
        let last_activity = stages.iter().map(|s| s.last_seen).max()?;

        Some((
            AttackChain {
                name: pattern.name.clone(),
                stages,
                confidence,
                progression,
                start_time,
                last_activity,
            },
            confidence,
        ))
    }

    /// Detect chain from single incident
    pub fn detect(&self, incident: &Incident) -> Option<AttackChain> {
        self.check_progression(incident)
    }
}

impl Default for ChainDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Default attack chain patterns
fn default_patterns() -> Vec<ChainPattern> {
    vec![
        ChainPattern {
            name: "APT-style Intrusion".to_string(),
            required_tactics: vec![
                MitreTactic::Reconnaissance,
                MitreTactic::InitialAccess,
            ],
            optional_tactics: vec![
                MitreTactic::Execution,
                MitreTactic::Persistence,
                MitreTactic::PrivilegeEscalation,
                MitreTactic::CommandAndControl,
                MitreTactic::Exfiltration,
            ],
            min_stages: 2,
            description: "Multi-stage intrusion with reconnaissance and exploitation".to_string(),
        },
        ChainPattern {
            name: "Credential Theft".to_string(),
            required_tactics: vec![
                MitreTactic::CredentialAccess,
            ],
            optional_tactics: vec![
                MitreTactic::LateralMovement,
                MitreTactic::PrivilegeEscalation,
            ],
            min_stages: 1,
            description: "Credential theft potentially leading to lateral movement".to_string(),
        },
        ChainPattern {
            name: "Data Breach".to_string(),
            required_tactics: vec![
                MitreTactic::Collection,
                MitreTactic::Exfiltration,
            ],
            optional_tactics: vec![
                MitreTactic::CommandAndControl,
            ],
            min_stages: 1,
            description: "Data collection and exfiltration".to_string(),
        },
        ChainPattern {
            name: "Ransomware-like Attack".to_string(),
            required_tactics: vec![
                MitreTactic::Execution,
                MitreTactic::Impact,
            ],
            optional_tactics: vec![
                MitreTactic::InitialAccess,
                MitreTactic::PrivilegeEscalation,
                MitreTactic::DefenseEvasion,
            ],
            min_stages: 2,
            description: "Execution leading to impact (encryption, destruction)".to_string(),
        },
        ChainPattern {
            name: "C2 Activity".to_string(),
            required_tactics: vec![
                MitreTactic::CommandAndControl,
            ],
            optional_tactics: vec![
                MitreTactic::Exfiltration,
                MitreTactic::Execution,
            ],
            min_stages: 1,
            description: "Command and control communication detected".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tactic_order() {
        assert!(MitreTactic::Reconnaissance.order() < MitreTactic::InitialAccess.order());
        assert!(MitreTactic::InitialAccess.order() < MitreTactic::Exfiltration.order());
    }

    #[test]
    fn test_tactic_from_detection_type() {
        assert_eq!(
            MitreTactic::from_detection_type(&DetectionType::PortScan),
            Some(MitreTactic::Reconnaissance)
        );
        assert_eq!(
            MitreTactic::from_detection_type(&DetectionType::ExploitAttempt),
            Some(MitreTactic::InitialAccess)
        );
        assert_eq!(
            MitreTactic::from_detection_type(&DetectionType::CnC),
            Some(MitreTactic::CommandAndControl)
        );
    }

    #[test]
    fn test_chain_detector_creation() {
        let detector = ChainDetector::new();
        assert!(!detector.patterns.is_empty());
    }
}
