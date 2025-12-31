//! SSH CVE database for vulnerability detection
//!
//! Loads and matches SSH server/client versions against known CVEs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::fs;
use tracing::info;

/// SSH CVE database
#[derive(Debug, Default)]
pub struct SshCveDatabase {
    /// CVE entries indexed by software name (lowercase)
    entries: HashMap<String, Vec<CveEntry>>,
    /// Statistics
    stats: CveStats,
}

/// Individual CVE entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    /// CVE identifier (e.g., "CVE-2023-38408")
    pub cve_id: String,
    /// Software name pattern (e.g., "openssh")
    pub software: String,
    /// Minimum affected version (inclusive)
    pub version_min: Option<SemVer>,
    /// Maximum affected version (inclusive)
    pub version_max: Option<SemVer>,
    /// Fixed version (if known)
    pub version_fixed: Option<SemVer>,
    /// CVSS score (0.0 - 10.0)
    pub cvss: f32,
    /// Severity level
    pub severity: CveSeverity,
    /// Short description
    pub description: String,
    /// Attack vector
    pub attack_vector: AttackVector,
    /// References (URLs)
    pub references: Vec<String>,
}

/// CVE severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CveSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl CveSeverity {
    pub fn from_cvss(cvss: f32) -> Self {
        if cvss >= 9.0 {
            CveSeverity::Critical
        } else if cvss >= 7.0 {
            CveSeverity::High
        } else if cvss >= 4.0 {
            CveSeverity::Medium
        } else {
            CveSeverity::Low
        }
    }
}

impl std::fmt::Display for CveSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CveSeverity::Low => write!(f, "low"),
            CveSeverity::Medium => write!(f, "medium"),
            CveSeverity::High => write!(f, "high"),
            CveSeverity::Critical => write!(f, "critical"),
        }
    }
}

/// Attack vector for CVE
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AttackVector {
    #[default]
    Network,
    AdjacentNetwork,
    Local,
    Physical,
}

/// Semantic version for comparison
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub extra: Option<String>,
}

impl SemVer {
    /// Parse version from string (e.g., "8.9p1" -> 8.9.1)
    pub fn parse(s: &str) -> Option<Self> {
        // Handle OpenSSH format like "8.9p1" or "9.0"
        let cleaned = s.trim()
            .replace("p", ".")
            .replace("P", ".");

        let parts: Vec<&str> = cleaned.split('.').collect();
        if parts.is_empty() {
            return None;
        }

        let major = parts.get(0).and_then(|s| s.parse().ok()).unwrap_or(0);
        let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let patch = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);

        // Extract extra suffix if present (after patch number)
        let extra = if parts.len() > 3 {
            Some(parts[3..].join("."))
        } else {
            None
        };

        Some(Self { major, minor, patch, extra })
    }

    /// Extract version from software string (e.g., "OpenSSH_8.9p1" -> "8.9p1")
    pub fn from_software(software: &str) -> Option<Self> {
        // Find the first digit and extract version from there
        let start = software.find(|c: char| c.is_ascii_digit())?;
        let version_str = &software[start..];

        // Find end of version (first non-version character)
        let end = version_str.find(|c: char| !c.is_ascii_digit() && c != '.' && c != 'p' && c != 'P')
            .unwrap_or(version_str.len());

        Self::parse(&version_str[..end])
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemVer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.major.cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
    }
}

impl std::fmt::Display for SemVer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(ref extra) = self.extra {
            write!(f, "-{}", extra)?;
        }
        Ok(())
    }
}

/// CVE database statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CveStats {
    pub total_entries: usize,
    pub by_software: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
}

/// Result of CVE lookup
#[derive(Debug, Clone)]
pub struct CveLookupResult {
    /// Matched CVEs
    pub cves: Vec<CveEntry>,
    /// Highest severity found
    pub max_severity: CveSeverity,
    /// Highest CVSS score
    pub max_cvss: f32,
}

impl SshCveDatabase {
    /// Create a new empty database
    pub fn new() -> Self {
        Self::default()
    }

    /// Load CVE database from JSON file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, CveError> {
        let path = path.as_ref();
        info!(path = %path.display(), "Loading SSH CVE database");

        let content = fs::read_to_string(path)
            .map_err(|e| CveError::IoError(e.to_string()))?;

        Self::load_from_json(&content)
    }

    /// Load CVE database from JSON string
    pub fn load_from_json(json: &str) -> Result<Self, CveError> {
        let entries: Vec<CveEntry> = serde_json::from_str(json)
            .map_err(|e| CveError::ParseError(e.to_string()))?;

        let mut db = Self::new();
        for entry in entries {
            db.add_entry(entry);
        }

        info!(entries = db.stats.total_entries, "SSH CVE database loaded");
        Ok(db)
    }

    /// Load database with embedded well-known CVEs
    pub fn load_embedded() -> Self {
        let mut db = Self::new();

        // Add critical OpenSSH CVEs
        db.add_entry(CveEntry {
            cve_id: "CVE-2024-6387".into(),
            software: "openssh".into(),
            version_min: Some(SemVer { major: 8, minor: 5, patch: 0, extra: None }),
            version_max: Some(SemVer { major: 9, minor: 7, patch: 0, extra: None }),
            version_fixed: Some(SemVer { major: 9, minor: 8, patch: 0, extra: None }),
            cvss: 8.1,
            severity: CveSeverity::High,
            description: "RegreSSHion - Race condition in signal handler allows RCE".into(),
            attack_vector: AttackVector::Network,
            references: vec!["https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt".into()],
        });

        db.add_entry(CveEntry {
            cve_id: "CVE-2023-38408".into(),
            software: "openssh".into(),
            version_min: None,
            version_max: Some(SemVer { major: 9, minor: 3, patch: 2, extra: None }),
            version_fixed: Some(SemVer { major: 9, minor: 3, patch: 2, extra: None }),
            cvss: 9.8,
            severity: CveSeverity::Critical,
            description: "PKCS#11 feature allows RCE via forwarded agent-socket".into(),
            attack_vector: AttackVector::Network,
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-38408".into()],
        });

        db.add_entry(CveEntry {
            cve_id: "CVE-2021-41617".into(),
            software: "openssh".into(),
            version_min: Some(SemVer { major: 6, minor: 2, patch: 0, extra: None }),
            version_max: Some(SemVer { major: 8, minor: 7, patch: 0, extra: None }),
            version_fixed: Some(SemVer { major: 8, minor: 8, patch: 0, extra: None }),
            cvss: 7.0,
            severity: CveSeverity::High,
            description: "Privilege escalation via AuthorizedKeysCommand".into(),
            attack_vector: AttackVector::Local,
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-41617".into()],
        });

        db.add_entry(CveEntry {
            cve_id: "CVE-2020-15778".into(),
            software: "openssh".into(),
            version_min: None,
            version_max: Some(SemVer { major: 8, minor: 3, patch: 1, extra: None }),
            version_fixed: Some(SemVer { major: 8, minor: 4, patch: 0, extra: None }),
            cvss: 7.8,
            severity: CveSeverity::High,
            description: "Command injection via scp with backticks in filename".into(),
            attack_vector: AttackVector::Network,
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-15778".into()],
        });

        db.add_entry(CveEntry {
            cve_id: "CVE-2016-20012".into(),
            software: "openssh".into(),
            version_min: None,
            version_max: Some(SemVer { major: 8, minor: 7, patch: 0, extra: None }),
            version_fixed: None,
            cvss: 5.3,
            severity: CveSeverity::Medium,
            description: "Username enumeration via timing attack".into(),
            attack_vector: AttackVector::Network,
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2016-20012".into()],
        });

        // Dropbear CVEs
        db.add_entry(CveEntry {
            cve_id: "CVE-2023-48795".into(),
            software: "dropbear".into(),
            version_min: None,
            version_max: Some(SemVer { major: 2022, minor: 83, patch: 0, extra: None }),
            version_fixed: Some(SemVer { major: 2024, minor: 84, patch: 0, extra: None }),
            cvss: 5.9,
            severity: CveSeverity::Medium,
            description: "Terrapin attack - Prefix truncation in SSH BPP".into(),
            attack_vector: AttackVector::Network,
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-48795".into()],
        });

        // Also add Terrapin for OpenSSH
        db.add_entry(CveEntry {
            cve_id: "CVE-2023-48795".into(),
            software: "openssh".into(),
            version_min: None,
            version_max: Some(SemVer { major: 9, minor: 5, patch: 0, extra: None }),
            version_fixed: Some(SemVer { major: 9, minor: 6, patch: 0, extra: None }),
            cvss: 5.9,
            severity: CveSeverity::Medium,
            description: "Terrapin attack - Prefix truncation in SSH BPP".into(),
            attack_vector: AttackVector::Network,
            references: vec!["https://terrapin-attack.com/".into()],
        });

        // libssh CVEs
        db.add_entry(CveEntry {
            cve_id: "CVE-2018-10933".into(),
            software: "libssh".into(),
            version_min: Some(SemVer { major: 0, minor: 6, patch: 0, extra: None }),
            version_max: Some(SemVer { major: 0, minor: 8, patch: 3, extra: None }),
            version_fixed: Some(SemVer { major: 0, minor: 8, patch: 4, extra: None }),
            cvss: 9.1,
            severity: CveSeverity::Critical,
            description: "Authentication bypass by sending SSH2_MSG_USERAUTH_SUCCESS".into(),
            attack_vector: AttackVector::Network,
            references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2018-10933".into()],
        });

        // SSH-1 protocol (deprecated/insecure)
        db.add_entry(CveEntry {
            cve_id: "SSH-1-DEPRECATED".into(),
            software: "ssh".into(),
            version_min: Some(SemVer { major: 1, minor: 0, patch: 0, extra: None }),
            version_max: Some(SemVer { major: 1, minor: 99, patch: 0, extra: None }),
            version_fixed: Some(SemVer { major: 2, minor: 0, patch: 0, extra: None }),
            cvss: 10.0,
            severity: CveSeverity::Critical,
            description: "SSH-1 protocol is deprecated and cryptographically broken".into(),
            attack_vector: AttackVector::Network,
            references: vec!["https://www.kb.cert.org/vuls/id/684820".into()],
        });

        info!(entries = db.stats.total_entries, "Loaded embedded SSH CVE database");
        db
    }

    /// Add a CVE entry to the database
    pub fn add_entry(&mut self, entry: CveEntry) {
        let software = entry.software.to_lowercase();

        // Update stats
        self.stats.total_entries += 1;
        *self.stats.by_software.entry(software.clone()).or_insert(0) += 1;
        *self.stats.by_severity.entry(entry.severity.to_string()).or_insert(0) += 1;

        self.entries.entry(software).or_default().push(entry);
    }

    /// Lookup CVEs for a software version
    pub fn lookup(&self, software: &str, version: Option<&SemVer>) -> Option<CveLookupResult> {
        // Normalize software name
        let software_lower = software.to_lowercase();

        // Find matching entries
        let mut matching_cves = Vec::new();

        // Try exact match first
        if let Some(entries) = self.entries.get(&software_lower) {
            for entry in entries {
                if self.version_matches(version, entry) {
                    matching_cves.push(entry.clone());
                }
            }
        }

        // Also check for partial matches (e.g., "openssh_8.9p1" contains "openssh")
        for (key, entries) in &self.entries {
            if software_lower.contains(key) && key != &software_lower {
                for entry in entries {
                    if self.version_matches(version, entry) {
                        matching_cves.push(entry.clone());
                    }
                }
            }
        }

        if matching_cves.is_empty() {
            return None;
        }

        let max_cvss = matching_cves.iter().map(|e| e.cvss).fold(0.0f32, f32::max);
        let max_severity = matching_cves.iter()
            .map(|e| e.severity)
            .max_by_key(|s| match s {
                CveSeverity::Critical => 4,
                CveSeverity::High => 3,
                CveSeverity::Medium => 2,
                CveSeverity::Low => 1,
            })
            .unwrap_or(CveSeverity::Low);

        Some(CveLookupResult {
            cves: matching_cves,
            max_severity,
            max_cvss,
        })
    }

    /// Check if version falls within CVE affected range
    fn version_matches(&self, version: Option<&SemVer>, entry: &CveEntry) -> bool {
        let version = match version {
            Some(v) => v,
            None => return true, // No version info = assume potentially vulnerable
        };

        // Check if version is in affected range
        let above_min = entry.version_min.as_ref()
            .map(|min| version >= min)
            .unwrap_or(true);

        let below_max = entry.version_max.as_ref()
            .map(|max| version <= max)
            .unwrap_or(true);

        // Check if fixed version exists and version is below it
        let below_fixed = entry.version_fixed.as_ref()
            .map(|fixed| version < fixed)
            .unwrap_or(true);

        above_min && below_max && below_fixed
    }

    /// Save database to JSON file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), CveError> {
        let all_entries: Vec<&CveEntry> = self.entries.values()
            .flatten()
            .collect();

        let json = serde_json::to_string_pretty(&all_entries)
            .map_err(|e| CveError::SerializeError(e.to_string()))?;

        fs::write(path, json)
            .map_err(|e| CveError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Get database statistics
    pub fn stats(&self) -> &CveStats {
        &self.stats
    }
}

/// CVE database errors
#[derive(Debug, Clone)]
pub enum CveError {
    IoError(String),
    ParseError(String),
    SerializeError(String),
}

impl std::fmt::Display for CveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CveError::IoError(e) => write!(f, "IO error: {}", e),
            CveError::ParseError(e) => write!(f, "Parse error: {}", e),
            CveError::SerializeError(e) => write!(f, "Serialize error: {}", e),
        }
    }
}

impl std::error::Error for CveError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semver_parse() {
        let v = SemVer::parse("8.9p1").unwrap();
        assert_eq!(v.major, 8);
        assert_eq!(v.minor, 9);
        assert_eq!(v.patch, 1);

        let v = SemVer::parse("9.0").unwrap();
        assert_eq!(v.major, 9);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_semver_from_software() {
        let v = SemVer::from_software("OpenSSH_8.9p1").unwrap();
        assert_eq!(v.major, 8);
        assert_eq!(v.minor, 9);
        assert_eq!(v.patch, 1);

        let v = SemVer::from_software("dropbear_2022.83").unwrap();
        assert_eq!(v.major, 2022);
        assert_eq!(v.minor, 83);
    }

    #[test]
    fn test_semver_compare() {
        let v1 = SemVer::parse("8.9p1").unwrap();
        let v2 = SemVer::parse("9.0").unwrap();
        let v3 = SemVer::parse("8.8").unwrap();

        assert!(v1 < v2);
        assert!(v3 < v1);
        assert!(v2 > v1);
    }

    #[test]
    fn test_embedded_database() {
        let db = SshCveDatabase::load_embedded();
        assert!(db.stats.total_entries > 0);

        // Test lookup for vulnerable OpenSSH
        let result = db.lookup("openssh", Some(&SemVer::parse("8.9p1").unwrap()));
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(!result.cves.is_empty());
    }

    #[test]
    fn test_cve_lookup_regresshion() {
        let db = SshCveDatabase::load_embedded();

        // Version 9.6 should be affected by regreSSHion
        let result = db.lookup("openssh", Some(&SemVer::parse("9.6").unwrap()));
        assert!(result.is_some());
        let cves = result.unwrap().cves;
        assert!(cves.iter().any(|c| c.cve_id == "CVE-2024-6387"));
    }

    #[test]
    fn test_ssh1_detection() {
        let db = SshCveDatabase::load_embedded();

        // SSH-1 should be flagged as critical
        let result = db.lookup("ssh", Some(&SemVer::parse("1.5").unwrap()));
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.max_severity, CveSeverity::Critical);
    }

    #[test]
    fn test_severity_from_cvss() {
        assert_eq!(CveSeverity::from_cvss(9.5), CveSeverity::Critical);
        assert_eq!(CveSeverity::from_cvss(7.5), CveSeverity::High);
        assert_eq!(CveSeverity::from_cvss(5.0), CveSeverity::Medium);
        assert_eq!(CveSeverity::from_cvss(2.0), CveSeverity::Low);
    }
}
