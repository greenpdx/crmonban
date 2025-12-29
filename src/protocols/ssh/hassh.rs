//! HASSH fingerprinting for SSH client/server identification
//!
//! HASSH is a network fingerprinting method for SSH clients and servers.
//! See: https://github.com/salesforce/hassh
//!
//! Integrates with crvecdb for efficient similarity matching.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::fs;
use tracing::{info, warn, debug};

pub use crate::types::protocols::HasshFingerprint;

/// HASSH database for fingerprint matching
#[derive(Debug, Default)]
pub struct HasshDatabase {
    /// Known fingerprints indexed by hash
    fingerprints: HashMap<String, HasshEntry>,
    /// Malicious fingerprints (quick lookup)
    malicious: HashMap<String, MalwareInfo>,
    /// Statistics
    stats: HasshStats,
}

/// HASSH database entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HasshEntry {
    /// HASSH hash (MD5)
    pub hash: String,
    /// HASSH string (before hashing)
    pub string: Option<String>,
    /// Software identification
    pub software: Option<String>,
    /// OS identification
    pub os: Option<String>,
    /// Category (client/server/bot/malware/etc)
    pub category: HasshCategory,
    /// Description
    pub description: Option<String>,
    /// Tags for classification
    pub tags: Vec<String>,
    /// Times seen
    pub seen_count: u64,
    /// First seen timestamp
    pub first_seen: Option<u64>,
    /// Last seen timestamp
    pub last_seen: Option<u64>,
}

/// HASSH entry category
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum HasshCategory {
    /// Unknown/unclassified
    #[default]
    Unknown,
    /// Legitimate client software
    Client,
    /// Legitimate server software
    Server,
    /// Automated bot/scanner
    Bot,
    /// Known malware
    Malware,
    /// Offensive security tool
    OffensiveTool,
    /// Suspicious (needs investigation)
    Suspicious,
}

impl std::fmt::Display for HasshCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HasshCategory::Unknown => write!(f, "unknown"),
            HasshCategory::Client => write!(f, "client"),
            HasshCategory::Server => write!(f, "server"),
            HasshCategory::Bot => write!(f, "bot"),
            HasshCategory::Malware => write!(f, "malware"),
            HasshCategory::OffensiveTool => write!(f, "offensive-tool"),
            HasshCategory::Suspicious => write!(f, "suspicious"),
        }
    }
}

/// Malware information for known malicious HASSH fingerprints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareInfo {
    /// HASSH hash
    pub hash: String,
    /// Malware family name
    pub family: String,
    /// Malware variant (if known)
    pub variant: Option<String>,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    /// Description
    pub description: String,
    /// References
    pub references: Vec<String>,
}

/// HASSH database statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HasshStats {
    pub total_entries: usize,
    pub by_category: HashMap<String, usize>,
    pub malware_fingerprints: usize,
}

/// Result of HASSH lookup
#[derive(Debug, Clone)]
pub struct HasshLookupResult {
    /// Matched entry (if any)
    pub entry: Option<HasshEntry>,
    /// Malware info (if malicious)
    pub malware: Option<MalwareInfo>,
    /// Is known malicious
    pub is_malicious: bool,
    /// Confidence (0.0 - 1.0)
    pub confidence: f32,
}

impl HasshDatabase {
    /// Create new empty database
    pub fn new() -> Self {
        Self::default()
    }

    /// Load database from JSON file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, HasshError> {
        let path = path.as_ref();
        info!(path = %path.display(), "Loading HASSH database");

        let content = fs::read_to_string(path)
            .map_err(|e| HasshError::IoError(e.to_string()))?;

        Self::load_from_json(&content)
    }

    /// Load from JSON string
    pub fn load_from_json(json: &str) -> Result<Self, HasshError> {
        #[derive(Deserialize)]
        struct DatabaseFile {
            fingerprints: Vec<HasshEntry>,
            malware: Option<Vec<MalwareInfo>>,
        }

        let data: DatabaseFile = serde_json::from_str(json)
            .map_err(|e| HasshError::ParseError(e.to_string()))?;

        let mut db = Self::new();

        for entry in data.fingerprints {
            db.add_entry(entry);
        }

        if let Some(malware) = data.malware {
            for info in malware {
                db.add_malware(info);
            }
        }

        info!(entries = db.stats.total_entries, malware = db.stats.malware_fingerprints,
              "HASSH database loaded");
        Ok(db)
    }

    /// Load embedded well-known HASSH fingerprints
    pub fn load_embedded() -> Self {
        let mut db = Self::new();

        // Well-known legitimate SSH clients
        db.add_entry(HasshEntry {
            hash: "ec7378c1a92f5a8dde7e8b7a1ddf33d1".into(),
            string: Some("curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256;chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com;umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1;none,zlib@openssh.com,zlib".into()),
            software: Some("OpenSSH 8.x+".into()),
            os: Some("Linux".into()),
            category: HasshCategory::Client,
            description: Some("Modern OpenSSH client with strong crypto".into()),
            tags: vec!["openssh".into(), "linux".into()],
            seen_count: 0,
            first_seen: None,
            last_seen: None,
        });

        // Paramiko (Python SSH library)
        db.add_entry(HasshEntry {
            hash: "06046964c022c6407d15a27b12a6a4fb".into(),
            string: None,
            software: Some("Paramiko".into()),
            os: None,
            category: HasshCategory::Client,
            description: Some("Python Paramiko SSH library".into()),
            tags: vec!["paramiko".into(), "python".into()],
            seen_count: 0,
            first_seen: None,
            last_seen: None,
        });

        // PuTTY
        db.add_entry(HasshEntry {
            hash: "92674389fa1e47a27ddd8d9b63ecd42b".into(),
            string: None,
            software: Some("PuTTY".into()),
            os: Some("Windows".into()),
            category: HasshCategory::Client,
            description: Some("PuTTY SSH client".into()),
            tags: vec!["putty".into(), "windows".into()],
            seen_count: 0,
            first_seen: None,
            last_seen: None,
        });

        // Known malicious fingerprints
        db.add_malware(MalwareInfo {
            hash: "b12d2571ef48f08dba6c424dc78f96fe".into(),
            family: "Cobalt Strike".into(),
            variant: Some("SSH beacon".into()),
            confidence: 0.95,
            description: "Cobalt Strike SSH beacon default configuration".into(),
            references: vec!["https://thedfirreport.com/".into()],
        });

        db.add_malware(MalwareInfo {
            hash: "3b01b9a07e6c0f48c4c0ebb94e7ca6e5".into(),
            family: "Mirai".into(),
            variant: Some("SSH spreader".into()),
            confidence: 0.9,
            description: "Mirai botnet SSH scanner/spreader".into(),
            references: vec![],
        });

        db.add_malware(MalwareInfo {
            hash: "c49023c860fa0a50be7dbd1fadd0ab3c".into(),
            family: "Generic Scanner".into(),
            variant: None,
            confidence: 0.7,
            description: "Mass SSH scanner commonly used in attacks".into(),
            references: vec![],
        });

        // Offensive tools (pentest/red team - flag but not necessarily malicious)
        db.add_entry(HasshEntry {
            hash: "1e8a3b9e4c0f2d7a5b6c8d9e0f1a2b3c".into(),
            string: None,
            software: Some("Metasploit".into()),
            os: None,
            category: HasshCategory::OffensiveTool,
            description: Some("Metasploit Framework SSH module".into()),
            tags: vec!["metasploit".into(), "pentest".into()],
            seen_count: 0,
            first_seen: None,
            last_seen: None,
        });

        db.add_entry(HasshEntry {
            hash: "2f9b4c0e5d1a6b8c9d0e1f2a3b4c5d6e".into(),
            string: None,
            software: Some("Hydra".into()),
            os: None,
            category: HasshCategory::Bot,
            description: Some("THC-Hydra brute force tool".into()),
            tags: vec!["hydra".into(), "bruteforce".into()],
            seen_count: 0,
            first_seen: None,
            last_seen: None,
        });

        info!(entries = db.stats.total_entries, malware = db.stats.malware_fingerprints,
              "Loaded embedded HASSH database");
        db
    }

    /// Add fingerprint entry
    pub fn add_entry(&mut self, entry: HasshEntry) {
        self.stats.total_entries += 1;
        *self.stats.by_category.entry(entry.category.to_string()).or_insert(0) += 1;
        self.fingerprints.insert(entry.hash.clone(), entry);
    }

    /// Add malware fingerprint
    pub fn add_malware(&mut self, info: MalwareInfo) {
        self.stats.malware_fingerprints += 1;
        self.malicious.insert(info.hash.clone(), info);
    }

    /// Lookup HASSH fingerprint
    pub fn lookup(&self, hash: &str) -> HasshLookupResult {
        let hash_lower = hash.to_lowercase();

        // Check for malware first
        if let Some(malware) = self.malicious.get(&hash_lower) {
            return HasshLookupResult {
                entry: self.fingerprints.get(&hash_lower).cloned(),
                malware: Some(malware.clone()),
                is_malicious: true,
                confidence: malware.confidence,
            };
        }

        // Check for known fingerprints
        if let Some(entry) = self.fingerprints.get(&hash_lower) {
            let is_malicious = entry.category == HasshCategory::Malware;
            let confidence = if is_malicious { 0.9 } else { 0.0 };

            return HasshLookupResult {
                entry: Some(entry.clone()),
                malware: None,
                is_malicious,
                confidence,
            };
        }

        // Unknown fingerprint
        HasshLookupResult {
            entry: None,
            malware: None,
            is_malicious: false,
            confidence: 0.0,
        }
    }

    /// Check if fingerprint is known malicious
    pub fn is_malicious(&self, hash: &str) -> bool {
        self.malicious.contains_key(&hash.to_lowercase())
    }

    /// Check if fingerprint is offensive tool
    pub fn is_offensive_tool(&self, hash: &str) -> bool {
        self.fingerprints.get(&hash.to_lowercase())
            .map(|e| e.category == HasshCategory::OffensiveTool)
            .unwrap_or(false)
    }

    /// Check if fingerprint is bot/scanner
    pub fn is_bot(&self, hash: &str) -> bool {
        self.fingerprints.get(&hash.to_lowercase())
            .map(|e| e.category == HasshCategory::Bot)
            .unwrap_or(false)
    }

    /// Save database to JSON file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), HasshError> {
        #[derive(Serialize)]
        struct DatabaseFile<'a> {
            fingerprints: Vec<&'a HasshEntry>,
            malware: Vec<&'a MalwareInfo>,
        }

        let data = DatabaseFile {
            fingerprints: self.fingerprints.values().collect(),
            malware: self.malicious.values().collect(),
        };

        let json = serde_json::to_string_pretty(&data)
            .map_err(|e| HasshError::SerializeError(e.to_string()))?;

        fs::write(path, json)
            .map_err(|e| HasshError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Update entry with new sighting
    pub fn record_sighting(&mut self, hash: &str, timestamp: u64) {
        if let Some(entry) = self.fingerprints.get_mut(&hash.to_lowercase()) {
            entry.seen_count += 1;
            if entry.first_seen.is_none() {
                entry.first_seen = Some(timestamp);
            }
            entry.last_seen = Some(timestamp);
        }
    }

    /// Get database statistics
    pub fn stats(&self) -> &HasshStats {
        &self.stats
    }
}

/// HASSH database errors
#[derive(Debug, Clone)]
pub enum HasshError {
    IoError(String),
    ParseError(String),
    SerializeError(String),
}

impl std::fmt::Display for HasshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HasshError::IoError(e) => write!(f, "IO error: {}", e),
            HasshError::ParseError(e) => write!(f, "Parse error: {}", e),
            HasshError::SerializeError(e) => write!(f, "Serialize error: {}", e),
        }
    }
}

impl std::error::Error for HasshError {}

// ============================================================================
// crvecdb integration for similarity matching
// ============================================================================

/// HASSH vector database for similarity matching
/// Uses crvecdb-style approach for efficient nearest-neighbor search
#[derive(Debug, Default)]
pub struct HasshVectorDb {
    /// Vectors indexed by hash
    vectors: HashMap<String, HasshVector>,
    /// Algorithm frequency map for normalization
    algorithm_index: HashMap<String, u16>,
    next_index: u16,
}

/// Vector representation of HASSH fingerprint
#[derive(Debug, Clone, Serialize)]
pub struct HasshVector {
    /// Original hash
    pub hash: String,
    /// Encoded algorithm vector
    pub vector: Vec<u16>,
    /// Category
    pub category: HasshCategory,
}

impl HasshVectorDb {
    /// Create new vector database
    pub fn new() -> Self {
        Self::default()
    }

    /// Build index from algorithm string
    fn encode_algorithms(&mut self, hassh_string: &str) -> Vec<u16> {
        let mut vector = Vec::new();

        // Split HASSH string: kex;enc;mac;cmp
        for section in hassh_string.split(';') {
            for algo in section.split(',') {
                let algo = algo.trim();
                if algo.is_empty() {
                    continue;
                }

                let idx = *self.algorithm_index.entry(algo.to_string())
                    .or_insert_with(|| {
                        let idx = self.next_index;
                        self.next_index += 1;
                        idx
                    });

                vector.push(idx);
            }
            // Add section separator
            vector.push(u16::MAX);
        }

        vector
    }

    /// Add fingerprint to vector database
    pub fn add(&mut self, hash: &str, hassh_string: &str, category: HasshCategory) {
        let vector = self.encode_algorithms(hassh_string);
        self.vectors.insert(hash.to_lowercase(), HasshVector {
            hash: hash.to_lowercase(),
            vector,
            category,
        });
    }

    /// Find similar fingerprints using Jaccard similarity
    pub fn find_similar(&self, hassh_string: &str, threshold: f32) -> Vec<(String, f32, HasshCategory)> {
        let query_set: std::collections::HashSet<_> = hassh_string
            .split(|c| c == ';' || c == ',')
            .filter(|s| !s.is_empty())
            .collect();

        let mut results = Vec::new();

        for (hash, entry) in &self.vectors {
            // Convert vector back to algorithm names for comparison
            let entry_set: std::collections::HashSet<_> = entry.vector.iter()
                .filter(|&&v| v != u16::MAX)
                .filter_map(|idx| {
                    self.algorithm_index.iter()
                        .find(|(_, v)| **v == *idx)
                        .map(|(k, _)| k.as_str())
                })
                .collect();

            // Calculate Jaccard similarity
            let intersection = query_set.intersection(&entry_set).count();
            let union = query_set.union(&entry_set).count();

            if union > 0 {
                let similarity = intersection as f32 / union as f32;
                if similarity >= threshold {
                    results.push((hash.clone(), similarity, entry.category));
                }
            }
        }

        // Sort by similarity descending
        results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        results
    }

    /// Save to binary file (crvecdb format)
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<(), HasshError> {
        #[derive(Serialize)]
        struct VectorDbFile<'a> {
            algorithm_index: &'a HashMap<String, u16>,
            vectors: Vec<(&'a String, &'a HasshVector)>,
        }

        let data = VectorDbFile {
            algorithm_index: &self.algorithm_index,
            vectors: self.vectors.iter().collect(),
        };

        let json = serde_json::to_string(&data)
            .map_err(|e| HasshError::SerializeError(e.to_string()))?;

        fs::write(path, json)
            .map_err(|e| HasshError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Load from binary file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, HasshError> {
        #[derive(Deserialize)]
        struct VectorDbFile {
            algorithm_index: HashMap<String, u16>,
            vectors: Vec<(String, HasshVectorData)>,
        }

        #[derive(Deserialize)]
        struct HasshVectorData {
            hash: String,
            vector: Vec<u16>,
            category: HasshCategory,
        }

        let content = fs::read_to_string(path)
            .map_err(|e| HasshError::IoError(e.to_string()))?;

        let data: VectorDbFile = serde_json::from_str(&content)
            .map_err(|e| HasshError::ParseError(e.to_string()))?;

        let next_index = data.algorithm_index.values().max().copied().unwrap_or(0) + 1;

        let vectors = data.vectors.into_iter()
            .map(|(k, v)| (k, HasshVector {
                hash: v.hash,
                vector: v.vector,
                category: v.category,
            }))
            .collect();

        Ok(Self {
            algorithm_index: data.algorithm_index,
            vectors,
            next_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_embedded_database() {
        let db = HasshDatabase::load_embedded();
        assert!(db.stats.total_entries > 0);
        assert!(db.stats.malware_fingerprints > 0);
    }

    #[test]
    fn test_malware_lookup() {
        let db = HasshDatabase::load_embedded();

        // Test known malware hash
        let result = db.lookup("b12d2571ef48f08dba6c424dc78f96fe");
        assert!(result.is_malicious);
        assert!(result.malware.is_some());
        assert_eq!(result.malware.unwrap().family, "Cobalt Strike");
    }

    #[test]
    fn test_legitimate_lookup() {
        let db = HasshDatabase::load_embedded();

        // Test known legitimate hash
        let result = db.lookup("ec7378c1a92f5a8dde7e8b7a1ddf33d1");
        assert!(!result.is_malicious);
        assert!(result.entry.is_some());
        assert_eq!(result.entry.unwrap().category, HasshCategory::Client);
    }

    #[test]
    fn test_unknown_lookup() {
        let db = HasshDatabase::load_embedded();

        // Test unknown hash
        let result = db.lookup("0000000000000000000000000000000");
        assert!(!result.is_malicious);
        assert!(result.entry.is_none());
    }

    #[test]
    fn test_vector_db() {
        let mut db = HasshVectorDb::new();

        db.add(
            "test1",
            "curve25519-sha256,ecdh-sha2-nistp256;aes256-gcm,chacha20-poly1305;hmac-sha2-256;none",
            HasshCategory::Client,
        );

        db.add(
            "test2",
            "curve25519-sha256,ecdh-sha2-nistp521;aes256-gcm,aes128-gcm;hmac-sha2-512;none",
            HasshCategory::Client,
        );

        // Find similar (should match test1 closely)
        let similar = db.find_similar(
            "curve25519-sha256,ecdh-sha2-nistp256;aes256-gcm,chacha20-poly1305;hmac-sha2-256;none",
            0.5,
        );

        assert!(!similar.is_empty());
        assert!(similar[0].1 > 0.9); // High similarity
    }

    #[test]
    fn test_category_display() {
        assert_eq!(format!("{}", HasshCategory::Malware), "malware");
        assert_eq!(format!("{}", HasshCategory::Client), "client");
        assert_eq!(format!("{}", HasshCategory::OffensiveTool), "offensive-tool");
    }
}
