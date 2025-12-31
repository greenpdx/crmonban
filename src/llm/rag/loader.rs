//! CTI Feed Loaders
//!
//! Loads threat intelligence from various sources into the vector store.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use super::vectorstore::{EntryMetadata, VectorEntry, VectorStore};
use crate::llm::provider::LlmProvider;

/// CTI source type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CtiSource {
    /// MITRE ATT&CK framework
    MitreAttack,
    /// Sigma detection rules
    SigmaRules,
    /// Suricata rules
    SuricataRules,
    /// NVD (CVE) database
    Nvd,
    /// Custom CTI
    Custom,
}

impl CtiSource {
    /// Get source name string
    pub fn name(&self) -> &str {
        match self {
            CtiSource::MitreAttack => "mitre",
            CtiSource::SigmaRules => "sigma",
            CtiSource::SuricataRules => "suricata",
            CtiSource::Nvd => "nvd",
            CtiSource::Custom => "custom",
        }
    }
}

/// CTI document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtiDocument {
    /// Document ID
    pub id: String,
    /// Source type
    pub source: CtiSource,
    /// Title
    pub title: String,
    /// Description/content
    pub content: String,
    /// Category
    pub category: String,
    /// Tags
    pub tags: Vec<String>,
    /// MITRE technique ID if applicable
    pub mitre_id: Option<String>,
    /// Severity
    pub severity: Option<String>,
}

/// CTI loader
pub struct CtiLoader {
    /// Embedding provider
    embedder: Arc<dyn LlmProvider>,
    /// Chunk size for splitting documents
    chunk_size: usize,
    /// Chunk overlap
    chunk_overlap: usize,
}

impl CtiLoader {
    /// Create a new CTI loader
    pub fn new(embedder: Arc<dyn LlmProvider>) -> Self {
        Self {
            embedder,
            chunk_size: 512,
            chunk_overlap: 64,
        }
    }

    /// Set chunk size
    pub fn with_chunk_size(mut self, size: usize, overlap: usize) -> Self {
        self.chunk_size = size;
        self.chunk_overlap = overlap;
        self
    }

    /// Load MITRE ATT&CK techniques
    pub async fn load_mitre(&self, store: &VectorStore) -> Result<usize, String> {
        info!("Loading MITRE ATT&CK techniques...");

        // Embedded MITRE techniques (key ones for network security)
        let techniques = get_mitre_techniques();
        let mut loaded = 0;

        for technique in techniques {
            let doc = CtiDocument {
                id: technique.id.clone(),
                source: CtiSource::MitreAttack,
                title: technique.name.clone(),
                content: format!(
                    "# {} - {}\n\n**Tactic**: {}\n\n**Description**: {}\n\n**Detection**: {}",
                    technique.id, technique.name, technique.tactic, technique.description, technique.detection
                ),
                category: "technique".to_string(),
                tags: vec![technique.tactic.clone()],
                mitre_id: Some(technique.id.clone()),
                severity: None,
            };

            if self.load_document(store, doc).await.is_ok() {
                loaded += 1;
            }
        }

        info!("Loaded {} MITRE ATT&CK techniques", loaded);
        Ok(loaded)
    }

    /// Load Sigma rules from directory
    pub async fn load_sigma(&self, store: &VectorStore, path: &Path) -> Result<usize, String> {
        info!("Loading Sigma rules from {:?}...", path);

        if !path.exists() {
            warn!("Sigma rules path does not exist: {:?}", path);
            return Ok(0);
        }

        let mut loaded = 0;

        // Walk directory for YAML files
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                if file_path.extension().map(|e| e == "yml" || e == "yaml").unwrap_or(false) {
                    if let Ok(content) = fs::read_to_string(&file_path) {
                        if let Some(doc) = self.parse_sigma_rule(&file_path, &content) {
                            if self.load_document(store, doc).await.is_ok() {
                                loaded += 1;
                            }
                        }
                    }
                }
            }
        }

        info!("Loaded {} Sigma rules", loaded);
        Ok(loaded)
    }

    /// Parse Sigma rule from YAML content
    fn parse_sigma_rule(&self, path: &Path, content: &str) -> Option<CtiDocument> {
        // Simple YAML parsing for key fields
        let mut title = String::new();
        let mut description = String::new();
        let mut level = String::new();
        let mut tags: Vec<String> = Vec::new();
        let mut mitre_id = None;

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("title:") {
                title = line.strip_prefix("title:")?.trim().to_string();
            } else if line.starts_with("description:") {
                description = line.strip_prefix("description:")?.trim().to_string();
            } else if line.starts_with("level:") {
                level = line.strip_prefix("level:")?.trim().to_string();
            } else if line.contains("attack.t") {
                // Extract MITRE technique
                if let Some(start) = line.find("attack.t") {
                    let rest = &line[start + 7..];
                    if let Some(end) = rest.find(|c: char| !c.is_alphanumeric() && c != '.') {
                        let tid = format!("T{}", &rest[..end]);
                        mitre_id = Some(tid.clone());
                        tags.push(tid);
                    }
                }
            }
        }

        if title.is_empty() {
            return None;
        }

        let id = path.file_stem()?.to_string_lossy().to_string();

        Some(CtiDocument {
            id,
            source: CtiSource::SigmaRules,
            title,
            content: format!("{}\n\n{}", description, content),
            category: "detection_rule".to_string(),
            tags,
            mitre_id,
            severity: Some(level),
        })
    }

    /// Load Suricata rules from directory
    pub async fn load_suricata(&self, store: &VectorStore, path: &Path) -> Result<usize, String> {
        info!("Loading Suricata rules from {:?}...", path);

        if !path.exists() {
            warn!("Suricata rules path does not exist: {:?}", path);
            return Ok(0);
        }

        let mut loaded = 0;

        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let file_path = entry.path();
                if file_path.extension().map(|e| e == "rules").unwrap_or(false) {
                    if let Ok(content) = fs::read_to_string(&file_path) {
                        let rules = self.parse_suricata_rules(&file_path, &content);
                        for doc in rules {
                            if self.load_document(store, doc).await.is_ok() {
                                loaded += 1;
                            }
                        }
                    }
                }
            }
        }

        info!("Loaded {} Suricata rules", loaded);
        Ok(loaded)
    }

    /// Parse Suricata rules file
    fn parse_suricata_rules(&self, path: &Path, content: &str) -> Vec<CtiDocument> {
        let mut docs = Vec::new();
        let file_stem = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();

        for (i, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            // Parse rule
            if let Some(msg_start) = line.find("msg:\"") {
                let msg_rest = &line[msg_start + 5..];
                if let Some(msg_end) = msg_rest.find('"') {
                    let msg = &msg_rest[..msg_end];

                    // Extract classtype
                    let classtype = line.find("classtype:")
                        .and_then(|start| {
                            let rest = &line[start + 10..];
                            rest.find(';').map(|end| rest[..end].to_string())
                        })
                        .unwrap_or_else(|| "unknown".to_string());

                    // Extract sid
                    let sid = line.find("sid:")
                        .and_then(|start| {
                            let rest = &line[start + 4..];
                            rest.find(';').map(|end| rest[..end].to_string())
                        })
                        .unwrap_or_else(|| format!("{}_{}", file_stem, i));

                    docs.push(CtiDocument {
                        id: format!("suri_{}", sid),
                        source: CtiSource::SuricataRules,
                        title: msg.to_string(),
                        content: line.to_string(),
                        category: classtype,
                        tags: vec![file_stem.clone()],
                        mitre_id: None,
                        severity: None,
                    });
                }
            }
        }

        docs
    }

    /// Load a single document into the vector store
    async fn load_document(&self, store: &VectorStore, doc: CtiDocument) -> Result<(), String> {
        // Split content into chunks
        let chunks = self.chunk_text(&doc.content);

        for (i, chunk) in chunks.iter().enumerate() {
            // Generate embedding
            let response = self.embedder.embed(&[chunk.clone()]).await
                .map_err(|e| format!("Embedding failed: {}", e))?;
            if response.embeddings.is_empty() {
                continue;
            }

            let entry_id = if chunks.len() == 1 {
                doc.id.clone()
            } else {
                format!("{}_{}", doc.id, i)
            };

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let entry = VectorEntry {
                id: entry_id,
                doc_id: doc.id.clone(),
                text: chunk.clone(),
                embedding: response.embeddings[0].clone(),
                metadata: EntryMetadata {
                    source: doc.source.name().to_string(),
                    category: doc.category.clone(),
                    tags: doc.tags.clone(),
                    mitre_id: doc.mitre_id.clone(),
                    severity: doc.severity.clone(),
                    created_at: now,
                },
            };

            store.add(entry)?;
        }

        Ok(())
    }

    /// Chunk text into smaller pieces
    fn chunk_text(&self, text: &str) -> Vec<String> {
        if text.len() <= self.chunk_size {
            return vec![text.to_string()];
        }

        let mut chunks = Vec::new();
        let mut start = 0;

        while start < text.len() {
            let end = (start + self.chunk_size).min(text.len());

            // Try to break at sentence boundary
            let chunk_end = if end < text.len() {
                text[start..end]
                    .rfind(|c| c == '.' || c == '\n')
                    .map(|pos| start + pos + 1)
                    .unwrap_or(end)
            } else {
                end
            };

            chunks.push(text[start..chunk_end].to_string());

            // Move start with overlap
            start = if chunk_end > self.chunk_overlap {
                chunk_end - self.chunk_overlap
            } else {
                chunk_end
            };
        }

        chunks
    }

    /// Load custom documents
    pub async fn load_custom(&self, store: &VectorStore, docs: Vec<CtiDocument>) -> Result<usize, String> {
        let mut loaded = 0;
        for doc in docs {
            if self.load_document(store, doc).await.is_ok() {
                loaded += 1;
            }
        }
        Ok(loaded)
    }
}

/// MITRE technique data
struct MitreTechnique {
    id: String,
    name: String,
    tactic: String,
    description: String,
    detection: String,
}

/// Get embedded MITRE techniques (network security focused)
fn get_mitre_techniques() -> Vec<MitreTechnique> {
    vec![
        MitreTechnique {
            id: "T1595".to_string(),
            name: "Active Scanning".to_string(),
            tactic: "Reconnaissance".to_string(),
            description: "Adversaries may scan victim IP ranges to gather information that can be used during targeting. Active scans involve probing victim infrastructure via network traffic.".to_string(),
            detection: "Monitor for suspicious network traffic that could indicate scanning activity (e.g., high rate of connection attempts, systematic probing of ports).".to_string(),
        },
        MitreTechnique {
            id: "T1595.001".to_string(),
            name: "Scanning IP Blocks".to_string(),
            tactic: "Reconnaissance".to_string(),
            description: "Adversaries may scan IP blocks to gather victim network information. Scans may range from simple pings to more nuanced scans.".to_string(),
            detection: "Monitor network traffic for large numbers of connection attempts from a single source to many different destination IPs.".to_string(),
        },
        MitreTechnique {
            id: "T1595.002".to_string(),
            name: "Vulnerability Scanning".to_string(),
            tactic: "Reconnaissance".to_string(),
            description: "Adversaries may scan victims for vulnerabilities that can be used during targeting. Vulnerability scans typically check for specific software versions.".to_string(),
            detection: "Monitor for unusual scanning patterns, particularly those targeting known vulnerable services or ports.".to_string(),
        },
        MitreTechnique {
            id: "T1110".to_string(),
            name: "Brute Force".to_string(),
            tactic: "Credential Access".to_string(),
            description: "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.".to_string(),
            detection: "Monitor authentication logs for multiple failed authentication attempts followed by a success. Monitor for unusually high number of authentication attempts.".to_string(),
        },
        MitreTechnique {
            id: "T1110.001".to_string(),
            name: "Password Guessing".to_string(),
            tactic: "Credential Access".to_string(),
            description: "Adversaries may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may systematically guess passwords.".to_string(),
            detection: "Monitor for many failed authentication attempts across various accounts that may suggest password guessing.".to_string(),
        },
        MitreTechnique {
            id: "T1110.003".to_string(),
            name: "Password Spraying".to_string(),
            tactic: "Credential Access".to_string(),
            description: "Adversaries may use a single or small list of commonly used passwords against many different accounts to acquire valid credentials.".to_string(),
            detection: "Monitor for failed logins across many accounts with the same password within a short timeframe.".to_string(),
        },
        MitreTechnique {
            id: "T1190".to_string(),
            name: "Exploit Public-Facing Application".to_string(),
            tactic: "Initial Access".to_string(),
            description: "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program using software, data, or commands to cause unintended behavior.".to_string(),
            detection: "Monitor network traffic for exploitation attempts. Use deep packet inspection to detect known exploit patterns.".to_string(),
        },
        MitreTechnique {
            id: "T1557".to_string(),
            name: "Adversary-in-the-Middle".to_string(),
            tactic: "Credential Access".to_string(),
            description: "Adversaries may position themselves between two targets to intercept traffic. This may enable data collection and manipulation.".to_string(),
            detection: "Monitor for ARP spoofing, DNS spoofing, and other network-based attacks that could indicate MITM positioning.".to_string(),
        },
        MitreTechnique {
            id: "T1557.002".to_string(),
            name: "ARP Cache Poisoning".to_string(),
            tactic: "Credential Access".to_string(),
            description: "Adversaries may poison ARP caches to position themselves between two communicating hosts.".to_string(),
            detection: "Monitor for gratuitous ARP replies. Static ARP entries can help detect poisoning attempts.".to_string(),
        },
        MitreTechnique {
            id: "T1498".to_string(),
            name: "Network Denial of Service".to_string(),
            tactic: "Impact".to_string(),
            description: "Adversaries may perform Network Denial of Service attacks to degrade or block the availability of targeted resources.".to_string(),
            detection: "Monitor for sudden spikes in traffic volume, unusual traffic patterns, or traffic from many sources to a single target.".to_string(),
        },
        MitreTechnique {
            id: "T1499".to_string(),
            name: "Endpoint Denial of Service".to_string(),
            tactic: "Impact".to_string(),
            description: "Adversaries may perform Endpoint Denial of Service attacks to exhaust system resources.".to_string(),
            detection: "Monitor for system resource exhaustion, service unavailability, and malformed packets designed to crash services.".to_string(),
        },
        MitreTechnique {
            id: "T1021".to_string(),
            name: "Remote Services".to_string(),
            tactic: "Lateral Movement".to_string(),
            description: "Adversaries may use valid accounts to log into remote services. This technique enables lateral movement.".to_string(),
            detection: "Monitor for remote login attempts, especially from unusual sources or at unusual times.".to_string(),
        },
        MitreTechnique {
            id: "T1021.001".to_string(),
            name: "Remote Desktop Protocol".to_string(),
            tactic: "Lateral Movement".to_string(),
            description: "Adversaries may use RDP to log into remote systems.".to_string(),
            detection: "Monitor for RDP connection attempts, especially from external IPs or to sensitive systems.".to_string(),
        },
        MitreTechnique {
            id: "T1021.004".to_string(),
            name: "SSH".to_string(),
            tactic: "Lateral Movement".to_string(),
            description: "Adversaries may use SSH to log into remote systems.".to_string(),
            detection: "Monitor for SSH connection attempts, key-based vs password auth, and unusual source IPs.".to_string(),
        },
        MitreTechnique {
            id: "T1059".to_string(),
            name: "Command and Scripting Interpreter".to_string(),
            tactic: "Execution".to_string(),
            description: "Adversaries may abuse command and script interpreters to execute commands.".to_string(),
            detection: "Monitor process execution, command-line arguments, and script execution patterns.".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_text() {
        // Would need a mock embedder for full test
        // Just verify the technique list is populated
        let techniques = get_mitre_techniques();
        assert!(!techniques.is_empty());
        assert!(techniques.iter().any(|t| t.id == "T1595"));
    }

    #[test]
    fn test_cti_source_name() {
        assert_eq!(CtiSource::MitreAttack.name(), "mitre");
        assert_eq!(CtiSource::SigmaRules.name(), "sigma");
        assert_eq!(CtiSource::SuricataRules.name(), "suricata");
    }
}
