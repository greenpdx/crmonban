//! Signature storage and persistence
//!
//! Handles reading and writing signature rules to /var/lib/crmonban/data/signatures

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::{Rule, RuleStats};

/// Default signature storage directory
pub const SIGNATURE_DATA_DIR: &str = "/var/lib/crmonban/data/signatures";

/// Stored signature set metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSetMetadata {
    /// Unique identifier for this signature set
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// Version string
    pub version: String,
    /// Source (e.g., "et-open", "custom", "imported")
    pub source: String,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last modified timestamp
    pub modified_at: chrono::DateTime<chrono::Utc>,
    /// Number of rules in this set
    pub rule_count: usize,
    /// Whether this set is enabled
    pub enabled: bool,
    /// Priority (lower = higher priority)
    pub priority: u32,
    /// Tags for categorization
    pub tags: Vec<String>,
}

impl Default for SignatureSetMetadata {
    fn default() -> Self {
        let now = chrono::Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: "Default".into(),
            description: String::new(),
            version: "1.0.0".into(),
            source: "custom".into(),
            created_at: now,
            modified_at: now,
            rule_count: 0,
            enabled: true,
            priority: 100,
            tags: Vec::new(),
        }
    }
}

/// A stored signature set with rules and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSet {
    /// Metadata about this set
    pub metadata: SignatureSetMetadata,
    /// The rules in this set
    pub rules: Vec<Rule>,
}

impl SignatureSet {
    /// Create a new empty signature set
    pub fn new(name: &str, source: &str) -> Self {
        let mut metadata = SignatureSetMetadata::default();
        metadata.name = name.into();
        metadata.source = source.into();
        Self {
            metadata,
            rules: Vec::new(),
        }
    }

    /// Add a rule to this set
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
        self.metadata.rule_count = self.rules.len();
        self.metadata.modified_at = chrono::Utc::now();
    }

    /// Get statistics about this rule set
    pub fn stats(&self) -> RuleStats {
        let mut stats = RuleStats::default();
        for rule in &self.rules {
            stats.add_rule(rule);
        }
        stats
    }
}

/// Signature storage manager
pub struct SignatureStorage {
    /// Base directory for signature data
    base_dir: PathBuf,
    /// Loaded signature sets by ID
    sets: HashMap<String, SignatureSet>,
}

impl SignatureStorage {
    /// Create a new storage manager with the default directory
    pub fn new() -> Self {
        Self::with_path(SIGNATURE_DATA_DIR)
    }

    /// Create a new storage manager with a custom path
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        Self {
            base_dir: path.as_ref().to_path_buf(),
            sets: HashMap::new(),
        }
    }

    /// Get the base directory
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Initialize the storage directory structure
    pub fn init(&self) -> std::io::Result<()> {
        // Create base directory
        fs::create_dir_all(&self.base_dir)?;

        // Create subdirectories
        fs::create_dir_all(self.base_dir.join("custom"))?;
        fs::create_dir_all(self.base_dir.join("imported"))?;
        fs::create_dir_all(self.base_dir.join("et-open"))?;
        fs::create_dir_all(self.base_dir.join("suricata"))?;
        fs::create_dir_all(self.base_dir.join("rules"))?;
        fs::create_dir_all(self.base_dir.join("cache"))?;

        info!("Initialized signature storage at {:?}", self.base_dir);
        Ok(())
    }

    /// List all available signature sets
    pub fn list_sets(&self) -> std::io::Result<Vec<SignatureSetMetadata>> {
        let mut sets = Vec::new();

        // Scan all subdirectories for .json files
        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                // Check for index.json in each subdirectory
                let index_path = path.join("index.json");
                if index_path.exists() {
                    if let Ok(metadata) = self.load_metadata(&index_path) {
                        sets.push(metadata);
                    }
                }

                // Also check for individual .json rule files
                for file_entry in fs::read_dir(&path)? {
                    let file_entry = file_entry?;
                    let file_path = file_entry.path();
                    if file_path.extension().map(|e| e == "json").unwrap_or(false)
                        && file_path.file_name().map(|n| n != "index.json").unwrap_or(true)
                    {
                        if let Ok(set) = self.load_set_file(&file_path) {
                            sets.push(set.metadata);
                        }
                    }
                }
            }
        }

        // Sort by priority
        sets.sort_by_key(|s| s.priority);
        Ok(sets)
    }

    /// Load metadata from an index file
    fn load_metadata(&self, path: &Path) -> std::io::Result<SignatureSetMetadata> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })
    }

    /// Load a signature set from a file
    fn load_set_file(&self, path: &Path) -> std::io::Result<SignatureSet> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })
    }

    /// Save a signature set to storage
    pub fn save_set(&mut self, set: &SignatureSet) -> std::io::Result<PathBuf> {
        // Determine directory based on source
        let subdir = match set.metadata.source.as_str() {
            "et-open" | "etopen" => "et-open",
            "imported" => "imported",
            _ => "custom",
        };

        let dir = self.base_dir.join(subdir);
        fs::create_dir_all(&dir)?;

        // Create filename from ID
        let filename = format!("{}.json", sanitize_filename(&set.metadata.id));
        let path = dir.join(&filename);

        // Write the set
        let file = File::create(&path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, set).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;

        info!(
            "Saved signature set '{}' ({} rules) to {:?}",
            set.metadata.name,
            set.rules.len(),
            path
        );

        // Update cache
        self.sets.insert(set.metadata.id.clone(), set.clone());

        Ok(path)
    }

    /// Load a signature set by ID
    pub fn load_set(&mut self, id: &str) -> std::io::Result<SignatureSet> {
        // Check cache first
        if let Some(set) = self.sets.get(id) {
            return Ok(set.clone());
        }

        // Search for the set file
        let filename = format!("{}.json", sanitize_filename(id));
        for subdir in &["custom", "imported", "et-open"] {
            let path = self.base_dir.join(subdir).join(&filename);
            if path.exists() {
                let set = self.load_set_file(&path)?;
                self.sets.insert(id.to_string(), set.clone());
                return Ok(set);
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Signature set not found: {}", id),
        ))
    }

    /// Delete a signature set
    pub fn delete_set(&mut self, id: &str) -> std::io::Result<()> {
        let filename = format!("{}.json", sanitize_filename(id));

        for subdir in &["custom", "imported", "et-open"] {
            let path = self.base_dir.join(subdir).join(&filename);
            if path.exists() {
                fs::remove_file(&path)?;
                self.sets.remove(id);
                info!("Deleted signature set: {}", id);
                return Ok(());
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Signature set not found: {}", id),
        ))
    }

    /// Load all enabled signature sets, importing Suricata .rules files first
    ///
    /// On first startup, this will:
    /// 1. Scan for any .rules files in the signature directories
    /// 2. Import them and convert to JSON format
    /// 3. Load all enabled JSON signature sets
    pub fn load_all_enabled(&mut self) -> std::io::Result<Vec<SignatureSet>> {
        // First, import any Suricata .rules files that haven't been imported yet
        self.import_suricata_rules_on_startup()?;

        let mut all_sets = Vec::new();

        for subdir in &["custom", "imported", "et-open", "suricata"] {
            let dir = self.base_dir.join(subdir);
            if !dir.exists() {
                continue;
            }

            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    match self.load_set_file(&path) {
                        Ok(set) => {
                            if set.metadata.enabled {
                                debug!(
                                    "Loaded signature set '{}' with {} rules",
                                    set.metadata.name,
                                    set.rules.len()
                                );
                                self.sets.insert(set.metadata.id.clone(), set.clone());
                                all_sets.push(set);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to load signature set {:?}: {}", path, e);
                        }
                    }
                }
            }
        }

        // Sort by priority
        all_sets.sort_by_key(|s| s.metadata.priority);

        info!(
            "Loaded {} enabled signature sets with {} total rules",
            all_sets.len(),
            all_sets.iter().map(|s| s.rules.len()).sum::<usize>()
        );

        Ok(all_sets)
    }

    /// Get all rules from all loaded sets
    pub fn get_all_rules(&self) -> Vec<&Rule> {
        self.sets
            .values()
            .filter(|s| s.metadata.enabled)
            .flat_map(|s| s.rules.iter())
            .collect()
    }

    /// Export rules to JSON format
    pub fn export_json(&self, set_id: &str, output: &Path) -> std::io::Result<()> {
        let set = self.sets.get(set_id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Set not found: {}", set_id),
            )
        })?;

        let file = File::create(output)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, set).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;

        info!("Exported {} rules to {:?}", set.rules.len(), output);
        Ok(())
    }

    /// Import Suricata .rules files found in signature directories on startup
    ///
    /// Scans for .rules files and imports any that haven't been imported yet.
    /// Tracks imported files via an import manifest to avoid re-importing.
    fn import_suricata_rules_on_startup(&mut self) -> std::io::Result<()> {
        // Create suricata subdirectory for imported rules
        let suricata_dir = self.base_dir.join("suricata");
        fs::create_dir_all(&suricata_dir)?;

        // Load manifest of already-imported files
        let manifest_path = self.base_dir.join(".imported_manifest.json");
        let mut imported_files: std::collections::HashSet<String> = if manifest_path.exists() {
            let content = fs::read_to_string(&manifest_path)?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            std::collections::HashSet::new()
        };

        let mut new_imports = 0;

        // Scan all subdirectories for .rules files
        for subdir in &["", "suricata", "et-open", "rules"] {
            let dir = if subdir.is_empty() {
                self.base_dir.clone()
            } else {
                self.base_dir.join(subdir)
            };

            if !dir.exists() {
                continue;
            }

            // Find all .rules files
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.extension().map(|e| e == "rules").unwrap_or(false) {
                    let path_str = path.to_string_lossy().to_string();

                    // Skip if already imported
                    if imported_files.contains(&path_str) {
                        continue;
                    }

                    // Get filename without extension for the set name
                    let name = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("imported");

                    info!("Importing Suricata rules from {:?}...", path);

                    match self.import_suricata_to_dir(&path, name, &suricata_dir) {
                        Ok(set) => {
                            info!(
                                "Imported {} rules from {:?} as '{}'",
                                set.rules.len(),
                                path,
                                set.metadata.name
                            );
                            imported_files.insert(path_str);
                            new_imports += 1;
                        }
                        Err(e) => {
                            warn!("Failed to import {:?}: {}", path, e);
                        }
                    }
                }
            }
        }

        // Save updated manifest
        if new_imports > 0 {
            let manifest_content = serde_json::to_string_pretty(&imported_files)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            fs::write(&manifest_path, manifest_content)?;
            info!("Imported {} new Suricata rule file(s)", new_imports);
        }

        Ok(())
    }

    /// Import rules from a Suricata rules file to a specific directory
    fn import_suricata_to_dir(
        &mut self,
        input: &Path,
        name: &str,
        output_dir: &Path,
    ) -> std::io::Result<SignatureSet> {
        let content = fs::read_to_string(input)?;
        let mut set = SignatureSet::new(name, "suricata");
        set.metadata.id = format!("suricata-{}", sanitize_filename(name));
        set.metadata.description = format!("Imported from {:?}", input);

        let mut rule_id = 1u32;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            match super::parse_rule(line) {
                Ok(mut rule) => {
                    rule.id = rule_id;
                    rule_id += 1;
                    set.add_rule(rule);
                }
                Err(e) => {
                    debug!("Failed to parse rule: {} - {}", e, line);
                }
            }
        }

        // Save to the specified directory
        let filename = format!("{}.json", sanitize_filename(&set.metadata.id));
        let path = output_dir.join(&filename);

        let file = File::create(&path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, &set).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e)
        })?;

        self.sets.insert(set.metadata.id.clone(), set.clone());

        Ok(set)
    }

    /// Import rules from a Suricata rules file
    pub fn import_suricata(
        &mut self,
        input: &Path,
        name: &str,
    ) -> std::io::Result<SignatureSet> {
        let content = fs::read_to_string(input)?;
        let mut set = SignatureSet::new(name, "imported");
        set.metadata.description = format!("Imported from {:?}", input);

        let mut rule_id = 1u32;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            match super::parse_rule(line) {
                Ok(mut rule) => {
                    rule.id = rule_id;
                    rule_id += 1;
                    set.add_rule(rule);
                }
                Err(e) => {
                    debug!("Failed to parse rule: {} - {}", e, line);
                }
            }
        }

        info!(
            "Imported {} rules from {:?}",
            set.rules.len(),
            input
        );

        // Save the imported set
        self.save_set(&set)?;

        Ok(set)
    }

    /// Create a custom rule and save it
    pub fn add_custom_rule(&mut self, rule: Rule) -> std::io::Result<()> {
        // Load or create custom rules set
        let custom_id = "custom-rules";
        let mut set = match self.load_set(custom_id) {
            Ok(s) => s,
            Err(_) => {
                let mut s = SignatureSet::new("Custom Rules", "custom");
                s.metadata.id = custom_id.to_string();
                s.metadata.description = "User-defined custom rules".to_string();
                s
            }
        };

        set.add_rule(rule);
        self.save_set(&set)?;

        Ok(())
    }

    /// Get storage statistics
    pub fn stats(&self) -> StorageStats {
        let mut stats = StorageStats::default();

        stats.total_sets = self.sets.len();
        stats.total_rules = self.sets.values().map(|s| s.rules.len()).sum();
        stats.enabled_sets = self.sets.values().filter(|s| s.metadata.enabled).count();
        stats.enabled_rules = self
            .sets
            .values()
            .filter(|s| s.metadata.enabled)
            .map(|s| s.rules.len())
            .sum();

        // Calculate storage size
        if let Ok(entries) = fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    if metadata.is_file() {
                        stats.storage_bytes += metadata.len();
                    }
                }
            }
        }

        stats
    }
}

impl Default for SignatureStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Storage statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total number of signature sets
    pub total_sets: usize,
    /// Total number of rules across all sets
    pub total_rules: usize,
    /// Number of enabled sets
    pub enabled_sets: usize,
    /// Number of rules in enabled sets
    pub enabled_rules: usize,
    /// Total storage size in bytes
    pub storage_bytes: u64,
}

/// Sanitize a string for use as a filename
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_storage_init() {
        let temp = TempDir::new().unwrap();
        let storage = SignatureStorage::with_path(temp.path());
        storage.init().unwrap();

        assert!(temp.path().join("custom").exists());
        assert!(temp.path().join("imported").exists());
        assert!(temp.path().join("et-open").exists());
    }

    #[test]
    fn test_save_and_load_set() {
        let temp = TempDir::new().unwrap();
        let mut storage = SignatureStorage::with_path(temp.path());
        storage.init().unwrap();

        let mut set = SignatureSet::new("Test Set", "custom");
        set.metadata.id = "test-set".to_string();

        // Add a test rule
        let rule = Rule::default();
        set.add_rule(rule);

        // Save
        storage.save_set(&set).unwrap();

        // Load
        let loaded = storage.load_set("test-set").unwrap();
        assert_eq!(loaded.metadata.name, "Test Set");
        assert_eq!(loaded.rules.len(), 1);
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("test-rule_123"), "test-rule_123");
        assert_eq!(sanitize_filename("test/rule:123"), "test_rule_123");
        assert_eq!(sanitize_filename("test rule 123"), "test_rule_123");
    }
}
