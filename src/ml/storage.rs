//! ML Model Storage and Persistence
//!
//! Handles saving and loading ML baselines and models to /var/lib/crmonban/data/ml

use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::baseline::Baseline;
use super::models::IsolationForest;

/// Default ML data storage directory
pub const ML_DATA_DIR: &str = "/var/lib/crmonban/data/ml";

/// ML storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLStorageConfig {
    /// Base directory for ML data
    pub data_dir: PathBuf,
    /// Auto-save interval in seconds
    pub auto_save_interval: u64,
    /// Keep backup copies
    pub keep_backups: bool,
    /// Maximum backup files to keep
    pub max_backups: usize,
}

impl Default for MLStorageConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from(ML_DATA_DIR),
            auto_save_interval: 3600, // 1 hour
            keep_backups: true,
            max_backups: 5,
        }
    }
}

/// Metadata about stored ML data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLDataMetadata {
    /// Version of the storage format
    pub version: u32,
    /// When the data was saved
    pub saved_at: DateTime<Utc>,
    /// Total samples in baseline
    pub baseline_samples: u64,
    /// When baseline learning started
    pub baseline_started: DateTime<Utc>,
    /// Number of trained models
    pub model_count: usize,
    /// Host identifier
    pub host_id: String,
}

impl Default for MLDataMetadata {
    fn default() -> Self {
        Self {
            version: 1,
            saved_at: Utc::now(),
            baseline_samples: 0,
            baseline_started: Utc::now(),
            model_count: 0,
            host_id: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
        }
    }
}

/// ML data storage manager
pub struct MLStorage {
    /// Base directory for ML data
    data_dir: PathBuf,
    /// Configuration
    config: MLStorageConfig,
}

impl MLStorage {
    /// Create a new ML storage manager with default directory
    pub fn new() -> Self {
        Self::with_config(MLStorageConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: MLStorageConfig) -> Self {
        Self {
            data_dir: config.data_dir.clone(),
            config,
        }
    }

    /// Create with custom path
    pub fn with_path<P: AsRef<Path>>(path: P) -> Self {
        let mut config = MLStorageConfig::default();
        config.data_dir = path.as_ref().to_path_buf();
        Self::with_config(config)
    }

    /// Get the base directory
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Initialize the storage directory structure
    pub fn init(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.data_dir)?;
        fs::create_dir_all(self.data_dir.join("baselines"))?;
        fs::create_dir_all(self.data_dir.join("models"))?;
        fs::create_dir_all(self.data_dir.join("backups"))?;
        fs::create_dir_all(self.data_dir.join("training"))?;

        info!("Initialized ML storage at {:?}", self.data_dir);
        Ok(())
    }

    // === Baseline Operations ===

    /// Get path to baseline file
    fn baseline_path(&self) -> PathBuf {
        self.data_dir.join("baselines").join("baseline.bin")
    }

    /// Get path to baseline backup
    fn baseline_backup_path(&self, index: usize) -> PathBuf {
        self.data_dir
            .join("backups")
            .join(format!("baseline.{}.bin", index))
    }

    /// Save baseline to storage
    pub fn save_baseline(&self, baseline: &Baseline) -> anyhow::Result<()> {
        let path = self.baseline_path();

        // Create backup of existing file
        if self.config.keep_backups && path.exists() {
            self.rotate_backups("baseline.bin")?;
        }

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Save baseline
        baseline.save(&path)?;

        // Save metadata
        let metadata = MLDataMetadata {
            version: 1,
            saved_at: Utc::now(),
            baseline_samples: baseline.total_samples,
            baseline_started: baseline.started,
            model_count: 0,
            host_id: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
        };
        self.save_metadata(&metadata)?;

        info!(
            "Saved baseline with {} samples to {:?}",
            baseline.total_samples, path
        );

        Ok(())
    }

    /// Load baseline from storage
    pub fn load_baseline(&self) -> anyhow::Result<Option<Baseline>> {
        let path = self.baseline_path();

        if !path.exists() {
            debug!("No baseline file found at {:?}", path);
            return Ok(None);
        }

        match Baseline::load(&path) {
            Ok(baseline) => {
                info!(
                    "Loaded baseline with {} samples (started: {})",
                    baseline.total_samples,
                    baseline.started.format("%Y-%m-%d %H:%M:%S")
                );
                Ok(Some(baseline))
            }
            Err(e) => {
                warn!("Failed to load baseline from {:?}: {}", path, e);
                // Try to load from backup
                self.load_baseline_from_backup()
            }
        }
    }

    /// Try to load baseline from backup files
    fn load_baseline_from_backup(&self) -> anyhow::Result<Option<Baseline>> {
        for i in 0..self.config.max_backups {
            let backup_path = self.baseline_backup_path(i);
            if backup_path.exists() {
                match Baseline::load(&backup_path) {
                    Ok(baseline) => {
                        info!(
                            "Restored baseline from backup {} ({} samples)",
                            i, baseline.total_samples
                        );
                        return Ok(Some(baseline));
                    }
                    Err(e) => {
                        debug!("Failed to load backup {}: {}", i, e);
                    }
                }
            }
        }
        Ok(None)
    }

    /// Check if baseline exists
    pub fn has_baseline(&self) -> bool {
        self.baseline_path().exists()
    }

    /// Get baseline info without loading
    pub fn baseline_info(&self) -> Option<MLDataMetadata> {
        self.load_metadata().ok()
    }

    // === Model Operations ===

    /// Save isolation forest model
    pub fn save_model(&self, name: &str, model: &IsolationForest) -> anyhow::Result<()> {
        let path = self.data_dir.join("models").join(format!("{}.bin", name));

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = File::create(&path)?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, model)?;

        info!("Saved model '{}' to {:?}", name, path);
        Ok(())
    }

    /// Load isolation forest model
    pub fn load_model(&self, name: &str) -> anyhow::Result<Option<IsolationForest>> {
        let path = self.data_dir.join("models").join(format!("{}.bin", name));

        if !path.exists() {
            return Ok(None);
        }

        let file = File::open(&path)?;
        let reader = BufReader::new(file);
        let model: IsolationForest = bincode::deserialize_from(reader)?;

        info!("Loaded model '{}' from {:?}", name, path);
        Ok(Some(model))
    }

    /// List available models
    pub fn list_models(&self) -> std::io::Result<Vec<String>> {
        let models_dir = self.data_dir.join("models");
        let mut models = Vec::new();

        if !models_dir.exists() {
            return Ok(models);
        }

        for entry in fs::read_dir(&models_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "bin").unwrap_or(false) {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    models.push(name.to_string());
                }
            }
        }

        Ok(models)
    }

    // === Metadata Operations ===

    /// Save metadata
    fn save_metadata(&self, metadata: &MLDataMetadata) -> anyhow::Result<()> {
        let path = self.data_dir.join("metadata.json");
        let content = serde_json::to_string_pretty(metadata)?;
        fs::write(path, content)?;
        Ok(())
    }

    /// Load metadata
    fn load_metadata(&self) -> anyhow::Result<MLDataMetadata> {
        let path = self.data_dir.join("metadata.json");
        let content = fs::read_to_string(path)?;
        let metadata: MLDataMetadata = serde_json::from_str(&content)?;
        Ok(metadata)
    }

    // === Backup Operations ===

    /// Rotate backup files
    fn rotate_backups(&self, filename: &str) -> anyhow::Result<()> {
        let backup_dir = self.data_dir.join("backups");
        fs::create_dir_all(&backup_dir)?;

        // Remove oldest backup if at limit
        let oldest = backup_dir.join(format!("{}.{}", filename, self.config.max_backups - 1));
        if oldest.exists() {
            fs::remove_file(&oldest)?;
        }

        // Rotate existing backups
        for i in (0..self.config.max_backups - 1).rev() {
            let current = backup_dir.join(format!("{}.{}", filename, i));
            let next = backup_dir.join(format!("{}.{}", filename, i + 1));
            if current.exists() {
                fs::rename(&current, &next)?;
            }
        }

        // Copy current file to backup.0
        let source = self.data_dir.join("baselines").join(filename);
        let dest = backup_dir.join(format!("{}.0", filename));
        if source.exists() {
            fs::copy(&source, &dest)?;
        }

        Ok(())
    }

    /// Get storage statistics
    pub fn stats(&self) -> StorageStats {
        let mut stats = StorageStats::default();

        // Count baselines
        if self.baseline_path().exists() {
            stats.has_baseline = true;
            if let Ok(metadata) = fs::metadata(self.baseline_path()) {
                stats.baseline_size = metadata.len();
            }
        }

        // Count models
        if let Ok(models) = self.list_models() {
            stats.model_count = models.len();
        }

        // Calculate total size
        if let Ok(entries) = fs::read_dir(&self.data_dir) {
            for entry in entries.flatten() {
                if let Ok(metadata) = entry.metadata() {
                    stats.total_size += metadata.len();
                }
            }
        }

        stats
    }

    /// Clean up old data
    pub fn cleanup(&self, keep_days: u32) -> anyhow::Result<()> {
        let cutoff = Utc::now() - chrono::Duration::days(keep_days as i64);
        let backup_dir = self.data_dir.join("backups");

        if backup_dir.exists() {
            for entry in fs::read_dir(&backup_dir)? {
                let entry = entry?;
                if let Ok(metadata) = entry.metadata() {
                    if let Ok(modified) = metadata.modified() {
                        let modified: DateTime<Utc> = modified.into();
                        if modified < cutoff {
                            fs::remove_file(entry.path())?;
                            debug!("Removed old backup: {:?}", entry.path());
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for MLStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Storage statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageStats {
    /// Whether a baseline exists
    pub has_baseline: bool,
    /// Baseline file size in bytes
    pub baseline_size: u64,
    /// Number of saved models
    pub model_count: usize,
    /// Total storage size in bytes
    pub total_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_storage_init() {
        let temp = TempDir::new().unwrap();
        let storage = MLStorage::with_path(temp.path());
        storage.init().unwrap();

        assert!(temp.path().join("baselines").exists());
        assert!(temp.path().join("models").exists());
        assert!(temp.path().join("backups").exists());
    }

    #[test]
    fn test_baseline_save_load() {
        let temp = TempDir::new().unwrap();
        let storage = MLStorage::with_path(temp.path());
        storage.init().unwrap();

        // Create a baseline
        let baseline = Baseline::new();

        // Save it
        storage.save_baseline(&baseline).unwrap();
        assert!(storage.has_baseline());

        // Load it back
        let loaded = storage.load_baseline().unwrap();
        assert!(loaded.is_some());
    }
}
