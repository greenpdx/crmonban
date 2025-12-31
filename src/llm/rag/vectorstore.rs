//! Vector Store for RAG
//!
//! Stores and retrieves embeddings for threat intelligence context.

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

/// Vector store entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VectorEntry {
    /// Unique ID
    pub id: String,
    /// Source document ID
    pub doc_id: String,
    /// Text chunk
    pub text: String,
    /// Embedding vector
    pub embedding: Vec<f32>,
    /// Metadata
    pub metadata: EntryMetadata,
}

/// Entry metadata
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntryMetadata {
    /// Source type (mitre, sigma, nvd, etc.)
    pub source: String,
    /// Category (technique, rule, vulnerability)
    pub category: String,
    /// Tags
    pub tags: Vec<String>,
    /// MITRE technique ID if applicable
    pub mitre_id: Option<String>,
    /// Severity if applicable
    pub severity: Option<String>,
    /// Creation timestamp
    pub created_at: u64,
}

/// Search result
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Entry
    pub entry: VectorEntry,
    /// Similarity score (0.0-1.0)
    pub score: f32,
}

/// Vector store
pub struct VectorStore {
    /// Storage path
    path: PathBuf,
    /// In-memory index
    index: RwLock<VectorIndex>,
    /// Embedding dimension
    embedding_dim: usize,
}

/// In-memory vector index
#[derive(Default, Serialize, Deserialize)]
struct VectorIndex {
    /// Entries by ID
    entries: HashMap<String, VectorEntry>,
    /// Document count by source
    doc_counts: HashMap<String, usize>,
}

impl VectorStore {
    /// Create or open vector store
    pub fn new(path: PathBuf, embedding_dim: usize) -> Result<Self, String> {
        // Create directory if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Failed to create directory: {}", e))?;
        }

        // Load existing index if present
        let index = if path.exists() {
            Self::load_index(&path)?
        } else {
            VectorIndex::default()
        };

        Ok(Self {
            path,
            index: RwLock::new(index),
            embedding_dim,
        })
    }

    /// Load index from disk
    fn load_index(path: &PathBuf) -> Result<VectorIndex, String> {
        let file = File::open(path).map_err(|e| format!("Failed to open index: {}", e))?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).map_err(|e| format!("Failed to parse index: {}", e))
    }

    /// Save index to disk
    pub fn save(&self) -> Result<(), String> {
        let index = self.index.read().map_err(|_| "Lock poisoned")?;
        let file = File::create(&self.path).map_err(|e| format!("Failed to create file: {}", e))?;
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, &*index).map_err(|e| format!("Failed to write index: {}", e))
    }

    /// Add entry to store
    pub fn add(&self, entry: VectorEntry) -> Result<(), String> {
        if entry.embedding.len() != self.embedding_dim {
            return Err(format!(
                "Embedding dimension mismatch: expected {}, got {}",
                self.embedding_dim,
                entry.embedding.len()
            ));
        }

        let mut index = self.index.write().map_err(|_| "Lock poisoned")?;
        let source = entry.metadata.source.clone();
        index.entries.insert(entry.id.clone(), entry);
        *index.doc_counts.entry(source).or_insert(0) += 1;

        Ok(())
    }

    /// Add multiple entries
    pub fn add_batch(&self, entries: Vec<VectorEntry>) -> Result<usize, String> {
        let mut added = 0;
        for entry in entries {
            if self.add(entry).is_ok() {
                added += 1;
            }
        }
        Ok(added)
    }

    /// Search for similar vectors
    pub fn search(&self, query_embedding: &[f32], top_k: usize, threshold: f32) -> Vec<SearchResult> {
        let index = match self.index.read() {
            Ok(idx) => idx,
            Err(_) => return Vec::new(),
        };

        let mut results: Vec<SearchResult> = index
            .entries
            .values()
            .filter_map(|entry| {
                let score = cosine_similarity(query_embedding, &entry.embedding);
                if score >= threshold {
                    Some(SearchResult {
                        entry: entry.clone(),
                        score,
                    })
                } else {
                    None
                }
            })
            .collect();

        // Sort by score descending
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

        // Take top_k
        results.truncate(top_k);
        results
    }

    /// Search with source filter
    pub fn search_filtered(
        &self,
        query_embedding: &[f32],
        top_k: usize,
        threshold: f32,
        sources: &[String],
    ) -> Vec<SearchResult> {
        let index = match self.index.read() {
            Ok(idx) => idx,
            Err(_) => return Vec::new(),
        };

        let mut results: Vec<SearchResult> = index
            .entries
            .values()
            .filter(|entry| sources.is_empty() || sources.contains(&entry.metadata.source))
            .filter_map(|entry| {
                let score = cosine_similarity(query_embedding, &entry.embedding);
                if score >= threshold {
                    Some(SearchResult {
                        entry: entry.clone(),
                        score,
                    })
                } else {
                    None
                }
            })
            .collect();

        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        results.truncate(top_k);
        results
    }

    /// Get entry by ID
    pub fn get(&self, id: &str) -> Option<VectorEntry> {
        let index = self.index.read().ok()?;
        index.entries.get(id).cloned()
    }

    /// Remove entry by ID
    pub fn remove(&self, id: &str) -> bool {
        let mut index = match self.index.write() {
            Ok(idx) => idx,
            Err(_) => return false,
        };

        if let Some(entry) = index.entries.remove(id) {
            if let Some(count) = index.doc_counts.get_mut(&entry.metadata.source) {
                *count = count.saturating_sub(1);
            }
            true
        } else {
            false
        }
    }

    /// Clear all entries from a source
    pub fn clear_source(&self, source: &str) -> usize {
        let mut index = match self.index.write() {
            Ok(idx) => idx,
            Err(_) => return 0,
        };

        let ids_to_remove: Vec<String> = index
            .entries
            .iter()
            .filter(|(_, e)| e.metadata.source == source)
            .map(|(id, _)| id.clone())
            .collect();

        let count = ids_to_remove.len();
        for id in ids_to_remove {
            index.entries.remove(&id);
        }
        index.doc_counts.insert(source.to_string(), 0);

        count
    }

    /// Get total entry count
    pub fn len(&self) -> usize {
        self.index.read().map(|idx| idx.entries.len()).unwrap_or(0)
    }

    /// Check if store is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get counts by source
    pub fn source_counts(&self) -> HashMap<String, usize> {
        self.index
            .read()
            .map(|idx| idx.doc_counts.clone())
            .unwrap_or_default()
    }

    /// Get embedding dimension
    pub fn embedding_dim(&self) -> usize {
        self.embedding_dim
    }
}

/// Compute cosine similarity between two vectors
fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }

    let dot_product: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }

    dot_product / (norm_a * norm_b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_entry(id: &str, embedding: Vec<f32>) -> VectorEntry {
        VectorEntry {
            id: id.to_string(),
            doc_id: format!("doc_{}", id),
            text: format!("Test text for {}", id),
            embedding,
            metadata: EntryMetadata {
                source: "test".to_string(),
                category: "test".to_string(),
                ..Default::default()
            },
        }
    }

    #[test]
    fn test_cosine_similarity() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert!((cosine_similarity(&a, &b) - 1.0).abs() < 0.0001);

        let c = vec![0.0, 1.0, 0.0];
        assert!((cosine_similarity(&a, &c) - 0.0).abs() < 0.0001);

        let d = vec![0.707, 0.707, 0.0];
        assert!((cosine_similarity(&a, &d) - 0.707).abs() < 0.01);
    }

    #[test]
    fn test_vector_store_add_search() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test_store.json");
        let store = VectorStore::new(path, 3).unwrap();

        // Add entries
        store.add(test_entry("1", vec![1.0, 0.0, 0.0])).unwrap();
        store.add(test_entry("2", vec![0.9, 0.1, 0.0])).unwrap();
        store.add(test_entry("3", vec![0.0, 1.0, 0.0])).unwrap();

        assert_eq!(store.len(), 3);

        // Search
        let results = store.search(&[1.0, 0.0, 0.0], 2, 0.5);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].entry.id, "1");
        assert!((results[0].score - 1.0).abs() < 0.0001);
    }

    #[test]
    fn test_vector_store_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("persist_store.json");

        // Create and add
        {
            let store = VectorStore::new(path.clone(), 3).unwrap();
            store.add(test_entry("1", vec![1.0, 0.0, 0.0])).unwrap();
            store.save().unwrap();
        }

        // Reload
        {
            let store = VectorStore::new(path, 3).unwrap();
            assert_eq!(store.len(), 1);
            assert!(store.get("1").is_some());
        }
    }

    #[test]
    fn test_dimension_mismatch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("dim_store.json");
        let store = VectorStore::new(path, 3).unwrap();

        let result = store.add(test_entry("1", vec![1.0, 0.0])); // Wrong dimension
        assert!(result.is_err());
    }
}
