//! Retrieval-Augmented Generation (RAG) System
//!
//! Provides context retrieval from threat intelligence sources for LLM analysis.

mod loader;
mod retriever;
mod vectorstore;

pub use loader::{CtiLoader, CtiSource, CtiDocument};
pub use retriever::RagRetriever;
pub use vectorstore::{VectorStore, VectorEntry, SearchResult};

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// RAG configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RagConfig {
    /// Enable RAG
    pub enabled: bool,
    /// Vector store path
    pub vector_store_path: PathBuf,
    /// Embedding model
    pub embedding_model: String,
    /// Number of results to retrieve
    pub top_k: usize,
    /// Similarity threshold (0.0-1.0)
    pub similarity_threshold: f32,
    /// CTI sources to load
    pub sources: Vec<CtiSourceConfig>,
    /// Update interval in hours
    pub update_interval_hours: u64,
}

impl Default for RagConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            vector_store_path: PathBuf::from("/var/lib/crmonban/llm/vectorstore"),
            embedding_model: "nomic-embed-text".to_string(),
            top_k: 3,
            similarity_threshold: 0.7,
            sources: vec![
                CtiSourceConfig {
                    source_type: CtiSource::MitreAttack,
                    enabled: true,
                    path: None,
                },
                CtiSourceConfig {
                    source_type: CtiSource::SigmaRules,
                    enabled: true,
                    path: Some(PathBuf::from("/var/lib/crmonban/data/signatures/sigma")),
                },
            ],
            update_interval_hours: 24,
        }
    }
}

/// CTI source configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtiSourceConfig {
    pub source_type: CtiSource,
    pub enabled: bool,
    pub path: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RagConfig::default();
        assert!(config.enabled);
        assert_eq!(config.top_k, 3);
    }
}
