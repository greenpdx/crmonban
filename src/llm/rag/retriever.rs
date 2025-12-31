//! RAG Retriever
//!
//! Retrieves relevant context from the vector store for LLM analysis.

use std::sync::Arc;

use tracing::{debug, warn};

use super::vectorstore::{SearchResult, VectorStore};
use super::RagConfig;
use crate::llm::provider::LlmProvider;

/// RAG retriever
pub struct RagRetriever {
    config: RagConfig,
    /// Vector store
    store: Arc<VectorStore>,
    /// Embedding provider
    embedder: Arc<dyn LlmProvider>,
}

impl RagRetriever {
    /// Create a new retriever
    pub fn new(
        config: RagConfig,
        store: Arc<VectorStore>,
        embedder: Arc<dyn LlmProvider>,
    ) -> Self {
        Self {
            config,
            store,
            embedder,
        }
    }

    /// Retrieve relevant context for a query
    pub async fn retrieve(&self, query: &str, top_k: usize) -> Result<String, String> {
        // Get query embedding
        let response = self.embedder.embed(&[query.to_string()]).await
            .map_err(|e| format!("Embedding failed: {}", e))?;
        if response.embeddings.is_empty() {
            return Err("No embedding returned".to_string());
        }

        let query_embedding = &response.embeddings[0];

        // Search vector store
        let k = if top_k > 0 { top_k } else { self.config.top_k };
        let results = self.store.search(query_embedding, k, self.config.similarity_threshold);

        if results.is_empty() {
            debug!("No relevant context found for query");
            return Ok(String::new());
        }

        // Format results as context
        let context = self.format_context(&results);
        debug!("Retrieved {} relevant documents", results.len());

        Ok(context)
    }

    /// Retrieve with source filter
    pub async fn retrieve_filtered(
        &self,
        query: &str,
        sources: &[String],
        top_k: usize,
    ) -> Result<String, String> {
        let response = self.embedder.embed(&[query.to_string()]).await
            .map_err(|e| format!("Embedding failed: {}", e))?;
        if response.embeddings.is_empty() {
            return Err("No embedding returned".to_string());
        }

        let query_embedding = &response.embeddings[0];
        let k = if top_k > 0 { top_k } else { self.config.top_k };
        let results = self.store.search_filtered(
            query_embedding,
            k,
            self.config.similarity_threshold,
            sources,
        );

        Ok(self.format_context(&results))
    }

    /// Retrieve MITRE ATT&CK context
    pub async fn retrieve_mitre(&self, query: &str) -> Result<String, String> {
        self.retrieve_filtered(query, &["mitre".to_string()], 3).await
    }

    /// Retrieve Sigma rules context
    pub async fn retrieve_sigma(&self, query: &str) -> Result<String, String> {
        self.retrieve_filtered(query, &["sigma".to_string()], 3).await
    }

    /// Format search results as context string
    fn format_context(&self, results: &[SearchResult]) -> String {
        if results.is_empty() {
            return String::new();
        }

        let mut context = String::new();

        for (i, result) in results.iter().enumerate() {
            let entry = &result.entry;

            context.push_str(&format!(
                "### Reference {} (relevance: {:.0}%)\n",
                i + 1,
                result.score * 100.0
            ));

            // Add source info
            if let Some(ref mitre_id) = entry.metadata.mitre_id {
                context.push_str(&format!("**MITRE ATT&CK**: {}\n", mitre_id));
            }

            if !entry.metadata.category.is_empty() {
                context.push_str(&format!("**Category**: {}\n", entry.metadata.category));
            }

            if let Some(ref severity) = entry.metadata.severity {
                context.push_str(&format!("**Severity**: {}\n", severity));
            }

            // Add text
            context.push_str("\n");
            context.push_str(&entry.text);
            context.push_str("\n\n");
        }

        context
    }

    /// Get retriever statistics
    pub fn stats(&self) -> RetrieverStats {
        RetrieverStats {
            total_documents: self.store.len(),
            source_counts: self.store.source_counts(),
            embedding_dim: self.store.embedding_dim(),
        }
    }

    /// Check if retriever is ready
    pub fn is_ready(&self) -> bool {
        !self.store.is_empty()
    }

    /// Get vector store reference
    pub fn store(&self) -> &Arc<VectorStore> {
        &self.store
    }
}

/// Retriever statistics
#[derive(Debug, Clone)]
pub struct RetrieverStats {
    pub total_documents: usize,
    pub source_counts: std::collections::HashMap<String, usize>,
    pub embedding_dim: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_context() {
        use super::super::vectorstore::{EntryMetadata, VectorEntry};

        let results = vec![
            SearchResult {
                entry: VectorEntry {
                    id: "1".to_string(),
                    doc_id: "doc1".to_string(),
                    text: "Test technique description".to_string(),
                    embedding: vec![],
                    metadata: EntryMetadata {
                        source: "mitre".to_string(),
                        category: "technique".to_string(),
                        mitre_id: Some("T1595".to_string()),
                        severity: Some("Medium".to_string()),
                        ..Default::default()
                    },
                },
                score: 0.95,
            },
        ];

        // Manual format test
        let context = format!(
            "### Reference 1 (relevance: {:.0}%)\n**MITRE ATT&CK**: T1595\n**Category**: technique\n**Severity**: Medium\n\nTest technique description\n\n",
            95.0
        );

        assert!(context.contains("T1595"));
        assert!(context.contains("95%"));
    }
}
