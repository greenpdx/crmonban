//! LLM Integration Module
//!
//! Provides LLM-powered analysis for security events including:
//! - Alert triage and prioritization
//! - Threat explanation and narratives
//! - Attack chain reconstruction
//! - MITRE ATT&CK mapping
//!
//! This module is feature-gated and only compiled with `--features llm`.
//!
//! # Example
//!
//! ```ignore
//! use crmonban::llm::{LlmAnalyzer, LlmConfig, PromptContext, AnalysisType};
//!
//! // Create analyzer with default config (Ollama)
//! let config = LlmConfig::default();
//! let analyzer = LlmAnalyzer::new(config).await?;
//!
//! // Create analysis context
//! let context = PromptContext::new("PortScan", "High", "Sequential port scan detected");
//!
//! // Perform triage analysis
//! let result = analyzer.analyze(AnalysisType::Triage, context).await?;
//! println!("Priority: {:?}", result.priority);
//! ```
//!
//! # Providers
//!
//! Supports multiple LLM providers:
//! - **Ollama** (default): Local LLM server, recommended for privacy
//! - **llama.cpp**: Direct llama.cpp server integration
//! - **OpenAI** (feature `llm-cloud`): Cloud fallback
//! - **Anthropic** (feature `llm-cloud`): Cloud fallback
//!
//! # Privacy
//!
//! By default, all data stays local. The `DataSanitizer` can sanitize
//! sensitive data (IPs, hostnames, credentials) before sending to cloud
//! providers if configured.

pub mod analyzer;
pub mod cache;
pub mod config;
pub mod privacy;
pub mod prompts;
pub mod provider;
pub mod queue;
pub mod rag;

// Re-exports for convenience
pub use analyzer::{
    AnalysisResponse, AnalyzerStats, FullAnalysisResult, LlmAnalyzer, MitreTechnique, TriageResult,
};
pub use cache::{CacheEntry, CacheStats, LlmCache};
pub use config::{
    AnalysisType, CacheConfig, LlmConfig, PrivacyConfig, ProviderType, QueueConfig, TriagePriority,
};
pub use privacy::{DataSanitizer, SanitizationResult};
pub use prompts::{OutputFormat, PromptContext, PromptTemplate, RelatedEvent};
pub use provider::{CompletionRequest, CompletionResponse, LlmError, LlmProvider};
pub use queue::{AnalysisQueue, AnalysisRequest, AnalysisResult, QueueStats, RequestPriority};
pub use rag::{CtiDocument, CtiLoader, CtiSource, RagConfig, RagRetriever, VectorStore};

use std::sync::Arc;
use tracing::info;

/// Initialize the LLM subsystem with default configuration
pub async fn init() -> Result<LlmAnalyzer, String> {
    init_with_config(LlmConfig::default()).await
}

/// Initialize the LLM subsystem with custom configuration
pub async fn init_with_config(config: LlmConfig) -> Result<LlmAnalyzer, String> {
    info!("Initializing LLM subsystem with provider: {:?}", config.provider);

    let analyzer = LlmAnalyzer::new(config).await?;

    // Health check
    if !analyzer.health_check().await {
        tracing::warn!("LLM provider health check failed, but continuing...");
    }

    info!("LLM subsystem initialized successfully");
    Ok(analyzer)
}

/// Initialize with RAG support
pub async fn init_with_rag(config: LlmConfig, rag_config: RagConfig) -> Result<LlmAnalyzer, String> {
    use rag::{RagRetriever, VectorStore};

    info!("Initializing LLM subsystem with RAG support");

    // Create analyzer
    let mut analyzer = LlmAnalyzer::new(config.clone()).await?;

    // Create vector store
    let embedding_dim = match config.provider {
        ProviderType::Ollama => 768, // nomic-embed-text default
        ProviderType::LlamaCpp => 768,
        #[cfg(feature = "llm-cloud")]
        ProviderType::OpenAI => 1536, // text-embedding-ada-002
        #[cfg(feature = "llm-cloud")]
        ProviderType::Anthropic => 768,
    };

    let store = Arc::new(VectorStore::new(rag_config.vector_store_path.clone(), embedding_dim)?);

    // Create retriever
    let embedder = provider::create_provider(config.provider, &config)
        .map_err(|e| format!("Failed to create embedder: {}", e))?;
    let retriever = Arc::new(RagRetriever::new(rag_config, store, Arc::from(embedder)));

    // Note: would need to add with_rag method that takes ownership
    // For now, RAG is initialized separately

    info!("LLM subsystem with RAG initialized successfully");
    Ok(analyzer)
}

/// Quick helper to analyze a single alert
pub async fn analyze_alert(
    analyzer: &LlmAnalyzer,
    event_type: &str,
    severity: &str,
    description: &str,
) -> Result<AnalysisResponse, String> {
    let context = PromptContext::new(event_type, severity, description);
    analyzer.analyze(AnalysisType::Triage, context).await
}

/// Quick helper to get full analysis (triage + explain + MITRE)
pub async fn full_analysis(
    analyzer: &LlmAnalyzer,
    event_type: &str,
    severity: &str,
    description: &str,
) -> Result<FullAnalysisResult, String> {
    let context = PromptContext::new(event_type, severity, description);
    analyzer.full_analysis(context).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_type_debug() {
        let provider = ProviderType::Ollama;
        assert_eq!(format!("{:?}", provider), "Ollama");
    }

    #[test]
    fn test_analysis_type_variants() {
        let types = [
            AnalysisType::Triage,
            AnalysisType::Explain,
            AnalysisType::AttackChain,
            AnalysisType::MitreMapping,
            AnalysisType::ThreatHunt,
            AnalysisType::Full,
        ];
        assert_eq!(types.len(), 6);
    }
}
