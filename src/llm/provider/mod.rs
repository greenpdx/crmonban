//! LLM Provider Abstraction
//!
//! Provides a unified interface for different LLM backends.

pub mod ollama;
pub mod llamacpp;

#[cfg(feature = "llm-cloud")]
pub mod openai;
#[cfg(feature = "llm-cloud")]
pub mod anthropic;

pub use ollama::OllamaProvider;
pub use llamacpp::LlamaCppProvider;

#[cfg(feature = "llm-cloud")]
pub use openai::OpenAIProvider;
#[cfg(feature = "llm-cloud")]
pub use anthropic::AnthropicProvider;

use std::fmt::Debug;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::config::ProviderType;

/// LLM Provider error types
#[derive(Debug, Error)]
pub enum LlmError {
    /// Provider not available
    #[error("Provider not available: {0}")]
    Unavailable(String),
    /// Connection error
    #[error("Connection error: {0}")]
    Connection(String),
    /// Request timeout
    #[error("Request timeout after {0}s")]
    Timeout(u64),
    /// Rate limited
    #[error("Rate limited: {0}")]
    RateLimited(String),
    /// Invalid response
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    /// Token limit exceeded
    #[error("Token limit exceeded: {used} > {limit}")]
    TokenLimit { used: usize, limit: usize },
    /// Authentication error
    #[error("Authentication error: {0}")]
    Authentication(String),
    /// Model not found
    #[error("Model not found: {0}")]
    ModelNotFound(String),
    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<reqwest::Error> for LlmError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            LlmError::Timeout(0)
        } else if err.is_connect() {
            LlmError::Connection(err.to_string())
        } else {
            LlmError::Internal(err.to_string())
        }
    }
}

/// Completion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionRequest {
    /// System prompt
    pub system: Option<String>,
    /// User prompt
    pub prompt: String,
    /// Maximum tokens to generate
    pub max_tokens: Option<usize>,
    /// Temperature (0-2)
    pub temperature: Option<f32>,
    /// Stop sequences
    pub stop: Option<Vec<String>>,
    /// Structured output format (JSON schema)
    pub json_schema: Option<String>,
}

impl CompletionRequest {
    /// Create a new completion request
    pub fn new(prompt: impl Into<String>) -> Self {
        Self {
            system: None,
            prompt: prompt.into(),
            max_tokens: None,
            temperature: None,
            stop: None,
            json_schema: None,
        }
    }

    /// Set system prompt
    pub fn with_system(mut self, system: impl Into<String>) -> Self {
        self.system = Some(system.into());
        self
    }

    /// Set max tokens
    pub fn with_max_tokens(mut self, max_tokens: usize) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// Set temperature
    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// Set stop sequences
    pub fn with_stop(mut self, stop: Vec<String>) -> Self {
        self.stop = Some(stop);
        self
    }

    /// Request JSON output
    pub fn with_json(mut self) -> Self {
        self.json_schema = Some("{}".to_string());
        self
    }
}

/// Completion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionResponse {
    /// Generated text
    pub text: String,
    /// Tokens used in prompt
    pub prompt_tokens: Option<usize>,
    /// Tokens generated
    pub completion_tokens: Option<usize>,
    /// Model used
    pub model: String,
    /// Finish reason
    pub finish_reason: Option<String>,
    /// Response time in milliseconds
    pub duration_ms: u64,
}

/// Embedding response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingResponse {
    /// Embedding vectors
    pub embeddings: Vec<Vec<f32>>,
    /// Tokens used
    pub total_tokens: Option<usize>,
    /// Model used
    pub model: String,
}

/// Provider health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHealth {
    /// Provider is available
    pub available: bool,
    /// Provider type
    pub provider: String,
    /// Model loaded
    pub model: Option<String>,
    /// Response time (ms)
    pub latency_ms: Option<u64>,
    /// Error message if unavailable
    pub error: Option<String>,
}

/// LLM Provider trait
#[async_trait]
pub trait LlmProvider: Send + Sync + Debug {
    /// Get provider name
    fn name(&self) -> &str;

    /// Get provider type
    fn provider_type(&self) -> ProviderType;

    /// Check if provider is available
    async fn health_check(&self) -> Result<ProviderHealth, LlmError>;

    /// Generate completion
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError>;

    /// Generate embeddings (if supported)
    async fn embed(&self, texts: &[String]) -> Result<EmbeddingResponse, LlmError> {
        Err(LlmError::Unavailable("Embeddings not supported by this provider".to_string()))
    }

    /// Count tokens in text
    fn count_tokens(&self, text: &str) -> usize {
        // Simple approximation: ~4 chars per token
        text.len() / 4
    }

    /// Get maximum context length
    fn max_context(&self) -> usize {
        8192 // Default
    }
}

/// Create provider from type
pub fn create_provider(
    provider_type: ProviderType,
    config: &super::config::LlmConfig,
) -> Result<Box<dyn LlmProvider>, LlmError> {
    match provider_type {
        ProviderType::Ollama => {
            Ok(Box::new(OllamaProvider::new(config.ollama.clone())))
        }
        ProviderType::LlamaCpp => {
            Ok(Box::new(LlamaCppProvider::new(config.llamacpp.clone())))
        }
        #[cfg(feature = "llm-cloud")]
        ProviderType::OpenAI => {
            Ok(Box::new(OpenAIProvider::new(config.openai.clone())?))
        }
        #[cfg(feature = "llm-cloud")]
        ProviderType::Anthropic => {
            Ok(Box::new(AnthropicProvider::new(config.anthropic.clone())?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_completion_request() {
        let req = CompletionRequest::new("Hello")
            .with_system("You are a helpful assistant")
            .with_max_tokens(100)
            .with_temperature(0.5);

        assert_eq!(req.prompt, "Hello");
        assert_eq!(req.system, Some("You are a helpful assistant".to_string()));
        assert_eq!(req.max_tokens, Some(100));
    }

    #[test]
    fn test_llm_error_from_reqwest() {
        // Can't easily create reqwest errors, but the conversion exists
    }
}
