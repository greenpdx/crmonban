//! Ollama LLM Provider
//!
//! Local LLM provider using Ollama server.
//! https://ollama.ai/

use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::{
    CompletionRequest, CompletionResponse, EmbeddingResponse, LlmError, LlmProvider,
    ProviderHealth,
};
use crate::llm::config::{OllamaConfig, ProviderType};

/// Ollama provider
#[derive(Debug)]
pub struct OllamaProvider {
    config: OllamaConfig,
    client: Client,
}

impl OllamaProvider {
    /// Create a new Ollama provider
    pub fn new(config: OllamaConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    /// Get the generate API URL
    fn generate_url(&self) -> String {
        format!("{}/api/generate", self.config.url)
    }

    /// Get the chat API URL
    fn chat_url(&self) -> String {
        format!("{}/api/chat", self.config.url)
    }

    /// Get the embeddings API URL
    fn embed_url(&self) -> String {
        format!("{}/api/embeddings", self.config.url)
    }

    /// Get the tags API URL (for health check)
    fn tags_url(&self) -> String {
        format!("{}/api/tags", self.config.url)
    }
}

/// Ollama generate request
#[derive(Debug, Serialize)]
struct OllamaGenerateRequest {
    model: String,
    prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
}

/// Ollama chat request
#[derive(Debug, Serialize)]
struct OllamaChatRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    format: Option<String>,
}

/// Ollama message
#[derive(Debug, Serialize)]
struct OllamaMessage {
    role: String,
    content: String,
}

/// Ollama options
#[derive(Debug, Serialize)]
struct OllamaOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_ctx: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_gpu: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Vec<String>>,
}

/// Ollama generate response
#[derive(Debug, Deserialize)]
struct OllamaGenerateResponse {
    model: String,
    response: String,
    done: bool,
    #[serde(default)]
    total_duration: u64,
    #[serde(default)]
    prompt_eval_count: Option<usize>,
    #[serde(default)]
    eval_count: Option<usize>,
}

/// Ollama chat response
#[derive(Debug, Deserialize)]
struct OllamaChatResponse {
    model: String,
    message: OllamaChatMessage,
    done: bool,
    #[serde(default)]
    total_duration: u64,
    #[serde(default)]
    prompt_eval_count: Option<usize>,
    #[serde(default)]
    eval_count: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct OllamaChatMessage {
    role: String,
    content: String,
}

/// Ollama embedding request
#[derive(Debug, Serialize)]
struct OllamaEmbedRequest {
    model: String,
    prompt: String,
}

/// Ollama embedding response
#[derive(Debug, Deserialize)]
struct OllamaEmbedResponse {
    embedding: Vec<f32>,
}

/// Ollama tags response
#[derive(Debug, Deserialize)]
struct OllamaTagsResponse {
    models: Vec<OllamaModel>,
}

#[derive(Debug, Deserialize)]
struct OllamaModel {
    name: String,
    #[serde(default)]
    size: u64,
}

#[async_trait]
impl LlmProvider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Ollama
    }

    async fn health_check(&self) -> Result<ProviderHealth, LlmError> {
        let start = Instant::now();

        let response = self.client
            .get(&self.tags_url())
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    let tags: OllamaTagsResponse = resp.json().await
                        .map_err(|e| LlmError::InvalidResponse(e.to_string()))?;

                    let model_available = tags.models.iter()
                        .any(|m| m.name.starts_with(&self.config.model));

                    Ok(ProviderHealth {
                        available: model_available,
                        provider: "ollama".to_string(),
                        model: if model_available { Some(self.config.model.clone()) } else { None },
                        latency_ms: Some(start.elapsed().as_millis() as u64),
                        error: if !model_available {
                            Some(format!("Model {} not found", self.config.model))
                        } else {
                            None
                        },
                    })
                } else {
                    Ok(ProviderHealth {
                        available: false,
                        provider: "ollama".to_string(),
                        model: None,
                        latency_ms: Some(start.elapsed().as_millis() as u64),
                        error: Some(format!("HTTP {}", resp.status())),
                    })
                }
            }
            Err(e) => {
                Ok(ProviderHealth {
                    available: false,
                    provider: "ollama".to_string(),
                    model: None,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    error: Some(e.to_string()),
                })
            }
        }
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        let start = Instant::now();

        // Use chat API for system prompt support
        let mut messages = Vec::new();
        if let Some(system) = &request.system {
            messages.push(OllamaMessage {
                role: "system".to_string(),
                content: system.clone(),
            });
        }
        messages.push(OllamaMessage {
            role: "user".to_string(),
            content: request.prompt.clone(),
        });

        let ollama_request = OllamaChatRequest {
            model: self.config.model.clone(),
            messages,
            stream: false,
            options: Some(OllamaOptions {
                temperature: request.temperature.or(Some(self.config.temperature)),
                num_ctx: Some(self.config.num_ctx),
                num_gpu: Some(self.config.num_gpu),
                stop: request.stop,
            }),
            format: if request.json_schema.is_some() { Some("json".to_string()) } else { None },
        };

        debug!("Sending Ollama request: model={}", self.config.model);

        let response = self.client
            .post(&self.chat_url())
            .json(&ollama_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            warn!("Ollama error: {} - {}", status, body);

            if status.as_u16() == 404 {
                return Err(LlmError::ModelNotFound(self.config.model.clone()));
            }
            return Err(LlmError::Internal(format!("HTTP {}: {}", status, body)));
        }

        let ollama_response: OllamaChatResponse = response.json().await
            .map_err(|e| LlmError::InvalidResponse(e.to_string()))?;

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(CompletionResponse {
            text: ollama_response.message.content,
            prompt_tokens: ollama_response.prompt_eval_count,
            completion_tokens: ollama_response.eval_count,
            model: ollama_response.model,
            finish_reason: if ollama_response.done { Some("stop".to_string()) } else { None },
            duration_ms,
        })
    }

    async fn embed(&self, texts: &[String]) -> Result<EmbeddingResponse, LlmError> {
        let mut embeddings = Vec::with_capacity(texts.len());
        let mut total_tokens = 0usize;

        for text in texts {
            let request = OllamaEmbedRequest {
                model: self.config.model.clone(),
                prompt: text.clone(),
            };

            let response = self.client
                .post(&self.embed_url())
                .json(&request)
                .send()
                .await?;

            if !response.status().is_success() {
                return Err(LlmError::Internal(format!("HTTP {}", response.status())));
            }

            let embed_response: OllamaEmbedResponse = response.json().await
                .map_err(|e| LlmError::InvalidResponse(e.to_string()))?;

            embeddings.push(embed_response.embedding);
            total_tokens += text.len() / 4; // Approximate
        }

        Ok(EmbeddingResponse {
            embeddings,
            total_tokens: Some(total_tokens),
            model: self.config.model.clone(),
        })
    }

    fn count_tokens(&self, text: &str) -> usize {
        // Use tiktoken for accurate counting if available
        // For now, use approximation
        text.len() / 4
    }

    fn max_context(&self) -> usize {
        self.config.num_ctx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let config = OllamaConfig::default();
        let provider = OllamaProvider::new(config);
        assert_eq!(provider.name(), "ollama");
    }

    #[test]
    fn test_urls() {
        let config = OllamaConfig::default();
        let provider = OllamaProvider::new(config);

        assert!(provider.generate_url().contains("/api/generate"));
        assert!(provider.chat_url().contains("/api/chat"));
        assert!(provider.embed_url().contains("/api/embeddings"));
    }
}
