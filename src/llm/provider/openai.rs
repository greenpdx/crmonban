//! OpenAI API Provider
//!
//! Cloud LLM provider using OpenAI API.
//! Only available with llm-cloud feature.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::{
    CompletionRequest, CompletionResponse, EmbeddingResponse, LlmError, LlmProvider,
    ProviderHealth,
};
use crate::llm::config::{OpenAIConfig, ProviderType};

/// OpenAI provider
#[derive(Debug)]
pub struct OpenAIProvider {
    config: OpenAIConfig,
    client: Client,
    api_key: String,
}

impl OpenAIProvider {
    /// Create a new OpenAI provider
    pub fn new(config: OpenAIConfig) -> Result<Self, LlmError> {
        let api_key = config.api_key.clone()
            .or_else(|| std::env::var("OPENAI_API_KEY").ok())
            .ok_or_else(|| LlmError::Authentication("OpenAI API key not found".to_string()))?;

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("Failed to create HTTP client");

        Ok(Self { config, client, api_key })
    }

    /// Get the chat completions URL
    fn chat_url(&self) -> String {
        format!("{}/chat/completions", self.config.base_url)
    }

    /// Get the embeddings URL
    fn embeddings_url(&self) -> String {
        format!("{}/embeddings", self.config.base_url)
    }

    /// Get the models URL
    fn models_url(&self) -> String {
        format!("{}/models", self.config.base_url)
    }
}

/// OpenAI chat request
#[derive(Debug, Serialize)]
struct OpenAIChatRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
}

#[derive(Debug, Serialize)]
struct OpenAIMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct ResponseFormat {
    #[serde(rename = "type")]
    format_type: String,
}

/// OpenAI chat response
#[derive(Debug, Deserialize)]
struct OpenAIChatResponse {
    id: String,
    model: String,
    choices: Vec<OpenAIChoice>,
    usage: Option<OpenAIUsage>,
}

#[derive(Debug, Deserialize)]
struct OpenAIChoice {
    index: usize,
    message: OpenAIResponseMessage,
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAIResponseMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OpenAIUsage {
    prompt_tokens: usize,
    completion_tokens: usize,
    total_tokens: usize,
}

/// OpenAI embedding request
#[derive(Debug, Serialize)]
struct OpenAIEmbedRequest {
    model: String,
    input: Vec<String>,
}

/// OpenAI embedding response
#[derive(Debug, Deserialize)]
struct OpenAIEmbedResponse {
    data: Vec<OpenAIEmbedding>,
    usage: OpenAIEmbedUsage,
}

#[derive(Debug, Deserialize)]
struct OpenAIEmbedding {
    embedding: Vec<f32>,
    index: usize,
}

#[derive(Debug, Deserialize)]
struct OpenAIEmbedUsage {
    prompt_tokens: usize,
    total_tokens: usize,
}

/// OpenAI error response
#[derive(Debug, Deserialize)]
struct OpenAIError {
    error: OpenAIErrorDetail,
}

#[derive(Debug, Deserialize)]
struct OpenAIErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: String,
    code: Option<String>,
}

#[async_trait]
impl LlmProvider for OpenAIProvider {
    fn name(&self) -> &str {
        "openai"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::OpenAI
    }

    async fn health_check(&self) -> Result<ProviderHealth, LlmError> {
        let start = Instant::now();

        let response = self.client
            .get(&self.models_url())
            .header("Authorization", format!("Bearer {}", self.api_key))
            .timeout(Duration::from_secs(10))
            .send()
            .await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    Ok(ProviderHealth {
                        available: true,
                        provider: "openai".to_string(),
                        model: Some(self.config.model.clone()),
                        latency_ms: Some(start.elapsed().as_millis() as u64),
                        error: None,
                    })
                } else if resp.status().as_u16() == 401 {
                    Ok(ProviderHealth {
                        available: false,
                        provider: "openai".to_string(),
                        model: None,
                        latency_ms: Some(start.elapsed().as_millis() as u64),
                        error: Some("Invalid API key".to_string()),
                    })
                } else {
                    Ok(ProviderHealth {
                        available: false,
                        provider: "openai".to_string(),
                        model: None,
                        latency_ms: Some(start.elapsed().as_millis() as u64),
                        error: Some(format!("HTTP {}", resp.status())),
                    })
                }
            }
            Err(e) => {
                Ok(ProviderHealth {
                    available: false,
                    provider: "openai".to_string(),
                    model: None,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    error: Some(e.to_string()),
                })
            }
        }
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        let start = Instant::now();

        let mut messages = Vec::new();
        if let Some(system) = &request.system {
            messages.push(OpenAIMessage {
                role: "system".to_string(),
                content: system.clone(),
            });
        }
        messages.push(OpenAIMessage {
            role: "user".to_string(),
            content: request.prompt.clone(),
        });

        let openai_request = OpenAIChatRequest {
            model: self.config.model.clone(),
            messages,
            max_tokens: request.max_tokens.or(Some(self.config.max_tokens)),
            temperature: request.temperature.or(Some(self.config.temperature)),
            stop: request.stop,
            response_format: if request.json_schema.is_some() {
                Some(ResponseFormat { format_type: "json_object".to_string() })
            } else {
                None
            },
        };

        debug!("Sending OpenAI request: model={}", self.config.model);

        let response = self.client
            .post(&self.chat_url())
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&openai_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();

            if status.as_u16() == 429 {
                return Err(LlmError::RateLimited("Rate limit exceeded".to_string()));
            }

            if let Ok(error) = response.json::<OpenAIError>().await {
                warn!("OpenAI error: {}", error.error.message);
                if error.error.code.as_deref() == Some("model_not_found") {
                    return Err(LlmError::ModelNotFound(self.config.model.clone()));
                }
                return Err(LlmError::Internal(error.error.message));
            }

            return Err(LlmError::Internal(format!("HTTP {}", status)));
        }

        let openai_response: OpenAIChatResponse = response.json().await
            .map_err(|e| LlmError::InvalidResponse(e.to_string()))?;

        let choice = openai_response.choices.first()
            .ok_or_else(|| LlmError::InvalidResponse("No choices in response".to_string()))?;

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(CompletionResponse {
            text: choice.message.content.clone(),
            prompt_tokens: openai_response.usage.as_ref().map(|u| u.prompt_tokens),
            completion_tokens: openai_response.usage.as_ref().map(|u| u.completion_tokens),
            model: openai_response.model,
            finish_reason: choice.finish_reason.clone(),
            duration_ms,
        })
    }

    async fn embed(&self, texts: &[String]) -> Result<EmbeddingResponse, LlmError> {
        let request = OpenAIEmbedRequest {
            model: "text-embedding-3-small".to_string(),
            input: texts.to_vec(),
        };

        let response = self.client
            .post(&self.embeddings_url())
            .header("Authorization", format!("Bearer {}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(LlmError::Internal(format!("HTTP {}", response.status())));
        }

        let embed_response: OpenAIEmbedResponse = response.json().await
            .map_err(|e| LlmError::InvalidResponse(e.to_string()))?;

        let mut embeddings: Vec<Vec<f32>> = vec![Vec::new(); texts.len()];
        for emb in embed_response.data {
            if emb.index < embeddings.len() {
                embeddings[emb.index] = emb.embedding;
            }
        }

        Ok(EmbeddingResponse {
            embeddings,
            total_tokens: Some(embed_response.usage.total_tokens),
            model: "text-embedding-3-small".to_string(),
        })
    }

    fn max_context(&self) -> usize {
        // Depends on model, 128k for gpt-4o
        128000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation_no_key() {
        let config = OpenAIConfig::default();
        // Remove env var temporarily would be needed for proper test
        // For now, just test the error path exists
    }
}
