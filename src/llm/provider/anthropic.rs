//! Anthropic Claude API Provider
//!
//! Cloud LLM provider using Anthropic Claude API.
//! Only available with llm-cloud feature.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::{
    CompletionRequest, CompletionResponse, LlmError, LlmProvider, ProviderHealth,
};
use crate::llm::config::{AnthropicConfig, ProviderType};

/// Anthropic API version
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Anthropic provider
#[derive(Debug)]
pub struct AnthropicProvider {
    config: AnthropicConfig,
    client: Client,
    api_key: String,
}

impl AnthropicProvider {
    /// Create a new Anthropic provider
    pub fn new(config: AnthropicConfig) -> Result<Self, LlmError> {
        let api_key = config.api_key.clone()
            .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
            .ok_or_else(|| LlmError::Authentication("Anthropic API key not found".to_string()))?;

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("Failed to create HTTP client");

        Ok(Self { config, client, api_key })
    }

    /// Get the messages API URL
    fn messages_url(&self) -> String {
        "https://api.anthropic.com/v1/messages".to_string()
    }
}

/// Anthropic messages request
#[derive(Debug, Serialize)]
struct AnthropicMessagesRequest {
    model: String,
    max_tokens: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<String>,
    messages: Vec<AnthropicMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_sequences: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

/// Anthropic messages response
#[derive(Debug, Deserialize)]
struct AnthropicMessagesResponse {
    id: String,
    #[serde(rename = "type")]
    response_type: String,
    role: String,
    content: Vec<AnthropicContent>,
    model: String,
    stop_reason: Option<String>,
    usage: AnthropicUsage,
}

#[derive(Debug, Deserialize)]
struct AnthropicContent {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicUsage {
    input_tokens: usize,
    output_tokens: usize,
}

/// Anthropic error response
#[derive(Debug, Deserialize)]
struct AnthropicError {
    #[serde(rename = "type")]
    error_type: String,
    error: AnthropicErrorDetail,
}

#[derive(Debug, Deserialize)]
struct AnthropicErrorDetail {
    #[serde(rename = "type")]
    error_type: String,
    message: String,
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Anthropic
    }

    async fn health_check(&self) -> Result<ProviderHealth, LlmError> {
        let start = Instant::now();

        // Send a minimal request to check API availability
        let request = AnthropicMessagesRequest {
            model: self.config.model.clone(),
            max_tokens: 1,
            system: None,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: "hi".to_string(),
            }],
            temperature: Some(0.0),
            stop_sequences: None,
        };

        let response = self.client
            .post(&self.messages_url())
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("Content-Type", "application/json")
            .json(&request)
            .timeout(Duration::from_secs(10))
            .send()
            .await;

        match response {
            Ok(resp) => {
                if resp.status().is_success() {
                    Ok(ProviderHealth {
                        available: true,
                        provider: "anthropic".to_string(),
                        model: Some(self.config.model.clone()),
                        latency_ms: Some(start.elapsed().as_millis() as u64),
                        error: None,
                    })
                } else if resp.status().as_u16() == 401 {
                    Ok(ProviderHealth {
                        available: false,
                        provider: "anthropic".to_string(),
                        model: None,
                        latency_ms: Some(start.elapsed().as_millis() as u64),
                        error: Some("Invalid API key".to_string()),
                    })
                } else {
                    let error_msg = if let Ok(err) = resp.json::<AnthropicError>().await {
                        err.error.message
                    } else {
                        "Unknown error".to_string()
                    };

                    Ok(ProviderHealth {
                        available: false,
                        provider: "anthropic".to_string(),
                        model: None,
                        latency_ms: Some(start.elapsed().as_millis() as u64),
                        error: Some(error_msg),
                    })
                }
            }
            Err(e) => {
                Ok(ProviderHealth {
                    available: false,
                    provider: "anthropic".to_string(),
                    model: None,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    error: Some(e.to_string()),
                })
            }
        }
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        let start = Instant::now();

        let anthropic_request = AnthropicMessagesRequest {
            model: self.config.model.clone(),
            max_tokens: request.max_tokens.unwrap_or(self.config.max_tokens),
            system: request.system,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: request.prompt,
            }],
            temperature: request.temperature.or(Some(self.config.temperature)),
            stop_sequences: request.stop,
        };

        debug!("Sending Anthropic request: model={}", self.config.model);

        let response = self.client
            .post(&self.messages_url())
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("Content-Type", "application/json")
            .json(&anthropic_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();

            if status.as_u16() == 429 {
                return Err(LlmError::RateLimited("Rate limit exceeded".to_string()));
            }

            if let Ok(error) = response.json::<AnthropicError>().await {
                warn!("Anthropic error: {}", error.error.message);
                if error.error.error_type == "not_found_error" {
                    return Err(LlmError::ModelNotFound(self.config.model.clone()));
                }
                return Err(LlmError::Internal(error.error.message));
            }

            return Err(LlmError::Internal(format!("HTTP {}", status)));
        }

        let anthropic_response: AnthropicMessagesResponse = response.json().await
            .map_err(|e| LlmError::InvalidResponse(e.to_string()))?;

        let text = anthropic_response.content
            .iter()
            .filter(|c| c.content_type == "text")
            .map(|c| c.text.as_str())
            .collect::<Vec<_>>()
            .join("");

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(CompletionResponse {
            text,
            prompt_tokens: Some(anthropic_response.usage.input_tokens),
            completion_tokens: Some(anthropic_response.usage.output_tokens),
            model: anthropic_response.model,
            finish_reason: anthropic_response.stop_reason,
            duration_ms,
        })
    }

    fn max_context(&self) -> usize {
        // Claude 3 models support 200k context
        200000
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_version() {
        assert!(!ANTHROPIC_VERSION.is_empty());
    }
}
