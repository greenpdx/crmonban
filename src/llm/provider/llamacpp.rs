//! llama.cpp Server Provider
//!
//! Local LLM provider using llama.cpp server.
//! https://github.com/ggerganov/llama.cpp

use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::{
    CompletionRequest, CompletionResponse, EmbeddingResponse, LlmError, LlmProvider,
    ProviderHealth,
};
use crate::llm::config::{LlamaCppConfig, ProviderType};

/// llama.cpp provider
#[derive(Debug)]
pub struct LlamaCppProvider {
    config: LlamaCppConfig,
    client: Client,
}

impl LlamaCppProvider {
    /// Create a new llama.cpp provider
    pub fn new(config: LlamaCppConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    /// Get the completion API URL
    fn completion_url(&self) -> String {
        format!("{}/completion", self.config.url)
    }

    /// Get the health API URL
    fn health_url(&self) -> String {
        format!("{}/health", self.config.url)
    }

    /// Get the embedding API URL
    fn embedding_url(&self) -> String {
        format!("{}/embedding", self.config.url)
    }

    /// Get the props API URL
    fn props_url(&self) -> String {
        format!("{}/props", self.config.url)
    }
}

/// llama.cpp completion request
#[derive(Debug, Serialize)]
struct LlamaCppRequest {
    prompt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    n_predict: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repeat_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Vec<String>>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    grammar: Option<String>,
}

/// llama.cpp completion response
#[derive(Debug, Deserialize)]
struct LlamaCppResponse {
    content: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    tokens_predicted: usize,
    #[serde(default)]
    tokens_evaluated: usize,
    #[serde(default)]
    generation_settings: Option<LlamaCppSettings>,
    stop: bool,
}

#[derive(Debug, Deserialize)]
struct LlamaCppSettings {
    #[serde(default)]
    n_ctx: usize,
    #[serde(default)]
    model: String,
}

/// llama.cpp health response
#[derive(Debug, Deserialize)]
struct LlamaCppHealth {
    status: String,
    #[serde(default)]
    slots_idle: usize,
    #[serde(default)]
    slots_processing: usize,
}

/// llama.cpp props response
#[derive(Debug, Deserialize)]
struct LlamaCppProps {
    #[serde(default)]
    total_slots: usize,
    #[serde(default)]
    default_generation_settings: Option<LlamaCppSettings>,
}

/// llama.cpp embedding request
#[derive(Debug, Serialize)]
struct LlamaCppEmbedRequest {
    content: String,
}

/// llama.cpp embedding response
#[derive(Debug, Deserialize)]
struct LlamaCppEmbedResponse {
    embedding: Vec<f32>,
}

#[async_trait]
impl LlmProvider for LlamaCppProvider {
    fn name(&self) -> &str {
        "llamacpp"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::LlamaCpp
    }

    async fn health_check(&self) -> Result<ProviderHealth, LlmError> {
        let start = Instant::now();

        // Try health endpoint first
        let health_response = self.client
            .get(&self.health_url())
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        match health_response {
            Ok(resp) => {
                if resp.status().is_success() {
                    let health: LlamaCppHealth = resp.json().await
                        .map_err(|e| LlmError::InvalidResponse(e.to_string()))?;

                    let available = health.status == "ok" || health.status == "no slot available";

                    // Try to get model info from props
                    let model = if let Ok(props_resp) = self.client
                        .get(&self.props_url())
                        .timeout(Duration::from_secs(2))
                        .send()
                        .await
                    {
                        if let Ok(props) = props_resp.json::<LlamaCppProps>().await {
                            props.default_generation_settings
                                .and_then(|s| if s.model.is_empty() { None } else { Some(s.model) })
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    Ok(ProviderHealth {
                        available,
                        provider: "llamacpp".to_string(),
                        model,
                        latency_ms: Some(start.elapsed().as_millis() as u64),
                        error: if !available {
                            Some(format!("Status: {}", health.status))
                        } else {
                            None
                        },
                    })
                } else {
                    Ok(ProviderHealth {
                        available: false,
                        provider: "llamacpp".to_string(),
                        model: None,
                        latency_ms: Some(start.elapsed().as_millis() as u64),
                        error: Some(format!("HTTP {}", resp.status())),
                    })
                }
            }
            Err(e) => {
                Ok(ProviderHealth {
                    available: false,
                    provider: "llamacpp".to_string(),
                    model: None,
                    latency_ms: Some(start.elapsed().as_millis() as u64),
                    error: Some(e.to_string()),
                })
            }
        }
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        let start = Instant::now();

        // Build prompt with system message if provided
        let full_prompt = if let Some(system) = &request.system {
            format!(
                "<|im_start|>system\n{}<|im_end|>\n<|im_start|>user\n{}<|im_end|>\n<|im_start|>assistant\n",
                system, request.prompt
            )
        } else {
            request.prompt.clone()
        };

        let llama_request = LlamaCppRequest {
            prompt: full_prompt,
            n_predict: request.max_tokens,
            temperature: request.temperature.or(Some(self.config.temperature)),
            top_p: Some(self.config.top_p),
            repeat_penalty: Some(self.config.repeat_penalty),
            stop: request.stop.or(Some(vec!["<|im_end|>".to_string()])),
            stream: false,
            grammar: if request.json_schema.is_some() {
                // Basic JSON grammar
                Some(r#"root ::= object
object ::= "{" ws members ws "}"
members ::= pair ("," ws pair)*
pair ::= string ":" ws value
value ::= string | number | object | array | "true" | "false" | "null"
string ::= "\"" [^"\\]* "\""
number ::= "-"? [0-9]+ ("." [0-9]+)?
array ::= "[" ws elements ws "]"
elements ::= value ("," ws value)*
ws ::= [ \t\n]*"#.to_string())
            } else {
                None
            },
        };

        debug!("Sending llama.cpp request");

        let response = self.client
            .post(&self.completion_url())
            .json(&llama_request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            warn!("llama.cpp error: {} - {}", status, body);

            if status.as_u16() == 503 {
                return Err(LlmError::RateLimited("No slots available".to_string()));
            }
            return Err(LlmError::Internal(format!("HTTP {}: {}", status, body)));
        }

        let llama_response: LlamaCppResponse = response.json().await
            .map_err(|e| LlmError::InvalidResponse(e.to_string()))?;

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(CompletionResponse {
            text: llama_response.content,
            prompt_tokens: Some(llama_response.tokens_evaluated),
            completion_tokens: Some(llama_response.tokens_predicted),
            model: llama_response.model,
            finish_reason: if llama_response.stop { Some("stop".to_string()) } else { None },
            duration_ms,
        })
    }

    async fn embed(&self, texts: &[String]) -> Result<EmbeddingResponse, LlmError> {
        let mut embeddings = Vec::with_capacity(texts.len());
        let mut total_tokens = 0usize;

        for text in texts {
            let request = LlamaCppEmbedRequest {
                content: text.clone(),
            };

            let response = self.client
                .post(&self.embedding_url())
                .json(&request)
                .send()
                .await?;

            if !response.status().is_success() {
                // Embeddings might not be enabled
                if response.status().as_u16() == 501 {
                    return Err(LlmError::Unavailable("Embeddings not enabled in llama.cpp server".to_string()));
                }
                return Err(LlmError::Internal(format!("HTTP {}", response.status())));
            }

            let embed_response: LlamaCppEmbedResponse = response.json().await
                .map_err(|e| LlmError::InvalidResponse(e.to_string()))?;

            embeddings.push(embed_response.embedding);
            total_tokens += text.len() / 4; // Approximate
        }

        Ok(EmbeddingResponse {
            embeddings,
            total_tokens: Some(total_tokens),
            model: "llama.cpp".to_string(),
        })
    }

    fn max_context(&self) -> usize {
        self.config.n_ctx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let config = LlamaCppConfig::default();
        let provider = LlamaCppProvider::new(config);
        assert_eq!(provider.name(), "llamacpp");
    }

    #[test]
    fn test_urls() {
        let config = LlamaCppConfig::default();
        let provider = LlamaCppProvider::new(config);

        assert!(provider.completion_url().contains("/completion"));
        assert!(provider.health_url().contains("/health"));
    }
}
