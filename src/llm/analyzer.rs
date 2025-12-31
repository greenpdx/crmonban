//! LLM Analysis Coordinator
//!
//! Orchestrates LLM-based security analysis including triage, explanation,
//! attack chain construction, and MITRE mapping.

use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use super::cache::LlmCache;
use super::config::{AnalysisType, LlmConfig, TriagePriority};
use super::privacy::DataSanitizer;
use super::prompts::{create_prompt, OutputFormat, PromptContext, PromptTemplate};
use super::provider::{create_provider, CompletionRequest, CompletionResponse, LlmError, LlmProvider};
use super::queue::{AnalysisQueue, AnalysisResult, RequestPriority};

/// LLM Analyzer - main coordinator for LLM analysis
pub struct LlmAnalyzer {
    config: LlmConfig,
    /// Primary LLM provider
    provider: Arc<dyn LlmProvider>,
    /// Fallback provider (cloud)
    #[cfg(feature = "llm-cloud")]
    fallback_provider: Option<Arc<dyn LlmProvider>>,
    /// Response cache
    cache: Arc<LlmCache>,
    /// Data sanitizer
    sanitizer: Arc<DataSanitizer>,
    /// Analysis queue
    queue: Arc<AnalysisQueue>,
    /// RAG retriever (optional)
    rag: Option<Arc<super::rag::RagRetriever>>,
    /// Statistics
    stats: Arc<RwLock<AnalyzerStats>>,
}

/// Analyzer statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalyzerStats {
    /// Total analyses performed
    pub total_analyses: u64,
    /// Successful analyses
    pub successful: u64,
    /// Failed analyses
    pub failed: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Average latency (ms)
    pub avg_latency_ms: u64,
    /// Analyses by type
    pub by_type: AnalysisByType,
    /// Provider failures (triggers fallback)
    pub provider_failures: u64,
}

/// Analysis counts by type
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisByType {
    pub triage: u64,
    pub explain: u64,
    pub attack_chain: u64,
    pub mitre_mapping: u64,
    pub threat_hunt: u64,
}

/// Analysis response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResponse {
    /// Analysis type performed
    pub analysis_type: AnalysisType,
    /// Response text
    pub response: String,
    /// Parsed triage priority (if triage analysis)
    pub priority: Option<TriagePriority>,
    /// Parsed MITRE techniques (if mapping analysis)
    pub mitre_techniques: Option<Vec<MitreTechnique>>,
    /// Model used
    pub model: String,
    /// Latency in milliseconds
    pub latency_ms: u64,
    /// Whether result was cached
    pub cached: bool,
    /// Whether data was sanitized
    pub sanitized: bool,
    /// Tokens used (if available)
    pub tokens_used: Option<usize>,
}

/// MITRE technique from mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechnique {
    pub id: String,
    pub name: String,
    pub tactic: String,
    pub confidence: f32,
    pub evidence: Option<String>,
}

/// Triage result from LLM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    pub priority: TriagePriority,
    pub confidence: f32,
    pub reasoning: String,
    pub recommended_actions: Vec<String>,
}

impl LlmAnalyzer {
    /// Create a new LLM analyzer
    pub async fn new(config: LlmConfig) -> Result<Self, String> {
        // Create primary provider
        let provider = create_provider(config.provider, &config)
            .map_err(|e| format!("Failed to create provider: {}", e))?;

        // Health check
        match provider.health_check().await {
            Ok(health) if !health.available => {
                warn!("Primary LLM provider health check returned unavailable");
            }
            Err(e) => {
                warn!("Primary LLM provider health check failed: {}", e);
            }
            _ => {}
        }

        // Create fallback provider if configured
        #[cfg(feature = "llm-cloud")]
        let fallback_provider = {
            use super::config::ProviderType;
            // Try OpenAI first, then Anthropic
            let fallback_type = if matches!(config.provider, ProviderType::Ollama | ProviderType::LlamaCpp) {
                Some(ProviderType::OpenAI)
            } else {
                None
            };

            fallback_type.and_then(|pt| {
                create_provider(pt, &config).ok().map(|p| Arc::from(p) as Arc<dyn LlmProvider>)
            })
        };

        // Create cache
        let cache = Arc::new(LlmCache::new(config.cache.clone()));

        // Create sanitizer
        let sanitizer = Arc::new(DataSanitizer::new(config.privacy.clone()));

        // Create queue
        let queue = Arc::new(AnalysisQueue::new(config.queue.clone()));

        Ok(Self {
            config,
            provider: Arc::from(provider),
            #[cfg(feature = "llm-cloud")]
            fallback_provider,
            cache,
            sanitizer,
            queue,
            rag: None,
            stats: Arc::new(RwLock::new(AnalyzerStats::default())),
        })
    }

    /// Set RAG retriever
    pub fn with_rag(mut self, rag: Arc<super::rag::RagRetriever>) -> Self {
        self.rag = Some(rag);
        self
    }

    /// Perform analysis
    pub async fn analyze(
        &self,
        analysis_type: AnalysisType,
        context: PromptContext,
    ) -> Result<AnalysisResponse, String> {
        let start = Instant::now();

        // Get prompt template
        let prompt_template = create_prompt(analysis_type);

        // Build prompt
        let mut enriched_context = context.clone();

        // Add RAG context if available
        if let Some(ref rag) = self.rag {
            // Use alert_summary for RAG retrieval
            if let Ok(rag_context) = rag.retrieve(&context.alert_summary, 3).await {
                enriched_context.rag_context = Some(rag_context);
            }
        }

        let user_prompt = prompt_template.build_prompt(&enriched_context);

        // Check cache
        let cache_key = self.cache.cache_key(&user_prompt, &format!("{:?}", analysis_type));
        if let Some(cached) = self.cache.get(&cache_key) {
            let mut stats = self.stats.write().await;
            stats.cache_hits += 1;

            return Ok(AnalysisResponse {
                analysis_type,
                response: cached,
                priority: None,
                mitre_techniques: None,
                model: "cached".to_string(),
                latency_ms: start.elapsed().as_millis() as u64,
                cached: true,
                sanitized: false,
                tokens_used: None,
            });
        }

        // Sanitize if using cloud provider
        let (final_prompt, sanitized) = if !self.sanitizer.should_use_cloud() {
            (user_prompt.clone(), false)
        } else {
            let result = self.sanitizer.sanitize(&user_prompt);
            if !result.warnings.is_empty() {
                for warning in &result.warnings {
                    warn!("Privacy warning: {}", warning);
                }
            }
            (result.text, true)
        };

        // Build completion request using builder pattern
        let mut request = CompletionRequest::new(&final_prompt)
            .with_system(prompt_template.system_prompt())
            .with_max_tokens(prompt_template.max_tokens())
            .with_temperature(self.config.ollama.temperature);

        // Add JSON schema if JSON output expected
        if prompt_template.output_format() == OutputFormat::Json {
            request = request.with_json();
        }

        // Try primary provider
        let result = self.provider.complete(request.clone()).await;

        let response = match result {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Primary provider failed: {}", e);

                // Track failure
                {
                    let mut stats = self.stats.write().await;
                    stats.provider_failures += 1;
                }

                // Try fallback
                #[cfg(feature = "llm-cloud")]
                {
                    if let Some(ref fallback) = self.fallback_provider {
                        // Ensure data is sanitized for cloud
                        let sanitized_request = if sanitized {
                            request.clone()
                        } else {
                            let sanitized_prompt = self.sanitizer.sanitize(&request.prompt).text;
                            CompletionRequest::new(&sanitized_prompt)
                                .with_system(prompt_template.system_prompt())
                                .with_max_tokens(prompt_template.max_tokens())
                        };

                        match fallback.complete(sanitized_request).await {
                            Ok(resp) => resp,
                            Err(fallback_err) => {
                                error!("Fallback provider also failed: {}", fallback_err);
                                return Err(format!("All providers failed: primary={}, fallback={}", e, fallback_err));
                            }
                        }
                    } else {
                        return Err(format!("Provider failed and no fallback: {}", e));
                    }
                }

                #[cfg(not(feature = "llm-cloud"))]
                return Err(format!("Provider failed: {}", e));
            }
        };

        let latency_ms = start.elapsed().as_millis() as u64;

        // Cache the response
        self.cache.put(&cache_key, &response.text, &response.model);

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_analyses += 1;
            stats.successful += 1;
            stats.avg_latency_ms = (stats.avg_latency_ms * (stats.total_analyses - 1) + latency_ms)
                / stats.total_analyses;

            match analysis_type {
                AnalysisType::Triage => stats.by_type.triage += 1,
                AnalysisType::Explain => stats.by_type.explain += 1,
                AnalysisType::AttackChain => stats.by_type.attack_chain += 1,
                AnalysisType::MitreMapping => stats.by_type.mitre_mapping += 1,
                AnalysisType::ThreatHunt => stats.by_type.threat_hunt += 1,
                AnalysisType::Full => {
                    stats.by_type.triage += 1;
                    stats.by_type.explain += 1;
                    stats.by_type.mitre_mapping += 1;
                }
            }
        }

        // Parse response based on type
        let (priority, mitre_techniques) = self.parse_response(analysis_type, &response.text);

        // Calculate tokens used from response
        let tokens_used = response.prompt_tokens
            .and_then(|p| response.completion_tokens.map(|c| p + c));

        Ok(AnalysisResponse {
            analysis_type,
            response: response.text,
            priority,
            mitre_techniques,
            model: response.model,
            latency_ms,
            cached: false,
            sanitized,
            tokens_used,
        })
    }

    /// Parse LLM response based on analysis type
    fn parse_response(
        &self,
        analysis_type: AnalysisType,
        response: &str,
    ) -> (Option<TriagePriority>, Option<Vec<MitreTechnique>>) {
        match analysis_type {
            AnalysisType::Triage => {
                let priority = self.parse_triage_priority(response);
                (priority, None)
            }
            AnalysisType::MitreMapping => {
                let techniques = self.parse_mitre_techniques(response);
                (None, techniques)
            }
            _ => (None, None),
        }
    }

    /// Parse triage priority from response
    fn parse_triage_priority(&self, response: &str) -> Option<TriagePriority> {
        // Try JSON parsing first
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(response) {
            if let Some(priority) = json.get("priority").and_then(|p| p.as_str()) {
                return match priority.to_uppercase().as_str() {
                    "P1" | "CRITICAL" => Some(TriagePriority::P1),
                    "P2" | "HIGH" => Some(TriagePriority::P2),
                    "P3" | "MEDIUM" => Some(TriagePriority::P3),
                    "P4" | "LOW" => Some(TriagePriority::P4),
                    _ => None,
                };
            }
        }

        // Fallback to text parsing
        let upper = response.to_uppercase();
        if upper.contains("P1") || upper.contains("CRITICAL") {
            Some(TriagePriority::P1)
        } else if upper.contains("P2") || upper.contains("HIGH") {
            Some(TriagePriority::P2)
        } else if upper.contains("P3") || upper.contains("MEDIUM") {
            Some(TriagePriority::P3)
        } else if upper.contains("P4") || upper.contains("LOW") {
            Some(TriagePriority::P4)
        } else {
            None
        }
    }

    /// Parse MITRE techniques from response
    fn parse_mitre_techniques(&self, response: &str) -> Option<Vec<MitreTechnique>> {
        // Try JSON parsing
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(response) {
            if let Some(techniques) = json.get("techniques").and_then(|t| t.as_array()) {
                let parsed: Vec<MitreTechnique> = techniques
                    .iter()
                    .filter_map(|t| {
                        Some(MitreTechnique {
                            id: t.get("id")?.as_str()?.to_string(),
                            name: t.get("name")?.as_str()?.to_string(),
                            tactic: t.get("tactic")?.as_str()?.to_string(),
                            confidence: t.get("confidence")?.as_f64()? as f32,
                            evidence: t.get("evidence").and_then(|e| e.as_str()).map(String::from),
                        })
                    })
                    .collect();

                if !parsed.is_empty() {
                    return Some(parsed);
                }
            }
        }

        // Fallback: extract technique IDs with regex
        let re = regex::Regex::new(r"T\d{4}(?:\.\d{3})?").ok()?;
        let techniques: Vec<MitreTechnique> = re
            .find_iter(response)
            .map(|m| MitreTechnique {
                id: m.as_str().to_string(),
                name: "Unknown".to_string(),
                tactic: "Unknown".to_string(),
                confidence: 0.5,
                evidence: None,
            })
            .collect();

        if techniques.is_empty() {
            None
        } else {
            Some(techniques)
        }
    }

    /// Perform full analysis (triage + explain + MITRE)
    pub async fn full_analysis(&self, context: PromptContext) -> Result<FullAnalysisResult, String> {
        let triage = self.analyze(AnalysisType::Triage, context.clone()).await?;
        let explanation = self.analyze(AnalysisType::Explain, context.clone()).await?;
        let mitre = self.analyze(AnalysisType::MitreMapping, context).await?;

        Ok(FullAnalysisResult {
            triage,
            explanation,
            mitre_mapping: mitre,
        })
    }

    /// Queue analysis for async processing
    pub async fn queue_analysis(
        &self,
        analysis_type: AnalysisType,
        context: PromptContext,
        priority: RequestPriority,
    ) -> Result<u64, String> {
        self.queue.enqueue(analysis_type, context, priority).await
    }

    /// Process queued analyses
    pub async fn process_queue(&self) -> Option<AnalysisResult> {
        let request = self.queue.dequeue().await?;
        let start = Instant::now();

        let result = self.analyze(request.analysis_type, request.context.clone()).await;
        let duration_ms = start.elapsed().as_millis() as u64;

        let analysis_result = match result {
            Ok(response) => {
                self.queue.mark_processed(true, duration_ms).await;
                AnalysisResult::success(
                    request.id,
                    request.analysis_type,
                    response.response,
                    duration_ms,
                )
            }
            Err(e) => {
                // Check if should retry
                if request.retries < self.config.queue.max_retries {
                    self.queue.requeue(request.clone()).await;
                }
                self.queue.mark_processed(false, duration_ms).await;
                AnalysisResult::failure(request.id, request.analysis_type, e)
            }
        };

        // Send result to callback if provided
        if let Some(tx) = request.result_tx {
            let _ = tx.send(analysis_result.clone()).await;
        }

        Some(analysis_result)
    }

    /// Get statistics
    pub async fn stats(&self) -> AnalyzerStats {
        self.stats.read().await.clone()
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> super::cache::CacheStats {
        self.cache.stats()
    }

    /// Get queue statistics
    pub async fn queue_stats(&self) -> super::queue::QueueStats {
        self.queue.stats().await
    }

    /// Check provider health
    pub async fn health_check(&self) -> bool {
        match self.provider.health_check().await {
            Ok(health) => health.available,
            Err(_) => false,
        }
    }

    /// Get provider name
    pub fn provider_name(&self) -> &str {
        self.provider.name()
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Shutdown analyzer
    pub async fn shutdown(&self) {
        self.queue.shutdown().await;
        info!("LLM Analyzer shutdown complete");
    }
}

/// Full analysis result combining all analysis types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullAnalysisResult {
    pub triage: AnalysisResponse,
    pub explanation: AnalysisResponse,
    pub mitre_mapping: AnalysisResponse,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_triage_priority_json() {
        let response = r#"{"priority": "P2", "confidence": 0.85}"#;
        let json: serde_json::Value = serde_json::from_str(response).unwrap();
        let priority = json.get("priority").and_then(|p| p.as_str()).unwrap();
        assert_eq!(priority, "P2");
    }

    #[test]
    fn test_parse_mitre_json() {
        let response = r#"{"techniques": [{"id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance", "confidence": 0.9}]}"#;
        let json: serde_json::Value = serde_json::from_str(response).unwrap();
        let techniques = json.get("techniques").and_then(|t| t.as_array()).unwrap();
        assert_eq!(techniques.len(), 1);
        assert_eq!(techniques[0].get("id").unwrap().as_str().unwrap(), "T1595");
    }

    #[test]
    fn test_mitre_regex_extraction() {
        let response = "This maps to T1595 Active Scanning and T1190.001";
        let re = regex::Regex::new(r"T\d{4}(?:\.\d{3})?").unwrap();
        let matches: Vec<&str> = re.find_iter(response).map(|m| m.as_str()).collect();
        assert_eq!(matches.len(), 2);
        assert!(matches.contains(&"T1595"));
        assert!(matches.contains(&"T1190.001"));
    }
}
