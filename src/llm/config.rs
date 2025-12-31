//! LLM Configuration
//!
//! Configuration for LLM providers and analysis settings.
//! Supports local-first deployment with Ollama and llama.cpp,
//! with optional cloud provider fallback.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Main LLM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// Enable LLM-based analysis
    pub enabled: bool,
    /// Primary provider to use
    pub provider: ProviderType,
    /// Ollama configuration
    pub ollama: OllamaConfig,
    /// llama.cpp server configuration
    pub llamacpp: LlamaCppConfig,
    /// OpenAI configuration (cloud fallback)
    #[cfg(feature = "llm-cloud")]
    pub openai: OpenAIConfig,
    /// Anthropic configuration (cloud fallback)
    #[cfg(feature = "llm-cloud")]
    pub anthropic: AnthropicConfig,
    /// Privacy settings
    pub privacy: PrivacyConfig,
    /// Analysis settings
    pub analysis: AnalysisConfig,
    /// Caching settings
    pub cache: CacheConfig,
    /// Queue settings
    pub queue: QueueConfig,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default, opt-in
            provider: ProviderType::Ollama,
            ollama: OllamaConfig::default(),
            llamacpp: LlamaCppConfig::default(),
            #[cfg(feature = "llm-cloud")]
            openai: OpenAIConfig::default(),
            #[cfg(feature = "llm-cloud")]
            anthropic: AnthropicConfig::default(),
            privacy: PrivacyConfig::default(),
            analysis: AnalysisConfig::default(),
            cache: CacheConfig::default(),
            queue: QueueConfig::default(),
        }
    }
}

/// LLM provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderType {
    /// Ollama local server
    Ollama,
    /// llama.cpp server
    LlamaCpp,
    /// OpenAI API (requires llm-cloud feature)
    #[cfg(feature = "llm-cloud")]
    OpenAI,
    /// Anthropic Claude API (requires llm-cloud feature)
    #[cfg(feature = "llm-cloud")]
    Anthropic,
}

impl Default for ProviderType {
    fn default() -> Self {
        Self::Ollama
    }
}

/// Ollama configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaConfig {
    /// Server URL
    pub url: String,
    /// Model name to use
    pub model: String,
    /// Request timeout
    pub timeout_secs: u64,
    /// Keep model loaded in memory
    pub keep_alive: bool,
    /// Number of GPU layers (-1 for all)
    pub num_gpu: i32,
    /// Context window size
    pub num_ctx: usize,
    /// Temperature for generation
    pub temperature: f32,
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:11434".to_string(),
            model: "llama3.2".to_string(),
            timeout_secs: 120,
            keep_alive: true,
            num_gpu: -1,
            num_ctx: 8192,
            temperature: 0.1, // Low temperature for consistent analysis
        }
    }
}

/// llama.cpp server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlamaCppConfig {
    /// Server URL
    pub url: String,
    /// Request timeout
    pub timeout_secs: u64,
    /// Context window size
    pub n_ctx: usize,
    /// Temperature for generation
    pub temperature: f32,
    /// Top-p sampling
    pub top_p: f32,
    /// Repeat penalty
    pub repeat_penalty: f32,
}

impl Default for LlamaCppConfig {
    fn default() -> Self {
        Self {
            url: "http://127.0.0.1:8080".to_string(),
            timeout_secs: 120,
            n_ctx: 8192,
            temperature: 0.1,
            top_p: 0.9,
            repeat_penalty: 1.1,
        }
    }
}

/// OpenAI API configuration
#[cfg(feature = "llm-cloud")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIConfig {
    /// API key (from environment or config)
    pub api_key: Option<String>,
    /// API base URL (for Azure or proxies)
    pub base_url: String,
    /// Model to use
    pub model: String,
    /// Request timeout
    pub timeout_secs: u64,
    /// Max tokens per request
    pub max_tokens: usize,
    /// Temperature
    pub temperature: f32,
}

#[cfg(feature = "llm-cloud")]
impl Default for OpenAIConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            base_url: "https://api.openai.com/v1".to_string(),
            model: "gpt-4o-mini".to_string(),
            timeout_secs: 60,
            max_tokens: 4096,
            temperature: 0.1,
        }
    }
}

/// Anthropic Claude API configuration
#[cfg(feature = "llm-cloud")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicConfig {
    /// API key (from environment or config)
    pub api_key: Option<String>,
    /// Model to use
    pub model: String,
    /// Request timeout
    pub timeout_secs: u64,
    /// Max tokens per request
    pub max_tokens: usize,
    /// Temperature
    pub temperature: f32,
}

#[cfg(feature = "llm-cloud")]
impl Default for AnthropicConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            model: "claude-3-haiku-20240307".to_string(),
            timeout_secs: 60,
            max_tokens: 4096,
            temperature: 0.1,
        }
    }
}

/// Privacy configuration for LLM analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Only use local providers (no cloud)
    pub local_only: bool,
    /// Sanitize internal IP addresses
    pub sanitize_internal_ips: bool,
    /// Sanitize hostnames
    pub sanitize_hostnames: bool,
    /// Sanitize usernames
    pub sanitize_usernames: bool,
    /// Redact patterns (regex)
    pub redact_patterns: Vec<String>,
    /// IP ranges to consider internal
    pub internal_ranges: Vec<String>,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            local_only: true, // Local-first by default
            sanitize_internal_ips: true,
            sanitize_hostnames: true,
            sanitize_usernames: true,
            redact_patterns: vec![
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b".to_string(), // Email
                r"\b(?:password|passwd|pwd|secret|token|key)\s*[:=]\s*\S+".to_string(), // Secrets
            ],
            internal_ranges: vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
                "fd00::/8".to_string(),
            ],
        }
    }
}

/// Analysis configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Enable alert triage
    pub enable_triage: bool,
    /// Enable threat explanation
    pub enable_explanation: bool,
    /// Enable attack chain narrative
    pub enable_attack_chain: bool,
    /// Enable MITRE ATT&CK mapping
    pub enable_mitre_mapping: bool,
    /// Minimum severity for LLM analysis
    pub min_severity: String,
    /// Maximum alerts per batch
    pub batch_size: usize,
    /// Analysis timeout
    pub timeout_secs: u64,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enable_triage: true,
            enable_explanation: true,
            enable_attack_chain: true,
            enable_mitre_mapping: true,
            min_severity: "medium".to_string(),
            batch_size: 10,
            timeout_secs: 300,
        }
    }
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable response caching
    pub enabled: bool,
    /// Cache directory
    pub cache_dir: Option<PathBuf>,
    /// Cache TTL in hours
    pub ttl_hours: u64,
    /// Maximum cache size in MB
    pub max_size_mb: usize,
    /// Cache similar alerts (hash-based)
    pub cache_similar: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_dir: None, // Will use default data dir
            ttl_hours: 24,
            max_size_mb: 100,
            cache_similar: true,
        }
    }
}

/// Queue configuration for async analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfig {
    /// Maximum queue size
    pub max_size: usize,
    /// Number of concurrent workers
    pub workers: usize,
    /// Retry failed analyses
    pub retry_failed: bool,
    /// Max retries
    pub max_retries: usize,
    /// Backoff base delay (ms)
    pub backoff_base_ms: u64,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            max_size: 1000,
            workers: 2,
            retry_failed: true,
            max_retries: 3,
            backoff_base_ms: 1000,
        }
    }
}

/// Analysis type to request from LLM
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AnalysisType {
    /// Prioritize alert (P1-P4)
    Triage,
    /// Human-readable threat explanation
    Explain,
    /// Attack chain narrative
    AttackChain,
    /// MITRE ATT&CK mapping
    MitreMapping,
    /// Generate threat hunting queries
    ThreatHunt,
    /// Full analysis (all types)
    Full,
}

impl AnalysisType {
    /// Get all individual analysis types
    pub fn all() -> Vec<Self> {
        vec![
            Self::Triage,
            Self::Explain,
            Self::AttackChain,
            Self::MitreMapping,
        ]
    }
}

/// Priority level for alert triage
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TriagePriority {
    /// P1: Critical - immediate action required
    P1,
    /// P2: High - action required within hours
    P2,
    /// P3: Medium - action required within day
    P3,
    /// P4: Low - informational, can wait
    P4,
}

impl std::fmt::Display for TriagePriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P1 => write!(f, "P1-Critical"),
            Self::P2 => write!(f, "P2-High"),
            Self::P3 => write!(f, "P3-Medium"),
            Self::P4 => write!(f, "P4-Low"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LlmConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.provider, ProviderType::Ollama);
        assert!(config.privacy.local_only);
    }

    #[test]
    fn test_ollama_config() {
        let config = OllamaConfig::default();
        assert_eq!(config.url, "http://127.0.0.1:11434");
        assert_eq!(config.model, "llama3.2");
    }

    #[test]
    fn test_privacy_config() {
        let config = PrivacyConfig::default();
        assert!(config.local_only);
        assert!(config.sanitize_internal_ips);
    }

    #[test]
    fn test_analysis_types() {
        let types = AnalysisType::all();
        assert_eq!(types.len(), 4);
    }

    #[test]
    fn test_triage_priority_ordering() {
        assert!(TriagePriority::P1 < TriagePriority::P2);
        assert!(TriagePriority::P2 < TriagePriority::P3);
    }
}
