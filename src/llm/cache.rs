//! LLM Response Caching
//!
//! Caches LLM responses to avoid redundant API calls for similar alerts.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::config::CacheConfig;

/// Cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Response text
    pub response: String,
    /// Timestamp when cached
    pub cached_at: u64,
    /// TTL in seconds
    pub ttl_secs: u64,
    /// Number of times accessed
    pub access_count: u64,
    /// Model used
    pub model: String,
}

impl CacheEntry {
    /// Create a new cache entry
    pub fn new(response: String, ttl_secs: u64, model: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            response,
            cached_at: now,
            ttl_secs,
            access_count: 0,
            model: model.to_string(),
        }
    }

    /// Check if entry is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now > self.cached_at + self.ttl_secs
    }
}

/// LLM response cache
pub struct LlmCache {
    config: CacheConfig,
    /// In-memory cache
    memory_cache: RwLock<HashMap<String, CacheEntry>>,
    /// Disk cache directory
    cache_dir: Option<PathBuf>,
    /// Statistics
    stats: RwLock<CacheStats>,
}

/// Cache statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    /// Cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Entries evicted
    pub evictions: u64,
    /// Disk saves
    pub disk_saves: u64,
    /// Disk loads
    pub disk_loads: u64,
}

impl CacheStats {
    /// Get hit rate
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total > 0 {
            self.hits as f64 / total as f64
        } else {
            0.0
        }
    }
}

impl LlmCache {
    /// Create a new cache
    pub fn new(config: CacheConfig) -> Self {
        let cache_dir = config.cache_dir.clone().or_else(|| {
            dirs_next::data_dir().map(|d| d.join("crmonban").join("llm_cache"))
        });

        // Create cache directory if needed
        if let Some(ref dir) = cache_dir {
            if let Err(e) = fs::create_dir_all(dir) {
                warn!("Failed to create cache directory: {}", e);
            }
        }

        Self {
            config,
            memory_cache: RwLock::new(HashMap::new()),
            cache_dir,
            stats: RwLock::new(CacheStats::default()),
        }
    }

    /// Generate cache key from prompt
    pub fn cache_key(&self, prompt: &str, analysis_type: &str) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        prompt.hash(&mut hasher);
        analysis_type.hash(&mut hasher);
        format!("{}_{:x}", analysis_type, hasher.finish())
    }

    /// Get cached response
    pub fn get(&self, key: &str) -> Option<String> {
        if !self.config.enabled {
            return None;
        }

        // Try memory cache first
        {
            let mut cache = self.memory_cache.write().ok()?;
            if let Some(entry) = cache.get_mut(key) {
                if !entry.is_expired() {
                    entry.access_count += 1;
                    let mut stats = self.stats.write().ok()?;
                    stats.hits += 1;
                    debug!("Cache hit for key: {}", key);
                    return Some(entry.response.clone());
                } else {
                    cache.remove(key);
                }
            }
        }

        // Try disk cache
        if let Some(entry) = self.load_from_disk(key) {
            if !entry.is_expired() {
                // Add to memory cache
                if let Ok(mut cache) = self.memory_cache.write() {
                    cache.insert(key.to_string(), entry.clone());
                }
                if let Ok(mut stats) = self.stats.write() {
                    stats.hits += 1;
                    stats.disk_loads += 1;
                }
                debug!("Cache hit from disk for key: {}", key);
                return Some(entry.response);
            }
        }

        // Miss
        if let Ok(mut stats) = self.stats.write() {
            stats.misses += 1;
        }
        debug!("Cache miss for key: {}", key);
        None
    }

    /// Store response in cache
    pub fn put(&self, key: &str, response: &str, model: &str) {
        if !self.config.enabled {
            return;
        }

        let ttl_secs = self.config.ttl_hours * 3600;
        let entry = CacheEntry::new(response.to_string(), ttl_secs, model);

        // Store in memory
        if let Ok(mut cache) = self.memory_cache.write() {
            // Evict if needed
            self.evict_if_needed(&mut cache);
            cache.insert(key.to_string(), entry.clone());
        }

        // Store on disk
        self.save_to_disk(key, &entry);

        debug!("Cached response for key: {}", key);
    }

    /// Evict old entries if cache is too large
    fn evict_if_needed(&self, cache: &mut HashMap<String, CacheEntry>) {
        // Simple LRU-ish eviction based on access count and age
        let max_entries = 10000; // In-memory limit

        if cache.len() >= max_entries {
            // Remove expired entries first
            let expired: Vec<String> = cache.iter()
                .filter(|(_, v)| v.is_expired())
                .map(|(k, _)| k.clone())
                .collect();

            for key in expired {
                cache.remove(&key);
                if let Ok(mut stats) = self.stats.write() {
                    stats.evictions += 1;
                }
            }

            // If still too large, remove lowest access count
            if cache.len() >= max_entries {
                if let Some(key) = cache.iter()
                    .min_by_key(|(_, v)| v.access_count)
                    .map(|(k, _)| k.clone())
                {
                    cache.remove(&key);
                    if let Ok(mut stats) = self.stats.write() {
                        stats.evictions += 1;
                    }
                }
            }
        }
    }

    /// Save entry to disk
    fn save_to_disk(&self, key: &str, entry: &CacheEntry) {
        let Some(ref cache_dir) = self.cache_dir else {
            return;
        };

        let path = cache_dir.join(format!("{}.json", key));
        match serde_json::to_string(entry) {
            Ok(json) => {
                if let Err(e) = fs::write(&path, json) {
                    warn!("Failed to save cache entry: {}", e);
                } else if let Ok(mut stats) = self.stats.write() {
                    stats.disk_saves += 1;
                }
            }
            Err(e) => warn!("Failed to serialize cache entry: {}", e),
        }
    }

    /// Load entry from disk
    fn load_from_disk(&self, key: &str) -> Option<CacheEntry> {
        let cache_dir = self.cache_dir.as_ref()?;
        let path = cache_dir.join(format!("{}.json", key));

        let json = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&json).ok()
    }

    /// Clear all cached entries
    pub fn clear(&self) {
        if let Ok(mut cache) = self.memory_cache.write() {
            cache.clear();
        }

        if let Some(ref cache_dir) = self.cache_dir {
            if let Ok(entries) = fs::read_dir(cache_dir) {
                for entry in entries.flatten() {
                    if entry.path().extension().map(|e| e == "json").unwrap_or(false) {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        self.stats.read().map(|s| s.clone()).unwrap_or_default()
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.memory_cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_entry() {
        let entry = CacheEntry::new("test response".to_string(), 3600, "test-model");
        assert!(!entry.is_expired());
        assert_eq!(entry.access_count, 0);
    }

    #[test]
    fn test_cache_key() {
        let config = CacheConfig::default();
        let cache = LlmCache::new(config);

        let key1 = cache.cache_key("prompt 1", "triage");
        let key2 = cache.cache_key("prompt 2", "triage");
        let key3 = cache.cache_key("prompt 1", "triage");

        assert_ne!(key1, key2);
        assert_eq!(key1, key3);
    }

    #[test]
    fn test_cache_put_get() {
        let mut config = CacheConfig::default();
        config.cache_dir = None; // In-memory only
        let cache = LlmCache::new(config);

        cache.put("test_key", "test response", "test-model");
        let result = cache.get("test_key");

        assert_eq!(result, Some("test response".to_string()));
    }

    #[test]
    fn test_cache_miss() {
        let config = CacheConfig::default();
        let cache = LlmCache::new(config);

        let result = cache.get("nonexistent_key");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_stats() {
        let mut config = CacheConfig::default();
        config.cache_dir = None;
        let cache = LlmCache::new(config);

        cache.put("key1", "response1", "model");
        cache.get("key1"); // Hit
        cache.get("key2"); // Miss

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }
}
