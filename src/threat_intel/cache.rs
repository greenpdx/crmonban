//! IOC Cache with efficient lookups
//!
//! Provides in-memory caching of threat indicators with support for
//! IP addresses, CIDR blocks, domains, URLs, and hashes.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use super::ioc::{Ioc, IocType, ThreatMatch, MatchContext};

/// Statistics for cache operations
#[derive(Debug, Default)]
pub struct CacheStats {
    pub total_iocs: u64,
    pub ip_count: u64,
    pub cidr_count: u64,
    pub domain_count: u64,
    pub url_count: u64,
    pub hash_count: u64,
    pub ja3_count: u64,
    pub lookups: AtomicU64,
    pub hits: AtomicU64,
}

impl Clone for CacheStats {
    fn clone(&self) -> Self {
        Self {
            total_iocs: self.total_iocs,
            ip_count: self.ip_count,
            cidr_count: self.cidr_count,
            domain_count: self.domain_count,
            url_count: self.url_count,
            hash_count: self.hash_count,
            ja3_count: self.ja3_count,
            lookups: AtomicU64::new(self.lookups.load(Ordering::Relaxed)),
            hits: AtomicU64::new(self.hits.load(Ordering::Relaxed)),
        }
    }
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let lookups = self.lookups.load(Ordering::Relaxed);
        let hits = self.hits.load(Ordering::Relaxed);
        if lookups == 0 {
            0.0
        } else {
            hits as f64 / lookups as f64
        }
    }
}

/// Entry in the cache with the IOC and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    ioc: Ioc,
}

/// IOC Cache for fast threat intelligence lookups
#[derive(Debug, Serialize, Deserialize)]
pub struct IocCache {
    /// IP address lookups (exact match)
    ips: HashMap<IpAddr, CacheEntry>,
    /// CIDR block lookups (prefix match)
    cidrs: Vec<(IpNetwork, CacheEntry)>,
    /// Domain lookups (exact match)
    domains: HashMap<String, CacheEntry>,
    /// URL lookups (exact match)
    urls: HashMap<String, CacheEntry>,
    /// Hash lookups (MD5, SHA1, SHA256)
    hashes: HashMap<String, CacheEntry>,
    /// JA3/JA3S fingerprint lookups
    ja3: HashMap<String, CacheEntry>,
    /// SSL certificate hashes
    ssl_certs: HashMap<String, CacheEntry>,

    /// Cache statistics (not serialized)
    #[serde(skip)]
    stats: CacheStats,
}

impl Default for IocCache {
    fn default() -> Self {
        Self::new()
    }
}

impl IocCache {
    /// Create a new empty cache
    pub fn new() -> Self {
        Self {
            ips: HashMap::new(),
            cidrs: Vec::new(),
            domains: HashMap::new(),
            urls: HashMap::new(),
            hashes: HashMap::new(),
            ja3: HashMap::new(),
            ssl_certs: HashMap::new(),
            stats: CacheStats::default(),
        }
    }

    /// Insert an IOC into the cache
    pub fn insert(&mut self, ioc: Ioc) {
        let entry = CacheEntry { ioc: ioc.clone() };

        match ioc.ioc_type {
            IocType::Ipv4 | IocType::Ipv6 => {
                if let Ok(ip) = ioc.value.parse::<IpAddr>() {
                    self.ips.insert(ip, entry);
                }
            }
            IocType::IpCidr => {
                if let Ok(network) = ioc.value.parse::<IpNetwork>() {
                    // Remove any existing entry for this CIDR
                    self.cidrs.retain(|(n, _)| *n != network);
                    self.cidrs.push((network, entry));
                }
            }
            IocType::Domain => {
                self.domains.insert(ioc.value.to_lowercase(), entry);
            }
            IocType::Url => {
                self.urls.insert(ioc.value.clone(), entry);
            }
            IocType::Md5 | IocType::Sha1 | IocType::Sha256 => {
                self.hashes.insert(ioc.value.to_lowercase(), entry);
            }
            IocType::Ja3 | IocType::Ja3s => {
                self.ja3.insert(ioc.value.to_lowercase(), entry);
            }
            IocType::SslCertSha1 => {
                self.ssl_certs.insert(ioc.value.to_lowercase(), entry);
            }
        }
    }

    /// Insert multiple IOCs
    pub fn insert_many(&mut self, iocs: impl IntoIterator<Item = Ioc>) {
        for ioc in iocs {
            self.insert(ioc);
        }
    }

    /// Check if an IP address is in the cache
    pub fn check_ip(&self, ip: &IpAddr) -> Option<ThreatMatch> {
        self.stats.lookups.fetch_add(1, Ordering::Relaxed);

        // Check exact IP match first
        if let Some(entry) = self.ips.get(ip) {
            if !entry.ioc.is_expired() {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return Some(ThreatMatch {
                    ioc: entry.ioc.clone(),
                    matched_value: ip.to_string(),
                    context: MatchContext::SourceIp,
                });
            }
        }

        // Check CIDR ranges
        for (network, entry) in &self.cidrs {
            if network.contains(*ip) && !entry.ioc.is_expired() {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return Some(ThreatMatch {
                    ioc: entry.ioc.clone(),
                    matched_value: ip.to_string(),
                    context: MatchContext::SourceIp,
                });
            }
        }

        None
    }

    /// Check if a domain is in the cache
    pub fn check_domain(&self, domain: &str) -> Option<ThreatMatch> {
        self.stats.lookups.fetch_add(1, Ordering::Relaxed);

        let domain_lower = domain.to_lowercase();

        // Check exact match
        if let Some(entry) = self.domains.get(&domain_lower) {
            if !entry.ioc.is_expired() {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return Some(ThreatMatch {
                    ioc: entry.ioc.clone(),
                    matched_value: domain.to_string(),
                    context: MatchContext::DnsQuery,
                });
            }
        }

        // Check parent domains (e.g., evil.example.com matches example.com)
        let parts: Vec<&str> = domain_lower.split('.').collect();
        for i in 1..parts.len().saturating_sub(1) {
            let parent = parts[i..].join(".");
            if let Some(entry) = self.domains.get(&parent) {
                if !entry.ioc.is_expired() {
                    self.stats.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(ThreatMatch {
                        ioc: entry.ioc.clone(),
                        matched_value: domain.to_string(),
                        context: MatchContext::DnsQuery,
                    });
                }
            }
        }

        None
    }

    /// Check if a URL is in the cache
    pub fn check_url(&self, url: &str) -> Option<ThreatMatch> {
        self.stats.lookups.fetch_add(1, Ordering::Relaxed);

        if let Some(entry) = self.urls.get(url) {
            if !entry.ioc.is_expired() {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return Some(ThreatMatch {
                    ioc: entry.ioc.clone(),
                    matched_value: url.to_string(),
                    context: MatchContext::HttpUrl,
                });
            }
        }

        None
    }

    /// Check if a hash is in the cache
    pub fn check_hash(&self, hash: &str) -> Option<ThreatMatch> {
        self.stats.lookups.fetch_add(1, Ordering::Relaxed);

        let hash_lower = hash.to_lowercase();
        if let Some(entry) = self.hashes.get(&hash_lower) {
            if !entry.ioc.is_expired() {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return Some(ThreatMatch {
                    ioc: entry.ioc.clone(),
                    matched_value: hash.to_string(),
                    context: MatchContext::FileHash,
                });
            }
        }

        None
    }

    /// Check if a JA3/JA3S fingerprint is in the cache
    pub fn check_ja3(&self, ja3: &str) -> Option<ThreatMatch> {
        self.stats.lookups.fetch_add(1, Ordering::Relaxed);

        let ja3_lower = ja3.to_lowercase();
        if let Some(entry) = self.ja3.get(&ja3_lower) {
            if !entry.ioc.is_expired() {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return Some(ThreatMatch {
                    ioc: entry.ioc.clone(),
                    matched_value: ja3.to_string(),
                    context: MatchContext::TlsJa3,
                });
            }
        }

        None
    }

    /// Check SSL certificate hash
    pub fn check_ssl_cert(&self, cert_hash: &str) -> Option<ThreatMatch> {
        self.stats.lookups.fetch_add(1, Ordering::Relaxed);

        let hash_lower = cert_hash.to_lowercase();
        if let Some(entry) = self.ssl_certs.get(&hash_lower) {
            if !entry.ioc.is_expired() {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return Some(ThreatMatch {
                    ioc: entry.ioc.clone(),
                    matched_value: cert_hash.to_string(),
                    context: MatchContext::SslCert,
                });
            }
        }

        None
    }

    /// Remove expired entries from the cache
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Utc::now();
        let mut removed = 0;

        self.ips.retain(|_, entry| {
            let keep = entry.ioc.expires_at.map(|e| e > now).unwrap_or(true);
            if !keep {
                removed += 1;
            }
            keep
        });

        self.cidrs.retain(|(_, entry)| {
            let keep = entry.ioc.expires_at.map(|e| e > now).unwrap_or(true);
            if !keep {
                removed += 1;
            }
            keep
        });

        self.domains.retain(|_, entry| {
            let keep = entry.ioc.expires_at.map(|e| e > now).unwrap_or(true);
            if !keep {
                removed += 1;
            }
            keep
        });

        self.urls.retain(|_, entry| {
            let keep = entry.ioc.expires_at.map(|e| e > now).unwrap_or(true);
            if !keep {
                removed += 1;
            }
            keep
        });

        self.hashes.retain(|_, entry| {
            let keep = entry.ioc.expires_at.map(|e| e > now).unwrap_or(true);
            if !keep {
                removed += 1;
            }
            keep
        });

        self.ja3.retain(|_, entry| {
            let keep = entry.ioc.expires_at.map(|e| e > now).unwrap_or(true);
            if !keep {
                removed += 1;
            }
            keep
        });

        self.ssl_certs.retain(|_, entry| {
            let keep = entry.ioc.expires_at.map(|e| e > now).unwrap_or(true);
            if !keep {
                removed += 1;
            }
            keep
        });

        if removed > 0 {
            debug!("Cleaned up {} expired IOCs from cache", removed);
        }

        removed
    }

    /// Clear all entries from a specific source
    pub fn clear_source(&mut self, source: &str) {
        self.ips.retain(|_, e| e.ioc.source != source);
        self.cidrs.retain(|(_, e)| e.ioc.source != source);
        self.domains.retain(|_, e| e.ioc.source != source);
        self.urls.retain(|_, e| e.ioc.source != source);
        self.hashes.retain(|_, e| e.ioc.source != source);
        self.ja3.retain(|_, e| e.ioc.source != source);
        self.ssl_certs.retain(|_, e| e.ioc.source != source);
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            total_iocs: self.total_count() as u64,
            ip_count: self.ips.len() as u64,
            cidr_count: self.cidrs.len() as u64,
            domain_count: self.domains.len() as u64,
            url_count: self.urls.len() as u64,
            hash_count: self.hashes.len() as u64,
            ja3_count: self.ja3.len() as u64,
            lookups: AtomicU64::new(self.stats.lookups.load(Ordering::Relaxed)),
            hits: AtomicU64::new(self.stats.hits.load(Ordering::Relaxed)),
        }
    }

    /// Get total number of IOCs in cache
    pub fn total_count(&self) -> usize {
        self.ips.len()
            + self.cidrs.len()
            + self.domains.len()
            + self.urls.len()
            + self.hashes.len()
            + self.ja3.len()
            + self.ssl_certs.len()
    }

    /// Save cache to disk
    pub fn save_to_disk(&self, path: &Path) -> anyhow::Result<()> {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, self)?;
        info!("Saved {} IOCs to cache file", self.total_count());
        Ok(())
    }

    /// Load cache from disk
    pub fn load_from_disk(path: &Path) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let cache: Self = bincode::deserialize_from(reader)?;
        info!("Loaded {} IOCs from cache file", cache.total_count());
        Ok(cache)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_intel::ioc::ThreatCategory;
    use std::net::Ipv4Addr;

    #[test]
    fn test_ip_lookup() {
        let mut cache = IocCache::new();

        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let ioc = Ioc::ip(ip, "test", ThreatCategory::C2);
        cache.insert(ioc);

        assert!(cache.check_ip(&ip).is_some());
        assert!(cache.check_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_none());
    }

    #[test]
    fn test_cidr_lookup() {
        let mut cache = IocCache::new();

        let ioc = Ioc::new(
            IocType::IpCidr,
            "192.168.0.0/16".to_string(),
            "test".to_string(),
            ThreatCategory::Spam,
        );
        cache.insert(ioc);

        // Should match IPs in the range
        assert!(cache.check_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).is_some());
        assert!(cache.check_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))).is_some());

        // Should not match IPs outside the range
        assert!(cache.check_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).is_none());
    }

    #[test]
    fn test_domain_lookup() {
        let mut cache = IocCache::new();

        let ioc = Ioc::domain("evil.com", "test", ThreatCategory::Phishing);
        cache.insert(ioc);

        // Exact match
        assert!(cache.check_domain("evil.com").is_some());
        // Subdomain should also match
        assert!(cache.check_domain("www.evil.com").is_some());
        assert!(cache.check_domain("sub.domain.evil.com").is_some());
        // Different domain should not match
        assert!(cache.check_domain("good.com").is_none());
    }

    #[test]
    fn test_hash_lookup() {
        let mut cache = IocCache::new();

        let ioc = Ioc::hash(
            "d41d8cd98f00b204e9800998ecf8427e",
            "test",
            ThreatCategory::Malware,
        );
        cache.insert(ioc);

        // Case insensitive
        assert!(cache.check_hash("d41d8cd98f00b204e9800998ecf8427e").is_some());
        assert!(cache.check_hash("D41D8CD98F00B204E9800998ECF8427E").is_some());
        assert!(cache.check_hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_none());
    }

    #[test]
    fn test_ja3_lookup() {
        let mut cache = IocCache::new();

        let ioc = Ioc::ja3("abc123def456", "test", ThreatCategory::Malware);
        cache.insert(ioc);

        assert!(cache.check_ja3("abc123def456").is_some());
        assert!(cache.check_ja3("ABC123DEF456").is_some());
        assert!(cache.check_ja3("unknown").is_none());
    }
}
