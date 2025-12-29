//! GeoIP filtering module
//!
//! Provides country-based IP filtering using MaxMind GeoIP databases.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use maxminddb::{geoip2, Reader};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur during GeoIP operations
#[derive(Error, Debug)]
pub enum GeoIpError {
    #[error("Failed to open GeoIP database: {0}")]
    DatabaseOpen(#[from] maxminddb::MaxMindDBError),

    #[error("Database file not found: {0}")]
    NotFound(String),
}

/// GeoIP lookup result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoLookup {
    /// ISO country code (e.g., "US", "CN")
    pub country_code: Option<String>,
    /// Country name
    pub country_name: Option<String>,
    /// Continent code
    pub continent_code: Option<String>,
    /// Whether this is an EU country
    pub is_eu: bool,
}

/// GeoIP filter for country-based filtering
#[derive(Debug)]
pub struct GeoIpFilter {
    reader: Option<Arc<Reader<Vec<u8>>>>,
    blocked_countries: HashSet<String>,
    allowed_countries: HashSet<String>,
    mode: FilterMode,
}

/// Filter mode for GeoIP
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterMode {
    /// Block specific countries (blocklist mode)
    Blocklist,
    /// Only allow specific countries (allowlist mode)
    Allowlist,
    /// No filtering, just lookup
    Disabled,
}

impl Default for GeoIpFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoIpFilter {
    /// Create a new GeoIP filter without a database
    pub fn new() -> Self {
        Self {
            reader: None,
            blocked_countries: HashSet::new(),
            allowed_countries: HashSet::new(),
            mode: FilterMode::Disabled,
        }
    }

    /// Load a MaxMind GeoIP2 database
    pub fn load_database<P: AsRef<Path>>(mut self, path: P) -> Result<Self, GeoIpError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(GeoIpError::NotFound(path.display().to_string()));
        }

        let reader = Reader::open_readfile(path)?;
        self.reader = Some(Arc::new(reader));
        Ok(self)
    }

    /// Load database from bytes (useful for embedded databases)
    pub fn load_from_bytes(mut self, data: Vec<u8>) -> Result<Self, GeoIpError> {
        let reader = Reader::from_source(data)?;
        self.reader = Some(Arc::new(reader));
        Ok(self)
    }

    /// Set the filter mode
    pub fn with_mode(mut self, mode: FilterMode) -> Self {
        self.mode = mode;
        self
    }

    /// Add a country to the blocklist
    pub fn block_country(&mut self, country_code: &str) {
        self.blocked_countries.insert(country_code.to_uppercase());
        if self.mode == FilterMode::Disabled {
            self.mode = FilterMode::Blocklist;
        }
    }

    /// Add multiple countries to the blocklist
    pub fn block_countries(&mut self, country_codes: &[&str]) {
        for code in country_codes {
            self.block_country(code);
        }
    }

    /// Add a country to the allowlist
    pub fn allow_country(&mut self, country_code: &str) {
        self.allowed_countries.insert(country_code.to_uppercase());
    }

    /// Add multiple countries to the allowlist
    pub fn allow_countries(&mut self, country_codes: &[&str]) {
        for code in country_codes {
            self.allow_country(code);
        }
    }

    /// Remove a country from the blocklist
    pub fn unblock_country(&mut self, country_code: &str) {
        self.blocked_countries.remove(&country_code.to_uppercase());
    }

    /// Remove a country from the allowlist
    pub fn disallow_country(&mut self, country_code: &str) {
        self.allowed_countries.remove(&country_code.to_uppercase());
    }

    /// Lookup country information for an IP
    pub fn lookup(&self, ip: &IpAddr) -> Option<GeoLookup> {
        let reader = self.reader.as_ref()?;

        let result: Result<geoip2::Country, _> = reader.lookup(*ip);
        let country = result.ok()?;

        let country_data = country.country?;
        let continent = country.continent;

        Some(GeoLookup {
            country_code: country_data.iso_code.map(String::from),
            country_name: country_data
                .names
                .and_then(|n| n.get("en").map(|s| s.to_string())),
            continent_code: continent.and_then(|c| c.code.map(String::from)),
            is_eu: country_data.is_in_european_union.unwrap_or(false),
        })
    }

    /// Get just the country code for an IP
    pub fn lookup_country(&self, ip: &IpAddr) -> Option<String> {
        self.lookup(ip).and_then(|l| l.country_code)
    }

    /// Check if an IP is blocked based on GeoIP
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        match self.mode {
            FilterMode::Disabled => false,
            FilterMode::Blocklist => {
                if let Some(country) = self.lookup_country(ip) {
                    self.blocked_countries.contains(&country)
                } else {
                    false // Unknown countries not blocked in blocklist mode
                }
            }
            FilterMode::Allowlist => {
                if let Some(country) = self.lookup_country(ip) {
                    !self.allowed_countries.contains(&country)
                } else {
                    true // Unknown countries blocked in allowlist mode
                }
            }
        }
    }

    /// Check if an IP is from an EU country
    pub fn is_eu(&self, ip: &IpAddr) -> bool {
        self.lookup(ip).map(|l| l.is_eu).unwrap_or(false)
    }

    /// Get list of blocked countries
    pub fn blocked_countries(&self) -> &HashSet<String> {
        &self.blocked_countries
    }

    /// Get list of allowed countries
    pub fn allowed_countries(&self) -> &HashSet<String> {
        &self.allowed_countries
    }

    /// Get the current filter mode
    pub fn mode(&self) -> FilterMode {
        self.mode
    }

    /// Check if database is loaded
    pub fn has_database(&self) -> bool {
        self.reader.is_some()
    }

    /// Get statistics about the filter configuration
    pub fn stats(&self) -> GeoIpStats {
        GeoIpStats {
            database_loaded: self.has_database(),
            mode: self.mode,
            blocked_countries: self.blocked_countries.len(),
            allowed_countries: self.allowed_countries.len(),
        }
    }
}

/// Statistics about the GeoIP filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpStats {
    pub database_loaded: bool,
    pub mode: FilterMode,
    pub blocked_countries: usize,
    pub allowed_countries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_filter_creation() {
        let filter = GeoIpFilter::new();
        assert!(!filter.has_database());
        assert_eq!(filter.mode(), FilterMode::Disabled);
    }

    #[test]
    fn test_block_countries() {
        let mut filter = GeoIpFilter::new();
        filter.block_countries(&["CN", "RU", "KP"]);

        assert!(filter.blocked_countries().contains("CN"));
        assert!(filter.blocked_countries().contains("RU"));
        assert!(filter.blocked_countries().contains("KP"));
        assert_eq!(filter.mode(), FilterMode::Blocklist);
    }

    #[test]
    fn test_allow_countries() {
        let mut filter = GeoIpFilter::new().with_mode(FilterMode::Allowlist);
        filter.allow_countries(&["US", "CA", "GB"]);

        assert!(filter.allowed_countries().contains("US"));
        assert!(filter.allowed_countries().contains("CA"));
        assert!(filter.allowed_countries().contains("GB"));
    }

    #[test]
    fn test_no_database_lookup() {
        let filter = GeoIpFilter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        assert!(filter.lookup(&ip).is_none());
        assert!(!filter.is_blocked(&ip));
    }

    #[test]
    fn test_case_insensitive_country_codes() {
        let mut filter = GeoIpFilter::new();
        filter.block_country("cn");
        filter.block_country("RU");
        filter.block_country("Kp");

        assert!(filter.blocked_countries().contains("CN"));
        assert!(filter.blocked_countries().contains("RU"));
        assert!(filter.blocked_countries().contains("KP"));
    }

    #[test]
    fn test_stats() {
        let mut filter = GeoIpFilter::new();
        filter.block_countries(&["CN", "RU"]);
        filter.allow_countries(&["US"]);

        let stats = filter.stats();
        assert!(!stats.database_loaded);
        assert_eq!(stats.blocked_countries, 2);
        assert_eq!(stats.allowed_countries, 1);
    }
}
