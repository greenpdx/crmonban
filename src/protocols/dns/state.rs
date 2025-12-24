//! DNS protocol state
//!
//! Per-flow state tracking for DNS protocol analysis.

use std::any::Any;
use std::collections::HashMap;

use crate::protocols::ProtocolStateData;
use super::types::*;

/// Per-flow DNS state
#[derive(Debug, Default)]
pub struct DnsState {
    /// Pending queries (by transaction ID)
    pub pending_queries: HashMap<u16, DnsQuery>,

    /// Query count
    pub query_count: u32,

    /// Response count
    pub response_count: u32,

    /// NXDOMAIN count (potential DGA)
    pub nxdomain_count: u32,

    /// Total unique domains queried
    pub unique_domains: std::collections::HashSet<String>,

    /// Tunneling detected
    pub tunneling_detected: bool,

    /// Suspicious domains detected
    pub suspicious_domains: Vec<String>,

    /// Last query name
    pub last_query: Option<String>,

    /// Last response code
    pub last_rcode: Option<u8>,

    /// Bytes in queries
    pub query_bytes: u64,

    /// Bytes in responses
    pub response_bytes: u64,
}

impl DnsState {
    /// Create new DNS state
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a query
    pub fn record_query(&mut self, query: &DnsQuery, tx_id: u16) {
        self.query_count += 1;
        self.last_query = Some(query.name.clone());
        self.unique_domains.insert(query.name.clone());
        self.pending_queries.insert(tx_id, query.clone());
    }

    /// Record a response
    pub fn record_response(&mut self, msg: &DnsMessage) {
        self.response_count += 1;
        self.last_rcode = Some(msg.rcode);

        // Track NXDOMAIN responses (potential DGA indicator)
        if msg.rcode == 3 {
            self.nxdomain_count += 1;
        }

        // Remove from pending
        self.pending_queries.remove(&msg.id);
    }

    /// Check for DGA indicators (high NXDOMAIN ratio)
    pub fn check_dga_indicators(&self) -> bool {
        if self.query_count < 10 {
            return false;
        }

        let nxdomain_ratio = self.nxdomain_count as f64 / self.query_count as f64;
        nxdomain_ratio > 0.5 // More than 50% NXDOMAIN is suspicious
    }

    /// Check for DNS tunneling patterns
    pub fn check_tunneling_patterns(&self) -> bool {
        self.tunneling_detected
    }

    /// Get query per second rate
    pub fn get_query_rate(&self) -> f64 {
        // Simplified - would need actual timing in real implementation
        self.query_count as f64
    }

    /// Check if this looks like enumeration/scanning
    pub fn check_enumeration(&self) -> bool {
        // Many queries to same domain with different subdomains
        if self.unique_domains.len() > 20 {
            // Check if they share common parent domain
            let mut parent_counts: HashMap<String, u32> = HashMap::new();
            for domain in &self.unique_domains {
                if let Some(parent) = domain.rsplit('.').take(2).collect::<Vec<_>>().join(".").chars().rev().collect::<String>().split('.').take(2).collect::<Vec<_>>().join(".").chars().rev().collect::<String>().into() {
                    *parent_counts.entry(parent).or_insert(0) += 1;
                }
            }
            // If any parent domain has many queries, likely enumeration
            parent_counts.values().any(|&count| count > 10)
        } else {
            false
        }
    }
}

impl ProtocolStateData for DnsState {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
