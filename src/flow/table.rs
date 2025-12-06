//! Flow hash table with timeout management
//!
//! Efficient storage and lookup for active flows.

use std::collections::HashMap;
use std::time::Instant;

use crate::core::flow::{Flow, FlowKey};
use crate::core::packet::Packet;
use super::FlowConfig;

/// Flow table entry with timeout tracking
struct FlowEntry {
    flow: Flow,
    timeout: Instant,
}

/// Hash table for flow storage
pub struct FlowTable {
    /// Flow storage
    flows: HashMap<FlowKey, FlowEntry>,
    /// Maximum table size
    max_size: usize,
    /// Configuration
    config: FlowConfig,
    /// Next flow ID
    next_id: u64,
    /// Statistics
    pub stats: TableStats,
}

/// Table statistics
#[derive(Debug, Clone, Default)]
pub struct TableStats {
    pub inserts: u64,
    pub lookups: u64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub expired: u64,
}

impl FlowTable {
    /// Create a new flow table
    pub fn new(config: FlowConfig) -> Self {
        let max_size = config.table_size;
        Self {
            flows: HashMap::with_capacity(max_size.min(100_000)),
            max_size,
            config,
            next_id: 1,
            stats: TableStats::default(),
        }
    }

    /// Get or create a flow for a packet
    /// Returns the flow and a bool indicating if it was newly created
    pub fn get_or_create(&mut self, pkt: &Packet) -> (&mut Flow, bool) {
        let key = FlowKey::from_packet(pkt);
        self.stats.lookups += 1;

        if self.flows.contains_key(&key) {
            self.stats.hits += 1;
            let entry = self.flows.get_mut(&key).unwrap();
            let timeout = self.config.timeout_for(&entry.flow);
            entry.timeout = Instant::now() + timeout;
            (&mut entry.flow, false)
        } else {
            self.stats.misses += 1;

            // Check if table is full
            if self.flows.len() >= self.max_size {
                // Evict oldest flow
                self.evict_oldest();
            }

            // Create new flow
            let flow_id = self.next_id;
            self.next_id += 1;
            let flow = Flow::new(flow_id, pkt);
            let timeout = self.config.timeout_for(&flow);

            self.stats.inserts += 1;
            self.flows.insert(key.clone(), FlowEntry {
                flow,
                timeout: Instant::now() + timeout,
            });

            (&mut self.flows.get_mut(&key).unwrap().flow, true)
        }
    }

    /// Get a flow by key
    pub fn get(&self, key: &FlowKey) -> Option<&Flow> {
        self.flows.get(key).map(|e| &e.flow)
    }

    /// Get a mutable flow by key
    pub fn get_mut(&mut self, key: &FlowKey) -> Option<&mut Flow> {
        self.flows.get_mut(key).map(|e| &mut e.flow)
    }

    /// Get a flow by ID
    pub fn get_by_id(&self, id: u64) -> Option<&Flow> {
        self.flows.values().find(|e| e.flow.id == id).map(|e| &e.flow)
    }

    /// Remove a flow
    pub fn remove(&mut self, key: &FlowKey) -> Option<Flow> {
        self.flows.remove(key).map(|e| e.flow)
    }

    /// Get current flow count
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Check if table is empty
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Iterate over all flows
    pub fn iter(&self) -> impl Iterator<Item = &Flow> {
        self.flows.values().map(|e| &e.flow)
    }

    /// Iterate over flows mutably
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Flow> {
        self.flows.values_mut().map(|e| &mut e.flow)
    }

    /// Remove expired flows
    pub fn cleanup_expired(&mut self) -> Vec<Flow> {
        let now = Instant::now();
        let expired_keys: Vec<FlowKey> = self.flows
            .iter()
            .filter(|(_, entry)| entry.timeout < now)
            .map(|(key, _)| key.clone())
            .collect();

        let mut expired_flows = Vec::with_capacity(expired_keys.len());
        for key in expired_keys {
            if let Some(entry) = self.flows.remove(&key) {
                self.stats.expired += 1;
                expired_flows.push(entry.flow);
            }
        }

        expired_flows
    }

    /// Evict the oldest flow (when table is full)
    fn evict_oldest(&mut self) {
        if let Some((oldest_key, _)) = self.flows
            .iter()
            .min_by_key(|(_, entry)| entry.flow.last_seen)
            .map(|(k, v)| (k.clone(), v))
        {
            self.flows.remove(&oldest_key);
            self.stats.evictions += 1;
        }
    }

    /// Update flow timeout after packet processing
    pub fn touch(&mut self, key: &FlowKey) {
        if let Some(entry) = self.flows.get_mut(key) {
            let timeout = self.config.timeout_for(&entry.flow);
            entry.timeout = Instant::now() + timeout;
        }
    }

    /// Get flows matching a predicate
    pub fn filter<F>(&self, predicate: F) -> Vec<&Flow>
    where
        F: Fn(&Flow) -> bool,
    {
        self.flows.values()
            .map(|e| &e.flow)
            .filter(|f| predicate(f))
            .collect()
    }

    /// Get completed flows (for export)
    pub fn drain_completed(&mut self) -> Vec<Flow> {
        let completed_keys: Vec<FlowKey> = self.flows
            .iter()
            .filter(|(_, entry)| entry.flow.is_complete())
            .map(|(key, _)| key.clone())
            .collect();

        let mut completed = Vec::with_capacity(completed_keys.len());
        for key in completed_keys {
            if let Some(entry) = self.flows.remove(&key) {
                completed.push(entry.flow);
            }
        }

        completed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::packet::{IpProtocol, TcpFlags};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_packet(src_port: u16, dst_port: u16) -> Packet {
        let mut pkt = Packet::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpProtocol::Tcp,
        );
        pkt.src_port = src_port;
        pkt.dst_port = dst_port;
        pkt.tcp_flags = Some(TcpFlags { syn: true, ..Default::default() });
        pkt.raw_len = 64;
        pkt
    }

    #[test]
    fn test_flow_table_create() {
        let config = FlowConfig::default();
        let mut table = FlowTable::new(config);

        let pkt = make_packet(54321, 80);
        let (flow, is_new) = table.get_or_create(&pkt);

        assert!(is_new);
        assert_eq!(flow.client_port, 54321);
        assert_eq!(flow.server_port, 80);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_flow_table_lookup() {
        let config = FlowConfig::default();
        let mut table = FlowTable::new(config);

        let pkt1 = make_packet(54321, 80);
        let (flow1, is_new1) = table.get_or_create(&pkt1);
        let flow1_id = flow1.id;
        assert!(is_new1);

        let pkt2 = make_packet(54321, 80);
        let (flow2, is_new2) = table.get_or_create(&pkt2);
        let flow2_id = flow2.id;
        assert!(!is_new2);

        assert_eq!(flow1_id, flow2_id);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_flow_table_different_flows() {
        let config = FlowConfig::default();
        let mut table = FlowTable::new(config);

        let pkt1 = make_packet(54321, 80);
        table.get_or_create(&pkt1);

        let pkt2 = make_packet(54322, 80);
        table.get_or_create(&pkt2);

        assert_eq!(table.len(), 2);
    }
}
