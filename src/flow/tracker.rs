//! Flow tracker - main flow tracking engine
//!
//! Coordinates flow table, timeout management, and statistics.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::core::flow::{Flow, FlowKey, FlowStats};
use crate::core::packet::{Direction, Packet};
use super::table::FlowTable;
use super::{FlowConfig, TrackerStats};

/// Main flow tracking engine
pub struct FlowTracker {
    /// Configuration
    config: FlowConfig,
    /// Flow table
    table: FlowTable,
    /// Tracker statistics
    stats: TrackerStats,
    /// Last cleanup time
    last_cleanup: Instant,
}

impl FlowTracker {
    /// Create a new flow tracker
    pub fn new(config: FlowConfig) -> Self {
        info!(
            "Initializing flow tracker (table_size={}, tcp_timeout={}s)",
            config.table_size, config.timeout_tcp_established
        );

        Self {
            table: FlowTable::new(config.clone()),
            config,
            stats: TrackerStats::default(),
            last_cleanup: Instant::now(),
        }
    }

    /// Process a packet and return its flow and direction
    pub fn process(&mut self, pkt: &mut Packet) -> (&Flow, Direction) {
        self.stats.packets_processed += 1;
        self.stats.bytes_processed += pkt.raw_len as u64;

        // Get or create flow
        let key = FlowKey::from_packet(pkt);
        let (flow, is_new) = self.table.get_or_create(pkt);

        // Track new flows
        if is_new {
            self.stats.flows_created += 1;
        }

        // Update flow with packet (if not the first packet, which was used in creation)
        let direction = if is_new {
            Direction::ToServer
        } else {
            flow.update(pkt)
        };

        // Update packet with flow info
        pkt.flow_id = Some(flow.id);
        pkt.direction = direction;

        // Periodic cleanup
        self.maybe_cleanup();

        // Return flow reference (need to get it again due to borrow checker)
        let flow = self.table.get(&key).unwrap();
        (flow, direction)
    }

    /// Get a flow by key
    pub fn get_flow(&self, key: &FlowKey) -> Option<&Flow> {
        self.table.get(key)
    }

    /// Get a flow by ID
    pub fn get_flow_by_id(&self, id: u64) -> Option<&Flow> {
        self.table.get_by_id(id)
    }

    /// Get flow statistics
    pub fn get_flow_stats(&self, key: &FlowKey) -> Option<FlowStats> {
        self.table.get(key).map(|f| f.stats())
    }

    /// Get active flow count
    pub fn active_flows(&self) -> usize {
        self.table.len()
    }

    /// Get tracker statistics
    pub fn stats(&self) -> &TrackerStats {
        &self.stats
    }

    /// Manually trigger cleanup
    pub fn cleanup(&mut self) -> Vec<Flow> {
        let expired = self.table.cleanup_expired();
        self.stats.flows_expired += expired.len() as u64;
        self.stats.active_flows = self.table.len();

        if !expired.is_empty() {
            debug!("Cleaned up {} expired flows", expired.len());
        }

        expired
    }

    /// Drain completed flows (for export)
    pub fn drain_completed(&mut self) -> Vec<Flow> {
        let completed = self.table.drain_completed();
        self.stats.flows_expired += completed.len() as u64;
        self.stats.active_flows = self.table.len();
        completed
    }

    /// Get all flows matching a filter
    pub fn filter_flows<F>(&self, predicate: F) -> Vec<&Flow>
    where
        F: Fn(&Flow) -> bool,
    {
        self.table.filter(predicate)
    }

    /// Get flows by source IP
    pub fn flows_by_src_ip(&self, ip: std::net::IpAddr) -> Vec<&Flow> {
        self.filter_flows(|f| f.client_ip == ip)
    }

    /// Get flows by destination IP
    pub fn flows_by_dst_ip(&self, ip: std::net::IpAddr) -> Vec<&Flow> {
        self.filter_flows(|f| f.server_ip == ip)
    }

    /// Get flows by destination port
    pub fn flows_by_port(&self, port: u16) -> Vec<&Flow> {
        self.filter_flows(|f| f.server_port == port || f.client_port == port)
    }

    /// Run periodic cleanup if needed
    fn maybe_cleanup(&mut self) {
        let cleanup_interval = Duration::from_secs(self.config.cleanup_interval);
        if self.last_cleanup.elapsed() >= cleanup_interval {
            let _ = self.cleanup();
            self.last_cleanup = Instant::now();
        }
    }

    /// Iterate over all active flows
    pub fn iter(&self) -> impl Iterator<Item = &Flow> {
        self.table.iter()
    }
}

/// Thread-safe flow tracker wrapper
pub struct SharedFlowTracker {
    inner: Arc<RwLock<FlowTracker>>,
}

impl SharedFlowTracker {
    pub fn new(config: FlowConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(FlowTracker::new(config))),
        }
    }

    pub async fn process(&self, pkt: &mut Packet) -> (u64, Direction) {
        let mut tracker = self.inner.write().await;
        let (flow, direction) = tracker.process(pkt);
        (flow.id, direction)
    }

    pub async fn get_flow_stats(&self, id: u64) -> Option<FlowStats> {
        let tracker = self.inner.read().await;
        tracker.get_flow_by_id(id).map(|f| f.stats())
    }

    pub async fn active_flows(&self) -> usize {
        let tracker = self.inner.read().await;
        tracker.active_flows()
    }

    pub async fn stats(&self) -> TrackerStats {
        let tracker = self.inner.read().await;
        tracker.stats().clone()
    }

    pub async fn cleanup(&self) -> Vec<Flow> {
        let mut tracker = self.inner.write().await;
        tracker.cleanup()
    }

    pub async fn drain_completed(&self) -> Vec<Flow> {
        let mut tracker = self.inner.write().await;
        tracker.drain_completed()
    }

    pub fn clone_inner(&self) -> Arc<RwLock<FlowTracker>> {
        self.inner.clone()
    }
}

impl Clone for SharedFlowTracker {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::packet::{IpProtocol, TcpFlags};
    use std::net::{IpAddr, Ipv4Addr};

    fn make_syn_packet(src_port: u16, dst_port: u16) -> Packet {
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

    fn make_syn_ack_packet(src_port: u16, dst_port: u16) -> Packet {
        let mut pkt = Packet::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpProtocol::Tcp,
        );
        pkt.src_port = src_port;
        pkt.dst_port = dst_port;
        pkt.tcp_flags = Some(TcpFlags { syn: true, ack: true, ..Default::default() });
        pkt.raw_len = 64;
        pkt
    }

    #[test]
    fn test_tracker_process() {
        let config = FlowConfig::default();
        let mut tracker = FlowTracker::new(config);

        let mut pkt = make_syn_packet(54321, 80);
        let (flow, direction) = tracker.process(&mut pkt);

        assert_eq!(direction, Direction::ToServer);
        assert!(pkt.flow_id.is_some());
        assert_eq!(tracker.active_flows(), 1);
    }

    #[test]
    fn test_tracker_bidirectional() {
        let config = FlowConfig::default();
        let mut tracker = FlowTracker::new(config);

        // SYN
        let mut syn = make_syn_packet(54321, 80);
        let (_, dir1) = tracker.process(&mut syn);
        assert_eq!(dir1, Direction::ToServer);

        // SYN-ACK
        let mut syn_ack = make_syn_ack_packet(80, 54321);
        let (flow, dir2) = tracker.process(&mut syn_ack);
        assert_eq!(dir2, Direction::ToClient);
        // Store values before releasing the borrow
        let fwd = flow.fwd_packets;
        let bwd = flow.bwd_packets;

        // Should still be same flow
        assert_eq!(tracker.active_flows(), 1);
        assert_eq!(fwd, 1);
        assert_eq!(bwd, 1);
    }

    #[test]
    fn test_tracker_stats() {
        let config = FlowConfig::default();
        let mut tracker = FlowTracker::new(config);

        let mut pkt1 = make_syn_packet(54321, 80);
        let mut pkt2 = make_syn_packet(54322, 443);

        tracker.process(&mut pkt1);
        tracker.process(&mut pkt2);

        let stats = tracker.stats();
        assert_eq!(stats.packets_processed, 2);
        assert_eq!(stats.flows_created, 2);
    }
}
