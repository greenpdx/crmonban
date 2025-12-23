//! Flow-based packet buffering for stream reassembly
//!
//! Buffers packets by flow (src_ip, src_port, dst_ip, dst_port) and flushes
//! batches to worker threads when thresholds are met.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::core::{FlowKey, Packet};

/// Configuration for flow buffering
#[derive(Debug, Clone)]
pub struct FlowBufferConfig {
    /// Flush when N packets accumulated per flow
    pub flush_packet_threshold: usize,
    /// Flush after timeout (ms) since first packet in flow
    pub flush_timeout_ms: u64,
    /// Max packets per flow before forced flush
    pub max_queue_size: usize,
    /// Max total flows to track (LRU eviction when exceeded)
    pub max_flows: usize,
}

impl Default for FlowBufferConfig {
    fn default() -> Self {
        Self {
            flush_packet_threshold: 10,
            flush_timeout_ms: 100,
            max_queue_size: 50,
            max_flows: 100_000,
        }
    }
}

/// Reason why a flow batch was flushed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushTrigger {
    /// Packet threshold reached
    PacketThreshold,
    /// Timeout elapsed
    Timeout,
    /// FIN flag seen
    Fin,
    /// RST flag seen
    Rst,
    /// Max queue size reached
    MaxSize,
    /// LRU eviction due to max_flows
    Eviction,
    /// Manual flush (shutdown)
    Manual,
}

/// A batch of packets from a single flow, ready for worker processing
#[derive(Debug)]
pub struct FlowBatch {
    /// Flow key identifying the connection
    pub key: FlowKey,
    /// Packets in this batch
    pub packets: Vec<Packet>,
    /// Why this batch was flushed
    pub trigger: FlushTrigger,
    /// Time of first packet in batch
    pub first_seen: Instant,
    /// Time of last packet in batch
    pub last_seen: Instant,
}

/// Per-flow packet queue
struct FlowQueue {
    packets: VecDeque<Packet>,
    first_seen: Instant,
    last_seen: Instant,
}

impl FlowQueue {
    fn new(packet: Packet) -> Self {
        let now = Instant::now();
        let mut packets = VecDeque::with_capacity(16);
        packets.push_back(packet);
        Self {
            packets,
            first_seen: now,
            last_seen: now,
        }
    }

    fn push(&mut self, packet: Packet) {
        self.last_seen = Instant::now();
        self.packets.push_back(packet);
    }

    fn len(&self) -> usize {
        self.packets.len()
    }

    fn into_batch(self, key: FlowKey, trigger: FlushTrigger) -> FlowBatch {
        FlowBatch {
            key,
            packets: self.packets.into(),
            trigger,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
        }
    }
}

/// Flow-based packet buffer
///
/// Accumulates packets by flow and flushes batches when:
/// - Packet count threshold reached
/// - Timeout elapsed since first packet
/// - FIN/RST flag seen (connection ending)
/// - Max queue size reached
pub struct FlowBuffer {
    flows: HashMap<FlowKey, FlowQueue>,
    config: FlowBufferConfig,
    /// Track insertion order for LRU eviction
    insertion_order: VecDeque<FlowKey>,
}

impl FlowBuffer {
    /// Create a new flow buffer with the given configuration
    pub fn new(config: FlowBufferConfig) -> Self {
        Self {
            flows: HashMap::with_capacity(config.max_flows / 4),
            config,
            insertion_order: VecDeque::with_capacity(1024),
        }
    }

    /// Add a packet to the buffer
    ///
    /// Returns a vector of flow batches ready to be sent to workers.
    /// May return multiple batches if LRU eviction occurs.
    pub fn push(&mut self, packet: Packet) -> Vec<FlowBatch> {
        let mut batches = Vec::new();
        let key = FlowKey::from_packet(&packet);

        // Check for FIN/RST flags
        let is_fin = packet.tcp_flags().as_ref().map(|f| f.fin).unwrap_or(false);
        let is_rst = packet.tcp_flags().as_ref().map(|f| f.rst).unwrap_or(false);

        // Get or create flow queue
        if let Some(queue) = self.flows.get_mut(&key) {
            queue.push(packet);

            // Check flush conditions
            let trigger = if is_rst {
                Some(FlushTrigger::Rst)
            } else if is_fin {
                Some(FlushTrigger::Fin)
            } else if queue.len() >= self.config.max_queue_size {
                Some(FlushTrigger::MaxSize)
            } else if queue.len() >= self.config.flush_packet_threshold {
                Some(FlushTrigger::PacketThreshold)
            } else {
                None
            };

            if let Some(trigger) = trigger {
                if let Some(queue) = self.flows.remove(&key) {
                    // Remove from insertion order
                    self.insertion_order.retain(|k| k != &key);
                    batches.push(queue.into_batch(key, trigger));
                }
            }
        } else {
            // New flow - check if we need to evict
            if self.flows.len() >= self.config.max_flows {
                // LRU eviction - remove oldest flow
                if let Some(old_key) = self.insertion_order.pop_front() {
                    if let Some(queue) = self.flows.remove(&old_key) {
                        batches.push(queue.into_batch(old_key, FlushTrigger::Eviction));
                    }
                }
            }

            // Check if single-packet flush (FIN/RST on new flow)
            if is_rst || is_fin {
                let trigger = if is_rst { FlushTrigger::Rst } else { FlushTrigger::Fin };
                let queue = FlowQueue::new(packet);
                batches.push(queue.into_batch(key, trigger));
            } else {
                // Add new flow
                self.flows.insert(key.clone(), FlowQueue::new(packet));
                self.insertion_order.push_back(key);
            }
        }

        batches
    }

    /// Check for timed-out flows and flush them
    ///
    /// Call this periodically (e.g., when no packets available)
    pub fn check_timeouts(&mut self) -> Vec<FlowBatch> {
        let timeout = Duration::from_millis(self.config.flush_timeout_ms);
        let now = Instant::now();
        let mut batches = Vec::new();
        let mut keys_to_remove = Vec::new();

        for (key, queue) in &self.flows {
            if now.duration_since(queue.first_seen) >= timeout {
                keys_to_remove.push(key.clone());
            }
        }

        for key in keys_to_remove {
            if let Some(queue) = self.flows.remove(&key) {
                self.insertion_order.retain(|k| k != &key);
                batches.push(queue.into_batch(key, FlushTrigger::Timeout));
            }
        }

        batches
    }

    /// Flush all flows (for shutdown or periodic forced flush)
    pub fn flush_all(&mut self) -> Vec<FlowBatch> {
        let mut batches = Vec::with_capacity(self.flows.len());

        for (key, queue) in self.flows.drain() {
            batches.push(queue.into_batch(key, FlushTrigger::Manual));
        }
        self.insertion_order.clear();

        batches
    }

    /// Number of active flows being tracked
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Total packets buffered across all flows
    pub fn packet_count(&self) -> usize {
        self.flows.values().map(|q| q.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::core::IpProtocol;

    fn make_test_packet() -> Packet {
        Packet::new(
            1,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpProtocol::Icmp,
            "lo",
        )
    }

    #[test]
    fn test_flow_buffer_config_default() {
        let config = FlowBufferConfig::default();
        assert_eq!(config.flush_packet_threshold, 10);
        assert_eq!(config.flush_timeout_ms, 100);
        assert_eq!(config.max_queue_size, 50);
        assert_eq!(config.max_flows, 100_000);
    }

    #[test]
    fn test_flow_buffer_new() {
        let config = FlowBufferConfig::default();
        let buffer = FlowBuffer::new(config);
        assert_eq!(buffer.flow_count(), 0);
        assert_eq!(buffer.packet_count(), 0);
    }
}
