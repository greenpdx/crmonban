use super::features::{WindowStats, DEFAULT_AUTH_PORTS};
use super::types::FeatureVector;
use crmonban_types::Packet;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

pub struct Aggregator {
    windows: HashMap<IpAddr, WindowStats>,
    window_size_ns: u64,
    min_packets: usize,
    auth_ports: Arc<HashSet<u16>>,
}

pub struct AggregatedWindow {
    pub src_ip: IpAddr,
    pub vector: FeatureVector,
    pub packet_count: usize,
    pub start_time_ns: u64,
    pub end_time_ns: u64,
}

impl Aggregator {
    pub fn new(window_size_ms: u64, min_packets: usize) -> Self {
        Self {
            windows: HashMap::new(),
            window_size_ns: window_size_ms * 1_000_000,
            min_packets,
            auth_ports: Arc::new(DEFAULT_AUTH_PORTS.iter().copied().collect()),
        }
    }

    pub fn with_auth_ports(window_size_ms: u64, min_packets: usize, auth_ports: Vec<u16>) -> Self {
        Self {
            windows: HashMap::new(),
            window_size_ns: window_size_ms * 1_000_000,
            min_packets,
            auth_ports: Arc::new(auth_ports.into_iter().collect()),
        }
    }

    pub fn add_packet(&mut self, packet: Packet) -> Option<AggregatedWindow> {
        let src_ip = packet.src_ip();
        let timestamp = packet.timestamp_ns();

        let auth_ports = Arc::clone(&self.auth_ports);
        let window = self
            .windows
            .entry(src_ip)
            .or_insert_with(|| WindowStats::with_auth_ports(src_ip, auth_ports));

        // Check if this packet belongs to a new window
        if !window.packets.is_empty() {
            let window_start = window.start_time_ns;
            if timestamp > window_start + self.window_size_ns {
                // Window expired, extract features and start new window
                let result = self.finalize_window(src_ip);

                // Create new window with this packet
                let mut new_window =
                    WindowStats::with_auth_ports(src_ip, Arc::clone(&self.auth_ports));
                new_window.add_packet(packet);
                self.windows.insert(src_ip, new_window);

                return result;
            }
        }

        window.add_packet(packet);
        None
    }

    pub fn flush(&mut self) -> Vec<AggregatedWindow> {
        let src_ips: Vec<IpAddr> = self.windows.keys().copied().collect();
        let mut results = Vec::new();

        for src_ip in src_ips {
            if let Some(result) = self.finalize_window(src_ip) {
                results.push(result);
            }
        }

        self.windows.clear();
        results
    }

    pub fn flush_expired(&mut self, current_time_ns: u64) -> Vec<AggregatedWindow> {
        let expired: Vec<IpAddr> = self
            .windows
            .iter()
            .filter(|(_, w)| {
                !w.packets.is_empty()
                    && current_time_ns > w.start_time_ns + self.window_size_ns
            })
            .map(|(ip, _)| *ip)
            .collect();

        let mut results = Vec::new();
        for src_ip in expired {
            if let Some(result) = self.finalize_window(src_ip) {
                results.push(result);
            }
            self.windows.remove(&src_ip);
        }

        results
    }

    fn finalize_window(&mut self, src_ip: IpAddr) -> Option<AggregatedWindow> {
        let window = self.windows.get(&src_ip)?;

        if window.packets.len() < self.min_packets {
            return None;
        }

        let vector = window.extract_features();

        Some(AggregatedWindow {
            src_ip,
            vector,
            packet_count: window.packets.len(),
            start_time_ns: window.start_time_ns,
            end_time_ns: window.end_time_ns,
        })
    }

    pub fn window_count(&self) -> usize {
        self.windows.len()
    }

    pub fn total_packets(&self) -> usize {
        self.windows.values().map(|w| w.packets.len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crmonban_types::IpProtocol;
    use chrono::{TimeZone, Utc};
    use std::net::Ipv4Addr;

    fn make_packet(src_ip: IpAddr, timestamp_ns: u64) -> Packet {
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let mut pkt = Packet::new(0, src_ip, dst_ip, IpProtocol::Tcp, "lo");
        pkt.timestamp = Utc.timestamp_nanos(timestamp_ns as i64);
        pkt
    }

    #[test]
    fn test_aggregator_window_expiry() {
        let mut agg = Aggregator::new(1000, 2); // 1 second window, min 2 packets

        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Add packets within window
        assert!(agg.add_packet(make_packet(src, 0)).is_none());
        assert!(agg.add_packet(make_packet(src, 500_000_000)).is_none()); // 500ms

        // Add packet after window expires (1.5s)
        let result = agg.add_packet(make_packet(src, 1_500_000_000));
        assert!(result.is_some());

        let window = result.unwrap();
        assert_eq!(window.src_ip, src);
        assert_eq!(window.packet_count, 2);
    }

    #[test]
    fn test_aggregator_min_packets() {
        let mut agg = Aggregator::new(1000, 5); // Need 5 packets minimum

        let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Add only 2 packets
        agg.add_packet(make_packet(src, 0));
        agg.add_packet(make_packet(src, 100_000_000));

        // Force window expiry with only 2 packets
        let result = agg.add_packet(make_packet(src, 2_000_000_000));

        // Should be None because we didn't meet min_packets
        assert!(result.is_none());
    }

    #[test]
    fn test_aggregator_flush() {
        let mut agg = Aggregator::new(60000, 2);

        let src1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let src2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Add packets from two sources
        for i in 0..5 {
            agg.add_packet(make_packet(src1, i * 1_000_000));
            agg.add_packet(make_packet(src2, i * 1_000_000));
        }

        let results = agg.flush();
        assert_eq!(results.len(), 2);
    }
}
