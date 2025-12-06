//! Alert aggregation
//!
//! Aggregates similar alerts to reduce noise.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::core::event::{DetectionEvent, DetectionType, Severity};

/// Alert aggregator
pub struct Aggregator {
    /// Aggregation buckets
    buckets: HashMap<AggregationKey, AggregatedAlert>,
    /// Minimum events to aggregate
    min_count: usize,
    /// Aggregation window
    window: Duration,
    /// Last cleanup time
    last_cleanup: DateTime<Utc>,
}

/// Key for aggregation bucket
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AggregationKey {
    /// Source IP hash (0 if none)
    src_ip_hash: u64,
    /// Destination IP hash (0 if none)
    dst_ip_hash: u64,
    /// Event type discriminant
    event_type: std::mem::Discriminant<DetectionType>,
    /// Signature ID if present
    signature_id: Option<u32>,
}

impl AggregationKey {
    fn from_event(event: &DetectionEvent) -> Self {
        use std::collections::hash_map::DefaultHasher;

        let mut src_hasher = DefaultHasher::new();
        event.src_ip.hash(&mut src_hasher);

        let mut dst_hasher = DefaultHasher::new();
        event.dst_ip.hash(&mut dst_hasher);

        Self {
            src_ip_hash: src_hasher.finish(),
            dst_ip_hash: dst_hasher.finish(),
            event_type: std::mem::discriminant(&event.event_type),
            signature_id: event.rule_id,
        }
    }
}

/// An aggregated alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedAlert {
    /// Aggregation ID
    pub id: Uuid,
    /// First event timestamp
    pub first_seen: DateTime<Utc>,
    /// Last event timestamp
    pub last_seen: DateTime<Utc>,
    /// Number of events aggregated
    pub count: usize,
    /// Highest severity seen
    pub max_severity: Severity,
    /// Representative event
    pub representative: DetectionEvent,
    /// Unique source IPs
    pub unique_sources: usize,
    /// Unique destination IPs
    pub unique_destinations: usize,
}

impl AggregatedAlert {
    /// Create from first event
    fn new(event: DetectionEvent) -> Self {
        Self {
            id: Uuid::new_v4(),
            first_seen: event.timestamp,
            last_seen: event.timestamp,
            count: 1,
            max_severity: event.severity,
            representative: event,
            unique_sources: 1,
            unique_destinations: 1,
        }
    }

    /// Add an event to the aggregation
    fn add(&mut self, event: &DetectionEvent) {
        self.last_seen = event.timestamp;
        self.count += 1;
        if event.severity > self.max_severity {
            self.max_severity = event.severity;
        }
    }

    /// Get duration of the aggregated alert
    pub fn duration(&self) -> chrono::Duration {
        self.last_seen - self.first_seen
    }

    /// Get events per second rate
    pub fn rate(&self) -> f64 {
        let duration_secs = self.duration().num_seconds().max(1) as f64;
        self.count as f64 / duration_secs
    }
}

impl Aggregator {
    /// Create a new aggregator
    pub fn new(min_count: usize, window: Duration) -> Self {
        Self {
            buckets: HashMap::new(),
            min_count,
            window,
            last_cleanup: Utc::now(),
        }
    }

    /// Try to aggregate an event
    ///
    /// Returns Some(aggregated) if this event was aggregated with existing ones,
    /// None if it should be processed individually.
    pub fn try_aggregate(&mut self, event: &DetectionEvent) -> Option<AggregatedAlert> {
        let now = Utc::now();

        // Periodic cleanup
        if now - self.last_cleanup > chrono::Duration::seconds(60) {
            self.cleanup();
            self.last_cleanup = now;
        }

        let key = AggregationKey::from_event(event);

        // Check if we have an existing bucket
        if let Some(agg) = self.buckets.get_mut(&key) {
            // Check if still within window
            let window_chrono = chrono::Duration::from_std(self.window)
                .unwrap_or(chrono::Duration::seconds(300));

            if now - agg.last_seen < window_chrono {
                agg.add(event);

                // Only report as aggregated if we've reached threshold
                if agg.count >= self.min_count {
                    return Some(agg.clone());
                }
                return None;
            }
        }

        // New bucket or window expired
        self.buckets.insert(key, AggregatedAlert::new(event.clone()));
        None
    }

    /// Get aggregation stats
    pub fn get_aggregated(&self) -> Vec<&AggregatedAlert> {
        self.buckets
            .values()
            .filter(|a| a.count >= self.min_count)
            .collect()
    }

    /// Cleanup old buckets
    fn cleanup(&mut self) {
        let now = Utc::now();
        let window_chrono = chrono::Duration::from_std(self.window)
            .unwrap_or(chrono::Duration::seconds(300));

        self.buckets.retain(|_, agg| now - agg.last_seen < window_chrono * 2);
    }

    /// Get number of active buckets
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Clear all buckets
    pub fn clear(&mut self) {
        self.buckets.clear();
    }
}

impl Default for Aggregator {
    fn default() -> Self {
        Self::new(5, Duration::from_secs(300))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event() -> DetectionEvent {
        DetectionEvent::new(
            DetectionType::PortScan,
            Severity::Low,
            "192.168.1.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "Test event".to_string(),
        )
        .with_ports(12345, 22)
    }

    #[test]
    fn test_aggregator_creation() {
        let agg = Aggregator::default();
        assert_eq!(agg.bucket_count(), 0);
    }

    #[test]
    fn test_aggregation() {
        let mut agg = Aggregator::new(3, Duration::from_secs(60));

        let event = make_event();

        // First few events should not trigger aggregation
        assert!(agg.try_aggregate(&event).is_none());
        assert!(agg.try_aggregate(&event).is_none());

        // Third event should trigger aggregation
        assert!(agg.try_aggregate(&event).is_some());
    }

    #[test]
    fn test_different_events_not_aggregated() {
        let mut agg = Aggregator::new(2, Duration::from_secs(60));

        let event1 = make_event();
        let event2 = DetectionEvent::new(
            DetectionType::PortScan,
            Severity::Low,
            "10.0.0.2".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            "Test event".to_string(),
        );

        agg.try_aggregate(&event1);
        agg.try_aggregate(&event2);

        // Different source IPs should create different buckets
        assert_eq!(agg.bucket_count(), 2);
    }

    #[test]
    fn test_aggregated_alert_rate() {
        let event = make_event();
        let mut agg = AggregatedAlert::new(event.clone());

        // Add some events
        for _ in 0..10 {
            agg.add(&event);
        }

        assert_eq!(agg.count, 11);
        assert!(agg.rate() > 0.0);
    }
}
