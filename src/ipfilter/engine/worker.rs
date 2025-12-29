//! Worker module for packet analysis
//!
//! Provides packet analysis and IP filtering decisions using crmonban-types.
//! Implements the `StageProcessor` trait for pipeline integration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{
    DetectionAction, DetectionEvent, DetectionType, Packet, PacketAnalysis, Severity,
    StageProcessor,
};

use super::super::filter::{GeoIpFilter, IpFilter, IpStatus};

/// Verdict returned after analyzing a packet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketVerdict {
    /// Allow the packet through
    Allow,
    /// Block the packet
    Block,
    /// Allow but flag for monitoring
    Watch,
    /// Drop silently (for stealth blocking)
    Drop,
}

/// Analysis result containing verdict and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// The verdict for this packet
    pub verdict: PacketVerdict,
    /// Status of the source IP
    pub src_status: IpStatus,
    /// Status of the destination IP
    pub dst_status: IpStatus,
    /// Country code of source IP (if GeoIP available)
    pub src_country: Option<String>,
    /// Country code of destination IP (if GeoIP available)
    pub dst_country: Option<String>,
    /// Reason for the verdict
    pub reason: String,
    /// Processing timestamp
    pub processed_at: DateTime<Utc>,
    /// Detection events generated during analysis
    #[serde(default)]
    pub events: Vec<DetectionEvent>,
}

/// Configuration for the IP filter stage
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpFilterConfig {
    /// Block packets from watched IPs (vs just logging)
    pub block_watched: bool,
    /// Enable GeoIP-based filtering
    pub geoip_enabled: bool,
}

/// Pipeline stage identifier for the IP filter
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IpFilterStage {
    /// IP address filtering stage
    IpFilter,
}

/// Worker that processes packets through the filter chain
pub struct Worker {
    ip_filter: IpFilter,
    geoip_filter: Option<GeoIpFilter>,
    /// Block packets from watched IPs (vs just logging)
    block_watched: bool,
}

impl Worker {
    /// Create a new worker with the given IP filter
    pub fn new(ip_filter: IpFilter) -> Self {
        Self {
            ip_filter,
            geoip_filter: None,
            block_watched: false,
        }
    }

    /// Add GeoIP filtering capability
    pub fn with_geoip(mut self, geoip: GeoIpFilter) -> Self {
        self.geoip_filter = Some(geoip);
        self
    }

    /// Set whether watched IPs should be blocked
    pub fn block_watched(mut self, block: bool) -> Self {
        self.block_watched = block;
        self
    }

    /// Analyze a packet and return a verdict
    pub fn analyze(&self, packet: &Packet) -> AnalysisResult {
        let src_ip = packet.src_ip();
        let dst_ip = packet.dst_ip();

        let src_status = self.ip_filter.check(&src_ip);
        let dst_status = self.ip_filter.check(&dst_ip);

        let src_country = self.geoip_filter.as_ref().and_then(|g| g.lookup_country(&src_ip));
        let dst_country = self.geoip_filter.as_ref().and_then(|g| g.lookup_country(&dst_ip));

        // Check GeoIP blocking
        let src_geo_blocked = self
            .geoip_filter
            .as_ref()
            .map(|g| g.is_blocked(&src_ip))
            .unwrap_or(false);
        let dst_geo_blocked = self
            .geoip_filter
            .as_ref()
            .map(|g| g.is_blocked(&dst_ip))
            .unwrap_or(false);

        let (verdict, reason) = self.determine_verdict(
            &src_status,
            &dst_status,
            src_geo_blocked,
            dst_geo_blocked,
            &src_country,
            &dst_country,
        );

        AnalysisResult {
            verdict,
            src_status,
            dst_status,
            src_country,
            dst_country,
            reason,
            processed_at: Utc::now(),
            events: Vec::new(),
        }
    }

    fn determine_verdict(
        &self,
        src_status: &IpStatus,
        dst_status: &IpStatus,
        src_geo_blocked: bool,
        dst_geo_blocked: bool,
        src_country: &Option<String>,
        dst_country: &Option<String>,
    ) -> (PacketVerdict, String) {
        // Priority 1: Blocked IPs
        if matches!(src_status, IpStatus::Blocked { .. }) {
            return (
                PacketVerdict::Block,
                format!("Source IP is blocked: {:?}", src_status),
            );
        }
        if matches!(dst_status, IpStatus::Blocked { .. }) {
            return (
                PacketVerdict::Block,
                format!("Destination IP is blocked: {:?}", dst_status),
            );
        }

        // Priority 2: GeoIP blocking
        if src_geo_blocked {
            return (
                PacketVerdict::Block,
                format!(
                    "Source country blocked: {}",
                    src_country.as_deref().unwrap_or("unknown")
                ),
            );
        }
        if dst_geo_blocked {
            return (
                PacketVerdict::Block,
                format!(
                    "Destination country blocked: {}",
                    dst_country.as_deref().unwrap_or("unknown")
                ),
            );
        }

        // Priority 3: Watch list
        if matches!(src_status, IpStatus::Watch { .. }) || matches!(dst_status, IpStatus::Watch { .. })
        {
            if self.block_watched {
                return (
                    PacketVerdict::Block,
                    "IP on watch list (blocking enabled)".to_string(),
                );
            }
            return (PacketVerdict::Watch, "IP on watch list".to_string());
        }

        // Priority 4: Clean/Unknown - allow
        (PacketVerdict::Allow, "No restrictions".to_string())
    }

    /// Get a reference to the IP filter
    pub fn ip_filter(&self) -> &IpFilter {
        &self.ip_filter
    }

    /// Get a mutable reference to the IP filter
    pub fn ip_filter_mut(&mut self) -> &mut IpFilter {
        &mut self.ip_filter
    }

    /// Get a reference to the GeoIP filter (if configured)
    pub fn geoip_filter(&self) -> Option<&GeoIpFilter> {
        self.geoip_filter.as_ref()
    }

    /// Get a mutable reference to the GeoIP filter (if configured)
    pub fn geoip_filter_mut(&mut self) -> Option<&mut GeoIpFilter> {
        self.geoip_filter.as_mut()
    }

    /// Set the GeoIP filter
    pub fn set_geoip(&mut self, geoip: GeoIpFilter) {
        self.geoip_filter = Some(geoip);
    }

    /// Process a packet analysis and generate detection events
    ///
    /// This is the core logic used by both `analyze()` and the `StageProcessor` impl.
    fn process_analysis(&mut self, analysis: &mut PacketAnalysis, config: &IpFilterConfig) {
        let src_ip = analysis.packet.src_ip();
        let dst_ip = analysis.packet.dst_ip();

        let src_status = self.ip_filter.check(&src_ip);
        let dst_status = self.ip_filter.check(&dst_ip);

        // Check for blocked source IP
        if let IpStatus::Blocked { reason, .. } = &src_status {
            analysis.add_event(DetectionEvent::new(
                DetectionType::MaliciousIp,
                Severity::High,
                src_ip,
                dst_ip,
                format!("Source IP blocked: {}", reason),
            ).with_action(DetectionAction::Drop));
            analysis.stop();
            return;
        }

        // Check for blocked destination IP
        if let IpStatus::Blocked { reason, .. } = &dst_status {
            analysis.add_event(DetectionEvent::new(
                DetectionType::MaliciousIp,
                Severity::High,
                src_ip,
                dst_ip,
                format!("Destination IP blocked: {}", reason),
            ).with_action(DetectionAction::Drop));
            analysis.stop();
            return;
        }

        // Check GeoIP blocking if enabled
        if config.geoip_enabled {
            if let Some(ref geoip) = self.geoip_filter {
                if geoip.is_blocked(&src_ip) {
                    let country = geoip.lookup_country(&src_ip).unwrap_or_default();
                    analysis.add_event(DetectionEvent::new(
                        DetectionType::PolicyViolation,
                        Severity::Medium,
                        src_ip,
                        dst_ip,
                        format!("Source country blocked: {}", country),
                    ).with_action(DetectionAction::Drop));
                    analysis.stop();
                    return;
                }

                if geoip.is_blocked(&dst_ip) {
                    let country = geoip.lookup_country(&dst_ip).unwrap_or_default();
                    analysis.add_event(DetectionEvent::new(
                        DetectionType::PolicyViolation,
                        Severity::Medium,
                        src_ip,
                        dst_ip,
                        format!("Destination country blocked: {}", country),
                    ).with_action(DetectionAction::Drop));
                    analysis.stop();
                    return;
                }
            }
        }

        // Check watch list
        if let IpStatus::Watch { reason, .. } = &src_status {
            self.ip_filter.record_hit(&src_ip);
            let action = if config.block_watched {
                DetectionAction::Drop
            } else {
                DetectionAction::Log
            };
            analysis.add_event(DetectionEvent::new(
                DetectionType::ThreatIntelMatch,
                Severity::Low,
                src_ip,
                dst_ip,
                format!("Source IP on watch list: {}", reason),
            ).with_action(action));

            if config.block_watched {
                analysis.stop();
                return;
            }
        }

        if let IpStatus::Watch { reason, .. } = &dst_status {
            self.ip_filter.record_hit(&dst_ip);
            let action = if config.block_watched {
                DetectionAction::Drop
            } else {
                DetectionAction::Log
            };
            analysis.add_event(DetectionEvent::new(
                DetectionType::ThreatIntelMatch,
                Severity::Low,
                src_ip,
                dst_ip,
                format!("Destination IP on watch list: {}", reason),
            ).with_action(action));

            if config.block_watched {
                analysis.stop();
            }
        }
    }
}

impl StageProcessor<IpFilterConfig, IpFilterStage> for Worker {
    /// Process the packet analysis through the IP filter stage
    ///
    /// Checks source and destination IPs against:
    /// - Blocked IP list
    /// - GeoIP country blocks (if enabled)
    /// - Watch list
    ///
    /// Adds detection events and sets control flags as appropriate.
    async fn process(
        &mut self,
        mut analysis: PacketAnalysis,
        config: &IpFilterConfig,
    ) -> PacketAnalysis {
        self.process_analysis(&mut analysis, config);
        analysis
    }

    /// Returns the pipeline stage type for this processor
    async fn stage(&self) -> IpFilterStage {
        IpFilterStage::IpFilter
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::types::IpProtocol;

    #[test]
    fn test_packet_creation() {
        let mut packet = Packet::new(
            0,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpProtocol::Tcp,
            "",
        );
        if let Some(tcp) = packet.tcp_mut() {
            tcp.src_port = 12345;
            tcp.dst_port = 443;
        }

        assert_eq!(packet.src_port(), 12345);
        assert_eq!(packet.dst_port(), 443);
    }

    #[test]
    fn test_clean_packet_allowed() {
        let filter = IpFilter::new();
        let worker = Worker::new(filter);

        let packet = Packet::new(
            0,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpProtocol::Tcp,
            "",
        );

        let result = worker.analyze(&packet);
        assert_eq!(result.verdict, PacketVerdict::Allow);
    }

    #[test]
    fn test_blocked_ip() {
        let mut filter = IpFilter::new();
        filter.block(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            "Test block".to_string(),
        );

        let worker = Worker::new(filter);
        let packet = Packet::new(
            0,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpProtocol::Tcp,
            "",
        );

        let result = worker.analyze(&packet);
        assert_eq!(result.verdict, PacketVerdict::Block);
    }

    #[test]
    fn test_watched_ip() {
        let mut filter = IpFilter::new();
        filter.watch(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
            "Suspicious activity".to_string(),
        );

        let worker = Worker::new(filter);
        let packet = Packet::new(
            0,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpProtocol::Udp,
            "",
        );

        let result = worker.analyze(&packet);
        assert_eq!(result.verdict, PacketVerdict::Watch);
    }
}
