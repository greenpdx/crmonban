use super::aggregator::{AggregatedWindow, Aggregator};
use super::config::Config;
use super::error::Result;
use super::output::OutputHandler;
use super::session::{SessionEvent, SessionTracker};
use super::store::{BaselineStore, SignatureStore};
use super::types::{
    DetectorConfig, DetectorStage, DetectorStageConfig, FeatureVector, ScanType,
    SignatureUpdate, SignatureUpdateSender, ThreatType,
};
use super::weights::DetectionWeights;
use crate::types::{
    DetectionAction, DetectionEvent, DetectionType, Severity,
    Packet, PacketAnalysis, StageProcessor,
};
use crate::types::event::{
    DetectionSubType, ScanSubType, DosSubType, AnomalySubType, CustomSubType,
};
use std::net::IpAddr;
use std::future::Future;
use std::path::Path;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};

pub struct Detector {
    config: DetectorConfig,
    signature_store: SignatureStore,
    baseline_store: BaselineStore,
    aggregator: Aggregator,
    session_tracker: SessionTracker,
    output: OutputHandler,
    /// Receiver for real-time signature updates
    update_rx: Option<mpsc::Receiver<SignatureUpdate>>,
    /// Detection weights for heuristic analysis
    weights: DetectionWeights,
}

impl Detector {
    pub fn builder() -> DetectorBuilder {
        DetectorBuilder::new()
    }

    /// Process a PacketAnalysis through the detection pipeline
    ///
    /// Adds detection events to the analysis via `analysis.add_event()`.
    /// Use `analysis.control.stop_processing` to check if further stages should be skipped.
    pub async fn process(&mut self, analysis: &mut PacketAnalysis) {
        // Track TCP sessions
        let session_events = self.session_tracker.process_packet(&analysis.packet);
        for event in session_events {
            self.handle_session_event(event).await;
        }

        // Aggregate for window-based analysis
        // Clone packet since aggregator takes ownership
        if let Some(window) = self.aggregator.add_packet(analysis.packet.clone()) {
            let detections = self.analyze_window_collect(window).await;
            for detection in detections {
                analysis.add_event(detection);
            }
        }
    }

    async fn handle_session_event(&mut self, event: SessionEvent) {
        match event {
            SessionEvent::TlsClientHello { sni } => {
                // Could emit event for TLS connection tracking
                let _ = sni;
            }
            SessionEvent::Reset => {
                // Connection reset - could indicate blocked port or firewall
            }
            _ => {}
        }
    }

    pub async fn flush(&mut self) -> Result<()> {
        let windows = self.aggregator.flush();
        for window in windows {
            self.analyze_window(window).await?;
        }
        Ok(())
    }

    pub async fn flush_expired(&mut self, current_time_ns: u64) -> Result<()> {
        let windows = self.aggregator.flush_expired(current_time_ns);
        for window in windows {
            self.analyze_window(window).await?;
        }
        Ok(())
    }

    /// Analyze a window and collect detection events (for process())
    async fn analyze_window_collect(&mut self, window: AggregatedWindow) -> Vec<DetectionEvent> {
        // Process any pending signature updates before analysis
        let _ = self.process_updates();

        let mut detections = Vec::new();
        let mut signature_detected = false;

        // Use a placeholder dst_ip for window-based detections (source is attacking multiple targets)
        let placeholder_dst = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

        // Check for signature matches
        if self.config.scan_detection || self.config.bruteforce_detection {
            if let Ok(Some(sig_match)) = self
                .signature_store
                .match_signature(&window.vector, self.config.signature_threshold)
            {
                let threat_type = classify_threat(&window.vector, sig_match.label.as_deref());
                let (event_type, subtype) = threat_to_detection(&threat_type);
                let severity = threat_to_severity(&threat_type);
                let message = format_threat_message(&threat_type, sig_match.label.as_deref());

                let action = threat_to_action(&threat_type);
                let event = DetectionEvent::new(
                    event_type,
                    severity,
                    window.src_ip,
                    placeholder_dst,
                    message,
                )
                .with_detector("layer2detect")
                .with_subtype(subtype)
                .with_action(action)
                .with_confidence(1.0 - sig_match.distance)
                .with_feature_array(window.vector);

                // Add rule name if available
                let event = if let Some(ref name) = sig_match.label {
                    event.with_rule(0, Some(name))
                } else {
                    event
                };

                detections.push(event);
                signature_detected = true;
            }
        }

        // Heuristic-based detection (if no signature matched)
        if !signature_detected && self.config.scan_detection {
            if let Some(threat_type) = heuristic_detect(&window.vector, &self.weights) {
                let (event_type, subtype) = threat_to_detection(&threat_type);
                let severity = threat_to_severity(&threat_type);
                let message = format_threat_message(&threat_type, None);
                let action = threat_to_action(&threat_type);

                let event = DetectionEvent::new(
                    event_type,
                    severity,
                    window.src_ip,
                    placeholder_dst,
                    message,
                )
                .with_detector("layer2detect")
                .with_subtype(subtype)
                .with_action(action)
                .with_confidence(0.7)
                .with_feature_array(window.vector);

                detections.push(event);
            }
        }

        // Check for anomalies
        if self.config.anomaly_detection && !self.baseline_store.is_empty() {
            if let Ok((true, distance)) = self
                .baseline_store
                .is_anomaly(&window.vector, self.config.anomaly_threshold)
            {
                let event = DetectionEvent::new(
                    DetectionType::AnomalyDetection,
                    Severity::Medium,
                    window.src_ip,
                    placeholder_dst,
                    format!("Anomaly detected with deviation score {:.2}", distance),
                )
                .with_detector("layer2detect")
                .with_subtype(DetectionSubType::Anomaly(AnomalySubType::BehaviorAnomaly))
                .with_action(DetectionAction::Alert) // Anomalies are informational
                .with_confidence(distance.min(1.0))
                .with_feature_array(window.vector)
                .with_detail("deviation_score", serde_json::json!(distance));

                detections.push(event);
            }
        }

        detections
    }

    /// Analyze a window and emit events to output (for flush())
    async fn analyze_window(&mut self, window: AggregatedWindow) -> Result<()> {
        let detections = self.analyze_window_collect(window).await;
        for event in detections {
            self.output.emit(event).await;
        }
        Ok(())
    }

    pub fn add_signature(&mut self, vector: &FeatureVector, name: String) -> Result<u64> {
        self.signature_store.add_signature(vector, name)
    }

    pub fn add_baseline(&mut self, vector: &FeatureVector) -> Result<u64> {
        self.baseline_store.add_baseline(vector)
    }

    pub async fn train_baseline<I>(&mut self, packets: I) -> Result<()>
    where
        I: IntoIterator<Item = Packet>,
    {
        let mut training_agg = Aggregator::new(self.config.window_size_ms, 1);

        for packet in packets {
            if let Some(window) = training_agg.add_packet(packet) {
                self.baseline_store.add_baseline(&window.vector)?;
            }
        }

        // Flush remaining
        for window in training_agg.flush() {
            self.baseline_store.add_baseline(&window.vector)?;
        }

        Ok(())
    }

    pub fn on_detection<F, Fut>(&mut self, callback: F)
    where
        F: Fn(DetectionEvent) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.output.add_callback(callback);
    }

    pub fn detection_stream(&self) -> broadcast::Receiver<DetectionEvent> {
        self.output.subscribe()
    }

    pub fn signature_count(&self) -> usize {
        self.signature_store.len()
    }

    pub fn baseline_count(&self) -> usize {
        self.baseline_store.len()
    }

    pub fn pending_packets(&self) -> usize {
        self.aggregator.total_packets()
    }

    pub fn active_windows(&self) -> usize {
        self.aggregator.window_count()
    }

    /// Process any pending signature updates from the update channel
    ///
    /// Returns the number of updates processed. Call this periodically
    /// or before analyzing each window to apply pending updates.
    pub fn process_updates(&mut self) -> Result<usize> {
        let rx = match &mut self.update_rx {
            Some(rx) => rx,
            None => return Ok(0),
        };

        let mut count = 0;
        while let Ok(update) = rx.try_recv() {
            match update {
                SignatureUpdate::Add { name, vector } => {
                    self.signature_store.add_signature(&vector, name)?;
                    count += 1;
                }
                SignatureUpdate::Disable { name } => {
                    self.signature_store.disable_signature(&name)?;
                    count += 1;
                }
                SignatureUpdate::Enable { name } => {
                    self.signature_store.enable_signature(&name)?;
                    count += 1;
                }
            }
        }

        Ok(count)
    }

    /// Disable a signature by name
    pub fn disable_signature(&self, name: &str) -> Result<()> {
        self.signature_store.disable_signature(name)
    }

    /// Enable a previously disabled signature
    pub fn enable_signature(&self, name: &str) -> Result<()> {
        self.signature_store.enable_signature(name)
    }

    /// Check if a signature is disabled
    pub fn is_signature_disabled(&self, name: &str) -> Result<bool> {
        self.signature_store.is_disabled(name)
    }

    /// Get list of all signature names
    pub fn signature_names(&self) -> Vec<String> {
        self.signature_store.signature_names()
    }

    /// Get count of active (non-disabled) signatures
    pub fn active_signature_count(&self) -> usize {
        self.signature_store.active_count()
    }

    /// Get reference to detection weights
    pub fn weights(&self) -> &DetectionWeights {
        &self.weights
    }

    /// Get mutable reference to detection weights
    pub fn weights_mut(&mut self) -> &mut DetectionWeights {
        &mut self.weights
    }

    /// Save detection weights to a TOML file
    pub fn save_weights<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.weights.save(path).map_err(|e| {
            super::error::NetVecError::ConfigError(format!("Failed to save weights: {}", e))
        })
    }

    /// Load detection weights from a TOML file
    pub fn load_weights<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let weights = DetectionWeights::from_file(path).map_err(|e| {
            super::error::NetVecError::ConfigError(format!("Failed to load weights: {}", e))
        })?;
        self.weights = weights;
        Ok(())
    }
}

/// Implementation of the pipeline StageProcessor trait for Detector
impl StageProcessor<DetectorStageConfig, DetectorStage> for Detector {
    async fn process(&mut self, mut analysis: PacketAnalysis, _config: &DetectorStageConfig) -> PacketAnalysis {
        // Track TCP sessions
        let session_events = self.session_tracker.process_packet(&analysis.packet);
        for event in session_events {
            self.handle_session_event(event).await;
        }

        // Aggregate for window-based analysis
        // Clone packet since aggregator takes ownership
        if let Some(window) = self.aggregator.add_packet(analysis.packet.clone()) {
            let detections = self.analyze_window_collect(window).await;
            for detection in detections {
                analysis.add_event(detection);
            }
        }

        analysis
    }

    async fn stage(&self) -> DetectorStage {
        DetectorStage::ThreatDetection
    }
}

pub struct DetectorBuilder {
    config: DetectorConfig,
    signature_path: Option<String>,
    baseline_path: Option<String>,
    signature_capacity: usize,
    baseline_capacity: usize,
    max_sessions: usize,
    auth_ports: Option<Vec<u16>>,
    /// Channel size for signature updates (None = no update channel)
    update_channel_size: Option<usize>,
    /// Detection weights for heuristic analysis
    weights: DetectionWeights,
}

impl DetectorBuilder {
    pub fn new() -> Self {
        Self {
            config: DetectorConfig::default(),
            signature_path: None,
            baseline_path: None,
            signature_capacity: 10_000,
            baseline_capacity: 100_000,
            max_sessions: 100_000,
            auth_ports: None,
            update_channel_size: None,
            weights: DetectionWeights::default(),
        }
    }

    /// Set custom detection weights
    pub fn with_weights(mut self, weights: DetectionWeights) -> Self {
        self.weights = weights;
        self
    }

    /// Enable real-time signature updates via a channel
    ///
    /// The `channel_size` parameter controls the buffer size of the mpsc channel.
    /// Use `build_with_updates()` to get both the detector and the sender handle.
    pub fn with_signature_updates(mut self, channel_size: usize) -> Self {
        self.update_channel_size = Some(channel_size);
        self
    }

    pub fn with_auth_ports(mut self, ports: Vec<u16>) -> Self {
        self.auth_ports = Some(ports);
        self
    }

    pub fn with_max_sessions(mut self, max: usize) -> Self {
        self.max_sessions = max;
        self
    }

    pub fn with_scan_detection(mut self, enabled: bool) -> Self {
        self.config.scan_detection = enabled;
        self
    }

    pub fn with_bruteforce_detection(mut self, enabled: bool) -> Self {
        self.config.bruteforce_detection = enabled;
        self
    }

    pub fn with_anomaly_detection(mut self, enabled: bool) -> Self {
        self.config.anomaly_detection = enabled;
        self
    }

    pub fn with_anomaly_threshold(mut self, threshold: f32) -> Self {
        self.config.anomaly_threshold = threshold;
        self
    }

    /// Enable or disable DoS attack detection
    pub fn with_dos_detection(mut self, enabled: bool) -> Self {
        self.config.dos_detection = enabled;
        self
    }

    /// Set DoS detection thresholds
    ///
    /// # Arguments
    /// * `min_packet_rate` - Minimum normalized packet rate (0.1 = 10,000 pps)
    /// * `half_open_threshold` - Half-open ratio threshold for SYN flood (default 0.7)
    pub fn with_dos_thresholds(mut self, min_packet_rate: f32, half_open_threshold: f32) -> Self {
        self.config.dos_min_packet_rate = min_packet_rate;
        self.config.dos_half_open_threshold = half_open_threshold;
        self
    }

    pub fn with_signature_threshold(mut self, threshold: f32) -> Self {
        self.config.signature_threshold = threshold;
        self
    }

    pub fn with_window_size(mut self, duration: Duration) -> Self {
        self.config.window_size_ms = duration.as_millis() as u64;
        self
    }

    pub fn with_min_packets(mut self, min: usize) -> Self {
        self.config.min_packets_for_detection = min;
        self
    }

    pub fn with_signature_persistence<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.signature_path = Some(path.as_ref().to_string_lossy().to_string());
        self
    }

    pub fn with_baseline_persistence<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.baseline_path = Some(path.as_ref().to_string_lossy().to_string());
        self
    }

    pub fn with_signature_capacity(mut self, capacity: usize) -> Self {
        self.signature_capacity = capacity;
        self
    }

    pub fn with_baseline_capacity(mut self, capacity: usize) -> Self {
        self.baseline_capacity = capacity;
        self
    }

    pub fn build(self) -> Result<Detector> {
        let signature_store = match &self.signature_path {
            Some(path) => SignatureStore::with_persistence(path, self.signature_capacity)?,
            None => SignatureStore::new(self.signature_capacity)?,
        };

        let baseline_store = match &self.baseline_path {
            Some(path) => BaselineStore::with_persistence(path, self.baseline_capacity)?,
            None => BaselineStore::new(self.baseline_capacity)?,
        };

        let aggregator = match self.auth_ports {
            Some(ports) => Aggregator::with_auth_ports(
                self.config.window_size_ms,
                self.config.min_packets_for_detection,
                ports,
            ),
            None => Aggregator::new(
                self.config.window_size_ms,
                self.config.min_packets_for_detection,
            ),
        };

        Ok(Detector {
            config: self.config,
            signature_store,
            baseline_store,
            aggregator,
            session_tracker: SessionTracker::new(self.max_sessions),
            output: OutputHandler::default(),
            update_rx: None,
            weights: self.weights.clone(),
        })
    }

    /// Build detector with a signature update channel
    ///
    /// Returns the detector and a sender handle for pushing signature updates.
    /// The sender is Clone and can be shared across multiple tasks.
    ///
    /// # Example
    /// ```ignore
    /// let (mut detector, update_sender) = Detector::builder()
    ///     .with_signature_updates(100)
    ///     .build_with_updates()?;
    ///
    /// // Clone sender for external task
    /// let sender = update_sender.clone();
    /// tokio::spawn(async move {
    ///     sender.send(SignatureUpdate::Add {
    ///         name: "new_attack".to_string(),
    ///         vector: attack_vector,
    ///     }).await.unwrap();
    /// });
    /// ```
    pub fn build_with_updates(self) -> Result<(Detector, SignatureUpdateSender)> {
        let channel_size = self.update_channel_size.unwrap_or(100);
        let (tx, rx) = mpsc::channel(channel_size);

        let signature_store = match &self.signature_path {
            Some(path) => SignatureStore::with_persistence(path, self.signature_capacity)?,
            None => SignatureStore::new(self.signature_capacity)?,
        };

        let baseline_store = match &self.baseline_path {
            Some(path) => BaselineStore::with_persistence(path, self.baseline_capacity)?,
            None => BaselineStore::new(self.baseline_capacity)?,
        };

        let aggregator = match self.auth_ports.clone() {
            Some(ports) => Aggregator::with_auth_ports(
                self.config.window_size_ms,
                self.config.min_packets_for_detection,
                ports,
            ),
            None => Aggregator::new(
                self.config.window_size_ms,
                self.config.min_packets_for_detection,
            ),
        };

        let detector = Detector {
            config: self.config,
            signature_store,
            baseline_store,
            aggregator,
            session_tracker: SessionTracker::new(self.max_sessions),
            output: OutputHandler::default(),
            update_rx: Some(rx),
            weights: self.weights.clone(),
        };

        Ok((detector, SignatureUpdateSender::new(tx)))
    }
}

impl Default for DetectorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectorBuilder {
    /// Create a DetectorBuilder from a Config object
    pub fn from_config(config: &Config) -> Self {
        Self {
            config: DetectorConfig {
                scan_detection: config.detector.scan_detection,
                bruteforce_detection: config.detector.brute_force_detection,
                anomaly_detection: config.detector.anomaly_detection,
                dos_detection: config.detector.dos_detection,
                anomaly_threshold: config.anomaly.threshold,
                signature_threshold: config.scan.signature_threshold,
                window_size_ms: config.detector.window_size_ms,
                min_packets_for_detection: config.detector.min_packets,
                dos_min_packet_rate: config.dos.min_packet_rate,
                dos_half_open_threshold: config.dos.half_open_threshold,
                // Layer 2 detection (default enabled)
                arp_detection: true,
                dhcp_detection: true,
                vlan_detection: true,
                // Layer 3 detection (default enabled)
                icmp_tunnel_detection: true,
                ipv6_ra_detection: true,
            },
            signature_path: config.performance.signature_path.clone(),
            baseline_path: config.performance.baseline_path.clone(),
            signature_capacity: config.performance.signature_capacity,
            baseline_capacity: config.performance.baseline_capacity,
            max_sessions: config.performance.max_sessions,
            auth_ports: Some(config.brute_force.auth_ports.clone()),
            update_channel_size: None,
            weights: DetectionWeights::default(),
        }
    }

    /// Set weights file path to load from
    pub fn with_weights_file<P: AsRef<Path>>(mut self, path: P) -> Result<Self> {
        self.weights = DetectionWeights::from_file(path).map_err(|e| {
            super::error::NetVecError::ConfigError(format!("Failed to load weights: {}", e))
        })?;
        Ok(self)
    }

    /// Load configuration from a TOML file and create a DetectorBuilder
    pub fn from_config_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config = Config::from_file(path)?;
        Ok(Self::from_config(&config))
    }

    /// Build a Detector with signatures loaded from Config
    pub fn build_with_config(self, config: &Config) -> Result<Detector> {
        let mut detector = self.build()?;

        // Load signatures from config
        for sig in &config.signatures {
            if sig.enabled {
                let vector = sig.to_vector();
                detector.add_signature(&vector, sig.name.clone())?;
            }
        }

        Ok(detector)
    }
}

/// Heuristic-based detection that returns Some(ThreatType) if an attack is detected,
/// or None if the traffic appears normal. This is used when no signature matches.
fn heuristic_detect(vector: &FeatureVector, weights: &DetectionWeights) -> Option<ThreatType> {
    // Protocol-agnostic features (0-11)
    let unique_port_ratio = vector[1];
    let unique_dst_ips = vector[8];

    // TCP features (12-23)
    let syn_ratio = vector[12];
    let synack_ratio = vector[13];
    let rst_ratio = vector[14];
    let half_open_ratio = vector[17];
    let handshake_complete_ratio = vector[18];
    let rst_after_syn = vector[19];
    let auth_port_ratio = vector[20];
    let single_port_concentration = vector[21];
    let xmas_indicator = vector[22];
    let null_indicator = vector[23];

    // ICMP features (36-47)
    let echo_req_ratio = vector[36];
    let ping_sweep_score = vector[40];

    // UDP features (24-35)
    let udp_unreachable_ratio = vector[25];
    let udp_other_services = vector[31];
    let amplification_factor = vector[34];

    // DoS features (64-71)
    let packets_per_sec = vector[64];
    let bytes_per_sec = vector[65];
    let conn_rate = vector[66];
    let half_open_flood = vector[67];
    let tcp_flood_score = vector[68];
    let udp_flood_score = vector[69];
    let icmp_flood_score = vector[70];
    let exhaustion_score = vector[71];

    let w = weights; // Shorthand

    // === SCAN vs DoS DIFFERENTIATION ===
    // Key insight: Scans target MANY ports, DoS targets FEW ports
    // Check for scans FIRST when unique_port_ratio is high

    // SYN scan - high SYN ratio + many unique ports = scan, not flood
    if syn_ratio > w.syn_scan.syn_ratio_min
        && synack_ratio < w.syn_scan.synack_ratio_max
        && unique_port_ratio > w.syn_scan.unique_port_ratio_min
    {
        return Some(ThreatType::PortScan {
            scan_type: ScanType::TcpSyn,
            ports_touched: estimate_ports_touched(vector),
        });
    }

    // === DoS DETECTION (only when few unique ports - not a scan) ===

    // SYN Flood
    if packets_per_sec > w.syn_flood.packets_per_sec_min
        && syn_ratio > w.syn_flood.syn_ratio_min
        && synack_ratio < w.syn_flood.synack_ratio_max
        && half_open_flood > w.syn_flood.half_open_flood_min
    {
        if unique_port_ratio < w.syn_flood.unique_port_ratio_max {
            return Some(ThreatType::SynFlood {
                packets_per_sec: packets_per_sec * 100_000.0,
                half_open_connections: (half_open_flood * 10_000.0) as u32,
            });
        }
    }

    if tcp_flood_score > w.syn_flood.tcp_flood_score_min
        && unique_port_ratio < w.syn_flood.unique_port_ratio_max
    {
        return Some(ThreatType::SynFlood {
            packets_per_sec: packets_per_sec * 100_000.0,
            half_open_connections: (half_open_flood * 10_000.0) as u32,
        });
    }

    // Connection Exhaustion
    if exhaustion_score > w.conn_exhaustion.exhaustion_score_min
        && bytes_per_sec < w.conn_exhaustion.bytes_per_sec_max
        && unique_port_ratio < w.conn_exhaustion.unique_port_ratio_max
    {
        return Some(ThreatType::ConnectionExhaustion {
            connection_rate: conn_rate * 10_000.0,
            half_open_ratio: half_open_flood.max(half_open_ratio),
        });
    }

    // UDP Flood
    if udp_flood_score > w.udp_flood.flood_score_min
        || (packets_per_sec > w.udp_flood.packets_per_sec_min
            && bytes_per_sec > w.udp_flood.bytes_per_sec_min
            && udp_other_services > w.udp_flood.other_services_min)
    {
        return Some(ThreatType::UdpFlood {
            packets_per_sec: packets_per_sec * 100_000.0,
            bytes_per_sec: bytes_per_sec * 125_000_000.0,
        });
    }

    // ICMP Flood
    if icmp_flood_score > w.icmp_flood.flood_score_min
        || (packets_per_sec > w.icmp_flood.packets_per_sec_min
            && echo_req_ratio > w.icmp_flood.echo_req_ratio_min
            && unique_dst_ips < w.icmp_flood.unique_dst_ips_max)
    {
        return Some(ThreatType::IcmpFlood {
            packets_per_sec: packets_per_sec * 100_000.0,
            target_ip_count: (unique_dst_ips * 100.0).max(1.0) as u32,
        });
    }

    // === SCAN DETECTION ===

    // XMAS scan
    if xmas_indicator > w.special_scans.xmas_indicator_min {
        return Some(ThreatType::PortScan {
            scan_type: ScanType::TcpXmas,
            ports_touched: estimate_ports_touched(vector),
        });
    }

    // NULL scan
    if null_indicator > w.special_scans.null_indicator_min {
        return Some(ThreatType::PortScan {
            scan_type: ScanType::TcpNull,
            ports_touched: estimate_ports_touched(vector),
        });
    }

    // Brute force (check before connect scan due to overlapping patterns)
    if auth_port_ratio > w.brute_force.auth_port_ratio_min
        && single_port_concentration > w.brute_force.single_port_concentration_min
        && handshake_complete_ratio > w.brute_force.handshake_complete_ratio_min
        && unique_port_ratio < w.brute_force.unique_port_ratio_max
    {
        return Some(ThreatType::BruteForce {
            attempts: estimate_brute_force_attempts(vector),
            target_service: extract_service_from_auth_port(vector),
        });
    }

    // SYN scan - large
    if syn_ratio > w.syn_scan.syn_ratio_min
        && synack_ratio < w.syn_scan.synack_ratio_max
        && half_open_ratio > w.syn_scan.half_open_ratio_min
    {
        return Some(ThreatType::PortScan {
            scan_type: ScanType::TcpSyn,
            ports_touched: estimate_ports_touched(vector),
        });
    }

    // SYN scan - small/targeted
    if syn_ratio > w.syn_scan.small_scan_syn_ratio_min
        && synack_ratio < w.syn_scan.synack_ratio_max
        && half_open_ratio > w.syn_scan.small_scan_half_open_min
        && unique_port_ratio > w.connect_scan.unique_port_ratio_min
    {
        return Some(ThreatType::PortScan {
            scan_type: ScanType::TcpSyn,
            ports_touched: estimate_ports_touched(vector),
        });
    }

    // Connect scan from ATTACKER perspective
    if syn_ratio > w.connect_scan.syn_ratio_min
        && syn_ratio < w.connect_scan.syn_ratio_max
        && rst_ratio > w.connect_scan.rst_ratio_min
        && rst_ratio < w.connect_scan.rst_ratio_max
        && synack_ratio < w.connect_scan.synack_ratio_max
        && rst_after_syn > w.connect_scan.rst_after_syn_min
        && unique_port_ratio > w.connect_scan.unique_port_ratio_min
    {
        return Some(ThreatType::PortScan {
            scan_type: ScanType::TcpConnect,
            ports_touched: estimate_ports_touched(vector),
        });
    }

    // Ping sweep
    if echo_req_ratio > w.ping_sweep.echo_req_ratio_min
        && ping_sweep_score > w.ping_sweep.sweep_score_min
    {
        return Some(ThreatType::PingSweep {
            hosts_probed: estimate_hosts_probed(vector),
        });
    }

    // High ICMP echo without sweep pattern = single target ping
    if echo_req_ratio > w.icmp_flood.single_target_echo_min
        && unique_dst_ips < w.icmp_flood.unique_dst_ips_max
    {
        return Some(ThreatType::IcmpFlood {
            packets_per_sec: packets_per_sec * 100_000.0,
            target_ip_count: 1,
        });
    }

    // UDP scan
    if udp_unreachable_ratio > w.udp_scan.unreachable_ratio_min {
        return Some(ThreatType::PortScan {
            scan_type: ScanType::Udp,
            ports_touched: estimate_ports_touched(vector),
        });
    }

    // Amplification attack
    if amplification_factor > w.amplification.factor_min {
        return Some(ThreatType::Amplification {
            protocol: "UDP".to_string(),
            amplification_factor: amplification_factor * 100.0,
        });
    }

    // No attack detected
    None
}

fn classify_threat(vector: &FeatureVector, label: Option<&str>) -> ThreatType {
    // Use label if available
    if let Some(l) = label {
        let lower = l.to_lowercase();

        // DoS attack labels (check first - higher priority)
        if lower.contains("syn_flood") || lower.contains("synflood") {
            return ThreatType::SynFlood {
                packets_per_sec: vector[64] * 100_000.0,
                half_open_connections: (vector[67] * 10_000.0) as u32,
            };
        }
        if lower.contains("udp_flood") || lower.contains("udpflood") {
            return ThreatType::UdpFlood {
                packets_per_sec: vector[64] * 100_000.0,
                bytes_per_sec: vector[65] * 125_000_000.0,
            };
        }
        if lower.contains("icmp_flood") || lower.contains("icmpflood") {
            return ThreatType::IcmpFlood {
                packets_per_sec: vector[64] * 100_000.0,
                target_ip_count: (vector[8] * 100.0).max(1.0) as u32,
            };
        }
        if lower.contains("connection_exhaustion") || lower.contains("exhaustion") {
            return ThreatType::ConnectionExhaustion {
                connection_rate: vector[66] * 10_000.0,
                half_open_ratio: vector[67],
            };
        }

        // Scan labels
        if lower.contains("syn") && !lower.contains("flood") {
            return ThreatType::PortScan {
                scan_type: ScanType::TcpSyn,
                ports_touched: estimate_ports_touched(vector),
            };
        }
        if lower.contains("connect") {
            return ThreatType::PortScan {
                scan_type: ScanType::TcpConnect,
                ports_touched: estimate_ports_touched(vector),
            };
        }
        if lower.contains("fin") {
            return ThreatType::PortScan {
                scan_type: ScanType::TcpFin,
                ports_touched: estimate_ports_touched(vector),
            };
        }
        if lower.contains("xmas") {
            return ThreatType::PortScan {
                scan_type: ScanType::TcpXmas,
                ports_touched: estimate_ports_touched(vector),
            };
        }
        if lower.contains("null") {
            return ThreatType::PortScan {
                scan_type: ScanType::TcpNull,
                ports_touched: estimate_ports_touched(vector),
            };
        }
        if lower.contains("udp") && !lower.contains("flood") {
            return ThreatType::PortScan {
                scan_type: ScanType::Udp,
                ports_touched: estimate_ports_touched(vector),
            };
        }
        if lower.contains("brute") || lower.contains("auth") {
            return ThreatType::BruteForce {
                attempts: 0,
                target_service: extract_service(vector),
            };
        }
        if lower.contains("ping") || lower.contains("sweep") {
            return ThreatType::PingSweep {
                hosts_probed: estimate_hosts_probed(vector),
            };
        }
        if lower.contains("amplif") {
            return ThreatType::Amplification {
                protocol: "UDP".to_string(),
                amplification_factor: vector[34] * 100.0,
            };
        }
    }

    // Heuristic classification based on vector values
    // Protocol-agnostic features (0-11)
    let unique_port_ratio = vector[1];
    let unique_dst_ips = vector[8];

    // TCP features (12-23)
    let syn_ratio = vector[12];
    let synack_ratio = vector[13];
    let rst_ratio = vector[14];
    let connection_success_rate = vector[16];
    let half_open_ratio = vector[17];
    let handshake_complete_ratio = vector[18];
    let auth_port_ratio = vector[20];
    let single_port_concentration = vector[21];
    let xmas_indicator = vector[22];
    let null_indicator = vector[23];

    // ICMP features (36-47)
    let echo_req_ratio = vector[36];
    let ping_sweep_score = vector[40];

    // UDP features (24-35)
    let udp_unreachable_ratio = vector[25];
    let udp_other_services = vector[31];
    let amplification_factor = vector[34];

    // Timing features (4-7)
    let timing_regularity = 1.0 - vector[5]; // Low variance = high regularity

    // DoS features (64-71)
    let packets_per_sec = vector[64];
    let bytes_per_sec = vector[65];
    let conn_rate = vector[66];
    let half_open_flood = vector[67];
    let tcp_flood_score = vector[68];
    let udp_flood_score = vector[69];
    let icmp_flood_score = vector[70];
    let exhaustion_score = vector[71];

    // === DoS DETECTION (check before scans - floods have priority) ===

    // SYN Flood Detection:
    // - High packet rate (> 0.1 = 10,000 pps)
    // - High SYN ratio
    // - Low SYN-ACK (no responses)
    // - Few unique ports (unlike scan which targets many ports)
    if packets_per_sec > 0.1 && syn_ratio > 0.8 && synack_ratio < 0.1 && half_open_flood > 0.7 {
        if unique_port_ratio < 0.05 {
            // Few ports = flood, many ports = scan
            return ThreatType::SynFlood {
                packets_per_sec: packets_per_sec * 100_000.0,
                half_open_connections: (half_open_flood * 10_000.0) as u32,
            };
        }
    }

    // Also detect via TCP flood score
    if tcp_flood_score > 0.6 && unique_port_ratio < 0.05 {
        return ThreatType::SynFlood {
            packets_per_sec: packets_per_sec * 100_000.0,
            half_open_connections: (half_open_flood * 10_000.0) as u32,
        };
    }

    // Connection Exhaustion:
    // Requires high exhaustion score AND low data transfer (attackers don't send data)
    if exhaustion_score > 0.5 && bytes_per_sec < 0.05 {
        return ThreatType::ConnectionExhaustion {
            connection_rate: conn_rate * 10_000.0,
            half_open_ratio: half_open_flood.max(half_open_ratio),
        };
    }

    // UDP Flood Detection:
    // - Very high packet rate
    // - Very high bytes per second
    // - Predominantly UDP traffic (high udp_other_services)
    if udp_flood_score > 0.5 || (packets_per_sec > 0.1 && bytes_per_sec > 0.1 && udp_other_services > 0.5) {
        return ThreatType::UdpFlood {
            packets_per_sec: packets_per_sec * 100_000.0,
            bytes_per_sec: bytes_per_sec * 125_000_000.0,
        };
    }

    // ICMP Flood Detection:
    // - High packet rate
    // - High ICMP echo request ratio
    // - Single target (unlike ping sweep which has many targets)
    if icmp_flood_score > 0.5 || (packets_per_sec > 0.1 && echo_req_ratio > 0.8 && unique_dst_ips < 0.1) {
        return ThreatType::IcmpFlood {
            packets_per_sec: packets_per_sec * 100_000.0,
            target_ip_count: (unique_dst_ips * 100.0).max(1.0) as u32,
        };
    }

    // === SCAN AND OTHER ATTACK DETECTION ===

    if xmas_indicator > 0.5 {
        return ThreatType::PortScan {
            scan_type: ScanType::TcpXmas,
            ports_touched: estimate_ports_touched(vector),
        };
    }

    if null_indicator > 0.5 {
        return ThreatType::PortScan {
            scan_type: ScanType::TcpNull,
            ports_touched: estimate_ports_touched(vector),
        };
    }

    // Brute force detection: high auth port ratio + single port + successful connections
    // Must check BEFORE connect scan since patterns overlap
    if auth_port_ratio > 0.5
        && single_port_concentration > 0.7
        && handshake_complete_ratio > 0.3
        && unique_port_ratio < 0.1
    {
        return ThreatType::BruteForce {
            attempts: estimate_brute_force_attempts(vector),
            target_service: extract_service_from_auth_port(vector),
        };
    }

    // Alternative brute force detection: many connections to single auth port with timing
    if auth_port_ratio > 0.8 && connection_success_rate > 0.5 && timing_regularity > 0.5 {
        return ThreatType::BruteForce {
            attempts: estimate_brute_force_attempts(vector),
            target_service: extract_service_from_auth_port(vector),
        };
    }

    // SYN scan detection - multiple conditions for different scan sizes
    // Large scan: many ports, high SYN ratio, high half-open
    if syn_ratio > 0.7 && synack_ratio < 0.1 && half_open_ratio > 0.5 {
        return ThreatType::PortScan {
            scan_type: ScanType::TcpSyn,
            ports_touched: estimate_ports_touched(vector),
        };
    }

    // Small/targeted SYN scan: fewer ports but still high SYN ratio and no responses
    // This catches scans with 50-200 ports that might not match the large scan signature
    if syn_ratio > 0.85 && synack_ratio < 0.05 && half_open_ratio > 0.8 && unique_port_ratio > 0.02 {
        return ThreatType::PortScan {
            scan_type: ScanType::TcpSyn,
            ports_touched: estimate_ports_touched(vector),
        };
    }

    // Connect scan from ATTACKER perspective:
    // - Pattern is SYN -> ACK -> RST per port (attacker doesn't send SYN-ACK)
    // - SYN ratio ~0.33 (1/3 of packets)
    // - RST ratio ~0.33 (1/3 of packets)
    // - No SYN-ACK from attacker (synack_ratio = 0)
    // - High RST-after-SYN ratio (connections with SYN+RST but no SYN-ACK)
    let rst_after_syn = vector[19]; // Index 19: RST after SYN ratio
    if syn_ratio > 0.2 && syn_ratio < 0.5  // SYN is ~1/3 of packets
        && rst_ratio > 0.2 && rst_ratio < 0.5  // RST is ~1/3 of packets
        && synack_ratio < 0.1  // Attacker doesn't send SYN-ACK
        && rst_after_syn > 0.7  // High RST-after-SYN (no SYN-ACK seen)
        && unique_port_ratio > 0.02  // Multiple ports targeted
    {
        return ThreatType::PortScan {
            scan_type: ScanType::TcpConnect,
            ports_touched: estimate_ports_touched(vector),
        };
    }

    if echo_req_ratio > 0.5 && ping_sweep_score > 0.5 {
        return ThreatType::PingSweep {
            hosts_probed: estimate_hosts_probed(vector),
        };
    }

    if udp_unreachable_ratio > 0.5 {
        return ThreatType::PortScan {
            scan_type: ScanType::Udp,
            ports_touched: estimate_ports_touched(vector),
        };
    }

    if amplification_factor > 0.3 {
        return ThreatType::Amplification {
            protocol: "UDP".to_string(),
            amplification_factor: amplification_factor * 100.0,
        };
    }

    ThreatType::PortScan {
        scan_type: ScanType::Unknown,
        ports_touched: estimate_ports_touched(vector),
    }
}

fn estimate_ports_touched(vector: &FeatureVector) -> u32 {
    // Use unique port count feature (index 1), denormalized
    (vector[1] * 1000.0) as u32
}

fn estimate_hosts_probed(vector: &FeatureVector) -> u32 {
    // Use unique destination IPs feature (index 8), denormalized
    (vector[8] * 100.0) as u32
}

fn extract_service(vector: &FeatureVector) -> String {
    // Check UDP service ratios (28-31)
    let dns_ratio = vector[28];
    let ntp_ratio = vector[29];
    let ssdp_ratio = vector[30];

    if dns_ratio > 0.5 {
        return "DNS".to_string();
    }
    if ntp_ratio > 0.5 {
        return "NTP".to_string();
    }
    if ssdp_ratio > 0.5 {
        return "SSDP".to_string();
    }

    // Could check common auth ports based on TCP patterns
    "Unknown".to_string()
}

fn estimate_brute_force_attempts(vector: &FeatureVector) -> u32 {
    // Estimate based on connection success rate and single port concentration
    // Higher concentration to single port = more attempts
    let concentration = vector[21];
    let success_rate = vector[16];

    // Base estimate on the normalized values
    // Assuming max ~1000 attempts in a window
    ((concentration * success_rate) * 500.0) as u32
}

fn extract_service_from_auth_port(vector: &FeatureVector) -> String {
    // Auth port ratio is high, try to identify the service
    // This is a heuristic based on common patterns

    // Check if it's likely SSH (most common brute force target)
    // We can't directly identify the port from features, but we can infer
    // based on the combination of TCP behavior

    let auth_port_ratio = vector[20];
    let single_port_concentration = vector[21];

    if auth_port_ratio > 0.9 && single_port_concentration > 0.9 {
        // Very concentrated on auth port - likely SSH or RDP
        return "SSH/RDP".to_string();
    }

    if auth_port_ratio > 0.5 {
        return "Auth Service".to_string();
    }

    "Unknown".to_string()
}

/// Convert internal ThreatType to crmonban-types (DetectionType, DetectionSubType)
fn threat_to_detection(threat: &ThreatType) -> (DetectionType, DetectionSubType) {
    match threat {
        ThreatType::PortScan { scan_type, .. } => {
            let subtype = match scan_type {
                ScanType::TcpSyn => ScanSubType::SynScan,
                ScanType::TcpConnect => ScanSubType::Unknown("connect".into()),
                ScanType::TcpFin => ScanSubType::FinScan,
                ScanType::TcpXmas => ScanSubType::XmasScan,
                ScanType::TcpNull => ScanSubType::NullScan,
                ScanType::Udp => ScanSubType::UdpScan,
                ScanType::Unknown => ScanSubType::Unknown(String::new()),
            };
            (DetectionType::PortScan, DetectionSubType::Scan(subtype))
        }
        ThreatType::PingSweep { .. } => {
            (DetectionType::NetworkScan, DetectionSubType::Scan(ScanSubType::PingSweep))
        }
        ThreatType::SynFlood { .. } => {
            (DetectionType::DoS, DetectionSubType::Dos(DosSubType::SynFlood))
        }
        ThreatType::UdpFlood { .. } => {
            (DetectionType::DoS, DetectionSubType::Dos(DosSubType::UdpFlood))
        }
        ThreatType::IcmpFlood { .. } => {
            (DetectionType::DoS, DetectionSubType::Dos(DosSubType::IcmpFlood))
        }
        ThreatType::ConnectionExhaustion { .. } => {
            (DetectionType::DoS, DetectionSubType::Dos(DosSubType::ConnectionExhaustion))
        }
        ThreatType::Amplification { protocol, .. } => {
            let subtype = match protocol.to_lowercase().as_str() {
                "dns" => DosSubType::DnsAmplification,
                "ntp" => DosSubType::NtpAmplification,
                "ssdp" => DosSubType::SsdpAmplification,
                _ => DosSubType::Unknown(protocol.clone()),
            };
            (DetectionType::DoS, DetectionSubType::Dos(subtype))
        }
        ThreatType::BruteForce { .. } => {
            (DetectionType::BruteForce, DetectionSubType::None)
        }
        ThreatType::Anomaly { .. } => {
            (DetectionType::AnomalyDetection, DetectionSubType::Anomaly(AnomalySubType::BehaviorAnomaly))
        }
        // Layer 2 attacks
        ThreatType::ArpSpoofing { .. } => {
            (DetectionType::Custom("layer2_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("layer2", "arp_spoofing", "ARP Spoofing", "ARP cache poisoning attack", Severity::Critical)
            ))
        }
        ThreatType::ArpFlood { .. } => {
            (DetectionType::Custom("layer2_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("layer2", "arp_flood", "ARP Flood", "High rate of ARP packets", Severity::High)
            ))
        }
        ThreatType::VlanHopping { .. } => {
            (DetectionType::Custom("layer2_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("layer2", "vlan_hopping", "VLAN Hopping", "Double-tagged 802.1Q frame", Severity::Critical)
            ))
        }
        ThreatType::DhcpStarvation { .. } => {
            (DetectionType::Custom("layer2_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("layer2", "dhcp_starvation", "DHCP Starvation", "DHCP address pool exhaustion", Severity::High)
            ))
        }
        ThreatType::RogueDhcp { .. } => {
            (DetectionType::Custom("layer2_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("layer2", "rogue_dhcp", "Rogue DHCP Server", "Unauthorized DHCP server detected", Severity::Critical)
            ))
        }
        // Layer 3 attacks
        ThreatType::IcmpTunnel { .. } => {
            (DetectionType::DataExfiltration, DetectionSubType::Custom(
                CustomSubType::new("layer3", "icmp_tunnel", "ICMP Tunnel", "Data exfiltration via ICMP", Severity::High)
            ))
        }
        ThreatType::Ipv6RaSpoofing { .. } => {
            (DetectionType::Custom("layer3_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("layer3", "ipv6_ra_spoofing", "IPv6 RA Spoofing", "Rogue router advertisement", Severity::Critical)
            ))
        }
        ThreatType::Ipv6RaFlood { .. } => {
            (DetectionType::DoS, DetectionSubType::Custom(
                CustomSubType::new("layer3", "ipv6_ra_flood", "IPv6 RA Flood", "Router advertisement flood", Severity::High)
            ))
        }
        // Infrastructure attacks (extra234 feature)
        #[cfg(feature = "extra234")]
        ThreatType::BgpHijack { .. } => {
            (DetectionType::Custom("routing_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("routing", "bgp_hijack", "BGP Hijack", "BGP prefix hijacking attempt", Severity::Critical)
            ))
        }
        #[cfg(feature = "extra234")]
        ThreatType::BgpPrefixFlap { .. } => {
            (DetectionType::Custom("routing_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("routing", "bgp_flap", "BGP Prefix Flap", "Rapid BGP prefix flapping", Severity::High)
            ))
        }
        #[cfg(feature = "extra234")]
        ThreatType::StpRootAttack { .. } => {
            (DetectionType::Custom("layer2_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("layer2", "stp_root", "STP Root Attack", "STP root bridge manipulation", Severity::Critical)
            ))
        }
        #[cfg(feature = "extra234")]
        ThreatType::StpTcFlood { .. } => {
            (DetectionType::DoS, DetectionSubType::Custom(
                CustomSubType::new("layer2", "stp_tc_flood", "STP TC Flood", "STP topology change flood", Severity::High)
            ))
        }
        #[cfg(feature = "extra234")]
        ThreatType::CdpSpoof { .. } => {
            (DetectionType::Custom("discovery_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("discovery", "cdp_spoof", "CDP Spoofing", "Fake CDP device announcement", Severity::High)
            ))
        }
        #[cfg(feature = "extra234")]
        ThreatType::LldpSpoof { .. } => {
            (DetectionType::Custom("discovery_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("discovery", "lldp_spoof", "LLDP Spoofing", "Fake LLDP neighbor discovery", Severity::High)
            ))
        }
        #[cfg(feature = "extra234")]
        ThreatType::OspfNeighborInject { .. } => {
            (DetectionType::Custom("routing_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("routing", "ospf_inject", "OSPF Injection", "Unauthorized OSPF neighbor", Severity::Critical)
            ))
        }
        #[cfg(feature = "extra234")]
        ThreatType::OspfDrManipulation { .. } => {
            (DetectionType::Custom("routing_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("routing", "ospf_dr", "OSPF DR Manipulation", "OSPF designated router manipulation", Severity::Critical)
            ))
        }
        #[cfg(feature = "extra234")]
        ThreatType::RipPoisoning { .. } => {
            (DetectionType::Custom("routing_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("routing", "rip_poison", "RIP Poisoning", "RIP route poisoning attack", Severity::High)
            ))
        }
        #[cfg(feature = "extra234")]
        ThreatType::GreTunnel { .. } => {
            (DetectionType::Custom("tunnel_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("tunnel", "gre", "Unauthorized GRE Tunnel", "Unauthorized GRE encapsulation", Severity::Medium)
            ))
        }
        #[cfg(feature = "extra234")]
        ThreatType::VxlanUnauthorized { .. } => {
            (DetectionType::Custom("tunnel_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("tunnel", "vxlan", "Unauthorized VXLAN", "Unauthorized VXLAN overlay traffic", Severity::Medium)
            ))
        }
        #[cfg(feature = "extra234")]
        ThreatType::Dot1xHubBypass { .. } => {
            (DetectionType::Custom("dot1x_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("dot1x", "hub_bypass", "802.1X Hub Bypass", "Multiple MACs behind authenticated port", Severity::High)
            ))
        }
        #[cfg(feature = "extra234")]
        ThreatType::EapFlood { .. } => {
            (DetectionType::DoS, DetectionSubType::Custom(
                CustomSubType::new("dot1x", "eap_flood", "EAP Flood", "EAP-Start packet flood", Severity::Medium)
            ))
        }
        #[cfg(feature = "extra234")]
        ThreatType::RogueAuthenticator { .. } => {
            (DetectionType::Custom("dot1x_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("dot1x", "rogue_auth", "Rogue Authenticator", "Unauthorized 802.1X authenticator", Severity::Critical)
            ))
        }
        // Advanced Layer 3-4 attacks (extra34 feature)
        #[cfg(feature = "extra34")]
        ThreatType::FragmentOverlap { .. } => {
            (DetectionType::Custom("fragmentation_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("layer3", "fragment_overlap", "Fragment Overlap (Teardrop)", "Overlapping IP fragments", Severity::Critical)
            ))
        }
        #[cfg(feature = "extra34")]
        ThreatType::FragmentOversized { .. } => {
            (DetectionType::Custom("fragmentation_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("layer3", "fragment_oversized", "Oversized Fragment (Ping of Death)", "Reassembled packet exceeds 64KB", Severity::Critical)
            ))
        }
        #[cfg(feature = "extra34")]
        ThreatType::FragmentFlood { .. } => {
            (DetectionType::DoS, DetectionSubType::Custom(
                CustomSubType::new("layer3", "fragment_flood", "Fragment Flood", "High rate of incomplete fragments", Severity::High)
            ))
        }
        #[cfg(feature = "extra34")]
        ThreatType::FragmentTiny { .. } => {
            (DetectionType::Custom("evasion".into()), DetectionSubType::Custom(
                CustomSubType::new("layer3", "fragment_tiny", "Tiny Fragment", "Evasion technique via tiny fragments", Severity::Medium)
            ))
        }
        #[cfg(feature = "extra34")]
        ThreatType::IpSpoofBogon { .. } => {
            (DetectionType::Custom("spoofing".into()), DetectionSubType::Custom(
                CustomSubType::new("layer3", "ip_bogon", "Bogon Source IP", "Source IP from reserved/invalid range", Severity::High)
            ))
        }
        #[cfg(feature = "extra34")]
        ThreatType::IpSpoofMartian { .. } => {
            (DetectionType::Custom("spoofing".into()), DetectionSubType::Custom(
                CustomSubType::new("layer3", "ip_martian", "Martian Source IP", "Impossible source address", Severity::Critical)
            ))
        }
        #[cfg(feature = "extra34")]
        ThreatType::LandAttack { .. } => {
            (DetectionType::DoS, DetectionSubType::Custom(
                CustomSubType::new("layer34", "land", "Land Attack", "Source equals destination (src==dst)", Severity::Critical)
            ))
        }
        #[cfg(feature = "extra34")]
        ThreatType::IcmpRedirect { .. } => {
            (DetectionType::Custom("layer3_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("layer3", "icmp_redirect", "ICMP Redirect", "Route manipulation via ICMP redirect", Severity::High)
            ))
        }
        #[cfg(feature = "extra34")]
        ThreatType::IcmpSourceQuench { .. } => {
            (DetectionType::Custom("layer3_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("layer3", "icmp_source_quench", "ICMP Source Quench", "Deprecated ICMP type used as attack vector", Severity::Medium)
            ))
        }
        #[cfg(feature = "extra34")]
        ThreatType::TcpRstInjection { .. } => {
            (DetectionType::Custom("tcp_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("layer4", "tcp_rst_injection", "TCP RST Injection", "Spoofed RST to terminate connections", Severity::High)
            ))
        }
        #[cfg(feature = "extra34")]
        ThreatType::TcpSessionHijack { .. } => {
            (DetectionType::Custom("tcp_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("layer4", "tcp_hijack", "TCP Session Hijack", "Sequence number manipulation detected", Severity::Critical)
            ))
        }
        #[cfg(feature = "extra34")]
        ThreatType::TcpSynAckReflection { .. } => {
            (DetectionType::DoS, DetectionSubType::Custom(
                CustomSubType::new("layer4", "synack_reflection", "SYN-ACK Reflection", "Reflection attack using spoofed SYN", Severity::High)
            ))
        }
        // 802.11 Wireless attacks (wireless feature)
        #[cfg(feature = "wireless")]
        ThreatType::WifiDeauthFlood { .. } => {
            (DetectionType::DoS, DetectionSubType::Custom(
                CustomSubType::new("wireless", "deauth_flood", "WiFi Deauth Flood", "802.11 deauthentication flood attack", Severity::High)
            ))
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiDisassocFlood { .. } => {
            (DetectionType::DoS, DetectionSubType::Custom(
                CustomSubType::new("wireless", "disassoc_flood", "WiFi Disassoc Flood", "802.11 disassociation flood attack", Severity::High)
            ))
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiEvilTwin { .. } => {
            (DetectionType::Custom("wireless_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("wireless", "evil_twin", "Evil Twin AP", "Rogue AP impersonating legitimate network", Severity::Critical)
            ))
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiFakeAp { .. } => {
            (DetectionType::Custom("wireless_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("wireless", "fake_ap", "Fake AP", "Unknown/unauthorized access point", Severity::High)
            ))
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiBeaconFlood { .. } => {
            (DetectionType::DoS, DetectionSubType::Custom(
                CustomSubType::new("wireless", "beacon_flood", "Beacon Flood", "Excessive beacon frames from single source", Severity::Medium)
            ))
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiKarmaAttack { .. } => {
            (DetectionType::Custom("wireless_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("wireless", "karma", "Karma Attack", "AP responding to all probe requests", Severity::Critical)
            ))
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiAuthFlood { .. } => {
            (DetectionType::DoS, DetectionSubType::Custom(
                CustomSubType::new("wireless", "auth_flood", "Auth Flood", "802.11 authentication flood", Severity::High)
            ))
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiProbeFlood { .. } => {
            (DetectionType::DoS, DetectionSubType::Custom(
                CustomSubType::new("wireless", "probe_flood", "Probe Flood", "Excessive probe requests", Severity::Medium)
            ))
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiPmkidCapture { .. } => {
            (DetectionType::Custom("wireless_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("wireless", "pmkid_capture", "PMKID Capture", "PMKID capture attempt detected", Severity::High)
            ))
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiHandshakeCapture { .. } => {
            (DetectionType::Custom("wireless_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("wireless", "handshake_capture", "Handshake Capture", "WPA handshake capture detected", Severity::High)
            ))
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiKrackAttack { .. } => {
            (DetectionType::Custom("wireless_attack".into()), DetectionSubType::Custom(
                CustomSubType::new("wireless", "krack", "KRACK Attack", "Key reinstallation attack detected", Severity::Critical)
            ))
        }
    }
}

/// Get severity for a ThreatType
fn threat_to_severity(threat: &ThreatType) -> Severity {
    match threat {
        ThreatType::SynFlood { .. } => Severity::High,
        ThreatType::UdpFlood { .. } => Severity::High,
        ThreatType::IcmpFlood { .. } => Severity::High,
        ThreatType::ConnectionExhaustion { .. } => Severity::High,
        ThreatType::Amplification { .. } => Severity::High,
        ThreatType::PortScan { .. } => Severity::Medium,
        ThreatType::BruteForce { .. } => Severity::Medium,
        ThreatType::PingSweep { .. } => Severity::Low,
        ThreatType::Anomaly { deviation_score } => {
            if *deviation_score > 0.8 {
                Severity::High
            } else if *deviation_score > 0.5 {
                Severity::Medium
            } else {
                Severity::Low
            }
        }
        // Layer 2 attacks - generally high severity (MITM potential)
        ThreatType::ArpSpoofing { .. } => Severity::Critical,
        ThreatType::ArpFlood { .. } => Severity::High,
        ThreatType::VlanHopping { .. } => Severity::Critical,
        ThreatType::DhcpStarvation { .. } => Severity::High,
        ThreatType::RogueDhcp { .. } => Severity::Critical,
        // Layer 3 attacks
        ThreatType::IcmpTunnel { entropy, .. } => {
            // Higher entropy suggests encrypted tunnel - more suspicious
            if *entropy > 0.9 {
                Severity::Critical
            } else if *entropy > 0.7 {
                Severity::High
            } else {
                Severity::Medium
            }
        }
        ThreatType::Ipv6RaSpoofing { .. } => Severity::Critical,
        ThreatType::Ipv6RaFlood { .. } => Severity::High,
        // Infrastructure attacks (extra234 feature)
        #[cfg(feature = "extra234")]
        ThreatType::BgpHijack { .. } => Severity::Critical,
        #[cfg(feature = "extra234")]
        ThreatType::BgpPrefixFlap { .. } => Severity::High,
        #[cfg(feature = "extra234")]
        ThreatType::StpRootAttack { .. } => Severity::Critical,
        #[cfg(feature = "extra234")]
        ThreatType::StpTcFlood { .. } => Severity::High,
        #[cfg(feature = "extra234")]
        ThreatType::CdpSpoof { .. } => Severity::High,
        #[cfg(feature = "extra234")]
        ThreatType::LldpSpoof { .. } => Severity::High,
        #[cfg(feature = "extra234")]
        ThreatType::OspfNeighborInject { .. } => Severity::Critical,
        #[cfg(feature = "extra234")]
        ThreatType::OspfDrManipulation { .. } => Severity::Critical,
        #[cfg(feature = "extra234")]
        ThreatType::RipPoisoning { .. } => Severity::High,
        #[cfg(feature = "extra234")]
        ThreatType::GreTunnel { .. } => Severity::Medium,
        #[cfg(feature = "extra234")]
        ThreatType::VxlanUnauthorized { .. } => Severity::Medium,
        #[cfg(feature = "extra234")]
        ThreatType::Dot1xHubBypass { .. } => Severity::High,
        #[cfg(feature = "extra234")]
        ThreatType::EapFlood { .. } => Severity::Medium,
        #[cfg(feature = "extra234")]
        ThreatType::RogueAuthenticator { .. } => Severity::Critical,
        // Advanced Layer 3-4 attacks (extra34 feature)
        #[cfg(feature = "extra34")]
        ThreatType::FragmentOverlap { .. } => Severity::Critical,
        #[cfg(feature = "extra34")]
        ThreatType::FragmentOversized { .. } => Severity::Critical,
        #[cfg(feature = "extra34")]
        ThreatType::FragmentFlood { .. } => Severity::High,
        #[cfg(feature = "extra34")]
        ThreatType::FragmentTiny { .. } => Severity::Medium,
        #[cfg(feature = "extra34")]
        ThreatType::IpSpoofBogon { .. } => Severity::High,
        #[cfg(feature = "extra34")]
        ThreatType::IpSpoofMartian { .. } => Severity::Critical,
        #[cfg(feature = "extra34")]
        ThreatType::LandAttack { .. } => Severity::Critical,
        #[cfg(feature = "extra34")]
        ThreatType::IcmpRedirect { .. } => Severity::High,
        #[cfg(feature = "extra34")]
        ThreatType::IcmpSourceQuench { .. } => Severity::Medium,
        #[cfg(feature = "extra34")]
        ThreatType::TcpRstInjection { .. } => Severity::High,
        #[cfg(feature = "extra34")]
        ThreatType::TcpSessionHijack { .. } => Severity::Critical,
        #[cfg(feature = "extra34")]
        ThreatType::TcpSynAckReflection { .. } => Severity::High,
        // 802.11 Wireless attacks (wireless feature)
        #[cfg(feature = "wireless")]
        ThreatType::WifiDeauthFlood { .. } => Severity::High,
        #[cfg(feature = "wireless")]
        ThreatType::WifiDisassocFlood { .. } => Severity::High,
        #[cfg(feature = "wireless")]
        ThreatType::WifiEvilTwin { .. } => Severity::Critical,
        #[cfg(feature = "wireless")]
        ThreatType::WifiFakeAp { .. } => Severity::High,
        #[cfg(feature = "wireless")]
        ThreatType::WifiBeaconFlood { .. } => Severity::Medium,
        #[cfg(feature = "wireless")]
        ThreatType::WifiKarmaAttack { .. } => Severity::Critical,
        #[cfg(feature = "wireless")]
        ThreatType::WifiAuthFlood { .. } => Severity::High,
        #[cfg(feature = "wireless")]
        ThreatType::WifiProbeFlood { .. } => Severity::Medium,
        #[cfg(feature = "wireless")]
        ThreatType::WifiPmkidCapture { .. } => Severity::High,
        #[cfg(feature = "wireless")]
        ThreatType::WifiHandshakeCapture { .. } => Severity::High,
        #[cfg(feature = "wireless")]
        ThreatType::WifiKrackAttack { .. } => Severity::Critical,
    }
}

/// Map ThreatType to appropriate DetectionAction
///
/// - Alert: Informational (scans, anomalies, probes)
/// - Drop: Active attacks (floods, DoS)
/// - Ban: Persistent attacks (brute force, spoofing)
fn threat_to_action(threat: &ThreatType) -> DetectionAction {
    match threat {
        // Scans - informational, don't block
        ThreatType::PortScan { .. } => DetectionAction::Alert,
        ThreatType::PingSweep { .. } => DetectionAction::Alert,
        ThreatType::Anomaly { .. } => DetectionAction::Alert,

        // Brute force - should ban the attacker
        ThreatType::BruteForce { .. } => DetectionAction::Ban,

        // DoS attacks - should drop immediately
        ThreatType::SynFlood { .. } => DetectionAction::Drop,
        ThreatType::UdpFlood { .. } => DetectionAction::Drop,
        ThreatType::IcmpFlood { .. } => DetectionAction::Drop,
        ThreatType::ConnectionExhaustion { .. } => DetectionAction::Drop,
        ThreatType::Amplification { .. } => DetectionAction::Drop,

        // Layer 2 attacks - should drop (MITM attempts)
        ThreatType::ArpSpoofing { .. } => DetectionAction::Drop,
        ThreatType::ArpFlood { .. } => DetectionAction::Drop,
        ThreatType::VlanHopping { .. } => DetectionAction::Drop,
        ThreatType::DhcpStarvation { .. } => DetectionAction::Drop,
        ThreatType::RogueDhcp { .. } => DetectionAction::Drop,

        // Layer 3 attacks
        ThreatType::IcmpTunnel { .. } => DetectionAction::Alert, // Could be legitimate VPN
        ThreatType::Ipv6RaSpoofing { .. } => DetectionAction::Drop,
        ThreatType::Ipv6RaFlood { .. } => DetectionAction::Drop,

        // Infrastructure attacks (extra234 feature)
        #[cfg(feature = "extra234")]
        ThreatType::BgpHijack { .. } => DetectionAction::Alert, // Alert only - BGP needs careful handling
        #[cfg(feature = "extra234")]
        ThreatType::BgpPrefixFlap { .. } => DetectionAction::Alert,
        #[cfg(feature = "extra234")]
        ThreatType::StpRootAttack { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra234")]
        ThreatType::StpTcFlood { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra234")]
        ThreatType::CdpSpoof { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra234")]
        ThreatType::LldpSpoof { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra234")]
        ThreatType::OspfNeighborInject { .. } => DetectionAction::Alert,
        #[cfg(feature = "extra234")]
        ThreatType::OspfDrManipulation { .. } => DetectionAction::Alert,
        #[cfg(feature = "extra234")]
        ThreatType::RipPoisoning { .. } => DetectionAction::Alert,
        #[cfg(feature = "extra234")]
        ThreatType::GreTunnel { .. } => DetectionAction::Alert,
        #[cfg(feature = "extra234")]
        ThreatType::VxlanUnauthorized { .. } => DetectionAction::Alert,
        #[cfg(feature = "extra234")]
        ThreatType::Dot1xHubBypass { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra234")]
        ThreatType::EapFlood { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra234")]
        ThreatType::RogueAuthenticator { .. } => DetectionAction::Drop,

        // Advanced Layer 3-4 attacks (extra34 feature)
        #[cfg(feature = "extra34")]
        ThreatType::FragmentOverlap { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra34")]
        ThreatType::FragmentOversized { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra34")]
        ThreatType::FragmentFlood { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra34")]
        ThreatType::FragmentTiny { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra34")]
        ThreatType::IpSpoofBogon { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra34")]
        ThreatType::IpSpoofMartian { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra34")]
        ThreatType::LandAttack { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra34")]
        ThreatType::IcmpRedirect { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra34")]
        ThreatType::IcmpSourceQuench { .. } => DetectionAction::Alert,
        #[cfg(feature = "extra34")]
        ThreatType::TcpRstInjection { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra34")]
        ThreatType::TcpSessionHijack { .. } => DetectionAction::Drop,
        #[cfg(feature = "extra34")]
        ThreatType::TcpSynAckReflection { .. } => DetectionAction::Drop,

        // 802.11 Wireless attacks (wireless feature)
        #[cfg(feature = "wireless")]
        ThreatType::WifiDeauthFlood { .. } => DetectionAction::Alert, // Can't drop WiFi at IP layer
        #[cfg(feature = "wireless")]
        ThreatType::WifiDisassocFlood { .. } => DetectionAction::Alert,
        #[cfg(feature = "wireless")]
        ThreatType::WifiEvilTwin { .. } => DetectionAction::Alert,
        #[cfg(feature = "wireless")]
        ThreatType::WifiFakeAp { .. } => DetectionAction::Alert,
        #[cfg(feature = "wireless")]
        ThreatType::WifiBeaconFlood { .. } => DetectionAction::Alert,
        #[cfg(feature = "wireless")]
        ThreatType::WifiKarmaAttack { .. } => DetectionAction::Alert,
        #[cfg(feature = "wireless")]
        ThreatType::WifiAuthFlood { .. } => DetectionAction::Alert,
        #[cfg(feature = "wireless")]
        ThreatType::WifiProbeFlood { .. } => DetectionAction::Alert,
        #[cfg(feature = "wireless")]
        ThreatType::WifiPmkidCapture { .. } => DetectionAction::Alert,
        #[cfg(feature = "wireless")]
        ThreatType::WifiHandshakeCapture { .. } => DetectionAction::Alert,
        #[cfg(feature = "wireless")]
        ThreatType::WifiKrackAttack { .. } => DetectionAction::Alert,
    }
}

/// Format alert message for a ThreatType
fn format_threat_message(threat: &ThreatType, signature: Option<&str>) -> String {
    let base = match threat {
        ThreatType::PortScan { scan_type, ports_touched } => {
            format!("{:?} scan detected - {} ports probed", scan_type, ports_touched)
        }
        ThreatType::SynFlood { packets_per_sec, half_open_connections } => {
            format!("SYN flood attack - {:.0} pps, {} half-open connections", packets_per_sec, half_open_connections)
        }
        ThreatType::UdpFlood { packets_per_sec, bytes_per_sec } => {
            format!("UDP flood attack - {:.0} pps, {:.0} Bps", packets_per_sec, bytes_per_sec)
        }
        ThreatType::IcmpFlood { packets_per_sec, target_ip_count } => {
            format!("ICMP flood attack - {:.0} pps targeting {} IPs", packets_per_sec, target_ip_count)
        }
        ThreatType::ConnectionExhaustion { connection_rate, half_open_ratio } => {
            format!("Connection exhaustion attack - {:.0} conn/s, {:.1}% half-open", connection_rate, half_open_ratio * 100.0)
        }
        ThreatType::Amplification { protocol, amplification_factor } => {
            format!("{} amplification attack - {:.1}x factor", protocol, amplification_factor)
        }
        ThreatType::BruteForce { attempts, target_service } => {
            format!("Brute force attack on {} - {} attempts", target_service, attempts)
        }
        ThreatType::PingSweep { hosts_probed } => {
            format!("Ping sweep detected - {} hosts probed", hosts_probed)
        }
        ThreatType::Anomaly { deviation_score } => {
            format!("Anomaly detected - deviation score {:.2}", deviation_score)
        }
        // Layer 2 attacks
        ThreatType::ArpSpoofing { spoofed_ip, attacker_mac, original_mac, change_count } => {
            format!("ARP spoofing detected - IP {} changed from MAC {} to {} ({} changes)",
                spoofed_ip, original_mac, attacker_mac, change_count)
        }
        ThreatType::ArpFlood { packets_per_sec, unique_ips_claimed } => {
            format!("ARP flood detected - {:.0} pps, {} unique IPs claimed", packets_per_sec, unique_ips_claimed)
        }
        ThreatType::VlanHopping { outer_vlan, inner_vlan } => {
            format!("VLAN hopping attempt - double-tagged frame: outer VLAN {}, inner VLAN {}", outer_vlan, inner_vlan)
        }
        ThreatType::DhcpStarvation { unique_macs, requests_per_sec } => {
            format!("DHCP starvation attack - {} unique MACs, {:.1} req/s", unique_macs, requests_per_sec)
        }
        ThreatType::RogueDhcp { server_ip, offers_count } => {
            format!("Rogue DHCP server detected - {} sent {} offers", server_ip, offers_count)
        }
        // Layer 3 attacks
        ThreatType::IcmpTunnel { avg_payload_size, packets_per_sec, entropy } => {
            format!("ICMP tunneling detected - avg payload {}B, {:.1} pps, entropy {:.2}",
                avg_payload_size, packets_per_sec, entropy)
        }
        ThreatType::Ipv6RaSpoofing { src_ip, router_lifetime } => {
            format!("IPv6 RA spoofing detected - rogue router {} (lifetime: {}s)", src_ip, router_lifetime)
        }
        ThreatType::Ipv6RaFlood { unique_routers, ra_per_sec } => {
            format!("IPv6 RA flood detected - {} routers, {:.1} RA/s", unique_routers, ra_per_sec)
        }
        // Infrastructure attacks (extra234 feature)
        #[cfg(feature = "extra234")]
        ThreatType::BgpHijack { prefix, suspicious_as, original_as } => {
            if let Some(orig) = original_as {
                format!("BGP hijacking detected - prefix {} claimed by AS{} (was AS{})", prefix, suspicious_as, orig)
            } else {
                format!("BGP hijacking detected - prefix {} announced by unknown AS{}", prefix, suspicious_as)
            }
        }
        #[cfg(feature = "extra234")]
        ThreatType::BgpPrefixFlap { prefix, flap_count } => {
            format!("BGP prefix flapping - {} flapped {} times", prefix, flap_count)
        }
        #[cfg(feature = "extra234")]
        ThreatType::StpRootAttack { attacker_mac, claimed_priority } => {
            format!("STP root bridge attack - {} claiming priority {}", attacker_mac, claimed_priority)
        }
        #[cfg(feature = "extra234")]
        ThreatType::StpTcFlood { tc_count, interval_ms } => {
            format!("STP TC flood - {} topology changes in {}ms", tc_count, interval_ms)
        }
        #[cfg(feature = "extra234")]
        ThreatType::CdpSpoof { device_id, claimed_ip } => {
            if let Some(ip) = claimed_ip {
                format!("CDP spoofing - fake device '{}' claiming IP {}", device_id, ip)
            } else {
                format!("CDP spoofing - fake device announcement '{}'", device_id)
            }
        }
        #[cfg(feature = "extra234")]
        ThreatType::LldpSpoof { chassis_id, port_id } => {
            format!("LLDP spoofing - fake neighbor chassis {} port {}", chassis_id, port_id)
        }
        #[cfg(feature = "extra234")]
        ThreatType::OspfNeighborInject { router_id, area_id } => {
            format!("OSPF neighbor injection - unauthorized router {} in area {}", router_id, area_id)
        }
        #[cfg(feature = "extra234")]
        ThreatType::OspfDrManipulation { claimed_dr, area_id } => {
            format!("OSPF DR manipulation - {} claiming DR in area {}", claimed_dr, area_id)
        }
        #[cfg(feature = "extra234")]
        ThreatType::RipPoisoning { route, metric } => {
            format!("RIP route poisoning - {} with metric {}", route, metric)
        }
        #[cfg(feature = "extra234")]
        ThreatType::GreTunnel { src_ip, dst_ip, inner_proto } => {
            format!("Unauthorized GRE tunnel - {} -> {} (inner proto 0x{:04x})", src_ip, dst_ip, inner_proto)
        }
        #[cfg(feature = "extra234")]
        ThreatType::VxlanUnauthorized { vni, vtep_ip } => {
            format!("Unauthorized VXLAN traffic - VNI {} to VTEP {}", vni, vtep_ip)
        }
        #[cfg(feature = "extra234")]
        ThreatType::Dot1xHubBypass { port_macs, port_id } => {
            format!("802.1X hub bypass - {} MACs behind authenticated port {}", port_macs, port_id)
        }
        #[cfg(feature = "extra234")]
        ThreatType::EapFlood { eap_starts_per_sec } => {
            format!("EAP flood attack - {:.1} EAP-Start/sec", eap_starts_per_sec)
        }
        #[cfg(feature = "extra234")]
        ThreatType::RogueAuthenticator { src_mac } => {
            format!("Rogue 802.1X authenticator - unauthorized EAP-Success from {}", src_mac)
        }
        // Advanced Layer 3-4 attacks (extra34 feature)
        #[cfg(feature = "extra34")]
        ThreatType::FragmentOverlap { id, offset1, offset2 } => {
            format!("Fragment overlap (Teardrop) - ID {} offsets {} and {} overlap", id, offset1, offset2)
        }
        #[cfg(feature = "extra34")]
        ThreatType::FragmentOversized { id, total_size } => {
            format!("Oversized fragment (Ping of Death) - ID {} would reassemble to {} bytes", id, total_size)
        }
        #[cfg(feature = "extra34")]
        ThreatType::FragmentFlood { fragments_per_sec, incomplete_count } => {
            format!("Fragment flood - {:.1} frags/sec, {} incomplete reassemblies", fragments_per_sec, incomplete_count)
        }
        #[cfg(feature = "extra34")]
        ThreatType::FragmentTiny { id, fragment_size } => {
            format!("Tiny fragment detected - ID {} size {} bytes (evasion technique)", id, fragment_size)
        }
        #[cfg(feature = "extra34")]
        ThreatType::IpSpoofBogon { src_ip, bogon_type } => {
            format!("Bogon source IP {} - {}", src_ip, bogon_type)
        }
        #[cfg(feature = "extra34")]
        ThreatType::IpSpoofMartian { src_ip } => {
            format!("Martian source IP {} - impossible address", src_ip)
        }
        #[cfg(feature = "extra34")]
        ThreatType::LandAttack { ip, port } => {
            format!("Land attack detected - {}:{} == {}:{}", ip, port, ip, port)
        }
        #[cfg(feature = "extra34")]
        ThreatType::IcmpRedirect { gateway, target } => {
            format!("ICMP redirect attack - gateway {} redirecting to {}", gateway, target)
        }
        #[cfg(feature = "extra34")]
        ThreatType::IcmpSourceQuench { target } => {
            format!("ICMP source quench to {} - deprecated attack vector", target)
        }
        #[cfg(feature = "extra34")]
        ThreatType::TcpRstInjection { flow, seq_delta } => {
            format!("TCP RST injection on {} - seq delta {}", flow, seq_delta)
        }
        #[cfg(feature = "extra34")]
        ThreatType::TcpSessionHijack { flow, seq_jump } => {
            format!("TCP session hijack on {} - sequence jump of {} bytes", flow, seq_jump)
        }
        #[cfg(feature = "extra34")]
        ThreatType::TcpSynAckReflection { target, rate } => {
            format!("SYN-ACK reflection to {} - {:.1} SYN-ACK/sec", target, rate)
        }
        // 802.11 Wireless attacks (wireless feature)
        #[cfg(feature = "wireless")]
        ThreatType::WifiDeauthFlood { bssid, rate, reason_code } => {
            format!("WiFi deauth flood on {} - {:.1} deauths/sec (reason {})", bssid, rate, reason_code)
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiDisassocFlood { bssid, rate } => {
            format!("WiFi disassoc flood on {} - {:.1} disassocs/sec", bssid, rate)
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiEvilTwin { ssid, legitimate_bssid, rogue_bssid } => {
            format!("Evil twin detected for '{}' - legit {} vs rogue {}", ssid, legitimate_bssid, rogue_bssid)
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiFakeAp { ssid, bssid } => {
            format!("Fake AP detected - '{}' at {}", ssid, bssid)
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiBeaconFlood { source_mac, ssid_count } => {
            format!("Beacon flood from {} - {} unique SSIDs", source_mac, ssid_count)
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiKarmaAttack { ap_mac } => {
            format!("Karma attack detected - AP {} responding to all probes", ap_mac)
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiAuthFlood { bssid, rate } => {
            format!("WiFi auth flood on {} - {:.1} auths/sec", bssid, rate)
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiProbeFlood { source_mac, rate } => {
            format!("Probe flood from {} - {:.1} probes/sec", source_mac, rate)
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiPmkidCapture { bssid, client } => {
            format!("PMKID capture attempt - AP {} to client {}", bssid, client)
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiHandshakeCapture { bssid, client } => {
            format!("WPA handshake capture - AP {} client {}", bssid, client)
        }
        #[cfg(feature = "wireless")]
        ThreatType::WifiKrackAttack { bssid, client, msg_num } => {
            format!("KRACK attack detected - AP {} client {} (msg {})", bssid, client, msg_num)
        }
    };

    if let Some(sig) = signature {
        format!("{} [signature: {}]", base, sig)
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer234::types::VECTOR_DIM;

    #[test]
    fn test_builder() {
        let detector = Detector::builder()
            .with_scan_detection(true)
            .with_anomaly_threshold(0.8)
            .with_window_size(Duration::from_secs(30))
            .build()
            .unwrap();

        assert_eq!(detector.signature_count(), 0);
        assert_eq!(detector.baseline_count(), 0);
    }

    #[test]
    fn test_classify_syn_scan() {
        let mut vector = [0.0f32; VECTOR_DIM];
        vector[12] = 0.9; // High SYN ratio
        vector[13] = 0.05; // Low SYN-ACK ratio
        vector[17] = 0.8; // High half-open ratio

        let threat = classify_threat(&vector, None);
        match threat {
            ThreatType::PortScan { scan_type, .. } => {
                assert!(matches!(scan_type, ScanType::TcpSyn));
            }
            _ => panic!("Expected PortScan"),
        }
    }

    #[test]
    fn test_classify_ping_sweep() {
        let mut vector = [0.0f32; VECTOR_DIM];
        vector[36] = 0.8; // High echo request ratio
        vector[40] = 0.7; // High ping sweep score

        let threat = classify_threat(&vector, None);
        match threat {
            ThreatType::PingSweep { .. } => {}
            _ => panic!("Expected PingSweep"),
        }
    }

    // === DoS Detection Tests ===

    #[test]
    fn test_classify_syn_flood() {
        let mut vector = [0.0f32; VECTOR_DIM];
        // SYN flood characteristics:
        // - Few unique ports (unlike scan)
        // - High SYN ratio
        // - Low SYN-ACK
        // - High packet rate
        // - High TCP flood score
        vector[1] = 0.02;  // Few unique ports
        vector[12] = 0.95; // Very high SYN ratio
        vector[13] = 0.02; // Almost no SYN-ACK
        vector[64] = 0.5;  // High packet rate (50k pps)
        vector[68] = 0.8;  // High TCP flood score

        let threat = classify_threat(&vector, None);
        match threat {
            ThreatType::SynFlood { packets_per_sec, half_open_connections } => {
                assert!(packets_per_sec > 40000.0); // Should be ~50k
                // half_open_connections comes from vector[67]
            }
            _ => panic!("Expected SynFlood, got {:?}", threat),
        }
    }

    #[test]
    fn test_classify_syn_flood_by_label() {
        let vector = [0.0f32; VECTOR_DIM];

        let threat = classify_threat(&vector, Some("syn_flood"));
        match threat {
            ThreatType::SynFlood { .. } => {}
            _ => panic!("Expected SynFlood from label"),
        }

        let threat2 = classify_threat(&vector, Some("synflood_attack"));
        match threat2 {
            ThreatType::SynFlood { .. } => {}
            _ => panic!("Expected SynFlood from label variant"),
        }
    }

    #[test]
    fn test_classify_udp_flood() {
        let mut vector = [0.0f32; VECTOR_DIM];
        // UDP flood characteristics:
        // - High packet rate
        // - High byte rate
        // - High UDP other services ratio
        // - High UDP flood score
        vector[31] = 0.9;  // High "other services" UDP ratio
        vector[64] = 0.5;  // High packet rate
        vector[65] = 0.5;  // High byte rate
        vector[69] = 0.8;  // High UDP flood score

        let threat = classify_threat(&vector, None);
        match threat {
            ThreatType::UdpFlood { packets_per_sec, bytes_per_sec } => {
                assert!(packets_per_sec > 40000.0);
                assert!(bytes_per_sec > 50_000_000.0);
            }
            _ => panic!("Expected UdpFlood, got {:?}", threat),
        }
    }

    #[test]
    fn test_classify_udp_flood_by_label() {
        let vector = [0.0f32; VECTOR_DIM];

        let threat = classify_threat(&vector, Some("udp_flood"));
        match threat {
            ThreatType::UdpFlood { .. } => {}
            _ => panic!("Expected UdpFlood from label"),
        }
    }

    #[test]
    fn test_classify_icmp_flood() {
        let mut vector = [0.0f32; VECTOR_DIM];
        // ICMP flood characteristics:
        // - Few destination IPs (single target, unlike sweep)
        // - High echo request ratio
        // - High packet rate
        // - High ICMP flood score
        vector[8] = 0.02;   // Single/few destination IPs
        vector[36] = 0.95;  // High ICMP echo request ratio
        vector[64] = 0.3;   // High packet rate
        vector[70] = 0.8;   // High ICMP flood score

        let threat = classify_threat(&vector, None);
        match threat {
            ThreatType::IcmpFlood { packets_per_sec, target_ip_count } => {
                assert!(packets_per_sec > 20000.0);
                assert!(target_ip_count <= 5); // Few targets
            }
            _ => panic!("Expected IcmpFlood, got {:?}", threat),
        }
    }

    #[test]
    fn test_classify_icmp_flood_by_label() {
        let vector = [0.0f32; VECTOR_DIM];

        let threat = classify_threat(&vector, Some("icmp_flood"));
        match threat {
            ThreatType::IcmpFlood { .. } => {}
            _ => panic!("Expected IcmpFlood from label"),
        }
    }

    #[test]
    fn test_classify_connection_exhaustion() {
        let mut vector = [0.0f32; VECTOR_DIM];
        // Connection exhaustion characteristics:
        // - Elevated SYN ratio
        // - Very high half-open ratio
        // - High connection rate
        // - High exhaustion score
        vector[12] = 0.6;   // Elevated SYN ratio
        vector[17] = 0.85;  // Very high half-open ratio
        vector[66] = 0.4;   // High connection rate
        vector[71] = 0.7;   // Connection exhaustion score

        let threat = classify_threat(&vector, None);
        match threat {
            ThreatType::ConnectionExhaustion { connection_rate, half_open_ratio } => {
                assert!(connection_rate > 3000.0); // ~4000 conn/s
                assert!(half_open_ratio > 0.7);
            }
            _ => panic!("Expected ConnectionExhaustion, got {:?}", threat),
        }
    }

    #[test]
    fn test_classify_connection_exhaustion_by_label() {
        let vector = [0.0f32; VECTOR_DIM];

        let threat = classify_threat(&vector, Some("connection_exhaustion"));
        match threat {
            ThreatType::ConnectionExhaustion { .. } => {}
            _ => panic!("Expected ConnectionExhaustion from label"),
        }
    }

    #[test]
    fn test_dos_builder_methods() {
        let detector = Detector::builder()
            .with_dos_detection(true)
            .with_dos_thresholds(0.2, 0.8)
            .build()
            .unwrap();

        assert!(detector.config.dos_detection);
        assert!((detector.config.dos_min_packet_rate - 0.2).abs() < 0.001);
        assert!((detector.config.dos_half_open_threshold - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_dos_disabled() {
        let detector = Detector::builder()
            .with_dos_detection(false)
            .build()
            .unwrap();

        assert!(!detector.config.dos_detection);
    }

    #[test]
    fn test_syn_flood_vs_syn_scan_differentiation() {
        // SYN flood: few ports, high rate
        let mut flood_vector = [0.0f32; VECTOR_DIM];
        flood_vector[1] = 0.02;   // Few unique ports
        flood_vector[12] = 0.95;  // High SYN ratio
        flood_vector[13] = 0.02;  // Low SYN-ACK
        flood_vector[64] = 0.5;   // High packet rate
        flood_vector[68] = 0.8;   // High TCP flood score

        // SYN scan: many ports, lower rate
        let mut scan_vector = [0.0f32; VECTOR_DIM];
        scan_vector[1] = 0.8;    // Many unique ports
        scan_vector[12] = 0.9;   // High SYN ratio
        scan_vector[13] = 0.05;  // Low SYN-ACK
        scan_vector[17] = 0.8;   // High half-open ratio
        scan_vector[64] = 0.01;  // Low packet rate (scan is slower)

        let flood_threat = classify_threat(&flood_vector, None);
        let scan_threat = classify_threat(&scan_vector, None);

        match flood_threat {
            ThreatType::SynFlood { .. } => {}
            _ => panic!("Expected SynFlood for flood pattern, got {:?}", flood_threat),
        }

        match scan_threat {
            ThreatType::PortScan { scan_type: ScanType::TcpSyn, .. } => {}
            _ => panic!("Expected PortScan for scan pattern, got {:?}", scan_threat),
        }
    }

    #[test]
    fn test_icmp_flood_vs_ping_sweep_differentiation() {
        // ICMP flood: single target, high rate
        let mut flood_vector = [0.0f32; VECTOR_DIM];
        flood_vector[8] = 0.02;   // Few unique IPs (single target)
        flood_vector[36] = 0.95;  // High echo request ratio
        flood_vector[40] = 0.1;   // Low ping sweep score
        flood_vector[64] = 0.3;   // High packet rate
        flood_vector[70] = 0.8;   // High ICMP flood score

        // Ping sweep: many targets, lower rate
        let mut sweep_vector = [0.0f32; VECTOR_DIM];
        sweep_vector[8] = 0.9;    // Many unique IPs
        sweep_vector[36] = 0.8;   // High echo request ratio
        sweep_vector[40] = 0.7;   // High ping sweep score
        sweep_vector[64] = 0.01;  // Low packet rate

        let flood_threat = classify_threat(&flood_vector, None);
        let sweep_threat = classify_threat(&sweep_vector, None);

        match flood_threat {
            ThreatType::IcmpFlood { .. } => {}
            _ => panic!("Expected IcmpFlood for flood pattern, got {:?}", flood_threat),
        }

        match sweep_threat {
            ThreatType::PingSweep { .. } => {}
            _ => panic!("Expected PingSweep for sweep pattern, got {:?}", sweep_threat),
        }
    }
}
