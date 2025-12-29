//! Benchmark runner for detection testing
//!
//! Processes packets through the detection pipeline and collects
//! per-stage metrics including latency, throughput, and accuracy.

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use pcap::Capture;
use serde::{Deserialize, Serialize};

use crate::types::{DetectionEvent, Packet, PacketAnalysis};
use crate::layer234::{Detector as Layer234Detector, DetectorBuilder as Layer234Builder, Config as Layer234Config};
use crate::http_detect::DetectionEngine as HttpDetectionEngine;

use super::ground_truth::{GroundTruth, MatchResult};
use super::metrics::{MetricsCollector, StageMetrics, AccuracyMetrics, PerformanceMetrics};
use super::report::BenchmarkReport;
use super::synthetic::{AttackGenerator, MixedTrafficGenerator};

/// Configuration for benchmark run
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkConfig {
    /// Enable layer234 detection
    pub enable_layer234: bool,
    /// Enable HTTP detection
    pub enable_http_detect: bool,
    /// Enable signature detection
    pub enable_signatures: bool,
    /// Enable protocol detection
    pub enable_protocols: bool,
    /// Number of warmup packets to process before measuring
    pub warmup_packets: u64,
    /// Verbose output (per-packet timing)
    pub verbose: bool,
    /// Path to layer234 config
    pub layer234_config_path: Option<String>,
    /// Path to HTTP patterns
    pub http_patterns_path: Option<String>,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            enable_layer234: true,
            enable_http_detect: true,
            enable_signatures: false,
            enable_protocols: false,
            warmup_packets: 100,
            verbose: false,
            layer234_config_path: None,
            http_patterns_path: None,
        }
    }
}

/// Benchmark runner
pub struct DetectionBenchmark {
    config: BenchmarkConfig,
    layer234: Option<Layer234Detector>,
    http_detect: Option<HttpDetectionEngine>,
    collectors: HashMap<String, MetricsCollector>,
    ground_truth: Option<GroundTruth>,
    start_time: Option<Instant>,
    total_packets: u64,
    total_bytes: u64,
    all_detections: Vec<DetectionEvent>,
    warmup_complete: bool,
}

impl DetectionBenchmark {
    /// Create a new benchmark runner
    pub fn new(config: BenchmarkConfig) -> Self {
        let mut benchmark = Self {
            config,
            layer234: None,
            http_detect: None,
            collectors: HashMap::new(),
            ground_truth: None,
            start_time: None,
            total_packets: 0,
            total_bytes: 0,
            all_detections: Vec::new(),
            warmup_complete: false,
        };

        benchmark.initialize_detectors();
        benchmark
    }

    /// Initialize detection engines
    fn initialize_detectors(&mut self) {
        if self.config.enable_layer234 {
            // Load default config with signatures
            let mut layer234_config = Layer234Config::default();
            // Override window settings for benchmark (matching layer2detect benchmark parameters)
            layer234_config.detector.window_size_ms = 2000; // 2 second windows
            layer234_config.detector.min_packets = 5; // Only need 5 packets per window

            // Build detector from config (which loads signatures!)
            if let Ok(detector) = Layer234Builder::from_config(&layer234_config)
                .build_with_config(&layer234_config)
            {
                self.layer234 = Some(detector);
                self.collectors.insert("layer234".to_string(), MetricsCollector::new("layer234"));
            }
        }

        if self.config.enable_http_detect {
            let patterns_path = self.config.http_patterns_path.as_deref()
                .unwrap_or("data/http_detect/attack_patterns.json");
            if let Ok(engine) = HttpDetectionEngine::from_file(patterns_path) {
                self.http_detect = Some(engine);
                self.collectors.insert("http_detect".to_string(), MetricsCollector::new("http_detect"));
            }
        }

        // Add collectors for other stages
        self.collectors.insert("overall".to_string(), MetricsCollector::new("overall"));
    }

    /// Load ground truth from file
    pub fn load_ground_truth(&mut self, path: &Path) -> anyhow::Result<()> {
        let gt = if path.extension().map_or(false, |e| e == "csv") {
            // Try CICIDS format first, fall back to simple CSV
            GroundTruth::from_cicids2017(path)
                .or_else(|_| GroundTruth::from_csv(path))?
        } else {
            GroundTruth::from_csv(path)?
        };

        self.ground_truth = Some(gt);
        Ok(())
    }

    /// Set ground truth directly
    pub fn set_ground_truth(&mut self, gt: GroundTruth) {
        self.ground_truth = Some(gt);
    }

    /// Process a PCAP file
    pub fn process_pcap(&mut self, path: &Path) -> anyhow::Result<BenchmarkReport> {
        let mut cap = Capture::from_file(path)?;

        self.start_time = Some(Instant::now());
        let mut packet_id = 0u64;

        while let Ok(packet_data) = cap.next_packet() {
            if let Some(packet) = Packet::from_ethernet_bytes(packet_id, packet_data.data, "pcap") {
                self.process_packet(packet);
            }
            packet_id += 1;
        }

        Ok(self.generate_report())
    }

    /// Process packets from a generator
    pub fn process_synthetic(&mut self, generator: &mut impl Iterator<Item = Packet>) -> BenchmarkReport {
        self.start_time = Some(Instant::now());

        for packet in generator {
            self.process_packet(packet);
        }

        self.generate_report()
    }

    /// Process packets from attack generator
    pub fn process_attack_generator(&mut self, generator: &mut AttackGenerator) -> BenchmarkReport {
        // Set ground truth from generator
        self.ground_truth = Some(generator.get_ground_truth());
        self.start_time = Some(Instant::now());

        while let Some(packet) = generator.next_packet() {
            self.process_packet(packet);
        }

        self.generate_report()
    }

    /// Process packets from mixed traffic generator
    pub fn process_mixed_generator(&mut self, generator: &mut MixedTrafficGenerator) -> BenchmarkReport {
        // Set ground truth from generator
        self.ground_truth = Some(generator.get_ground_truth().clone());
        self.start_time = Some(Instant::now());

        while let Some(packet) = generator.next_packet() {
            self.process_packet(packet);
        }

        self.generate_report()
    }

    /// Process packets from realistic traffic generator
    pub fn process_realistic_generator(&mut self, generator: &mut super::realistic::RealisticTrafficGenerator) -> BenchmarkReport {
        // Generate all attack traffic and clone immediately to release mutable borrow
        let packets: Vec<_> = generator.generate_all_attacks().to_vec();

        // Set ground truth from generator (now safe since packets are owned)
        self.ground_truth = Some(generator.get_ground_truth().clone());
        self.start_time = Some(Instant::now());

        // Print ground truth attackers
        if let Some(ref gt) = self.ground_truth {
            eprintln!("\nAttack Sources ({} attackers, {} packets):",
                gt.attacker_ips.len(), packets.len());
            for attack in &gt.attacks {
                eprintln!("  {} -> {}", attack.src_ip, attack.attack_type);
            }
            eprintln!();
        }

        // Subscribe to detection stream before processing to catch flush events
        let mut detection_rx = self.layer234.as_ref().map(|d| d.detection_stream());

        // Process all packets
        for packet in packets {
            self.process_packet(packet);
        }

        // Flush the detector to process remaining windows and collect events
        if let Some(ref mut detector) = self.layer234 {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let _ = detector.flush().await;
            });

            // Collect any events from the detection stream (from flush)
            if let Some(ref mut rx) = detection_rx {
                while let Ok(event) = rx.try_recv() {
                    // Record detection in metrics
                    let is_known_attack = self.ground_truth.as_ref()
                        .map(|gt| gt.is_attacker(&event.src_ip))
                        .unwrap_or(false);

                    // Print each detection
                    let status = if is_known_attack { "TP" } else { "FP" };
                    eprintln!("  [{}] {:?} from {}", status, event.event_type, event.src_ip);

                    if let Some(collector) = self.collectors.get_mut("layer234") {
                        collector.record_detection(&format!("{:?}", event.event_type), is_known_attack);
                    }
                    if let Some(collector) = self.collectors.get_mut("overall") {
                        collector.record_detection(&format!("{:?}", event.event_type), is_known_attack);
                    }

                    self.all_detections.push(event);
                }
            }
        }

        self.generate_report()
    }

    /// Process a single packet through all enabled detectors
    pub fn process_packet(&mut self, packet: Packet) {
        // Skip warmup packets from metrics
        if !self.warmup_complete {
            if self.total_packets < self.config.warmup_packets {
                self.total_packets += 1;
                return;
            }
            self.warmup_complete = true;
            // Reset start time after warmup
            self.start_time = Some(Instant::now());
            self.total_packets = 0;
        }

        let packet_bytes = packet.raw_len as u64;
        let overall_start = Instant::now();
        let mut detections = Vec::new();

        // Layer 234 detection
        if let Some(ref mut detector) = self.layer234 {
            let stage_start = Instant::now();

            // Run detection
            let events = tokio::runtime::Handle::try_current()
                .map(|handle| {
                    handle.block_on(async {
                        let mut analysis = PacketAnalysis::new(packet.clone());
                        detector.process(&mut analysis).await;
                        analysis.events
                    })
                })
                .unwrap_or_else(|_| {
                    // No runtime, create one
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    rt.block_on(async {
                        let mut analysis = PacketAnalysis::new(packet.clone());
                        detector.process(&mut analysis).await;
                        analysis.events
                    })
                });

            let latency = stage_start.elapsed().as_nanos() as u64;

            // Pre-compute values before borrowing collector
            let is_known_attack = self.is_known_attack(&packet);
            let detection_results: Vec<_> = events.iter()
                .map(|event| {
                    let is_tp = self.check_true_positive(&packet, event);
                    (format!("{:?}", event.event_type), is_tp)
                })
                .collect();

            if let Some(collector) = self.collectors.get_mut("layer234") {
                collector.record_packet(packet_bytes, latency);

                for (det_type, is_tp) in &detection_results {
                    collector.record_detection(det_type, *is_tp);
                }

                // Check for missed detections
                if events.is_empty() && is_known_attack {
                    collector.record_miss();
                } else if events.is_empty() && !is_known_attack {
                    collector.record_pass();
                }
            }

            detections.extend(events);
        }

        // HTTP detection (if packet has HTTP payload)
        if let Some(ref _engine) = self.http_detect {
            // TODO: Integrate with http_detect::PacketProcessor
            // For now, HTTP detection is tested separately via httpAttack binary
        }

        // Record overall metrics - pre-compute detection results
        let overall_detection_results: Vec<_> = detections.iter()
            .map(|event| {
                let is_tp = self.check_true_positive(&packet, event);
                (format!("{:?}", event.event_type), is_tp)
            })
            .collect();

        let overall_latency = overall_start.elapsed().as_nanos() as u64;
        if let Some(collector) = self.collectors.get_mut("overall") {
            collector.record_packet(packet_bytes, overall_latency);

            for (det_type, is_tp) in &overall_detection_results {
                collector.record_detection(det_type, *is_tp);
            }
        }

        // Store detections for report
        self.all_detections.extend(detections);

        self.total_packets += 1;
        self.total_bytes += packet_bytes;

        if self.config.verbose && self.total_packets % 10000 == 0 {
            let elapsed = self.start_time.unwrap().elapsed().as_secs_f64();
            let pps = self.total_packets as f64 / elapsed;
            eprintln!("Processed {} packets ({:.0} pps)", self.total_packets, pps);
        }
    }

    /// Check if detection is a true positive
    fn check_true_positive(&mut self, packet: &Packet, event: &DetectionEvent) -> bool {
        if let Some(ref mut gt) = self.ground_truth {
            matches!(gt.match_detection(event), MatchResult::TruePositive { .. })
        } else {
            // Without ground truth, assume all detections could be true
            true
        }
    }

    /// Check if packet is from known attack
    fn is_known_attack(&self, packet: &Packet) -> bool {
        if let Some(ref gt) = self.ground_truth {
            gt.is_attacker(&packet.src_ip())
        } else {
            false
        }
    }

    /// Generate the benchmark report
    pub fn generate_report(&mut self) -> BenchmarkReport {
        let total_duration = self.start_time.map(|s| s.elapsed()).unwrap_or_default();

        // Finalize all collectors
        let mut stage_metrics: Vec<StageMetrics> = Vec::new();
        let mut total_time_ns = 0u64;

        for (name, collector) in self.collectors.drain() {
            let mut metrics = collector.finalize();
            total_time_ns += metrics.total_time_ns;
            stage_metrics.push(metrics);
        }

        // Calculate time percentages
        if total_time_ns > 0 {
            for metrics in &mut stage_metrics {
                metrics.time_percentage = metrics.total_time_ns as f64 / total_time_ns as f64 * 100.0;
            }
        }

        // Sort by name for consistent output
        stage_metrics.sort_by(|a, b| a.name.cmp(&b.name));

        // Calculate overall accuracy
        let mut accuracy = AccuracyMetrics::default();
        for metrics in &stage_metrics {
            if metrics.name != "overall" {
                accuracy.total_true_positives += metrics.true_positives;
                accuracy.total_false_positives += metrics.false_positives;
                accuracy.total_false_negatives += metrics.false_negatives;
                accuracy.total_true_negatives += metrics.true_negatives;
            }
        }
        accuracy.calculate();

        // Calculate performance metrics
        let mut performance = PerformanceMetrics {
            total_duration_ms: total_duration.as_millis() as u64,
            total_packets: self.total_packets,
            total_bytes: self.total_bytes,
            overall_pps: self.total_packets as f64 / total_duration.as_secs_f64().max(0.001),
            overall_mbps: (self.total_bytes as f64 * 8.0)
                / (total_duration.as_secs_f64().max(0.001) * 1_000_000.0),
            bottleneck_stage: String::new(),
            bottleneck_latency_ns: 0,
        };

        // Find bottleneck
        for metrics in &stage_metrics {
            if metrics.name != "overall" && metrics.latency_p99_ns > performance.bottleneck_latency_ns {
                performance.bottleneck_stage = metrics.name.clone();
                performance.bottleneck_latency_ns = metrics.latency_p99_ns;
            }
        }

        // Get ground truth stats
        let gt_stats = self.ground_truth.as_ref().map(|gt| gt.get_statistics());

        BenchmarkReport::new(stage_metrics, accuracy, performance, gt_stats)
    }

    /// Get current packet count
    pub fn packets_processed(&self) -> u64 {
        self.total_packets
    }

    /// Get all detections
    pub fn detections(&self) -> &[DetectionEvent] {
        &self.all_detections
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::synthetic::{AttackConfig, AttackType};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_benchmark_synthetic() {
        let config = BenchmarkConfig {
            enable_layer234: true,
            enable_http_detect: false,
            warmup_packets: 0,
            ..Default::default()
        };

        let mut benchmark = DetectionBenchmark::new(config);

        let attack_config = AttackConfig::port_scan(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            vec![22, 80, 443, 8080, 3389],
        );

        let mut generator = AttackGenerator::new(attack_config);
        let report = benchmark.process_attack_generator(&mut generator);

        assert!(report.summary.total_packets > 0);
        println!("{}", report.to_markdown());
    }
}
