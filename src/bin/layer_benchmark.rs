//! Layer Benchmark - Measures latency and throughput for all detection layers
//!
//! Usage: layer_benchmark [--iterations N] [--packet-size SIZE] [--layers LAYER,...]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use hdrhistogram::Histogram;

// Import types from crmonban
use crmonban::types::{Packet, IpProtocol, TcpFlags, PacketAnalysis};
use crmonban::ipfilter::{Worker as IpFilterWorker, IpFilter};
use crmonban::http_detect::DetectionEngine as HttpEngine;
use crmonban::layer234::{DetectorBuilder as Layer234Builder, Config as Layer234Config};

#[cfg(feature = "flow-tracking")]
use crmonban::flow::{FlowTracker, FlowConfig};

#[cfg(feature = "protocols")]
use crmonban::protocols::{ProtocolDetector, ProtocolConfig};

#[cfg(feature = "protocols")]
use crmonban::core::Flow;

#[cfg(feature = "ml-detection")]
use crmonban::ml::{MLEngine, MLConfig};

#[cfg(feature = "correlation")]
use crmonban::correlation::{CorrelationEngine, CorrelationConfig};

#[cfg(feature = "correlation")]
use crmonban::core::{DetectionEvent, DetectionType, Severity};

#[cfg(feature = "signatures")]
use crmonban::signatures::{SignatureEngine, SignatureConfig, ProtocolContext, FlowState as SigFlowState};

/// Benchmark result for a single layer
#[derive(Debug, Clone)]
pub struct LayerBenchmark {
    pub name: String,
    pub operations: u64,
    pub total_time_ns: u64,
    pub latency_p50_ns: u64,
    pub latency_p95_ns: u64,
    pub latency_p99_ns: u64,
    pub latency_max_ns: u64,
    pub latency_mean_ns: f64,
    pub ops_per_second: f64,
    pub mbps: f64,
}

impl LayerBenchmark {
    fn format_latency(ns: u64) -> String {
        if ns >= 1_000_000 {
            format!("{:.2}ms", ns as f64 / 1_000_000.0)
        } else if ns >= 1_000 {
            format!("{:.2}µs", ns as f64 / 1_000.0)
        } else {
            format!("{}ns", ns)
        }
    }

    fn format_throughput(ops: f64) -> String {
        if ops >= 1_000_000.0 {
            format!("{:.2}M ops/s", ops / 1_000_000.0)
        } else if ops >= 1_000.0 {
            format!("{:.2}K ops/s", ops / 1_000.0)
        } else {
            format!("{:.0} ops/s", ops)
        }
    }
}

/// Generate test packets for benchmarking
fn generate_test_packets(count: usize, packet_size: usize) -> Vec<Packet> {
    generate_test_packets_with_attack_ratio(count, packet_size, 0)
}

/// Generate test packets with attack traffic ratio (0-100%)
fn generate_test_packets_with_attack_ratio(count: usize, packet_size: usize, attack_percent: usize) -> Vec<Packet> {
    let mut packets = Vec::with_capacity(count);
    let attack_count = (count * attack_percent) / 100;

    for i in 0..count {
        let is_attack = i < attack_count;

        let (src_ip, dst_ip, src_port, dst_port, flags) = if is_attack {
            // Attack traffic - 3 types rotating
            match i % 3 {
                0 => {
                    // Port scan - same src, different dst ports
                    let src = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 50));
                    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
                    let flags = TcpFlags { syn: true, ..Default::default() };
                    (src, dst, 45000, 1 + (i % 65000) as u16, flags)
                }
                1 => {
                    // SYN flood - different src, same dst port
                    let src = IpAddr::V4(Ipv4Addr::new(
                        192, 168, ((i / 256) % 256) as u8, (i % 256) as u8
                    ));
                    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
                    let flags = TcpFlags { syn: true, ..Default::default() };
                    (src, dst, 40000 + (i % 10000) as u16, 80, flags)
                }
                _ => {
                    // SSH brute force - same src, same dst port 22
                    let src = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 100));
                    let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
                    let flags = TcpFlags { syn: true, ack: true, psh: true, ..Default::default() };
                    (src, dst, 50000 + (i % 10000) as u16, 22, flags)
                }
            }
        } else {
            // Normal traffic
            let src = IpAddr::V4(Ipv4Addr::new(
                192, 168, (i / 256) as u8, (i % 256) as u8
            ));
            let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
            let port = match i % 5 {
                0 => 80,
                1 => 443,
                2 => 8080,
                3 => 3000,
                _ => 8443,
            };
            let flags = TcpFlags {
                syn: false,
                ack: true,
                psh: i % 4 == 0,
                ..Default::default()
            };
            (src, dst, 50000 + (i % 10000) as u16, port, flags)
        };

        let mut pkt = Packet::new(i as u64, src_ip, dst_ip, IpProtocol::Tcp, "eth0");
        pkt.raw_len = packet_size as u32;

        if let Some(tcp) = pkt.tcp_mut() {
            tcp.src_port = src_port;
            tcp.dst_port = dst_port;
            tcp.flags = flags;
        }

        packets.push(pkt);
    }

    packets
}

/// Generate test HTTP requests for benchmarking
fn generate_http_requests(count: usize) -> Vec<(String, String, HashMap<String, String>)> {
    let urls = vec![
        "/index.html",
        "/api/users",
        "/search?q=test",
        "/login",
        "/admin/dashboard",
        "/static/css/style.css",
        "/api/v1/products?page=1&limit=10",
        "/download/file.pdf",
    ];

    let mut requests = Vec::with_capacity(count);
    let mut headers = HashMap::new();
    headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
    headers.insert("host".to_string(), "example.com".to_string());

    for i in 0..count {
        let method = if i % 5 == 0 { "POST" } else { "GET" };
        let url = urls[i % urls.len()].to_string();
        requests.push((method.to_string(), url, headers.clone()));
    }

    requests
}

/// Benchmark IP Filter layer
fn benchmark_ipfilter(packets: &[Packet], warmup: usize) -> LayerBenchmark {
    let mut histogram = Histogram::<u64>::new_with_bounds(1, 1_000_000_000, 3).unwrap();

    // Create IP filter with some rules
    let mut ip_filter = IpFilter::new();
    for i in 0..100 {
        ip_filter.block(
            IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)),
            "Blocked IP".to_string(),
        );
    }
    for i in 0..50 {
        ip_filter.watch(
            IpAddr::V4(Ipv4Addr::new(172, 16, (i / 256) as u8, (i % 256) as u8)),
            "Watched IP".to_string(),
        );
    }

    let worker = IpFilterWorker::new(ip_filter);

    // Warmup
    for pkt in packets.iter().take(warmup) {
        let _ = worker.analyze(pkt);
    }

    // Benchmark
    let start = Instant::now();
    for pkt in packets.iter().skip(warmup) {
        let op_start = Instant::now();
        let _ = worker.analyze(pkt);
        let elapsed = op_start.elapsed().as_nanos() as u64;
        let _ = histogram.record(elapsed.max(1).min(1_000_000_000));
    }
    let total_time = start.elapsed();

    let ops = (packets.len() - warmup) as u64;
    let bytes = ops * packets[0].raw_len as u64;
    let secs = total_time.as_secs_f64();

    LayerBenchmark {
        name: "ip_filter".to_string(),
        operations: ops,
        total_time_ns: total_time.as_nanos() as u64,
        latency_p50_ns: histogram.value_at_percentile(50.0),
        latency_p95_ns: histogram.value_at_percentile(95.0),
        latency_p99_ns: histogram.value_at_percentile(99.0),
        latency_max_ns: histogram.max(),
        latency_mean_ns: histogram.mean(),
        ops_per_second: ops as f64 / secs,
        mbps: (bytes as f64 * 8.0) / (secs * 1_000_000.0),
    }
}

/// Benchmark Flow Tracker layer
#[cfg(feature = "flow-tracking")]
fn benchmark_flow_tracker(packets: &[Packet], warmup: usize) -> LayerBenchmark {
    let mut histogram = Histogram::<u64>::new_with_bounds(1, 1_000_000_000, 3).unwrap();

    let config = FlowConfig::default();
    let mut tracker = FlowTracker::new(config);

    // Clone packets for mutable access
    let mut packets_clone: Vec<Packet> = packets.to_vec();

    // Warmup
    for pkt in packets_clone.iter_mut().take(warmup) {
        let _ = tracker.process(pkt);
    }

    // Benchmark
    let start = Instant::now();
    for pkt in packets_clone.iter_mut().skip(warmup) {
        let op_start = Instant::now();
        let _ = tracker.process(pkt);
        let elapsed = op_start.elapsed().as_nanos() as u64;
        let _ = histogram.record(elapsed.max(1).min(1_000_000_000));
    }
    let total_time = start.elapsed();

    let ops = (packets.len() - warmup) as u64;
    let bytes = ops * packets[0].raw_len as u64;
    let secs = total_time.as_secs_f64();

    LayerBenchmark {
        name: "flow_tracker".to_string(),
        operations: ops,
        total_time_ns: total_time.as_nanos() as u64,
        latency_p50_ns: histogram.value_at_percentile(50.0),
        latency_p95_ns: histogram.value_at_percentile(95.0),
        latency_p99_ns: histogram.value_at_percentile(99.0),
        latency_max_ns: histogram.max(),
        latency_mean_ns: histogram.mean(),
        ops_per_second: ops as f64 / secs,
        mbps: (bytes as f64 * 8.0) / (secs * 1_000_000.0),
    }
}

/// Benchmark Layer234 detector (scan/DoS/brute force)
fn benchmark_layer234(packets: &[Packet], warmup: usize) -> LayerBenchmark {
    let mut histogram = Histogram::<u64>::new_with_bounds(1, 1_000_000_000, 3).unwrap();

    // Create layer234 detector
    let mut config = Layer234Config::default();
    config.detector.window_size_ms = 2000;
    config.detector.min_packets = 5;

    let mut detector = Layer234Builder::from_config(&config)
        .build_with_config(&config)
        .expect("Failed to create layer234 detector");

    // Subscribe to events (required for processing)
    let _rx = detector.detection_stream();

    // Warmup - using PacketAnalysis wrapper
    for pkt in packets.iter().take(warmup) {
        let mut analysis = PacketAnalysis::new(pkt.clone());
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        rt.block_on(detector.process(&mut analysis));
    }

    // Benchmark
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let start = Instant::now();
    for pkt in packets.iter().skip(warmup) {
        let op_start = Instant::now();
        let mut analysis = PacketAnalysis::new(pkt.clone());
        rt.block_on(detector.process(&mut analysis));
        let elapsed = op_start.elapsed().as_nanos() as u64;
        let _ = histogram.record(elapsed.max(1).min(1_000_000_000));
    }
    let total_time = start.elapsed();

    let ops = (packets.len() - warmup) as u64;
    let bytes = ops * packets[0].raw_len as u64;
    let secs = total_time.as_secs_f64();

    LayerBenchmark {
        name: "layer234".to_string(),
        operations: ops,
        total_time_ns: total_time.as_nanos() as u64,
        latency_p50_ns: histogram.value_at_percentile(50.0),
        latency_p95_ns: histogram.value_at_percentile(95.0),
        latency_p99_ns: histogram.value_at_percentile(99.0),
        latency_max_ns: histogram.max(),
        latency_mean_ns: histogram.mean(),
        ops_per_second: ops as f64 / secs,
        mbps: (bytes as f64 * 8.0) / (secs * 1_000_000.0),
    }
}

/// Benchmark HTTP detection layer
fn benchmark_http_detect(requests: &[(String, String, HashMap<String, String>)], warmup: usize) -> Option<LayerBenchmark> {
    let mut histogram = Histogram::<u64>::new_with_bounds(1, 1_000_000_000, 3).unwrap();

    // Load HTTP detection patterns
    let engine = match HttpEngine::from_file("data/http_detect/attack_patterns.json") {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Warning: Could not load HTTP patterns: {}. Skipping http_detect.", e);
            return None;
        }
    };

    // Warmup
    for (method, url, headers) in requests.iter().take(warmup) {
        let _ = engine.scan_request(method, url, headers, None);
    }

    // Benchmark
    let start = Instant::now();
    for (method, url, headers) in requests.iter().skip(warmup) {
        let op_start = Instant::now();
        let _ = engine.scan_request(method, url, headers, None);
        let elapsed = op_start.elapsed().as_nanos() as u64;
        let _ = histogram.record(elapsed.max(1).min(1_000_000_000));
    }
    let total_time = start.elapsed();

    let ops = (requests.len() - warmup) as u64;
    let avg_url_len = requests.iter().skip(warmup).map(|(_, u, _)| u.len()).sum::<usize>() / ops.max(1) as usize;
    let bytes = ops * avg_url_len as u64;
    let secs = total_time.as_secs_f64();

    Some(LayerBenchmark {
        name: "http_detect".to_string(),
        operations: ops,
        total_time_ns: total_time.as_nanos() as u64,
        latency_p50_ns: histogram.value_at_percentile(50.0),
        latency_p95_ns: histogram.value_at_percentile(95.0),
        latency_p99_ns: histogram.value_at_percentile(99.0),
        latency_max_ns: histogram.max(),
        latency_mean_ns: histogram.mean(),
        ops_per_second: ops as f64 / secs,
        mbps: (bytes as f64 * 8.0) / (secs * 1_000_000.0),
    })
}

/// Benchmark signature matching layer (all rules)
#[cfg(feature = "signatures")]
fn benchmark_signatures(packets: &[Packet], warmup: usize) -> Option<LayerBenchmark> {
    let rules_dir = std::path::Path::new("/var/lib/crmonban/data/signatures/suricata/rules");
    let engine = SignatureEngine::load_from_dir(rules_dir)?;
    run_signature_benchmark(packets, warmup, engine)
}

/// Benchmark signature matching with filtered rules (high-priority only)
#[cfg(feature = "signatures")]
fn benchmark_signatures_filtered(packets: &[Packet], warmup: usize) -> Option<LayerBenchmark> {
    use crmonban::signatures::RuleLoader;

    let mut config = SignatureConfig::default();
    config.included_classtypes = vec![
        "trojan-activity".into(),
        "command-and-control".into(),
        "exploit-kit".into(),
    ];

    let rules_dir = std::path::Path::new("/var/lib/crmonban/data/signatures/suricata/rules");
    let loader = RuleLoader::new(config.clone());
    let ruleset = loader.load_directory(rules_dir).ok()?;

    let mut engine = SignatureEngine::new(config);
    for (_sid, rule) in ruleset.rules {
        engine.add_rule(rule);
    }
    engine.rebuild_prefilter();

    run_signature_benchmark(packets, warmup, engine)
}

#[cfg(feature = "signatures")]
fn run_signature_benchmark(packets: &[Packet], warmup: usize, engine: SignatureEngine) -> Option<LayerBenchmark> {
    run_signature_benchmark_inner(packets, warmup, engine, "signatures", false)
}

#[cfg(feature = "signatures")]
fn run_signature_benchmark_inner(
    packets: &[Packet],
    warmup: usize,
    engine: SignatureEngine,
    name: &str,
    #[allow(unused)] use_hyperscan: bool,
) -> Option<LayerBenchmark> {
    let mut histogram = Histogram::<u64>::new_with_bounds(1, 1_000_000_000, 3).unwrap();

    #[cfg(feature = "hyperscan")]
    {
        if use_hyperscan {
            print!(" ({} rules, {} hs patterns)",
                engine.rule_count(),
                engine.hyperscan_pattern_count());
        } else {
            print!(" ({} rules)", engine.rule_count());
        }
    }
    #[cfg(not(feature = "hyperscan"))]
    print!(" ({} rules)", engine.rule_count());

    // Default contexts for matching
    let proto_ctx = ProtocolContext::default();
    let flow_state = SigFlowState { established: true, to_server: true };

    // Warmup
    for pkt in packets.iter().take(warmup) {
        #[cfg(feature = "hyperscan")]
        {
            if use_hyperscan {
                let _ = engine.match_packet_hyperscan(pkt, &proto_ctx, &flow_state);
            } else {
                let _ = engine.match_packet(pkt, &proto_ctx, &flow_state);
            }
        }
        #[cfg(not(feature = "hyperscan"))]
        let _ = engine.match_packet(pkt, &proto_ctx, &flow_state);
    }

    // Benchmark
    let start = Instant::now();
    for pkt in packets.iter().skip(warmup) {
        let op_start = Instant::now();
        #[cfg(feature = "hyperscan")]
        {
            if use_hyperscan {
                let _ = engine.match_packet_hyperscan(pkt, &proto_ctx, &flow_state);
            } else {
                let _ = engine.match_packet(pkt, &proto_ctx, &flow_state);
            }
        }
        #[cfg(not(feature = "hyperscan"))]
        let _ = engine.match_packet(pkt, &proto_ctx, &flow_state);
        let elapsed = op_start.elapsed().as_nanos() as u64;
        let _ = histogram.record(elapsed.max(1).min(1_000_000_000));
    }
    let total_time = start.elapsed();

    let ops = (packets.len() - warmup) as u64;
    let bytes = ops * packets[0].raw_len as u64;
    let secs = total_time.as_secs_f64();

    Some(LayerBenchmark {
        name: name.to_string(),
        operations: ops,
        total_time_ns: total_time.as_nanos() as u64,
        latency_p50_ns: histogram.value_at_percentile(50.0),
        latency_p95_ns: histogram.value_at_percentile(95.0),
        latency_p99_ns: histogram.value_at_percentile(99.0),
        latency_max_ns: histogram.max(),
        latency_mean_ns: histogram.mean(),
        ops_per_second: ops as f64 / secs,
        mbps: (bytes as f64 * 8.0) / (secs * 1_000_000.0),
    })
}

/// Benchmark signature matching using Hyperscan acceleration
#[cfg(all(feature = "signatures", feature = "hyperscan"))]
fn benchmark_signatures_hyperscan(packets: &[Packet], warmup: usize) -> Option<LayerBenchmark> {
    use crmonban::signatures::RuleLoader;

    let config = SignatureConfig::default();
    let rules_dir = std::path::Path::new("/var/lib/crmonban/data/signatures/suricata/rules");
    let loader = RuleLoader::new(config.clone());
    let ruleset = loader.load_directory(rules_dir).ok()?;

    let mut engine = SignatureEngine::new(config);
    for (_sid, rule) in ruleset.rules {
        engine.add_rule(rule);
    }
    engine.rebuild_prefilter();  // This also builds hyperscan

    if !engine.has_hyperscan() {
        println!("  [Hyperscan not available]");
        return None;
    }

    run_signature_benchmark_inner(packets, warmup, engine, "sig-hyperscan", true)
}

/// Benchmark Protocol Analysis layer (DNS, TLS, SSH, HTTP parsing + attack detection)
#[cfg(feature = "protocols")]
fn benchmark_protocols(packets: &[Packet], warmup: usize) -> LayerBenchmark {
    let mut histogram = Histogram::<u64>::new_with_bounds(1, 1_000_000_000, 3).unwrap();

    // Create protocol detector with attack detection
    let config = ProtocolConfig::default();
    let detector = ProtocolDetector::with_http_attack_engine(
        config,
        "data/http_detect/attack_patterns.json",
    );

    // Clone packets for mutable flow access
    let mut flows: Vec<Flow> = packets.iter()
        .map(|p| Flow::new(p.id as u64, p))
        .collect();

    // Warmup
    for (pkt, flow) in packets.iter().zip(flows.iter_mut()).take(warmup) {
        let _ = detector.analyze(pkt, flow);
    }

    // Benchmark
    let start = Instant::now();
    for (pkt, flow) in packets.iter().zip(flows.iter_mut()).skip(warmup) {
        let op_start = Instant::now();
        let _ = detector.analyze(pkt, flow);
        let elapsed = op_start.elapsed().as_nanos() as u64;
        let _ = histogram.record(elapsed.max(1).min(1_000_000_000));
    }
    let total_time = start.elapsed();

    let ops = (packets.len() - warmup) as u64;
    let bytes = ops * packets[0].raw_len as u64;
    let secs = total_time.as_secs_f64();

    LayerBenchmark {
        name: "protocols".to_string(),
        operations: ops,
        total_time_ns: total_time.as_nanos() as u64,
        latency_p50_ns: histogram.value_at_percentile(50.0),
        latency_p95_ns: histogram.value_at_percentile(95.0),
        latency_p99_ns: histogram.value_at_percentile(99.0),
        latency_max_ns: histogram.max(),
        latency_mean_ns: histogram.mean(),
        ops_per_second: ops as f64 / secs,
        mbps: (bytes as f64 * 8.0) / (secs * 1_000_000.0),
    }
}

/// Benchmark ML Detection layer (anomaly detection, feature extraction)
#[cfg(feature = "ml-detection")]
fn benchmark_ml_detection(packets: &[Packet], warmup: usize) -> LayerBenchmark {
    let mut histogram = Histogram::<u64>::new_with_bounds(1, 1_000_000_000, 3).unwrap();

    // Create ML engine
    let config = MLConfig::default();
    let mut engine = MLEngine::new(config);

    // Create flows for feature extraction
    let mut flows: Vec<crmonban::core::Flow> = packets.iter()
        .map(|p| crmonban::core::Flow::new(p.id as u64, p))
        .collect();

    // Warmup - feed some flows for baseline learning
    for flow in flows.iter().take(warmup) {
        engine.update_baseline(flow);
    }

    // Benchmark anomaly scoring (process_flow does feature extraction + scoring)
    let start = Instant::now();
    for flow in flows.iter_mut().skip(warmup) {
        let op_start = Instant::now();
        let _ = engine.process_flow(flow);
        let elapsed = op_start.elapsed().as_nanos() as u64;
        let _ = histogram.record(elapsed.max(1).min(1_000_000_000));
    }
    let total_time = start.elapsed();

    let ops = (packets.len() - warmup) as u64;
    let bytes = ops * packets[0].raw_len as u64;
    let secs = total_time.as_secs_f64();

    LayerBenchmark {
        name: "ml_detect".to_string(),
        operations: ops,
        total_time_ns: total_time.as_nanos() as u64,
        latency_p50_ns: histogram.value_at_percentile(50.0),
        latency_p95_ns: histogram.value_at_percentile(95.0),
        latency_p99_ns: histogram.value_at_percentile(99.0),
        latency_max_ns: histogram.max(),
        latency_mean_ns: histogram.mean(),
        ops_per_second: ops as f64 / secs,
        mbps: (bytes as f64 * 8.0) / (secs * 1_000_000.0),
    }
}

/// Benchmark Correlation Engine (alert correlation, incident grouping)
#[cfg(feature = "correlation")]
fn benchmark_correlation(count: usize, warmup: usize) -> LayerBenchmark {
    let mut histogram = Histogram::<u64>::new_with_bounds(1, 1_000_000_000, 3).unwrap();

    // Create correlation engine
    let config = CorrelationConfig::default();
    let mut engine = CorrelationEngine::new(config);

    // Generate synthetic detection events
    let events: Vec<DetectionEvent> = (0..count + warmup)
        .map(|i| {
            let src_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                192, 168, (i / 256) as u8, (i % 256) as u8
            ));
            let dst_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));

            let detection_type = match i % 5 {
                0 => DetectionType::PortScan,
                1 => DetectionType::BruteForce,
                2 => DetectionType::DoS,
                3 => DetectionType::SqlInjection,
                _ => DetectionType::Custom("test".into()),
            };

            DetectionEvent::new(
                detection_type,
                Severity::Medium,
                src_ip,
                dst_ip,
                format!("Test event {}", i),
            )
        })
        .collect();

    // Warmup
    for event in events.iter().take(warmup) {
        let _ = engine.process_event(event.clone());
    }

    // Benchmark
    let start = Instant::now();
    for event in events.iter().skip(warmup) {
        let op_start = Instant::now();
        let _ = engine.process_event(event.clone());
        let elapsed = op_start.elapsed().as_nanos() as u64;
        let _ = histogram.record(elapsed.max(1).min(1_000_000_000));
    }
    let total_time = start.elapsed();

    let ops = count as u64;
    let secs = total_time.as_secs_f64();

    LayerBenchmark {
        name: "correlation".to_string(),
        operations: ops,
        total_time_ns: total_time.as_nanos() as u64,
        latency_p50_ns: histogram.value_at_percentile(50.0),
        latency_p95_ns: histogram.value_at_percentile(95.0),
        latency_p99_ns: histogram.value_at_percentile(99.0),
        latency_max_ns: histogram.max(),
        latency_mean_ns: histogram.mean(),
        ops_per_second: ops as f64 / secs,
        mbps: 0.0, // N/A for correlation (not packet-based throughput)
    }
}

fn print_results(results: &[LayerBenchmark]) {
    println!("\n╔════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                           DETECTION LAYER BENCHMARK RESULTS                                ║");
    println!("╠════════════════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ Layer           │ Ops      │ p50        │ p95        │ p99        │ max        │ Throughput │");
    println!("╠═════════════════╪══════════╪════════════╪════════════╪════════════╪════════════╪════════════╣");

    for r in results {
        println!(
            "║ {:15} │ {:>8} │ {:>10} │ {:>10} │ {:>10} │ {:>10} │ {:>10} ║",
            r.name,
            format_ops(r.operations),
            LayerBenchmark::format_latency(r.latency_p50_ns),
            LayerBenchmark::format_latency(r.latency_p95_ns),
            LayerBenchmark::format_latency(r.latency_p99_ns),
            LayerBenchmark::format_latency(r.latency_max_ns),
            LayerBenchmark::format_throughput(r.ops_per_second),
        );
    }

    println!("╚═════════════════╧══════════╧════════════╧════════════╧════════════╧════════════╧════════════╝");

    // Print detailed stats
    println!("\nDetailed Statistics:");
    println!("─────────────────────────────────────────────────────────────────────────────────────");
    for r in results {
        println!(
            "{:15}: mean={:>10} | {:.2} Mbps | total_time={:.2}ms",
            r.name,
            LayerBenchmark::format_latency(r.latency_mean_ns as u64),
            r.mbps,
            r.total_time_ns as f64 / 1_000_000.0,
        );
    }

    // Find bottleneck
    if let Some(slowest) = results.iter().max_by(|a, b| {
        a.latency_p99_ns.partial_cmp(&b.latency_p99_ns).unwrap()
    }) {
        println!("\nBottleneck: {} (p99: {})",
            slowest.name,
            LayerBenchmark::format_latency(slowest.latency_p99_ns)
        );
    }
}

fn format_ops(ops: u64) -> String {
    if ops >= 1_000_000 {
        format!("{:.1}M", ops as f64 / 1_000_000.0)
    } else if ops >= 1_000 {
        format!("{:.1}K", ops as f64 / 1_000.0)
    } else {
        format!("{}", ops)
    }
}

fn main() {
    // Parse arguments
    let args: Vec<String> = std::env::args().collect();
    let mut iterations = 100_000usize;
    let mut packet_size = 1500usize;
    let mut attack_ratio = 0usize;
    let warmup = 1000usize;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iterations" | "-n" => {
                iterations = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(iterations);
                i += 1;
            }
            "--packet-size" | "-s" => {
                packet_size = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(packet_size);
                i += 1;
            }
            "--attack-ratio" | "-a" => {
                attack_ratio = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(0);
                attack_ratio = attack_ratio.min(100);
                i += 1;
            }
            "--help" | "-h" => {
                println!("Usage: layer_benchmark [OPTIONS]");
                println!();
                println!("Options:");
                println!("  -n, --iterations N    Number of operations per layer (default: 100000)");
                println!("  -s, --packet-size N   Packet size in bytes (default: 1500)");
                println!("  -a, --attack-ratio N  Percentage of attack traffic 0-100 (default: 0)");
                println!("  -h, --help            Show this help");
                println!();
                println!("Examples:");
                println!("  layer_benchmark -n 1000 -a 33    # 1000 packets, 33% attack traffic");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    println!("CR Monban Layer Benchmark");
    println!("=========================");
    println!("Iterations: {}", iterations);
    println!("Packet size: {} bytes", packet_size);
    if attack_ratio > 0 {
        println!("Attack ratio: {}% ({} attack, {} normal)",
            attack_ratio,
            (iterations * attack_ratio) / 100,
            iterations - (iterations * attack_ratio) / 100);
        println!("Attack types: Port scan, SYN flood, SSH brute force");
    }
    println!("Warmup: {} operations", warmup);
    println!();

    // Generate test data
    println!("Generating test data...");
    let packets = generate_test_packets_with_attack_ratio(iterations + warmup, packet_size, attack_ratio);
    let http_requests = generate_http_requests(iterations + warmup);

    let mut results = Vec::new();

    // Benchmark each layer
    println!("\nBenchmarking layers...\n");

    let mut step = 1;
    let total_steps = 10;

    // 1. IP Filter (Stage 0)
    print!("  [{}/{}] ip_filter...", step, total_steps);
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    results.push(benchmark_ipfilter(&packets, warmup));
    println!(" done");
    step += 1;

    // 2. Flow Tracker (Stage 1)
    #[cfg(feature = "flow-tracking")]
    {
        print!("  [{}/{}] flow_tracker...", step, total_steps);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        results.push(benchmark_flow_tracker(&packets, warmup));
        println!(" done");
    }
    #[cfg(not(feature = "flow-tracking"))]
    {
        println!("  [{}/{}] flow_tracker... skipped (feature disabled)", step, total_steps);
    }
    step += 1;

    // 3. Layer234 (Stage 2)
    print!("  [{}/{}] layer234 (scan/DoS/brute)...", step, total_steps);
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    results.push(benchmark_layer234(&packets, warmup));
    println!(" done");
    step += 1;

    // 4. Protocol Analysis (Stage 4)
    #[cfg(feature = "protocols")]
    {
        print!("  [{}/{}] protocols (DNS/TLS/SSH/HTTP)...", step, total_steps);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        results.push(benchmark_protocols(&packets, warmup));
        println!(" done");
    }
    #[cfg(not(feature = "protocols"))]
    {
        println!("  [{}/{}] protocols... skipped (feature disabled)", step, total_steps);
    }
    step += 1;

    // 5. HTTP Detection (part of Protocol Analysis)
    print!("  [{}/{}] http_detect...", step, total_steps);
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    if let Some(result) = benchmark_http_detect(&http_requests, warmup) {
        results.push(result);
        println!(" done");
    } else {
        println!(" skipped");
    }
    step += 1;

    // 6. Signatures (Stage 3) - All rules
    #[cfg(feature = "signatures")]
    {
        print!("  [{}/{}] signatures (all)...", step, total_steps);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        if let Some(sig_result) = benchmark_signatures(&packets, warmup) {
            results.push(sig_result);
            println!(" done");
        } else {
            println!(" skipped (no rules)");
        }
    }
    #[cfg(not(feature = "signatures"))]
    {
        println!("  [{}/{}] signatures... skipped (feature disabled)", step, total_steps);
    }
    step += 1;

    // 7. Signatures with Hyperscan (if available)
    #[cfg(all(feature = "signatures", feature = "hyperscan"))]
    {
        print!("  [{}/{}] signatures (hyperscan)...", step, total_steps);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        if let Some(sig_result) = benchmark_signatures_hyperscan(&packets, warmup) {
            results.push(sig_result);
            println!(" done");
        } else {
            println!(" skipped (hyperscan not available)");
        }
    }
    #[cfg(not(all(feature = "signatures", feature = "hyperscan")))]
    {
        println!("  [{}/{}] signatures (hyperscan)... skipped (feature disabled)", step, total_steps);
    }
    step += 1;

    // 8. ML Detection (Stage 6)
    #[cfg(feature = "ml-detection")]
    {
        print!("  [{}/{}] ml_detect (anomaly scoring)...", step, total_steps);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        results.push(benchmark_ml_detection(&packets, warmup));
        println!(" done");
    }
    #[cfg(not(feature = "ml-detection"))]
    {
        println!("  [{}/{}] ml_detect... skipped (feature disabled)", step, total_steps);
    }
    step += 1;

    // 9. Correlation Engine (Stage 7)
    #[cfg(feature = "correlation")]
    {
        print!("  [{}/{}] correlation (incident grouping)...", step, total_steps);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        results.push(benchmark_correlation(iterations, warmup));
        println!(" done");
    }
    #[cfg(not(feature = "correlation"))]
    {
        println!("  [{}/{}] correlation... skipped (feature disabled)", step, total_steps);
    }
    step += 1;

    // 10. Signatures Filtered (high-priority only) - bonus benchmark
    #[cfg(feature = "signatures")]
    {
        print!("  [{}/{}] sig_filtered (high-priority)...", step, total_steps);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        if let Some(mut sig_result) = benchmark_signatures_filtered(&packets, warmup) {
            sig_result.name = "sig_filtered".to_string();
            results.push(sig_result);
            println!(" done");
        } else {
            println!(" skipped");
        }
    }
    #[cfg(not(feature = "signatures"))]
    {
        println!("  [{}/{}] sig_filtered... skipped", step, total_steps);
    }

    // Print results
    print_results(&results);
}
