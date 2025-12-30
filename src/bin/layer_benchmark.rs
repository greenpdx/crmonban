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
use crmonban::layer234::{Detector as Layer234Detector, DetectorBuilder as Layer234Builder, Config as Layer234Config};

#[cfg(feature = "flow-tracking")]
use crmonban::flow::{FlowTracker, FlowConfig};

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
    let mut packets = Vec::with_capacity(count);

    for i in 0..count {
        let src_ip = IpAddr::V4(Ipv4Addr::new(
            192, 168, (i / 256) as u8, (i % 256) as u8
        ));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let mut pkt = Packet::new(i as u64, src_ip, dst_ip, IpProtocol::Tcp, "eth0");
        pkt.raw_len = packet_size as u32;

        // Set TCP fields
        if let Some(tcp) = pkt.tcp_mut() {
            tcp.src_port = 50000 + (i % 10000) as u16;
            tcp.dst_port = match i % 5 {
                0 => 80,
                1 => 443,
                2 => 22,
                3 => 8080,
                _ => 3306,
            };
            tcp.flags = TcpFlags {
                syn: i % 3 == 0,
                ack: i % 3 != 0,
                fin: i % 20 == 0,
                rst: i % 50 == 0,
                psh: i % 4 == 0,
                ..Default::default()
            };
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
            "--help" | "-h" => {
                println!("Usage: layer_benchmark [OPTIONS]");
                println!();
                println!("Options:");
                println!("  -n, --iterations N    Number of operations per layer (default: 100000)");
                println!("  -s, --packet-size N   Packet size in bytes (default: 1500)");
                println!("  -h, --help            Show this help");
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
    println!("Warmup: {} operations", warmup);
    println!();

    // Generate test data
    println!("Generating test data...");
    let packets = generate_test_packets(iterations + warmup, packet_size);
    let http_requests = generate_http_requests(iterations + warmup);

    let mut results = Vec::new();

    // Benchmark each layer
    println!("\nBenchmarking layers...\n");

    // 1. IP Filter (Stage 0)
    print!("  [1/7] ip_filter...");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    results.push(benchmark_ipfilter(&packets, warmup));
    println!(" done");

    // 2. Flow Tracker (Stage 1)
    #[cfg(feature = "flow-tracking")]
    {
        print!("  [2/7] flow_tracker...");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        results.push(benchmark_flow_tracker(&packets, warmup));
        println!(" done");
    }
    #[cfg(not(feature = "flow-tracking"))]
    {
        println!("  [2/7] flow_tracker... skipped (flow-tracking feature disabled)");
    }

    // 3. Layer234 (Stage 2)
    print!("  [3/7] layer234 (scan/DoS/brute)...");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    results.push(benchmark_layer234(&packets, warmup));
    println!(" done");

    // 4. HTTP Detection (Stage 4 - Protocol Analysis)
    print!("  [4/7] http_detect...");
    std::io::Write::flush(&mut std::io::stdout()).unwrap();
    if let Some(result) = benchmark_http_detect(&http_requests, warmup) {
        results.push(result);
        println!(" done");
    } else {
        println!(" skipped");
    }

    // 5. Signatures (Stage 3) - All rules
    #[cfg(feature = "signatures")]
    {
        print!("  [5/7] signatures (all)...");
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
        println!("  [5/7] signatures... skipped (feature disabled)");
    }

    // 6. Signatures Filtered (high-priority only)
    #[cfg(feature = "signatures")]
    {
        print!("  [6/7] signatures (filtered)...");
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
        println!("  [6/7] signatures (filtered)... skipped");
    }

    // 7. Signatures with Hyperscan (if available)
    #[cfg(all(feature = "signatures", feature = "hyperscan"))]
    {
        print!("  [7/7] signatures (hyperscan)...");
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
        println!("  [7/7] signatures (hyperscan)... skipped (feature disabled)");
    }

    // Print results
    print_results(&results);
}
