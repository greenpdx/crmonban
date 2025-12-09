//! PCAP/CSV Replay Benchmark
//!
//! For packet generation only, all packet processing is in src/
//!
//! Reads real network traffic from PCAP files or CSV flow records
//! and measures actual detection pipeline performance.

use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

use clap::Parser;
use etherparse::SlicedPacket;
use pcap::Capture;

use crmonban::core::flow::Flow;
use crmonban::core::packet::{AppProtocol, IpProtocol, Packet, TcpFlags};
use crmonban::flow::{FlowConfig, FlowTracker};
use crmonban::brute_force::BruteForceTracker;
use crmonban::scan_detect::{ScanDetectEngine, ScanDetectConfig, Classification, AlertType};

#[cfg(feature = "signatures")]
use crmonban::signatures::{SignatureConfig, SignatureEngine, RuleLoader, ast::Protocol};
#[cfg(feature = "signatures")]
use crmonban::signatures::matcher::{ProtocolContext, FlowState, HttpContext, DnsContext, TlsContext};

#[cfg(feature = "protocols")]
use crmonban::protocols::{HttpConfig, TlsConfig};
#[cfg(feature = "protocols")]
use crmonban::protocols::http::HttpAnalyzer;
#[cfg(feature = "protocols")]
use crmonban::protocols::tls::TlsAnalyzer;

#[cfg(feature = "threat-intel")]
use crmonban::threat_intel::IocCache;

#[cfg(feature = "ml-detection")]
use crmonban::ml::{AnomalyDetector, Baseline, FeatureExtractor};

#[cfg(feature = "parallel")]
use crmonban::parallel::ParallelConfig;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[cfg(feature = "parallel")]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[cfg(feature = "parallel")]
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "pcap_benchmark")]
#[command(about = "Benchmark NIDS pipeline with real PCAP traffic")]
struct Args {
    /// Path to PCAP file or directory
    #[arg(short, long, default_value = "data/pcap")]
    pcap_path: PathBuf,

    /// Maximum packets to process (0 = unlimited)
    #[arg(short, long, default_value = "100000")]
    max_packets: usize,

    /// Enable flow tracking
    #[arg(long, default_value = "true")]
    flow: bool,

    /// Enable signature matching
    #[arg(long)]
    signatures: bool,

    /// Enable threat intel lookup
    #[arg(long)]
    threat_intel: bool,

    /// Enable ML detection
    #[arg(long)]
    ml: bool,

    /// Enable all features
    #[arg(long)]
    all: bool,

    /// Warmup packets before measuring
    #[arg(long, default_value = "1000")]
    warmup: usize,

    /// Path to CSV file or directory (NetFlow v3 format)
    #[arg(short, long)]
    csv_path: Option<PathBuf>,

    /// Enable parallel processing
    #[arg(long)]
    parallel: bool,

    /// Number of threads for parallel processing (0 = auto-detect)
    #[arg(long, default_value = "0")]
    threads: usize,

    /// Batch size for parallel processing
    #[arg(long, default_value = "1000")]
    batch_size: usize,
}

/// NetFlow v3 CSV record (NF-ToN-IoT format)
#[derive(Debug, Clone)]
struct CsvFlowRecord {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    l7_proto: u16,
    in_bytes: u64,
    in_pkts: u64,
    out_bytes: u64,
    out_pkts: u64,
    tcp_flags: u8,
    flow_duration_ms: u64,
    label: String,
    attack: String,
}

impl CsvFlowRecord {
    /// Parse a CSV line into a flow record
    fn from_csv_line(line: &str, header_map: &std::collections::HashMap<String, usize>) -> Option<Self> {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 10 {
            return None;
        }

        let get_field = |name: &str| -> Option<&str> {
            header_map.get(name).and_then(|&idx| fields.get(idx).copied())
        };

        let src_ip = get_field("IPV4_SRC_ADDR")
            .and_then(|s| Ipv4Addr::from_str(s).ok())
            .map(IpAddr::V4)?;
        let dst_ip = get_field("IPV4_DST_ADDR")
            .and_then(|s| Ipv4Addr::from_str(s).ok())
            .map(IpAddr::V4)?;
        let src_port = get_field("L4_SRC_PORT")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let dst_port = get_field("L4_DST_PORT")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let protocol = get_field("PROTOCOL")
            .and_then(|s| s.parse().ok())
            .unwrap_or(6);
        let l7_proto = get_field("L7_PROTO")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let in_bytes = get_field("IN_BYTES")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let in_pkts = get_field("IN_PKTS")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let out_bytes = get_field("OUT_BYTES")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let out_pkts = get_field("OUT_PKTS")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let tcp_flags = get_field("TCP_FLAGS")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let flow_duration_ms = get_field("FLOW_DURATION_MILLISECONDS")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let label = get_field("Label")
            .unwrap_or("Unknown")
            .to_string();
        let attack = get_field("Attack")
            .unwrap_or("")
            .to_string();

        Some(Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            l7_proto,
            in_bytes,
            in_pkts,
            out_bytes,
            out_pkts,
            tcp_flags,
            flow_duration_ms,
            label,
            attack,
        })
    }

    /// Convert to a Packet for processing through the pipeline
    fn to_packet(&self) -> Packet {
        let protocol = match self.protocol {
            6 => IpProtocol::Tcp,
            17 => IpProtocol::Udp,
            1 => IpProtocol::Icmp,
            58 => IpProtocol::Icmpv6,
            other => IpProtocol::Other(other),
        };

        let mut pkt = Packet::new(self.src_ip, self.dst_ip, protocol);
        // Set ports and flags via layer access
        if let Some(tcp) = pkt.tcp_mut() {
            tcp.src_port = self.src_port;
            tcp.dst_port = self.dst_port;
            if self.protocol == 6 {
                tcp.flags = TcpFlags {
                    syn: (self.tcp_flags & 0x02) != 0,
                    ack: (self.tcp_flags & 0x10) != 0,
                    fin: (self.tcp_flags & 0x01) != 0,
                    rst: (self.tcp_flags & 0x04) != 0,
                    psh: (self.tcp_flags & 0x08) != 0,
                    urg: (self.tcp_flags & 0x20) != 0,
                    ece: false,
                    cwr: false,
                };
            }
        } else if let Some(udp) = pkt.udp_mut() {
            udp.src_port = self.src_port;
            udp.dst_port = self.dst_port;
        }
        pkt.raw_len = (self.in_bytes / self.in_pkts.max(1)) as u32;

        // Detect app protocol from port
        pkt.app_protocol = match (self.src_port, self.dst_port) {
            (80, _) | (_, 80) | (8080, _) | (_, 8080) => AppProtocol::Http,
            (443, _) | (_, 443) | (8443, _) | (_, 8443) => AppProtocol::Https,
            (22, _) | (_, 22) => AppProtocol::Ssh,
            (21, _) | (_, 21) => AppProtocol::Ftp,
            (25, _) | (_, 25) | (587, _) | (_, 587) => AppProtocol::Smtp,
            (53, _) | (_, 53) => AppProtocol::Dns,
            _ => AppProtocol::Unknown,
        };

        pkt
    }
}

/// Simple timing accumulator
#[derive(Debug, Default, Clone)]
struct TimingStats {
    count: u64,
    sum_ns: u64,
    min_ns: u64,
    max_ns: u64,
}

impl TimingStats {
    fn new() -> Self {
        Self {
            count: 0,
            sum_ns: 0,
            min_ns: u64::MAX,
            max_ns: 0,
        }
    }

    fn record(&mut self, duration: Duration) {
        let ns = duration.as_nanos() as u64;
        self.count += 1;
        self.sum_ns += ns;
        if ns < self.min_ns { self.min_ns = ns; }
        if ns > self.max_ns { self.max_ns = ns; }
    }

    fn mean_ns(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.sum_ns as f64 / self.count as f64 }
    }

    fn mean_us(&self) -> f64 {
        self.mean_ns() / 1000.0
    }
}

/// Per-component timing results
#[derive(Debug, Default)]
struct ComponentTimings {
    parse: TimingStats,
    flow: TimingStats,
    signatures: TimingStats,
    threat_intel: TimingStats,
    ml_features: TimingStats,
    ml_score: TimingStats,
    total: TimingStats,
}

impl ComponentTimings {
    fn new() -> Self {
        Self {
            parse: TimingStats::new(),
            flow: TimingStats::new(),
            signatures: TimingStats::new(),
            threat_intel: TimingStats::new(),
            ml_features: TimingStats::new(),
            ml_score: TimingStats::new(),
            total: TimingStats::new(),
        }
    }
}

/// Label statistics for CSV benchmark
#[derive(Debug, Default)]
struct LabelStats {
    counts: std::collections::HashMap<String, usize>,
    attack_counts: std::collections::HashMap<String, usize>,
}

impl LabelStats {
    fn new() -> Self {
        Self {
            counts: std::collections::HashMap::new(),
            attack_counts: std::collections::HashMap::new(),
        }
    }

    fn record(&mut self, label: &str, attack: &str) {
        // Use attack name if available, otherwise use label
        let display_label = if !attack.is_empty() { attack } else { label };
        *self.counts.entry(display_label.to_string()).or_insert(0) += 1;
        if !attack.is_empty() && attack != "Benign" {
            *self.attack_counts.entry(attack.to_string()).or_insert(0) += 1;
        }
    }
}

/// Detection statistics for accuracy metrics
#[derive(Debug, Default)]
struct DetectionStats {
    // Signature detections
    signature_matches: usize,

    // ML detections
    ml_anomalies: usize,
    ml_scores_sum: f64,

    // Port scan detections
    scan_alerts: usize,
    targeted_scan_alerts: usize,

    // Brute force detections
    brute_force_alerts: usize,

    // Confusion matrix (combined signature + ML)
    true_positives: usize,   // Attack correctly detected
    false_positives: usize,  // Benign incorrectly flagged
    true_negatives: usize,   // Benign correctly passed
    false_negatives: usize,  // Attack missed

    // Debug stats
    packets_with_payload: usize,
    total_payload_bytes: usize,
}

impl DetectionStats {
    fn new() -> Self {
        Self::default()
    }

    fn record_detection(&mut self, detected: bool, is_actually_attack: bool, ml_score: f32, sig_matches: usize) {
        if sig_matches > 0 {
            self.signature_matches += 1;
        }
        if ml_score >= 0.5 {
            self.ml_anomalies += 1;
        }
        self.ml_scores_sum += ml_score as f64;

        match (detected, is_actually_attack) {
            (true, true) => self.true_positives += 1,
            (true, false) => self.false_positives += 1,
            (false, true) => self.false_negatives += 1,
            (false, false) => self.true_negatives += 1,
        }
    }

    fn precision(&self) -> f64 {
        let tp_fp = self.true_positives + self.false_positives;
        if tp_fp == 0 { 0.0 } else { self.true_positives as f64 / tp_fp as f64 }
    }

    fn recall(&self) -> f64 {
        let tp_fn = self.true_positives + self.false_negatives;
        if tp_fn == 0 { 0.0 } else { self.true_positives as f64 / tp_fn as f64 }
    }

    fn f1_score(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 { 0.0 } else { 2.0 * p * r / (p + r) }
    }

    fn accuracy(&self) -> f64 {
        let total = self.true_positives + self.true_negatives + self.false_positives + self.false_negatives;
        if total == 0 { 0.0 } else { (self.true_positives + self.true_negatives) as f64 / total as f64 }
    }

    fn avg_ml_score(&self, total: usize) -> f64 {
        if total == 0 { 0.0 } else { self.ml_scores_sum / total as f64 }
    }
}

/// Benchmark runner
struct PcapBenchmark {
    args: Args,
    timings: ComponentTimings,
    packets_processed: usize,
    bytes_processed: u64,
    flows_processed: usize,
    label_stats: LabelStats,
    detection_stats: DetectionStats,

    // Components
    flow_tracker: Option<FlowTracker>,
    scan_detect_engine: ScanDetectEngine,
    brute_force_tracker: BruteForceTracker,
    #[cfg(feature = "signatures")]
    signature_engine: Option<SignatureEngine>,
    #[cfg(feature = "threat-intel")]
    ioc_cache: Option<IocCache>,
    #[cfg(feature = "ml-detection")]
    feature_extractor: Option<FeatureExtractor>,
    #[cfg(feature = "ml-detection")]
    anomaly_detector: Option<AnomalyDetector>,
    #[cfg(feature = "ml-detection")]
    baseline: Option<Baseline>,
    #[cfg(feature = "protocols")]
    http_analyzer: Option<HttpAnalyzer>,
    #[cfg(feature = "protocols")]
    tls_analyzer: Option<TlsAnalyzer>,
}

impl PcapBenchmark {
    fn new(args: Args) -> Self {
        let enable_all = args.all;

        // Initialize flow tracker
        let flow_tracker = if args.flow || enable_all {
            Some(FlowTracker::new(FlowConfig::default()))
        } else {
            None
        };

        // Initialize signature engine
        #[cfg(feature = "signatures")]
        let signature_engine = if args.signatures || enable_all {
            let mut config = SignatureConfig::default();
            // Add ET Open rules directory
            let rules_dir = PathBuf::from("/var/lib/crmonban/data/signatures/suricata/rules");
            if rules_dir.exists() {
                config.rule_dirs = vec![rules_dir.clone()];
                println!("Loading rules from: {:?}", rules_dir);
            }

            let mut engine = SignatureEngine::new(config.clone());

            // Load rules
            let mut loader = RuleLoader::new(config);
            match loader.load_all() {
                Ok(ruleset) => {
                    println!("Loaded {} rules ({} enabled, {} with content patterns)",
                        ruleset.stats.total_rules,
                        ruleset.stats.total_rules - ruleset.stats.disabled,
                        ruleset.stats.with_content);
                    // Add rules to engine
                    for (_, rule) in ruleset.rules {
                        engine.add_rule(rule);
                    }
                    engine.rebuild_prefilter();
                    println!("Prefilter patterns: {}", engine.prefilter_pattern_count());
                }
                Err(e) => {
                    eprintln!("Warning: Failed to load rules: {}", e);
                }
            }

            Some(engine)
        } else {
            None
        };

        // Initialize threat intel cache
        #[cfg(feature = "threat-intel")]
        let ioc_cache = if args.threat_intel || enable_all {
            Some(IocCache::new())
        } else {
            None
        };

        // Initialize ML components
        #[cfg(feature = "ml-detection")]
        let (feature_extractor, anomaly_detector, baseline) = if args.ml || enable_all {
            (
                Some(FeatureExtractor::new()),
                Some(AnomalyDetector::default()),
                Some(Baseline::new()),
            )
        } else {
            (None, None, None)
        };

        // Initialize protocol analyzers
        #[cfg(feature = "protocols")]
        let (http_analyzer, tls_analyzer) = if enable_all {
            let mut http_config = HttpConfig::default();
            http_config.extract_headers = true;
            let mut tls_config = TlsConfig::default();
            tls_config.ja3_enabled = true;
            (
                Some(HttpAnalyzer::new(http_config)),
                Some(TlsAnalyzer::new(tls_config)),
            )
        } else {
            (None, None)
        };

        Self {
            args,
            timings: ComponentTimings::new(),
            packets_processed: 0,
            bytes_processed: 0,
            flows_processed: 0,
            label_stats: LabelStats::new(),
            detection_stats: DetectionStats::new(),
            flow_tracker,
            scan_detect_engine: ScanDetectEngine::new(ScanDetectConfig::default()),
            brute_force_tracker: BruteForceTracker::new(),
            #[cfg(feature = "signatures")]
            signature_engine,
            #[cfg(feature = "threat-intel")]
            ioc_cache,
            #[cfg(feature = "ml-detection")]
            feature_extractor,
            #[cfg(feature = "ml-detection")]
            anomaly_detector,
            #[cfg(feature = "ml-detection")]
            baseline,
            #[cfg(feature = "protocols")]
            http_analyzer,
            #[cfg(feature = "protocols")]
            tls_analyzer,
        }
    }

    /// Parse HTTP from payload
    #[cfg(feature = "protocols")]
    fn parse_http(&self, payload: &[u8]) -> Option<(Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>)> {
        if let Some(ref analyzer) = self.http_analyzer {
            if let Some(request) = analyzer.parse_request(payload) {
                let method = Some(request.method.as_bytes().to_vec());
                let uri = Some(request.uri.as_bytes().to_vec());
                let host = request.host.map(|h| h.as_bytes().to_vec());
                let user_agent = request.user_agent.map(|ua| ua.as_bytes().to_vec());
                // Build headers buffer
                let headers = {
                    let mut buf = Vec::new();
                    for (name, value) in &request.headers {
                        buf.extend_from_slice(name.as_bytes());
                        buf.extend_from_slice(b": ");
                        buf.extend_from_slice(value.as_bytes());
                        buf.extend_from_slice(b"\r\n");
                    }
                    if !buf.is_empty() { Some(buf) } else { None }
                };
                return Some((method, uri, host, user_agent, headers));
            }
        }
        None
    }

    /// Parse TLS ClientHello from payload
    #[cfg(feature = "protocols")]
    fn parse_tls(&self, payload: &[u8]) -> Option<(Option<Vec<u8>>, Option<String>)> {
        if let Some(ref analyzer) = self.tls_analyzer {
            // TLS record: type (1) + version (2) + length (2) + handshake data
            if payload.len() >= 5 && payload[0] == 22 { // Handshake record
                let length = u16::from_be_bytes([payload[3], payload[4]]) as usize;
                if payload.len() >= 5 + length {
                    let handshake_data = &payload[5..5 + length];
                    if !handshake_data.is_empty() && handshake_data[0] == 1 { // ClientHello
                        // Parse SNI from ClientHello extensions
                        if let Some(sni) = self.parse_sni(handshake_data) {
                            let ja3 = self.compute_ja3_simple(handshake_data);
                            return Some((Some(sni.as_bytes().to_vec()), ja3));
                        }
                    }
                }
            }
        }
        None
    }

    /// Parse SNI from ClientHello handshake data
    #[cfg(feature = "protocols")]
    fn parse_sni(&self, data: &[u8]) -> Option<String> {
        if data.len() < 38 { return None; }
        let mut offset = 38; // Skip past fixed fields

        // Session ID
        if offset >= data.len() { return None; }
        let session_id_len = data[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher suites
        if offset + 2 > data.len() { return None; }
        let cipher_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2 + cipher_len;

        // Compression
        if offset >= data.len() { return None; }
        let comp_len = data[offset] as usize;
        offset += 1 + comp_len;

        // Extensions
        if offset + 2 > data.len() { return None; }
        let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        let ext_end = offset + ext_len;
        while offset + 4 <= ext_end && offset + 4 <= data.len() {
            let ext_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let ext_data_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if ext_type == 0 && offset + ext_data_len <= data.len() { // SNI extension
                // SNI list length (2) + type (1) + name length (2) + name
                if ext_data_len >= 5 {
                    let name_len = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;
                    if offset + 5 + name_len <= data.len() {
                        return String::from_utf8(data[offset + 5..offset + 5 + name_len].to_vec()).ok();
                    }
                }
            }
            offset += ext_data_len;
        }
        None
    }

    /// Compute simple JA3 hash
    #[cfg(feature = "protocols")]
    fn compute_ja3_simple(&self, _data: &[u8]) -> Option<String> {
        // For now, just return None - full JA3 computation is complex
        // The TLS analyzer already does this properly
        None
    }

    /// Parse raw packet bytes into our Packet struct
    fn parse_packet(&self, data: &[u8]) -> Option<Packet> {
        match SlicedPacket::from_ethernet(data) {
            Ok(sliced) => {
                let (src_ip, dst_ip, protocol) = match &sliced.net {
                    Some(etherparse::NetSlice::Ipv4(ipv4)) => {
                        let header = ipv4.header();
                        let src = IpAddr::V4(header.source_addr());
                        let dst = IpAddr::V4(header.destination_addr());
                        let proto = match header.protocol().0 {
                            6 => IpProtocol::Tcp,
                            17 => IpProtocol::Udp,
                            1 => IpProtocol::Icmp,
                            other => IpProtocol::Other(other),
                        };
                        (src, dst, proto)
                    }
                    Some(etherparse::NetSlice::Ipv6(ipv6)) => {
                        let header = ipv6.header();
                        let src = IpAddr::V6(header.source_addr());
                        let dst = IpAddr::V6(header.destination_addr());
                        let proto = match header.next_header().0 {
                            6 => IpProtocol::Tcp,
                            17 => IpProtocol::Udp,
                            58 => IpProtocol::Icmpv6,
                            other => IpProtocol::Other(other),
                        };
                        (src, dst, proto)
                    }
                    None => return None,
                    _ => return None, // ARP and other non-IP packets
                };

                let mut pkt = Packet::new(src_ip, dst_ip, protocol);
                pkt.raw_len = data.len() as u32;

                // Extract transport layer info
                match &sliced.transport {
                    Some(etherparse::TransportSlice::Tcp(tcp)) => {
                        if let Some(tcp_info) = pkt.tcp_mut() {
                            tcp_info.src_port = tcp.source_port();
                            tcp_info.dst_port = tcp.destination_port();
                            tcp_info.seq = tcp.sequence_number();
                            tcp_info.ack = tcp.acknowledgment_number();
                            tcp_info.flags = TcpFlags {
                                syn: tcp.syn(),
                                ack: tcp.ack(),
                                fin: tcp.fin(),
                                rst: tcp.rst(),
                                psh: tcp.psh(),
                                urg: tcp.urg(),
                                ece: tcp.ece(),
                                cwr: tcp.cwr(),
                            };
                            tcp_info.payload = tcp.payload().to_vec();
                        }

                        // Detect app protocol from port
                        pkt.app_protocol = match (pkt.src_port(), pkt.dst_port()) {
                            (80, _) | (_, 80) | (8080, _) | (_, 8080) => AppProtocol::Http,
                            (443, _) | (_, 443) | (8443, _) | (_, 8443) => AppProtocol::Https,
                            (22, _) | (_, 22) => AppProtocol::Ssh,
                            (21, _) | (_, 21) => AppProtocol::Ftp,
                            (25, _) | (_, 25) | (587, _) | (_, 587) => AppProtocol::Smtp,
                            (53, _) | (_, 53) => AppProtocol::Dns,
                            _ => AppProtocol::Unknown,
                        };
                    }
                    Some(etherparse::TransportSlice::Udp(udp)) => {
                        if let Some(udp_info) = pkt.udp_mut() {
                            udp_info.src_port = udp.source_port();
                            udp_info.dst_port = udp.destination_port();
                            udp_info.payload = udp.payload().to_vec();
                        }

                        pkt.app_protocol = match (pkt.src_port(), pkt.dst_port()) {
                            (53, _) | (_, 53) => AppProtocol::Dns,
                            (123, _) | (_, 123) => AppProtocol::Ntp,
                            _ => AppProtocol::Unknown,
                        };
                    }
                    _ => {}
                }

                Some(pkt)
            }
            Err(_) => None,
        }
    }

    /// Process a single packet through the pipeline
    fn process_packet(&mut self, data: &[u8], warmup: bool) {
        let total_start = Instant::now();

        // Parse packet
        let parse_start = Instant::now();
        let pkt = match self.parse_packet(data) {
            Some(p) => p,
            None => return,
        };
        let parse_time = parse_start.elapsed();

        self.bytes_processed += pkt.raw_len as u64;

        // Parse HTTP/TLS before flow tracking to avoid borrow conflicts
        #[cfg(feature = "protocols")]
        let (http_method, http_uri, http_host, http_user_agent, http_headers) =
            if !pkt.payload().is_empty() && (pkt.dst_port() == 80 || pkt.dst_port() == 8080 || pkt.src_port() == 80 || pkt.src_port() == 8080) {
                self.parse_http(&pkt.payload()).unwrap_or((None, None, None, None, None))
            } else {
                (None, None, None, None, None)
            };
        #[cfg(not(feature = "protocols"))]
        let (http_method, http_uri, http_host, http_user_agent, http_headers): (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>) = (None, None, None, None, None);

        #[cfg(feature = "protocols")]
        let (tls_sni, ja3_hash) =
            if !pkt.payload().is_empty() && (pkt.dst_port() == 443 || pkt.dst_port() == 8443 || pkt.src_port() == 443 || pkt.src_port() == 8443) {
                self.parse_tls(&pkt.payload()).unwrap_or((None, None))
            } else {
                (None, None)
            };
        #[cfg(not(feature = "protocols"))]
        let (tls_sni, ja3_hash): (Option<Vec<u8>>, Option<String>) = (None, None);

        // Flow tracking
        let mut flow_time = Duration::ZERO;
        let mut _flow_ref: Option<&Flow> = None;
        if let Some(ref mut tracker) = self.flow_tracker {
            let start = Instant::now();
            let mut pkt_mut = pkt.clone();
            let (flow, _direction) = tracker.process(&mut pkt_mut);
            _flow_ref = Some(flow);
            flow_time = start.elapsed();
        }

        // Signature matching
        #[allow(unused_mut)]
        let mut sig_time = Duration::ZERO;
        #[allow(unused_mut)]
        let mut sig_match_count: usize = 0;
        #[cfg(feature = "signatures")]
        if let Some(ref engine) = self.signature_engine {
            let start = Instant::now();

            // Build protocol context based on parsed data
            let proto_ctx = if http_uri.is_some() || http_method.is_some() {
                ProtocolContext::Http(HttpContext {
                    uri: http_uri,
                    method: http_method,
                    headers: http_headers,
                    host: http_host,
                    user_agent: http_user_agent,
                })
            } else if tls_sni.is_some() || ja3_hash.is_some() {
                ProtocolContext::Tls(TlsContext {
                    sni: tls_sni,
                    ja3_hash,
                })
            } else {
                ProtocolContext::None
            };

            let flow_state = FlowState {
                established: false,
                to_server: true,
            };

            let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
            sig_match_count = matches.len();
            sig_time = start.elapsed();
        }

        // Threat intel lookup
        #[allow(unused_mut)]
        let mut intel_time = Duration::ZERO;
        #[cfg(feature = "threat-intel")]
        if let Some(ref cache) = self.ioc_cache {
            let start = Instant::now();
            let _src_match = cache.check_ip(&pkt.src_ip());
            let _dst_match = cache.check_ip(&pkt.dst_ip());
            intel_time = start.elapsed();
        }

        // ML feature extraction and scoring
        #[allow(unused_mut)]
        let mut ml_feat_time = Duration::ZERO;
        #[allow(unused_mut)]
        let mut ml_score_time = Duration::ZERO;
        #[allow(unused_mut)]
        let mut ml_anomaly_score: f32 = 0.0;
        #[cfg(feature = "ml-detection")]
        if self.feature_extractor.is_some() && _flow_ref.is_some() {
            let flow = _flow_ref.unwrap();
            let feat_start = Instant::now();
            let features = self.feature_extractor.as_mut().unwrap().extract(flow);
            ml_feat_time = feat_start.elapsed();

            let score_start = Instant::now();
            if let Some(ref baseline) = self.baseline {
                let score = self.anomaly_detector.as_ref().unwrap().score(&features, baseline);
                ml_anomaly_score = score.score;
            }
            ml_score_time = score_start.elapsed();
        }

        // Port scan tracking - detect when a source touches many different destination ports
        let scan_alert = self.scan_detect_engine.process(&pkt);

        // Brute force tracking - detect repeated failed login attempts
        let is_syn = pkt.tcp_flags().as_ref().map(|f| f.syn && !f.ack).unwrap_or(false);
        let is_fin = pkt.tcp_flags().as_ref().map(|f| f.fin).unwrap_or(false);
        let is_rst = pkt.tcp_flags().as_ref().map(|f| f.rst).unwrap_or(false);
        let brute_force_alert = if is_syn {
            // Session start
            self.brute_force_tracker.session_start(pkt.src_ip(), pkt.dst_ip(), pkt.dst_port());
            None
        } else if is_fin || is_rst {
            // Session end - check for brute force pattern
            self.brute_force_tracker.session_end(pkt.src_ip(), pkt.dst_ip(), pkt.dst_port(), is_rst)
        } else {
            // Track packet in session
            self.brute_force_tracker.session_packet(pkt.src_ip(), pkt.dst_ip(), pkt.dst_port(), pkt.payload().len());
            None
        };

        let total_time = total_start.elapsed();

        // Record timings and detection stats (skip warmup)
        if !warmup {
            self.packets_processed += 1;
            self.timings.parse.record(parse_time);
            self.timings.flow.record(flow_time);
            self.timings.signatures.record(sig_time);
            self.timings.threat_intel.record(intel_time);
            self.timings.ml_features.record(ml_feat_time);
            self.timings.ml_score.record(ml_score_time);
            self.timings.total.record(total_time);

            // Track signature matches (no ground truth for PCAP, just count)
            if sig_match_count > 0 {
                self.detection_stats.signature_matches += 1;
            }
            if ml_anomaly_score >= 0.5 {
                self.detection_stats.ml_anomalies += 1;
            }
            self.detection_stats.ml_scores_sum += ml_anomaly_score as f64;

            // Track port scan alerts
            if let Some(ref alert) = scan_alert {
                self.detection_stats.scan_alerts += 1;
                // Consider ConfirmedScan or LikelyAttack as targeted
                if matches!(alert.classification, Classification::ConfirmedScan | Classification::LikelyAttack) {
                    self.detection_stats.targeted_scan_alerts += 1;
                }
            }

            // Track brute force alerts
            if brute_force_alert.is_some() {
                self.detection_stats.brute_force_alerts += 1;
            }

            // Track payload stats
            if !pkt.payload().is_empty() {
                self.detection_stats.packets_with_payload += 1;
                self.detection_stats.total_payload_bytes += pkt.payload().len();
            }
        }
    }

    /// Run benchmark on PCAP file(s)
    fn run(&mut self) -> anyhow::Result<()> {
        let path = &self.args.pcap_path;

        // Collect PCAP files
        let pcap_files: Vec<PathBuf> = if path.is_file() {
            vec![path.clone()]
        } else if path.is_dir() {
            fs::read_dir(path)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .map(|e| e == "pcap" || e == "pcapng")
                        .unwrap_or(false)
                })
                .collect()
        } else {
            println!("No PCAP files found at {:?}", path);
            println!("Waiting for downloads to complete...");
            println!("Check: tail -f data/pcap/download.log");
            return Ok(());
        };

        if pcap_files.is_empty() {
            println!("No PCAP files found at {:?}", path);
            println!("Downloads may still be in progress.");
            println!("Check: ls -la data/pcap/");
            return Ok(());
        }

        println!("PCAP Replay Benchmark");
        println!("=====================");
        println!("Files: {:?}", pcap_files.iter().map(|p| p.file_name().unwrap()).collect::<Vec<_>>());
        println!("Max packets: {}", if self.args.max_packets == 0 { "unlimited".to_string() } else { self.args.max_packets.to_string() });
        println!("Warmup: {} packets", self.args.warmup);
        println!();
        println!("Features enabled:");
        println!("  Flow tracking: {}", self.flow_tracker.is_some());
        #[cfg(feature = "signatures")]
        println!("  Signatures: {}", self.signature_engine.is_some());
        #[cfg(feature = "threat-intel")]
        println!("  Threat intel: {}", self.ioc_cache.is_some());
        #[cfg(feature = "ml-detection")]
        println!("  ML detection: {}", self.feature_extractor.is_some());
        println!();

        let start = Instant::now();
        let mut total_packets = 0usize;

        for pcap_file in pcap_files {
            println!("Processing {:?}...", pcap_file.file_name().unwrap());

            let mut cap = Capture::from_file(&pcap_file)?;

            while let Ok(packet) = cap.next_packet() {
                let is_warmup = total_packets < self.args.warmup;
                self.process_packet(packet.data, is_warmup);
                total_packets += 1;

                if self.args.max_packets > 0 && total_packets >= self.args.max_packets + self.args.warmup {
                    break;
                }

                // Progress indicator
                if total_packets % 10000 == 0 {
                    print!("\r  {} packets processed...", total_packets);
                    std::io::Write::flush(&mut std::io::stdout())?;
                }
            }
            println!();

            if self.args.max_packets > 0 && total_packets >= self.args.max_packets + self.args.warmup {
                break;
            }
        }

        let elapsed = start.elapsed();

        // Print results
        self.print_results(elapsed);

        Ok(())
    }

    /// Run benchmark with parallel processing
    #[cfg(feature = "parallel")]
    fn run_parallel(&mut self) -> anyhow::Result<()> {
        let path = &self.args.pcap_path;
        let batch_size = self.args.batch_size;
        let num_threads = if self.args.threads == 0 {
            num_cpus::get()
        } else {
            self.args.threads
        };

        // Initialize rayon thread pool
        rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build_global()
            .ok(); // Ignore if already initialized

        // Collect PCAP files
        let pcap_files: Vec<PathBuf> = if path.is_file() {
            vec![path.clone()]
        } else if path.is_dir() {
            fs::read_dir(path)?
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .map(|e| e == "pcap" || e == "pcapng")
                        .unwrap_or(false)
                })
                .collect()
        } else {
            println!("No PCAP files found at {:?}", path);
            return Ok(());
        };

        if pcap_files.is_empty() {
            println!("No PCAP files found at {:?}", path);
            return Ok(());
        }

        println!("PCAP Replay Benchmark (PARALLEL)");
        println!("=================================");
        println!("Files: {:?}", pcap_files.iter().map(|p| p.file_name().unwrap()).collect::<Vec<_>>());
        println!("Max packets: {}", if self.args.max_packets == 0 { "unlimited".to_string() } else { self.args.max_packets.to_string() });
        println!("Warmup: {} packets", self.args.warmup);
        println!("Threads: {}", num_threads);
        println!("Batch size: {}", batch_size);
        println!();
        println!("Features enabled:");
        println!("  Flow tracking: {}", self.flow_tracker.is_some());
        #[cfg(feature = "signatures")]
        println!("  Signatures: {}", self.signature_engine.is_some());
        println!();

        // Thread-safe counters
        let packets_processed = Arc::new(AtomicU64::new(0));
        let bytes_processed = Arc::new(AtomicU64::new(0));
        let signature_matches = Arc::new(AtomicU64::new(0));
        let packets_with_payload = Arc::new(AtomicU64::new(0));
        let total_payload_bytes = Arc::new(AtomicU64::new(0));

        let start = Instant::now();
        let mut total_raw_packets = 0usize;

        for pcap_file in pcap_files {
            println!("Processing {:?}...", pcap_file.file_name().unwrap());

            let mut cap = Capture::from_file(&pcap_file)?;
            let mut batch: Vec<Vec<u8>> = Vec::with_capacity(batch_size);

            while let Ok(packet) = cap.next_packet() {
                // Skip warmup packets
                if total_raw_packets < self.args.warmup {
                    total_raw_packets += 1;
                    continue;
                }

                batch.push(packet.data.to_vec());
                total_raw_packets += 1;

                // Process batch when full
                if batch.len() >= batch_size {
                    self.process_batch_parallel(
                        &batch,
                        &packets_processed,
                        &bytes_processed,
                        &signature_matches,
                        &packets_with_payload,
                        &total_payload_bytes,
                    );
                    batch.clear();

                    // Progress indicator
                    let processed = packets_processed.load(Ordering::Relaxed);
                    if processed % 10000 < batch_size as u64 {
                        print!("\r  {} packets processed...", processed);
                        std::io::Write::flush(&mut std::io::stdout())?;
                    }
                }

                if self.args.max_packets > 0 && packets_processed.load(Ordering::Relaxed) >= self.args.max_packets as u64 {
                    break;
                }
            }

            // Process remaining packets
            if !batch.is_empty() {
                self.process_batch_parallel(
                    &batch,
                    &packets_processed,
                    &bytes_processed,
                    &signature_matches,
                    &packets_with_payload,
                    &total_payload_bytes,
                );
            }
            println!();

            if self.args.max_packets > 0 && packets_processed.load(Ordering::Relaxed) >= self.args.max_packets as u64 {
                break;
            }
        }

        let elapsed = start.elapsed();

        // Update self stats from atomics for print_results
        self.packets_processed = packets_processed.load(Ordering::Relaxed) as usize;
        self.bytes_processed = bytes_processed.load(Ordering::Relaxed);
        self.detection_stats.signature_matches = signature_matches.load(Ordering::Relaxed) as usize;
        self.detection_stats.packets_with_payload = packets_with_payload.load(Ordering::Relaxed) as usize;
        self.detection_stats.total_payload_bytes = total_payload_bytes.load(Ordering::Relaxed) as usize;

        // Print results
        self.print_results(elapsed);
        println!();
        println!("Parallel processing: {} threads, batch size {}", num_threads, batch_size);

        Ok(())
    }

    /// Process a batch of packets in parallel
    #[cfg(feature = "parallel")]
    fn process_batch_parallel(
        &self,
        batch: &[Vec<u8>],
        packets_processed: &Arc<AtomicU64>,
        bytes_processed: &Arc<AtomicU64>,
        signature_matches: &Arc<AtomicU64>,
        packets_with_payload: &Arc<AtomicU64>,
        total_payload_bytes: &Arc<AtomicU64>,
    ) {
        // Parse all packets in parallel
        let parsed: Vec<_> = batch.par_iter()
            .filter_map(|data| self.parse_packet(data))
            .collect();

        // Update byte counter
        let total_bytes: u64 = parsed.iter().map(|p| p.raw_len as u64).sum();
        bytes_processed.fetch_add(total_bytes, Ordering::Relaxed);
        packets_processed.fetch_add(parsed.len() as u64, Ordering::Relaxed);

        // Count payload stats
        let payload_count: u64 = parsed.iter().filter(|p| !p.payload().is_empty()).count() as u64;
        let payload_bytes: u64 = parsed.iter().map(|p| p.payload().len() as u64).sum();
        packets_with_payload.fetch_add(payload_count, Ordering::Relaxed);
        total_payload_bytes.fetch_add(payload_bytes, Ordering::Relaxed);

        // Signature matching in parallel (using new API)
        #[cfg(feature = "signatures")]
        if let Some(ref engine) = self.signature_engine {
            // Match all packets in parallel using new API
            let match_count: u64 = parsed.par_iter()
                .map(|pkt| {
                    let proto_ctx = ProtocolContext::None;
                    let flow_state = FlowState {
                        established: false,
                        to_server: true,
                    };
                    engine.match_packet(pkt, &proto_ctx, &flow_state)
                })
                .filter(|matches| !matches.is_empty())
                .count() as u64;
            signature_matches.fetch_add(match_count, Ordering::Relaxed);
        }
    }

    fn print_results(&self, elapsed: Duration) {
        println!();
        println!("════════════════════════════════════════════════════════════════════════════════");
        println!("                           PCAP BENCHMARK RESULTS");
        println!("════════════════════════════════════════════════════════════════════════════════");
        println!();
        println!("Total packets:     {:>12}", self.packets_processed);
        println!("Total bytes:       {:>12} ({:.2} MB)", self.bytes_processed, self.bytes_processed as f64 / 1_000_000.0);
        println!("Total time:        {:>12.2?}", elapsed);
        println!("Throughput:        {:>12.0} pkt/s", self.packets_processed as f64 / elapsed.as_secs_f64());
        println!("Throughput:        {:>12.2} Mbps", (self.bytes_processed as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0);

        // Print detection results
        println!();
        println!("────────────────────────────────────────────────────────────────────────────────");
        println!("                        DETECTION RESULTS");
        println!("────────────────────────────────────────────────────────────────────────────────");
        let d = &self.detection_stats;
        println!("Signature matches:  {:>10} ({:.2}% of packets)",
            d.signature_matches,
            d.signature_matches as f64 / self.packets_processed as f64 * 100.0);
        println!("ML anomalies:       {:>10} (score >= 0.5)", d.ml_anomalies);
        println!("Avg ML score:       {:>10.4}", d.avg_ml_score(self.packets_processed));
        println!();
        println!("Port Scan Detection:");
        println!("  Scan alerts:          {:>8} (sources touching 10+ ports)", d.scan_alerts);
        println!("  Targeted scans:       {:>8} (>50% commonly targeted ports)", d.targeted_scan_alerts);
        // Show top scanners
        let top_scanners = self.scan_detect_engine.top_scanners(5);
        if !top_scanners.is_empty() {
            println!("  Top suspicious sources:");
            for (ip, score, classification) in top_scanners.iter().take(5) {
                if *score >= 3.0 {
                    println!("    {} -> score={:.1} ({:?})", ip, score, classification);
                }
            }
        }
        println!();
        println!("Brute Force Detection:");
        println!("  Brute force alerts:   {:>8} (5+ failed attempts in 60s)", d.brute_force_alerts);
        // Show top brute force targets
        let top_targets = self.brute_force_tracker.top_targets(5);
        if !top_targets.is_empty() {
            println!("  Top targets:");
            for (src, dst, port, count) in top_targets.iter().take(5) {
                if *count >= 3 {
                    let service = self.brute_force_tracker.get_service_name(*port).unwrap_or("Unknown");
                    println!("    {} -> {}:{} ({}) - {} attempts", src, dst, port, service, count);
                }
            }
        }
        println!();
        println!("Payload Stats:");
        println!("  Packets with payload: {:>8} ({:.2}% of packets)",
            d.packets_with_payload,
            d.packets_with_payload as f64 / self.packets_processed as f64 * 100.0);
        println!("  Total payload bytes:  {:>8} ({:.2} MB)",
            d.total_payload_bytes,
            d.total_payload_bytes as f64 / 1_000_000.0);

        println!();
        println!("────────────────────────────────────────────────────────────────────────────────");
        println!("                        LATENCY PER PACKET (µs)");
        println!("────────────────────────────────────────────────────────────────────────────────");
        println!("{:<20} {:>12} {:>12} {:>12}",
                 "Component", "Avg (µs)", "Min (ns)", "Max (ns)");
        println!("────────────────────────────────────────────────────────────────────────────────");

        self.print_timing("Parse", &self.timings.parse);
        self.print_timing("Flow Tracking", &self.timings.flow);
        self.print_timing("Signatures", &self.timings.signatures);
        self.print_timing("Threat Intel", &self.timings.threat_intel);
        self.print_timing("ML Features", &self.timings.ml_features);
        self.print_timing("ML Scoring", &self.timings.ml_score);
        println!("────────────────────────────────────────────────────────────────────────────────");
        self.print_timing("TOTAL", &self.timings.total);
        println!("════════════════════════════════════════════════════════════════════════════════");
    }

    fn print_timing(&self, name: &str, stats: &TimingStats) {
        if stats.count == 0 {
            println!("{:<20} {:>12} {:>12} {:>12}", name, "-", "-", "-");
            return;
        }
        println!("{:<20} {:>12.2} {:>12} {:>12}",
                 name, stats.mean_us(), stats.min_ns, stats.max_ns);
    }

    /// Train the ML baseline on a benign flow record
    #[cfg(feature = "ml-detection")]
    fn train_baseline_from_record(&mut self, record: &CsvFlowRecord) {
        // Only train on benign traffic
        if record.attack != "Benign" && !record.attack.is_empty() {
            return;
        }

        // Convert to packet and process through flow tracker
        let pkt = record.to_packet();

        if let Some(ref mut tracker) = self.flow_tracker {
            let mut pkt_mut = pkt;
            let (flow, _direction) = tracker.process(&mut pkt_mut);

            // Extract features and train baseline
            if let Some(ref mut extractor) = self.feature_extractor {
                let features = extractor.extract(flow);
                if let Some(ref mut baseline) = self.baseline {
                    baseline.update_fast(&features);
                }
            }
        }
    }

    /// Process a CSV flow record through the pipeline
    fn process_csv_record(&mut self, record: &CsvFlowRecord, warmup: bool) {
        let total_start = Instant::now();

        // Convert CSV record to packet
        let parse_start = Instant::now();
        let pkt = record.to_packet();
        let parse_time = parse_start.elapsed();

        // Simulate processing each packet in the flow
        let total_pkts = record.in_pkts + record.out_pkts;
        self.bytes_processed += record.in_bytes + record.out_bytes;

        // Flow tracking
        let mut flow_time = Duration::ZERO;
        let mut _flow_ref: Option<&Flow> = None;
        if let Some(ref mut tracker) = self.flow_tracker {
            let start = Instant::now();
            let mut pkt_mut = pkt.clone();
            let (flow, _direction) = tracker.process(&mut pkt_mut);
            _flow_ref = Some(flow);
            flow_time = start.elapsed();
        }

        // Signature matching
        #[allow(unused_mut)]
        let mut sig_time = Duration::ZERO;
        #[allow(unused_mut)]
        let mut sig_match_count: usize = 0;
        #[cfg(feature = "signatures")]
        if let Some(ref engine) = self.signature_engine {
            let start = Instant::now();

            let proto_ctx = ProtocolContext::None;
            let flow_state = FlowState {
                established: (record.tcp_flags & 0x10) != 0, // ACK flag
                to_server: true,
            };

            let matches = engine.match_packet(&pkt, &proto_ctx, &flow_state);
            sig_match_count = matches.len();
            sig_time = start.elapsed();
        }

        // Threat intel lookup
        #[allow(unused_mut)]
        let mut intel_time = Duration::ZERO;
        #[cfg(feature = "threat-intel")]
        if let Some(ref cache) = self.ioc_cache {
            let start = Instant::now();
            let _src_match = cache.check_ip(&pkt.src_ip());
            let _dst_match = cache.check_ip(&pkt.dst_ip());
            intel_time = start.elapsed();
        }

        // ML feature extraction and scoring
        #[allow(unused_mut)]
        let mut ml_feat_time = Duration::ZERO;
        #[allow(unused_mut)]
        let mut ml_score_time = Duration::ZERO;
        #[allow(unused_mut)]
        let mut ml_anomaly_score: f32 = 0.0;
        #[cfg(feature = "ml-detection")]
        if self.feature_extractor.is_some() && _flow_ref.is_some() {
            let flow = _flow_ref.unwrap();
            let feat_start = Instant::now();
            let features = self.feature_extractor.as_mut().unwrap().extract(flow);
            ml_feat_time = feat_start.elapsed();

            let score_start = Instant::now();
            if let Some(ref baseline) = self.baseline {
                let score = self.anomaly_detector.as_ref().unwrap().score(&features, baseline);
                ml_anomaly_score = score.score;
            }
            ml_score_time = score_start.elapsed();
        }

        let total_time = total_start.elapsed();

        // Determine if this flow is actually an attack (ground truth)
        let is_attack = record.attack != "Benign" && !record.attack.is_empty();

        // Determine if we detected it (signature match OR high ML score)
        let detected = sig_match_count > 0 || ml_anomaly_score >= 0.5;

        // Record timings (skip warmup)
        if !warmup {
            self.flows_processed += 1;
            self.packets_processed += total_pkts as usize;
            self.label_stats.record(&record.label, &record.attack);

            // Record detection stats
            self.detection_stats.record_detection(detected, is_attack, ml_anomaly_score, sig_match_count);
            self.timings.parse.record(parse_time);
            self.timings.flow.record(flow_time);
            self.timings.signatures.record(sig_time);
            self.timings.threat_intel.record(intel_time);
            self.timings.ml_features.record(ml_feat_time);
            self.timings.ml_score.record(ml_score_time);
            self.timings.total.record(total_time);
        }
    }

    /// Run benchmark on CSV file(s)
    fn run_csv(&mut self) -> anyhow::Result<()> {
        let path = self.args.csv_path.as_ref().unwrap();

        // Collect CSV files
        let csv_files: Vec<PathBuf> = if path.is_file() {
            vec![path.clone()]
        } else if path.is_dir() {
            Self::find_csv_files(path)?
        } else {
            println!("No CSV files found at {:?}", path);
            return Ok(());
        };

        if csv_files.is_empty() {
            println!("No CSV files found at {:?}", path);
            return Ok(());
        }

        println!("CSV Flow Benchmark");
        println!("==================");
        println!("Files: {:?}", csv_files.iter().map(|p| p.file_name().unwrap()).collect::<Vec<_>>());
        println!("Max records: {}", if self.args.max_packets == 0 { "unlimited".to_string() } else { self.args.max_packets.to_string() });
        println!("Warmup: {} records", self.args.warmup);
        println!();
        println!("Features enabled:");
        println!("  Flow tracking: {}", self.flow_tracker.is_some());
        #[cfg(feature = "signatures")]
        println!("  Signatures: {}", self.signature_engine.is_some());
        #[cfg(feature = "threat-intel")]
        println!("  Threat intel: {}", self.ioc_cache.is_some());
        #[cfg(feature = "ml-detection")]
        println!("  ML detection: {}", self.feature_extractor.is_some());
        println!();

        // Phase 1: Train baseline on benign flows from warmup records
        #[cfg(feature = "ml-detection")]
        if self.feature_extractor.is_some() && self.args.warmup > 0 {
            println!("Phase 1: Training ML baseline on benign traffic...");
            let train_start = Instant::now();
            let mut trained_count = 0usize;
            let mut warmup_count = 0usize;

            'training: for csv_file in &csv_files {
                let file = File::open(csv_file)?;
                let reader = BufReader::new(file);
                let mut lines = reader.lines();

                // Parse header
                let header_line = match lines.next() {
                    Some(Ok(line)) => line,
                    _ => continue,
                };
                let header_map: std::collections::HashMap<String, usize> = header_line
                    .split(',')
                    .enumerate()
                    .map(|(i, name)| (name.to_string(), i))
                    .collect();

                for line_result in lines {
                    if warmup_count >= self.args.warmup {
                        break 'training;
                    }

                    let line = match line_result {
                        Ok(l) => l,
                        Err(_) => continue,
                    };

                    if let Some(record) = CsvFlowRecord::from_csv_line(&line, &header_map) {
                        warmup_count += 1;

                        // Train baseline on benign flows only
                        if record.attack == "Benign" || record.attack.is_empty() {
                            self.train_baseline_from_record(&record);
                            trained_count += 1;
                        }

                        if warmup_count % 10000 == 0 {
                            print!("\r  Training: {}/{} warmup records ({} benign)...",
                                warmup_count, self.args.warmup, trained_count);
                            std::io::Write::flush(&mut std::io::stdout())?;
                        }
                    }
                }
            }

            let train_elapsed = train_start.elapsed();
            println!();
            println!("Baseline training complete: {} benign samples in {:.2?}", trained_count, train_elapsed);

            #[cfg(feature = "ml-detection")]
            if let Some(ref baseline) = self.baseline {
                println!("Baseline stats: {} total samples", baseline.total_samples);
            }
            println!();
        }

        // Phase 2: Detection benchmark
        println!("Phase 2: Running detection benchmark...");
        let start = Instant::now();
        let mut total_records = 0usize;

        for csv_file in csv_files {
            println!("Processing {:?}...", csv_file.file_name().unwrap());

            let file = File::open(&csv_file)?;
            let reader = BufReader::new(file);
            let mut lines = reader.lines();

            // Parse header
            let header_line = match lines.next() {
                Some(Ok(line)) => line,
                _ => continue,
            };
            let header_map: std::collections::HashMap<String, usize> = header_line
                .split(',')
                .enumerate()
                .map(|(i, name)| (name.to_string(), i))
                .collect();

            for line_result in lines {
                let line = match line_result {
                    Ok(l) => l,
                    Err(_) => continue,
                };

                if let Some(record) = CsvFlowRecord::from_csv_line(&line, &header_map) {
                    // Skip warmup records (already used for training)
                    if total_records < self.args.warmup {
                        total_records += 1;
                        continue;
                    }

                    self.process_csv_record(&record, false);
                    total_records += 1;

                    if self.args.max_packets > 0 && (total_records - self.args.warmup) >= self.args.max_packets {
                        break;
                    }

                    // Progress indicator
                    if total_records % 100000 == 0 {
                        print!("\r  {} records processed...", total_records);
                        std::io::Write::flush(&mut std::io::stdout())?;
                    }
                }
            }
            println!();

            if self.args.max_packets > 0 && (total_records - self.args.warmup) >= self.args.max_packets {
                break;
            }
        }

        let elapsed = start.elapsed();

        // Print results
        self.print_csv_results(elapsed);

        Ok(())
    }

    /// Find CSV files recursively
    fn find_csv_files(path: &PathBuf) -> anyhow::Result<Vec<PathBuf>> {
        let mut csv_files = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                csv_files.extend(Self::find_csv_files(&path)?);
            } else if path.extension().map(|e| e == "csv").unwrap_or(false) {
                csv_files.push(path);
            }
        }
        Ok(csv_files)
    }

    fn print_csv_results(&self, elapsed: Duration) {
        println!();
        println!("════════════════════════════════════════════════════════════════════════════════");
        println!("                           CSV BENCHMARK RESULTS");
        println!("════════════════════════════════════════════════════════════════════════════════");
        println!();
        println!("Total flows:       {:>12}", self.flows_processed);
        println!("Total packets:     {:>12} (from flow records)", self.packets_processed);
        println!("Total bytes:       {:>12} ({:.2} MB)", self.bytes_processed, self.bytes_processed as f64 / 1_000_000.0);
        println!("Total time:        {:>12.2?}", elapsed);
        println!("Throughput:        {:>12.0} flows/s", self.flows_processed as f64 / elapsed.as_secs_f64());
        println!("Throughput:        {:>12.2} Mbps", (self.bytes_processed as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0);
        println!();

        // Print label distribution
        if !self.label_stats.counts.is_empty() {
            println!("────────────────────────────────────────────────────────────────────────────────");
            println!("                        LABEL DISTRIBUTION");
            println!("────────────────────────────────────────────────────────────────────────────────");
            let mut labels: Vec<_> = self.label_stats.counts.iter().collect();
            labels.sort_by(|a, b| b.1.cmp(a.1));
            for (label, count) in labels.iter().take(10) {
                let pct = **count as f64 / self.flows_processed as f64 * 100.0;
                println!("{:<30} {:>10} ({:>5.1}%)", label, count, pct);
            }
        }

        // Print detection results
        println!();
        println!("────────────────────────────────────────────────────────────────────────────────");
        println!("                        DETECTION RESULTS");
        println!("────────────────────────────────────────────────────────────────────────────────");
        let d = &self.detection_stats;
        let total_actual_attacks = d.true_positives + d.false_negatives;
        let total_actual_benign = d.true_negatives + d.false_positives;
        println!("Signature matches:  {:>10}", d.signature_matches);
        println!("ML anomalies:       {:>10} (score >= 0.5)", d.ml_anomalies);
        println!("Avg ML score:       {:>10.4}", d.avg_ml_score(self.flows_processed));
        println!();
        println!("Confusion Matrix:");
        println!("                    Predicted");
        println!("                    Attack      Benign");
        println!("  Actual Attack     {:>8} TP  {:>8} FN  (Total: {})", d.true_positives, d.false_negatives, total_actual_attacks);
        println!("  Actual Benign     {:>8} FP  {:>8} TN  (Total: {})", d.false_positives, d.true_negatives, total_actual_benign);
        println!();
        println!("Metrics:");
        println!("  Accuracy:         {:>10.2}%", d.accuracy() * 100.0);
        println!("  Precision:        {:>10.2}%", d.precision() * 100.0);
        println!("  Recall:           {:>10.2}%", d.recall() * 100.0);
        println!("  F1 Score:         {:>10.4}", d.f1_score());

        println!();
        println!("────────────────────────────────────────────────────────────────────────────────");
        println!("                        LATENCY PER FLOW (µs)");
        println!("────────────────────────────────────────────────────────────────────────────────");
        println!("{:<20} {:>12} {:>12} {:>12}",
                 "Component", "Avg (µs)", "Min (ns)", "Max (ns)");
        println!("────────────────────────────────────────────────────────────────────────────────");

        self.print_timing("Parse/Convert", &self.timings.parse);
        self.print_timing("Flow Tracking", &self.timings.flow);
        self.print_timing("Signatures", &self.timings.signatures);
        self.print_timing("Threat Intel", &self.timings.threat_intel);
        self.print_timing("ML Features", &self.timings.ml_features);
        self.print_timing("ML Scoring", &self.timings.ml_score);
        println!("────────────────────────────────────────────────────────────────────────────────");
        self.print_timing("TOTAL", &self.timings.total);
        println!("════════════════════════════════════════════════════════════════════════════════");
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut benchmark = PcapBenchmark::new(args);

    // Check if CSV mode or PCAP mode
    if benchmark.args.csv_path.is_some() {
        benchmark.run_csv()
    } else {
        #[cfg(feature = "parallel")]
        if benchmark.args.parallel {
            return benchmark.run_parallel();
        }
        benchmark.run()
    }
}
