//! PCAP/CSV Replay Benchmark
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

#[cfg(feature = "signatures")]
use crmonban::signatures::{SignatureConfig, SignatureEngine, RuleLoader, matcher::PacketContext, ast::Protocol};

#[cfg(feature = "threat-intel")]
use crmonban::threat_intel::IocCache;

#[cfg(feature = "ml-detection")]
use crmonban::ml::{AnomalyDetector, Baseline, FeatureExtractor};

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
        pkt.src_port = self.src_port;
        pkt.dst_port = self.dst_port;
        pkt.raw_len = (self.in_bytes / self.in_pkts.max(1)) as u32;

        // Set TCP flags if TCP
        if self.protocol == 6 {
            pkt.tcp_flags = Some(TcpFlags {
                syn: (self.tcp_flags & 0x02) != 0,
                ack: (self.tcp_flags & 0x10) != 0,
                fin: (self.tcp_flags & 0x01) != 0,
                rst: (self.tcp_flags & 0x04) != 0,
                psh: (self.tcp_flags & 0x08) != 0,
                urg: (self.tcp_flags & 0x20) != 0,
                ece: false,
                cwr: false,
            });
        }

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
            let rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/rules/rules");
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

        Self {
            args,
            timings: ComponentTimings::new(),
            packets_processed: 0,
            bytes_processed: 0,
            flows_processed: 0,
            label_stats: LabelStats::new(),
            detection_stats: DetectionStats::new(),
            flow_tracker,
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
        }
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
                        pkt.src_port = tcp.source_port();
                        pkt.dst_port = tcp.destination_port();
                        pkt.seq = Some(tcp.sequence_number());
                        pkt.ack = if tcp.ack() { Some(tcp.acknowledgment_number()) } else { None };
                        pkt.tcp_flags = Some(TcpFlags {
                            syn: tcp.syn(),
                            ack: tcp.ack(),
                            fin: tcp.fin(),
                            rst: tcp.rst(),
                            psh: tcp.psh(),
                            urg: tcp.urg(),
                            ece: tcp.ece(),
                            cwr: tcp.cwr(),
                        });

                        // Extract payload for signature matching
                        pkt.payload = tcp.payload().to_vec();

                        // Detect app protocol from port
                        pkt.app_protocol = match (pkt.src_port, pkt.dst_port) {
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
                        pkt.src_port = udp.source_port();
                        pkt.dst_port = udp.destination_port();
                        pkt.payload = udp.payload().to_vec();

                        pkt.app_protocol = match (pkt.src_port, pkt.dst_port) {
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
            let ctx = PacketContext {
                src_ip: Some(pkt.src_ip),
                dst_ip: Some(pkt.dst_ip),
                src_port: Some(pkt.src_port),
                dst_port: Some(pkt.dst_port),
                protocol: match pkt.protocol {
                    IpProtocol::Tcp => Protocol::Tcp,
                    IpProtocol::Udp => Protocol::Udp,
                    IpProtocol::Icmp | IpProtocol::Icmpv6 => Protocol::Icmp,
                    _ => Protocol::Ip,
                },
                tcp_flags: pkt.tcp_flags.as_ref().map(|f| {
                    let mut flags = 0u8;
                    if f.syn { flags |= 0x02; }
                    if f.ack { flags |= 0x10; }
                    if f.fin { flags |= 0x01; }
                    if f.rst { flags |= 0x04; }
                    if f.psh { flags |= 0x08; }
                    if f.urg { flags |= 0x20; }
                    flags
                }).unwrap_or(0),
                ttl: 64,
                payload: pkt.payload.clone(),
                established: false,
                to_server: true,
                http_uri: None,
                http_method: None,
                http_headers: None,
                http_host: None,
                http_user_agent: None,
                dns_query: None,
                tls_sni: None,
                ja3_hash: None,
            };
            let matches = engine.match_packet(&ctx);
            sig_match_count = matches.len();
            sig_time = start.elapsed();
        }

        // Threat intel lookup
        #[allow(unused_mut)]
        let mut intel_time = Duration::ZERO;
        #[cfg(feature = "threat-intel")]
        if let Some(ref cache) = self.ioc_cache {
            let start = Instant::now();
            let _src_match = cache.check_ip(&pkt.src_ip);
            let _dst_match = cache.check_ip(&pkt.dst_ip);
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

            // Track payload stats
            if !pkt.payload.is_empty() {
                self.detection_stats.packets_with_payload += 1;
                self.detection_stats.total_payload_bytes += pkt.payload.len();
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
            let ctx = PacketContext {
                src_ip: Some(pkt.src_ip),
                dst_ip: Some(pkt.dst_ip),
                src_port: Some(pkt.src_port),
                dst_port: Some(pkt.dst_port),
                protocol: match pkt.protocol {
                    IpProtocol::Tcp => Protocol::Tcp,
                    IpProtocol::Udp => Protocol::Udp,
                    IpProtocol::Icmp | IpProtocol::Icmpv6 => Protocol::Icmp,
                    _ => Protocol::Ip,
                },
                tcp_flags: record.tcp_flags,
                ttl: 64,
                payload: Vec::new(),
                established: (record.tcp_flags & 0x10) != 0, // ACK flag
                to_server: true,
                http_uri: None,
                http_method: None,
                http_headers: None,
                http_host: None,
                http_user_agent: None,
                dns_query: None,
                tls_sni: None,
                ja3_hash: None,
            };
            let matches = engine.match_packet(&ctx);
            sig_match_count = matches.len();
            sig_time = start.elapsed();
        }

        // Threat intel lookup
        #[allow(unused_mut)]
        let mut intel_time = Duration::ZERO;
        #[cfg(feature = "threat-intel")]
        if let Some(ref cache) = self.ioc_cache {
            let start = Instant::now();
            let _src_match = cache.check_ip(&pkt.src_ip);
            let _dst_match = cache.check_ip(&pkt.dst_ip);
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
                    let is_warmup = total_records < self.args.warmup;
                    self.process_csv_record(&record, is_warmup);
                    total_records += 1;

                    if self.args.max_packets > 0 && total_records >= self.args.max_packets + self.args.warmup {
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

            if self.args.max_packets > 0 && total_records >= self.args.max_packets + self.args.warmup {
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
        benchmark.run()
    }
}
