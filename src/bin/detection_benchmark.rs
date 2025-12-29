//! Detection Benchmark - Comprehensive detection testing tool
//!
//! Processes PCAP files or synthetic traffic through the detection pipeline
//! and measures latency, throughput, detection rate, and false positive rate.
//!
//! Run with: cargo run --bin detection_benchmark --release -- -f capture.pcap

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Instant;

use crmonban::testing::{
    BenchmarkConfig, DetectionBenchmark, BenchmarkReport, ReportFormat,
    AttackConfig, AttackGenerator, MixedTrafficGenerator,
    RealisticTrafficGenerator, RealisticConfig,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut input_file: Option<String> = None;
    let mut ground_truth_file: Option<String> = None;
    let mut output_file: Option<String> = None;
    let mut output_format = ReportFormat::Text;
    let mut warmup_packets = 100u64;
    let mut verbose = false;
    let mut synthetic_mode = false;
    let mut attack_type: Option<String> = None;
    let mut packet_count = 10000u64;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--file" | "-f" => {
                if i + 1 < args.len() {
                    input_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--ground-truth" | "-g" => {
                if i + 1 < args.len() {
                    ground_truth_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    output_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--format" => {
                if i + 1 < args.len() {
                    output_format = match args[i + 1].to_lowercase().as_str() {
                        "json" => ReportFormat::Json,
                        "csv" => ReportFormat::Csv,
                        "markdown" | "md" => ReportFormat::Markdown,
                        _ => ReportFormat::Text,
                    };
                    i += 1;
                }
            }
            "--warmup" => {
                if i + 1 < args.len() {
                    warmup_packets = args[i + 1].parse().unwrap_or(100);
                    i += 1;
                }
            }
            "--verbose" | "-v" => {
                verbose = true;
            }
            "--synthetic" | "-s" => {
                synthetic_mode = true;
            }
            "--attack-type" | "-a" => {
                if i + 1 < args.len() {
                    attack_type = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--count" | "-n" => {
                if i + 1 < args.len() {
                    packet_count = args[i + 1].parse().unwrap_or(10000);
                    i += 1;
                }
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    // Need either input file or synthetic mode
    if input_file.is_none() && !synthetic_mode {
        eprintln!("Error: Either input file (-f) or synthetic mode (-s) required.");
        eprintln!("Use --help for usage information.");
        std::process::exit(1);
    }

    println!("Detection Benchmark Tool");
    println!("========================\n");

    // Create benchmark config
    let config = BenchmarkConfig {
        enable_layer234: true,
        enable_http_detect: false, // HTTP tested separately via httpAttack
        enable_signatures: false,
        enable_protocols: false,
        warmup_packets,
        verbose,
        layer234_config_path: None,
        http_patterns_path: None,
    };

    let mut benchmark = DetectionBenchmark::new(config);

    // Load ground truth if provided
    if let Some(ref gt_path) = ground_truth_file {
        println!("Loading ground truth: {}", gt_path);
        benchmark.load_ground_truth(Path::new(gt_path))?;
    }

    let start_time = Instant::now();
    let report: BenchmarkReport;

    if synthetic_mode {
        // Synthetic traffic mode
        let attack = attack_type.as_deref().unwrap_or("port_scan");
        println!("Mode: Synthetic traffic generation");
        println!("Attack type: {}", attack);
        println!("Packets: {}\n", packet_count);

        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        let attack_config = match attack.to_lowercase().as_str() {
            "port_scan" | "portscan" => AttackConfig::port_scan(
                src_ip, dst_ip,
                vec![22, 80, 443, 8080, 3389, 3306, 5432, 27017, 6379, 11211],
            ),
            "syn_flood" | "synflood" => AttackConfig::syn_flood(
                src_ip, dst_ip, 80, packet_count,
            ),
            "ssh_brute" | "sshbrute" => AttackConfig::ssh_brute_force(
                src_ip, dst_ip, packet_count,
            ),
            "mixed" => {
                // Use mixed traffic generator
                println!("Running mixed traffic benchmark...\n");
                let configs = vec![
                    AttackConfig::port_scan(
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                        dst_ip,
                        vec![22, 80, 443, 8080],
                    ),
                    AttackConfig::ssh_brute_force(
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
                        dst_ip,
                        50,
                    ),
                    AttackConfig::benign(
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
                        dst_ip,
                        100,
                    ),
                ];

                let mut generator = MixedTrafficGenerator::new(configs);
                report = benchmark.process_mixed_generator(&mut generator);
                print_report(&report, output_format, output_file.as_deref())?;
                return Ok(());
            }
            "realistic" | "all" => {
                // Use realistic traffic generator that tests ALL detection layers
                println!("Running realistic traffic benchmark (ALL layers)...\n");
                println!("Generating:");
                println!("  - Port scan (vertical scan detection)");
                println!("  - SYN flood (DoS detection)");
                println!("  - SSH brute force (auth port detection)");
                println!("  - HTTP attacks (SQL injection, XSS, path traversal)");
                println!("  - Network sweep (horizontal scan)");
                println!("  - UDP flood (DNS amplification)");
                println!("  - Benign traffic (baseline)\n");

                let config = RealisticConfig::default();
                let mut generator = RealisticTrafficGenerator::new(config);
                report = benchmark.process_realistic_generator(&mut generator);
                print_report(&report, output_format, output_file.as_deref())?;
                return Ok(());
            }
            _ => {
                eprintln!("Unknown attack type: {}", attack);
                eprintln!("Supported: port_scan, syn_flood, ssh_brute, mixed, realistic");
                std::process::exit(1);
            }
        };

        let mut generator = AttackGenerator::new(attack_config);
        report = benchmark.process_attack_generator(&mut generator);
    } else {
        // PCAP file mode
        let pcap_path = input_file.as_ref().unwrap();
        println!("Mode: PCAP file processing");
        println!("Input: {}\n", pcap_path);

        report = benchmark.process_pcap(Path::new(pcap_path))?;
    }

    let total_time = start_time.elapsed();
    println!("Total benchmark time: {:.2?}\n", total_time);

    print_report(&report, output_format, output_file.as_deref())?;

    Ok(())
}

fn print_report(
    report: &BenchmarkReport,
    format: ReportFormat,
    output_file: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let content = match format {
        ReportFormat::Json => report.to_json(),
        ReportFormat::Csv => report.to_csv(),
        ReportFormat::Markdown => report.to_markdown(),
        ReportFormat::Text => report.to_text(),
    };

    if let Some(path) = output_file {
        std::fs::write(path, &content)?;
        println!("Report written to: {}", path);
    } else {
        println!("{}", content);
    }

    Ok(())
}

fn print_help() {
    println!("Detection Benchmark - Comprehensive detection testing tool\n");
    println!("USAGE:");
    println!("  detection_benchmark [OPTIONS]\n");
    println!("OPTIONS:");
    println!("  -f, --file <FILE>         Input PCAP file");
    println!("  -g, --ground-truth <FILE> Ground truth CSV for accuracy metrics");
    println!("  -o, --output <FILE>       Output report file");
    println!("  --format <FMT>            Output format: text, json, csv, markdown");
    println!("  --warmup <N>              Warmup packets before measuring (default: 100)");
    println!("  -v, --verbose             Show per-packet timing");
    println!("  -s, --synthetic           Use synthetic traffic generation");
    println!("  -a, --attack-type <TYPE>  Attack type for synthetic mode:");
    println!("                            port_scan, syn_flood, ssh_brute, mixed, realistic");
    println!("                            (realistic tests ALL detection layers)");
    println!("  -n, --count <N>           Packet count for synthetic (default: 10000)");
    println!("  -h, --help                Show this help\n");
    println!("EXAMPLES:");
    println!("  # Benchmark with PCAP file");
    println!("  detection_benchmark -f capture.pcap -g ground_truth.csv\n");
    println!("  # Synthetic port scan benchmark");
    println!("  detection_benchmark -s -a port_scan -n 5000\n");
    println!("  # Mixed traffic with JSON output");
    println!("  detection_benchmark -s -a mixed --format json -o report.json\n");
    println!("  # Realistic traffic testing ALL detection layers");
    println!("  detection_benchmark -s -a realistic --format markdown\n");
    println!("GROUND TRUTH FORMAT (CSV):");
    println!("  timestamp,src_ip,dst_ip,attack_type,severity");
    println!("  1609459200,192.168.1.100,10.0.0.1,port_scan,medium");
}
