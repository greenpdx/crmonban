//! Layer234 Pcap Reader - Read packets from pcap files
//!
//! Process pcap files through layer234 detector for threat detection.
//!
//! Run with: cargo run --bin layer234_pcap --release -- -f capture.pcap

use crmonban::layer234::{
    Config, Detector, DetectorBuilder, DetectionEvent, DetectionType, DetectionSubType,
    PacketAnalysis, parse_packet, NetVecError,
};
use pcap_file::pcap::PcapReader;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut input_file: Option<String> = None;
    let mut config_file: Option<String> = None;
    let mut stats_only = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--file" | "-f" => {
                if i + 1 < args.len() {
                    input_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--config" | "-c" => {
                if i + 1 < args.len() {
                    config_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--stats" | "-s" => {
                stats_only = true;
            }
            "--help" | "-h" => {
                println!("Layer234 Pcap Reader - Process pcap files with layer234 detector\n");
                println!("Usage: layer234_pcap [OPTIONS]\n");
                println!("Options:");
                println!("  -f, --file <FILE>     Input pcap file (required)");
                println!("  -c, --config <FILE>   Config file (default: config.toml or built-in)");
                println!("  -s, --stats           Show statistics only, suppress individual detections");
                println!("  -h, --help            Show this help");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    let input_file = match input_file {
        Some(f) => f,
        None => {
            eprintln!("Error: Input file required. Use -f <file>");
            eprintln!("Use --help for usage information.");
            std::process::exit(1);
        }
    };

    println!("Layer234 Pcap Reader");
    println!("====================");
    println!("Input: {}", input_file);

    // Load configuration
    let config = match &config_file {
        Some(path) => {
            println!("Config: {}", path);
            Config::from_file(path)?
        }
        None => {
            if Path::new("config.toml").exists() {
                println!("Config: config.toml");
                Config::from_file("config.toml")?
            } else {
                println!("Config: built-in defaults");
                Config::default()
            }
        }
    };

    // Create detector
    let mut detector = DetectorBuilder::from_config(&config)
        .build_with_config(&config)?;

    println!("Signatures loaded: {}", detector.signature_count());
    println!();

    // Set up detection handler
    let mut rx = detector.detection_stream();
    let (stats_tx, _stats_rx) = mpsc::channel::<DetectionEvent>(1000);

    let stats_only_clone = stats_only;
    let detection_handler = tokio::spawn(async move {
        let mut detections: Vec<DetectionEvent> = Vec::new();
        while let Ok(event) = rx.recv().await {
            if !stats_only_clone {
                print_detection(&event);
            }
            detections.push(event.clone());
            let _ = stats_tx.send(event).await;
        }
        detections
    });

    // Process pcap file
    let start_time = Instant::now();
    let (packet_count, byte_count) = process_pcap_file(&input_file, &mut detector).await?;
    let processing_time = start_time.elapsed();

    // Flush remaining windows
    detector.flush().await?;

    // Wait for detection handler
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(detector);

    let detections = detection_handler.await?;

    // Print statistics
    println!("\n{}", "=".repeat(60));
    println!("PROCESSING STATISTICS");
    println!("{}", "=".repeat(60));
    println!("Packets processed: {}", packet_count);
    println!("Bytes processed:   {} ({:.2} MB)", byte_count, byte_count as f64 / 1_000_000.0);
    println!("Processing time:   {:.2?}", processing_time);
    println!("Throughput:        {:.0} packets/sec", packet_count as f64 / processing_time.as_secs_f64());
    println!("                   {:.2} Mbps", (byte_count as f64 * 8.0) / processing_time.as_secs_f64() / 1_000_000.0);

    println!("\n{}", "=".repeat(60));
    println!("DETECTION SUMMARY");
    println!("{}", "=".repeat(60));
    println!("Total detections:  {}", detections.len());

    // Group by detection type
    let mut scan_count = 0;
    let mut brute_count = 0;
    let mut anomaly_count = 0;
    let mut sweep_count = 0;
    let mut dos_count = 0;

    for event in &detections {
        match &event.event_type {
            DetectionType::PortScan => scan_count += 1,
            DetectionType::BruteForce => brute_count += 1,
            DetectionType::AnomalyDetection | DetectionType::BehaviorAnomaly => anomaly_count += 1,
            DetectionType::NetworkScan => sweep_count += 1,
            DetectionType::DoS => dos_count += 1,
            _ => {}
        }
    }

    println!("  Port scans:      {}", scan_count);
    println!("  Brute force:     {}", brute_count);
    println!("  Anomalies:       {}", anomaly_count);
    println!("  Network scans:   {}", sweep_count);
    println!("  DoS attacks:     {}", dos_count);

    // Unique sources
    let mut sources: std::collections::HashSet<_> = std::collections::HashSet::new();
    for event in &detections {
        sources.insert(event.src_ip);
    }
    println!("\nUnique attackers:  {}", sources.len());
    for src in sources.iter().take(10) {
        println!("  - {}", src);
    }
    if sources.len() > 10 {
        println!("  ... and {} more", sources.len() - 10);
    }

    Ok(())
}

async fn process_pcap_file(
    path: &str,
    detector: &mut Detector,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut pcap_reader = PcapReader::new(reader)?;

    let mut packet_count = 0usize;
    let mut byte_count = 0usize;
    let mut last_report = Instant::now();

    while let Some(packet) = pcap_reader.next_packet() {
        let packet = packet?;
        let data = packet.data;

        byte_count += data.len();

        // Get timestamp from pcap
        let timestamp_ns = packet.timestamp.as_nanos() as u64;

        // Parse packet first
        match parse_packet(&data, timestamp_ns) {
            Ok(packet) => {
                let mut analysis = PacketAnalysis::new(packet);
                detector.process(&mut analysis).await;
            }
            Err(NetVecError::NoIpLayer) => {
                // Skip non-IP packets
            }
            Err(e) => {
                eprintln!("Warning: Failed to parse packet: {}", e);
            }
        }

        packet_count += 1;

        // Progress report every second
        if last_report.elapsed() >= Duration::from_secs(1) {
            eprint!("\rProcessed {} packets...", packet_count);
            last_report = Instant::now();
        }
    }

    eprintln!("\rProcessed {} packets.    ", packet_count);
    Ok((packet_count, byte_count))
}

fn print_detection(event: &DetectionEvent) {
    let type_desc = format_detection_type(&event.event_type, &event.subtype);
    let timestamp_ns = event.timestamp.timestamp_nanos_opt().unwrap_or(0);

    println!(
        "[{:.3}s] {} | {} | conf={:.0}% | sig={}",
        timestamp_ns as f64 / 1_000_000_000.0,
        event.src_ip,
        type_desc,
        event.confidence * 100.0,
        event.rule_name.as_deref().unwrap_or("-")
    );
}

fn format_detection_type(event_type: &DetectionType, subtype: &DetectionSubType) -> String {
    match (event_type, subtype) {
        (DetectionType::PortScan, DetectionSubType::Scan(scan)) => {
            format!("PORT_SCAN ({})", scan)
        }
        (DetectionType::NetworkScan, DetectionSubType::Scan(scan)) => {
            format!("NETWORK_SCAN ({})", scan)
        }
        (DetectionType::BruteForce, _) => "BRUTE_FORCE".to_string(),
        (DetectionType::AnomalyDetection, _) => "ANOMALY".to_string(),
        (DetectionType::DoS, DetectionSubType::Dos(dos)) => {
            format!("DOS ({})", dos)
        }
        _ => format!("{}", event_type).to_uppercase(),
    }
}
