//! Scan Detection False Positive Test
//!
//! Reads a PCAP file and runs packets through ScanDetectEngine
//! to measure detection rate and false positives.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use etherparse::SlicedPacket;
use pcap::Capture;

use crmonban::core::packet::{IpProtocol, Packet, TcpFlags};
use crmonban::scan_detect::{ScanDetectEngine, ScanDetectConfig, SourceBehavior};

#[derive(Parser, Debug)]
#[command(name = "scan_detect_test")]
#[command(about = "Test scan detection false positive rate on PCAP files")]
struct Args {
    /// Path to PCAP file
    #[arg(short, long, default_value = "data/Monday-WorkingHours.pcap")]
    pcap_path: PathBuf,

    /// Maximum packets to process (0 = unlimited)
    #[arg(short, long, default_value = "0")]
    max_packets: usize,

    /// Print details for each alert
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Default)]
struct Stats {
    total_packets: usize,
    tcp_packets: usize,
    udp_packets: usize,
    other_packets: usize,
    parse_errors: usize,

    // Alerts
    total_alerts: usize,
    suspicious_alerts: usize,
    probable_scan_alerts: usize,
    likely_attack_alerts: usize,
    confirmed_scan_alerts: usize,

    // Unique IPs flagged
    flagged_ips: HashSet<IpAddr>,

    // Per-IP alert counts
    alerts_per_ip: HashMap<IpAddr, usize>,

    // Classification counts per IP (stored as string for HashMap compatibility)
    classifications: HashMap<IpAddr, String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!("╔════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                    SCAN DETECTION FALSE POSITIVE TEST                          ║");
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ PCAP: {:70} ║", args.pcap_path.display());
    println!("╚════════════════════════════════════════════════════════════════════════════════╝");
    println!();

    // Initialize scan detection engine
    let config = ScanDetectConfig::default();
    let mut engine = ScanDetectEngine::new(config);

    let mut stats = Stats::default();

    // Open PCAP
    println!("Opening PCAP file...");
    let mut cap = Capture::from_file(&args.pcap_path)?;

    let start_time = Instant::now();
    let mut last_report = Instant::now();
    let mut last_tick = Instant::now();
    let mut packet_id: u64 = 0;

    println!("Processing packets...\n");

    while let Ok(packet) = cap.next_packet() {
        packet_id += 1;
        stats.total_packets += 1;

        // Parse packet
        let parsed = match SlicedPacket::from_ethernet(packet.data) {
            Ok(p) => p,
            Err(_) => {
                stats.parse_errors += 1;
                continue;
            }
        };

        // Extract IP info
        let (src_ip, dst_ip, protocol) = match &parsed.net {
            Some(etherparse::NetSlice::Ipv4(ipv4)) => {
                let src: IpAddr = ipv4.header().source().into();
                let dst: IpAddr = ipv4.header().destination().into();
                let proto = ipv4.header().protocol().0;
                (src, dst, proto)
            }
            Some(etherparse::NetSlice::Ipv6(ipv6)) => {
                let src: IpAddr = ipv6.header().source().into();
                let dst: IpAddr = ipv6.header().destination().into();
                let proto = ipv6.header().next_header().0;
                (src, dst, proto)
            }
            _ => continue, // Skip ARP and other non-IP
        };

        let ip_protocol = match protocol {
            6 => { stats.tcp_packets += 1; IpProtocol::Tcp }
            17 => { stats.udp_packets += 1; IpProtocol::Udp }
            1 => { stats.other_packets += 1; IpProtocol::Icmp }
            _ => { stats.other_packets += 1; continue; } // Skip non-TCP/UDP/ICMP
        };

        // Only process TCP for scan detection
        if ip_protocol != IpProtocol::Tcp {
            continue;
        }

        // Build Packet struct
        let mut pkt = Packet::new(packet_id, src_ip, dst_ip, ip_protocol, "pcap");

        // Extract TCP info
        if let Some(etherparse::TransportSlice::Tcp(tcp)) = &parsed.transport {
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
            }
        }

        pkt.raw_len = packet.data.len() as u32;

        // Process through scan detection
        if let Some(alert) = engine.process_packet(&pkt) {
            stats.total_alerts += 1;
            stats.flagged_ips.insert(src_ip);
            *stats.alerts_per_ip.entry(src_ip).or_insert(0) += 1;

            match &alert.alert_type {
                crmonban::scan_detect::AlertType::Suspicious { .. } => stats.suspicious_alerts += 1,
                crmonban::scan_detect::AlertType::ProbableScan { .. } => stats.probable_scan_alerts += 1,
                crmonban::scan_detect::AlertType::LikelyAttack { .. } => stats.likely_attack_alerts += 1,
                crmonban::scan_detect::AlertType::ConfirmedScan { .. } => stats.confirmed_scan_alerts += 1,
                crmonban::scan_detect::AlertType::VerifiedAttack { .. } => stats.confirmed_scan_alerts += 1,
                crmonban::scan_detect::AlertType::NetworkIssue { .. } => {} // Ignore network issues
            }

            if args.verbose {
                println!("[ALERT] {} -> {} : {:?}", src_ip, dst_ip, alert.alert_type);
            }
        }

        // Progress report
        if last_report.elapsed().as_secs() >= 1 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let pps = stats.total_packets as f64 / elapsed;
            print!("\rPackets: {} | TCP: {} | Alerts: {} | Flagged IPs: {} | {:.0} pps    ",
                stats.total_packets, stats.tcp_packets, stats.total_alerts,
                stats.flagged_ips.len(), pps);
            std::io::Write::flush(&mut std::io::stdout())?;
            last_report = Instant::now();
        }

        // Check limit
        if args.max_packets > 0 && stats.total_packets >= args.max_packets {
            break;
        }
    }

    let elapsed = start_time.elapsed();
    println!("\n");

    // Get final classifications for all tracked IPs
    for ip in &stats.flagged_ips {
        if let Some(behavior) = engine.get_behavior(ip) {
            stats.classifications.insert(*ip, format!("{:?}", behavior.classification));
        }
    }

    // Print results
    println!("╔════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                              RESULTS                                           ║");
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ Packets                                                                        ║");
    println!("║   Total:        {:>10}                                                     ║", stats.total_packets);
    println!("║   TCP:          {:>10}                                                     ║", stats.tcp_packets);
    println!("║   UDP:          {:>10}                                                     ║", stats.udp_packets);
    println!("║   Other:        {:>10}                                                     ║", stats.other_packets);
    println!("║   Parse errors: {:>10}                                                     ║", stats.parse_errors);
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ Alerts                                                                         ║");
    println!("║   Total:        {:>10}                                                     ║", stats.total_alerts);
    println!("║   Suspicious:   {:>10}                                                     ║", stats.suspicious_alerts);
    println!("║   ProbableScan: {:>10}                                                     ║", stats.probable_scan_alerts);
    println!("║   LikelyAttack: {:>10}                                                     ║", stats.likely_attack_alerts);
    println!("║   ConfirmedScan:{:>10}                                                     ║", stats.confirmed_scan_alerts);
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ Unique IPs Flagged: {:>6}                                                     ║", stats.flagged_ips.len());
    println!("║ Sources Tracked:    {:>6}                                                     ║", engine.tracked_sources());
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ Performance                                                                    ║");
    println!("║   Duration:     {:>10.2}s                                                    ║", elapsed.as_secs_f64());
    println!("║   Rate:         {:>10.0} pps                                                 ║", stats.total_packets as f64 / elapsed.as_secs_f64());
    println!("╚════════════════════════════════════════════════════════════════════════════════╝");

    // Top flagged IPs
    if !stats.alerts_per_ip.is_empty() {
        println!("\nTop 10 Flagged IPs:");
        println!("{:<20} {:>10} {:>20}", "IP", "Alerts", "Classification");
        println!("{}", "-".repeat(55));

        let mut sorted: Vec<_> = stats.alerts_per_ip.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));

        for (ip, count) in sorted.iter().take(10) {
            let class = stats.classifications.get(ip).map(|s| s.as_str()).unwrap_or("Normal");
            println!("{:<20} {:>10} {:>20}", ip, count, class);
        }
    }

    // Classification summary
    println!("\nFinal Classification Summary:");
    let mut class_counts: HashMap<String, usize> = HashMap::new();
    for class in stats.classifications.values() {
        *class_counts.entry(class.clone()).or_insert(0) += 1;
    }
    for (class, count) in &class_counts {
        println!("  {}: {}", class, count);
    }

    Ok(())
}
