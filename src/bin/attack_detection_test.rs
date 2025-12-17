//! Attack Detection Test for CICIDS2017 Tuesday Dataset
//!
//! Measures detection rate for FTP-Patator and SSH-Patator attacks.
//! Ground truth: Attacker is 192.168.10.51, target is 192.168.10.50

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Instant;

use clap::Parser;
use etherparse::SlicedPacket;
use pcap::Capture;

use crmonban::core::packet::{IpProtocol, Packet, TcpFlags};
use crmonban::flow::{FlowConfig, FlowTracker};
use crmonban::brute_force::BruteForceTracker;
use crmonban::scan_detect::{ScanDetectEngine, ScanDetectConfig, Classification};

#[cfg(feature = "signatures")]
use crmonban::signatures::{SignatureConfig, SignatureEngine, RuleLoader};
#[cfg(feature = "signatures")]
use crmonban::signatures::matcher::{ProtocolContext, FlowState};

#[derive(Parser, Debug)]
#[command(name = "attack_detection_test")]
#[command(about = "Test attack detection rate on CICIDS2017 Tuesday dataset")]
struct Args {
    /// Path to Tuesday PCAP file
    #[arg(short, long, default_value = "data/Tuesday-WorkingHours.pcap")]
    pcap_path: PathBuf,

    /// Maximum packets to process (0 = unlimited)
    #[arg(short, long, default_value = "0")]
    max_packets: usize,
}

/// Known attacker IPs for CICIDS2017 Tuesday (FTP-Patator, SSH-Patator)
const ATTACKER_IPS: &[&str] = &["192.168.10.51"];

/// Known attack ports
const ATTACK_PORTS: &[u16] = &[21, 22]; // FTP, SSH

/// Detection results
#[derive(Debug, Default)]
struct DetectionResults {
    // Total packets
    total_packets: usize,

    // Attack packets (from known attacker IPs to attack ports)
    attack_packets: usize,

    // Benign packets
    benign_packets: usize,

    // Detected attackers (IPs flagged by any engine)
    detected_attackers: HashSet<IpAddr>,

    // Packets until first detection of each attacker
    packets_to_detection: Vec<(IpAddr, usize)>,

    // Signature detections on attack packets
    signature_attack_detections: usize,

    // Brute force detections on attack sources
    brute_force_detections: usize,

    // Scan detections on attack sources
    scan_detections: usize,

    // False positives (benign flagged as attack)
    false_positives: usize,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Parse known attacker IPs
    let attacker_ips: HashSet<IpAddr> = ATTACKER_IPS.iter()
        .map(|s| s.parse().unwrap())
        .collect();

    println!("╔════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                    CICIDS2017 ATTACK DETECTION TEST                            ║");
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ Dataset: Tuesday-WorkingHours.pcap                                             ║");
    println!("║ Attacks: FTP-Patator (port 21), SSH-Patator (port 22)                          ║");
    println!("║ Attacker IP: 192.168.10.51                                                     ║");
    println!("╚════════════════════════════════════════════════════════════════════════════════╝");
    println!();

    // Initialize detection engines
    let mut flow_tracker = FlowTracker::new(FlowConfig::default());
    let mut brute_force_tracker = BruteForceTracker::new();
    let mut scan_detect_engine = ScanDetectEngine::new(ScanDetectConfig::default());

    #[cfg(feature = "signatures")]
    let signature_engine = {
        let mut config = SignatureConfig::default();
        let rules_dir = PathBuf::from("/var/lib/crmonban/data/signatures/suricata/rules");
        if rules_dir.exists() {
            config.rule_dirs = vec![rules_dir.clone()];
        }

        let mut engine = SignatureEngine::new(config.clone());
        let mut loader = RuleLoader::new(config);
        if let Ok(ruleset) = loader.load_all() {
            println!("Loaded {} rules", ruleset.stats.total_rules);
            for (_, rule) in ruleset.rules {
                engine.add_rule(rule);
            }
            engine.rebuild_prefilter();
        }
        engine
    };

    let mut results = DetectionResults::default();
    let mut detected_this_run: HashSet<IpAddr> = HashSet::new();

    println!("Processing {}...", args.pcap_path.display());
    let start = Instant::now();

    let mut cap = Capture::from_file(&args.pcap_path)?;

    while let Ok(packet) = cap.next_packet() {
        results.total_packets += 1;

        // Parse packet
        let pkt = match parse_packet(packet.data) {
            Some(p) => p,
            None => continue,
        };

        let src_ip = pkt.src_ip();
        let dst_port = pkt.dst_port();

        // Determine if this is attack traffic
        let is_attack_packet = attacker_ips.contains(&src_ip) &&
                               ATTACK_PORTS.contains(&dst_port);

        if is_attack_packet {
            results.attack_packets += 1;
        } else {
            results.benign_packets += 1;
        }

        // Run detection engines
        let mut detected = false;

        // 1. Flow tracking
        let mut pkt_clone = pkt.clone();
        let (_flow, _direction) = flow_tracker.process(&mut pkt_clone);

        // 2. Signature matching
        #[cfg(feature = "signatures")]
        {
            let proto_ctx = ProtocolContext::None;
            let flow_state = FlowState {
                established: false,
                to_server: true,
            };
            let matches = signature_engine.match_packet(&pkt, &proto_ctx, &flow_state);
            if !matches.is_empty() {
                if is_attack_packet {
                    results.signature_attack_detections += 1;
                }
                detected = true;
            }
        }

        // 3. Brute force tracking
        let is_syn = pkt.tcp_flags().as_ref().map(|f| f.syn && !f.ack).unwrap_or(false);
        let is_fin = pkt.tcp_flags().as_ref().map(|f| f.fin).unwrap_or(false);
        let is_rst = pkt.tcp_flags().as_ref().map(|f| f.rst).unwrap_or(false);

        let brute_force_alert = if is_syn {
            brute_force_tracker.session_start(src_ip, pkt.dst_ip(), dst_port);
            None
        } else if is_fin || is_rst {
            brute_force_tracker.session_end(src_ip, pkt.dst_ip(), dst_port, is_rst)
        } else {
            brute_force_tracker.session_packet(src_ip, pkt.dst_ip(), dst_port, pkt.payload().len());
            None
        };

        if brute_force_alert.is_some() {
            if attacker_ips.contains(&src_ip) {
                results.brute_force_detections += 1;
            }
            detected = true;
        }

        // 4. Scan detection
        let scan_alert = scan_detect_engine.process_packet(&pkt);
        if let Some(ref alert) = scan_alert {
            if matches!(alert.classification, Classification::ConfirmedScan | Classification::LikelyAttack) {
                if attacker_ips.contains(&src_ip) {
                    results.scan_detections += 1;
                }
                detected = true;
            }
        }

        // Track first detection
        if detected && attacker_ips.contains(&src_ip) && !detected_this_run.contains(&src_ip) {
            detected_this_run.insert(src_ip);
            results.detected_attackers.insert(src_ip);
            results.packets_to_detection.push((src_ip, results.total_packets));
            println!("  [DETECTED] Attacker {} detected at packet #{}", src_ip, results.total_packets);
        }

        // Track false positives (detection on benign traffic)
        if detected && !attacker_ips.contains(&src_ip) {
            results.false_positives += 1;
        }

        // Progress
        if results.total_packets % 100000 == 0 {
            print!("\r  {} packets processed...", results.total_packets);
            std::io::Write::flush(&mut std::io::stdout())?;
        }

        if args.max_packets > 0 && results.total_packets >= args.max_packets {
            break;
        }
    }

    let elapsed = start.elapsed();
    println!();
    println!();

    // Calculate metrics
    let total_attackers = attacker_ips.len();
    let detected_attackers = results.detected_attackers.len();
    let attacker_detection_rate = detected_attackers as f64 / total_attackers as f64 * 100.0;

    // For attack packet-level detection, we use brute force + scan + signature
    let attack_packets_detected = results.brute_force_detections + results.scan_detections + results.signature_attack_detections;

    // Print results
    println!("╔════════════════════════════════════════════════════════════════════════════════╗");
    println!("║                              DETECTION RESULTS                                 ║");
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ Processing time: {:>10.2?}                                                  ║", elapsed);
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ TRAFFIC SUMMARY                                                                ║");
    println!("╠────────────────────────────────────────────────────────────────────────────────╣");
    println!("║   Total packets:           {:>12}                                        ║", results.total_packets);
    println!("║   Attack packets:          {:>12} (from known attacker IPs)              ║", results.attack_packets);
    println!("║   Benign packets:          {:>12}                                        ║", results.benign_packets);
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ ATTACKER DETECTION (SOURCE-LEVEL)                                              ║");
    println!("╠────────────────────────────────────────────────────────────────────────────────╣");
    println!("║   Known attackers:         {:>12}                                        ║", total_attackers);
    println!("║   Detected attackers:      {:>12}                                        ║", detected_attackers);
    println!("║   Detection rate:          {:>11.1}%                                        ║", attacker_detection_rate);

    for (ip, pkt_num) in &results.packets_to_detection {
        println!("║     {} detected at packet #{}                                     ║", ip, pkt_num);
    }

    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ ENGINE-SPECIFIC DETECTIONS                                                     ║");
    println!("╠────────────────────────────────────────────────────────────────────────────────╣");
    println!("║   Signature matches on attack:   {:>8}                                     ║", results.signature_attack_detections);
    println!("║   Brute force alerts:            {:>8}                                     ║", results.brute_force_detections);
    println!("║   Scan alerts on attacker:       {:>8}                                     ║", results.scan_detections);
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ FALSE POSITIVE ANALYSIS                                                        ║");
    println!("╠────────────────────────────────────────────────────────────────────────────────╣");
    println!("║   Detections on benign sources:  {:>8}                                     ║", results.false_positives);
    let fp_rate = if results.benign_packets > 0 {
        results.false_positives as f64 / results.benign_packets as f64 * 100.0
    } else { 0.0 };
    println!("║   FP rate:                       {:>7.3}%                                     ║", fp_rate);
    println!("╠════════════════════════════════════════════════════════════════════════════════╣");
    println!("║ FINAL VERDICT                                                                  ║");
    println!("╠────────────────────────────────────────────────────────────────────────────────╣");

    if attacker_detection_rate >= 99.9 {
        println!("║   ✓ PASS: Attacker detection rate >= 99.9%                                    ║");
    } else {
        println!("║   ✗ FAIL: Attacker detection rate < 99.9%                                     ║");
    }

    if fp_rate < 0.5 {
        println!("║   ✓ PASS: False positive rate < 0.5%                                          ║");
    } else {
        println!("║   ✗ FAIL: False positive rate >= 0.5%                                         ║");
    }

    println!("╚════════════════════════════════════════════════════════════════════════════════╝");

    Ok(())
}

/// Parse raw packet bytes into Packet struct
fn parse_packet(data: &[u8]) -> Option<Packet> {
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
                _ => return None,
            };

            let mut pkt = Packet::new(0, src_ip, dst_ip, protocol, "lo");
            pkt.raw_len = data.len() as u32;

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
                }
                Some(etherparse::TransportSlice::Udp(udp)) => {
                    if let Some(udp_info) = pkt.udp_mut() {
                        udp_info.src_port = udp.source_port();
                        udp_info.dst_port = udp.destination_port();
                        udp_info.payload = udp.payload().to_vec();
                    }
                }
                _ => {}
            }

            Some(pkt)
        }
        Err(_) => None,
    }
}
