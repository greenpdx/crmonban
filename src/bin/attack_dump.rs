//! Attack Packet Dumper for CICIDS2017 Dataset
//!
//! Extracts attack packets from CICIDS2017 PCAP files based on ground truth:
//! - Attacker IPs, target IPs, ports, and time windows
//! - Outputs packets to a new PCAP file or text summary

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;

use clap::{Parser, ValueEnum};
use etherparse::SlicedPacket;
use pcap::Capture;

#[derive(Parser, Debug)]
#[command(name = "attack_dump")]
#[command(about = "Dump attack packets from CICIDS2017 PCAP files")]
struct Args {
    /// Input PCAP file
    #[arg(short, long)]
    input: PathBuf,

    /// Output file (PCAP or text depending on format)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Output format
    #[arg(short, long, default_value = "summary")]
    format: OutputFormat,

    /// Day of week for the PCAP (auto-detected from filename if not specified)
    #[arg(short, long)]
    day: Option<Day>,

    /// Maximum packets to process (0 = unlimited)
    #[arg(short, long, default_value = "0")]
    max_packets: usize,

    /// Show verbose output for each attack packet
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Text summary with packet details
    Summary,
    /// Output to PCAP file
    Pcap,
    /// CSV format
    Csv,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq)]
enum Day {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
}

impl Day {
    fn from_filename(filename: &str) -> Option<Self> {
        let lower = filename.to_lowercase();
        if lower.contains("monday") {
            Some(Day::Monday)
        } else if lower.contains("tuesday") {
            Some(Day::Tuesday)
        } else if lower.contains("wednesday") {
            Some(Day::Wednesday)
        } else if lower.contains("thursday") {
            Some(Day::Thursday)
        } else if lower.contains("friday") {
            Some(Day::Friday)
        } else {
            None
        }
    }
}

/// Ground truth for CICIDS2017 attacks
///
/// Note: CICIDS2017 PCAPs capture internal network traffic only (192.168.10.x).
/// External attackers (205.174.165.x) are NATed through the firewall (172.16.0.1).
/// We identify attacks by:
/// 1. Traffic from NAT gateway (172.16.0.1) to internal targets on attack ports
/// 2. Traffic from known internal attackers (e.g., 192.168.10.51 for Tuesday brute force)
/// 3. Traffic from infected machines during post-exploitation (Thursday infiltration)
struct GroundTruth {
    /// Known attacker IPs (including NAT gateway for external attacks)
    attacker_ips: HashSet<IpAddr>,
    /// Known target IPs
    target_ips: HashSet<IpAddr>,
    /// Attack ports (if applicable)
    attack_ports: HashSet<u16>,
    /// Attack descriptions
    attacks: Vec<&'static str>,
    /// For port scan detection - any source to target on many ports
    detect_port_scan: bool,
    /// Infected machines that become attackers (for infiltration)
    infected_machines: HashSet<IpAddr>,
}

impl GroundTruth {
    fn for_day(day: Day) -> Self {
        // NAT gateway IP - external attackers appear as this IP
        let nat_gateway: IpAddr = "172.16.0.1".parse().unwrap();

        match day {
            Day::Monday => Self {
                attacker_ips: HashSet::new(),
                target_ips: HashSet::new(),
                attack_ports: HashSet::new(),
                attacks: vec!["Normal day - no attacks"],
                detect_port_scan: false,
                infected_machines: HashSet::new(),
            },
            Day::Tuesday => {
                // Brute Force FTP (9:20-10:20), SSH (14:00-15:00)
                // Internal attacker: 192.168.10.51 -> Target: 192.168.10.50
                // External attacks come through NAT gateway
                let mut attacker_ips = HashSet::new();
                attacker_ips.insert("192.168.10.51".parse().unwrap()); // Internal attacker
                attacker_ips.insert(nat_gateway); // External attacks via NAT

                let mut target_ips = HashSet::new();
                target_ips.insert("192.168.10.50".parse().unwrap());

                let mut attack_ports = HashSet::new();
                attack_ports.insert(21); // FTP
                attack_ports.insert(22); // SSH

                Self {
                    attacker_ips,
                    target_ips,
                    attack_ports,
                    attacks: vec!["FTP-Patator (Brute Force)", "SSH-Patator (Brute Force)"],
                    detect_port_scan: false,
                    infected_machines: HashSet::new(),
                }
            }
            Day::Wednesday => {
                // DoS attacks: Slowloris, Slowhttptest, Hulk, GoldenEye (9:47-11:23)
                // Heartbleed (15:12-15:32) on port 444
                // All attacks from external, via NAT gateway
                let mut attacker_ips = HashSet::new();
                attacker_ips.insert(nat_gateway);

                let mut target_ips = HashSet::new();
                target_ips.insert("192.168.10.50".parse().unwrap()); // Web server (DoS target)
                target_ips.insert("192.168.10.51".parse().unwrap()); // Heartbleed target

                let mut attack_ports = HashSet::new();
                attack_ports.insert(80);  // HTTP for DoS
                attack_ports.insert(443); // HTTPS
                attack_ports.insert(444); // Heartbleed

                Self {
                    attacker_ips,
                    target_ips,
                    attack_ports,
                    attacks: vec![
                        "DoS Slowloris",
                        "DoS Slowhttptest",
                        "DoS Hulk",
                        "DoS GoldenEye",
                        "Heartbleed",
                    ],
                    detect_port_scan: false,
                    infected_machines: HashSet::new(),
                }
            }
            Day::Thursday => {
                // Web attacks (9:20-10:42) from external via NAT
                // Infiltration (14:19-15:45):
                //   - Initial attack to 192.168.10.8 (Win Vista) and 192.168.10.25 (MAC)
                //   - Post-exploitation: 192.168.10.8 scans/attacks other internal hosts
                let mut attacker_ips = HashSet::new();
                attacker_ips.insert(nat_gateway); // External web attacks

                let mut target_ips = HashSet::new();
                target_ips.insert("192.168.10.50".parse().unwrap()); // Web server
                target_ips.insert("192.168.10.8".parse().unwrap());  // Win Vista (initial infiltration target)
                target_ips.insert("192.168.10.25".parse().unwrap()); // MAC (Cool Disk target)

                let mut attack_ports = HashSet::new();
                attack_ports.insert(80);   // Web attacks
                attack_ports.insert(443);  // HTTPS
                attack_ports.insert(8080); // Alt HTTP

                // Infected machines doing secondary attacks
                let mut infected_machines = HashSet::new();
                infected_machines.insert("192.168.10.8".parse().unwrap()); // Compromised, does internal scanning

                Self {
                    attacker_ips,
                    target_ips,
                    attack_ports,
                    attacks: vec![
                        "Web Attack - Brute Force",
                        "Web Attack - XSS",
                        "Web Attack - SQL Injection",
                        "Infiltration",
                    ],
                    detect_port_scan: false,
                    infected_machines,
                }
            }
            Day::Friday => {
                // Botnet (10:02-11:02): Infected machines communicate with C2 (external)
                // Port Scan (13:55-15:27): External via NAT to 192.168.10.50
                // DDoS LOIT (15:56-16:16): Multiple external attackers via NAT
                let mut attacker_ips = HashSet::new();
                attacker_ips.insert(nat_gateway); // External attacks via NAT

                let mut target_ips = HashSet::new();
                target_ips.insert("192.168.10.50".parse().unwrap()); // Scan/DDoS target
                // Botnet-infected machines (communicate with C2)
                target_ips.insert("192.168.10.5".parse().unwrap());
                target_ips.insert("192.168.10.8".parse().unwrap());
                target_ips.insert("192.168.10.9".parse().unwrap());
                target_ips.insert("192.168.10.14".parse().unwrap());
                target_ips.insert("192.168.10.15".parse().unwrap());

                // Port scan and DDoS - broader port range
                let mut attack_ports = HashSet::new();
                // Common scanned ports
                for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443] {
                    attack_ports.insert(port);
                }

                // Botnet-infected machines
                let mut infected_machines = HashSet::new();
                infected_machines.insert("192.168.10.5".parse().unwrap());
                infected_machines.insert("192.168.10.8".parse().unwrap());
                infected_machines.insert("192.168.10.9".parse().unwrap());
                infected_machines.insert("192.168.10.14".parse().unwrap());
                infected_machines.insert("192.168.10.15".parse().unwrap());

                Self {
                    attacker_ips,
                    target_ips,
                    attack_ports,
                    attacks: vec!["Botnet ARES", "Port Scan", "DDoS LOIT"],
                    detect_port_scan: true,
                    infected_machines,
                }
            }
        }
    }

    /// Check if a packet is attack traffic
    fn is_attack(&self, src_ip: IpAddr, dst_ip: IpAddr, dst_port: u16, src_port: u16) -> bool {
        // Check if source is attacker and destination is target
        let src_is_attacker = self.attacker_ips.contains(&src_ip);
        let dst_is_target = self.target_ips.contains(&dst_ip);
        let port_matches = self.attack_ports.is_empty() || self.attack_ports.contains(&dst_port);

        // Also check reverse direction for responses
        let dst_is_attacker = self.attacker_ips.contains(&dst_ip);
        let src_is_target = self.target_ips.contains(&src_ip);
        let reverse_port_matches = self.attack_ports.is_empty() || self.attack_ports.contains(&src_port);

        // Check if source is an infected machine (post-exploitation traffic)
        let src_is_infected = self.infected_machines.contains(&src_ip);
        let dst_is_infected = self.infected_machines.contains(&dst_ip);

        // Attack if:
        // 1. Known attacker -> target on attack port
        // 2. Target -> attacker (response traffic) on attack port
        // 3. Infected machine -> any internal target (lateral movement)
        // 4. External (NAT) -> infected machine (C2 traffic)
        (src_is_attacker && dst_is_target && port_matches)
            || (dst_is_attacker && src_is_target && reverse_port_matches)
            || (src_is_infected && !dst_is_infected) // Lateral movement from compromised host
            || (src_is_attacker && dst_is_infected)  // C2 to botnet
            || (src_is_infected && dst_is_attacker)  // Botnet to C2
    }
}

#[derive(Debug, Default)]
struct Stats {
    total_packets: usize,
    attack_packets: usize,
    tcp_attacks: usize,
    udp_attacks: usize,
    icmp_attacks: usize,
    other_attacks: usize,
    unique_src_ips: HashSet<IpAddr>,
    unique_dst_ips: HashSet<IpAddr>,
    unique_dst_ports: HashSet<u16>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Determine day from filename or argument
    let day = args.day.or_else(|| {
        args.input
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(Day::from_filename)
    });

    let day = match day {
        Some(d) => d,
        None => {
            eprintln!("Could not determine day from filename. Use --day to specify.");
            std::process::exit(1);
        }
    };

    if day == Day::Monday {
        println!("Monday is normal traffic day - no attacks to extract.");
        return Ok(());
    }

    let ground_truth = GroundTruth::for_day(day);

    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                    CICIDS2017 ATTACK PACKET DUMPER                           ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║ Input:  {:68} ║", args.input.display().to_string().chars().take(68).collect::<String>());
    println!("║ Day:    {:68} ║", format!("{:?}", day));
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║ Attacks for this day:                                                        ║");
    for attack in &ground_truth.attacks {
        println!("║   - {:72} ║", attack);
    }
    println!("║                                                                              ║");
    println!("║ Attacker IPs:                                                                ║");
    for ip in &ground_truth.attacker_ips {
        println!("║   - {:72} ║", ip);
    }
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");
    println!();

    let mut stats = Stats::default();
    let start = Instant::now();

    // Open input PCAP
    let mut cap = Capture::from_file(&args.input)?;
    let _linktype = cap.get_datalink();

    // Prepare output writers
    let mut pcap_writer: Option<pcap::Savefile> = None;
    let mut text_writer: Option<BufWriter<File>> = None;

    match args.format {
        OutputFormat::Pcap => {
            let output_path = args.output.unwrap_or_else(|| {
                let stem = args.input.file_stem().unwrap().to_str().unwrap();
                PathBuf::from(format!("data/{}_attacks.pcap", stem))
            });
            pcap_writer = Some(cap.savefile(&output_path)?);
            println!("Writing attack packets to: {}", output_path.display());
        }
        OutputFormat::Summary | OutputFormat::Csv => {
            if let Some(ref output_path) = args.output {
                let file = File::create(output_path)?;
                text_writer = Some(BufWriter::new(file));
                println!("Writing to: {}", output_path.display());
            }
            if matches!(args.format, OutputFormat::Csv) {
                if let Some(ref mut w) = text_writer {
                    writeln!(w, "packet_num,timestamp_us,src_ip,dst_ip,protocol,src_port,dst_port,length,flags")?;
                } else {
                    println!("packet_num,timestamp_us,src_ip,dst_ip,protocol,src_port,dst_port,length,flags");
                }
            }
        }
    }

    println!();
    println!("Processing packets...");

    while let Ok(packet) = cap.next_packet() {
        stats.total_packets += 1;

        // Parse packet
        let parsed = match SlicedPacket::from_ethernet(packet.data) {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Extract IP info
        let (src_ip, dst_ip, protocol): (IpAddr, IpAddr, &str) = match &parsed.net {
            Some(etherparse::NetSlice::Ipv4(ipv4)) => {
                let h = ipv4.header();
                (
                    IpAddr::V4(h.source_addr()),
                    IpAddr::V4(h.destination_addr()),
                    match h.protocol().0 {
                        6 => "TCP",
                        17 => "UDP",
                        1 => "ICMP",
                        _ => "OTHER",
                    },
                )
            }
            Some(etherparse::NetSlice::Ipv6(ipv6)) => {
                let h = ipv6.header();
                (
                    IpAddr::V6(h.source_addr()),
                    IpAddr::V6(h.destination_addr()),
                    match h.next_header().0 {
                        6 => "TCP",
                        17 => "UDP",
                        58 => "ICMPv6",
                        _ => "OTHER",
                    },
                )
            }
            _ => continue,
        };

        // Extract port info
        let (src_port, dst_port, flags) = match &parsed.transport {
            Some(etherparse::TransportSlice::Tcp(tcp)) => {
                let mut flag_str = String::new();
                if tcp.syn() { flag_str.push('S'); }
                if tcp.ack() { flag_str.push('A'); }
                if tcp.fin() { flag_str.push('F'); }
                if tcp.rst() { flag_str.push('R'); }
                if tcp.psh() { flag_str.push('P'); }
                if tcp.urg() { flag_str.push('U'); }
                (tcp.source_port(), tcp.destination_port(), flag_str)
            }
            Some(etherparse::TransportSlice::Udp(udp)) => {
                (udp.source_port(), udp.destination_port(), String::new())
            }
            _ => (0, 0, String::new()),
        };

        // Check if this is attack traffic
        if ground_truth.is_attack(src_ip, dst_ip, dst_port, src_port) {
            stats.attack_packets += 1;
            stats.unique_src_ips.insert(src_ip);
            stats.unique_dst_ips.insert(dst_ip);
            if dst_port != 0 {
                stats.unique_dst_ports.insert(dst_port);
            }

            match protocol {
                "TCP" => stats.tcp_attacks += 1,
                "UDP" => stats.udp_attacks += 1,
                "ICMP" | "ICMPv6" => stats.icmp_attacks += 1,
                _ => stats.other_attacks += 1,
            }

            // Output based on format
            match args.format {
                OutputFormat::Pcap => {
                    if let Some(ref mut w) = pcap_writer {
                        w.write(&packet);
                    }
                }
                OutputFormat::Csv => {
                    let ts_us = packet.header.ts.tv_sec as u64 * 1_000_000 + packet.header.ts.tv_usec as u64;
                    let line = format!(
                        "{},{},{},{},{},{},{},{},{}",
                        stats.total_packets, ts_us, src_ip, dst_ip, protocol, src_port, dst_port, packet.header.len, flags
                    );
                    if let Some(ref mut w) = text_writer {
                        writeln!(w, "{}", line)?;
                    } else {
                        println!("{}", line);
                    }
                }
                OutputFormat::Summary => {
                    if args.verbose {
                        println!(
                            "  [{}] {} {}:{} -> {}:{} len={} flags={}",
                            stats.attack_packets, protocol, src_ip, src_port, dst_ip, dst_port, packet.header.len, flags
                        );
                    }
                }
            }
        }

        // Progress
        if stats.total_packets % 500_000 == 0 {
            print!("\r  {} packets processed, {} attacks found...", stats.total_packets, stats.attack_packets);
            std::io::Write::flush(&mut std::io::stdout())?;
        }

        if args.max_packets > 0 && stats.total_packets >= args.max_packets {
            break;
        }
    }

    let elapsed = start.elapsed();

    // Flush writers
    if let Some(mut w) = text_writer {
        w.flush()?;
    }

    println!("\r                                                                              ");
    println!();
    println!("╔══════════════════════════════════════════════════════════════════════════════╗");
    println!("║                              EXTRACTION RESULTS                              ║");
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║ Processing time:      {:>10.2?}                                            ║", elapsed);
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║ PACKET COUNTS                                                                ║");
    println!("╠──────────────────────────────────────────────────────────────────────────────╣");
    println!("║   Total packets:      {:>12}                                          ║", stats.total_packets);
    println!("║   Attack packets:     {:>12}                                          ║", stats.attack_packets);
    let pct = if stats.total_packets > 0 {
        stats.attack_packets as f64 / stats.total_packets as f64 * 100.0
    } else { 0.0 };
    println!("║   Attack ratio:       {:>11.2}%                                          ║", pct);
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║ ATTACK BREAKDOWN BY PROTOCOL                                                 ║");
    println!("╠──────────────────────────────────────────────────────────────────────────────╣");
    println!("║   TCP:                {:>12}                                          ║", stats.tcp_attacks);
    println!("║   UDP:                {:>12}                                          ║", stats.udp_attacks);
    println!("║   ICMP:               {:>12}                                          ║", stats.icmp_attacks);
    println!("║   Other:              {:>12}                                          ║", stats.other_attacks);
    println!("╠══════════════════════════════════════════════════════════════════════════════╣");
    println!("║ UNIQUE VALUES                                                                ║");
    println!("╠──────────────────────────────────────────────────────────────────────────────╣");
    println!("║   Unique source IPs:  {:>12}                                          ║", stats.unique_src_ips.len());
    println!("║   Unique dest IPs:    {:>12}                                          ║", stats.unique_dst_ips.len());
    println!("║   Unique dest ports:  {:>12}                                          ║", stats.unique_dst_ports.len());
    println!("╚══════════════════════════════════════════════════════════════════════════════╝");

    if args.verbose || matches!(args.format, OutputFormat::Summary) {
        println!();
        println!("Source IPs seen in attacks:");
        for ip in &stats.unique_src_ips {
            println!("  - {}", ip);
        }
        println!();
        println!("Top destination ports:");
        let mut ports: Vec<_> = stats.unique_dst_ports.iter().collect();
        ports.sort();
        for port in ports.iter().take(20) {
            println!("  - {}", port);
        }
    }

    Ok(())
}
