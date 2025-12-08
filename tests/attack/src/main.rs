//! Attack Generator for crmonban testing
//!
//! Generates stateful attack traffic with 90% attacks, 10% benign.
//! Optionally uses signature payloads from NIDS rules for guaranteed matches.
//!
//! Usage:
//!   synth_attack --target 192.168.1.1 --count 2000000 --output packets.csv
//!   synth_attack --target 192.168.1.1 --interface eth0 --rate 10000
//!   synth_attack --target 192.168.1.1 --rules-dir /path/to/rules --interface eth0

mod attacks;
mod generator;
mod recorder;
mod signatures;
mod state_machine;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use chrono::Utc;
use clap::{Parser, ValueEnum};
use rand::seq::SliceRandom;
use rand::Rng;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use attacks::*;
use attacks::port_scan::*;
use attacks::syn_flood::*;
use attacks::brute_force::*;
use attacks::web_attacks::*;
use attacks::dns_attacks::*;
use attacks::fuzzer::*;
use generator::{PacketRecord, PacketSender, SenderConfig};
use recorder::{AttackStats, RecordFormat, Recorder, SessionSummary};
use signatures::SignatureProvider;
use state_machine::{TcpFlags, TcpStateMachine};

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Csv,
    Json,
    Jsonl,
}

#[derive(Parser, Debug)]
#[command(name = "attack_gen")]
#[command(author = "svvs")]
#[command(version = "0.1.0")]
#[command(about = "Stateful attack generator for crmonban IPS testing")]
struct Args {
    /// Target IP address
    #[arg(short, long)]
    target: IpAddr,

    /// Source IP address (default: 10.0.0.100)
    #[arg(short, long, default_value = "10.0.0.100")]
    source: IpAddr,

    /// Number of packets to generate
    #[arg(short, long, default_value = "100000")]
    count: usize,

    /// Output file for packet records
    #[arg(short, long, default_value = "attack_packets.csv")]
    output: PathBuf,

    /// Output format
    #[arg(short = 'f', long, default_value = "csv")]
    format: OutputFormat,

    /// Network interface for sending (enables actual sending)
    #[arg(short, long)]
    interface: Option<String>,

    /// Rate limit in packets per second (0 = unlimited)
    #[arg(short, long, default_value = "0")]
    rate: u64,

    /// Dry run - generate records without sending (default: only when no interface specified)
    #[arg(long)]
    dry_run: bool,

    /// Percentage of attack traffic (0-100)
    #[arg(long, default_value = "90")]
    attack_pct: u8,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Batch size for processing
    #[arg(long, default_value = "10000")]
    batch_size: usize,

    /// Rules directory for signature-based payloads (optional)
    /// When specified, uses actual content patterns from NIDS rules
    #[arg(long)]
    rules_dir: Option<PathBuf>,

    /// Maximum number of rules to load from rules directory
    #[arg(long, default_value = "1000")]
    max_rules: usize,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Setup logging
    let level = if args.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Attack Generator v0.1.0");
    info!("Target: {}", args.target);
    info!("Source: {}", args.source);
    info!("Count: {} packets", args.count);
    info!("Attack %: {}%", args.attack_pct);
    info!("Output: {:?}", args.output);

    let start_time = Utc::now();

    // Calculate distribution
    let attack_count = (args.count as f64 * (args.attack_pct as f64 / 100.0)) as usize;
    let benign_count = args.count - attack_count;

    info!("Generating {} attack packets, {} benign packets", attack_count, benign_count);

    // Create recorder
    let record_format = match args.format {
        OutputFormat::Csv => RecordFormat::Csv,
        OutputFormat::Json => RecordFormat::Json,
        OutputFormat::Jsonl => RecordFormat::JsonLines,
    };
    let mut recorder = Recorder::new(&args.output, record_format)?;

    // Create sender (dry run by default)
    let sender_config = SenderConfig {
        interface: args.interface.clone().unwrap_or_else(|| "eth0".to_string()),
        dry_run: args.dry_run || args.interface.is_none(),
        rate_limit: args.rate,
        ..Default::default()
    };
    let is_dry_run = sender_config.dry_run;
    let mut sender = PacketSender::new(sender_config)?;

    if !is_dry_run {
        if sender.can_send() {
            info!("Live mode: will send packets on interface");
        } else {
            info!("Warning: interface not available, falling back to dry run");
        }
    }

    // Load signature provider if rules-dir is specified
    let sig_provider: Option<std::sync::Arc<SignatureProvider>> = if let Some(ref rules_dir) = args.rules_dir {
        match SignatureProvider::from_rules_dir(rules_dir.to_str().unwrap_or("."), args.max_rules) {
            Ok(provider) => {
                info!("Loaded {} rules from {:?}", provider.rule_count(), rules_dir);
                Some(std::sync::Arc::new(provider))
            }
            Err(e) => {
                tracing::warn!("Failed to load rules from {:?}: {}", rules_dir, e);
                None
            }
        }
    } else {
        None
    };

    // Attack generators
    let mut generators: Vec<Box<dyn AttackGenerator>> = vec![
        // Port scanning (20%)
        Box::new(SynScanGenerator::new()),
        Box::new(NullScanGenerator::new()),
        Box::new(XmasScanGenerator::new()),
        Box::new(FinScanGenerator::new()),
        Box::new(AckScanGenerator::new()),
        Box::new(UdpScanGenerator::new()),

        // DoS (20%)
        Box::new(SynFloodGenerator::new(80)),
        Box::new(SynFloodGenerator::new(443)),
        Box::new(IcmpFloodGenerator::new()),
        Box::new(UdpFloodGenerator::new(53)),
        Box::new(HttpFloodGenerator::new(80)),
        Box::new(SlowlorisGenerator::new(80, 100)),

        // Brute force (15%)
        Box::new(SshBruteForceGenerator::new()),
        Box::new(FtpBruteForceGenerator::new()),
        Box::new(HttpBruteForceGenerator::new(80)),
        Box::new(TelnetBruteForceGenerator::new()),

        // Web attacks (15%)
        Box::new(SqlInjectionGenerator::new(80)),
        Box::new(XssGenerator::new(80)),
        Box::new(CommandInjectionGenerator::new(80)),
        Box::new(PathTraversalGenerator::new(80)),

        // DNS (10%)
        Box::new(DnsTunnelingGenerator::new()),
        Box::new(DnsAmplificationGenerator::new()),

        // Fuzzing (10%)
        Box::new(MalformedTcpGenerator::new()),
        Box::new(InvalidFlagsGenerator::new()),
        Box::new(OversizedPacketGenerator::new()),
        Box::new(FragmentAttackGenerator::new()),
    ];

    // Add signature-based generators if rules are loaded
    if let Some(ref provider) = sig_provider {
        info!("Adding signature-based attack generators");
        // Add multiple signature generators for more coverage
        for _ in 0..10 {
            generators.push(Box::new(SignatureAttackGenerator::new(provider.clone())));
        }
    }

    let mut benign_generator = BenignTrafficGenerator::new();
    let mut stats = AttackStats::new();
    let mut rng = rand::thread_rng();

    // Generate packets in batches
    let mut packet_id: u64 = 0;
    let mut attack_remaining = attack_count;
    let mut benign_remaining = benign_count;

    while attack_remaining > 0 || benign_remaining > 0 {
        let batch_size = args.batch_size.min(attack_remaining + benign_remaining);
        let mut batch_records: Vec<PacketRecord> = Vec::with_capacity(batch_size);

        for _ in 0..batch_size {
            // Decide attack or benign based on remaining counts
            let is_attack = if benign_remaining == 0 {
                true
            } else if attack_remaining == 0 {
                false
            } else {
                rng.gen_ratio(attack_remaining as u32, (attack_remaining + benign_remaining) as u32)
            };

            let records = if is_attack {
                // Pick random attack generator
                let gen_idx = rng.gen_range(0..generators.len());
                let generator = &mut generators[gen_idx];
                let records = generator.generate(1, args.target, args.source);
                stats.add(generator.attack_type(), 1);
                attack_remaining = attack_remaining.saturating_sub(1);
                records
            } else {
                let records = benign_generator.generate(1, args.target, args.source);
                stats.add(AttackType::Benign, 1);
                benign_remaining = benign_remaining.saturating_sub(1);
                records
            };

            for mut record in records {
                record.id = packet_id;
                packet_id += 1;
                batch_records.push(record);
            }
        }

        // Shuffle batch for realistic interleaving
        batch_records.shuffle(&mut rng);

        // Write and optionally send
        for record in &batch_records {
            recorder.write(record)?;

            if !is_dry_run && sender.can_send() {
                // Build and send actual packet from record
                let packet = build_packet_from_record(&sender, record);
                if !packet.is_empty() {
                    let _ = sender.send(&packet);
                }
            }
        }

        // Progress update
        let total_done = packet_id;
        if total_done % 100000 == 0 {
            let pct = (total_done as f64 / args.count as f64) * 100.0;
            info!("Progress: {:.1}% ({} packets)", pct, total_done);
        }
    }

    // Finalize
    let records_written = recorder.finish()?;

    // Print summary
    stats.print_summary();

    let summary = SessionSummary::new(
        start_time,
        records_written,
        stats.to_string_map(),
        args.target.to_string(),
        args.source.to_string(),
    );

    // Write summary file
    let summary_path = args.output.with_extension("summary.json");
    summary.write_to_file(&summary_path)?;

    info!("\nGeneration complete!");
    info!("  Total packets: {}", records_written);
    info!("  Duration: {:.2}s", summary.duration_secs);
    info!("  Rate: {:.0} pps", summary.packets_per_second);
    info!("  Output: {:?}", args.output);
    info!("  Summary: {:?}", summary_path);

    Ok(())
}

/// Build a raw packet from a PacketRecord
fn build_packet_from_record(sender: &PacketSender, record: &PacketRecord) -> Vec<u8> {
    // Extract IPs
    let src_ip = match record.src_ip {
        IpAddr::V4(ip) => ip,
        _ => return vec![],
    };
    let dst_ip = match record.dst_ip {
        IpAddr::V4(ip) => ip,
        _ => return vec![],
    };

    match record.protocol.as_str() {
        "tcp" => {
            let src = SocketAddr::new(IpAddr::V4(src_ip), record.src_port);
            let dst = SocketAddr::new(IpAddr::V4(dst_ip), record.dst_port);
            let flags = TcpFlags::from_u8(record.tcp_flags.unwrap_or(0));
            let seq = record.seq.unwrap_or(0);
            let ack = record.ack.unwrap_or(0);
            // Generate payload based on size
            let payload = vec![0x41u8; record.payload_size]; // 'A' padding
            sender.build_tcp_packet(src, dst, flags, seq, ack, &payload)
        }
        "udp" => {
            let src = SocketAddr::new(IpAddr::V4(src_ip), record.src_port);
            let dst = SocketAddr::new(IpAddr::V4(dst_ip), record.dst_port);
            let payload = vec![0x41u8; record.payload_size];
            sender.build_udp_packet(src, dst, &payload)
        }
        "icmp" => {
            sender.build_icmp_packet(src_ip, dst_ip)
        }
        _ => vec![],
    }
}

/// Signature-based attack generator that uses actual NIDS rule payloads
pub struct SignatureAttackGenerator {
    provider: std::sync::Arc<SignatureProvider>,
    state_machine: TcpStateMachine,
}

impl SignatureAttackGenerator {
    pub fn new(provider: std::sync::Arc<SignatureProvider>) -> Self {
        Self {
            provider,
            state_machine: TcpStateMachine::new(),
        }
    }
}

impl AttackGenerator for SignatureAttackGenerator {
    fn generate(&mut self, count: usize, target: IpAddr, src_ip: IpAddr) -> Vec<PacketRecord> {
        let mut records = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();
        let mut packet_id = 0u64;

        let attempts = count / 4; // 4 packets per connection (SYN, SYN-ACK complete, payload, FIN)

        for _ in 0..attempts {
            if packet_id as usize >= count {
                break;
            }

            // Get a random rule from the provider
            let rule = match self.provider.get_random_rule(&mut rng) {
                Some(r) => r.clone(),
                None => continue,
            };

            let dst_port = rule.dst_port.unwrap_or(80);
            let src_port: u16 = rng.gen_range(1024..65535);
            let src = SocketAddr::new(src_ip, src_port);
            let dst = SocketAddr::new(target, dst_port);

            // TCP handshake
            let (seq, ack, flags) = self.state_machine.start_handshake(src, dst);
            records.push(PacketRecord::new(packet_id, AttackType::SqlInjection) // Generic attack type
                .with_tcp(src, dst, flags, seq, ack, &[]));
            packet_id += 1;

            if packet_id as usize >= count {
                break;
            }

            let server_seq: u32 = rng.gen();
            let (seq2, ack2, flags2) = self.state_machine.complete_handshake(src, dst, server_seq);
            records.push(PacketRecord::new(packet_id, AttackType::SqlInjection)
                .with_tcp(src, dst, flags2, seq2, ack2, &[]));
            packet_id += 1;

            if packet_id as usize >= count {
                break;
            }

            // Build payload from rule contents
            let payload = self.provider.build_payload(&rule);

            // Wrap in HTTP if it's a web port
            let final_payload = if dst_port == 80 || dst_port == 443 || dst_port == 8080 {
                let http_req = format!(
                    "GET /test?data={} HTTP/1.1\r\nHost: target\r\nUser-Agent: Mozilla/5.0\r\nContent-Length: {}\r\n\r\n",
                    String::from_utf8_lossy(&payload).replace(' ', "%20"),
                    payload.len()
                );
                let mut http_payload = http_req.into_bytes();
                http_payload.extend_from_slice(&payload);
                http_payload
            } else {
                payload
            };

            records.push(PacketRecord::new(packet_id, AttackType::SqlInjection)
                .with_tcp(src, dst, TcpFlags::psh_ack(), seq2, ack2, &final_payload));
            packet_id += 1;

            if packet_id as usize >= count {
                break;
            }

            // FIN
            records.push(PacketRecord::new(packet_id, AttackType::SqlInjection)
                .with_tcp(src, dst, TcpFlags::fin_ack(), seq2 + final_payload.len() as u32, ack2, &[]));
            packet_id += 1;
        }

        records
    }

    fn attack_type(&self) -> AttackType {
        AttackType::SqlInjection // Using SqlInjection as a generic marker for signature-based
    }

    fn description(&self) -> &'static str {
        "Signature-based attack using actual NIDS rule payloads"
    }
}
