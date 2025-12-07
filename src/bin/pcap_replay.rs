use pcap::{Capture, Offline, Active, Device};
use std::env;
use std::time::{Duration, Instant};
use std::io::{self, Write};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <pcap_file> [interface] [--rate <pps>] [--count <n>]", args[0]);
        eprintln!("  pcap_file: Path to PCAP file to replay");
        eprintln!("  interface: Network interface to inject packets (default: lo)");
        eprintln!("  --rate: Packets per second (default: 0 = as fast as possible)");
        eprintln!("  --count: Maximum number of packets to replay (default: 0 = all)");
        std::process::exit(1);
    }

    let pcap_file = &args[1];
    let interface = args.get(2).map(|s| s.as_str()).unwrap_or("lo");

    // Parse rate limit and count
    let mut rate_pps: u64 = 0;
    let mut max_count: u64 = 0;
    for i in 0..args.len() {
        if args[i] == "--rate" && i + 1 < args.len() {
            rate_pps = args[i + 1].parse().unwrap_or(0);
        }
        if args[i] == "--count" && i + 1 < args.len() {
            max_count = args[i + 1].parse().unwrap_or(0);
        }
    }

    println!("Opening PCAP file: {}", pcap_file);
    let mut reader = Capture::from_file(pcap_file)?;

    println!("Opening interface {} for injection", interface);
    let device = Device::list()?
        .into_iter()
        .find(|d| d.name == interface)
        .ok_or_else(|| anyhow::anyhow!("Interface {} not found", interface))?;

    // Create an injector using sendpacket
    let mut sender = Capture::from_device(device)?
        .promisc(false)
        .snaplen(65535)
        .open()?;

    println!("Starting packet replay...");
    if rate_pps > 0 {
        println!("Rate limit: {} packets/second", rate_pps);
    }
    if max_count > 0 {
        println!("Packet limit: {}", max_count);
    }

    let start_time = Instant::now();
    let mut packet_count: u64 = 0;
    let mut byte_count: u64 = 0;
    let mut last_report = Instant::now();

    let packet_interval = if rate_pps > 0 {
        Duration::from_nanos(1_000_000_000 / rate_pps)
    } else {
        Duration::ZERO
    };

    let mut last_packet_time = Instant::now();

    loop {
        match reader.next_packet() {
            Ok(packet) => {
                // Rate limiting
                if rate_pps > 0 {
                    let elapsed = last_packet_time.elapsed();
                    if elapsed < packet_interval {
                        std::thread::sleep(packet_interval - elapsed);
                    }
                    last_packet_time = Instant::now();
                }

                // Inject packet
                match sender.sendpacket(packet.data) {
                    Ok(_) => {
                        packet_count += 1;
                        byte_count += packet.data.len() as u64;
                    }
                    Err(e) => {
                        eprintln!("Failed to send packet: {:?}", e);
                    }
                }

                // Check count limit
                if max_count > 0 && packet_count >= max_count {
                    break;
                }

                // Progress report every second
                if last_report.elapsed() >= Duration::from_secs(1) {
                    let elapsed = start_time.elapsed().as_secs_f64();
                    let pps = packet_count as f64 / elapsed;
                    let mbps = (byte_count as f64 * 8.0) / (elapsed * 1_000_000.0);
                    print!("\rPackets: {} | Rate: {:.0} pps | Throughput: {:.2} Mbps    ",
                           packet_count, pps, mbps);
                    io::stdout().flush()?;
                    last_report = Instant::now();
                }
            }
            Err(pcap::Error::NoMorePackets) => {
                break;
            }
            Err(e) => {
                eprintln!("\nError reading packet: {:?}", e);
                break;
            }
        }
    }

    let total_time = start_time.elapsed().as_secs_f64();
    println!("\n\nReplay complete:");
    println!("  Total packets: {}", packet_count);
    println!("  Total bytes: {}", byte_count);
    println!("  Duration: {:.2}s", total_time);
    println!("  Average rate: {:.0} pps", packet_count as f64 / total_time);
    println!("  Average throughput: {:.2} Mbps", (byte_count as f64 * 8.0) / (total_time * 1_000_000.0));

    Ok(())
}
