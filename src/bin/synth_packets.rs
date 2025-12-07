//! Synthetic packet generator for testing signature detection
//!
//! Generates packets designed to trigger signature rules by embedding
//! the content patterns from rules into crafted packets.
//! Also generates various scan types (SYN, FIN, XMAS, NULL, etc.)

use std::collections::HashMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::thread;
use std::time::Duration;

use pcap::Device;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::icmp::{MutableIcmpPacket, IcmpTypes};
use regex::Regex;

/// TCP flags
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const TCP_URG: u8 = 0x20;

/// Extracted rule info for packet generation
#[derive(Debug, Clone)]
struct RuleInfo {
    sid: u32,
    _msg: String,
    protocol: String,
    _src_port: Option<u16>,
    dst_port: Option<u16>,
    contents: Vec<Vec<u8>>,
    is_established: bool,
}

/// Packet sender wrapper
struct PacketSender {
    cap: pcap::Capture<pcap::Active>,
    sent: u64,
    by_type: HashMap<String, u64>,
}

impl PacketSender {
    fn new(interface: &str) -> anyhow::Result<Self> {
        let device = Device::list()?
            .into_iter()
            .find(|d| d.name == interface)
            .ok_or_else(|| anyhow::anyhow!("Interface {} not found", interface))?;

        let cap = pcap::Capture::from_device(device)?
            .promisc(false)
            .snaplen(65535)
            .open()?;

        Ok(Self {
            cap,
            sent: 0,
            by_type: HashMap::new(),
        })
    }

    fn send(&mut self, packet: &[u8], pkt_type: &str) -> bool {
        match self.cap.sendpacket(packet) {
            Ok(_) => {
                self.sent += 1;
                *self.by_type.entry(pkt_type.to_string()).or_insert(0) += 1;
                true
            }
            Err(e) => {
                eprintln!("Send error: {:?}", e);
                false
            }
        }
    }

    fn stats(&self) {
        println!("\n  Total sent: {}", self.sent);
        println!("  By type:");
        let mut types: Vec<_> = self.by_type.iter().collect();
        types.sort_by_key(|(_, v)| std::cmp::Reverse(*v));
        for (t, count) in types {
            println!("    {}: {}", t, count);
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <interface> [rules_dir] [max_rules] [options]", args[0]);
        eprintln!("  interface: Network interface to inject packets");
        eprintln!("  rules_dir: Path to rules directory (default: rules)");
        eprintln!("  max_rules: Maximum rules to process (default: 1000)");
        eprintln!("  Options:");
        eprintln!("    --scans       Generate scan packets (SYN, FIN, XMAS, NULL, etc.)");
        eprintln!("    --bruteforce  Generate brute force attack packets (SSH, FTP, HTTP, etc.)");
        eprintln!("    --handshake   Use TCP handshake for established connections");
        eprintln!("    --all         Include rules requiring established connections");
        std::process::exit(1);
    }

    let interface = &args[1];
    let rules_dir = args.get(2).map(|s| s.as_str()).unwrap_or("rules");
    let max_rules: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1000);

    let do_scans = args.iter().any(|a| a == "--scans");
    let do_bruteforce = args.iter().any(|a| a == "--bruteforce");
    let do_handshake = args.iter().any(|a| a == "--handshake");
    let include_established = args.iter().any(|a| a == "--all");

    println!("Synthetic Packet Generator");
    println!("  Interface: {}", interface);
    println!("  Rules dir: {}", rules_dir);
    println!("  Max rules: {}", max_rules);
    println!("  Scans: {}", do_scans);
    println!("  Brute force: {}", do_bruteforce);
    println!("  Handshake: {}", do_handshake);
    println!("  Include established: {}", include_established);
    println!();

    let mut sender = PacketSender::new(interface)?;

    // Generate scan packets first
    if do_scans {
        println!("Generating scan packets...");
        generate_scan_packets(&mut sender)?;
    }

    // Generate brute force packets
    if do_bruteforce {
        println!("Generating brute force attack packets...");
        generate_bruteforce_packets(&mut sender)?;
    }

    // Parse and send rule-based packets
    println!("Parsing rules...");
    let rules = parse_rules_dir(rules_dir, max_rules, include_established)?;
    println!("Parsed {} rules with content patterns", rules.len());

    println!("Sending rule-triggered packets...");
    send_rule_packets(&mut sender, &rules, do_handshake)?;

    println!("\nComplete!");
    sender.stats();

    Ok(())
}

/// Generate various scan packet types
fn generate_scan_packets(sender: &mut PacketSender) -> anyhow::Result<()> {
    let target_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 993, 995,
                        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017];
    let src_ips = [
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(10, 0, 0, 50),
        Ipv4Addr::new(172, 16, 0, 25),
    ];
    let dst_ip = Ipv4Addr::new(10, 0, 0, 1);

    // SYN Scan - most common
    println!("  SYN scan...");
    for &port in &target_ports {
        for &src_ip in &src_ips {
            if let Some(pkt) = build_tcp_scan(src_ip, dst_ip, port, TCP_SYN) {
                sender.send(&pkt, "syn_scan");
            }
        }
    }

    // FIN Scan - stealthy
    println!("  FIN scan...");
    for &port in &target_ports[..10] {
        if let Some(pkt) = build_tcp_scan(src_ips[0], dst_ip, port, TCP_FIN) {
            sender.send(&pkt, "fin_scan");
        }
    }

    // NULL Scan - no flags
    println!("  NULL scan...");
    for &port in &target_ports[..10] {
        if let Some(pkt) = build_tcp_scan(src_ips[0], dst_ip, port, 0) {
            sender.send(&pkt, "null_scan");
        }
    }

    // XMAS Scan - FIN+PSH+URG
    println!("  XMAS scan...");
    for &port in &target_ports[..10] {
        if let Some(pkt) = build_tcp_scan(src_ips[0], dst_ip, port, TCP_FIN | TCP_PSH | TCP_URG) {
            sender.send(&pkt, "xmas_scan");
        }
    }

    // ACK Scan - firewall detection
    println!("  ACK scan...");
    for &port in &target_ports[..10] {
        if let Some(pkt) = build_tcp_scan(src_ips[0], dst_ip, port, TCP_ACK) {
            sender.send(&pkt, "ack_scan");
        }
    }

    // Window Scan
    println!("  Window scan...");
    for &port in &target_ports[..5] {
        if let Some(pkt) = build_tcp_scan(src_ips[0], dst_ip, port, TCP_ACK) {
            sender.send(&pkt, "window_scan");
        }
    }

    // UDP Scan
    println!("  UDP scan...");
    let udp_ports = [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 5353];
    for &port in &udp_ports {
        if let Some(pkt) = build_udp_packet_full(src_ips[0], dst_ip, 54321, port, &[]) {
            sender.send(&pkt, "udp_scan");
        }
    }

    // ICMP Ping sweep
    println!("  ICMP ping sweep...");
    for i in 1..20 {
        let target = Ipv4Addr::new(10, 0, 0, i);
        if let Some(pkt) = build_icmp_echo(src_ips[0], target, i as u16) {
            sender.send(&pkt, "icmp_ping");
        }
    }

    // Port sweep - one host, many ports (rapid)
    println!("  Port sweep...");
    for port in (1..1024).step_by(50) {
        if let Some(pkt) = build_tcp_scan(src_ips[0], dst_ip, port, TCP_SYN) {
            sender.send(&pkt, "port_sweep");
        }
    }

    // RST Flood simulation
    println!("  RST packets...");
    for &port in &target_ports[..5] {
        if let Some(pkt) = build_tcp_scan(src_ips[0], dst_ip, port, TCP_RST) {
            sender.send(&pkt, "rst_packet");
        }
    }

    // SYN-ACK (response simulation)
    println!("  SYN-ACK packets...");
    for &port in &target_ports[..5] {
        if let Some(pkt) = build_tcp_scan(dst_ip, src_ips[0], port, TCP_SYN | TCP_ACK) {
            sender.send(&pkt, "syn_ack");
        }
    }

    Ok(())
}

/// Generate brute force attack simulation packets
fn generate_bruteforce_packets(sender: &mut PacketSender) -> anyhow::Result<()> {
    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 1);

    // Common usernames for brute force
    let usernames = ["root", "admin", "administrator", "user", "guest", "test",
                     "oracle", "postgres", "mysql", "ftp", "www-data", "nobody"];

    // Common weak passwords
    let passwords = ["password", "123456", "admin", "root", "12345678", "qwerty",
                     "abc123", "password123", "letmein", "welcome", "monkey", "dragon"];

    // SSH Brute Force (port 22)
    println!("  SSH brute force...");
    for username in &usernames[..6] {
        for password in &passwords[..6] {
            // SSH password auth attempt pattern
            let payload = format!(
                "SSH-2.0-OpenSSH_8.0\r\n\x00\x00\x00\x14\x05{}\x00{}\x00",
                username, password
            );
            send_tcp_handshake(sender, src_ip, dst_ip, 54321, 22)?;
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54321, 22, payload.as_bytes(), TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "ssh_bruteforce");
            }
        }
    }

    // FTP Brute Force (port 21)
    println!("  FTP brute force...");
    for username in &usernames[..6] {
        for password in &passwords[..6] {
            // FTP USER and PASS commands
            let user_cmd = format!("USER {}\r\n", username);
            let pass_cmd = format!("PASS {}\r\n", password);

            send_tcp_handshake(sender, src_ip, dst_ip, 54322, 21)?;
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54322, 21, user_cmd.as_bytes(), TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "ftp_bruteforce");
            }
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54322, 21, pass_cmd.as_bytes(), TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "ftp_bruteforce");
            }
        }
    }

    // Telnet Brute Force (port 23)
    println!("  Telnet brute force...");
    for username in &usernames[..4] {
        for password in &passwords[..4] {
            let payload = format!("{}\r\n{}\r\n", username, password);
            send_tcp_handshake(sender, src_ip, dst_ip, 54323, 23)?;
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54323, 23, payload.as_bytes(), TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "telnet_bruteforce");
            }
        }
    }

    // HTTP Basic Auth Brute Force (port 80)
    println!("  HTTP Basic Auth brute force...");
    for username in &usernames[..4] {
        for password in &passwords[..4] {
            // Base64 encode credentials (simplified - not actual base64)
            let auth = format!("{}:{}", username, password);
            let http_request = format!(
                "GET /admin HTTP/1.1\r\nHost: target.local\r\nAuthorization: Basic {}\r\n\r\n",
                auth
            );
            send_tcp_handshake(sender, src_ip, dst_ip, 54324, 80)?;
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54324, 80, http_request.as_bytes(), TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "http_bruteforce");
            }
        }
    }

    // HTTP Form-based Login Brute Force
    println!("  HTTP form login brute force...");
    for username in &usernames[..4] {
        for password in &passwords[..4] {
            let body = format!("username={}&password={}", username, password);
            let http_request = format!(
                "POST /login HTTP/1.1\r\nHost: target.local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}",
                body.len(), body
            );
            send_tcp_handshake(sender, src_ip, dst_ip, 54325, 80)?;
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54325, 80, http_request.as_bytes(), TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "http_form_bruteforce");
            }
        }
    }

    // MySQL Brute Force (port 3306)
    println!("  MySQL brute force...");
    for username in &usernames[..4] {
        for password in &passwords[..4] {
            // MySQL auth packet (simplified) - build as bytes to handle high-value escapes
            let mut payload = vec![0x00, 0x00, 0x01, 0x85, 0xa6, 0x03, 0x00];
            payload.extend_from_slice(username.as_bytes());
            payload.push(0x00);
            payload.extend_from_slice(password.as_bytes());
            payload.push(0x00);
            payload.extend_from_slice(b"mysql_native_password\x00");
            send_tcp_handshake(sender, src_ip, dst_ip, 54326, 3306)?;
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54326, 3306, &payload, TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "mysql_bruteforce");
            }
        }
    }

    // PostgreSQL Brute Force (port 5432)
    println!("  PostgreSQL brute force...");
    for username in &usernames[..4] {
        for password in &passwords[..4] {
            // PostgreSQL startup message (simplified)
            let payload = format!("\x00\x00\x00\x50\x00\x03\x00\x00user\x00{}\x00database\x00postgres\x00\x00",
                username);
            send_tcp_handshake(sender, src_ip, dst_ip, 54327, 5432)?;
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54327, 5432, payload.as_bytes(), TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "postgres_bruteforce");
            }
        }
    }

    // SMTP Auth Brute Force (port 25/587)
    println!("  SMTP auth brute force...");
    for username in &usernames[..4] {
        for password in &passwords[..4] {
            let payload = format!("AUTH LOGIN\r\n{}\r\n{}\r\n", username, password);
            send_tcp_handshake(sender, src_ip, dst_ip, 54328, 25)?;
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54328, 25, payload.as_bytes(), TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "smtp_bruteforce");
            }
        }
    }

    // POP3 Brute Force (port 110)
    println!("  POP3 brute force...");
    for username in &usernames[..4] {
        for password in &passwords[..4] {
            let payload = format!("USER {}\r\nPASS {}\r\n", username, password);
            send_tcp_handshake(sender, src_ip, dst_ip, 54329, 110)?;
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54329, 110, payload.as_bytes(), TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "pop3_bruteforce");
            }
        }
    }

    // IMAP Brute Force (port 143)
    println!("  IMAP brute force...");
    for username in &usernames[..4] {
        for password in &passwords[..4] {
            let payload = format!("a001 LOGIN {} {}\r\n", username, password);
            send_tcp_handshake(sender, src_ip, dst_ip, 54330, 143)?;
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54330, 143, payload.as_bytes(), TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "imap_bruteforce");
            }
        }
    }

    // RDP Brute Force (port 3389) - NLA negotiation
    println!("  RDP brute force...");
    for username in &usernames[..4] {
        // RDP connection request with username hint - build as bytes
        let mut payload = vec![0x03, 0x00, 0x00, 0x2f, 0x2a, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00];
        payload.extend_from_slice(b"Cookie: mstshash=");
        payload.extend_from_slice(username.as_bytes());
        payload.extend_from_slice(b"\r\n");
        payload.extend_from_slice(&[0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00]);
        send_tcp_handshake(sender, src_ip, dst_ip, 54331, 3389)?;
        if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54331, 3389, &payload, TCP_ACK | TCP_PSH) {
            sender.send(&pkt, "rdp_bruteforce");
        }
    }

    // VNC Brute Force (port 5900)
    println!("  VNC brute force...");
    for password in &passwords[..8] {
        // VNC auth response (DES encrypted challenge - simplified)
        let payload = format!("RFB 003.008\n\x02\x01\x02{:016}", password);
        send_tcp_handshake(sender, src_ip, dst_ip, 54332, 5900)?;
        if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54332, 5900, payload.as_bytes(), TCP_ACK | TCP_PSH) {
            sender.send(&pkt, "vnc_bruteforce");
        }
    }

    // Redis Brute Force (port 6379)
    println!("  Redis auth brute force...");
    for password in &passwords[..8] {
        let payload = format!("*2\r\n$4\r\nAUTH\r\n${}\r\n{}\r\n", password.len(), password);
        send_tcp_handshake(sender, src_ip, dst_ip, 54333, 6379)?;
        if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54333, 6379, payload.as_bytes(), TCP_ACK | TCP_PSH) {
            sender.send(&pkt, "redis_bruteforce");
        }
    }

    // MongoDB Brute Force (port 27017)
    println!("  MongoDB auth brute force...");
    for username in &usernames[..4] {
        for password in &passwords[..4] {
            // MongoDB auth command (simplified BSON) - build as bytes
            let mut payload = vec![0x3a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            payload.extend_from_slice(b"admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00authenticate\x00\x02user\x00");
            payload.extend_from_slice(username.as_bytes());
            payload.extend_from_slice(b"\x00\x02pwd\x00");
            payload.extend_from_slice(password.as_bytes());
            payload.push(0x00);
            send_tcp_handshake(sender, src_ip, dst_ip, 54334, 27017)?;
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54334, 27017, &payload, TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "mongodb_bruteforce");
            }
        }
    }

    // LDAP Brute Force (port 389)
    println!("  LDAP bind brute force...");
    for username in &usernames[..4] {
        for password in &passwords[..4] {
            // LDAP simple bind request (simplified) - build as bytes
            let dn = format!("cn={},dc=example,dc=com", username);
            let mut payload = vec![0x30, 0x2d, 0x02, 0x01, 0x01, 0x60, 0x28, 0x02, 0x01, 0x03, 0x04];
            payload.extend_from_slice(dn.as_bytes());
            payload.push(0x80);
            payload.extend_from_slice(password.as_bytes());
            send_tcp_handshake(sender, src_ip, dst_ip, 54335, 389)?;
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54335, 389, &payload, TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "ldap_bruteforce");
            }
        }
    }

    // SMB Brute Force (port 445)
    println!("  SMB auth brute force...");
    for username in &usernames[..4] {
        for password in &passwords[..4] {
            // SMB session setup (simplified NTLMSSP) - build as bytes
            let mut payload = vec![0x00, 0x00, 0x00, 0x55, 0xff];
            payload.extend_from_slice(b"SMB\x73\x00\x00\x00\x00\x18\x07");
            payload.push(0xc0);
            payload.extend_from_slice(b"NTLMSSP\x00\x03\x00\x00\x00");
            payload.extend_from_slice(username.as_bytes());
            payload.push(0x00);
            payload.extend_from_slice(password.as_bytes());
            payload.extend_from_slice(b"\x00WORKGROUP\x00");
            send_tcp_handshake(sender, src_ip, dst_ip, 54336, 445)?;
            if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 54336, 445, &payload, TCP_ACK | TCP_PSH) {
                sender.send(&pkt, "smb_bruteforce");
            }
        }
    }

    Ok(())
}

/// Send packets for parsed rules
fn send_rule_packets(sender: &mut PacketSender, rules: &[RuleInfo], do_handshake: bool) -> anyhow::Result<()> {
    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(10, 0, 0, 1);

    for rule in rules {
        // Build packet payload with all content patterns
        let mut payload = Vec::new();
        for content in &rule.contents {
            payload.extend_from_slice(content);
            payload.push(b' '); // Separator
        }

        if payload.is_empty() {
            continue;
        }

        let dst_port = match rule.dst_port {
            Some(p) => p,
            None => continue,
        };

        match rule.protocol.as_str() {
            "tcp" => {
                if rule.is_established && do_handshake {
                    // Send TCP handshake first
                    send_tcp_handshake(sender, src_ip, dst_ip, 12345, dst_port)?;
                    // Small delay to let flow tracker process
                    thread::sleep(Duration::from_micros(100));
                }

                // Send data packet
                let flags = if rule.is_established {
                    TCP_ACK | TCP_PSH
                } else {
                    TCP_SYN
                };

                if let Some(pkt) = build_tcp_data(src_ip, dst_ip, 12345, dst_port, &payload, flags) {
                    let pkt_type = if rule.is_established { "tcp_established" } else { "tcp_data" };
                    sender.send(&pkt, pkt_type);
                }
            }
            "udp" => {
                if let Some(pkt) = build_udp_packet_full(src_ip, dst_ip, 12345, dst_port, &payload) {
                    sender.send(&pkt, "udp_data");
                }
            }
            _ => {}
        }

        if sender.sent % 100 == 0 {
            print!("\rSent {} packets...", sender.sent);
            std::io::Write::flush(&mut std::io::stdout())?;
        }
    }

    Ok(())
}

/// Send a TCP three-way handshake
fn send_tcp_handshake(
    sender: &mut PacketSender,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> anyhow::Result<()> {
    // SYN
    if let Some(pkt) = build_tcp_handshake_packet(src_ip, dst_ip, src_port, dst_port, 1000, 0, TCP_SYN) {
        sender.send(&pkt, "handshake_syn");
    }
    thread::sleep(Duration::from_micros(50));

    // SYN-ACK (simulated response)
    if let Some(pkt) = build_tcp_handshake_packet(dst_ip, src_ip, dst_port, src_port, 2000, 1001, TCP_SYN | TCP_ACK) {
        sender.send(&pkt, "handshake_synack");
    }
    thread::sleep(Duration::from_micros(50));

    // ACK
    if let Some(pkt) = build_tcp_handshake_packet(src_ip, dst_ip, src_port, dst_port, 1001, 2001, TCP_ACK) {
        sender.send(&pkt, "handshake_ack");
    }

    Ok(())
}

/// Build a TCP handshake packet (no payload)
fn build_tcp_handshake_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
) -> Option<Vec<u8>> {
    // Ethernet (14) + IP (20) + TCP (20)
    let total_len = 14 + 20 + 20;
    let mut buffer = vec![0u8; total_len];

    // Ethernet header
    {
        let mut eth = MutableEthernetPacket::new(&mut buffer[0..14])?;
        eth.set_destination(pnet::util::MacAddr(0x00, 0x00, 0x00, 0x00, 0x00, 0x00));
        eth.set_source(pnet::util::MacAddr(0x00, 0x00, 0x00, 0x00, 0x00, 0x01));
        eth.set_ethertype(EtherTypes::Ipv4);
    }

    // IP header
    {
        let mut ip = MutableIpv4Packet::new(&mut buffer[14..34])?;
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(checksum);
    }

    // TCP header
    {
        let mut tcp = MutableTcpPacket::new(&mut buffer[34..54])?;
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(flags);
        tcp.set_window(65535);
    }

    Some(buffer)
}

/// Build a TCP scan packet (no payload)
fn build_tcp_scan(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, dst_port: u16, flags: u8) -> Option<Vec<u8>> {
    build_tcp_handshake_packet(src_ip, dst_ip, 54321, dst_port, 1000, 0, flags)
}

/// Build a TCP data packet with payload
fn build_tcp_data(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    flags: u8,
) -> Option<Vec<u8>> {
    // Ethernet (14) + IP (20) + TCP (20) + payload
    let total_len = 14 + 20 + 20 + payload.len();
    let mut buffer = vec![0u8; total_len];

    // Ethernet header
    {
        let mut eth = MutableEthernetPacket::new(&mut buffer[0..14])?;
        eth.set_destination(pnet::util::MacAddr(0x00, 0x00, 0x00, 0x00, 0x00, 0x00));
        eth.set_source(pnet::util::MacAddr(0x00, 0x00, 0x00, 0x00, 0x00, 0x01));
        eth.set_ethertype(EtherTypes::Ipv4);
    }

    // IP header
    {
        let mut ip = MutableIpv4Packet::new(&mut buffer[14..34])?;
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((20 + 20 + payload.len()) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(checksum);
    }

    // TCP header
    {
        let mut tcp = MutableTcpPacket::new(&mut buffer[34..54])?;
        tcp.set_source(src_port);
        tcp.set_destination(dst_port);
        tcp.set_sequence(1001);
        tcp.set_acknowledgement(2001);
        tcp.set_data_offset(5);
        tcp.set_flags(flags);
        tcp.set_window(65535);
    }

    // Payload
    buffer[54..].copy_from_slice(payload);

    Some(buffer)
}

/// Build a UDP packet with full control
fn build_udp_packet_full(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    // Ethernet (14) + IP (20) + UDP (8) + payload
    let total_len = 14 + 20 + 8 + payload.len();
    let mut buffer = vec![0u8; total_len];

    // Ethernet header
    {
        let mut eth = MutableEthernetPacket::new(&mut buffer[0..14])?;
        eth.set_destination(pnet::util::MacAddr(0x00, 0x00, 0x00, 0x00, 0x00, 0x00));
        eth.set_source(pnet::util::MacAddr(0x00, 0x00, 0x00, 0x00, 0x00, 0x01));
        eth.set_ethertype(EtherTypes::Ipv4);
    }

    // IP header
    {
        let mut ip = MutableIpv4Packet::new(&mut buffer[14..34])?;
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((20 + 8 + payload.len()) as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(checksum);
    }

    // UDP header
    {
        let mut udp = MutableUdpPacket::new(&mut buffer[34..42])?;
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length((8 + payload.len()) as u16);
    }

    // Payload
    if !payload.is_empty() {
        buffer[42..].copy_from_slice(payload);
    }

    Some(buffer)
}

/// Build an ICMP echo request
fn build_icmp_echo(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, id: u16) -> Option<Vec<u8>> {
    // Ethernet (14) + IP (20) + ICMP (8)
    let total_len = 14 + 20 + 8;
    let mut buffer = vec![0u8; total_len];

    // Ethernet header
    {
        let mut eth = MutableEthernetPacket::new(&mut buffer[0..14])?;
        eth.set_destination(pnet::util::MacAddr(0x00, 0x00, 0x00, 0x00, 0x00, 0x00));
        eth.set_source(pnet::util::MacAddr(0x00, 0x00, 0x00, 0x00, 0x00, 0x01));
        eth.set_ethertype(EtherTypes::Ipv4);
    }

    // IP header
    {
        let mut ip = MutableIpv4Packet::new(&mut buffer[14..34])?;
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(28);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip.set_source(src_ip);
        ip.set_destination(dst_ip);
        let checksum = pnet::packet::ipv4::checksum(&ip.to_immutable());
        ip.set_checksum(checksum);
    }

    // ICMP header - set type/code first, then id/seq, then checksum
    {
        let mut icmp = MutableIcmpPacket::new(&mut buffer[34..42])?;
        icmp.set_icmp_type(IcmpTypes::EchoRequest);
        icmp.set_icmp_code(pnet::packet::icmp::IcmpCode::new(0));
    }
    // Set identifier and sequence in payload area (after ICMP header)
    buffer[38] = (id >> 8) as u8;
    buffer[39] = (id & 0xff) as u8;
    buffer[40] = 0;
    buffer[41] = 1;
    // Calculate checksum over full ICMP packet
    {
        let icmp = MutableIcmpPacket::new(&mut buffer[34..42])?;
        let checksum = pnet::packet::icmp::checksum(&icmp.to_immutable());
        let mut icmp = MutableIcmpPacket::new(&mut buffer[34..42])?;
        icmp.set_checksum(checksum);
    }

    Some(buffer)
}

/// Parse rules directory and extract content patterns
fn parse_rules_dir(dir: &str, max_rules: usize, include_established: bool) -> anyhow::Result<Vec<RuleInfo>> {
    let mut rules = Vec::new();
    let path = Path::new(dir);

    if !path.exists() {
        anyhow::bail!("Rules directory not found: {}", dir);
    }

    // Regex patterns for parsing rules
    let sid_re = Regex::new(r"sid:(\d+)")?;
    let msg_re = Regex::new(r#"msg:"([^"]+)""#)?;
    let content_re = Regex::new(r#"content:"([^"]+)""#)?;
    let content_hex_re = Regex::new(r#"content:\|([^|]+)\|"#)?;
    let flow_re = Regex::new(r"flow:([^;]+)")?;
    let header_re = Regex::new(r"^alert\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s+\(")?;

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let file_path = entry.path();

        if file_path.extension().map(|e| e == "rules").unwrap_or(false) {
            let content = fs::read_to_string(&file_path)?;

            for line in content.lines() {
                if rules.len() >= max_rules {
                    break;
                }

                let line = line.trim();
                if !line.starts_with("alert ") {
                    continue;
                }

                // Parse the header
                let header_caps = match header_re.captures(line) {
                    Some(caps) => caps,
                    None => continue,
                };

                let protocol = header_caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let protocol = match protocol {
                    "tcp" | "http" => "tcp",
                    "udp" => "udp",
                    _ => continue,
                };

                let src_port_str = header_caps.get(3).map(|m| m.as_str()).unwrap_or("any");
                let dst_port_str = header_caps.get(5).map(|m| m.as_str()).unwrap_or("any");

                let src_port: Option<u16> = src_port_str.parse().ok();
                let dst_port: Option<u16> = dst_port_str.parse().ok();

                if dst_port.is_none() {
                    continue;
                }

                let sid = match sid_re.captures(line) {
                    Some(caps) => caps.get(1).unwrap().as_str().parse().unwrap_or(0),
                    None => continue,
                };

                let msg = msg_re.captures(line)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default();

                // Extract content patterns
                let mut contents = Vec::new();

                for caps in content_re.captures_iter(line) {
                    if let Some(m) = caps.get(1) {
                        let bytes = unescape_content(m.as_str());
                        if bytes.len() >= 4 {
                            contents.push(bytes);
                        }
                    }
                }

                for caps in content_hex_re.captures_iter(line) {
                    if let Some(m) = caps.get(1) {
                        if let Some(bytes) = parse_hex_content(m.as_str()) {
                            if bytes.len() >= 4 {
                                contents.push(bytes);
                            }
                        }
                    }
                }

                if contents.is_empty() {
                    continue;
                }

                let is_established = flow_re.captures(line)
                    .map(|c| c.get(1).unwrap().as_str().contains("established"))
                    .unwrap_or(false);

                // Skip established rules unless explicitly included
                if is_established && !include_established {
                    continue;
                }

                rules.push(RuleInfo {
                    sid,
                    _msg: msg,
                    protocol: protocol.to_string(),
                    _src_port: src_port,
                    dst_port,
                    contents,
                    is_established,
                });
            }
        }

        if rules.len() >= max_rules {
            break;
        }
    }

    Ok(rules)
}

/// Unescape content string
fn unescape_content(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('r') => result.push(b'\r'),
                Some('n') => result.push(b'\n'),
                Some('t') => result.push(b'\t'),
                Some('\\') => result.push(b'\\'),
                Some('"') => result.push(b'"'),
                Some('x') => {
                    let mut hex = String::new();
                    if let Some(&c1) = chars.peek() {
                        if c1.is_ascii_hexdigit() {
                            hex.push(chars.next().unwrap());
                            if let Some(&c2) = chars.peek() {
                                if c2.is_ascii_hexdigit() {
                                    hex.push(chars.next().unwrap());
                                }
                            }
                        }
                    }
                    if let Ok(b) = u8::from_str_radix(&hex, 16) {
                        result.push(b);
                    }
                }
                Some(c) => result.push(c as u8),
                None => {}
            }
        } else {
            result.push(c as u8);
        }
    }

    result
}

/// Parse hex content like "00 01 02 03"
fn parse_hex_content(s: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();

    for part in s.split_whitespace() {
        if let Ok(b) = u8::from_str_radix(part, 16) {
            result.push(b);
        } else {
            return None;
        }
    }

    Some(result)
}
