//! Nginx log validation tool
//!
//! Validates detection patterns against real nginx access logs.
//! Includes Cloudflare IP detection and real IP extraction.

use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use crmonban::cloudflare::CloudflareChecker;

#[derive(Debug)]
struct Pattern {
    name: &'static str,
    regex: Regex,
    event_type: &'static str,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let log_path = args.get(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from("/home/svvs/nginx/access.log")
    });

    println!("=== Nginx Access Log Attack Validation ===\n");
    println!("Log file: {}\n", log_path.display());

    // Initialize Cloudflare checker
    let cf_checker = CloudflareChecker::new();

    let patterns = vec![
        Pattern {
            name: "sql_injection_union",
            regex: Regex::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(?i)(union\+select|union%20select|UNION\s+SELECT)").unwrap(),
            event_type: "exploit",
        },
        Pattern {
            name: "path_traversal",
            regex: Regex::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(\.\.\/|\.\.%2[fF]|\.\.%252[fF])").unwrap(),
            event_type: "exploit",
        },
        Pattern {
            name: "env_file_probe",
            regex: Regex::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+).*GET.*/\.env").unwrap(),
            event_type: "exploit",
        },
        Pattern {
            name: "git_probe",
            regex: Regex::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+).*GET.*/\.git/").unwrap(),
            event_type: "exploit",
        },
        Pattern {
            name: "wordpress_probe",
            regex: Regex::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(wp-login\.php|xmlrpc\.php|wp-admin)").unwrap(),
            event_type: "exploit",
        },
        Pattern {
            name: "shell_access",
            regex: Regex::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(shell\.php|c99\.php|r57\.php|cmd\.php|eval\()").unwrap(),
            event_type: "exploit",
        },
        Pattern {
            name: "config_probe",
            regex: Regex::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(config\.json|\.bak|\.sql|aws-config)").unwrap(),
            event_type: "exploit",
        },
        Pattern {
            name: "scanner_uagent",
            regex: Regex::new(r#"(?P<ip>\d+\.\d+\.\d+\.\d+).*"(nikto|sqlmap|nmap|masscan|nuclei|zgrab)"#).unwrap(),
            event_type: "exploit",
        },
        Pattern {
            name: "docker_probe",
            regex: Regex::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+).*/\.docker/").unwrap(),
            event_type: "exploit",
        },
        Pattern {
            name: "credentials_probe",
            regex: Regex::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(\.aws/credentials|\.ssh/|id_rsa)").unwrap(),
            event_type: "exploit",
        },
        Pattern {
            name: "pearcmd_exploit",
            regex: Regex::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+).*pearcmd").unwrap(),
            event_type: "exploit",
        },
        Pattern {
            name: "php_info",
            regex: Regex::new(r"(?P<ip>\d+\.\d+\.\d+\.\d+).*phpinfo").unwrap(),
            event_type: "exploit",
        },
    ];

    let file = File::open(&log_path).context("Failed to open log file")?;
    let reader = BufReader::new(file);

    let mut detections_by_pattern: HashMap<&str, Vec<String>> = HashMap::new();
    let mut detections_by_ip: HashMap<String, usize> = HashMap::new();
    let mut cloudflare_ips: HashMap<String, usize> = HashMap::new();
    let mut real_ips: HashMap<String, usize> = HashMap::new();
    let mut total_lines = 0;
    let mut total_detections = 0;
    let mut cf_proxied_attacks = 0;

    for line_result in reader.lines() {
        let line = line_result?;
        total_lines += 1;

        for pattern in &patterns {
            if let Some(captures) = pattern.regex.captures(&line) {
                if let Some(ip_match) = captures.name("ip") {
                    let ip_str = ip_match.as_str();
                    let ip = ip_str.to_string();

                    // Check if this is a Cloudflare IP
                    if let Ok(parsed_ip) = IpAddr::from_str(ip_str) {
                        if cf_checker.is_cloudflare_ip(parsed_ip) {
                            *cloudflare_ips.entry(ip.clone()).or_default() += 1;
                            cf_proxied_attacks += 1;
                        } else {
                            *real_ips.entry(ip.clone()).or_default() += 1;
                        }
                    }

                    detections_by_pattern
                        .entry(pattern.name)
                        .or_default()
                        .push(ip.clone());

                    *detections_by_ip.entry(ip).or_default() += 1;
                    total_detections += 1;
                    break; // Only count first matching pattern
                }
            }
        }
    }

    println!("Total lines processed: {}", total_lines);
    println!("Total detections: {}", total_detections);
    println!("Unique IPs (all): {}", detections_by_ip.len());
    println!("  - Cloudflare proxy IPs: {} ({} attacks)", cloudflare_ips.len(), cf_proxied_attacks);
    println!("  - Real client IPs: {} ({} attacks)\n", real_ips.len(), total_detections - cf_proxied_attacks);

    println!("=== Detections by Pattern ===\n");
    let mut pattern_counts: Vec<_> = detections_by_pattern.iter()
        .map(|(name, ips)| (*name, ips.len()))
        .collect();
    pattern_counts.sort_by(|a, b| b.1.cmp(&a.1));

    for (name, count) in &pattern_counts {
        println!("{:25} {:6} detections", name, count);
    }

    println!("\n=== Top 20 Attacking IPs ===\n");
    let mut ip_counts: Vec<_> = detections_by_ip.iter().collect();
    ip_counts.sort_by(|a, b| b.1.cmp(a.1));

    for (ip, count) in ip_counts.iter().take(20) {
        println!("{:20} {:6} events", ip, count);
    }

    // Check which IPs would be banned (threshold: 5)
    let threshold = 5;
    let would_ban: Vec<_> = ip_counts.iter()
        .filter(|(_, count)| **count >= threshold)
        .collect();

    println!("\n=== IPs That Would Be Banned (>= {} events) ===\n", threshold);
    println!("Total: {} IPs\n", would_ban.len());
    for (ip, count) in would_ban.iter().take(30) {
        println!("{:20} {:6} events", ip, count);
    }

    // Show real client IPs (non-Cloudflare) that would be banned
    println!("\n=== Real Client IPs (non-Cloudflare) ===\n");
    let mut real_ip_counts: Vec<_> = real_ips.iter().collect();
    real_ip_counts.sort_by(|a, b| b.1.cmp(a.1));

    println!("Top 20 real attacking IPs:\n");
    for (ip, count) in real_ip_counts.iter().take(20) {
        println!("{:20} {:6} events", ip, count);
    }

    let real_would_ban: Vec<_> = real_ip_counts.iter()
        .filter(|(_, count)| **count >= threshold)
        .collect();

    println!("\nReal IPs that SHOULD be banned: {} IPs\n", real_would_ban.len());
    for (ip, count) in real_would_ban.iter().take(30) {
        println!("{:20} {:6} events", ip, count);
    }

    // Cloudflare analysis
    println!("\n=== Cloudflare Proxy Analysis ===\n");
    println!("WARNING: {} attacks came through Cloudflare proxies.", cf_proxied_attacks);
    println!("These IPs are Cloudflare's, NOT the real attackers.");
    println!("\nTo get real attacker IPs, configure nginx to log CF-Connecting-IP.");
    println!("See: docs/nginx-cloudflare-setup.md");

    if !cloudflare_ips.is_empty() {
        println!("\nCloudflare proxy IPs seen (do NOT ban these):");
        let mut cf_counts: Vec<_> = cloudflare_ips.iter().collect();
        cf_counts.sort_by(|a, b| b.1.cmp(a.1));
        for (ip, count) in cf_counts.iter().take(10) {
            println!("  {:20} {:6} attacks proxied", ip, count);
        }
    }

    Ok(())
}
