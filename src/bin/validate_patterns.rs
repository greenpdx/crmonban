//! Pattern validation tool
//!
//! Validates log detection patterns against sample attack logs.
//! Usage: cargo run --bin validate_patterns -- [sample_log_dir]

use anyhow::{Context, Result};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
struct Pattern {
    name: String,
    regex: Regex,
    event_type: String,
}

#[derive(Debug)]
struct DetectionResult {
    ip: IpAddr,
    pattern_name: String,
    event_type: String,
    log_line: String,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let sample_dir = args.get(1).map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from("tests/sample_attack_logs")
    });

    println!("=== Crmonban Pattern Validation Tool ===\n");
    println!("Sample log directory: {}\n", sample_dir.display());

    // Load patterns from config
    let patterns = load_patterns()?;
    println!("Loaded {} patterns\n", patterns.len());

    // Process each log file
    let mut total_detections = 0;
    let mut detections_by_ip: HashMap<IpAddr, Vec<DetectionResult>> = HashMap::new();

    for entry in fs::read_dir(&sample_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map_or(false, |e| e == "log") {
            println!("Processing: {}", path.display());

            let content = fs::read_to_string(&path)?;
            let mut file_detections = 0;

            for line in content.lines() {
                // Skip comments and empty lines
                if line.starts_with('#') || line.trim().is_empty() {
                    continue;
                }

                for pattern in &patterns {
                    if let Some(captures) = pattern.regex.captures(line) {
                        if let Some(ip_match) = captures.name("ip") {
                            if let Ok(ip) = ip_match.as_str().parse::<IpAddr>() {
                                let result = DetectionResult {
                                    ip,
                                    pattern_name: pattern.name.clone(),
                                    event_type: pattern.event_type.clone(),
                                    log_line: line.to_string(),
                                };

                                detections_by_ip.entry(ip).or_default().push(result);
                                file_detections += 1;
                                total_detections += 1;
                                break; // Only count first matching pattern per line
                            }
                        }
                    }
                }
            }

            println!("  Detections: {}", file_detections);
        }
    }

    // Print summary
    println!("\n=== Detection Summary ===\n");
    println!("Total detections: {}", total_detections);
    println!("Unique IPs detected: {}\n", detections_by_ip.len());

    // Print detections by IP
    println!("=== Detections by IP ===\n");
    let mut ips: Vec<_> = detections_by_ip.keys().collect();
    ips.sort();

    for ip in ips {
        let detections = &detections_by_ip[ip];
        println!("IP: {} ({} events)", ip, detections.len());

        // Group by pattern
        let mut by_pattern: HashMap<&str, usize> = HashMap::new();
        for d in detections {
            *by_pattern.entry(&d.pattern_name).or_default() += 1;
        }

        for (pattern, count) in by_pattern {
            println!("  - {}: {} events", pattern, count);
        }
        println!();
    }

    // Check for patterns that didn't match anything
    println!("=== Pattern Coverage ===\n");
    let matched_patterns: std::collections::HashSet<_> = detections_by_ip
        .values()
        .flatten()
        .map(|d| d.pattern_name.as_str())
        .collect();

    let unmatched: Vec<_> = patterns
        .iter()
        .filter(|p| !matched_patterns.contains(p.name.as_str()))
        .collect();

    if unmatched.is_empty() {
        println!("All patterns matched at least one log line!");
    } else {
        println!("Patterns with no matches ({}):", unmatched.len());
        for p in unmatched {
            println!("  - {} ({})", p.name, p.event_type);
        }
    }

    // Simulate ban decisions
    println!("\n=== Ban Simulation (threshold: 5 events) ===\n");
    let threshold = 5;

    for (ip, detections) in &detections_by_ip {
        if detections.len() >= threshold {
            println!("WOULD BAN: {} ({} events)", ip, detections.len());
        }
    }

    Ok(())
}

fn load_patterns() -> Result<Vec<Pattern>> {
    let mut patterns = Vec::new();

    // SSH patterns
    let ssh_patterns = vec![
        ("failed_password", r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)", "failed_auth"),
        ("invalid_user", r"Invalid user .* from (?P<ip>\d+\.\d+\.\d+\.\d+)", "invalid_user"),
        ("connection_closed_preauth", r"Connection closed by (?P<ip>\d+\.\d+\.\d+\.\d+) port \d+ \[preauth\]", "failed_auth"),
        ("too_many_auth_failures", r"Disconnecting authenticating user .* (?P<ip>\d+\.\d+\.\d+\.\d+) .* Too many authentication failures", "brute_force"),
        ("failed_password_root", r"Failed password for root from (?P<ip>\d+\.\d+\.\d+\.\d+)", "brute_force"),
        ("refused_connect", r"refused connect from (?P<ip>\d+\.\d+\.\d+\.\d+)", "failed_auth"),
        ("did_not_receive_identification", r"Did not receive identification string from (?P<ip>\d+\.\d+\.\d+\.\d+)", "exploit"),
        ("connection_reset", r"Connection reset by (?P<ip>\d+\.\d+\.\d+\.\d+) port \d+ \[preauth\]", "failed_auth"),
        ("bad_protocol_version", r"Bad protocol version identification.*from (?P<ip>\d+\.\d+\.\d+\.\d+)", "exploit"),
        ("ssh_disconnect_protocol_error", r"Disconnected from (?P<ip>\d+\.\d+\.\d+\.\d+) port \d+.*protocol error", "exploit"),
        ("pam_auth_failure", r"pam_unix\(sshd:auth\): authentication failure.*rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)", "failed_auth"),
        ("publickey_not_accepted", r"Connection closed by authenticating user .* (?P<ip>\d+\.\d+\.\d+\.\d+) .* \[preauth\]", "failed_auth"),
        ("maximum_auth_attempts", r"error: maximum authentication attempts exceeded for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)", "brute_force"),
        ("ssh_banner_exchange", r"kex_exchange_identification: banner exchange: Connection reset by (?P<ip>\d+\.\d+\.\d+\.\d+)", "exploit"),
    ];

    for (name, regex, event_type) in ssh_patterns {
        patterns.push(Pattern {
            name: name.to_string(),
            regex: Regex::new(regex).context(format!("Invalid pattern: {}", name))?,
            event_type: event_type.to_string(),
        });
    }

    // Web attack patterns (nginx access log)
    let web_patterns = vec![
        ("sql_injection_union", r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(?i)(union\+select|union%20select|UNION SELECT)", "exploit"),
        ("sql_injection_or", r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(?i)(or%201%3D1|OR '1'='1|' or ''=')", "exploit"),
        ("path_traversal", r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(\.\.\/|\.\.%2f|\.\.%252f|\.\.\\)", "exploit"),
        ("xss_script", r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(<script|%3Cscript|javascript:)", "exploit"),
        ("cmd_injection", r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(;cat%20|%7Ccat|%60id%60|\$\()", "exploit"),
        ("wordpress_attack", r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(wp-login\.php|xmlrpc\.php|wp-admin).* 404", "exploit"),
        ("scanner_uagent", r#"(?P<ip>\d+\.\d+\.\d+\.\d+).*"(nikto|sqlmap|nmap|masscan|zgrab|nessus|nuclei)"#, "exploit"),
        ("shell_access", r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(shell\.php|c99\.php|r57\.php|b374k|cmd\.php)", "exploit"),
        ("sensitive_files", r"(?P<ip>\d+\.\d+\.\d+\.\d+).*(\.env|\.git|\.htaccess|\.htpasswd|wp-config\.php)", "exploit"),
        ("admin_bruteforce", r"(?P<ip>\d+\.\d+\.\d+\.\d+).*POST.*(\/admin|\/login|\/wp-login).* 401", "brute_force"),
    ];

    for (name, regex, event_type) in web_patterns {
        patterns.push(Pattern {
            name: name.to_string(),
            regex: Regex::new(regex).context(format!("Invalid pattern: {}", name))?,
            event_type: event_type.to_string(),
        });
    }

    Ok(patterns)
}
