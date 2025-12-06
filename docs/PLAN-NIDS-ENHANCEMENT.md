# Plan: Making crmonban the Best NIDS

Based on analysis of Snort, Suricata, Zeek, OSSEC, Security Onion, and Sagan, plus modern ML/AI research.

## Current crmonban Features
- nftables-based blocking (fast kernel-level)
- Log monitoring with regex patterns
- Port scan detection
- Deep packet inspection (DPI)
- TLS interception proxy
- eBPF malware detection
- DNS covert channel detection
- Port hopping detection
- Intel gathering (GeoIP, WHOIS, Shodan, AbuseIPDB)
- D-Bus API
- SIEM integration (Splunk, ELK, Graylog)
- Zone-based policies

## Features to Add (Priority Order)

### Phase 1: Core Detection Engine Enhancements

#### 1.1 Multi-threaded Packet Processing (like Suricata)
- **Why**: Snort's single-threaded model is a weakness; Suricata wins here
- **Implementation**: Use Rust's async/tokio with multiple NFQUEUE workers
- **Files**: New `src/packet_engine.rs`

#### 1.2 Signature-Based Detection with Suricata/Snort Rule Compatibility
- **Why**: Leverage 30,000+ community rules from Emerging Threats
- **Implementation**: Parse and execute Snort/Suricata rule syntax
- **Files**: New `src/rules/` module (parser, matcher, loader)

#### 1.3 Protocol Analyzers (like Zeek)
- **Why**: Deep protocol understanding catches more attacks
- **Protocols**: HTTP, DNS, TLS, SSH, SMTP, FTP, SMB, MySQL, Redis
- **Files**: New `src/protocols/` with per-protocol analyzers

#### 1.4 Connection Tracking & Flow Analysis
- **Why**: Zeek's strength - understanding conversations not just packets
- **Implementation**: Track TCP/UDP flows, compute flow statistics
- **Files**: New `src/flow_tracker.rs`

### Phase 2: Machine Learning & Anomaly Detection

#### 2.1 Behavioral Baseline Learning
- **Why**: Detect zero-day attacks that signatures miss
- **Implementation**: Learn normal traffic patterns, alert on deviations
- **Metrics**: Bytes/sec, packets/sec, connection rate, protocol distribution
- **Files**: New `src/ml/baseline.rs`

#### 2.2 ML-Based Classification
- **Why**: Modern IDS use Random Forest, XGBoost, neural networks
- **Implementation**: Use `linfa` or `smartcore` Rust ML crates
- **Features**: Flow duration, packet sizes, inter-arrival times, flags
- **Files**: New `src/ml/classifier.rs`

#### 2.3 Anomaly Scoring Engine
- **Why**: Reduce false positives with confidence scores
- **Implementation**: Combine multiple detection signals into risk score
- **Files**: New `src/ml/scoring.rs`

### Phase 3: Advanced Threat Detection

#### 3.1 JA3/JA3S TLS Fingerprinting
- **Why**: Identify malware by TLS client/server fingerprints
- **Implementation**: Hash TLS ClientHello parameters
- **Database**: Known malware JA3 hashes
- **Files**: Extend `src/tls_proxy.rs`

#### 3.2 HASSH SSH Fingerprinting
- **Why**: Detect malicious SSH clients/scanners
- **Implementation**: Hash SSH KEX parameters
- **Files**: New `src/protocols/ssh.rs`

#### 3.3 HTTP Request Anomaly Detection
- **Why**: Detect SQLi, XSS, command injection, path traversal
- **Implementation**: Already have basic DPI, enhance patterns
- **Files**: Extend `src/dpi.rs`

#### 3.4 Encrypted Traffic Analysis (ETA)
- **Why**: Detect threats in encrypted traffic without decryption
- **Implementation**: Analyze packet sizes, timing, TLS metadata
- **Files**: New `src/eta.rs`

### Phase 4: Threat Intelligence Integration

#### 4.1 Real-time Threat Feed Integration
- **Why**: Block known-bad IPs/domains immediately
- **Feeds**: AlienVault OTX, Abuse.ch, EmergingThreats, Spamhaus
- **Files**: Extend `src/intel.rs`

#### 4.2 MITRE ATT&CK Mapping
- **Why**: Map detections to attack techniques for SOC analysts
- **Implementation**: Tag alerts with ATT&CK IDs
- **Files**: New `src/mitre.rs`

#### 4.3 IOC Extraction & Sharing
- **Why**: Extract and export indicators of compromise
- **Formats**: STIX/TAXII, OpenIOC
- **Files**: New `src/ioc.rs`

### Phase 5: Visualization & Management

#### 5.1 Web Dashboard
- **Why**: Security Onion's strength is unified UI
- **Implementation**: Rust web server (axum) + React/HTMX frontend
- **Features**: Real-time alerts, traffic graphs, rule management
- **Files**: New `src/web/` and `web/` frontend

#### 5.2 Alert Correlation Engine
- **Why**: Group related alerts, reduce noise
- **Implementation**: Correlate by IP, time window, attack chain
- **Files**: New `src/correlation.rs`

#### 5.3 Reporting & Compliance
- **Why**: PCI-DSS, HIPAA require audit logs
- **Implementation**: Generate PDF/HTML reports
- **Files**: New `src/reporting.rs`

### Phase 6: Performance & Scalability

#### 6.1 Hardware Offload (XDP/eBPF)
- **Why**: Kernel bypass for line-rate processing
- **Implementation**: Use eBPF for fast packet filtering
- **Files**: Extend `src/ebpf.rs` with XDP programs

#### 6.2 Distributed Deployment
- **Why**: Monitor multiple network segments
- **Implementation**: Central manager + remote sensors
- **Files**: New `src/cluster/`

#### 6.3 PCAP Replay & Analysis
- **Why**: Forensic analysis of captured traffic
- **Implementation**: Read pcap files, replay through detection engine
- **Files**: New `src/pcap.rs`

## Implementation Priority

### Immediate (High Impact, Feasible)
1. Suricata/Snort rule parser (instant 30k+ rules)
2. JA3/JA3S fingerprinting (unique differentiator)
3. Flow tracking with statistics
4. Threat feed integration (OTX, Abuse.ch)

### Short-term
5. Protocol analyzers (HTTP, DNS, TLS)
6. Multi-threaded packet engine
7. Basic ML baseline detection
8. MITRE ATT&CK mapping

### Medium-term
9. Web dashboard
10. Alert correlation
11. Full ML classifier
12. Encrypted traffic analysis

### Long-term
13. XDP hardware offload
14. Distributed deployment
15. STIX/TAXII sharing

## Competitive Advantages Over Existing Tools

| Feature | Snort | Suricata | Zeek | crmonban |
|---------|-------|----------|------|----------|
| Active IPS | Yes | Yes | No | **Yes** |
| Multi-threaded | v3 only | Yes | Yes | **Yes (Rust async)** |
| ML Detection | No | No | No | **Yes** |
| TLS Inspection | No | Basic | No | **Full MITM** |
| eBPF Malware Detection | No | No | No | **Yes** |
| JA3 Fingerprinting | No | Yes | Yes | **Yes** |
| Threat Intel | Manual | Manual | Manual | **Auto-integrated** |
| Memory Safe | No (C) | No (C) | No (C++) | **Yes (Rust)** |
| Resource Usage | High | Medium | Medium | **Low** |
| Web UI | No | No | No | **Yes** |

## Next Steps

1. Start with Suricata rule parser - immediate value
2. Add JA3/JA3S - differentiator
3. Implement flow tracking - foundation for ML
4. Integrate threat feeds - quick wins
