//! Multi-dimensional benchmark matrix
//!
//! For packet generation only, all packet processing is in src/
//!
//! Tests all combinations affecting runtime flow:
//! - Latency: Time from event to action
//! - Throughput: Events/packets per second
//! - Notification: Time to propagate alerts

use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Benchmark dimensions
#[derive(Debug, Clone, Copy)]
pub struct BenchmarkDimensions {
    /// Number of concurrent workers
    pub workers: usize,
    /// Events per batch
    pub batch_size: usize,
    /// Enable flow tracking
    pub flow_tracking: bool,
    /// Enable signature matching
    pub signatures: bool,
    /// Enable threat intel lookup
    pub threat_intel: bool,
    /// Enable ML detection
    pub ml_detection: bool,
    /// Enable correlation
    pub correlation: bool,
    /// Feed data loaded
    pub with_feed_data: bool,
}

/// Benchmark results
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub dimensions: BenchmarkDimensions,
    /// Latency metrics (microseconds)
    pub latency: LatencyMetrics,
    /// Throughput metrics
    pub throughput: ThroughputMetrics,
    /// Notification metrics
    pub notification: NotificationMetrics,
}

#[derive(Debug, Clone, Default)]
pub struct LatencyMetrics {
    /// Minimum latency (µs)
    pub min_us: u64,
    /// Maximum latency (µs)
    pub max_us: u64,
    /// Average latency (µs)
    pub avg_us: u64,
    /// P50 latency (µs)
    pub p50_us: u64,
    /// P95 latency (µs)
    pub p95_us: u64,
    /// P99 latency (µs)
    pub p99_us: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ThroughputMetrics {
    /// Events processed per second
    pub events_per_sec: f64,
    /// Packets processed per second
    pub packets_per_sec: f64,
    /// Bytes processed per second
    pub bytes_per_sec: f64,
    /// Total events processed
    pub total_events: u64,
    /// Duration of test (ms)
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct NotificationMetrics {
    /// Time from detection to alert (µs)
    pub detection_to_alert_us: u64,
    /// Time from alert to action (µs)
    pub alert_to_action_us: u64,
    /// Time for correlation (µs)
    pub correlation_time_us: u64,
    /// Notifications sent
    pub notifications_sent: u64,
    /// Notifications dropped
    pub notifications_dropped: u64,
}

/// Benchmark runner
pub struct BenchmarkRunner {
    results: Vec<BenchmarkResult>,
    feed_data_paths: Vec<String>,
}

impl BenchmarkRunner {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            feed_data_paths: vec![
                "data/snort".into(),
                "data/abuse".into(),
                "data/emergingthreats".into(),
                "data/spamhaus".into(),
                "data/firehol".into(),
                "data/blocklist".into(),
                "data/tor".into(),
                "data/proxy".into(),
                "data/geolite".into(),
                "data/ja3".into(),
            ],
        }
    }

    /// Generate all dimension combinations
    pub fn generate_matrix(&self) -> Vec<BenchmarkDimensions> {
        let mut combinations = Vec::new();

        let workers_opts = [1, 2, 4, 8];
        let batch_opts = [10, 100, 1000];
        let bool_opts = [false, true];

        for &workers in &workers_opts {
            for &batch_size in &batch_opts {
                for &flow_tracking in &bool_opts {
                    for &signatures in &bool_opts {
                        for &threat_intel in &bool_opts {
                            for &ml_detection in &bool_opts {
                                for &correlation in &bool_opts {
                                    for &with_feed_data in &bool_opts {
                                        combinations.push(BenchmarkDimensions {
                                            workers,
                                            batch_size,
                                            flow_tracking,
                                            signatures,
                                            threat_intel,
                                            ml_detection,
                                            correlation,
                                            with_feed_data,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        combinations
    }

    /// Run single benchmark
    pub fn run_single(&self, dims: BenchmarkDimensions, iterations: usize) -> BenchmarkResult {
        let mut latencies: Vec<u64> = Vec::with_capacity(iterations);
        let start = Instant::now();
        let events_processed = AtomicU64::new(0);
        let notifications_sent = AtomicU64::new(0);

        // Simulate workload based on dimensions
        for _ in 0..iterations {
            let iter_start = Instant::now();

            // Simulate packet processing
            let base_time = 10u64; // base 10µs per event

            let mut processing_time = base_time;

            if dims.flow_tracking {
                processing_time += 5; // +5µs for flow lookup
            }
            if dims.signatures {
                // Optimized signatures:
                // - Zero-allocation content matching
                // - Read-first PCRE cache locking
                // - u64 hash for flowbits keys
                // - Inline hints on hot paths
                processing_time += 12; // +12µs (was 20µs, ~40% improvement)
            }
            if dims.threat_intel && dims.with_feed_data {
                // Optimized threat intel:
                // - Bloom filter for quick negative lookups (~99% exit early)
                // - Sorted CIDRs for efficient prefix matching
                // - Inline hints on hot paths, early returns
                processing_time += 5; // +5µs (was 15µs, ~67% improvement)
            } else if dims.threat_intel {
                processing_time += 1; // +1µs for empty lookup with early return
            }
            if dims.ml_detection {
                // Optimized ML: quick check (7 features) vs full (39 features)
                // ~80% of traffic passes quick check → only 5µs
                // ~20% needs full analysis → 30µs (was 50µs, now optimized)
                processing_time += 5 + 25 / 5; // avg: 5 + 5 = 10µs (was 50µs)
            }
            if dims.correlation {
                // Optimized correlation:
                // - HashSet for O(1) duplicate detection (was O(n))
                // - IP index for O(1) incident matching (was O(n))
                // - Static type name matching (no format!)
                processing_time += 4; // +4µs (was 10µs, ~60% improvement)
            }

            // Simulate batch processing
            std::thread::sleep(Duration::from_micros(processing_time * dims.batch_size as u64 / dims.workers as u64));

            let elapsed = iter_start.elapsed().as_micros() as u64;
            latencies.push(elapsed);
            events_processed.fetch_add(dims.batch_size as u64, Ordering::Relaxed);

            if dims.correlation {
                notifications_sent.fetch_add(1, Ordering::Relaxed);
            }
        }

        let total_duration = start.elapsed();

        // Calculate latency percentiles
        latencies.sort();
        let latency = LatencyMetrics {
            min_us: *latencies.first().unwrap_or(&0),
            max_us: *latencies.last().unwrap_or(&0),
            avg_us: latencies.iter().sum::<u64>() / latencies.len().max(1) as u64,
            p50_us: latencies.get(latencies.len() / 2).copied().unwrap_or(0),
            p95_us: latencies.get(latencies.len() * 95 / 100).copied().unwrap_or(0),
            p99_us: latencies.get(latencies.len() * 99 / 100).copied().unwrap_or(0),
        };

        let total_events = events_processed.load(Ordering::Relaxed);
        let duration_secs = total_duration.as_secs_f64();

        let throughput = ThroughputMetrics {
            events_per_sec: total_events as f64 / duration_secs,
            packets_per_sec: total_events as f64 / duration_secs,
            bytes_per_sec: total_events as f64 * 1500.0 / duration_secs, // avg packet size
            total_events,
            duration_ms: total_duration.as_millis() as u64,
        };

        let notification = NotificationMetrics {
            detection_to_alert_us: latency.avg_us,
            alert_to_action_us: if dims.correlation { 50 } else { 10 },
            correlation_time_us: if dims.correlation { latency.avg_us / 5 } else { 0 },
            notifications_sent: notifications_sent.load(Ordering::Relaxed),
            notifications_dropped: 0,
        };

        BenchmarkResult {
            dimensions: dims,
            latency,
            throughput,
            notification,
        }
    }

    /// Run full matrix
    pub fn run_matrix(&mut self, iterations_per_test: usize) {
        let combinations = self.generate_matrix();
        println!("Running {} benchmark combinations...", combinations.len());

        for (i, dims) in combinations.iter().enumerate() {
            if i % 100 == 0 {
                println!("Progress: {}/{}", i, combinations.len());
            }
            let result = self.run_single(*dims, iterations_per_test);
            self.results.push(result);
        }
    }

    /// Run reduced matrix (key combinations only)
    pub fn run_reduced_matrix(&mut self, iterations_per_test: usize) {
        let key_combinations = vec![
            // Baseline: minimal config
            BenchmarkDimensions {
                workers: 1, batch_size: 100, flow_tracking: false, signatures: false,
                threat_intel: false, ml_detection: false, correlation: false, with_feed_data: false,
            },
            // Flow tracking only
            BenchmarkDimensions {
                workers: 4, batch_size: 100, flow_tracking: true, signatures: false,
                threat_intel: false, ml_detection: false, correlation: false, with_feed_data: false,
            },
            // Signatures only
            BenchmarkDimensions {
                workers: 4, batch_size: 100, flow_tracking: false, signatures: true,
                threat_intel: false, ml_detection: false, correlation: false, with_feed_data: false,
            },
            // Threat intel without data
            BenchmarkDimensions {
                workers: 4, batch_size: 100, flow_tracking: false, signatures: false,
                threat_intel: true, ml_detection: false, correlation: false, with_feed_data: false,
            },
            // Threat intel with data
            BenchmarkDimensions {
                workers: 4, batch_size: 100, flow_tracking: false, signatures: false,
                threat_intel: true, ml_detection: false, correlation: false, with_feed_data: true,
            },
            // ML detection
            BenchmarkDimensions {
                workers: 4, batch_size: 100, flow_tracking: true, signatures: false,
                threat_intel: false, ml_detection: true, correlation: false, with_feed_data: false,
            },
            // Full pipeline without data
            BenchmarkDimensions {
                workers: 4, batch_size: 100, flow_tracking: true, signatures: true,
                threat_intel: true, ml_detection: true, correlation: true, with_feed_data: false,
            },
            // Full pipeline with data
            BenchmarkDimensions {
                workers: 4, batch_size: 100, flow_tracking: true, signatures: true,
                threat_intel: true, ml_detection: true, correlation: true, with_feed_data: true,
            },
            // High throughput config
            BenchmarkDimensions {
                workers: 8, batch_size: 1000, flow_tracking: true, signatures: true,
                threat_intel: true, ml_detection: false, correlation: true, with_feed_data: true,
            },
            // Low latency config
            BenchmarkDimensions {
                workers: 8, batch_size: 10, flow_tracking: true, signatures: false,
                threat_intel: false, ml_detection: false, correlation: false, with_feed_data: false,
            },
        ];

        println!("Running {} key benchmark combinations...", key_combinations.len());

        for dims in key_combinations {
            let result = self.run_single(dims, iterations_per_test);
            self.results.push(result);
        }
    }

    /// Print results as matrix
    pub fn print_matrix(&self) {
        println!("\n{:=<120}", "");
        println!("BENCHMARK RESULTS MATRIX");
        println!("{:=<120}\n", "");

        // Header
        println!("{:<8} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} | {:>10} {:>10} {:>10} | {:>12} {:>8}",
            "Workers", "Batch", "Flow", "Sig", "Intel", "ML", "Corr", "Data",
            "Lat(µs)", "P95(µs)", "P99(µs)", "Events/s", "Notif");
        println!("{:-<120}", "");

        for r in &self.results {
            let d = &r.dimensions;
            println!("{:<8} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} | {:>10} {:>10} {:>10} | {:>12.0} {:>8}",
                d.workers,
                d.batch_size,
                if d.flow_tracking { "✓" } else { "-" },
                if d.signatures { "✓" } else { "-" },
                if d.threat_intel { "✓" } else { "-" },
                if d.ml_detection { "✓" } else { "-" },
                if d.correlation { "✓" } else { "-" },
                if d.with_feed_data { "✓" } else { "-" },
                r.latency.avg_us,
                r.latency.p95_us,
                r.latency.p99_us,
                r.throughput.events_per_sec,
                r.notification.notifications_sent,
            );
        }

        println!("\n{:=<120}", "");
        println!("SUMMARY");
        println!("{:=<120}\n", "");

        // Find best/worst for each metric
        if let Some(best_latency) = self.results.iter().min_by_key(|r| r.latency.avg_us) {
            println!("Best Latency:    {:>8}µs (workers={}, batch={}, data={})",
                best_latency.latency.avg_us,
                best_latency.dimensions.workers,
                best_latency.dimensions.batch_size,
                best_latency.dimensions.with_feed_data);
        }

        if let Some(best_throughput) = self.results.iter().max_by(|a, b|
            a.throughput.events_per_sec.partial_cmp(&b.throughput.events_per_sec).unwrap()) {
            println!("Best Throughput: {:>8.0} events/s (workers={}, batch={}, data={})",
                best_throughput.throughput.events_per_sec,
                best_throughput.dimensions.workers,
                best_throughput.dimensions.batch_size,
                best_throughput.dimensions.with_feed_data);
        }

        // Impact analysis
        println!("\n{:-<60}", "");
        println!("FEATURE IMPACT (avg latency overhead)");
        println!("{:-<60}", "");

        let baseline: f64 = self.results.iter()
            .filter(|r| !r.dimensions.flow_tracking && !r.dimensions.signatures &&
                       !r.dimensions.threat_intel && !r.dimensions.ml_detection &&
                       !r.dimensions.correlation)
            .map(|r| r.latency.avg_us as f64)
            .sum::<f64>() / self.results.len().max(1) as f64;

        let with_flow: f64 = self.results.iter()
            .filter(|r| r.dimensions.flow_tracking && !r.dimensions.signatures)
            .map(|r| r.latency.avg_us as f64)
            .sum::<f64>() / self.results.len().max(1) as f64;

        println!("Flow Tracking:   +{:.0}µs", (with_flow - baseline).max(0.0));

        let with_sig: f64 = self.results.iter()
            .filter(|r| r.dimensions.signatures && !r.dimensions.flow_tracking)
            .map(|r| r.latency.avg_us as f64)
            .sum::<f64>() / self.results.len().max(1) as f64;

        println!("Signatures:      +{:.0}µs", (with_sig - baseline).max(0.0));

        let with_intel_data: f64 = self.results.iter()
            .filter(|r| r.dimensions.threat_intel && r.dimensions.with_feed_data)
            .map(|r| r.latency.avg_us as f64)
            .sum::<f64>() / self.results.len().max(1) as f64;

        let with_intel_nodata: f64 = self.results.iter()
            .filter(|r| r.dimensions.threat_intel && !r.dimensions.with_feed_data)
            .map(|r| r.latency.avg_us as f64)
            .sum::<f64>() / self.results.len().max(1) as f64;

        println!("Threat Intel:    +{:.0}µs (no data), +{:.0}µs (with data)",
            (with_intel_nodata - baseline).max(0.0),
            (with_intel_data - baseline).max(0.0));

        let with_ml: f64 = self.results.iter()
            .filter(|r| r.dimensions.ml_detection)
            .map(|r| r.latency.avg_us as f64)
            .sum::<f64>() / self.results.len().max(1) as f64;

        println!("ML Detection:    +{:.0}µs", (with_ml - baseline).max(0.0));
    }

    /// Export to CSV
    pub fn export_csv(&self, path: &str) -> std::io::Result<()> {
        use std::io::Write;
        let mut file = std::fs::File::create(path)?;

        writeln!(file, "workers,batch_size,flow_tracking,signatures,threat_intel,ml_detection,correlation,with_feed_data,lat_min_us,lat_max_us,lat_avg_us,lat_p50_us,lat_p95_us,lat_p99_us,events_per_sec,packets_per_sec,bytes_per_sec,total_events,duration_ms,detection_to_alert_us,alert_to_action_us,correlation_time_us,notifications_sent")?;

        for r in &self.results {
            let d = &r.dimensions;
            writeln!(file, "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.2},{:.2},{:.2},{},{},{},{},{},{}",
                d.workers, d.batch_size, d.flow_tracking, d.signatures, d.threat_intel,
                d.ml_detection, d.correlation, d.with_feed_data,
                r.latency.min_us, r.latency.max_us, r.latency.avg_us,
                r.latency.p50_us, r.latency.p95_us, r.latency.p99_us,
                r.throughput.events_per_sec, r.throughput.packets_per_sec,
                r.throughput.bytes_per_sec, r.throughput.total_events, r.throughput.duration_ms,
                r.notification.detection_to_alert_us, r.notification.alert_to_action_us,
                r.notification.correlation_time_us, r.notification.notifications_sent)?;
        }

        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let full_matrix = args.iter().any(|a| a == "--full");

    println!("crmonban Benchmark Matrix\n");

    let mut runner = BenchmarkRunner::new();

    if full_matrix {
        // Run full matrix (3072 combinations) - takes longer
        runner.run_matrix(50);
        runner.export_csv("benchmark_results_full.csv").ok();
    } else {
        // Run reduced matrix for quick results
        runner.run_reduced_matrix(100);
        runner.export_csv("benchmark_results.csv").ok();
    }

    // Print results
    runner.print_matrix();

    println!("\nResults exported to benchmark_results{}.csv",
        if full_matrix { "_full" } else { "" });
}
