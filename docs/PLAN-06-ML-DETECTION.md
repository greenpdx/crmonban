# Implementation Plan: ML-Based Anomaly Detection

## Overview

Machine learning-based detection identifies threats that signature-based systems miss, including:
- Zero-day attacks (no known signature)
- Slow/low attacks (below threshold-based detection)
- Polymorphic malware (changing signatures)
- Insider threats (legitimate credentials, abnormal behavior)
- Data exfiltration (unusual data flows)
- C2 beaconing (periodic communication patterns)

## Detection Approaches

### 1. Supervised Classification
Train on labeled attack data (CICIDS2017, NSL-KDD) to classify traffic as:
- Normal
- DoS/DDoS
- Port Scan/Probe
- Brute Force
- Web Attack (SQLi, XSS)
- Botnet
- Infiltration
- Data Exfiltration

### 2. Unsupervised Anomaly Detection
Learn normal baseline, flag deviations:
- Isolation Forest (fast, effective for high-dimensional data)
- One-Class SVM (boundary around normal)
- Autoencoders (reconstruction error = anomaly score)
- DBSCAN clustering (outlier detection)

### 3. Time-Series Analysis
Detect temporal anomalies:
- ARIMA for traffic volume prediction
- LSTM for sequence modeling
- Beaconing detection (periodic intervals)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              ML Detection Engine                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
                                        │
         ┌──────────────────────────────┼──────────────────────────────┐
         │                              │                              │
         ▼                              ▼                              ▼
┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
│    Feature      │          │    Baseline     │          │   Real-Time     │
│   Extraction    │          │    Learning     │          │   Inference     │
└────────┬────────┘          └────────┬────────┘          └────────┬────────┘
         │                            │                            │
         ▼                            ▼                            ▼
┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
│ Flow Features   │          │ Statistical     │          │ Classification  │
│ - Duration      │          │ Baseline        │          │ - Random Forest │
│ - Bytes/packets │          │ - Per-host      │          │ - Gradient Boost│
│ - IAT stats     │          │ - Per-service   │          │ - Neural Net    │
│ - TCP flags     │          │ - Time-of-day   │          └────────┬────────┘
│ - Protocol dist │          └────────┬────────┘                   │
└────────┬────────┘                   │                            │
         │                            │                            ▼
         │                            │                   ┌─────────────────┐
         │                            │                   │ Anomaly Scoring │
         │                            │                   │ - Isolation For │
         │                            │                   │ - Autoencoder   │
         │                            │                   │ - One-Class SVM │
         │                            │                   └────────┬────────┘
         │                            │                            │
         └────────────────────────────┼────────────────────────────┘
                                      │
                                      ▼
                            ┌─────────────────┐
                            │   Ensemble      │
                            │   Combiner      │
                            └────────┬────────┘
                                     │
                                     ▼
                            ┌─────────────────┐
                            │  Detection      │
                            │  Events         │
                            └─────────────────┘
```

## File Structure

```
src/ml/
├── mod.rs                  # MLEngine struct, public API
├── features/
│   ├── mod.rs              # Feature extraction coordinator
│   ├── flow.rs             # Flow-level features (41 CICIDS features)
│   ├── packet.rs           # Packet-level features
│   ├── host.rs             # Host behavior features
│   ├── time.rs             # Time-series features
│   └── normalize.rs        # Feature normalization/scaling
├── baseline/
│   ├── mod.rs              # Baseline manager
│   ├── statistical.rs      # Statistical baseline (mean, std, percentiles)
│   ├── host_profile.rs     # Per-host behavior profiles
│   ├── service_profile.rs  # Per-service profiles
│   └── temporal.rs         # Time-of-day patterns
├── models/
│   ├── mod.rs              # Model trait, registry
│   ├── random_forest.rs    # Random Forest classifier
│   ├── gradient_boost.rs   # XGBoost-style gradient boosting
│   ├── isolation_forest.rs # Isolation Forest anomaly detection
│   ├── one_class_svm.rs    # One-Class SVM
│   ├── autoencoder.rs      # Neural network autoencoder
│   └── ensemble.rs         # Ensemble combiner
├── training/
│   ├── mod.rs              # Training coordinator
│   ├── dataset.rs          # Dataset loading (CICIDS, NSL-KDD)
│   ├── validation.rs       # Cross-validation, metrics
│   └── hyperopt.rs         # Hyperparameter optimization
├── inference/
│   ├── mod.rs              # Real-time inference
│   ├── batch.rs            # Batch inference
│   └── cache.rs            # Prediction caching
├── detection/
│   ├── mod.rs              # Detection logic
│   ├── beaconing.rs        # C2 beacon detection
│   ├── exfiltration.rs     # Data exfil detection
│   ├── lateral.rs          # Lateral movement detection
│   └── scanner.rs          # Scanner/probe detection
└── persistence/
    ├── mod.rs              # Model save/load
    └── onnx.rs             # ONNX model support (optional)
```

## Feature Engineering

### Flow-Level Features (CICIDS2017 Compatible)

```rust
// src/ml/features/flow.rs

/// 41 standard flow features used by CICIDS2017 and similar datasets
#[derive(Debug, Clone, Default)]
pub struct FlowFeatures {
    // Basic flow info
    pub duration: f64,              // Flow duration in microseconds
    pub protocol: u8,               // Protocol type (TCP=6, UDP=17)

    // Packet counts
    pub total_fwd_packets: u64,     // Packets in forward direction
    pub total_bwd_packets: u64,     // Packets in backward direction

    // Byte counts
    pub total_length_fwd: u64,      // Total bytes forward
    pub total_length_bwd: u64,      // Total bytes backward

    // Packet length statistics (forward)
    pub fwd_pkt_len_max: u16,
    pub fwd_pkt_len_min: u16,
    pub fwd_pkt_len_mean: f64,
    pub fwd_pkt_len_std: f64,

    // Packet length statistics (backward)
    pub bwd_pkt_len_max: u16,
    pub bwd_pkt_len_min: u16,
    pub bwd_pkt_len_mean: f64,
    pub bwd_pkt_len_std: f64,

    // Flow rates
    pub flow_bytes_per_sec: f64,
    pub flow_packets_per_sec: f64,

    // Inter-arrival times (forward)
    pub fwd_iat_total: f64,
    pub fwd_iat_mean: f64,
    pub fwd_iat_std: f64,
    pub fwd_iat_max: f64,
    pub fwd_iat_min: f64,

    // Inter-arrival times (backward)
    pub bwd_iat_total: f64,
    pub bwd_iat_mean: f64,
    pub bwd_iat_std: f64,
    pub bwd_iat_max: f64,
    pub bwd_iat_min: f64,

    // TCP flags
    pub fwd_psh_flags: u32,
    pub bwd_psh_flags: u32,
    pub fwd_urg_flags: u32,
    pub bwd_urg_flags: u32,
    pub fin_flag_count: u32,
    pub syn_flag_count: u32,
    pub rst_flag_count: u32,
    pub psh_flag_count: u32,
    pub ack_flag_count: u32,
    pub urg_flag_count: u32,
    pub ece_flag_count: u32,
    pub cwr_flag_count: u32,

    // Header lengths
    pub fwd_header_length: u32,
    pub bwd_header_length: u32,

    // Packet rates
    pub fwd_packets_per_sec: f64,
    pub bwd_packets_per_sec: f64,

    // Packet sizes
    pub min_packet_length: u16,
    pub max_packet_length: u16,
    pub packet_length_mean: f64,
    pub packet_length_std: f64,
    pub packet_length_variance: f64,

    // Subflows
    pub subflow_fwd_packets: u32,
    pub subflow_fwd_bytes: u64,
    pub subflow_bwd_packets: u32,
    pub subflow_bwd_bytes: u64,

    // Window sizes
    pub init_win_bytes_fwd: u32,
    pub init_win_bytes_bwd: u32,

    // Active/idle times
    pub active_mean: f64,
    pub active_std: f64,
    pub active_max: f64,
    pub active_min: f64,
    pub idle_mean: f64,
    pub idle_std: f64,
    pub idle_max: f64,
    pub idle_min: f64,
}

impl FlowFeatures {
    /// Extract features from a completed flow
    pub fn from_flow(flow: &Flow) -> Self {
        let mut features = Self::default();

        // Duration
        features.duration = flow.duration().as_micros() as f64;
        features.protocol = flow.protocol as u8;

        // Packet counts
        features.total_fwd_packets = flow.packets_to_server;
        features.total_bwd_packets = flow.packets_to_client;

        // Byte counts
        features.total_length_fwd = flow.bytes_to_server;
        features.total_length_bwd = flow.bytes_to_client;

        // Calculate statistics from stored packet info
        let fwd_sizes: Vec<f64> = flow.fwd_packet_sizes.iter().map(|&s| s as f64).collect();
        let bwd_sizes: Vec<f64> = flow.bwd_packet_sizes.iter().map(|&s| s as f64).collect();

        if !fwd_sizes.is_empty() {
            features.fwd_pkt_len_max = *flow.fwd_packet_sizes.iter().max().unwrap_or(&0);
            features.fwd_pkt_len_min = *flow.fwd_packet_sizes.iter().min().unwrap_or(&0);
            features.fwd_pkt_len_mean = mean(&fwd_sizes);
            features.fwd_pkt_len_std = std_dev(&fwd_sizes);
        }

        // ... similar for all other features

        features
    }

    /// Convert to feature vector for ML model
    pub fn to_vector(&self) -> Vec<f64> {
        vec![
            self.duration,
            self.protocol as f64,
            self.total_fwd_packets as f64,
            self.total_bwd_packets as f64,
            self.total_length_fwd as f64,
            self.total_length_bwd as f64,
            self.fwd_pkt_len_max as f64,
            self.fwd_pkt_len_min as f64,
            self.fwd_pkt_len_mean,
            self.fwd_pkt_len_std,
            // ... all 41 features
        ]
    }

    /// Feature names for explainability
    pub fn feature_names() -> &'static [&'static str] {
        &[
            "duration",
            "protocol",
            "total_fwd_packets",
            "total_bwd_packets",
            "total_length_fwd",
            "total_length_bwd",
            "fwd_pkt_len_max",
            "fwd_pkt_len_min",
            "fwd_pkt_len_mean",
            "fwd_pkt_len_std",
            // ... all 41 names
        ]
    }
}
```

### Host Behavior Features

```rust
// src/ml/features/host.rs

/// Per-host behavioral features over a time window
#[derive(Debug, Clone, Default)]
pub struct HostFeatures {
    // Connection patterns
    pub unique_dst_ips: u32,        // Number of unique destinations
    pub unique_dst_ports: u32,      // Number of unique ports
    pub unique_services: u32,       // Number of unique services
    pub connection_rate: f64,       // Connections per second
    pub failed_connection_rate: f64,

    // Traffic patterns
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub bytes_ratio: f64,           // sent/received
    pub avg_packet_size: f64,

    // Protocol distribution
    pub tcp_ratio: f64,
    pub udp_ratio: f64,
    pub icmp_ratio: f64,
    pub other_ratio: f64,

    // Port patterns
    pub high_port_ratio: f64,       // Ports > 1024
    pub well_known_port_ratio: f64, // Ports < 1024
    pub sequential_port_scan: bool, // Detected sequential access

    // Timing patterns
    pub activity_duration: f64,
    pub idle_periods: u32,
    pub burst_count: u32,
    pub avg_burst_duration: f64,

    // DNS behavior
    pub dns_query_rate: f64,
    pub unique_domains: u32,
    pub avg_domain_length: f64,
    pub suspicious_tld_ratio: f64,

    // Deviation from baseline
    pub traffic_volume_zscore: f64,
    pub connection_rate_zscore: f64,
    pub port_diversity_zscore: f64,
}
```

### Beaconing Detection Features

```rust
// src/ml/features/beacon.rs

/// Features for detecting C2 beaconing behavior
#[derive(Debug, Clone)]
pub struct BeaconFeatures {
    // Interval analysis
    pub connection_intervals: Vec<Duration>,
    pub interval_mean: f64,
    pub interval_std: f64,
    pub interval_median: f64,
    pub interval_mode: f64,
    pub interval_skewness: f64,
    pub interval_kurtosis: f64,

    // Regularity metrics
    pub coefficient_of_variation: f64,  // std/mean - low = regular
    pub jitter: f64,                    // Variation in intervals
    pub periodicity_score: f64,         // FFT-based periodicity

    // Payload patterns
    pub payload_size_mean: f64,
    pub payload_size_std: f64,
    pub payload_entropy_mean: f64,
    pub constant_payload_ratio: f64,    // Same size payloads

    // Destination patterns
    pub single_destination: bool,
    pub destination_changes: u32,

    // Time of day
    pub spans_business_hours: bool,
    pub spans_night_hours: bool,
    pub spans_weekend: bool,
}

impl BeaconFeatures {
    /// Score beaconing likelihood (0.0 - 1.0)
    pub fn beacon_score(&self) -> f64 {
        let mut score = 0.0;

        // Low coefficient of variation indicates regular intervals
        if self.coefficient_of_variation < 0.1 {
            score += 0.3;
        } else if self.coefficient_of_variation < 0.2 {
            score += 0.2;
        }

        // High periodicity score
        score += self.periodicity_score * 0.3;

        // Consistent payload sizes
        if self.payload_size_std < 10.0 {
            score += 0.2;
        }

        // Single destination
        if self.single_destination {
            score += 0.1;
        }

        // Long duration spanning multiple time periods
        if self.spans_night_hours && self.connection_intervals.len() > 100 {
            score += 0.1;
        }

        score.min(1.0)
    }
}
```

## Model Implementations

### Random Forest Classifier

```rust
// src/ml/models/random_forest.rs

use linfa::prelude::*;
use linfa_trees::{DecisionTree, RandomForest};

pub struct RandomForestModel {
    model: Option<RandomForest<f64, usize>>,
    n_trees: usize,
    max_depth: Option<usize>,
    min_samples_split: usize,
    feature_names: Vec<String>,
    class_names: Vec<String>,
}

impl RandomForestModel {
    pub fn new() -> Self {
        Self {
            model: None,
            n_trees: 100,
            max_depth: Some(20),
            min_samples_split: 2,
            feature_names: FlowFeatures::feature_names()
                .iter()
                .map(|s| s.to_string())
                .collect(),
            class_names: vec![
                "Normal".into(),
                "DoS".into(),
                "PortScan".into(),
                "BruteForce".into(),
                "WebAttack".into(),
                "Botnet".into(),
                "Infiltration".into(),
            ],
        }
    }

    pub fn train(&mut self, dataset: &Dataset<f64, usize>) -> Result<TrainingMetrics> {
        let model = RandomForest::params()
            .n_trees(self.n_trees)
            .max_depth(self.max_depth)
            .min_samples_split(self.min_samples_split)
            .fit(dataset)?;

        self.model = Some(model);

        // Calculate training metrics
        let predictions = self.model.as_ref().unwrap().predict(dataset);
        let metrics = calculate_metrics(&predictions, dataset.targets());

        Ok(metrics)
    }

    pub fn predict(&self, features: &FlowFeatures) -> Prediction {
        let vector = features.to_vector();
        let array = Array1::from_vec(vector);

        let class_idx = self.model
            .as_ref()
            .expect("Model not trained")
            .predict(&array.insert_axis(Axis(0)))[0];

        Prediction {
            class: self.class_names[class_idx].clone(),
            class_idx,
            confidence: self.predict_proba(features)[class_idx],
            feature_importance: self.feature_importance(features),
        }
    }

    pub fn predict_proba(&self, features: &FlowFeatures) -> Vec<f64> {
        // Return probability distribution over classes
        let vector = features.to_vector();
        // ... tree voting to get probabilities
        vec![0.0; self.class_names.len()] // Placeholder
    }

    pub fn feature_importance(&self, features: &FlowFeatures) -> Vec<(String, f64)> {
        // SHAP-like local feature importance
        self.feature_names
            .iter()
            .zip(self.model.as_ref().unwrap().feature_importance())
            .map(|(name, &imp)| (name.clone(), imp))
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct Prediction {
    pub class: String,
    pub class_idx: usize,
    pub confidence: f64,
    pub feature_importance: Vec<(String, f64)>,
}

#[derive(Debug, Clone)]
pub struct TrainingMetrics {
    pub accuracy: f64,
    pub precision: Vec<f64>,
    pub recall: Vec<f64>,
    pub f1_score: Vec<f64>,
    pub confusion_matrix: Vec<Vec<u64>>,
    pub feature_importance: Vec<(String, f64)>,
}
```

### Isolation Forest (Anomaly Detection)

```rust
// src/ml/models/isolation_forest.rs

use rand::prelude::*;

/// Isolation Forest for unsupervised anomaly detection
pub struct IsolationForest {
    trees: Vec<IsolationTree>,
    n_trees: usize,
    max_samples: usize,
    contamination: f64,     // Expected proportion of anomalies
    threshold: f64,         // Anomaly score threshold
}

struct IsolationTree {
    root: Option<Box<IsolationNode>>,
    max_depth: usize,
}

enum IsolationNode {
    Internal {
        feature_idx: usize,
        split_value: f64,
        left: Box<IsolationNode>,
        right: Box<IsolationNode>,
    },
    Leaf {
        size: usize,
    },
}

impl IsolationForest {
    pub fn new(n_trees: usize, max_samples: usize, contamination: f64) -> Self {
        Self {
            trees: Vec::new(),
            n_trees,
            max_samples,
            contamination,
            threshold: 0.5,
        }
    }

    pub fn fit(&mut self, data: &[Vec<f64>]) {
        let mut rng = thread_rng();
        let max_depth = (self.max_samples as f64).log2().ceil() as usize;

        self.trees = (0..self.n_trees)
            .map(|_| {
                // Subsample data
                let indices: Vec<usize> = (0..data.len())
                    .choose_multiple(&mut rng, self.max_samples.min(data.len()));
                let subsample: Vec<&Vec<f64>> = indices.iter().map(|&i| &data[i]).collect();

                IsolationTree {
                    root: Some(Box::new(self.build_tree(&subsample, 0, max_depth, &mut rng))),
                    max_depth,
                }
            })
            .collect();

        // Set threshold based on contamination
        let scores: Vec<f64> = data.iter().map(|x| self.anomaly_score(x)).collect();
        let mut sorted = scores.clone();
        sorted.sort_by(|a, b| b.partial_cmp(a).unwrap());
        let threshold_idx = (data.len() as f64 * self.contamination) as usize;
        self.threshold = sorted.get(threshold_idx).copied().unwrap_or(0.5);
    }

    fn build_tree(
        &self,
        data: &[&Vec<f64>],
        depth: usize,
        max_depth: usize,
        rng: &mut ThreadRng,
    ) -> IsolationNode {
        if depth >= max_depth || data.len() <= 1 {
            return IsolationNode::Leaf { size: data.len() };
        }

        let n_features = data[0].len();
        let feature_idx = rng.gen_range(0..n_features);

        // Get min/max for this feature
        let values: Vec<f64> = data.iter().map(|x| x[feature_idx]).collect();
        let min_val = values.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_val = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        if (max_val - min_val).abs() < f64::EPSILON {
            return IsolationNode::Leaf { size: data.len() };
        }

        let split_value = rng.gen_range(min_val..max_val);

        let (left_data, right_data): (Vec<_>, Vec<_>) = data
            .iter()
            .partition(|x| x[feature_idx] < split_value);

        IsolationNode::Internal {
            feature_idx,
            split_value,
            left: Box::new(self.build_tree(&left_data, depth + 1, max_depth, rng)),
            right: Box::new(self.build_tree(&right_data, depth + 1, max_depth, rng)),
        }
    }

    /// Calculate anomaly score (0.0 = normal, 1.0 = anomaly)
    pub fn anomaly_score(&self, x: &[f64]) -> f64 {
        let avg_path_length: f64 = self.trees
            .iter()
            .map(|tree| self.path_length(x, tree.root.as_ref().unwrap(), 0) as f64)
            .sum::<f64>() / self.trees.len() as f64;

        let n = self.max_samples as f64;
        let c_n = 2.0 * (n.ln() + 0.5772156649) - (2.0 * (n - 1.0) / n);

        // Score = 2^(-E(h(x))/c(n))
        2.0_f64.powf(-avg_path_length / c_n)
    }

    fn path_length(&self, x: &[f64], node: &IsolationNode, depth: usize) -> usize {
        match node {
            IsolationNode::Leaf { size } => {
                depth + self.c(*size)
            }
            IsolationNode::Internal { feature_idx, split_value, left, right } => {
                if x[*feature_idx] < *split_value {
                    self.path_length(x, left, depth + 1)
                } else {
                    self.path_length(x, right, depth + 1)
                }
            }
        }
    }

    fn c(&self, n: usize) -> usize {
        if n <= 1 { return 0; }
        let n = n as f64;
        (2.0 * (n.ln() + 0.5772156649) - (2.0 * (n - 1.0) / n)) as usize
    }

    /// Check if sample is anomaly
    pub fn is_anomaly(&self, x: &[f64]) -> bool {
        self.anomaly_score(x) > self.threshold
    }
}
```

### Autoencoder (Deep Learning)

```rust
// src/ml/models/autoencoder.rs

use ndarray::{Array1, Array2};

/// Simple autoencoder for anomaly detection via reconstruction error
pub struct Autoencoder {
    encoder_weights: Vec<Array2<f64>>,
    encoder_biases: Vec<Array1<f64>>,
    decoder_weights: Vec<Array2<f64>>,
    decoder_biases: Vec<Array1<f64>>,
    threshold: f64,
}

impl Autoencoder {
    pub fn new(input_dim: usize, encoding_dims: &[usize]) -> Self {
        let mut encoder_weights = Vec::new();
        let mut encoder_biases = Vec::new();
        let mut decoder_weights = Vec::new();
        let mut decoder_biases = Vec::new();

        // Build encoder layers
        let mut prev_dim = input_dim;
        for &dim in encoding_dims {
            encoder_weights.push(Self::xavier_init(prev_dim, dim));
            encoder_biases.push(Array1::zeros(dim));
            prev_dim = dim;
        }

        // Build decoder layers (reverse)
        for &dim in encoding_dims.iter().rev().skip(1) {
            decoder_weights.push(Self::xavier_init(prev_dim, dim));
            decoder_biases.push(Array1::zeros(dim));
            prev_dim = dim;
        }
        decoder_weights.push(Self::xavier_init(prev_dim, input_dim));
        decoder_biases.push(Array1::zeros(input_dim));

        Self {
            encoder_weights,
            encoder_biases,
            decoder_weights,
            decoder_biases,
            threshold: 0.1,
        }
    }

    fn xavier_init(input: usize, output: usize) -> Array2<f64> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let scale = (6.0 / (input + output) as f64).sqrt();
        Array2::from_shape_fn((input, output), |_| rng.gen_range(-scale..scale))
    }

    fn relu(x: f64) -> f64 {
        x.max(0.0)
    }

    fn forward(&self, x: &Array1<f64>) -> (Array1<f64>, Vec<Array1<f64>>) {
        let mut activations = vec![x.clone()];
        let mut current = x.clone();

        // Encoder
        for (w, b) in self.encoder_weights.iter().zip(&self.encoder_biases) {
            current = current.dot(w) + b;
            current.mapv_inplace(Self::relu);
            activations.push(current.clone());
        }

        // Decoder
        for (w, b) in self.decoder_weights.iter().zip(&self.decoder_biases) {
            current = current.dot(w) + b;
            current.mapv_inplace(Self::relu);
            activations.push(current.clone());
        }

        (current, activations)
    }

    /// Calculate reconstruction error (anomaly score)
    pub fn reconstruction_error(&self, x: &Array1<f64>) -> f64 {
        let (reconstructed, _) = self.forward(x);
        let diff = x - &reconstructed;
        diff.mapv(|v| v * v).sum().sqrt() / x.len() as f64
    }

    /// Train on normal data
    pub fn train(&mut self, data: &[Array1<f64>], epochs: usize, learning_rate: f64) {
        for epoch in 0..epochs {
            let mut total_loss = 0.0;

            for sample in data {
                let (output, activations) = self.forward(sample);
                let loss = self.reconstruction_error(sample);
                total_loss += loss;

                // Backpropagation (simplified)
                self.backprop(sample, &output, &activations, learning_rate);
            }

            if epoch % 10 == 0 {
                println!("Epoch {}: Loss = {:.6}", epoch, total_loss / data.len() as f64);
            }
        }

        // Set threshold based on training data
        let errors: Vec<f64> = data.iter().map(|x| self.reconstruction_error(x)).collect();
        let mean_error: f64 = errors.iter().sum::<f64>() / errors.len() as f64;
        let std_error: f64 = (errors.iter().map(|e| (e - mean_error).powi(2)).sum::<f64>()
            / errors.len() as f64).sqrt();
        self.threshold = mean_error + 2.0 * std_error;
    }

    fn backprop(
        &mut self,
        _input: &Array1<f64>,
        _output: &Array1<f64>,
        _activations: &[Array1<f64>],
        _lr: f64,
    ) {
        // Simplified backprop - in production use a proper ML framework
    }

    pub fn is_anomaly(&self, x: &Array1<f64>) -> bool {
        self.reconstruction_error(x) > self.threshold
    }
}
```

## Baseline Learning

```rust
// src/ml/baseline/statistical.rs

use std::collections::HashMap;

/// Statistical baseline for normal behavior
pub struct StatisticalBaseline {
    /// Per-host statistics
    host_stats: HashMap<IpAddr, HostStatistics>,
    /// Per-service statistics
    service_stats: HashMap<(u16, Protocol), ServiceStatistics>,
    /// Global statistics
    global_stats: GlobalStatistics,
    /// Learning period
    learning_mode: bool,
    learning_start: Instant,
    learning_duration: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct HostStatistics {
    // Traffic volume
    bytes_per_hour: RollingStats,
    packets_per_hour: RollingStats,
    connections_per_hour: RollingStats,

    // Destination diversity
    unique_dsts_per_hour: RollingStats,
    unique_ports_per_hour: RollingStats,

    // Protocol distribution
    tcp_ratio: RollingStats,
    udp_ratio: RollingStats,

    // Time patterns
    hourly_activity: [RollingStats; 24],
    daily_activity: [RollingStats; 7],

    // Samples count
    samples: u64,
}

#[derive(Debug, Clone, Default)]
pub struct RollingStats {
    count: u64,
    mean: f64,
    m2: f64,          // For Welford's online variance
    min: f64,
    max: f64,
    percentiles: [f64; 5], // 10th, 25th, 50th, 75th, 90th
}

impl RollingStats {
    pub fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;

        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }

    pub fn variance(&self) -> f64 {
        if self.count < 2 { return 0.0; }
        self.m2 / (self.count - 1) as f64
    }

    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    pub fn z_score(&self, value: f64) -> f64 {
        let std = self.std_dev();
        if std < f64::EPSILON { return 0.0; }
        (value - self.mean) / std
    }
}

impl StatisticalBaseline {
    pub fn new(learning_duration: Duration) -> Self {
        Self {
            host_stats: HashMap::new(),
            service_stats: HashMap::new(),
            global_stats: GlobalStatistics::default(),
            learning_mode: true,
            learning_start: Instant::now(),
            learning_duration,
        }
    }

    /// Update baseline with new flow data
    pub fn update(&mut self, flow: &Flow) {
        let now = Instant::now();

        // Check if still in learning mode
        if self.learning_mode && now.duration_since(self.learning_start) > self.learning_duration {
            self.learning_mode = false;
            info!("Baseline learning complete");
        }

        // Update host stats
        let host_entry = self.host_stats
            .entry(flow.src_ip)
            .or_insert_with(HostStatistics::default);

        host_entry.bytes_per_hour.update(flow.bytes_to_server as f64);
        host_entry.packets_per_hour.update(flow.packets_to_server as f64);
        host_entry.samples += 1;

        // Update service stats
        let service_key = (flow.dst_port, flow.protocol);
        let service_entry = self.service_stats
            .entry(service_key)
            .or_insert_with(ServiceStatistics::default);

        service_entry.update(flow);

        // Update global stats
        self.global_stats.update(flow);
    }

    /// Check if flow deviates from baseline
    pub fn check_deviation(&self, flow: &Flow) -> Option<BaselineDeviation> {
        if self.learning_mode {
            return None; // Don't alert during learning
        }

        let mut deviations = Vec::new();

        // Check host behavior
        if let Some(host_stats) = self.host_stats.get(&flow.src_ip) {
            let bytes_zscore = host_stats.bytes_per_hour.z_score(flow.bytes_to_server as f64);
            if bytes_zscore.abs() > 3.0 {
                deviations.push(("bytes_volume".into(), bytes_zscore));
            }

            let packets_zscore = host_stats.packets_per_hour.z_score(flow.packets_to_server as f64);
            if packets_zscore.abs() > 3.0 {
                deviations.push(("packet_count".into(), packets_zscore));
            }
        }

        // Check service behavior
        let service_key = (flow.dst_port, flow.protocol);
        if let Some(service_stats) = self.service_stats.get(&service_key) {
            // Check flow duration
            let duration_zscore = service_stats.duration.z_score(flow.duration().as_secs_f64());
            if duration_zscore.abs() > 3.0 {
                deviations.push(("flow_duration".into(), duration_zscore));
            }
        }

        if deviations.is_empty() {
            None
        } else {
            Some(BaselineDeviation {
                flow_id: flow.id,
                src_ip: flow.src_ip,
                dst_ip: flow.dst_ip,
                deviations,
                severity: self.calculate_severity(&deviations),
            })
        }
    }

    fn calculate_severity(&self, deviations: &[(String, f64)]) -> Severity {
        let max_zscore = deviations.iter().map(|(_, z)| z.abs()).fold(0.0, f64::max);

        if max_zscore > 5.0 {
            Severity::High
        } else if max_zscore > 4.0 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

#[derive(Debug, Clone)]
pub struct BaselineDeviation {
    pub flow_id: u64,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub deviations: Vec<(String, f64)>,
    pub severity: Severity,
}
```

## Beaconing Detection

```rust
// src/ml/detection/beaconing.rs

use std::collections::HashMap;
use rustfft::{FftPlanner, num_complex::Complex};

/// Detect C2 beaconing patterns
pub struct BeaconDetector {
    /// Track connection intervals per (src, dst) pair
    connection_history: HashMap<(IpAddr, IpAddr), Vec<Instant>>,
    /// Minimum connections to analyze
    min_connections: usize,
    /// Maximum interval variance for beacon detection
    max_variance_ratio: f64,
    /// FFT periodicity threshold
    periodicity_threshold: f64,
}

impl BeaconDetector {
    pub fn new() -> Self {
        Self {
            connection_history: HashMap::new(),
            min_connections: 20,
            max_variance_ratio: 0.2,
            periodicity_threshold: 0.7,
        }
    }

    /// Record a connection and check for beaconing
    pub fn record_connection(&mut self, src: IpAddr, dst: IpAddr) -> Option<BeaconAlert> {
        let key = (src, dst);
        let now = Instant::now();

        let history = self.connection_history.entry(key).or_insert_with(Vec::new);
        history.push(now);

        // Keep only last hour of connections
        history.retain(|t| now.duration_since(*t) < Duration::from_secs(3600));

        if history.len() < self.min_connections {
            return None;
        }

        // Calculate intervals
        let intervals: Vec<f64> = history
            .windows(2)
            .map(|w| w[1].duration_since(w[0]).as_secs_f64())
            .collect();

        // Check variance ratio (coefficient of variation)
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals.iter().map(|i| (i - mean).powi(2)).sum::<f64>()
            / intervals.len() as f64;
        let cv = variance.sqrt() / mean;

        // Check periodicity via FFT
        let periodicity = self.calculate_periodicity(&intervals);

        // Beacon criteria: low variance OR high periodicity
        let is_beacon = cv < self.max_variance_ratio || periodicity > self.periodicity_threshold;

        if is_beacon {
            Some(BeaconAlert {
                src_ip: src,
                dst_ip: dst,
                interval_mean: mean,
                interval_std: variance.sqrt(),
                coefficient_of_variation: cv,
                periodicity_score: periodicity,
                connection_count: history.len(),
                confidence: self.calculate_confidence(cv, periodicity, history.len()),
            })
        } else {
            None
        }
    }

    /// Calculate periodicity using FFT
    fn calculate_periodicity(&self, intervals: &[f64]) -> f64 {
        if intervals.len() < 8 {
            return 0.0;
        }

        // Pad to power of 2
        let n = intervals.len().next_power_of_two();
        let mut data: Vec<Complex<f64>> = intervals
            .iter()
            .map(|&x| Complex::new(x, 0.0))
            .collect();
        data.resize(n, Complex::new(0.0, 0.0));

        // Compute FFT
        let mut planner = FftPlanner::new();
        let fft = planner.plan_fft_forward(n);
        fft.process(&mut data);

        // Find dominant frequency (skip DC component)
        let magnitudes: Vec<f64> = data[1..n/2]
            .iter()
            .map(|c| c.norm())
            .collect();

        let max_magnitude = magnitudes.iter().cloned().fold(0.0, f64::max);
        let total_energy: f64 = magnitudes.iter().map(|m| m * m).sum();

        if total_energy < f64::EPSILON {
            return 0.0;
        }

        // Periodicity = dominant frequency energy / total energy
        (max_magnitude * max_magnitude) / total_energy
    }

    fn calculate_confidence(&self, cv: f64, periodicity: f64, count: usize) -> f64 {
        let cv_score = (1.0 - cv.min(1.0)) * 0.4;
        let periodicity_score = periodicity * 0.4;
        let count_score = (count as f64 / 100.0).min(1.0) * 0.2;

        cv_score + periodicity_score + count_score
    }
}

#[derive(Debug, Clone)]
pub struct BeaconAlert {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub interval_mean: f64,
    pub interval_std: f64,
    pub coefficient_of_variation: f64,
    pub periodicity_score: f64,
    pub connection_count: usize,
    pub confidence: f64,
}
```

## ML Engine (Main Interface)

```rust
// src/ml/mod.rs

pub struct MLEngine {
    config: MLConfig,

    // Models
    classifier: Option<RandomForestModel>,
    anomaly_detector: Option<IsolationForest>,
    autoencoder: Option<Autoencoder>,

    // Baseline
    baseline: StatisticalBaseline,

    // Detection modules
    beacon_detector: BeaconDetector,

    // State
    is_trained: bool,
}

impl MLEngine {
    pub fn new(config: MLConfig) -> Self {
        Self {
            baseline: StatisticalBaseline::new(
                Duration::from_secs(config.baseline.learning_period_hours * 3600)
            ),
            classifier: None,
            anomaly_detector: None,
            autoencoder: None,
            beacon_detector: BeaconDetector::new(),
            config,
            is_trained: false,
        }
    }

    /// Load pre-trained model
    pub fn load_model(&mut self, path: &Path) -> Result<()> {
        // Load serialized model
        let data = std::fs::read(path)?;
        let model: RandomForestModel = bincode::deserialize(&data)?;
        self.classifier = Some(model);
        self.is_trained = true;
        Ok(())
    }

    /// Train on labeled dataset
    pub fn train(&mut self, dataset_path: &Path) -> Result<TrainingMetrics> {
        let dataset = load_cicids_dataset(dataset_path)?;

        // Train classifier
        let mut rf = RandomForestModel::new();
        let metrics = rf.train(&dataset)?;
        self.classifier = Some(rf);

        // Train anomaly detector on normal samples only
        let normal_samples: Vec<Vec<f64>> = dataset
            .records()
            .iter()
            .zip(dataset.targets())
            .filter(|(_, &label)| label == 0) // Normal
            .map(|(features, _)| features.to_vec())
            .collect();

        let mut iso_forest = IsolationForest::new(100, 256, 0.1);
        iso_forest.fit(&normal_samples);
        self.anomaly_detector = Some(iso_forest);

        self.is_trained = true;
        Ok(metrics)
    }

    /// Process a flow and return detections
    pub fn analyze(&mut self, flow: &Flow) -> Vec<DetectionEvent> {
        let mut events = Vec::new();

        // Extract features
        let features = FlowFeatures::from_flow(flow);

        // 1. Baseline deviation check
        self.baseline.update(flow);
        if let Some(deviation) = self.baseline.check_deviation(flow) {
            events.push(DetectionEvent {
                event_type: DetectionType::BaselineDeviation,
                severity: deviation.severity,
                message: format!(
                    "Traffic deviation detected: {:?}",
                    deviation.deviations
                ),
                ..Default::default()
            });
        }

        // 2. Classification (if trained)
        if let Some(ref classifier) = self.classifier {
            let prediction = classifier.predict(&features);
            if prediction.class != "Normal" && prediction.confidence > 0.7 {
                events.push(DetectionEvent {
                    event_type: DetectionType::MLClassification,
                    severity: self.class_to_severity(&prediction.class),
                    confidence: prediction.confidence as f32,
                    message: format!(
                        "ML classified as {} (confidence: {:.2})",
                        prediction.class, prediction.confidence
                    ),
                    details: prediction.feature_importance
                        .into_iter()
                        .map(|(k, v)| (k, serde_json::Value::from(v)))
                        .collect(),
                    ..Default::default()
                });
            }
        }

        // 3. Anomaly detection
        if let Some(ref detector) = self.anomaly_detector {
            let vector = features.to_vector();
            let score = detector.anomaly_score(&vector);
            if detector.is_anomaly(&vector) {
                events.push(DetectionEvent {
                    event_type: DetectionType::Anomaly,
                    severity: Severity::Medium,
                    confidence: score as f32,
                    message: format!("Anomaly detected (score: {:.3})", score),
                    ..Default::default()
                });
            }
        }

        // 4. Beaconing detection
        if let Some(alert) = self.beacon_detector.record_connection(flow.src_ip, flow.dst_ip) {
            if alert.confidence > 0.6 {
                events.push(DetectionEvent {
                    event_type: DetectionType::Beaconing,
                    severity: Severity::High,
                    confidence: alert.confidence as f32,
                    message: format!(
                        "C2 beaconing detected: interval={:.1}s, CV={:.3}, periodicity={:.3}",
                        alert.interval_mean,
                        alert.coefficient_of_variation,
                        alert.periodicity_score
                    ),
                    mitre_attack: vec!["T1071".into(), "T1573".into()],
                    ..Default::default()
                });
            }
        }

        events
    }

    fn class_to_severity(&self, class: &str) -> Severity {
        match class {
            "DoS" | "DDoS" => Severity::High,
            "Botnet" | "Infiltration" => Severity::Critical,
            "WebAttack" | "BruteForce" => Severity::High,
            "PortScan" => Severity::Medium,
            _ => Severity::Low,
        }
    }
}
```

## Configuration

```toml
# config.toml

[ml]
enabled = true
model_path = "/var/lib/crmonban/ml_model.bin"

[ml.baseline]
enabled = true
learning_period_hours = 168     # 1 week initial learning
update_interval_hours = 24      # Continuous baseline updates

[ml.classification]
enabled = true
min_confidence = 0.7
model_type = "random_forest"    # random_forest, gradient_boost
n_trees = 100
max_depth = 20

[ml.anomaly]
enabled = true
algorithm = "isolation_forest"  # isolation_forest, one_class_svm, autoencoder
contamination = 0.1             # Expected anomaly ratio
threshold = 0.5

[ml.beaconing]
enabled = true
min_connections = 20
max_variance_ratio = 0.2
periodicity_threshold = 0.7

[ml.training]
dataset_path = "/var/lib/crmonban/training_data"
auto_retrain = false
retrain_interval_days = 30
```

## Dependencies

```toml
[dependencies]
# ML frameworks
linfa = "0.7"
linfa-trees = "0.7"
linfa-clustering = "0.7"
ndarray = "0.15"

# FFT for beaconing detection
rustfft = "6"

# Serialization
bincode = "1"
serde = { version = "1", features = ["derive"] }

[features]
ml-detection = ["linfa", "linfa-trees", "ndarray", "rustfft"]
```

## CLI Commands

```bash
# Train model on dataset
crmonban ml train --dataset /path/to/cicids2017.csv

# Show model info
crmonban ml info

# Test model on pcap
crmonban ml test --pcap /path/to/capture.pcap

# Show baseline status
crmonban ml baseline status

# Reset baseline (start learning again)
crmonban ml baseline reset

# Show detection statistics
crmonban ml stats
```

## Estimated Effort

| Component | Files | Lines |
|-----------|-------|-------|
| Feature extraction | 6 | 800 |
| Baseline learning | 4 | 600 |
| Random Forest | 1 | 300 |
| Isolation Forest | 1 | 250 |
| Autoencoder | 1 | 300 |
| Beaconing detection | 1 | 250 |
| ML Engine | 1 | 400 |
| Training utilities | 2 | 300 |
| **Total** | **17** | **~3,200** |

## Success Criteria

1. Baseline learns normal traffic within 1 week
2. Classification accuracy > 95% on CICIDS2017
3. False positive rate < 1%
4. Detect beaconing with > 80% accuracy
5. Process flows at 10,000+ per second
6. Memory usage < 1GB for models + baseline
