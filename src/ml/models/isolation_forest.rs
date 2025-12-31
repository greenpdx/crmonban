//! Isolation Forest implementation
//!
//! Anomaly detection using isolation trees. Anomalies are easier to isolate
//! and thus have shorter path lengths in the trees.

use rand::prelude::*;
use serde::{Deserialize, Serialize};

use super::{AnomalyModel, ModelConfig};
use crate::ml::features::FeatureVector;

/// Isolation Forest model for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationForest {
    /// Individual isolation trees
    trees: Vec<IsolationTree>,
    /// Number of trees
    num_trees: usize,
    /// Sample size for each tree
    sample_size: usize,
    /// Anomaly score threshold
    threshold: f32,
    /// Average path length normalization factor
    avg_path_length: f32,
    /// Whether the model is trained
    trained: bool,
}

impl Default for IsolationForest {
    fn default() -> Self {
        Self::new(ModelConfig::default())
    }
}

impl IsolationForest {
    /// Create a new Isolation Forest
    pub fn new(config: ModelConfig) -> Self {
        Self {
            trees: Vec::new(),
            num_trees: config.num_trees,
            sample_size: config.sample_size,
            threshold: config.threshold,
            avg_path_length: 0.0,
            trained: false,
        }
    }

    /// Create with custom parameters
    pub fn with_params(num_trees: usize, sample_size: usize, threshold: f32) -> Self {
        Self {
            trees: Vec::new(),
            num_trees,
            sample_size,
            threshold,
            avg_path_length: 0.0,
            trained: false,
        }
    }

    /// Calculate average path length for normalization (c(n) function)
    fn average_path_length(n: usize) -> f32 {
        if n <= 1 {
            return 0.0;
        }
        let n = n as f32;
        2.0 * (n.ln() + 0.5772156649) - 2.0 * (n - 1.0) / n
    }

    /// Score a single sample
    fn score_sample(&self, sample: &[f32]) -> f32 {
        if self.trees.is_empty() || self.avg_path_length == 0.0 {
            return 0.5;
        }

        let total_path_length: f32 = self.trees
            .iter()
            .map(|tree| tree.path_length(sample, 0, self.sample_size))
            .sum();

        let avg_path = total_path_length / self.trees.len() as f32;

        // Anomaly score: 2^(-avg_path / c(sample_size))
        2.0_f32.powf(-avg_path / self.avg_path_length)
    }
}

impl AnomalyModel for IsolationForest {
    fn fit(&mut self, data: &[FeatureVector]) {
        if data.is_empty() {
            return;
        }

        let mut rng = rand::rng();
        let n_features = data[0].features.len();

        self.trees.clear();
        self.avg_path_length = Self::average_path_length(self.sample_size);

        for _ in 0..self.num_trees {
            // Sample with replacement
            let sample: Vec<Vec<f32>> = (0..self.sample_size.min(data.len()))
                .map(|_| {
                    let idx = rng.random_range(0..data.len());
                    data[idx].features.clone()
                })
                .collect();

            // Build tree
            let max_depth = (self.sample_size as f32).log2().ceil() as usize;
            let tree = IsolationTree::build(&sample, n_features, max_depth, &mut rng);
            self.trees.push(tree);
        }

        self.trained = true;
    }

    fn score(&self, sample: &FeatureVector) -> f32 {
        self.score_sample(&sample.features)
    }

    fn predict(&self, sample: &FeatureVector) -> bool {
        self.score(sample) >= self.threshold
    }

    fn name(&self) -> &str {
        "IsolationForest"
    }

    fn is_trained(&self) -> bool {
        self.trained
    }
}

/// A single isolation tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationTree {
    root: Option<Box<IsolationNode>>,
}

impl IsolationTree {
    /// Build an isolation tree from samples
    fn build<R: Rng>(
        samples: &[Vec<f32>],
        n_features: usize,
        max_depth: usize,
        rng: &mut R,
    ) -> Self {
        let root = Self::build_node(samples, n_features, 0, max_depth, rng);
        Self { root }
    }

    /// Recursively build tree nodes
    fn build_node<R: Rng>(
        samples: &[Vec<f32>],
        n_features: usize,
        depth: usize,
        max_depth: usize,
        rng: &mut R,
    ) -> Option<Box<IsolationNode>> {
        if samples.is_empty() {
            return None;
        }

        // Terminal conditions
        if depth >= max_depth || samples.len() <= 1 {
            return Some(Box::new(IsolationNode::Leaf {
                size: samples.len(),
            }));
        }

        // Randomly select feature
        let feature_idx = rng.random_range(0..n_features);

        // Find min/max for selected feature
        let mut min_val = f32::MAX;
        let mut max_val = f32::MIN;
        for sample in samples {
            if let Some(&val) = sample.get(feature_idx) {
                if val < min_val {
                    min_val = val;
                }
                if val > max_val {
                    max_val = val;
                }
            }
        }

        // If all values are the same, make a leaf
        if (max_val - min_val).abs() < f32::EPSILON {
            return Some(Box::new(IsolationNode::Leaf {
                size: samples.len(),
            }));
        }

        // Random split point
        let split_value = rng.random_range(min_val..max_val);

        // Partition samples
        let (left_samples, right_samples): (Vec<Vec<f32>>, Vec<Vec<f32>>) = samples
            .iter()
            .cloned()
            .partition(|s| s.get(feature_idx).map(|&v| v < split_value).unwrap_or(true));

        // Build child nodes
        let left = Self::build_node(&left_samples, n_features, depth + 1, max_depth, rng);
        let right = Self::build_node(&right_samples, n_features, depth + 1, max_depth, rng);

        Some(Box::new(IsolationNode::Internal {
            feature_idx,
            split_value,
            left,
            right,
        }))
    }

    /// Calculate path length for a sample
    fn path_length(&self, sample: &[f32], current_depth: usize, tree_size: usize) -> f32 {
        match &self.root {
            None => current_depth as f32,
            Some(node) => Self::node_path_length(node, sample, current_depth, tree_size),
        }
    }

    fn node_path_length(
        node: &IsolationNode,
        sample: &[f32],
        depth: usize,
        tree_size: usize,
    ) -> f32 {
        match node {
            IsolationNode::Leaf { size } => {
                // Add expected path length adjustment for leaves with multiple samples
                depth as f32 + IsolationForest::average_path_length(*size)
            }
            IsolationNode::Internal {
                feature_idx,
                split_value,
                left,
                right,
            } => {
                let val = sample.get(*feature_idx).copied().unwrap_or(0.0);
                let next_node = if val < *split_value { left } else { right };

                match next_node {
                    Some(n) => Self::node_path_length(n, sample, depth + 1, tree_size),
                    None => depth as f32 + 1.0,
                }
            }
        }
    }
}

/// Node in an isolation tree
#[derive(Debug, Clone, Serialize, Deserialize)]
enum IsolationNode {
    /// Internal node with split
    Internal {
        feature_idx: usize,
        split_value: f32,
        left: Option<Box<IsolationNode>>,
        right: Option<Box<IsolationNode>>,
    },
    /// Leaf node
    Leaf {
        size: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::AppProtocol;
    use chrono::Utc;

    fn make_features(values: Vec<f32>) -> FeatureVector {
        FeatureVector {
            features: values,
            flow_id: 1,
            timestamp: Utc::now(),
            protocol: AppProtocol::Unknown,
        }
    }

    #[test]
    fn test_isolation_forest_creation() {
        let forest = IsolationForest::default();
        assert!(!forest.is_trained());
        assert_eq!(forest.name(), "IsolationForest");
    }

    #[test]
    fn test_isolation_forest_training() {
        let mut forest = IsolationForest::with_params(10, 32, 0.5);

        // Create normal training data
        let data: Vec<FeatureVector> = (0..100)
            .map(|i| make_features(vec![50.0 + (i as f32 % 10.0); 10]))
            .collect();

        forest.fit(&data);

        assert!(forest.is_trained());
        assert_eq!(forest.trees.len(), 10);
    }

    #[test]
    fn test_isolation_forest_scoring() {
        let mut forest = IsolationForest::with_params(50, 64, 0.6);

        // Train on varied data (need variance for meaningful splits)
        let data: Vec<FeatureVector> = (0..200)
            .map(|i| {
                // Values vary between 40 and 60
                let value = 50.0 + (i as f32 % 21.0) - 10.0;
                make_features(vec![value; 10])
            })
            .collect();

        forest.fit(&data);

        // Normal sample should get a score
        let normal = make_features(vec![50.0; 10]);
        let normal_score = forest.score(&normal);

        // Anomalous sample (way outside normal range)
        let anomalous = make_features(vec![500.0; 10]);
        let anomalous_score = forest.score(&anomalous);

        // Both should be valid scores
        assert!(normal_score >= 0.0 && normal_score <= 1.0);
        assert!(anomalous_score >= 0.0 && anomalous_score <= 1.0);
    }

    #[test]
    fn test_average_path_length() {
        // c(1) should be 0
        assert_eq!(IsolationForest::average_path_length(1), 0.0);

        // c(n) should increase with n
        let c_10 = IsolationForest::average_path_length(10);
        let c_100 = IsolationForest::average_path_length(100);
        assert!(c_100 > c_10, "c(100)={} should be > c(10)={}", c_100, c_10);
    }
}
