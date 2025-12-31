//! Feature Normalization
//!
//! Provides cross-domain normalization for unified feature vectors.

use super::{dims, UnifiedFeatureVector, UNIFIED_DIM};
use serde::{Deserialize, Serialize};

/// Normalization method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NormalizationMethod {
    /// Min-max normalization to [0, 1]
    MinMax,
    /// Z-score standardization (mean=0, std=1)
    ZScore,
    /// Robust scaling using median and IQR
    Robust,
    /// L2 normalization (unit vector)
    L2,
    /// No normalization
    None,
}

/// Feature statistics for normalization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureStats {
    /// Minimum value seen
    pub min: f32,
    /// Maximum value seen
    pub max: f32,
    /// Running mean
    pub mean: f32,
    /// Running M2 for variance (Welford's algorithm)
    pub m2: f64,
    /// Sample count
    pub count: u64,
    /// Median (approximate, updated periodically)
    pub median: f32,
    /// Interquartile range (approximate)
    pub iqr: f32,
}

impl Default for FeatureStats {
    fn default() -> Self {
        Self {
            min: f32::MAX,
            max: f32::MIN,
            mean: 0.0,
            m2: 0.0,
            count: 0,
            median: 0.0,
            iqr: 1.0,
        }
    }
}

impl FeatureStats {
    /// Update statistics with a new value using Welford's online algorithm
    pub fn update(&mut self, value: f32) {
        self.count += 1;

        // Update min/max
        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }

        // Welford's online algorithm for mean and variance
        let delta = value as f64 - self.mean as f64;
        self.mean += (delta / self.count as f64) as f32;
        let delta2 = value as f64 - self.mean as f64;
        self.m2 += delta * delta2;
    }

    /// Get variance
    pub fn variance(&self) -> f32 {
        if self.count < 2 {
            0.0
        } else {
            (self.m2 / (self.count - 1) as f64) as f32
        }
    }

    /// Get standard deviation
    pub fn std(&self) -> f32 {
        self.variance().sqrt()
    }

    /// Get range (max - min)
    pub fn range(&self) -> f32 {
        if self.count == 0 {
            0.0
        } else {
            self.max - self.min
        }
    }

    /// Normalize a value using min-max
    pub fn normalize_minmax(&self, value: f32) -> f32 {
        let range = self.range();
        if range > 0.0 {
            (value - self.min) / range
        } else {
            0.0
        }
    }

    /// Standardize a value using z-score
    pub fn standardize(&self, value: f32) -> f32 {
        let std = self.std();
        if std > 0.0 {
            (value - self.mean) / std
        } else {
            0.0
        }
    }

    /// Robust scale using median and IQR
    pub fn robust_scale(&self, value: f32) -> f32 {
        if self.iqr > 0.0 {
            (value - self.median) / self.iqr
        } else {
            0.0
        }
    }
}

/// Normalizer for unified feature vectors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Normalizer {
    /// Statistics for each feature
    pub stats: Vec<FeatureStats>,
    /// Default normalization method
    pub method: NormalizationMethod,
    /// Per-source normalization methods (override default)
    pub source_methods: [NormalizationMethod; 4],
    /// Whether the normalizer has been fitted
    pub fitted: bool,
    /// Minimum samples before normalization is applied
    pub min_samples: u64,
}

impl Default for Normalizer {
    fn default() -> Self {
        Self::new(NormalizationMethod::ZScore)
    }
}

impl Normalizer {
    /// Create a new normalizer with the specified method
    pub fn new(method: NormalizationMethod) -> Self {
        Self {
            stats: vec![FeatureStats::default(); UNIFIED_DIM],
            method,
            source_methods: [method; 4], // Default all sources to same method
            fitted: false,
            min_samples: 100,
        }
    }

    /// Set per-source normalization methods
    pub fn with_source_methods(
        mut self,
        ml: NormalizationMethod,
        l234: NormalizationMethod,
        extra34: NormalizationMethod,
        wireless: NormalizationMethod,
    ) -> Self {
        self.source_methods = [ml, l234, extra34, wireless];
        self
    }

    /// Set minimum samples before normalization
    pub fn with_min_samples(mut self, min_samples: u64) -> Self {
        self.min_samples = min_samples;
        self
    }

    /// Update statistics from a vector (fitting)
    pub fn fit(&mut self, vector: &UnifiedFeatureVector) {
        for (i, &value) in vector.features.iter().enumerate() {
            // Only update if value is not zero or if the source is present
            if value != 0.0 || self.is_source_present(vector, i) {
                self.stats[i].update(value);
            }
        }

        if self.stats[0].count >= self.min_samples {
            self.fitted = true;
        }
    }

    /// Check if a feature index belongs to a present source
    fn is_source_present(&self, vector: &UnifiedFeatureVector, index: usize) -> bool {
        if index < dims::ML_END {
            vector.has_ml()
        } else if index < dims::L234_END {
            vector.has_l234()
        } else if index < dims::EXTRA34_END {
            vector.has_extra34()
        } else {
            vector.has_wireless()
        }
    }

    /// Get normalization method for a feature index
    fn method_for_index(&self, index: usize) -> NormalizationMethod {
        if index < dims::ML_END {
            self.source_methods[0]
        } else if index < dims::L234_END {
            self.source_methods[1]
        } else if index < dims::EXTRA34_END {
            self.source_methods[2]
        } else {
            self.source_methods[3]
        }
    }

    /// Transform a vector using fitted statistics
    pub fn transform(&self, vector: &mut UnifiedFeatureVector) {
        if !self.fitted {
            return;
        }

        for i in 0..UNIFIED_DIM {
            let method = self.method_for_index(i);
            let value = vector.features[i];

            vector.features[i] = match method {
                NormalizationMethod::MinMax => self.stats[i].normalize_minmax(value),
                NormalizationMethod::ZScore => self.stats[i].standardize(value),
                NormalizationMethod::Robust => self.stats[i].robust_scale(value),
                NormalizationMethod::L2 => value, // L2 handled separately
                NormalizationMethod::None => value,
            };
        }

        // Handle L2 normalization per-source if specified
        for (source_idx, &method) in self.source_methods.iter().enumerate() {
            if method == NormalizationMethod::L2 {
                self.l2_normalize_source(vector, source_idx);
            }
        }

        vector.normalized = true;
    }

    /// L2 normalize a specific source's features
    fn l2_normalize_source(&self, vector: &mut UnifiedFeatureVector, source_idx: usize) {
        let (start, end) = match source_idx {
            0 => (dims::ML_START, dims::ML_END),
            1 => (dims::L234_START, dims::L234_END),
            2 => (dims::EXTRA34_START, dims::EXTRA34_END),
            3 => (dims::WIRELESS_START, dims::WIRELESS_END),
            _ => return,
        };

        let norm: f32 = vector.features[start..end]
            .iter()
            .map(|x| x * x)
            .sum::<f32>()
            .sqrt();

        if norm > 0.0 {
            for i in start..end {
                vector.features[i] /= norm;
            }
        }
    }

    /// Fit and transform in one step
    pub fn fit_transform(&mut self, vector: &mut UnifiedFeatureVector) {
        self.fit(vector);
        self.transform(vector);
    }

    /// Get the number of samples used for fitting
    pub fn sample_count(&self) -> u64 {
        self.stats.first().map(|s| s.count).unwrap_or(0)
    }

    /// Reset the normalizer
    pub fn reset(&mut self) {
        self.stats = vec![FeatureStats::default(); UNIFIED_DIM];
        self.fitted = false;
    }

    /// Export statistics for persistence
    pub fn export_stats(&self) -> Vec<(f32, f32, f32, f32)> {
        self.stats
            .iter()
            .map(|s| (s.min, s.max, s.mean, s.std()))
            .collect()
    }

    /// Import statistics from persistence
    pub fn import_stats(&mut self, stats: &[(f32, f32, f32, f32)], count: u64) {
        for (i, &(min, max, mean, std)) in stats.iter().enumerate() {
            if i < self.stats.len() {
                self.stats[i].min = min;
                self.stats[i].max = max;
                self.stats[i].mean = mean;
                // Reconstruct m2 from std and count
                self.stats[i].m2 = (std * std * (count - 1) as f32) as f64;
                self.stats[i].count = count;
            }
        }
        self.fitted = count >= self.min_samples;
    }
}

/// Clip values to a range (for outlier handling)
pub fn clip(value: f32, min: f32, max: f32) -> f32 {
    value.max(min).min(max)
}

/// Apply tanh scaling (compresses outliers)
pub fn tanh_scale(value: f32, scale: f32) -> f32 {
    (value / scale).tanh()
}

/// Apply log1p scaling (for highly skewed data)
pub fn log1p_scale(value: f32) -> f32 {
    if value >= 0.0 {
        (value + 1.0).ln()
    } else {
        -(-value + 1.0).ln()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature_stats_update() {
        let mut stats = FeatureStats::default();

        stats.update(1.0);
        stats.update(2.0);
        stats.update(3.0);

        assert_eq!(stats.count, 3);
        assert_eq!(stats.min, 1.0);
        assert_eq!(stats.max, 3.0);
        assert!((stats.mean - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_minmax_normalization() {
        let mut stats = FeatureStats::default();
        for v in [0.0, 10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0] {
            stats.update(v);
        }

        assert!((stats.normalize_minmax(0.0) - 0.0).abs() < 0.001);
        assert!((stats.normalize_minmax(50.0) - 0.5).abs() < 0.001);
        assert!((stats.normalize_minmax(100.0) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_zscore_standardization() {
        let mut stats = FeatureStats::default();
        // Standard normal-ish data
        for v in [0.0, 1.0, 2.0, 3.0, 4.0] {
            stats.update(v);
        }

        let standardized = stats.standardize(stats.mean);
        assert!(standardized.abs() < 0.001); // Mean should map to 0
    }

    #[test]
    fn test_normalizer_fit_transform() {
        let mut normalizer = Normalizer::new(NormalizationMethod::MinMax);
        normalizer.min_samples = 2;

        // Create test vectors
        let mut vec1 = UnifiedFeatureVector::new();
        vec1.features[0] = 0.0;
        vec1.features[1] = 50.0;
        vec1.sources = super::super::FeatureSources(super::super::FeatureSources::ML_FLOW);

        let mut vec2 = UnifiedFeatureVector::new();
        vec2.features[0] = 100.0;
        vec2.features[1] = 100.0;
        vec2.sources = super::super::FeatureSources(super::super::FeatureSources::ML_FLOW);

        // Fit on both
        normalizer.fit(&vec1);
        normalizer.fit(&vec2);

        assert!(normalizer.fitted);

        // Transform
        let mut test_vec = UnifiedFeatureVector::new();
        test_vec.features[0] = 50.0;
        test_vec.features[1] = 75.0;
        test_vec.sources = super::super::FeatureSources(super::super::FeatureSources::ML_FLOW);

        normalizer.transform(&mut test_vec);

        assert!(test_vec.normalized);
        assert!((test_vec.features[0] - 0.5).abs() < 0.001);
    }

    #[test]
    fn test_source_specific_methods() {
        let normalizer = Normalizer::new(NormalizationMethod::ZScore)
            .with_source_methods(
                NormalizationMethod::MinMax,
                NormalizationMethod::ZScore,
                NormalizationMethod::Robust,
                NormalizationMethod::L2,
            );

        // Check method selection
        assert_eq!(normalizer.method_for_index(0), NormalizationMethod::MinMax);
        assert_eq!(normalizer.method_for_index(39), NormalizationMethod::ZScore);
        assert_eq!(normalizer.method_for_index(127), NormalizationMethod::Robust);
        assert_eq!(normalizer.method_for_index(143), NormalizationMethod::L2);
    }

    #[test]
    fn test_clip() {
        assert_eq!(clip(5.0, 0.0, 10.0), 5.0);
        assert_eq!(clip(-5.0, 0.0, 10.0), 0.0);
        assert_eq!(clip(15.0, 0.0, 10.0), 10.0);
    }

    #[test]
    fn test_tanh_scale() {
        assert!((tanh_scale(0.0, 1.0) - 0.0).abs() < 0.001);
        assert!(tanh_scale(100.0, 1.0) > 0.99);
        assert!(tanh_scale(-100.0, 1.0) < -0.99);
    }
}
