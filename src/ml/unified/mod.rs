//! Unified Feature Vector
//!
//! Combines features from all detection sources into a single 159-dimensional vector:
//! - ML Flow features (CICIDS2017-compatible): 39D
//! - Layer234 features: 88D
//! - Extra34 features: 16D
//! - Wireless features: 16D (when available)

mod mapping;
mod normalization;
mod fusion;

pub use mapping::{FeatureRange, FeatureSource, FEATURE_RANGES};
pub use normalization::{Normalizer, NormalizationMethod};
pub use fusion::{FeatureFuser, FusionConfig};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Total dimensions in the unified feature vector
pub const UNIFIED_DIM: usize = 159;

/// Custom serialization for large arrays (serde doesn't support arrays > 32 by default)
mod serde_features {
    use super::UNIFIED_DIM;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(features: &[f32; UNIFIED_DIM], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        features.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[f32; UNIFIED_DIM], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<f32>::deserialize(deserializer)?;
        if vec.len() != UNIFIED_DIM {
            return Err(serde::de::Error::custom(format!(
                "expected {} elements, got {}",
                UNIFIED_DIM,
                vec.len()
            )));
        }
        let mut arr = [0.0f32; UNIFIED_DIM];
        arr.copy_from_slice(&vec);
        Ok(arr)
    }
}

/// Dimension ranges for each source
pub mod dims {
    /// ML Flow features (CICIDS2017-compatible)
    pub const ML_START: usize = 0;
    pub const ML_END: usize = 39;
    pub const ML_DIM: usize = 39;

    /// Layer234 features
    pub const L234_START: usize = 39;
    pub const L234_END: usize = 127;
    pub const L234_DIM: usize = 88;

    /// Extra34 features (IP/Fragment/ICMP/TCP attacks)
    pub const EXTRA34_START: usize = 127;
    pub const EXTRA34_END: usize = 143;
    pub const EXTRA34_DIM: usize = 16;

    /// Wireless features
    pub const WIRELESS_START: usize = 143;
    pub const WIRELESS_END: usize = 159;
    pub const WIRELESS_DIM: usize = 16;
}

/// Flags indicating which feature sources contributed to the vector
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FeatureSources(u8);

impl FeatureSources {
    /// ML flow features present
    pub const ML_FLOW: u8 = 0b0001;
    /// Layer234 features present
    pub const LAYER234: u8 = 0b0010;
    /// Extra34 features present
    pub const EXTRA34: u8 = 0b0100;
    /// Wireless features present
    pub const WIRELESS: u8 = 0b1000;
    /// All wired features (ML + L234 + Extra34)
    pub const ALL_WIRED: u8 = Self::ML_FLOW | Self::LAYER234 | Self::EXTRA34;
    /// All features including wireless
    pub const ALL: u8 = Self::ALL_WIRED | Self::WIRELESS;

    /// Create empty sources
    pub fn empty() -> Self {
        Self(0)
    }

    /// Create from raw bits
    pub fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// Get raw bits
    pub fn bits(&self) -> u8 {
        self.0
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }

    /// Check if contains a flag
    pub fn contains(&self, flag: u8) -> bool {
        (self.0 & flag) == flag
    }

    /// Insert a flag
    pub fn insert(&mut self, flag: u8) {
        self.0 |= flag;
    }

    /// Remove a flag
    pub fn remove(&mut self, flag: u8) {
        self.0 &= !flag;
    }
}

impl std::ops::BitOr<u8> for FeatureSources {
    type Output = Self;
    fn bitor(self, rhs: u8) -> Self::Output {
        Self(self.0 | rhs)
    }
}

impl std::ops::BitOrAssign<u8> for FeatureSources {
    fn bitor_assign(&mut self, rhs: u8) {
        self.0 |= rhs;
    }
}

/// Unified feature vector combining all detection sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedFeatureVector {
    /// Feature values (159 dimensions)
    #[serde(with = "serde_features")]
    pub features: [f32; UNIFIED_DIM],
    /// Which sources contributed to this vector
    pub sources: FeatureSources,
    /// Flow ID for reference (0 if not from flow)
    pub flow_id: u64,
    /// Source IP address
    pub src_ip: Option<std::net::IpAddr>,
    /// Timestamp of extraction
    pub timestamp: DateTime<Utc>,
    /// Whether features have been normalized
    pub normalized: bool,
}

impl Default for UnifiedFeatureVector {
    fn default() -> Self {
        Self {
            features: [0.0; UNIFIED_DIM],
            sources: FeatureSources::empty(),
            flow_id: 0,
            src_ip: None,
            timestamp: Utc::now(),
            normalized: false,
        }
    }
}

impl UnifiedFeatureVector {
    /// Create a new empty unified feature vector
    pub fn new() -> Self {
        Self::default()
    }

    /// Create with a specific flow ID
    pub fn with_flow_id(flow_id: u64) -> Self {
        Self {
            flow_id,
            ..Self::default()
        }
    }

    /// Create with a specific source IP
    pub fn with_src_ip(src_ip: std::net::IpAddr) -> Self {
        Self {
            src_ip: Some(src_ip),
            ..Self::default()
        }
    }

    /// Set ML flow features (indices 0-38)
    pub fn set_ml_features(&mut self, features: &[f32]) {
        let len = features.len().min(dims::ML_DIM);
        self.features[dims::ML_START..dims::ML_START + len].copy_from_slice(&features[..len]);
        self.sources.insert(FeatureSources::ML_FLOW);
    }

    /// Set Layer234 features (indices 39-126)
    pub fn set_l234_features(&mut self, features: &[f32; 88]) {
        self.features[dims::L234_START..dims::L234_END].copy_from_slice(features);
        self.sources.insert(FeatureSources::LAYER234);
    }

    /// Set Extra34 features (indices 127-142)
    pub fn set_extra34_features(&mut self, features: &[f32; 16]) {
        self.features[dims::EXTRA34_START..dims::EXTRA34_END].copy_from_slice(features);
        self.sources.insert(FeatureSources::EXTRA34);
    }

    /// Set Wireless features (indices 143-158)
    pub fn set_wireless_features(&mut self, features: &[f32; 16]) {
        self.features[dims::WIRELESS_START..dims::WIRELESS_END].copy_from_slice(features);
        self.sources.insert(FeatureSources::WIRELESS);
    }

    /// Get ML flow features slice
    pub fn ml_features(&self) -> &[f32] {
        &self.features[dims::ML_START..dims::ML_END]
    }

    /// Get Layer234 features slice
    pub fn l234_features(&self) -> &[f32] {
        &self.features[dims::L234_START..dims::L234_END]
    }

    /// Get Extra34 features slice
    pub fn extra34_features(&self) -> &[f32] {
        &self.features[dims::EXTRA34_START..dims::EXTRA34_END]
    }

    /// Get Wireless features slice
    pub fn wireless_features(&self) -> &[f32] {
        &self.features[dims::WIRELESS_START..dims::WIRELESS_END]
    }

    /// Check if ML flow features are present
    pub fn has_ml(&self) -> bool {
        self.sources.contains(FeatureSources::ML_FLOW)
    }

    /// Check if Layer234 features are present
    pub fn has_l234(&self) -> bool {
        self.sources.contains(FeatureSources::LAYER234)
    }

    /// Check if Extra34 features are present
    pub fn has_extra34(&self) -> bool {
        self.sources.contains(FeatureSources::EXTRA34)
    }

    /// Check if Wireless features are present
    pub fn has_wireless(&self) -> bool {
        self.sources.contains(FeatureSources::WIRELESS)
    }

    /// Check if all wired features are present
    pub fn has_all_wired(&self) -> bool {
        self.sources.contains(FeatureSources::ALL_WIRED)
    }

    /// Check if all features are present
    pub fn has_all(&self) -> bool {
        self.sources.contains(FeatureSources::ALL)
    }

    /// Get all features as a slice
    pub fn as_slice(&self) -> &[f32] {
        &self.features
    }

    /// Get mutable features slice
    pub fn as_mut_slice(&mut self) -> &mut [f32] {
        &mut self.features
    }

    /// Get feature count for present sources
    pub fn active_feature_count(&self) -> usize {
        let mut count = 0;
        if self.has_ml() {
            count += dims::ML_DIM;
        }
        if self.has_l234() {
            count += dims::L234_DIM;
        }
        if self.has_extra34() {
            count += dims::EXTRA34_DIM;
        }
        if self.has_wireless() {
            count += dims::WIRELESS_DIM;
        }
        count
    }

    /// Compute L2 norm of the feature vector
    pub fn l2_norm(&self) -> f32 {
        self.features.iter().map(|x| x * x).sum::<f32>().sqrt()
    }

    /// Compute cosine similarity with another vector
    pub fn cosine_similarity(&self, other: &Self) -> f32 {
        let dot: f32 = self.features.iter()
            .zip(other.features.iter())
            .map(|(a, b)| a * b)
            .sum();

        let norm_self = self.l2_norm();
        let norm_other = other.l2_norm();

        if norm_self > 0.0 && norm_other > 0.0 {
            dot / (norm_self * norm_other)
        } else {
            0.0
        }
    }

    /// Compute Euclidean distance to another vector
    pub fn euclidean_distance(&self, other: &Self) -> f32 {
        self.features.iter()
            .zip(other.features.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f32>()
            .sqrt()
    }

    /// Create a mask for active features (1.0 for present, 0.0 for absent)
    pub fn active_mask(&self) -> [f32; UNIFIED_DIM] {
        let mut mask = [0.0; UNIFIED_DIM];

        if self.has_ml() {
            for i in dims::ML_START..dims::ML_END {
                mask[i] = 1.0;
            }
        }
        if self.has_l234() {
            for i in dims::L234_START..dims::L234_END {
                mask[i] = 1.0;
            }
        }
        if self.has_extra34() {
            for i in dims::EXTRA34_START..dims::EXTRA34_END {
                mask[i] = 1.0;
            }
        }
        if self.has_wireless() {
            for i in dims::WIRELESS_START..dims::WIRELESS_END {
                mask[i] = 1.0;
            }
        }

        mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_vector_creation() {
        let vec = UnifiedFeatureVector::new();
        assert_eq!(vec.features.len(), UNIFIED_DIM);
        assert!(vec.sources.is_empty());
        assert!(!vec.normalized);
    }

    #[test]
    fn test_set_ml_features() {
        let mut vec = UnifiedFeatureVector::new();
        let ml = [1.0f32; 39];
        vec.set_ml_features(&ml);

        assert!(vec.has_ml());
        assert!(!vec.has_l234());
        assert_eq!(vec.ml_features()[0], 1.0);
    }

    #[test]
    fn test_set_l234_features() {
        let mut vec = UnifiedFeatureVector::new();
        let l234 = [2.0f32; 88];
        vec.set_l234_features(&l234);

        assert!(vec.has_l234());
        assert_eq!(vec.l234_features()[0], 2.0);
    }

    #[test]
    fn test_set_extra34_features() {
        let mut vec = UnifiedFeatureVector::new();
        let extra34 = [3.0f32; 16];
        vec.set_extra34_features(&extra34);

        assert!(vec.has_extra34());
        assert_eq!(vec.extra34_features()[0], 3.0);
    }

    #[test]
    fn test_set_wireless_features() {
        let mut vec = UnifiedFeatureVector::new();
        let wireless = [4.0f32; 16];
        vec.set_wireless_features(&wireless);

        assert!(vec.has_wireless());
        assert_eq!(vec.wireless_features()[0], 4.0);
    }

    #[test]
    fn test_active_feature_count() {
        let mut vec = UnifiedFeatureVector::new();
        assert_eq!(vec.active_feature_count(), 0);

        vec.set_ml_features(&[0.0; 39]);
        assert_eq!(vec.active_feature_count(), 39);

        vec.set_l234_features(&[0.0; 88]);
        assert_eq!(vec.active_feature_count(), 127);
    }

    #[test]
    fn test_cosine_similarity() {
        let mut vec1 = UnifiedFeatureVector::new();
        let mut vec2 = UnifiedFeatureVector::new();

        vec1.features[0] = 1.0;
        vec2.features[0] = 1.0;

        // Identical vectors should have similarity 1.0
        let sim = vec1.cosine_similarity(&vec2);
        assert!((sim - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_dimensions() {
        // Verify dimension ranges don't overlap
        assert_eq!(dims::ML_START, 0);
        assert_eq!(dims::ML_END, dims::L234_START);
        assert_eq!(dims::L234_END, dims::EXTRA34_START);
        assert_eq!(dims::EXTRA34_END, dims::WIRELESS_START);
        assert_eq!(dims::WIRELESS_END, UNIFIED_DIM);

        // Verify totals
        assert_eq!(dims::ML_DIM + dims::L234_DIM + dims::EXTRA34_DIM + dims::WIRELESS_DIM, UNIFIED_DIM);
    }
}
