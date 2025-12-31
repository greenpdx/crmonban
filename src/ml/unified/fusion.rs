//! Feature Fusion
//!
//! Combines features from multiple detection sources into unified vectors.

use std::net::IpAddr;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::{
    dims, FeatureSources, Normalizer, NormalizationMethod, UnifiedFeatureVector, UNIFIED_DIM,
};

/// Configuration for feature fusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FusionConfig {
    /// Whether to normalize features
    pub normalize: bool,
    /// Normalization method
    pub normalization_method: NormalizationMethod,
    /// Whether to include flow features
    pub include_ml: bool,
    /// Whether to include Layer234 features
    pub include_l234: bool,
    /// Whether to include Extra34 features
    pub include_extra34: bool,
    /// Whether to include wireless features
    pub include_wireless: bool,
    /// Minimum feature sources required for valid vector
    pub min_sources: u8,
}

impl Default for FusionConfig {
    fn default() -> Self {
        Self {
            normalize: true,
            normalization_method: NormalizationMethod::ZScore,
            include_ml: true,
            include_l234: true,
            include_extra34: true,
            include_wireless: true,
            min_sources: 1,
        }
    }
}

/// Feature fuser combining all detection sources
#[derive(Debug)]
pub struct FeatureFuser {
    /// Configuration
    config: FusionConfig,
    /// Normalizer for feature normalization
    normalizer: Normalizer,
    /// Statistics
    stats: FuserStats,
}

/// Fuser statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FuserStats {
    /// Total vectors created
    pub vectors_created: u64,
    /// Vectors with ML features
    pub with_ml: u64,
    /// Vectors with L234 features
    pub with_l234: u64,
    /// Vectors with Extra34 features
    pub with_extra34: u64,
    /// Vectors with wireless features
    pub with_wireless: u64,
    /// Full vectors (all sources)
    pub full_vectors: u64,
}

impl Default for FeatureFuser {
    fn default() -> Self {
        Self::new(FusionConfig::default())
    }
}

impl FeatureFuser {
    /// Create a new feature fuser with the given configuration
    pub fn new(config: FusionConfig) -> Self {
        let normalizer = Normalizer::new(config.normalization_method)
            .with_min_samples(100);

        Self {
            config,
            normalizer,
            stats: FuserStats::default(),
        }
    }

    /// Create a unified vector from ML flow features
    pub fn from_ml_features(&mut self, features: &[f32], flow_id: u64) -> UnifiedFeatureVector {
        let mut vec = UnifiedFeatureVector::with_flow_id(flow_id);

        if self.config.include_ml && features.len() >= dims::ML_DIM {
            vec.set_ml_features(&features[..dims::ML_DIM]);
            self.stats.with_ml += 1;
        }

        self.finalize_vector(vec)
    }

    /// Create a unified vector from Layer234 features
    pub fn from_l234_features(
        &mut self,
        features: &[f32; 88],
        src_ip: IpAddr,
    ) -> UnifiedFeatureVector {
        let mut vec = UnifiedFeatureVector::with_src_ip(src_ip);

        if self.config.include_l234 {
            vec.set_l234_features(features);
            self.stats.with_l234 += 1;
        }

        self.finalize_vector(vec)
    }

    /// Create a unified vector from Extra34 features
    pub fn from_extra34_features(
        &mut self,
        features: &[f32; 16],
        src_ip: IpAddr,
    ) -> UnifiedFeatureVector {
        let mut vec = UnifiedFeatureVector::with_src_ip(src_ip);

        if self.config.include_extra34 {
            vec.set_extra34_features(features);
            self.stats.with_extra34 += 1;
        }

        self.finalize_vector(vec)
    }

    /// Create a unified vector from Wireless features
    pub fn from_wireless_features(
        &mut self,
        features: &[f32; 16],
        src_ip: Option<IpAddr>,
    ) -> UnifiedFeatureVector {
        let mut vec = if let Some(ip) = src_ip {
            UnifiedFeatureVector::with_src_ip(ip)
        } else {
            UnifiedFeatureVector::new()
        };

        if self.config.include_wireless {
            vec.set_wireless_features(features);
            self.stats.with_wireless += 1;
        }

        self.finalize_vector(vec)
    }

    /// Create a unified vector from multiple sources
    pub fn fuse(
        &mut self,
        ml_features: Option<&[f32]>,
        l234_features: Option<&[f32; 88]>,
        extra34_features: Option<&[f32; 16]>,
        wireless_features: Option<&[f32; 16]>,
        flow_id: u64,
        src_ip: Option<IpAddr>,
    ) -> Option<UnifiedFeatureVector> {
        let mut vec = UnifiedFeatureVector {
            flow_id,
            src_ip,
            timestamp: Utc::now(),
            ..Default::default()
        };

        // Add ML features
        if self.config.include_ml {
            if let Some(features) = ml_features {
                let len = features.len().min(dims::ML_DIM);
                vec.features[dims::ML_START..dims::ML_START + len]
                    .copy_from_slice(&features[..len]);
                vec.sources |= FeatureSources::ML_FLOW;
                self.stats.with_ml += 1;
            }
        }

        // Add Layer234 features
        if self.config.include_l234 {
            if let Some(features) = l234_features {
                vec.set_l234_features(features);
                self.stats.with_l234 += 1;
            }
        }

        // Add Extra34 features
        if self.config.include_extra34 {
            if let Some(features) = extra34_features {
                vec.set_extra34_features(features);
                self.stats.with_extra34 += 1;
            }
        }

        // Add Wireless features
        if self.config.include_wireless {
            if let Some(features) = wireless_features {
                vec.set_wireless_features(features);
                self.stats.with_wireless += 1;
            }
        }

        // Check minimum sources
        let source_count = vec.sources.bits().count_ones() as u8;
        if source_count < self.config.min_sources {
            return None;
        }

        // Track full vectors
        if source_count == 4 {
            self.stats.full_vectors += 1;
        }

        Some(self.finalize_vector(vec))
    }

    /// Merge an existing vector with new features
    pub fn merge(
        &mut self,
        existing: &UnifiedFeatureVector,
        ml_features: Option<&[f32]>,
        l234_features: Option<&[f32; 88]>,
        extra34_features: Option<&[f32; 16]>,
        wireless_features: Option<&[f32; 16]>,
    ) -> UnifiedFeatureVector {
        let mut vec = existing.clone();

        // Add ML features if not present
        if self.config.include_ml && !vec.has_ml() {
            if let Some(features) = ml_features {
                let len = features.len().min(dims::ML_DIM);
                vec.features[dims::ML_START..dims::ML_START + len]
                    .copy_from_slice(&features[..len]);
                vec.sources |= FeatureSources::ML_FLOW;
            }
        }

        // Add Layer234 features if not present
        if self.config.include_l234 && !vec.has_l234() {
            if let Some(features) = l234_features {
                vec.set_l234_features(features);
            }
        }

        // Add Extra34 features if not present
        if self.config.include_extra34 && !vec.has_extra34() {
            if let Some(features) = extra34_features {
                vec.set_extra34_features(features);
            }
        }

        // Add Wireless features if not present
        if self.config.include_wireless && !vec.has_wireless() {
            if let Some(features) = wireless_features {
                vec.set_wireless_features(features);
            }
        }

        vec.timestamp = Utc::now();
        vec.normalized = false; // Re-normalization needed

        self.finalize_vector(vec)
    }

    /// Finalize a vector (normalize, update stats)
    fn finalize_vector(&mut self, mut vec: UnifiedFeatureVector) -> UnifiedFeatureVector {
        self.stats.vectors_created += 1;

        // Update normalizer
        self.normalizer.fit(&vec);

        // Normalize if configured
        if self.config.normalize && self.normalizer.fitted {
            self.normalizer.transform(&mut vec);
        }

        vec
    }

    /// Get normalizer reference
    pub fn normalizer(&self) -> &Normalizer {
        &self.normalizer
    }

    /// Get mutable normalizer reference
    pub fn normalizer_mut(&mut self) -> &mut Normalizer {
        &mut self.normalizer
    }

    /// Get statistics
    pub fn stats(&self) -> &FuserStats {
        &self.stats
    }

    /// Get configuration
    pub fn config(&self) -> &FusionConfig {
        &self.config
    }

    /// Reset the fuser
    pub fn reset(&mut self) {
        self.normalizer.reset();
        self.stats = FuserStats::default();
    }
}

/// Builder for creating unified vectors incrementally
#[derive(Debug, Default)]
pub struct UnifiedVectorBuilder {
    vec: UnifiedFeatureVector,
}

impl UnifiedVectorBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set flow ID
    pub fn flow_id(mut self, id: u64) -> Self {
        self.vec.flow_id = id;
        self
    }

    /// Set source IP
    pub fn src_ip(mut self, ip: IpAddr) -> Self {
        self.vec.src_ip = Some(ip);
        self
    }

    /// Add ML features
    pub fn ml_features(mut self, features: &[f32]) -> Self {
        self.vec.set_ml_features(features);
        self
    }

    /// Add Layer234 features
    pub fn l234_features(mut self, features: &[f32; 88]) -> Self {
        self.vec.set_l234_features(features);
        self
    }

    /// Add Extra34 features
    pub fn extra34_features(mut self, features: &[f32; 16]) -> Self {
        self.vec.set_extra34_features(features);
        self
    }

    /// Add Wireless features
    pub fn wireless_features(mut self, features: &[f32; 16]) -> Self {
        self.vec.set_wireless_features(features);
        self
    }

    /// Build the final vector
    pub fn build(self) -> UnifiedFeatureVector {
        self.vec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fuser_creation() {
        let fuser = FeatureFuser::default();
        assert_eq!(fuser.stats().vectors_created, 0);
    }

    #[test]
    fn test_from_ml_features() {
        let mut fuser = FeatureFuser::default();
        let ml_features = [1.0f32; 39];

        let vec = fuser.from_ml_features(&ml_features, 123);

        assert!(vec.has_ml());
        assert_eq!(vec.flow_id, 123);
        assert_eq!(fuser.stats().with_ml, 1);
    }

    #[test]
    fn test_from_l234_features() {
        let mut fuser = FeatureFuser::default();
        let l234_features = [2.0f32; 88];
        let src_ip: IpAddr = "192.168.1.1".parse().unwrap();

        let vec = fuser.from_l234_features(&l234_features, src_ip);

        assert!(vec.has_l234());
        assert_eq!(vec.src_ip, Some(src_ip));
        assert_eq!(fuser.stats().with_l234, 1);
    }

    #[test]
    fn test_fuse_multiple_sources() {
        let mut fuser = FeatureFuser::default();

        let ml = [1.0f32; 39];
        let l234 = [2.0f32; 88];
        let extra34 = [3.0f32; 16];
        let wireless = [4.0f32; 16];

        let vec = fuser.fuse(
            Some(&ml),
            Some(&l234),
            Some(&extra34),
            Some(&wireless),
            42,
            Some("10.0.0.1".parse().unwrap()),
        );

        assert!(vec.is_some());
        let vec = vec.unwrap();

        assert!(vec.has_ml());
        assert!(vec.has_l234());
        assert!(vec.has_extra34());
        assert!(vec.has_wireless());
        assert_eq!(vec.flow_id, 42);
        assert_eq!(fuser.stats().full_vectors, 1);
    }

    #[test]
    fn test_min_sources() {
        let config = FusionConfig {
            min_sources: 2,
            ..Default::default()
        };
        let mut fuser = FeatureFuser::new(config);

        // Single source should fail
        let ml = [1.0f32; 39];
        let vec = fuser.fuse(Some(&ml), None, None, None, 1, None);
        assert!(vec.is_none());

        // Two sources should succeed
        let l234 = [2.0f32; 88];
        let vec = fuser.fuse(Some(&ml), Some(&l234), None, None, 2, None);
        assert!(vec.is_some());
    }

    #[test]
    fn test_builder() {
        let ml = [1.0f32; 39];
        let l234 = [2.0f32; 88];

        let vec = UnifiedVectorBuilder::new()
            .flow_id(100)
            .src_ip("192.168.1.100".parse().unwrap())
            .ml_features(&ml)
            .l234_features(&l234)
            .build();

        assert_eq!(vec.flow_id, 100);
        assert!(vec.has_ml());
        assert!(vec.has_l234());
        assert!(!vec.has_extra34());
        assert!(!vec.has_wireless());
    }

    #[test]
    fn test_merge() {
        let mut fuser = FeatureFuser::default();

        // Create initial vector with ML features
        let ml = [1.0f32; 39];
        let initial = fuser.from_ml_features(&ml, 1);

        // Merge with L234 features
        let l234 = [2.0f32; 88];
        let merged = fuser.merge(&initial, None, Some(&l234), None, None);

        assert!(merged.has_ml());
        assert!(merged.has_l234());
    }
}
