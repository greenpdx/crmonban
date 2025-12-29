use super::error::{NetVecError, Result};
use super::types::{FeatureVector, VECTOR_DIM};
use crvecdb::{DistanceMetric, Index};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::RwLock;

#[derive(Clone, Debug)]
pub struct SearchResult {
    pub id: u64,
    pub distance: f32,
    pub label: Option<String>,
}

pub struct VectorStore {
    index: Index,
    labels: std::collections::HashMap<u64, String>,
    next_id: u64,
}

impl VectorStore {
    pub fn new(capacity: usize) -> Result<Self> {
        let index = Index::builder(VECTOR_DIM)
            .metric(DistanceMetric::Cosine)
            .m(16)
            .ef_construction(200)
            .capacity(capacity)
            .build()
            .map_err(|e| NetVecError::StoreError(e.to_string()))?;

        Ok(Self {
            index,
            labels: std::collections::HashMap::new(),
            next_id: 0,
        })
    }

    pub fn with_persistence<P: AsRef<Path>>(path: P, capacity: usize) -> Result<Self> {
        let index = Index::builder(VECTOR_DIM)
            .metric(DistanceMetric::Cosine)
            .m(16)
            .ef_construction(200)
            .capacity(capacity)
            .build_mmap(path)
            .map_err(|e| NetVecError::StoreError(e.to_string()))?;

        Ok(Self {
            index,
            labels: std::collections::HashMap::new(),
            next_id: 0,
        })
    }

    pub fn insert(&mut self, vector: &FeatureVector, label: Option<String>) -> Result<u64> {
        let id = self.next_id;
        self.next_id += 1;

        self.index
            .insert(id, vector)
            .map_err(|e| NetVecError::StoreError(e.to_string()))?;

        if let Some(l) = label {
            self.labels.insert(id, l);
        }

        Ok(id)
    }

    pub fn insert_with_id(
        &mut self,
        id: u64,
        vector: &FeatureVector,
        label: Option<String>,
    ) -> Result<()> {
        self.index
            .insert(id, vector)
            .map_err(|e| NetVecError::StoreError(e.to_string()))?;

        if let Some(l) = label {
            self.labels.insert(id, l);
        }

        if id >= self.next_id {
            self.next_id = id + 1;
        }

        Ok(())
    }

    pub fn search(&self, vector: &FeatureVector, k: usize) -> Result<Vec<SearchResult>> {
        let results = self
            .index
            .search(vector, k)
            .map_err(|e| NetVecError::StoreError(e.to_string()))?;

        Ok(results
            .into_iter()
            .map(|r| SearchResult {
                id: r.id,
                distance: r.distance,
                label: self.labels.get(&r.id).cloned(),
            })
            .collect())
    }

    pub fn nearest_distance(&self, vector: &FeatureVector) -> Result<Option<f32>> {
        let results = self.search(vector, 1)?;
        Ok(results.first().map(|r| r.distance))
    }

    pub fn flush(&self) -> Result<()> {
        self.index
            .flush()
            .map_err(|e| NetVecError::StoreError(e.to_string()))
    }

    pub fn len(&self) -> usize {
        self.next_id as usize
    }

    pub fn is_empty(&self) -> bool {
        self.next_id == 0
    }
}

pub struct SignatureStore {
    store: VectorStore,
    /// Set of disabled signature IDs (not removed from index, just inactive)
    disabled: RwLock<HashSet<u64>>,
    /// Map signature name -> ID for lookup
    name_to_id: RwLock<HashMap<String, u64>>,
}

impl SignatureStore {
    pub fn new(capacity: usize) -> Result<Self> {
        Ok(Self {
            store: VectorStore::new(capacity)?,
            disabled: RwLock::new(HashSet::new()),
            name_to_id: RwLock::new(HashMap::new()),
        })
    }

    pub fn with_persistence<P: AsRef<Path>>(path: P, capacity: usize) -> Result<Self> {
        Ok(Self {
            store: VectorStore::with_persistence(path, capacity)?,
            disabled: RwLock::new(HashSet::new()),
            name_to_id: RwLock::new(HashMap::new()),
        })
    }

    pub fn add_signature(&mut self, vector: &FeatureVector, name: String) -> Result<u64> {
        let id = self.store.insert(vector, Some(name.clone()))?;

        // Track name -> ID mapping
        if let Ok(mut name_map) = self.name_to_id.write() {
            name_map.insert(name, id);
        }

        Ok(id)
    }

    /// Disable a signature by name (keeps in index, marks inactive)
    pub fn disable_signature(&self, name: &str) -> Result<()> {
        let id = {
            let name_map = self.name_to_id.read()
                .map_err(|_| NetVecError::StoreError("RwLock poisoned".to_string()))?;
            name_map.get(name).copied()
        };

        match id {
            Some(id) => {
                let mut disabled = self.disabled.write()
                    .map_err(|_| NetVecError::StoreError("RwLock poisoned".to_string()))?;
                disabled.insert(id);
                Ok(())
            }
            None => Err(NetVecError::SignatureNotFound(name.to_string())),
        }
    }

    /// Re-enable a previously disabled signature
    pub fn enable_signature(&self, name: &str) -> Result<()> {
        let id = {
            let name_map = self.name_to_id.read()
                .map_err(|_| NetVecError::StoreError("RwLock poisoned".to_string()))?;
            name_map.get(name).copied()
        };

        match id {
            Some(id) => {
                let mut disabled = self.disabled.write()
                    .map_err(|_| NetVecError::StoreError("RwLock poisoned".to_string()))?;
                disabled.remove(&id);
                Ok(())
            }
            None => Err(NetVecError::SignatureNotFound(name.to_string())),
        }
    }

    /// Check if a signature is disabled
    pub fn is_disabled(&self, name: &str) -> Result<bool> {
        let id = {
            let name_map = self.name_to_id.read()
                .map_err(|_| NetVecError::StoreError("RwLock poisoned".to_string()))?;
            name_map.get(name).copied()
        };

        match id {
            Some(id) => {
                let disabled = self.disabled.read()
                    .map_err(|_| NetVecError::StoreError("RwLock poisoned".to_string()))?;
                Ok(disabled.contains(&id))
            }
            None => Err(NetVecError::SignatureNotFound(name.to_string())),
        }
    }

    /// Get list of all signature names
    pub fn signature_names(&self) -> Vec<String> {
        self.name_to_id.read()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Get count of active (non-disabled) signatures
    pub fn active_count(&self) -> usize {
        let total = self.store.len();
        let disabled_count = self.disabled.read()
            .map(|d| d.len())
            .unwrap_or(0);
        total.saturating_sub(disabled_count)
    }

    pub fn match_signature(
        &self,
        vector: &FeatureVector,
        threshold: f32,
    ) -> Result<Option<SearchResult>> {
        // Search for multiple results in case top matches are disabled
        let results = self.store.search(vector, 10)?;

        let disabled = self.disabled.read()
            .map_err(|_| NetVecError::StoreError("RwLock poisoned".to_string()))?;

        for result in results {
            // Skip disabled signatures
            if disabled.contains(&result.id) {
                continue;
            }

            // For cosine similarity, lower distance = more similar
            // threshold of 0.15 means 85% similarity
            if result.distance <= (1.0 - threshold) {
                return Ok(Some(result));
            }
        }

        Ok(None)
    }

    pub fn search(&self, vector: &FeatureVector, k: usize) -> Result<Vec<SearchResult>> {
        self.store.search(vector, k)
    }

    /// Search excluding disabled signatures
    pub fn search_active(&self, vector: &FeatureVector, k: usize) -> Result<Vec<SearchResult>> {
        // Search for more than k to account for disabled ones
        let results = self.store.search(vector, k * 2 + 10)?;

        let disabled = self.disabled.read()
            .map_err(|_| NetVecError::StoreError("RwLock poisoned".to_string()))?;

        Ok(results
            .into_iter()
            .filter(|r| !disabled.contains(&r.id))
            .take(k)
            .collect())
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    pub fn flush(&self) -> Result<()> {
        self.store.flush()
    }
}

pub struct BaselineStore {
    store: VectorStore,
}

impl BaselineStore {
    pub fn new(capacity: usize) -> Result<Self> {
        Ok(Self {
            store: VectorStore::new(capacity)?,
        })
    }

    pub fn with_persistence<P: AsRef<Path>>(path: P, capacity: usize) -> Result<Self> {
        Ok(Self {
            store: VectorStore::with_persistence(path, capacity)?,
        })
    }

    pub fn add_baseline(&mut self, vector: &FeatureVector) -> Result<u64> {
        self.store.insert(vector, None)
    }

    pub fn is_anomaly(&self, vector: &FeatureVector, threshold: f32) -> Result<(bool, f32)> {
        if self.store.is_empty() {
            return Ok((false, 0.0));
        }

        let distance = self
            .store
            .nearest_distance(vector)?
            .unwrap_or(1.0);

        // Higher distance from baseline = more anomalous
        Ok((distance > threshold, distance))
    }

    pub fn train(&mut self, vectors: &[FeatureVector]) -> Result<()> {
        for vector in vectors {
            self.add_baseline(vector)?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    pub fn flush(&self) -> Result<()> {
        self.store.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_store_basic() {
        let mut store = VectorStore::new(100).unwrap();
        let vec = [0.5f32; VECTOR_DIM];

        let id = store.insert(&vec, Some("test".to_string())).unwrap();
        assert_eq!(id, 0);

        let results = store.search(&vec, 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, 0);
        assert!(results[0].distance < 0.01);
    }

    #[test]
    fn test_signature_store() {
        let mut store = SignatureStore::new(100).unwrap();
        let vec = [0.5f32; VECTOR_DIM];

        store.add_signature(&vec, "syn_scan".to_string()).unwrap();

        let result = store.match_signature(&vec, 0.9).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().label.unwrap(), "syn_scan");
    }

    #[test]
    fn test_baseline_store() {
        let mut store = BaselineStore::new(100).unwrap();

        // Add baseline vector - represents "normal" traffic pattern
        let mut baseline = [0.0f32; VECTOR_DIM];
        baseline[0] = 0.1;  // Low port entropy
        baseline[12] = 0.2; // Low SYN ratio
        store.add_baseline(&baseline).unwrap();

        // Similar vector should not be anomaly
        let mut similar = [0.0f32; VECTOR_DIM];
        similar[0] = 0.15;  // Slightly higher port entropy
        similar[12] = 0.25; // Slightly higher SYN ratio
        let (is_anomaly, distance) = store.is_anomaly(&similar, 0.5).unwrap();
        assert!(!is_anomaly, "Similar vector should not be anomaly, distance: {}", distance);

        // Very different vector - represents scan pattern (high SYN, many ports)
        let mut different = [0.0f32; VECTOR_DIM];
        different[0] = 0.9;  // High port entropy
        different[1] = 0.8;  // Many unique ports
        different[12] = 0.95; // Very high SYN ratio
        different[17] = 0.9; // High half-open ratio
        let (is_anomaly, distance) = store.is_anomaly(&different, 0.2).unwrap();
        assert!(is_anomaly, "Different vector should be anomaly, distance: {}", distance);
    }

    #[test]
    fn test_signature_disable_enable() {
        let mut store = SignatureStore::new(100).unwrap();
        let vec = [0.5f32; VECTOR_DIM];

        // Add signature
        store.add_signature(&vec, "test_sig".to_string()).unwrap();
        assert_eq!(store.active_count(), 1);
        assert!(!store.is_disabled("test_sig").unwrap());

        // Should match before disabling
        let result = store.match_signature(&vec, 0.9).unwrap();
        assert!(result.is_some());

        // Disable signature
        store.disable_signature("test_sig").unwrap();
        assert!(store.is_disabled("test_sig").unwrap());
        assert_eq!(store.active_count(), 0);
        assert_eq!(store.len(), 1); // Still in store

        // Should not match after disabling
        let result = store.match_signature(&vec, 0.9).unwrap();
        assert!(result.is_none());

        // Re-enable signature
        store.enable_signature("test_sig").unwrap();
        assert!(!store.is_disabled("test_sig").unwrap());
        assert_eq!(store.active_count(), 1);

        // Should match again after enabling
        let result = store.match_signature(&vec, 0.9).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn test_signature_names() {
        let mut store = SignatureStore::new(100).unwrap();
        let vec = [0.5f32; VECTOR_DIM];

        store.add_signature(&vec, "sig_a".to_string()).unwrap();
        store.add_signature(&vec, "sig_b".to_string()).unwrap();
        store.add_signature(&vec, "sig_c".to_string()).unwrap();

        let names = store.signature_names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"sig_a".to_string()));
        assert!(names.contains(&"sig_b".to_string()));
        assert!(names.contains(&"sig_c".to_string()));
    }

    #[test]
    fn test_search_active() {
        let mut store = SignatureStore::new(100).unwrap();

        // Add three distinct signatures
        let mut vec1 = [0.0f32; VECTOR_DIM];
        vec1[0] = 1.0;
        let mut vec2 = [0.0f32; VECTOR_DIM];
        vec2[1] = 1.0;
        let mut vec3 = [0.0f32; VECTOR_DIM];
        vec3[2] = 1.0;

        store.add_signature(&vec1, "sig_1".to_string()).unwrap();
        store.add_signature(&vec2, "sig_2".to_string()).unwrap();
        store.add_signature(&vec3, "sig_3".to_string()).unwrap();

        // All three should appear in search
        let results = store.search_active(&vec1, 10).unwrap();
        assert_eq!(results.len(), 3);

        // Disable sig_2
        store.disable_signature("sig_2").unwrap();

        // Only 2 should appear in search_active
        let results = store.search_active(&vec1, 10).unwrap();
        assert_eq!(results.len(), 2);

        // Regular search still returns all 3
        let results = store.search(&vec1, 10).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_signature_not_found_error() {
        let store = SignatureStore::new(100).unwrap();

        // Try to disable non-existent signature
        let result = store.disable_signature("nonexistent");
        assert!(result.is_err());

        // Try to enable non-existent signature
        let result = store.enable_signature("nonexistent");
        assert!(result.is_err());

        // Try to check disabled status of non-existent signature
        let result = store.is_disabled("nonexistent");
        assert!(result.is_err());
    }
}
