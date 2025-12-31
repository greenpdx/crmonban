//! Ensemble Voting Strategies
//!
//! Provides different voting strategies for combining model predictions.

use serde::{Deserialize, Serialize};

/// Voting strategy for combining model outputs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VotingStrategy {
    /// Simple average of all scores
    Average,
    /// Weighted average based on model weights
    Weighted,
    /// Maximum score from any model
    Max,
    /// Minimum score from any model
    Min,
    /// Median score
    Median,
    /// Soft voting with probability calibration
    Soft,
    /// Hard voting (majority decision)
    Hard,
}

impl Default for VotingStrategy {
    fn default() -> Self {
        VotingStrategy::Weighted
    }
}

/// A single model's vote
#[derive(Debug, Clone)]
pub struct ModelVote {
    /// Model name
    pub model: String,
    /// Anomaly score (0.0-1.0)
    pub score: f32,
    /// Confidence in the score
    pub confidence: f32,
    /// Weight for this model
    pub weight: f32,
    /// Is trained
    pub is_trained: bool,
}

impl ModelVote {
    /// Create a new vote
    pub fn new(model: impl Into<String>, score: f32, weight: f32) -> Self {
        Self {
            model: model.into(),
            score: score.clamp(0.0, 1.0),
            confidence: 1.0,
            weight,
            is_trained: true,
        }
    }

    /// Set confidence
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Mark as not trained
    pub fn not_trained(mut self) -> Self {
        self.is_trained = false;
        self
    }
}

/// Vote aggregator
#[derive(Debug, Clone)]
pub struct VoteAggregator {
    votes: Vec<ModelVote>,
    strategy: VotingStrategy,
    threshold: f32,
}

impl VoteAggregator {
    /// Create a new aggregator with the given strategy
    pub fn new(strategy: VotingStrategy) -> Self {
        Self {
            votes: Vec::new(),
            strategy,
            threshold: 0.5,
        }
    }

    /// Set anomaly threshold
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Add a vote
    pub fn add_vote(&mut self, vote: ModelVote) {
        self.votes.push(vote);
    }

    /// Clear all votes
    pub fn clear(&mut self) {
        self.votes.clear();
    }

    /// Get trained votes only
    fn trained_votes(&self) -> Vec<&ModelVote> {
        self.votes.iter().filter(|v| v.is_trained).collect()
    }

    /// Compute aggregate score
    pub fn aggregate(&self) -> f32 {
        let votes = self.trained_votes();
        if votes.is_empty() {
            return 0.0;
        }

        match self.strategy {
            VotingStrategy::Average => {
                votes.iter().map(|v| v.score).sum::<f32>() / votes.len() as f32
            }
            VotingStrategy::Weighted => {
                let total_weight: f32 = votes.iter().map(|v| v.weight).sum();
                if total_weight == 0.0 {
                    return 0.0;
                }
                votes.iter().map(|v| v.score * v.weight).sum::<f32>() / total_weight
            }
            VotingStrategy::Max => {
                votes.iter().map(|v| v.score).fold(0.0f32, f32::max)
            }
            VotingStrategy::Min => {
                votes.iter().map(|v| v.score).fold(1.0f32, f32::min)
            }
            VotingStrategy::Median => {
                let mut scores: Vec<f32> = votes.iter().map(|v| v.score).collect();
                scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
                if scores.len() % 2 == 0 {
                    (scores[scores.len() / 2 - 1] + scores[scores.len() / 2]) / 2.0
                } else {
                    scores[scores.len() / 2]
                }
            }
            VotingStrategy::Soft => {
                // Soft voting: weighted average with confidence
                let total_weight: f32 = votes.iter().map(|v| v.weight * v.confidence).sum();
                if total_weight == 0.0 {
                    return 0.0;
                }
                votes.iter()
                    .map(|v| v.score * v.weight * v.confidence)
                    .sum::<f32>() / total_weight
            }
            VotingStrategy::Hard => {
                // Hard voting: count predictions above threshold
                let positives = votes.iter().filter(|v| v.score > self.threshold).count();
                if positives > votes.len() / 2 {
                    1.0
                } else {
                    0.0
                }
            }
        }
    }

    /// Compute aggregate confidence
    pub fn aggregate_confidence(&self) -> f32 {
        let votes = self.trained_votes();
        if votes.is_empty() {
            return 0.0;
        }

        // Confidence is the weighted average of individual confidences
        let total_weight: f32 = votes.iter().map(|v| v.weight).sum();
        if total_weight == 0.0 {
            return 0.0;
        }

        votes.iter()
            .map(|v| v.confidence * v.weight)
            .sum::<f32>() / total_weight
    }

    /// Get individual votes
    pub fn votes(&self) -> &[ModelVote] {
        &self.votes
    }

    /// Check if aggregated score indicates anomaly
    pub fn is_anomaly(&self) -> bool {
        self.aggregate() > self.threshold
    }

    /// Get vote breakdown as string
    pub fn breakdown(&self) -> String {
        let mut lines: Vec<String> = self.votes
            .iter()
            .map(|v| format!(
                "{}: score={:.3} weight={:.2} conf={:.2} trained={}",
                v.model, v.score, v.weight, v.confidence, v.is_trained
            ))
            .collect();

        lines.push(format!(
            "Aggregate ({:?}): score={:.3} conf={:.3}",
            self.strategy,
            self.aggregate(),
            self.aggregate_confidence()
        ));

        lines.join("\n")
    }
}

impl Default for VoteAggregator {
    fn default() -> Self {
        Self::new(VotingStrategy::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_average_voting() {
        let mut agg = VoteAggregator::new(VotingStrategy::Average);

        agg.add_vote(ModelVote::new("model1", 0.3, 1.0));
        agg.add_vote(ModelVote::new("model2", 0.5, 1.0));
        agg.add_vote(ModelVote::new("model3", 0.7, 1.0));

        let score = agg.aggregate();
        assert!((score - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_weighted_voting() {
        let mut agg = VoteAggregator::new(VotingStrategy::Weighted);

        // Model with weight 2 should count more
        agg.add_vote(ModelVote::new("low", 0.2, 1.0));
        agg.add_vote(ModelVote::new("high", 0.8, 2.0));

        let score = agg.aggregate();
        // Expected: (0.2*1 + 0.8*2) / 3 = 0.6
        assert!((score - 0.6).abs() < 0.01);
    }

    #[test]
    fn test_max_voting() {
        let mut agg = VoteAggregator::new(VotingStrategy::Max);

        agg.add_vote(ModelVote::new("model1", 0.3, 1.0));
        agg.add_vote(ModelVote::new("model2", 0.9, 1.0));
        agg.add_vote(ModelVote::new("model3", 0.5, 1.0));

        assert!((agg.aggregate() - 0.9).abs() < 0.01);
    }

    #[test]
    fn test_hard_voting() {
        let mut agg = VoteAggregator::new(VotingStrategy::Hard)
            .with_threshold(0.5);

        // 2 out of 3 say anomaly
        agg.add_vote(ModelVote::new("model1", 0.6, 1.0));
        agg.add_vote(ModelVote::new("model2", 0.7, 1.0));
        agg.add_vote(ModelVote::new("model3", 0.3, 1.0));

        assert!((agg.aggregate() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_untrained_excluded() {
        let mut agg = VoteAggregator::new(VotingStrategy::Average);

        agg.add_vote(ModelVote::new("trained", 0.8, 1.0));
        agg.add_vote(ModelVote::new("untrained", 0.1, 1.0).not_trained());

        // Only trained vote should count
        assert!((agg.aggregate() - 0.8).abs() < 0.01);
    }

    #[test]
    fn test_confidence() {
        let mut agg = VoteAggregator::new(VotingStrategy::Soft);

        agg.add_vote(ModelVote::new("low_conf", 0.5, 1.0).with_confidence(0.2));
        agg.add_vote(ModelVote::new("high_conf", 0.8, 1.0).with_confidence(0.9));

        // High confidence vote should dominate
        let score = agg.aggregate();
        assert!(score > 0.6);
    }
}
