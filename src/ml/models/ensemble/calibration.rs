//! Confidence Calibration
//!
//! Provides methods to calibrate model predictions to produce well-calibrated
//! probability estimates. Implements Platt scaling and isotonic regression.

use serde::{Deserialize, Serialize};

/// Calibration method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CalibrationMethod {
    /// Platt scaling (sigmoid calibration)
    Platt,
    /// Isotonic regression (non-parametric)
    Isotonic,
    /// Temperature scaling (simple division)
    Temperature,
    /// No calibration
    None,
}

impl Default for CalibrationMethod {
    fn default() -> Self {
        CalibrationMethod::Platt
    }
}

/// Platt scaling parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlattParams {
    /// Slope parameter A
    pub a: f32,
    /// Intercept parameter B
    pub b: f32,
}

impl Default for PlattParams {
    fn default() -> Self {
        Self { a: 1.0, b: 0.0 }
    }
}

/// Isotonic regression calibration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsotonicParams {
    /// Sorted calibration points (score, probability)
    points: Vec<(f32, f32)>,
}

impl Default for IsotonicParams {
    fn default() -> Self {
        Self { points: Vec::new() }
    }
}

/// Calibrator for model scores
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Calibrator {
    method: CalibrationMethod,
    platt: PlattParams,
    isotonic: IsotonicParams,
    temperature: f32,
    fitted: bool,
}

impl Calibrator {
    /// Create a new calibrator with the specified method
    pub fn new(method: CalibrationMethod) -> Self {
        Self {
            method,
            platt: PlattParams::default(),
            isotonic: IsotonicParams::default(),
            temperature: 1.0,
            fitted: false,
        }
    }

    /// Fit calibrator to validation data
    /// scores: raw model scores
    /// labels: true labels (0.0 or 1.0)
    pub fn fit(&mut self, scores: &[f32], labels: &[f32]) {
        if scores.is_empty() || scores.len() != labels.len() {
            return;
        }

        match self.method {
            CalibrationMethod::Platt => self.fit_platt(scores, labels),
            CalibrationMethod::Isotonic => self.fit_isotonic(scores, labels),
            CalibrationMethod::Temperature => self.fit_temperature(scores, labels),
            CalibrationMethod::None => {}
        }

        self.fitted = true;
    }

    /// Fit Platt scaling using gradient descent
    fn fit_platt(&mut self, scores: &[f32], labels: &[f32]) {
        // Simple gradient descent for logistic regression
        // P(y=1|s) = 1 / (1 + exp(A*s + B))
        let mut a = 0.0f32;
        let mut b = 0.0f32;

        let learning_rate = 0.01;
        let iterations = 1000;

        for _ in 0..iterations {
            let mut grad_a = 0.0f32;
            let mut grad_b = 0.0f32;

            for (&s, &y) in scores.iter().zip(labels.iter()) {
                let prob = sigmoid(a * s + b);
                let error = prob - y;
                grad_a += error * s;
                grad_b += error;
            }

            grad_a /= scores.len() as f32;
            grad_b /= scores.len() as f32;

            a -= learning_rate * grad_a;
            b -= learning_rate * grad_b;
        }

        self.platt = PlattParams { a, b };
    }

    /// Fit isotonic regression
    fn fit_isotonic(&mut self, scores: &[f32], labels: &[f32]) {
        // Sort by score
        let mut pairs: Vec<(f32, f32)> = scores
            .iter()
            .zip(labels.iter())
            .map(|(&s, &l)| (s, l))
            .collect();
        pairs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));

        // Pool Adjacent Violators Algorithm (PAVA)
        let mut calibrated = pairs.clone();
        let mut changed = true;

        while changed {
            changed = false;
            let mut i = 0;
            while i < calibrated.len() - 1 {
                if calibrated[i].1 > calibrated[i + 1].1 {
                    // Violating monotonicity - pool together
                    let avg = (calibrated[i].1 + calibrated[i + 1].1) / 2.0;
                    calibrated[i].1 = avg;
                    calibrated[i + 1].1 = avg;
                    changed = true;
                }
                i += 1;
            }
        }

        // Deduplicate consecutive points with same probability
        let mut points = Vec::new();
        for (score, prob) in calibrated {
            if points.is_empty() || (points.last().unwrap() as &(f32, f32)).1 != prob {
                points.push((score, prob));
            }
        }

        self.isotonic = IsotonicParams { points };
    }

    /// Fit temperature scaling
    fn fit_temperature(&mut self, scores: &[f32], labels: &[f32]) {
        // Find temperature that minimizes negative log likelihood
        let mut best_temp = 1.0f32;
        let mut best_nll = f32::MAX;

        for t in (1..50).map(|i| i as f32 * 0.1) {
            let nll: f32 = scores
                .iter()
                .zip(labels.iter())
                .map(|(&s, &y)| {
                    let p = sigmoid(s / t);
                    if y > 0.5 {
                        -p.ln()
                    } else {
                        -(1.0 - p).ln()
                    }
                })
                .sum();

            if nll < best_nll {
                best_nll = nll;
                best_temp = t;
            }
        }

        self.temperature = best_temp;
    }

    /// Calibrate a score
    pub fn calibrate(&self, score: f32) -> f32 {
        if !self.fitted {
            return score;
        }

        match self.method {
            CalibrationMethod::Platt => {
                sigmoid(self.platt.a * score + self.platt.b)
            }
            CalibrationMethod::Isotonic => {
                self.interpolate_isotonic(score)
            }
            CalibrationMethod::Temperature => {
                sigmoid(score / self.temperature)
            }
            CalibrationMethod::None => score,
        }
    }

    /// Interpolate isotonic calibration
    fn interpolate_isotonic(&self, score: f32) -> f32 {
        let points = &self.isotonic.points;
        if points.is_empty() {
            return score;
        }

        // Find surrounding points
        let mut lower = 0;
        let mut upper = points.len() - 1;

        while lower < upper {
            let mid = (lower + upper) / 2;
            if points[mid].0 < score {
                lower = mid + 1;
            } else {
                upper = mid;
            }
        }

        // Interpolate
        if lower == 0 {
            return points[0].1;
        }
        if lower >= points.len() {
            return points.last().unwrap().1;
        }

        let (s1, p1) = points[lower - 1];
        let (s2, p2) = points[lower];

        if (s2 - s1).abs() < 1e-6 {
            return p1;
        }

        // Linear interpolation
        p1 + (score - s1) * (p2 - p1) / (s2 - s1)
    }

    /// Check if fitted
    pub fn is_fitted(&self) -> bool {
        self.fitted
    }

    /// Get method
    pub fn method(&self) -> CalibrationMethod {
        self.method
    }

    /// Get reliability diagram data (for visualization)
    /// Returns (predicted_probs, actual_frequencies, counts) for binned data
    pub fn reliability_diagram(&self, scores: &[f32], labels: &[f32], n_bins: usize) -> ReliabilityData {
        let calibrated: Vec<f32> = scores.iter().map(|&s| self.calibrate(s)).collect();

        let mut bins = vec![(0.0f32, 0.0f32, 0usize); n_bins];

        for (&prob, &label) in calibrated.iter().zip(labels.iter()) {
            let bin = ((prob * n_bins as f32) as usize).min(n_bins - 1);
            bins[bin].0 += prob;
            bins[bin].1 += label;
            bins[bin].2 += 1;
        }

        let predicted: Vec<f32> = bins
            .iter()
            .map(|(sum, _, count)| if *count > 0 { sum / *count as f32 } else { 0.0 })
            .collect();

        let actual: Vec<f32> = bins
            .iter()
            .map(|(_, sum, count)| if *count > 0 { sum / *count as f32 } else { 0.0 })
            .collect();

        let counts: Vec<usize> = bins.iter().map(|(_, _, c)| *c).collect();

        ReliabilityData {
            predicted,
            actual,
            counts,
        }
    }

    /// Compute Expected Calibration Error (ECE)
    pub fn expected_calibration_error(&self, scores: &[f32], labels: &[f32], n_bins: usize) -> f32 {
        let diagram = self.reliability_diagram(scores, labels, n_bins);
        let total: usize = diagram.counts.iter().sum();

        if total == 0 {
            return 0.0;
        }

        diagram
            .predicted
            .iter()
            .zip(diagram.actual.iter())
            .zip(diagram.counts.iter())
            .map(|((p, a), &c)| (p - a).abs() * c as f32)
            .sum::<f32>() / total as f32
    }
}

impl Default for Calibrator {
    fn default() -> Self {
        Self::new(CalibrationMethod::default())
    }
}

/// Reliability diagram data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReliabilityData {
    /// Mean predicted probability per bin
    pub predicted: Vec<f32>,
    /// Actual frequency of positives per bin
    pub actual: Vec<f32>,
    /// Number of samples per bin
    pub counts: Vec<usize>,
}

/// Sigmoid function
fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platt_calibration() {
        let mut calibrator = Calibrator::new(CalibrationMethod::Platt);

        // Synthetic data: higher scores should map to higher probabilities
        let scores: Vec<f32> = (0..100).map(|i| i as f32 / 100.0).collect();
        let labels: Vec<f32> = scores.iter().map(|&s| if s > 0.5 { 1.0 } else { 0.0 }).collect();

        calibrator.fit(&scores, &labels);
        assert!(calibrator.is_fitted());

        // High score should give high probability
        let high = calibrator.calibrate(0.9);
        let low = calibrator.calibrate(0.1);
        assert!(high > low);
    }

    #[test]
    fn test_isotonic_calibration() {
        let mut calibrator = Calibrator::new(CalibrationMethod::Isotonic);

        let scores: Vec<f32> = vec![0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9];
        let labels: Vec<f32> = vec![0.0, 0.0, 0.0, 0.5, 0.5, 0.5, 1.0, 1.0, 1.0];

        calibrator.fit(&scores, &labels);
        assert!(calibrator.is_fitted());

        // Should be monotonically increasing
        let c1 = calibrator.calibrate(0.2);
        let c2 = calibrator.calibrate(0.5);
        let c3 = calibrator.calibrate(0.8);
        assert!(c1 <= c2);
        assert!(c2 <= c3);
    }

    #[test]
    fn test_temperature_scaling() {
        let mut calibrator = Calibrator::new(CalibrationMethod::Temperature);

        let scores: Vec<f32> = (0..100).map(|i| i as f32 / 100.0).collect();
        let labels: Vec<f32> = scores.iter().map(|&s| if s > 0.5 { 1.0 } else { 0.0 }).collect();

        calibrator.fit(&scores, &labels);
        assert!(calibrator.is_fitted());
    }

    #[test]
    fn test_reliability_diagram() {
        let calibrator = Calibrator::new(CalibrationMethod::None);

        let scores: Vec<f32> = (0..100).map(|i| i as f32 / 100.0).collect();
        let labels: Vec<f32> = scores.iter().map(|&s| if s > 0.5 { 1.0 } else { 0.0 }).collect();

        let diagram = calibrator.reliability_diagram(&scores, &labels, 10);
        assert_eq!(diagram.predicted.len(), 10);
        assert_eq!(diagram.actual.len(), 10);
    }

    #[test]
    fn test_ece() {
        let calibrator = Calibrator::new(CalibrationMethod::None);

        // Perfectly calibrated
        let scores: Vec<f32> = (0..100).map(|i| i as f32 / 100.0).collect();
        let labels: Vec<f32> = scores.iter().map(|&s| if s > 0.5 { 1.0 } else { 0.0 }).collect();

        let ece = calibrator.expected_calibration_error(&scores, &labels, 10);
        // Should be relatively low for this synthetic data
        assert!(ece < 0.5);
    }
}
