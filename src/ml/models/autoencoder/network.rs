//! Autoencoder Network Architecture
//!
//! Implements a symmetric autoencoder for anomaly detection using reconstruction error.
//! Architecture: 159 -> 80 -> 32 -> 16 (latent) -> 32 -> 80 -> 159

#[cfg(feature = "ml-advanced")]
use burn::{
    module::Module,
    nn::{
        self,
        loss::MseLoss,
        Linear, LinearConfig,
        Relu,
    },
    tensor::{backend::Backend, Tensor},
    train::metric::LossMetric,
};

use serde::{Deserialize, Serialize};

/// Autoencoder configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoencoderConfig {
    /// Input dimension (unified feature vector size)
    pub input_dim: usize,
    /// Hidden layer dimensions (encoder path)
    pub hidden_dims: Vec<usize>,
    /// Latent space dimension
    pub latent_dim: usize,
    /// Dropout rate (0.0-1.0)
    pub dropout: f32,
    /// Learning rate
    pub learning_rate: f64,
    /// Batch size for training
    pub batch_size: usize,
    /// Number of training epochs
    pub epochs: usize,
}

impl Default for AutoencoderConfig {
    fn default() -> Self {
        Self {
            input_dim: 159,
            hidden_dims: vec![80, 32],
            latent_dim: 16,
            dropout: 0.1,
            learning_rate: 0.001,
            batch_size: 64,
            epochs: 100,
        }
    }
}

/// Autoencoder network (feature-gated for burn dependency)
#[cfg(feature = "ml-advanced")]
#[derive(Module, Debug)]
pub struct Autoencoder<B: Backend> {
    // Encoder layers
    encoder_fc1: Linear<B>,
    encoder_fc2: Linear<B>,
    encoder_fc3: Linear<B>,
    // Decoder layers
    decoder_fc1: Linear<B>,
    decoder_fc2: Linear<B>,
    decoder_fc3: Linear<B>,
    // Activation
    activation: Relu,
}

#[cfg(feature = "ml-advanced")]
impl<B: Backend> Autoencoder<B> {
    /// Create a new autoencoder with the given configuration
    pub fn new(config: &AutoencoderConfig, device: &B::Device) -> Self {
        let input_dim = config.input_dim;
        let h1 = config.hidden_dims.first().copied().unwrap_or(80);
        let h2 = config.hidden_dims.get(1).copied().unwrap_or(32);
        let latent = config.latent_dim;

        Self {
            // Encoder: input -> h1 -> h2 -> latent
            encoder_fc1: LinearConfig::new(input_dim, h1).init(device),
            encoder_fc2: LinearConfig::new(h1, h2).init(device),
            encoder_fc3: LinearConfig::new(h2, latent).init(device),
            // Decoder: latent -> h2 -> h1 -> input
            decoder_fc1: LinearConfig::new(latent, h2).init(device),
            decoder_fc2: LinearConfig::new(h2, h1).init(device),
            decoder_fc3: LinearConfig::new(h1, input_dim).init(device),
            activation: Relu::new(),
        }
    }

    /// Encode input to latent representation
    pub fn encode(&self, x: Tensor<B, 2>) -> Tensor<B, 2> {
        let x = self.encoder_fc1.forward(x);
        let x = self.activation.forward(x);
        let x = self.encoder_fc2.forward(x);
        let x = self.activation.forward(x);
        self.encoder_fc3.forward(x)
    }

    /// Decode latent representation to reconstruction
    pub fn decode(&self, z: Tensor<B, 2>) -> Tensor<B, 2> {
        let x = self.decoder_fc1.forward(z);
        let x = self.activation.forward(x);
        let x = self.decoder_fc2.forward(x);
        let x = self.activation.forward(x);
        self.decoder_fc3.forward(x)
    }

    /// Forward pass: encode then decode
    pub fn forward(&self, x: Tensor<B, 2>) -> Tensor<B, 2> {
        let z = self.encode(x);
        self.decode(z)
    }

    /// Compute reconstruction error (MSE)
    pub fn reconstruction_error(&self, x: Tensor<B, 2>) -> Tensor<B, 1> {
        let reconstructed = self.forward(x.clone());
        let diff = x - reconstructed;
        let squared = diff.clone() * diff;
        squared.mean_dim(1)
    }
}

/// Stub implementation when ml-advanced feature is not enabled
#[cfg(not(feature = "ml-advanced"))]
#[allow(dead_code)]
pub struct Autoencoder {
    config: AutoencoderConfig,
}

#[cfg(not(feature = "ml-advanced"))]
impl Autoencoder {
    pub fn new(config: &AutoencoderConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    pub fn reconstruction_error(&self, _features: &[f32]) -> f32 {
        0.0 // Stub - returns no anomaly when feature not enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autoencoder_config_default() {
        let config = AutoencoderConfig::default();
        assert_eq!(config.input_dim, 159);
        assert_eq!(config.latent_dim, 16);
        assert_eq!(config.hidden_dims, vec![80, 32]);
    }
}
