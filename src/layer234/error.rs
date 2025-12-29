use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetVecError {
    #[error("packet parse error: {0}")]
    ParseError(String),

    #[error("no IP layer found in packet")]
    NoIpLayer,

    #[error("vector store error: {0}")]
    StoreError(String),

    #[error("invalid vector dimension: expected {expected}, got {got}")]
    InvalidDimension { expected: usize, got: usize },

    #[error("detector not initialized")]
    NotInitialized,

    #[error("config error: {0}")]
    ConfigError(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("signature not found: {0}")]
    SignatureNotFound(String),
}

pub type Result<T> = std::result::Result<T, NetVecError>;
