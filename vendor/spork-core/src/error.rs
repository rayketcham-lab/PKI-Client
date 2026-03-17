//! Error types for spork-core

use thiserror::Error;

/// Result type alias for spork-core
pub type Result<T> = std::result::Result<T, Error>;

/// Core error types
#[derive(Debug, Error)]
pub enum Error {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Random number generation error: {0}")]
    RandomError(String),

    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("Decoding error: {0}")]
    Decoding(String),

    #[error("Invalid CSR: {0}")]
    InvalidCsr(String),

    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    #[error("CA not initialized")]
    CaNotInitialized,

    #[error("CA already initialized")]
    CaAlreadyInitialized,

    #[error("Certificate expired")]
    CertificateExpired,

    #[error("Certificate not yet valid")]
    CertificateNotYetValid,

    #[error("Certificate revoked")]
    CertificateRevoked,

    #[error("Algorithm mismatch: expected {expected}, got {got}")]
    AlgorithmMismatch { expected: String, got: String },

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Serial number exhausted")]
    SerialExhausted,

    #[error("Extension error: {0}")]
    Extension(String),

    #[error("Name constraint violation: {0}")]
    NameConstraint(String),

    #[error("Path length exceeded")]
    PathLengthExceeded,

    #[error("FIPS 140-3 violation: {0}")]
    FipsViolation(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DER error: {0}")]
    Der(String),

    /// Network error during AIA chasing (only present when aia-chasing feature is enabled)
    #[cfg(feature = "aia-chasing")]
    #[error("Network error: {0}")]
    Network(String),
}

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Error::Der(e.to_string())
    }
}
