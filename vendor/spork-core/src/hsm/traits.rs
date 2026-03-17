//! HSM trait definitions

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroizing;

/// Key store errors
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum KeyStoreError {
    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Key already exists
    #[error("Key already exists: {0}")]
    KeyExists(String),

    /// Invalid key specification
    #[error("Invalid key spec: {0}")]
    InvalidKeySpec(String),

    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// HSM connection error
    #[error("HSM connection error: {0}")]
    ConnectionError(String),

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Operation not supported
    #[error("Operation not supported: {0}")]
    NotSupported(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Key store result type
pub type KeyStoreResult<T> = Result<T, KeyStoreError>;

/// Key identifier (opaque — construct via `KeyId::new()` or `From<&str>`)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(String);

impl KeyId {
    /// Create a new key ID
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Get the key ID string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for KeyId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for KeyId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Key specification for generation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeySpec {
    /// Ed25519 (RFC 8032/8410)
    Ed25519,
    /// ECDSA with P-256 curve
    EcdsaP256,
    /// ECDSA with P-384 curve
    EcdsaP384,
    /// RSA with 2048-bit key
    Rsa2048,
    /// RSA with 3072-bit key
    Rsa3072,
    /// RSA with 4096-bit key
    Rsa4096,
    /// ML-DSA-44 (FIPS 204, Level 2)
    #[cfg(feature = "pqc")]
    MlDsa44,
    /// ML-DSA-65 (FIPS 204, Level 3)
    #[cfg(feature = "pqc")]
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, Level 5)
    #[cfg(feature = "pqc")]
    MlDsa87,
    /// SLH-DSA-SHA2-128s (FIPS 205, Level 1)
    #[cfg(feature = "pqc")]
    SlhDsaSha2_128s,
    /// SLH-DSA-SHA2-192s (FIPS 205, Level 3)
    #[cfg(feature = "pqc")]
    SlhDsaSha2_192s,
    /// SLH-DSA-SHA2-256s (FIPS 205, Level 5)
    #[cfg(feature = "pqc")]
    SlhDsaSha2_256s,
    /// ML-DSA-44 + ECDSA-P256 hybrid composite (RFC 9621)
    #[cfg(feature = "pqc")]
    MlDsa44EcdsaP256,
    /// ML-DSA-65 + ECDSA-P384 hybrid composite (RFC 9621)
    #[cfg(feature = "pqc")]
    MlDsa65EcdsaP384,
}

impl KeySpec {
    /// Get the algorithm name
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            KeySpec::Ed25519 => "Ed25519",
            KeySpec::EcdsaP256 => "ECDSA-P256",
            KeySpec::EcdsaP384 => "ECDSA-P384",
            KeySpec::Rsa2048 => "RSA-2048",
            KeySpec::Rsa3072 => "RSA-3072",
            KeySpec::Rsa4096 => "RSA-4096",
            #[cfg(feature = "pqc")]
            KeySpec::MlDsa44 => "ML-DSA-44",
            #[cfg(feature = "pqc")]
            KeySpec::MlDsa65 => "ML-DSA-65",
            #[cfg(feature = "pqc")]
            KeySpec::MlDsa87 => "ML-DSA-87",
            #[cfg(feature = "pqc")]
            KeySpec::SlhDsaSha2_128s => "SLH-DSA-SHA2-128s",
            #[cfg(feature = "pqc")]
            KeySpec::SlhDsaSha2_192s => "SLH-DSA-SHA2-192s",
            #[cfg(feature = "pqc")]
            KeySpec::SlhDsaSha2_256s => "SLH-DSA-SHA2-256s",
            #[cfg(feature = "pqc")]
            KeySpec::MlDsa44EcdsaP256 => "ML-DSA-44-ECDSA-P256",
            #[cfg(feature = "pqc")]
            KeySpec::MlDsa65EcdsaP384 => "ML-DSA-65-ECDSA-P384",
        }
    }

    /// Check if this is an elliptic curve key
    pub fn is_ec(&self) -> bool {
        matches!(self, KeySpec::EcdsaP256 | KeySpec::EcdsaP384)
    }

    /// Check if this is an RSA key
    pub fn is_rsa(&self) -> bool {
        matches!(self, KeySpec::Rsa2048 | KeySpec::Rsa3072 | KeySpec::Rsa4096)
    }

    /// Check if this is a post-quantum key
    #[cfg(feature = "pqc")]
    pub fn is_pqc(&self) -> bool {
        matches!(
            self,
            KeySpec::MlDsa44
                | KeySpec::MlDsa65
                | KeySpec::MlDsa87
                | KeySpec::SlhDsaSha2_128s
                | KeySpec::SlhDsaSha2_192s
                | KeySpec::SlhDsaSha2_256s
                | KeySpec::MlDsa44EcdsaP256
                | KeySpec::MlDsa65EcdsaP384
        )
    }

    /// Check if this is a hybrid composite key
    #[cfg(feature = "pqc")]
    pub fn is_composite(&self) -> bool {
        matches!(self, KeySpec::MlDsa44EcdsaP256 | KeySpec::MlDsa65EcdsaP384)
    }
}

/// Key usage purpose for key store operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum KeyUsage {
    /// Digital signature operations
    Signing,
    /// Encryption operations
    Encryption,
    /// Key agreement (e.g., ECDH)
    KeyAgreement,
}

/// Information about a stored key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeyInfo {
    /// Key identifier
    pub id: KeyId,
    /// Key specification
    pub spec: KeySpec,
    /// Key label/name
    pub label: String,
    /// When the key was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Whether the key can be exported
    pub exportable: bool,
    /// Key fingerprint (SHA-256 of public key)
    pub fingerprint: String,
}

/// Key attestation data (for HSMs that support it)
#[derive(Debug, Clone)]
pub struct KeyAttestation {
    /// Attestation certificate chain
    pub certificate_chain: Vec<Vec<u8>>,
    /// Attestation statement
    pub statement: Vec<u8>,
    /// HSM manufacturer
    pub manufacturer: String,
    /// HSM model
    pub model: String,
    /// Firmware version
    pub firmware_version: String,
}

/// Key store trait
///
/// This trait defines the interface for key storage backends.
/// Implementations can be software-based or hardware HSMs.
pub trait KeyStore: Send + Sync {
    /// Generate a new key pair
    ///
    /// # Arguments
    /// * `label` - Human-readable label for the key
    /// * `spec` - Key specification (algorithm and size)
    ///
    /// # Returns
    /// Key ID for referencing the key in future operations
    fn generate_key(&self, label: &str, spec: KeySpec) -> KeyStoreResult<KeyId>;

    /// Import an existing private key
    ///
    /// # Arguments
    /// * `label` - Human-readable label for the key
    /// * `pkcs8_der` - Private key in PKCS#8 DER format
    ///
    /// # Returns
    /// Key ID for referencing the key
    fn import_key(&self, label: &str, pkcs8_der: &[u8]) -> KeyStoreResult<KeyId>;

    /// Sign data with a key
    ///
    /// # Arguments
    /// * `key_id` - ID of the signing key
    /// * `data` - Data to sign (will be hashed if needed)
    ///
    /// # Returns
    /// Signature bytes
    fn sign(&self, key_id: &KeyId, data: &[u8]) -> KeyStoreResult<Vec<u8>>;

    /// Verify a signature
    ///
    /// # Arguments
    /// * `key_id` - ID of the verification key
    /// * `data` - Original data
    /// * `signature` - Signature to verify
    ///
    /// # Returns
    /// True if signature is valid
    fn verify(&self, key_id: &KeyId, data: &[u8], signature: &[u8]) -> KeyStoreResult<bool>;

    /// Get the public key in SPKI DER format
    ///
    /// # Arguments
    /// * `key_id` - ID of the key
    ///
    /// # Returns
    /// Public key in SPKI DER format
    fn public_key_der(&self, key_id: &KeyId) -> KeyStoreResult<Vec<u8>>;

    /// Get key information
    ///
    /// # Arguments
    /// * `key_id` - ID of the key
    ///
    /// # Returns
    /// Key information
    fn key_info(&self, key_id: &KeyId) -> KeyStoreResult<StoredKeyInfo>;

    /// List all keys
    ///
    /// # Returns
    /// List of key information
    fn list_keys(&self) -> KeyStoreResult<Vec<StoredKeyInfo>>;

    /// Delete a key
    ///
    /// # Arguments
    /// * `key_id` - ID of the key to delete
    fn delete_key(&self, key_id: &KeyId) -> KeyStoreResult<()>;

    /// Check if a key exists
    ///
    /// # Arguments
    /// * `key_id` - ID of the key
    ///
    /// # Returns
    /// True if key exists
    fn key_exists(&self, key_id: &KeyId) -> bool;

    /// Get key attestation (if supported)
    ///
    /// # Arguments
    /// * `key_id` - ID of the key
    ///
    /// # Returns
    /// Key attestation data, or error if not supported
    fn get_attestation(&self, _key_id: &KeyId) -> KeyStoreResult<KeyAttestation> {
        Err(KeyStoreError::NotSupported(
            "Key attestation not supported".into(),
        ))
    }

    /// Export private key (if allowed)
    ///
    /// # Arguments
    /// * `key_id` - ID of the key
    ///
    /// # Returns
    /// Private key in PKCS#8 DER format wrapped in `Zeroizing` for automatic
    /// memory cleanup, or error if not exportable
    fn export_private_key(&self, _key_id: &KeyId) -> KeyStoreResult<Zeroizing<Vec<u8>>> {
        Err(KeyStoreError::NotSupported(
            "Key export not supported".into(),
        ))
    }

    /// Get the backend name
    fn backend_name(&self) -> &'static str;

    /// Check if the backend is healthy
    fn health_check(&self) -> KeyStoreResult<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== KeyId ==========

    #[test]
    fn test_key_id() {
        let id = KeyId::new("test-key");
        assert_eq!(id.as_str(), "test-key");
        assert_eq!(id.to_string(), "test-key");
    }

    #[test]
    fn test_key_id_from_string() {
        let id: KeyId = "my-key".into();
        assert_eq!(id.as_str(), "my-key");
    }

    #[test]
    fn test_key_id_from_owned_string() {
        let id: KeyId = String::from("owned-key").into();
        assert_eq!(id.as_str(), "owned-key");
    }

    #[test]
    fn test_key_id_equality() {
        let id1 = KeyId::new("same");
        let id2 = KeyId::new("same");
        let id3 = KeyId::new("different");
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_key_id_display() {
        let id = KeyId::new("display-test");
        assert_eq!(format!("{}", id), "display-test");
    }

    #[test]
    fn test_key_id_empty() {
        let id = KeyId::new("");
        assert_eq!(id.as_str(), "");
    }

    // ========== KeySpec ==========

    #[test]
    fn test_key_spec_is_ec() {
        assert!(KeySpec::EcdsaP256.is_ec());
        assert!(KeySpec::EcdsaP384.is_ec());
        assert!(!KeySpec::Rsa2048.is_ec());
        assert!(!KeySpec::Rsa3072.is_ec());
        assert!(!KeySpec::Rsa4096.is_ec());
    }

    #[test]
    fn test_key_spec_is_rsa() {
        assert!(KeySpec::Rsa2048.is_rsa());
        assert!(KeySpec::Rsa3072.is_rsa());
        assert!(KeySpec::Rsa4096.is_rsa());
        assert!(!KeySpec::EcdsaP256.is_rsa());
        assert!(!KeySpec::EcdsaP384.is_rsa());
    }

    #[test]
    fn test_key_spec_algorithm_name_ec() {
        assert_eq!(KeySpec::EcdsaP256.algorithm_name(), "ECDSA-P256");
        assert_eq!(KeySpec::EcdsaP384.algorithm_name(), "ECDSA-P384");
    }

    #[test]
    fn test_key_spec_algorithm_name_rsa() {
        assert_eq!(KeySpec::Rsa2048.algorithm_name(), "RSA-2048");
        assert_eq!(KeySpec::Rsa3072.algorithm_name(), "RSA-3072");
        assert_eq!(KeySpec::Rsa4096.algorithm_name(), "RSA-4096");
    }

    #[test]
    fn test_key_spec_ec_not_rsa() {
        // EC and RSA should be mutually exclusive
        for spec in [KeySpec::EcdsaP256, KeySpec::EcdsaP384] {
            assert!(spec.is_ec());
            assert!(!spec.is_rsa());
        }
    }

    #[test]
    fn test_key_spec_rsa_not_ec() {
        for spec in [KeySpec::Rsa2048, KeySpec::Rsa3072, KeySpec::Rsa4096] {
            assert!(spec.is_rsa());
            assert!(!spec.is_ec());
        }
    }

    // ========== KeyStoreError ==========

    #[test]
    fn test_key_store_error_display() {
        let err = KeyStoreError::KeyNotFound("my-key".to_string());
        assert_eq!(err.to_string(), "Key not found: my-key");
    }

    #[test]
    fn test_key_store_error_exists() {
        let err = KeyStoreError::KeyExists("dup-key".to_string());
        assert!(err.to_string().contains("dup-key"));
    }

    #[test]
    fn test_key_store_error_signing_failed() {
        let err = KeyStoreError::SigningFailed("bad input".to_string());
        assert!(err.to_string().contains("Signing failed"));
    }

    #[test]
    fn test_key_store_error_not_supported() {
        let err = KeyStoreError::NotSupported("export".to_string());
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn test_key_store_error_connection() {
        let err = KeyStoreError::ConnectionError("timeout".to_string());
        assert!(err.to_string().contains("connection error"));
    }

    #[test]
    fn test_key_store_error_auth() {
        let err = KeyStoreError::AuthenticationFailed("bad pin".to_string());
        assert!(err.to_string().contains("Authentication failed"));
    }

    #[test]
    fn test_key_store_error_internal() {
        let err = KeyStoreError::Internal("unknown".to_string());
        assert!(err.to_string().contains("Internal error"));
    }

    #[test]
    fn test_key_store_error_invalid_spec() {
        let err = KeyStoreError::InvalidKeySpec("unsupported".to_string());
        assert!(err.to_string().contains("Invalid key spec"));
    }

    // ========== KeyUsage ==========

    #[test]
    fn test_key_usage_variants() {
        // Just ensure they can be created and compared
        assert_eq!(KeyUsage::Signing, KeyUsage::Signing);
        assert_ne!(KeyUsage::Signing, KeyUsage::Encryption);
        assert_ne!(KeyUsage::Encryption, KeyUsage::KeyAgreement);
    }
}
