//! Signer abstraction for CA key operations
//!
//! Supports both in-memory private keys (current behavior) and external
//! key stores (TPM, HSM, software keystore).

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::algo::{AlgorithmId, KeyPair};
use crate::error::{Error, Result};
use crate::hsm::{KeyId, KeyStore};

/// Signing backend for a Certificate Authority
///
/// Abstracts over in-memory keys and external key stores so the CA
/// can sign certificates regardless of where the private key lives.
pub enum Signer {
    /// In-memory private key (current/default behavior)
    InMemory {
        /// Private key in PKCS#8 DER format
        private_key_der: Zeroizing<Vec<u8>>,
        /// Algorithm used by this key
        algorithm: AlgorithmId,
    },
    /// External key store (TPM, HSM, software keystore)
    External {
        /// The key store backend
        key_store: Arc<dyn KeyStore>,
        /// Key identifier within the store
        key_id: KeyId,
        /// Algorithm used by this key
        algorithm: AlgorithmId,
    },
}

impl Signer {
    /// Create an in-memory signer from PKCS#8 DER bytes
    pub fn in_memory(private_key_der: Vec<u8>, algorithm: AlgorithmId) -> Self {
        Signer::InMemory {
            private_key_der: Zeroizing::new(private_key_der),
            algorithm,
        }
    }

    /// Create an external signer backed by a key store
    pub fn external(key_store: Arc<dyn KeyStore>, key_id: KeyId, algorithm: AlgorithmId) -> Self {
        Signer::External {
            key_store,
            key_id,
            algorithm,
        }
    }

    /// Get the algorithm for this signer
    pub fn algorithm(&self) -> AlgorithmId {
        match self {
            Signer::InMemory { algorithm, .. } => *algorithm,
            Signer::External { algorithm, .. } => *algorithm,
        }
    }

    /// Get a `KeyPair` for signing (in-memory only)
    ///
    /// Returns an error for external signers — use `sign()` instead.
    pub fn signing_key(&self) -> Result<KeyPair> {
        match self {
            Signer::InMemory {
                private_key_der,
                algorithm,
            } => KeyPair::from_pkcs8_der(*algorithm, private_key_der),
            Signer::External { .. } => Err(Error::InvalidKey(
                "Cannot extract KeyPair from external signer — use sign() instead".into(),
            )),
        }
    }

    /// Sign data using this signer
    ///
    /// For in-memory keys, creates a `KeyPair` and signs directly.
    /// For external keys, delegates to the key store.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Signer::InMemory {
                private_key_der,
                algorithm,
            } => {
                let key_pair = KeyPair::from_pkcs8_der(*algorithm, private_key_der)?;
                key_pair
                    .sign(data)
                    .map_err(|e| Error::SigningError(e.to_string()))
            }
            Signer::External {
                key_store, key_id, ..
            } => key_store
                .sign(key_id, data)
                .map_err(|e| Error::SigningError(e.to_string())),
        }
    }

    /// Get the public key in SPKI DER format
    ///
    /// For in-memory keys, creates a `KeyPair` and extracts the SPKI.
    /// For external keys, delegates to the key store.
    pub fn public_key_der(&self) -> Result<Vec<u8>> {
        match self {
            Signer::InMemory {
                private_key_der,
                algorithm,
            } => {
                let key_pair = KeyPair::from_pkcs8_der(*algorithm, private_key_der)?;
                key_pair
                    .public_key_der()
                    .map_err(|e| Error::InvalidKey(e.to_string()))
            }
            Signer::External {
                key_store, key_id, ..
            } => key_store
                .public_key_der(key_id)
                .map_err(|e| Error::InvalidKey(e.to_string())),
        }
    }

    /// Export the private key DER (in-memory only)
    ///
    /// Returns an error for external signers.
    pub fn export_private_key_der(&self) -> Result<&[u8]> {
        match self {
            Signer::InMemory {
                private_key_der, ..
            } => Ok(private_key_der),
            Signer::External { .. } => Err(Error::InvalidKey(
                "Cannot export private key from external signer".into(),
            )),
        }
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Signer::InMemory { algorithm, .. } => f
                .debug_struct("Signer::InMemory")
                .field("algorithm", algorithm)
                .field("private_key_der", &"[REDACTED]")
                .finish(),
            Signer::External {
                key_id, algorithm, ..
            } => f
                .debug_struct("Signer::External")
                .field("key_id", key_id)
                .field("algorithm", algorithm)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algo::KeyPair;
    use crate::hsm::KeyStore;

    #[test]
    fn test_in_memory_signer_sign() {
        let key_pair = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let der = key_pair.private_key_der().unwrap();

        let signer = Signer::in_memory(der.to_vec(), AlgorithmId::EcdsaP256);
        let signature = signer.sign(b"test data").unwrap();
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_in_memory_signer_signing_key() {
        let key_pair = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let der = key_pair.private_key_der().unwrap();

        let signer = Signer::in_memory(der.to_vec(), AlgorithmId::EcdsaP256);
        let retrieved = signer.signing_key().unwrap();
        assert_eq!(
            retrieved.public_key_der().unwrap(),
            key_pair.public_key_der().unwrap()
        );
    }

    #[test]
    fn test_in_memory_signer_export() {
        let key_pair = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let der = key_pair.private_key_der().unwrap();
        let der_copy = der.to_vec();

        let signer = Signer::in_memory(der.to_vec(), AlgorithmId::EcdsaP256);
        let exported = signer.export_private_key_der().unwrap();
        assert_eq!(exported, &der_copy[..]);
    }

    #[test]
    fn test_external_signer_signing_key_errors() {
        use crate::hsm::SoftwareKeyStore;

        let store = Arc::new(SoftwareKeyStore::new());
        let key_id = store
            .generate_key("test", crate::hsm::KeySpec::EcdsaP256)
            .unwrap();

        let signer = Signer::external(store, key_id, AlgorithmId::EcdsaP256);

        // signing_key() should error for external signer
        assert!(signer.signing_key().is_err());
    }

    #[test]
    fn test_external_signer_export_errors() {
        use crate::hsm::SoftwareKeyStore;

        let store = Arc::new(SoftwareKeyStore::new());
        let key_id = store
            .generate_key("test", crate::hsm::KeySpec::EcdsaP256)
            .unwrap();

        let signer = Signer::external(store, key_id, AlgorithmId::EcdsaP256);

        // export should error for external signer
        assert!(signer.export_private_key_der().is_err());
    }

    #[test]
    fn test_external_signer_sign() {
        use crate::hsm::SoftwareKeyStore;

        let store = Arc::new(SoftwareKeyStore::new());
        let key_id = store
            .generate_key("test-sign", crate::hsm::KeySpec::EcdsaP256)
            .unwrap();

        let signer = Signer::external(store, key_id, AlgorithmId::EcdsaP256);
        let signature = signer.sign(b"hello world").unwrap();
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_signer_algorithm() {
        let key_pair = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let der = key_pair.private_key_der().unwrap();

        let signer = Signer::in_memory(der.to_vec(), AlgorithmId::EcdsaP256);
        assert_eq!(signer.algorithm(), AlgorithmId::EcdsaP256);
    }

    #[test]
    fn test_in_memory_signer_public_key_der() {
        let key_pair = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let expected_pub = key_pair.public_key_der().unwrap();
        let der = key_pair.private_key_der().unwrap();

        let signer = Signer::in_memory(der.to_vec(), AlgorithmId::EcdsaP256);
        let pub_der = signer.public_key_der().unwrap();
        assert_eq!(pub_der, expected_pub);
    }

    #[test]
    fn test_external_signer_public_key_der() {
        use crate::hsm::SoftwareKeyStore;

        let store = Arc::new(SoftwareKeyStore::new());
        let key_id = store
            .generate_key("pub-key-test", crate::hsm::KeySpec::EcdsaP256)
            .unwrap();

        let expected_pub = store.public_key_der(&key_id).unwrap();
        let signer = Signer::external(store, key_id, AlgorithmId::EcdsaP256);

        let pub_der = signer.public_key_der().unwrap();
        assert_eq!(pub_der, expected_pub);
    }

    #[test]
    fn test_signer_debug_redacts_key() {
        let key_pair = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let der = key_pair.private_key_der().unwrap();

        let signer = Signer::in_memory(der.to_vec(), AlgorithmId::EcdsaP256);
        let debug_str = format!("{:?}", signer);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains(&format!("{:?}", &der[..])));
    }
}
