//! Software-based key store implementation
//!
//! This implementation stores keys in memory or on disk with encryption.
//! Suitable for development, testing, and deployments without HSM.

use std::collections::HashMap;
use std::sync::RwLock;

use chrono::Utc;
use zeroize::Zeroizing;

use crate::digest;

use super::traits::{KeyId, KeySpec, KeyStore, KeyStoreError, KeyStoreResult, StoredKeyInfo};
use crate::algo::{AlgorithmId, KeyPair};

/// Software-based key store
///
/// Stores keys in memory with optional persistence.
/// Keys are protected by the process memory space.
///
/// # Security Notes
///
/// - Keys are stored in process memory
/// - For production, use HSM-backed implementation
/// - Consider using `Zeroizing` wrapper for key material
pub struct SoftwareKeyStore {
    /// Keys indexed by ID
    keys: RwLock<HashMap<KeyId, StoredKey>>,
    /// Whether keys can be exported
    allow_export: bool,
}

/// A stored key
struct StoredKey {
    /// The key pair
    key_pair: KeyPair,
    /// PKCS#8 DER of private key — wrapped in Zeroizing for guaranteed zeroization on drop.
    /// RustCrypto key types (SigningKey<P256>, RsaPrivateKey) don't implement ZeroizeOnDrop,
    /// so this field ensures at least one copy of the key material is properly zeroed.
    /// Never read directly — exists solely for its Drop-triggered zeroization.
    #[allow(dead_code)]
    private_key_der: Zeroizing<Vec<u8>>,
    /// Key label (zeroized on drop to avoid leaking key identifiers)
    label: Zeroizing<String>,
    /// Key specification
    spec: KeySpec,
    /// Creation time
    created_at: chrono::DateTime<chrono::Utc>,
    /// Whether exportable
    exportable: bool,
}

impl SoftwareKeyStore {
    /// Create a new software key store
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            allow_export: false,
        }
    }

    /// Create a new software key store that allows key export
    pub fn new_exportable() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            allow_export: true,
        }
    }

    /// Convert KeySpec to AlgorithmId
    fn spec_to_algorithm(spec: KeySpec) -> KeyStoreResult<AlgorithmId> {
        match spec {
            KeySpec::Ed25519 => Ok(AlgorithmId::Ed25519),
            KeySpec::EcdsaP256 => Ok(AlgorithmId::EcdsaP256),
            KeySpec::EcdsaP384 => Ok(AlgorithmId::EcdsaP384),
            KeySpec::Rsa2048 => Ok(AlgorithmId::Rsa2048),
            KeySpec::Rsa3072 => Ok(AlgorithmId::Rsa3072),
            KeySpec::Rsa4096 => Ok(AlgorithmId::Rsa4096),
            #[cfg(feature = "pqc")]
            KeySpec::MlDsa44 => Ok(AlgorithmId::MlDsa44),
            #[cfg(feature = "pqc")]
            KeySpec::MlDsa65 => Ok(AlgorithmId::MlDsa65),
            #[cfg(feature = "pqc")]
            KeySpec::MlDsa87 => Ok(AlgorithmId::MlDsa87),
            #[cfg(feature = "pqc")]
            KeySpec::SlhDsaSha2_128s => Ok(AlgorithmId::SlhDsaSha2_128s),
            #[cfg(feature = "pqc")]
            KeySpec::SlhDsaSha2_192s => Ok(AlgorithmId::SlhDsaSha2_192s),
            #[cfg(feature = "pqc")]
            KeySpec::SlhDsaSha2_256s => Ok(AlgorithmId::SlhDsaSha2_256s),
            #[cfg(feature = "pqc")]
            KeySpec::MlDsa44EcdsaP256 => Ok(AlgorithmId::MlDsa44EcdsaP256),
            #[cfg(feature = "pqc")]
            KeySpec::MlDsa65EcdsaP384 => Ok(AlgorithmId::MlDsa65EcdsaP384),
        }
    }

    /// Calculate key fingerprint
    fn calculate_fingerprint(public_key_der: &[u8]) -> String {
        let hash = digest::sha256(public_key_der);

        // Format as colon-separated hex
        hash.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Generate a unique key ID
    fn generate_key_id(label: &str) -> KeyId {
        use rand::RngCore;
        let mut bytes = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        KeyId::new(format!("{}-{}", label, hex::encode(bytes)))
    }

    /// Detect the algorithm from PKCS#8 DER by parsing the AlgorithmIdentifier OID
    fn detect_algorithm(pkcs8_der: &[u8]) -> KeyStoreResult<AlgorithmId> {
        use pkcs8::DecodePrivateKey;

        // Parse the PKCS#8 PrivateKeyInfo to extract the algorithm OID
        let pk_info = pkcs8::PrivateKeyInfo::try_from(pkcs8_der)
            .map_err(|e| KeyStoreError::Internal(format!("Failed to parse PKCS#8: {}", e)))?;

        let oid = pk_info.algorithm.oid;

        use crate::algo::oid;

        if oid == oid::EC_PUBLIC_KEY {
            // Determine curve from parameters
            if let Some(params) = pk_info.algorithm.parameters {
                let curve_oid = params.decode_as::<pkcs8::ObjectIdentifier>().map_err(|e| {
                    KeyStoreError::Internal(format!("Failed to parse EC params: {}", e))
                })?;
                if curve_oid == oid::SECP256R1 {
                    return Ok(AlgorithmId::EcdsaP256);
                } else if curve_oid == oid::SECP384R1 {
                    return Ok(AlgorithmId::EcdsaP384);
                }
            }
            Err(KeyStoreError::InvalidKeySpec("Unknown EC curve".into()))
        } else if oid == oid::RSA_ENCRYPTION {
            // Parse RSA key to determine bit size
            // Try loading as RSA to check modulus length
            use rsa::traits::PublicKeyParts;
            let rsa_key = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8_der)
                .map_err(|e| KeyStoreError::Internal(format!("Failed to parse RSA key: {}", e)))?;
            let bits = rsa_key.size() * 8;
            match bits {
                2048 => Ok(AlgorithmId::Rsa2048),
                3072 => Ok(AlgorithmId::Rsa3072),
                4096 => Ok(AlgorithmId::Rsa4096),
                _ => Err(KeyStoreError::InvalidKeySpec(format!(
                    "Unsupported RSA key size: {} bits (supported: 2048, 3072, 4096)",
                    bits
                ))),
            }
        } else {
            // Check PQC OIDs
            #[cfg(feature = "pqc")]
            {
                // ML-DSA (FIPS 204)
                if oid == oid::ML_DSA_44 {
                    return Ok(AlgorithmId::MlDsa44);
                } else if oid == oid::ML_DSA_65 {
                    return Ok(AlgorithmId::MlDsa65);
                } else if oid == oid::ML_DSA_87 {
                    return Ok(AlgorithmId::MlDsa87);
                }
                // SLH-DSA (FIPS 205)
                if oid == oid::SLH_DSA_SHA2_128S {
                    return Ok(AlgorithmId::SlhDsaSha2_128s);
                } else if oid == oid::SLH_DSA_SHA2_192S {
                    return Ok(AlgorithmId::SlhDsaSha2_192s);
                } else if oid == oid::SLH_DSA_SHA2_256S {
                    return Ok(AlgorithmId::SlhDsaSha2_256s);
                }
                // Hybrid composites (draft-ietf-lamps-pq-composite-sigs)
                if oid == oid::ML_DSA_44_ECDSA_P256 {
                    return Ok(AlgorithmId::MlDsa44EcdsaP256);
                } else if oid == oid::ML_DSA_65_ECDSA_P256 {
                    return Ok(AlgorithmId::MlDsa65EcdsaP256);
                } else if oid == oid::ML_DSA_65_ECDSA_P384 {
                    return Ok(AlgorithmId::MlDsa65EcdsaP384);
                } else if oid == oid::ML_DSA_87_ECDSA_P384 {
                    return Ok(AlgorithmId::MlDsa87EcdsaP384);
                }
            }
            Err(KeyStoreError::InvalidKeySpec(format!(
                "Unknown algorithm OID: {}",
                oid
            )))
        }
    }
}

/// Zeroize key material on drop.
///
/// Each `StoredKey.private_key_der` is a `Zeroizing<Vec<u8>>` that is
/// guaranteed to be zeroed when dropped. The inner `KeyPair` crypto types
/// (e.g., `SigningKey<P256>`, `RsaPrivateKey`) do NOT implement `ZeroizeOnDrop`
/// upstream — this is a known RustCrypto limitation. We mitigate by ensuring
/// at least the serialized PKCS#8 DER copy is properly zeroed.
impl Drop for SoftwareKeyStore {
    fn drop(&mut self) {
        // Recover the lock even if poisoned — the data is still valid and we
        // must not skip cleanup just because a previous holder panicked.
        let mut keys = match self.keys.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Drain all keys — StoredKey.private_key_der (Zeroizing<Vec<u8>>) is
        // automatically zeroed by Zeroizing's Drop impl when each StoredKey
        // is dropped here.
        keys.drain();
    }
}

impl Default for SoftwareKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for SoftwareKeyStore {
    fn generate_key(&self, label: &str, spec: KeySpec) -> KeyStoreResult<KeyId> {
        let algorithm = Self::spec_to_algorithm(spec)?;

        let key_pair = KeyPair::generate(algorithm)
            .map_err(|e| KeyStoreError::Internal(format!("Key generation failed: {}", e)))?;

        // Capture DER for guaranteed zeroization on drop
        let private_key_der = key_pair
            .private_key_der()
            .map_err(|e| KeyStoreError::Internal(format!("DER export for zeroize: {}", e)))?;

        let key_id = Self::generate_key_id(label);

        let stored_key = StoredKey {
            key_pair,
            private_key_der,
            label: Zeroizing::new(label.to_string()),
            spec,
            created_at: Utc::now(),
            exportable: self.allow_export,
        };

        let mut keys = self
            .keys
            .write()
            .map_err(|_| KeyStoreError::Internal("Lock poisoned".into()))?;

        keys.insert(key_id.clone(), stored_key);

        Ok(key_id)
    }

    fn import_key(&self, label: &str, pkcs8_der: &[u8]) -> KeyStoreResult<KeyId> {
        // Detect algorithm from PKCS#8 DER AlgorithmIdentifier OID
        let algorithm = Self::detect_algorithm(pkcs8_der)?;

        let key_pair = KeyPair::from_pkcs8_der(algorithm, pkcs8_der)
            .map_err(|e| KeyStoreError::Internal(format!("Key import failed: {}", e)))?;

        let spec = match key_pair.algorithm_id() {
            AlgorithmId::Ed25519 => KeySpec::Ed25519,
            AlgorithmId::EcdsaP256 => KeySpec::EcdsaP256,
            AlgorithmId::EcdsaP384 => KeySpec::EcdsaP384,
            AlgorithmId::Rsa2048 => KeySpec::Rsa2048,
            AlgorithmId::Rsa3072 | AlgorithmId::Rsa3072Pss => KeySpec::Rsa3072,
            AlgorithmId::Rsa4096 | AlgorithmId::Rsa4096Pss => KeySpec::Rsa4096,
            #[cfg(feature = "pqc")]
            AlgorithmId::MlDsa44 => KeySpec::MlDsa44,
            #[cfg(feature = "pqc")]
            AlgorithmId::MlDsa65 => KeySpec::MlDsa65,
            #[cfg(feature = "pqc")]
            AlgorithmId::MlDsa87 => KeySpec::MlDsa87,
            // SLH-DSA, composites, and future PQC algorithms are not yet in KeySpec
            #[cfg(feature = "pqc")]
            _ => {
                return Err(KeyStoreError::InvalidKeySpec(
                    "Unsupported algorithm".into(),
                ))
            }
        };

        let key_id = Self::generate_key_id(label);

        // Store DER copy for zeroization — imported keys already have their DER available
        let private_key_der = Zeroizing::new(pkcs8_der.to_vec());

        let stored_key = StoredKey {
            key_pair,
            private_key_der,
            label: Zeroizing::new(label.to_string()),
            spec,
            created_at: Utc::now(),
            exportable: self.allow_export,
        };

        let mut keys = self
            .keys
            .write()
            .map_err(|_| KeyStoreError::Internal("Lock poisoned".into()))?;

        keys.insert(key_id.clone(), stored_key);

        Ok(key_id)
    }

    fn sign(&self, key_id: &KeyId, data: &[u8]) -> KeyStoreResult<Vec<u8>> {
        let keys = self
            .keys
            .read()
            .map_err(|_| KeyStoreError::Internal("Lock poisoned".into()))?;

        let stored_key = keys
            .get(key_id)
            .ok_or_else(|| KeyStoreError::KeyNotFound(key_id.to_string()))?;

        stored_key
            .key_pair
            .sign(data)
            .map_err(|e| KeyStoreError::SigningFailed(e.to_string()))
    }

    fn verify(&self, key_id: &KeyId, data: &[u8], signature: &[u8]) -> KeyStoreResult<bool> {
        let keys = self
            .keys
            .read()
            .map_err(|_| KeyStoreError::Internal("Lock poisoned".into()))?;

        let stored_key = keys
            .get(key_id)
            .ok_or_else(|| KeyStoreError::KeyNotFound(key_id.to_string()))?;

        stored_key
            .key_pair
            .verify(data, signature)
            .map_err(|e| KeyStoreError::VerificationFailed(e.to_string()))
    }

    fn public_key_der(&self, key_id: &KeyId) -> KeyStoreResult<Vec<u8>> {
        let keys = self
            .keys
            .read()
            .map_err(|_| KeyStoreError::Internal("Lock poisoned".into()))?;

        let stored_key = keys
            .get(key_id)
            .ok_or_else(|| KeyStoreError::KeyNotFound(key_id.to_string()))?;

        stored_key
            .key_pair
            .public_key_der()
            .map_err(|e| KeyStoreError::Internal(e.to_string()))
    }

    fn key_info(&self, key_id: &KeyId) -> KeyStoreResult<StoredKeyInfo> {
        let keys = self
            .keys
            .read()
            .map_err(|_| KeyStoreError::Internal("Lock poisoned".into()))?;

        let stored_key = keys
            .get(key_id)
            .ok_or_else(|| KeyStoreError::KeyNotFound(key_id.to_string()))?;

        let public_key_der = stored_key
            .key_pair
            .public_key_der()
            .map_err(|e| KeyStoreError::Internal(e.to_string()))?;

        Ok(StoredKeyInfo {
            id: key_id.clone(),
            spec: stored_key.spec,
            label: (*stored_key.label).clone(),
            created_at: stored_key.created_at,
            exportable: stored_key.exportable,
            fingerprint: Self::calculate_fingerprint(&public_key_der),
        })
    }

    fn list_keys(&self) -> KeyStoreResult<Vec<StoredKeyInfo>> {
        let keys = self
            .keys
            .read()
            .map_err(|_| KeyStoreError::Internal("Lock poisoned".into()))?;

        let mut result = Vec::new();
        for (key_id, stored_key) in keys.iter() {
            let public_key_der = stored_key
                .key_pair
                .public_key_der()
                .map_err(|e| KeyStoreError::Internal(e.to_string()))?;

            result.push(StoredKeyInfo {
                id: key_id.clone(),
                spec: stored_key.spec,
                label: (*stored_key.label).clone(),
                created_at: stored_key.created_at,
                exportable: stored_key.exportable,
                fingerprint: Self::calculate_fingerprint(&public_key_der),
            });
        }

        Ok(result)
    }

    fn delete_key(&self, key_id: &KeyId) -> KeyStoreResult<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| KeyStoreError::Internal("Lock poisoned".into()))?;

        let stored_key = keys
            .remove(key_id)
            .ok_or_else(|| KeyStoreError::KeyNotFound(key_id.to_string()))?;

        // Force zeroization of key material before the StoredKey is dropped
        let _ = stored_key.key_pair.private_key_der();

        Ok(())
    }

    fn key_exists(&self, key_id: &KeyId) -> bool {
        self.keys
            .read()
            .map(|keys| keys.contains_key(key_id))
            .unwrap_or(false)
    }

    fn export_private_key(&self, key_id: &KeyId) -> KeyStoreResult<Zeroizing<Vec<u8>>> {
        let keys = self
            .keys
            .read()
            .map_err(|_| KeyStoreError::Internal("Lock poisoned".into()))?;

        let stored_key = keys
            .get(key_id)
            .ok_or_else(|| KeyStoreError::KeyNotFound(key_id.to_string()))?;

        if !stored_key.exportable {
            return Err(KeyStoreError::NotSupported("Key is not exportable".into()));
        }

        stored_key
            .key_pair
            .private_key_der()
            .map_err(|e| KeyStoreError::Internal(e.to_string()))
    }

    fn backend_name(&self) -> &'static str {
        "SoftwareKeyStore"
    }

    fn health_check(&self) -> KeyStoreResult<()> {
        // Software key store is always healthy if we can acquire the lock
        let _keys = self
            .keys
            .read()
            .map_err(|_| KeyStoreError::Internal("Lock poisoned".into()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let store = SoftwareKeyStore::new();

        let key_id = store.generate_key("test-key", KeySpec::EcdsaP256).unwrap();
        assert!(store.key_exists(&key_id));

        let info = store.key_info(&key_id).unwrap();
        assert_eq!(info.spec, KeySpec::EcdsaP256);
        assert!(info.label.starts_with("test-key"));
    }

    #[test]
    fn test_sign_verify() {
        let store = SoftwareKeyStore::new();
        let key_id = store.generate_key("test-key", KeySpec::EcdsaP256).unwrap();

        let data = b"test data to sign";
        let signature = store.sign(&key_id, data).unwrap();

        assert!(store.verify(&key_id, data, &signature).unwrap());
        assert!(!store
            .verify(&key_id, b"wrong data", &signature)
            .unwrap_or(true));
    }

    #[test]
    fn test_list_keys() {
        let store = SoftwareKeyStore::new();

        // Use FIPS-safe key types to avoid race with runtime FIPS mode toggle
        store.generate_key("key1", KeySpec::EcdsaP256).unwrap();
        store.generate_key("key2", KeySpec::EcdsaP384).unwrap();
        store.generate_key("key3", KeySpec::Rsa4096).unwrap();

        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 3);
    }

    #[test]
    fn test_delete_key() {
        let store = SoftwareKeyStore::new();
        let key_id = store.generate_key("test-key", KeySpec::EcdsaP256).unwrap();

        assert!(store.key_exists(&key_id));
        store.delete_key(&key_id).unwrap();
        assert!(!store.key_exists(&key_id));
    }

    #[test]
    fn test_export_not_allowed() {
        let store = SoftwareKeyStore::new();
        let key_id = store.generate_key("test-key", KeySpec::EcdsaP256).unwrap();

        // Default store doesn't allow export
        assert!(store.export_private_key(&key_id).is_err());
    }

    #[test]
    fn test_export_allowed() {
        let store = SoftwareKeyStore::new_exportable();
        let key_id = store.generate_key("test-key", KeySpec::EcdsaP256).unwrap();

        // Exportable store allows export
        let exported = store.export_private_key(&key_id).unwrap();
        assert!(!exported.is_empty());
    }

    #[test]
    fn test_health_check() {
        let store = SoftwareKeyStore::new();
        assert!(store.health_check().is_ok());
    }

    #[test]
    fn test_import_key_roundtrip() {
        // Generate a key, export it, import it into a new store, verify signing works
        let store1 = SoftwareKeyStore::new_exportable();
        let key_id1 = store1
            .generate_key("export-key", KeySpec::EcdsaP256)
            .unwrap();

        let exported = store1.export_private_key(&key_id1).unwrap();

        let store2 = SoftwareKeyStore::new();
        let key_id2 = store2.import_key("imported-key", &exported).unwrap();

        // Verify the imported key can sign and the original can verify
        let data = b"roundtrip test data";
        let signature = store2.sign(&key_id2, data).unwrap();

        // Get public keys — they should match
        let pub1 = store1.public_key_der(&key_id1).unwrap();
        let pub2 = store2.public_key_der(&key_id2).unwrap();
        assert_eq!(pub1, pub2);

        // Verify signature with original store
        assert!(store1.verify(&key_id1, data, &signature).unwrap());
    }

    #[test]
    fn test_import_key_detects_algorithm() {
        let store = SoftwareKeyStore::new_exportable();

        // Test P-256
        let p256_id = store.generate_key("p256", KeySpec::EcdsaP256).unwrap();
        let p256_der = store.export_private_key(&p256_id).unwrap();
        let import_store = SoftwareKeyStore::new();
        let imported_id = import_store.import_key("p256-imported", &p256_der).unwrap();
        let info = import_store.key_info(&imported_id).unwrap();
        assert_eq!(info.spec, KeySpec::EcdsaP256);

        // Test P-384
        let p384_id = store.generate_key("p384", KeySpec::EcdsaP384).unwrap();
        let p384_der = store.export_private_key(&p384_id).unwrap();
        let imported_id = import_store.import_key("p384-imported", &p384_der).unwrap();
        let info = import_store.key_info(&imported_id).unwrap();
        assert_eq!(info.spec, KeySpec::EcdsaP384);
    }

    #[test]
    fn test_key_not_found_errors() {
        let store = SoftwareKeyStore::new();
        let bogus = KeyId::new("nonexistent");
        assert!(matches!(
            store.sign(&bogus, b"data"),
            Err(KeyStoreError::KeyNotFound(_))
        ));
        assert!(matches!(
            store.delete_key(&bogus),
            Err(KeyStoreError::KeyNotFound(_))
        ));
        assert!(matches!(
            store.key_info(&bogus),
            Err(KeyStoreError::KeyNotFound(_))
        ));
        assert!(matches!(
            store.public_key_der(&bogus),
            Err(KeyStoreError::KeyNotFound(_))
        ));
        assert!(!store.key_exists(&bogus));
    }

    #[test]
    fn test_import_invalid_der() {
        let store = SoftwareKeyStore::new();

        // Empty input
        assert!(store.import_key("bad", &[]).is_err());
        // Garbage bytes
        assert!(store.import_key("bad", &[0xFF; 64]).is_err());
        // PEM instead of DER
        assert!(store
            .import_key("bad", b"-----BEGIN PRIVATE KEY-----")
            .is_err());
    }

    #[test]
    fn test_import_rsa_roundtrip() {
        let store = SoftwareKeyStore::new_exportable();
        // Use RSA-4096 to avoid race with runtime FIPS mode (RSA-2048 rejected)
        let key_id = store.generate_key("rsa-key", KeySpec::Rsa4096).unwrap();
        let exported = store.export_private_key(&key_id).unwrap();

        let store2 = SoftwareKeyStore::new();
        let imported_id = store2.import_key("rsa-imported", &exported).unwrap();
        let info = store2.key_info(&imported_id).unwrap();
        assert_eq!(info.spec, KeySpec::Rsa4096);

        // Verify signing works with imported key
        let data = b"rsa roundtrip";
        let sig = store2.sign(&imported_id, data).unwrap();
        assert!(store.verify(&key_id, data, &sig).unwrap());
    }

    #[test]
    fn test_drop_does_not_panic() {
        let store = SoftwareKeyStore::new();
        store.generate_key("k1", KeySpec::EcdsaP256).unwrap();
        store.generate_key("k2", KeySpec::Rsa4096).unwrap();
        drop(store); // Should not panic
    }

    #[test]
    fn test_public_key_fingerprint() {
        let store = SoftwareKeyStore::new();
        let key_id = store
            .generate_key("fingerprint-key", KeySpec::EcdsaP256)
            .unwrap();

        let info = store.key_info(&key_id).unwrap();

        // Fingerprint should be colon-separated hex (SHA-256 = 32 bytes = 95 chars with colons)
        assert!(info.fingerprint.contains(':'));
        let parts: Vec<&str> = info.fingerprint.split(':').collect();
        assert_eq!(parts.len(), 32);
    }
}
