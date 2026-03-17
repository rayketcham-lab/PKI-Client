//! Algorithm abstraction layer for PQC/legacy parity
//!
//! Provides a unified interface across:
//! - PQC: ML-DSA-{44,65,87}, SLH-DSA-SHA2-{128s,192s,256s} (requires "pqc" feature)
//! - Legacy: ECDSA P-{256,384}, RSA-{2048,4096}
//! - Hybrid: Composite signatures (ML-DSA + ECDSA) per draft-ietf-lamps-pq-composite-sigs (requires "pqc" feature)

#[cfg(feature = "pqc")]
pub(crate) mod composite_impl;

// Classical algorithm backends: feature-gated dual backend
// Default (non-fips): RustCrypto pure-Rust implementations
// --features fips: aws-lc-rs FIPS 140-3 certified backend
#[cfg(not(feature = "fips"))]
mod ecdsa_impl;
#[cfg(not(feature = "fips"))]
mod ed25519_impl;
#[cfg(not(feature = "fips"))]
mod rsa_impl;

#[cfg(feature = "fips")]
mod awslc_ecdsa;
#[cfg(feature = "fips")]
mod awslc_ed25519;
#[cfg(feature = "fips")]
mod awslc_rsa;

#[cfg(feature = "pqc")]
mod mldsa_impl;
pub mod oid;
#[cfg(not(feature = "fips"))]
pub mod rsa_oaep;
#[cfg(feature = "pqc")]
mod slhdsa_impl;
pub mod validate;

use std::fmt;
use zeroize::Zeroizing;

#[cfg(feature = "pqc")]
pub use composite_impl::CompositeKeyPair;

// Re-exports: pick the right backend based on feature flags
#[cfg(feature = "fips")]
pub use awslc_ecdsa::{EcdsaP256, EcdsaP384};
#[cfg(not(feature = "fips"))]
pub use ecdsa_impl::{EcdsaP256, EcdsaP384};

#[cfg(feature = "fips")]
pub use awslc_ed25519::Ed25519;
#[cfg(not(feature = "fips"))]
pub use ed25519_impl::Ed25519;

#[cfg(feature = "fips")]
pub use awslc_rsa::{Rsa2048, Rsa3072, Rsa3072Pss, Rsa4096, Rsa4096Pss};
#[cfg(not(feature = "fips"))]
pub use rsa_impl::{Rsa2048, Rsa3072, Rsa3072Pss, Rsa4096, Rsa4096Pss};

#[cfg(feature = "pqc")]
pub use mldsa_impl::{MlDsa44, MlDsa65, MlDsa87};
#[cfg(feature = "pqc")]
pub use slhdsa_impl::{SlhDsaSha2_128s, SlhDsaSha2_192s, SlhDsaSha2_256s};

use crate::error::{Error, Result};

/// Algorithm identifier for serialization/deserialization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AlgorithmId {
    // PQC - FIPS 204
    #[cfg(feature = "pqc")]
    MlDsa44,
    #[cfg(feature = "pqc")]
    MlDsa65,
    #[cfg(feature = "pqc")]
    MlDsa87,
    // PQC - FIPS 205
    #[cfg(feature = "pqc")]
    SlhDsaSha2_128s,
    #[cfg(feature = "pqc")]
    SlhDsaSha2_192s,
    #[cfg(feature = "pqc")]
    SlhDsaSha2_256s,
    // Hybrid/Composite - draft-ietf-lamps-pq-composite-sigs (PQC + Classical)
    #[cfg(feature = "pqc")]
    MlDsa44EcdsaP256,
    #[cfg(feature = "pqc")]
    MlDsa65EcdsaP256,
    #[cfg(feature = "pqc")]
    MlDsa65EcdsaP384,
    #[cfg(feature = "pqc")]
    MlDsa87EcdsaP384,
    // EdDSA (RFC 8410/8032)
    Ed25519,
    // Legacy - ECDSA
    EcdsaP256,
    EcdsaP384,
    // Legacy - RSA (PKCS#1 v1.5)
    Rsa2048,
    Rsa3072,
    Rsa4096,
    // RSA-PSS (RFC 4055) — FIPS-preferred
    Rsa3072Pss,
    Rsa4096Pss,
}

impl fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "pqc")]
            Self::MlDsa44 => write!(f, "ML-DSA-44"),
            #[cfg(feature = "pqc")]
            Self::MlDsa65 => write!(f, "ML-DSA-65"),
            #[cfg(feature = "pqc")]
            Self::MlDsa87 => write!(f, "ML-DSA-87"),
            #[cfg(feature = "pqc")]
            Self::SlhDsaSha2_128s => write!(f, "SLH-DSA-SHA2-128s"),
            #[cfg(feature = "pqc")]
            Self::SlhDsaSha2_192s => write!(f, "SLH-DSA-SHA2-192s"),
            #[cfg(feature = "pqc")]
            Self::SlhDsaSha2_256s => write!(f, "SLH-DSA-SHA2-256s"),
            // Hybrid composites
            #[cfg(feature = "pqc")]
            Self::MlDsa44EcdsaP256 => write!(f, "ML-DSA-44 + ECDSA P-256"),
            #[cfg(feature = "pqc")]
            Self::MlDsa65EcdsaP256 => write!(f, "ML-DSA-65 + ECDSA P-256"),
            #[cfg(feature = "pqc")]
            Self::MlDsa65EcdsaP384 => write!(f, "ML-DSA-65 + ECDSA P-384"),
            #[cfg(feature = "pqc")]
            Self::MlDsa87EcdsaP384 => write!(f, "ML-DSA-87 + ECDSA P-384"),
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::EcdsaP256 => write!(f, "ECDSA P-256"),
            Self::EcdsaP384 => write!(f, "ECDSA P-384"),
            Self::Rsa2048 => write!(f, "RSA-2048"),
            Self::Rsa3072 => write!(f, "RSA-3072"),
            Self::Rsa4096 => write!(f, "RSA-4096"),
            Self::Rsa3072Pss => write!(f, "RSA-3072-PSS"),
            Self::Rsa4096Pss => write!(f, "RSA-4096-PSS"),
        }
    }
}

impl AlgorithmId {
    /// Whether this is a post-quantum algorithm (pure PQC or hybrid)
    pub fn is_pqc(&self) -> bool {
        #[cfg(feature = "pqc")]
        {
            matches!(
                self,
                Self::MlDsa44
                    | Self::MlDsa65
                    | Self::MlDsa87
                    | Self::SlhDsaSha2_128s
                    | Self::SlhDsaSha2_192s
                    | Self::SlhDsaSha2_256s
                    | Self::MlDsa44EcdsaP256
                    | Self::MlDsa65EcdsaP256
                    | Self::MlDsa65EcdsaP384
                    | Self::MlDsa87EcdsaP384
            )
        }
        #[cfg(not(feature = "pqc"))]
        {
            false
        }
    }

    /// Whether this is an RSA algorithm (any variant)
    pub fn is_rsa(&self) -> bool {
        matches!(
            self,
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 | Self::Rsa3072Pss | Self::Rsa4096Pss
        )
    }

    /// Whether this is a hybrid/composite algorithm
    #[cfg(feature = "pqc")]
    pub fn is_composite(&self) -> bool {
        matches!(
            self,
            Self::MlDsa44EcdsaP256
                | Self::MlDsa65EcdsaP256
                | Self::MlDsa65EcdsaP384
                | Self::MlDsa87EcdsaP384
        )
    }

    /// Get the PQC component of a composite algorithm
    #[cfg(feature = "pqc")]
    pub fn pqc_component(&self) -> Option<AlgorithmId> {
        match self {
            Self::MlDsa44EcdsaP256 => Some(AlgorithmId::MlDsa44),
            Self::MlDsa65EcdsaP256 | Self::MlDsa65EcdsaP384 => Some(AlgorithmId::MlDsa65),
            Self::MlDsa87EcdsaP384 => Some(AlgorithmId::MlDsa87),
            _ => None,
        }
    }

    /// Get the classical component of a composite algorithm
    #[cfg(feature = "pqc")]
    pub fn classical_component(&self) -> Option<AlgorithmId> {
        match self {
            Self::MlDsa44EcdsaP256 | Self::MlDsa65EcdsaP256 => Some(AlgorithmId::EcdsaP256),
            Self::MlDsa65EcdsaP384 | Self::MlDsa87EcdsaP384 => Some(AlgorithmId::EcdsaP384),
            _ => None,
        }
    }

    /// NIST security level (1-5)
    pub fn security_level(&self) -> u8 {
        match self {
            #[cfg(feature = "pqc")]
            Self::MlDsa44 | Self::SlhDsaSha2_128s => 1,
            Self::Ed25519 => 2,   // ~128-bit classical
            Self::EcdsaP256 => 2, // ~128-bit classical
            #[cfg(feature = "pqc")]
            Self::MlDsa65 | Self::SlhDsaSha2_192s => 3,
            Self::EcdsaP384 => 3,
            Self::Rsa2048 => 2,                    // ~112-bit
            Self::Rsa3072 | Self::Rsa3072Pss => 2, // ~128-bit
            Self::Rsa4096 | Self::Rsa4096Pss => 3, // ~140-bit
            #[cfg(feature = "pqc")]
            Self::MlDsa87 | Self::SlhDsaSha2_256s => 5,
            // Composites: security level is min(PQC, classical)
            #[cfg(feature = "pqc")]
            Self::MlDsa44EcdsaP256 => 1, // min(1, 2) = 1
            #[cfg(feature = "pqc")]
            Self::MlDsa65EcdsaP256 => 2, // min(3, 2) = 2
            #[cfg(feature = "pqc")]
            Self::MlDsa65EcdsaP384 => 3, // min(3, 3) = 3
            #[cfg(feature = "pqc")]
            Self::MlDsa87EcdsaP384 => 3, // min(5, 3) = 3
        }
    }

    /// Typical signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            #[cfg(feature = "pqc")]
            Self::MlDsa44 => 2420,
            #[cfg(feature = "pqc")]
            Self::MlDsa65 => 3309,
            #[cfg(feature = "pqc")]
            Self::MlDsa87 => 4627,
            #[cfg(feature = "pqc")]
            Self::SlhDsaSha2_128s => 7856,
            #[cfg(feature = "pqc")]
            Self::SlhDsaSha2_192s => 16224,
            #[cfg(feature = "pqc")]
            Self::SlhDsaSha2_256s => 29792,
            // Composite signatures: PQC_sig + ECDSA_sig (wrapped in SEQUENCE)
            #[cfg(feature = "pqc")]
            Self::MlDsa44EcdsaP256 => 2420 + 72 + 10, // ML-DSA-44 + ECDSA P-256 DER + overhead
            #[cfg(feature = "pqc")]
            Self::MlDsa65EcdsaP256 => 3309 + 72 + 10, // ML-DSA-65 + ECDSA P-256 DER + overhead
            #[cfg(feature = "pqc")]
            Self::MlDsa65EcdsaP384 => 3309 + 104 + 10, // ML-DSA-65 + ECDSA P-384 DER + overhead
            #[cfg(feature = "pqc")]
            Self::MlDsa87EcdsaP384 => 4627 + 104 + 10, // ML-DSA-87 + ECDSA P-384 DER + overhead
            Self::Ed25519 => 64,   // Raw 64-byte signature (not DER-wrapped)
            Self::EcdsaP256 => 64, // DER will be ~70-72
            Self::EcdsaP384 => 96, // DER will be ~102-104
            Self::Rsa2048 => 256,
            Self::Rsa3072 | Self::Rsa3072Pss => 384,
            Self::Rsa4096 | Self::Rsa4096Pss => 512,
        }
    }

    /// Public key size in bytes (approximate, DER encoded may vary)
    pub fn public_key_size(&self) -> usize {
        match self {
            #[cfg(feature = "pqc")]
            Self::MlDsa44 => 1312,
            #[cfg(feature = "pqc")]
            Self::MlDsa65 => 1952,
            #[cfg(feature = "pqc")]
            Self::MlDsa87 => 2592,
            #[cfg(feature = "pqc")]
            Self::SlhDsaSha2_128s => 32,
            #[cfg(feature = "pqc")]
            Self::SlhDsaSha2_192s => 48,
            #[cfg(feature = "pqc")]
            Self::SlhDsaSha2_256s => 64,
            // Composite public keys: PQC_pk + ECDSA_pk (wrapped in SEQUENCE)
            #[cfg(feature = "pqc")]
            Self::MlDsa44EcdsaP256 => 1312 + 65 + 20, // ML-DSA-44 + ECDSA P-256 + overhead
            #[cfg(feature = "pqc")]
            Self::MlDsa65EcdsaP256 => 1952 + 65 + 20, // ML-DSA-65 + ECDSA P-256 + overhead
            #[cfg(feature = "pqc")]
            Self::MlDsa65EcdsaP384 => 1952 + 97 + 20, // ML-DSA-65 + ECDSA P-384 + overhead
            #[cfg(feature = "pqc")]
            Self::MlDsa87EcdsaP384 => 2592 + 97 + 20, // ML-DSA-87 + ECDSA P-384 + overhead
            Self::Ed25519 => 32,   // Raw 32-byte public key
            Self::EcdsaP256 => 65, // Uncompressed point
            Self::EcdsaP384 => 97,
            Self::Rsa2048 => 294, // Typical SPKI
            Self::Rsa3072 | Self::Rsa3072Pss => 422,
            Self::Rsa4096 | Self::Rsa4096Pss => 550,
        }
    }

    /// Get the signature algorithm OID for X.509
    pub fn signature_oid(&self) -> const_oid::ObjectIdentifier {
        match self {
            #[cfg(feature = "pqc")]
            Self::MlDsa44 => oid::ML_DSA_44,
            #[cfg(feature = "pqc")]
            Self::MlDsa65 => oid::ML_DSA_65,
            #[cfg(feature = "pqc")]
            Self::MlDsa87 => oid::ML_DSA_87,
            #[cfg(feature = "pqc")]
            Self::SlhDsaSha2_128s => oid::SLH_DSA_SHA2_128S,
            #[cfg(feature = "pqc")]
            Self::SlhDsaSha2_192s => oid::SLH_DSA_SHA2_192S,
            #[cfg(feature = "pqc")]
            Self::SlhDsaSha2_256s => oid::SLH_DSA_SHA2_256S,
            #[cfg(feature = "pqc")]
            Self::MlDsa44EcdsaP256 => oid::ML_DSA_44_ECDSA_P256,
            #[cfg(feature = "pqc")]
            Self::MlDsa65EcdsaP256 => oid::ML_DSA_65_ECDSA_P256,
            #[cfg(feature = "pqc")]
            Self::MlDsa65EcdsaP384 => oid::ML_DSA_65_ECDSA_P384,
            #[cfg(feature = "pqc")]
            Self::MlDsa87EcdsaP384 => oid::ML_DSA_87_ECDSA_P384,
            Self::Ed25519 => oid::ED25519, // RFC 8410: same OID for key type and signature
            Self::EcdsaP256 => oid::ECDSA_SHA256,
            Self::EcdsaP384 => oid::ECDSA_SHA384,
            Self::Rsa2048 | Self::Rsa4096 => oid::RSA_SHA256,
            Self::Rsa3072 => oid::RSA_SHA384,
            Self::Rsa3072Pss | Self::Rsa4096Pss => oid::RSASSA_PSS,
        }
    }

    /// Get the DER-encoded AlgorithmIdentifier for the signature algorithm
    pub fn signature_algorithm_der(&self) -> Result<Vec<u8>> {
        let oid = self.signature_oid();
        let oid_bytes = oid.as_bytes();

        // AlgorithmIdentifier ::= SEQUENCE {
        //     algorithm OBJECT IDENTIFIER,
        //     parameters ANY DEFINED BY algorithm OPTIONAL
        // }
        let mut inner = Vec::new();

        // OID
        inner.push(0x06); // OBJECT IDENTIFIER tag
        inner.push(oid_bytes.len() as u8);
        inner.extend_from_slice(oid_bytes);

        // Parameters - NULL for RSA PKCS#1 v1.5, PSS params for RSA-PSS, absent for ECDSA/PQC
        match self {
            Self::Rsa2048 | Self::Rsa3072 | Self::Rsa4096 => {
                inner.push(0x05); // NULL tag
                inner.push(0x00); // NULL length
            }
            Self::Rsa3072Pss | Self::Rsa4096Pss => {
                // RSASSA-PSS-params with SHA-256 per RFC 4055
                inner.extend_from_slice(&Self::pss_sha256_params());
            }
            _ => {
                // No parameters for ECDSA and PQC
            }
        }

        // Wrap in SEQUENCE
        let mut result = Vec::new();
        result.push(0x30); // SEQUENCE tag
        result.push(inner.len() as u8);
        result.extend_from_slice(&inner);

        Ok(result)
    }

    /// DER-encoded RSASSA-PSS-params for SHA-256 (RFC 4055)
    ///
    /// Encodes: hash=SHA-256, mgf=mgf1(SHA-256), saltLength=32
    pub fn pss_sha256_params() -> Vec<u8> {
        // Pre-computed DER for RSASSA-PSS-params with SHA-256:
        //   SEQUENCE {
        //     [0] AlgorithmIdentifier { sha-256, NULL }
        //     [1] AlgorithmIdentifier { mgf1, AlgorithmIdentifier { sha-256, NULL } }
        //     [2] INTEGER 32
        //   }
        let sha256_ai: &[u8] = &[
            0x30, 0x0D, // SEQUENCE (13)
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // OID sha-256
            0x05, 0x00, // NULL
        ];
        let mgf1_ai: &[u8] = &[
            0x30, 0x1A, // SEQUENCE (26)
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08, // OID mgf1
            0x30, 0x0D, // SEQUENCE (13) = sha-256 AI
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // OID sha-256
            0x05, 0x00, // NULL
        ];

        let mut params = Vec::new();
        // [0] EXPLICIT hashAlgorithm
        params.push(0xA0);
        params.push(sha256_ai.len() as u8);
        params.extend_from_slice(sha256_ai);
        // [1] EXPLICIT maskGenAlgorithm
        params.push(0xA1);
        params.push(mgf1_ai.len() as u8);
        params.extend_from_slice(mgf1_ai);
        // [2] EXPLICIT saltLength = 32
        params.push(0xA2);
        params.push(0x03);
        params.push(0x02); // INTEGER
        params.push(0x01); // length 1
        params.push(0x20); // 32

        // Wrap in SEQUENCE
        let mut result = Vec::new();
        result.push(0x30);
        result.push(params.len() as u8);
        result.extend_from_slice(&params);
        result
    }
}

/// Core trait for all signing algorithms
pub trait SigningAlgorithm: Send + Sync + 'static {
    /// Algorithm identifier
    fn algorithm_id(&self) -> AlgorithmId;

    /// Sign a message, returning DER-encoded signature
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool>;

    /// Export private key as PKCS#8 DER
    fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>>;

    /// Export private key as PKCS#8 PEM
    fn private_key_pem(&self) -> Result<Zeroizing<String>>;

    /// Export public key as SPKI DER
    fn public_key_der(&self) -> Result<Vec<u8>>;

    /// Export public key as SPKI PEM
    fn public_key_pem(&self) -> Result<String>;

    /// Get OID for the algorithm (for X.509)
    fn oid(&self) -> const_oid::ObjectIdentifier;
}

/// Key pair container with type erasure
pub struct KeyPair {
    inner: Box<dyn SigningAlgorithm>,
}

impl KeyPair {
    /// Generate a new key pair for the specified algorithm
    pub fn generate(algorithm: AlgorithmId) -> Result<Self> {
        crate::fips::validate_algorithm(algorithm)?;
        let inner: Box<dyn SigningAlgorithm> = match algorithm {
            #[cfg(feature = "pqc")]
            AlgorithmId::MlDsa44 => Box::new(MlDsa44::generate()?),
            #[cfg(feature = "pqc")]
            AlgorithmId::MlDsa65 => Box::new(MlDsa65::generate()?),
            #[cfg(feature = "pqc")]
            AlgorithmId::MlDsa87 => Box::new(MlDsa87::generate()?),
            #[cfg(feature = "pqc")]
            AlgorithmId::SlhDsaSha2_128s => Box::new(SlhDsaSha2_128s::generate()?),
            #[cfg(feature = "pqc")]
            AlgorithmId::SlhDsaSha2_192s => Box::new(SlhDsaSha2_192s::generate()?),
            #[cfg(feature = "pqc")]
            AlgorithmId::SlhDsaSha2_256s => Box::new(SlhDsaSha2_256s::generate()?),
            // Composite (hybrid) algorithms
            #[cfg(feature = "pqc")]
            AlgorithmId::MlDsa44EcdsaP256
            | AlgorithmId::MlDsa65EcdsaP256
            | AlgorithmId::MlDsa65EcdsaP384
            | AlgorithmId::MlDsa87EcdsaP384 => Box::new(CompositeKeyPair::generate(algorithm)?),
            AlgorithmId::Ed25519 => Box::new(Ed25519::generate()?),
            AlgorithmId::EcdsaP256 => Box::new(EcdsaP256::generate()?),
            AlgorithmId::EcdsaP384 => Box::new(EcdsaP384::generate()?),
            AlgorithmId::Rsa2048 => Box::new(Rsa2048::generate()?),
            AlgorithmId::Rsa3072 => Box::new(Rsa3072::generate()?),
            AlgorithmId::Rsa4096 => Box::new(Rsa4096::generate()?),
            AlgorithmId::Rsa3072Pss => Box::new(Rsa3072Pss::generate()?),
            AlgorithmId::Rsa4096Pss => Box::new(Rsa4096Pss::generate()?),
        };
        Ok(Self { inner })
    }

    /// Load a key pair from PKCS#8 DER.
    ///
    /// Only unencrypted PrivateKeyInfo (RFC 5958 §2) is supported.
    /// Encrypted PKCS#8 (EncryptedPrivateKeyInfo, RFC 5958 §3) is detected
    /// and rejected with a clear error message.
    pub fn from_pkcs8_der(algorithm: AlgorithmId, der: &[u8]) -> Result<Self> {
        // RFC 5958 §3: Detect EncryptedPrivateKeyInfo.
        // EncryptedPrivateKeyInfo starts with SEQUENCE { SEQUENCE { OID (encryption alg) ... } ... }
        // PrivateKeyInfo starts with SEQUENCE { INTEGER (version) ... }
        // The second element tag distinguishes them: INTEGER (0x02) = unencrypted,
        // SEQUENCE (0x30) = encrypted.
        if der.len() > 4 && der[0] == 0x30 {
            // Skip outer SEQUENCE tag + length to find first inner element
            let (inner_offset, _) = Self::skip_der_length(&der[1..])?;
            let first_inner = 1 + inner_offset;
            if first_inner < der.len() && der[first_inner] == 0x30 {
                // Check if this looks like AlgorithmIdentifier for an encryption scheme
                // (not a PrivateKeyInfo which would have INTEGER version as first element)
                // Look for PKCS#5 OID prefix (1.2.840.113549.1.5) indicating encryption
                let search = &der[first_inner..std::cmp::min(first_inner + 30, der.len())];
                // OID 1.2.840.113549.1.5 prefix bytes (PBES2 etc.)
                const PKCS5_PREFIX: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05];
                if search
                    .windows(PKCS5_PREFIX.len())
                    .any(|w| w == PKCS5_PREFIX)
                {
                    return Err(Error::Encoding(
                        "Encrypted PKCS#8 (EncryptedPrivateKeyInfo per RFC 5958 §3) is not \
                         supported. Please decrypt the key first (e.g., openssl pkey -in key.pem \
                         -out decrypted.pem)"
                            .to_string(),
                    ));
                }
            }
        }

        // RFC 5958 §2: Detect OneAsymmetricKey (PKCS#8 v2) with optional
        // publicKey [1] BIT STRING field. If present, log it but proceed
        // with normal key loading (the publicKey is for validation only).
        Self::detect_pkcs8_v2_public_key(der);

        let inner: Box<dyn SigningAlgorithm> = match algorithm {
            #[cfg(feature = "pqc")]
            AlgorithmId::MlDsa44 => Box::new(MlDsa44::from_pkcs8_der(der)?),
            #[cfg(feature = "pqc")]
            AlgorithmId::MlDsa65 => Box::new(MlDsa65::from_pkcs8_der(der)?),
            #[cfg(feature = "pqc")]
            AlgorithmId::MlDsa87 => Box::new(MlDsa87::from_pkcs8_der(der)?),
            #[cfg(feature = "pqc")]
            AlgorithmId::SlhDsaSha2_128s => Box::new(SlhDsaSha2_128s::from_pkcs8_der(der)?),
            #[cfg(feature = "pqc")]
            AlgorithmId::SlhDsaSha2_192s => Box::new(SlhDsaSha2_192s::from_pkcs8_der(der)?),
            #[cfg(feature = "pqc")]
            AlgorithmId::SlhDsaSha2_256s => Box::new(SlhDsaSha2_256s::from_pkcs8_der(der)?),
            // Composite keys use custom DER format: [pqc_len:u32][pqc_der][classical_der]
            #[cfg(feature = "pqc")]
            AlgorithmId::MlDsa44EcdsaP256
            | AlgorithmId::MlDsa65EcdsaP256
            | AlgorithmId::MlDsa65EcdsaP384
            | AlgorithmId::MlDsa87EcdsaP384 => {
                Box::new(CompositeKeyPair::from_composite_der(algorithm, der)?)
            }
            AlgorithmId::Ed25519 => Box::new(Ed25519::from_pkcs8_der(der)?),
            AlgorithmId::EcdsaP256 => Box::new(EcdsaP256::from_pkcs8_der(der)?),
            AlgorithmId::EcdsaP384 => Box::new(EcdsaP384::from_pkcs8_der(der)?),
            AlgorithmId::Rsa2048 => Box::new(Rsa2048::from_pkcs8_der(der)?),
            AlgorithmId::Rsa3072 => Box::new(Rsa3072::from_pkcs8_der(der)?),
            AlgorithmId::Rsa4096 => Box::new(Rsa4096::from_pkcs8_der(der)?),
            AlgorithmId::Rsa3072Pss => Box::new(Rsa3072Pss::from_pkcs8_der(der)?),
            AlgorithmId::Rsa4096Pss => Box::new(Rsa4096Pss::from_pkcs8_der(der)?),
        };
        Ok(Self { inner })
    }

    /// Load a key pair from encrypted PKCS#8 DER (RFC 5958 §3).
    ///
    /// Supports PBES2 (RFC 8018) with:
    /// - KDF: PBKDF2 with HMAC-SHA-256
    /// - Encryption: AES-128-CBC, AES-256-CBC
    ///
    /// Also supports scrypt-based encryption (RFC 7914).
    pub fn from_encrypted_pkcs8_der(
        algorithm: AlgorithmId,
        encrypted_der: &[u8],
        password: &[u8],
    ) -> Result<Self> {
        use pkcs8::EncryptedPrivateKeyInfo;

        let encrypted_key_info = EncryptedPrivateKeyInfo::try_from(encrypted_der).map_err(|e| {
            Error::Encoding(format!(
                "Invalid EncryptedPrivateKeyInfo (RFC 5958 §3): {e}"
            ))
        })?;

        let decrypted = encrypted_key_info.decrypt(password).map_err(|e| {
            Error::Encoding(format!(
                "Failed to decrypt PKCS#8 key (wrong password or unsupported cipher): {e}"
            ))
        })?;

        Self::from_pkcs8_der(algorithm, decrypted.as_bytes())
    }

    /// Load a key pair from encrypted PKCS#8 PEM (RFC 5958 §3).
    ///
    /// Accepts PEM with tag "ENCRYPTED PRIVATE KEY" and decrypts using the
    /// provided password. Supports PBES2 (RFC 8018) encryption schemes.
    pub fn from_encrypted_pem(
        pem_str: &str,
        algorithm: AlgorithmId,
        password: &[u8],
    ) -> Result<Self> {
        use pem::parse;

        let pem = parse(pem_str).map_err(|e| Error::Encoding(format!("Invalid PEM: {}", e)))?;

        let tag = pem.tag();
        if tag != "ENCRYPTED PRIVATE KEY" {
            return Err(Error::Encoding(format!(
                "Expected ENCRYPTED PRIVATE KEY PEM tag, got: {tag}"
            )));
        }

        Self::from_encrypted_pkcs8_der(algorithm, pem.contents(), password)
    }

    /// Load a key pair from PKCS#8 PEM
    pub fn from_pem(pem_str: &str, algorithm: AlgorithmId) -> Result<Self> {
        use pem::parse;

        let pem = parse(pem_str).map_err(|e| Error::Encoding(format!("Invalid PEM: {}", e)))?;

        // RFC 5958 §3: Detect encrypted PKCS#8 by PEM tag
        let tag = pem.tag();
        if tag == "ENCRYPTED PRIVATE KEY" {
            return Err(Error::Encoding(
                "Encrypted PKCS#8 detected. Use from_encrypted_pem() with a password, \
                 or decrypt first (e.g., openssl pkey -in key.pem -out decrypted.pem)"
                    .to_string(),
            ));
        }

        // Accept both "PRIVATE KEY" (PKCS#8) and algorithm-specific tags
        if tag != "PRIVATE KEY" && !tag.contains("PRIVATE KEY") && !tag.contains("SIGNING KEY") {
            return Err(Error::Encoding(format!(
                "Invalid PEM tag: expected PRIVATE KEY, got {}",
                tag
            )));
        }

        Self::from_pkcs8_der(algorithm, pem.contents())
    }

    /// Algorithm identifier
    pub fn algorithm_id(&self) -> AlgorithmId {
        self.inner.algorithm_id()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.inner.sign(message)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        self.inner.verify(message, signature)
    }

    /// Export private key as PKCS#8 DER
    pub fn private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.inner.private_key_der()
    }

    /// Export private key as PKCS#8 PEM
    pub fn private_key_pem(&self) -> Result<Zeroizing<String>> {
        self.inner.private_key_pem()
    }

    /// Export public key as SPKI DER
    pub fn public_key_der(&self) -> Result<Vec<u8>> {
        self.inner.public_key_der()
    }

    /// Export public key as SPKI PEM
    pub fn public_key_pem(&self) -> Result<String> {
        self.inner.public_key_pem()
    }

    /// Get algorithm OID
    pub fn oid(&self) -> const_oid::ObjectIdentifier {
        self.inner.oid()
    }

    /// Get raw public key bytes (for hashing, etc.)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        // Try to get the DER and return it, or return empty on error
        self.inner.public_key_der().unwrap_or_default()
    }

    /// Detect RFC 5958 §2 OneAsymmetricKey (PKCS#8 v2) publicKey [1] BIT STRING.
    ///
    /// OneAsymmetricKey extends PrivateKeyInfo with optional fields:
    /// ```text
    /// OneAsymmetricKey ::= SEQUENCE {
    ///   version      Version (v1(0) | v2(1)),
    ///   algorithm    AlgorithmIdentifier,
    ///   privateKey   OCTET STRING,
    ///   attributes   [0] Attributes OPTIONAL,
    ///   publicKey    [1] BIT STRING OPTIONAL    ← detected here
    /// }
    /// ```
    /// If version is 1 (v2) and publicKey [1] is present, we log it.
    /// The field is informational — we don't use it for key loading.
    fn detect_pkcs8_v2_public_key(der: &[u8]) {
        if der.len() < 6 || der[0] != 0x30 {
            return;
        }
        // Skip outer SEQUENCE length
        let Ok((len_bytes, _outer_len)) = Self::skip_der_length(&der[1..]) else {
            return;
        };
        let inner = &der[1 + len_bytes..];
        // version INTEGER
        if inner.is_empty() || inner[0] != 0x02 {
            return;
        }
        let Ok((vlen_bytes, vlen)) = Self::skip_der_length(&inner[1..]) else {
            return;
        };
        let version_start = 1 + vlen_bytes;
        if version_start + vlen > inner.len() {
            return;
        }
        let version = inner[version_start..version_start + vlen]
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | b as u32);
        if version == 1 {
            // v2 — look for [1] tag (0x81 for implicit BIT STRING)
            // Scan remaining for context tag [1]
            let mut pos = version_start + vlen;
            // Skip AlgorithmIdentifier SEQUENCE
            if pos < inner.len() && inner[pos] == 0x30 {
                if let Ok((al, alen)) = Self::skip_der_length(&inner[pos + 1..]) {
                    pos += 1 + al + alen;
                }
            }
            // Skip privateKey OCTET STRING
            if pos < inner.len() && inner[pos] == 0x04 {
                if let Ok((pl, plen)) = Self::skip_der_length(&inner[pos + 1..]) {
                    pos += 1 + pl + plen;
                }
            }
            // Skip optional attributes [0]
            if pos < inner.len() && inner[pos] == 0xA0 {
                if let Ok((al, alen)) = Self::skip_der_length(&inner[pos + 1..]) {
                    pos += 1 + al + alen;
                }
            }
            // Check for publicKey [1] — recognized but not required for key loading
            // RFC 5958 §2: publicKey is informational (for validation without deriving)
            if pos < inner.len() && inner[pos] == 0x81 {
                // v2 key with embedded public key — proceed normally
            }
        }
    }

    /// Skip a DER length field, returning (number_of_bytes_consumed, length_value).
    fn skip_der_length(data: &[u8]) -> Result<(usize, usize)> {
        if data.is_empty() {
            return Err(Error::Encoding("missing DER length byte".into()));
        }
        if data[0] < 128 {
            Ok((1, data[0] as usize))
        } else {
            let num_bytes = (data[0] & 0x7F) as usize;
            if num_bytes == 0 || num_bytes > 3 || 1 + num_bytes > data.len() {
                return Err(Error::Encoding("invalid DER length encoding".into()));
            }
            let mut length: usize = 0;
            for i in 0..num_bytes {
                length = (length << 8) | (data[1 + i] as usize);
            }
            Ok((1 + num_bytes, length))
        }
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("algorithm", &self.algorithm_id())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_id_display() {
        assert_eq!(AlgorithmId::EcdsaP256.to_string(), "ECDSA P-256");
    }

    #[test]
    fn test_generate_ecdsa_p256() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        assert_eq!(kp.algorithm_id(), AlgorithmId::EcdsaP256);

        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_algorithm_id_display_all_classical() {
        assert_eq!(AlgorithmId::EcdsaP256.to_string(), "ECDSA P-256");
        assert_eq!(AlgorithmId::EcdsaP384.to_string(), "ECDSA P-384");
        assert_eq!(AlgorithmId::Rsa2048.to_string(), "RSA-2048");
        assert_eq!(AlgorithmId::Rsa3072.to_string(), "RSA-3072");
        assert_eq!(AlgorithmId::Rsa4096.to_string(), "RSA-4096");
    }

    #[test]
    fn test_security_levels() {
        assert_eq!(AlgorithmId::EcdsaP256.security_level(), 2);
        assert_eq!(AlgorithmId::EcdsaP384.security_level(), 3);
        assert_eq!(AlgorithmId::Rsa2048.security_level(), 2);
        assert_eq!(AlgorithmId::Rsa3072.security_level(), 2);
        assert_eq!(AlgorithmId::Rsa4096.security_level(), 3);
    }

    #[test]
    fn test_signature_sizes() {
        assert_eq!(AlgorithmId::EcdsaP256.signature_size(), 64);
        assert_eq!(AlgorithmId::EcdsaP384.signature_size(), 96);
        assert_eq!(AlgorithmId::Rsa2048.signature_size(), 256);
        assert_eq!(AlgorithmId::Rsa3072.signature_size(), 384);
        assert_eq!(AlgorithmId::Rsa4096.signature_size(), 512);
    }

    #[test]
    fn test_public_key_sizes() {
        assert_eq!(AlgorithmId::EcdsaP256.public_key_size(), 65);
        assert_eq!(AlgorithmId::EcdsaP384.public_key_size(), 97);
        assert_eq!(AlgorithmId::Rsa2048.public_key_size(), 294);
        assert_eq!(AlgorithmId::Rsa3072.public_key_size(), 422);
        assert_eq!(AlgorithmId::Rsa4096.public_key_size(), 550);
    }

    #[test]
    fn test_is_pqc_classical() {
        assert!(!AlgorithmId::EcdsaP256.is_pqc());
        assert!(!AlgorithmId::EcdsaP384.is_pqc());
        assert!(!AlgorithmId::Rsa2048.is_pqc());
        assert!(!AlgorithmId::Rsa3072.is_pqc());
        assert!(!AlgorithmId::Rsa4096.is_pqc());
    }

    #[test]
    fn test_serde_roundtrip() {
        let algos = [
            AlgorithmId::EcdsaP256,
            AlgorithmId::EcdsaP384,
            AlgorithmId::Rsa2048,
            AlgorithmId::Rsa3072,
            AlgorithmId::Rsa4096,
        ];
        for algo in algos {
            let json = serde_json::to_string(&algo).unwrap();
            let restored: AlgorithmId = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, algo, "Serde roundtrip failed for {:?}", algo);
        }
    }

    #[test]
    fn test_serde_kebab_case() {
        // kebab-case on enum variants: EcdsaP256 → "ecdsa-p256", Rsa4096 → "rsa4096"
        let json = serde_json::to_string(&AlgorithmId::EcdsaP256).unwrap();
        assert_eq!(json, "\"ecdsa-p256\"");

        // Rsa4096 has no camelCase boundary before the digits, so serde keeps it as "rsa4096"
        let json = serde_json::to_string(&AlgorithmId::Rsa4096).unwrap();
        assert_eq!(json, "\"rsa4096\"");
    }

    #[test]
    fn test_signature_algorithm_der() {
        // RSA should have NULL parameters
        let rsa_der = AlgorithmId::Rsa2048.signature_algorithm_der().unwrap();
        assert_eq!(rsa_der[0], 0x30); // SEQUENCE
        assert!(rsa_der.contains(&0x05)); // NULL tag

        // ECDSA should NOT have NULL parameters
        let ec_der = AlgorithmId::EcdsaP256.signature_algorithm_der().unwrap();
        assert_eq!(ec_der[0], 0x30); // SEQUENCE
        assert!(!ec_der[2..].contains(&0x05)); // No NULL after OID
    }

    #[test]
    fn test_algorithm_equality_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AlgorithmId::EcdsaP256);
        set.insert(AlgorithmId::EcdsaP384);
        set.insert(AlgorithmId::EcdsaP256); // duplicate

        assert_eq!(set.len(), 2);
        assert!(set.contains(&AlgorithmId::EcdsaP256));
        assert!(set.contains(&AlgorithmId::EcdsaP384));
    }

    #[test]
    #[cfg(not(feature = "fips"))] // Ed25519 is rejected in FIPS mode
    fn test_generate_ed25519() {
        let kp = KeyPair::generate(AlgorithmId::Ed25519).unwrap();
        assert_eq!(kp.algorithm_id(), AlgorithmId::Ed25519);

        let msg = b"test message";
        let sig = kp.sign(msg).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(kp.verify(msg, &sig).unwrap());
    }

    #[test]
    #[cfg(not(feature = "fips"))] // Ed25519 is rejected in FIPS mode
    fn test_ed25519_pkcs8_roundtrip_via_keypair() {
        let kp1 = KeyPair::generate(AlgorithmId::Ed25519).unwrap();
        let der = kp1.private_key_der().unwrap();
        let kp2 = KeyPair::from_pkcs8_der(AlgorithmId::Ed25519, &der).unwrap();

        let msg = b"roundtrip test";
        let sig = kp1.sign(msg).unwrap();
        assert!(kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_ed25519_display() {
        assert_eq!(AlgorithmId::Ed25519.to_string(), "Ed25519");
    }

    #[test]
    fn test_ed25519_properties() {
        assert_eq!(AlgorithmId::Ed25519.security_level(), 2);
        assert_eq!(AlgorithmId::Ed25519.signature_size(), 64);
        assert_eq!(AlgorithmId::Ed25519.public_key_size(), 32);
        assert!(!AlgorithmId::Ed25519.is_pqc());
    }

    #[test]
    fn test_ed25519_serde_roundtrip() {
        let json = serde_json::to_string(&AlgorithmId::Ed25519).unwrap();
        let restored: AlgorithmId = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, AlgorithmId::Ed25519);
    }

    #[test]
    fn test_keypair_debug() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let debug = format!("{:?}", kp);
        assert!(debug.contains("KeyPair"));
        assert!(debug.contains("EcdsaP256"));
    }

    #[test]
    fn test_encrypted_pkcs8_pem_rejected_without_password() {
        // RFC 5958 §3: ENCRYPTED PRIVATE KEY PEM should be detected when using from_pem()
        let encrypted_pem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
            MIIBvTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI\n\
            -----END ENCRYPTED PRIVATE KEY-----\n";
        let result = KeyPair::from_pem(encrypted_pem, AlgorithmId::EcdsaP256);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Encrypted PKCS#8") || err.contains("from_encrypted_pem"),
            "Expected encrypted PKCS#8 guidance, got: {err}"
        );
    }

    #[test]
    fn test_encrypted_pkcs8_der_rejected() {
        // Build a minimal EncryptedPrivateKeyInfo-like DER:
        // SEQUENCE { SEQUENCE { OID (PBES2 prefix) ... } OCTET STRING { ... } }
        // PBES2 OID prefix: 1.2.840.113549.1.5 = 2A 86 48 86 F7 0D 01 05
        let inner_seq = vec![
            0x30, 0x0E, // SEQUENCE
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D, // OID (PBES2)
            0x30, 0x01, 0x00, // params
        ];
        let encrypted_data = vec![0x04, 0x02, 0xAA, 0xBB]; // OCTET STRING
        let mut der = vec![0x30]; // outer SEQUENCE
        let total_len = inner_seq.len() + encrypted_data.len();
        der.push(total_len as u8);
        der.extend_from_slice(&inner_seq);
        der.extend_from_slice(&encrypted_data);

        let result = KeyPair::from_pkcs8_der(AlgorithmId::EcdsaP256, &der);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Encrypted PKCS#8") || err.contains("from_encrypted_pem"),
            "Expected encrypted PKCS#8 error, got: {err}"
        );
    }

    #[test]
    fn test_encrypted_pkcs8_roundtrip() {
        // Generate a key, encrypt it to PKCS#8, then decrypt and verify
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let msg = b"test message for encrypted PKCS#8 roundtrip";
        let sig = kp.sign(msg).unwrap();

        // Export unencrypted DER
        let der = kp.private_key_der().unwrap();

        // Encrypt it with PBES2
        let password = b"test-password-12345";
        let doc = pkcs8::PrivateKeyInfo::try_from(der.as_ref()).unwrap();
        let encrypted_der = doc
            .encrypt(rand::thread_rng(), password)
            .expect("PBES2 encryption should succeed");

        // Decrypt and reload
        let kp2 = KeyPair::from_encrypted_pkcs8_der(
            AlgorithmId::EcdsaP256,
            encrypted_der.as_bytes(),
            password,
        )
        .expect("Decryption should succeed");

        // Verify the decrypted key produces compatible signatures
        assert!(kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_encrypted_pkcs8_wrong_password() {
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let der = kp.private_key_der().unwrap();

        let password = b"correct-password";
        let doc = pkcs8::PrivateKeyInfo::try_from(der.as_ref()).unwrap();
        let encrypted_der = doc
            .encrypt(rand::thread_rng(), password)
            .expect("encryption should succeed");

        let result = KeyPair::from_encrypted_pkcs8_der(
            AlgorithmId::EcdsaP256,
            encrypted_der.as_bytes(),
            b"wrong-password",
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("decrypt") || err.contains("password") || err.contains("cipher"),
            "Expected decryption error, got: {err}"
        );
    }

    #[cfg(not(feature = "fips"))]
    #[test]
    fn test_encrypted_pkcs8_rsa_roundtrip() {
        // Test with RSA key to ensure algorithm-agnostic support
        let kp = KeyPair::generate(AlgorithmId::Rsa2048).unwrap();
        let msg = b"RSA encrypted PKCS#8 roundtrip test";
        let sig = kp.sign(msg).unwrap();

        let der = kp.private_key_der().unwrap();
        let password = b"rsa-test-pw";
        let doc = pkcs8::PrivateKeyInfo::try_from(der.as_ref()).unwrap();
        let encrypted_der = doc
            .encrypt(rand::thread_rng(), password)
            .expect("encryption should succeed");

        let kp2 = KeyPair::from_encrypted_pkcs8_der(
            AlgorithmId::Rsa2048,
            encrypted_der.as_bytes(),
            password,
        )
        .expect("RSA decryption should succeed");

        assert!(kp2.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_encrypted_pem_wrong_tag_rejected() {
        // from_encrypted_pem should reject non-encrypted PEM
        let plain_pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n";
        let result = KeyPair::from_encrypted_pem(plain_pem, AlgorithmId::EcdsaP256, b"password");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("ENCRYPTED PRIVATE KEY"),
            "Should reject non-encrypted PEM tag, got: {err}"
        );
    }
}
