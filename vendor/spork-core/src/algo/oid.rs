//! Shared OID constants for algorithm identification
//!
//! Consolidates algorithm OIDs used across the codebase to avoid duplication.

use const_oid::ObjectIdentifier;

// --- Key type OIDs (AlgorithmIdentifier in PKCS#8/SPKI) ---

/// EC public key (1.2.840.10045.2.1)
pub const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// RSA encryption (1.2.840.113549.1.1.1)
pub const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

// --- EdDSA OIDs (RFC 8410) ---

/// Ed25519 (1.3.101.112) — RFC 8410
pub const ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// Ed448 (1.3.101.113) — RFC 8410
pub const ED448: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.113");

// --- EC curve OIDs ---

/// secp256r1 / P-256 (1.2.840.10045.3.1.7)
pub const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// secp384r1 / P-384 (1.3.132.0.34)
pub const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

// --- Signature algorithm OIDs ---

/// ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
pub const ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
pub const ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// sha256WithRSAEncryption (1.2.840.113549.1.1.11)
pub const RSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// sha384WithRSAEncryption (1.2.840.113549.1.1.12)
pub const RSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");

/// id-RSASSA-PSS (1.2.840.113549.1.1.10) — RFC 4055
pub const RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");

// --- Digest algorithm OIDs (RFC 4055 §2, NIST FIPS 180-4) ---

/// id-sha256 (2.16.840.1.101.3.4.2.1) — FIPS 180-4
pub const SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// id-sha384 (2.16.840.1.101.3.4.2.2) — FIPS 180-4
pub const SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

/// id-sha512 (2.16.840.1.101.3.4.2.3) — FIPS 180-4
pub const SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

/// id-sha224 (2.16.840.1.101.3.4.2.4) — FIPS 180-4 (recognized but not approved for PSS)
pub const SHA224: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.4");

/// id-sha1 (1.3.14.3.2.26) — deprecated, rejected in PSS validation
pub const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

/// id-md5 (1.2.840.113549.2.5) — deprecated, rejected in PSS validation
pub const MD5: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.2.5");

/// id-mgf1 (1.2.840.113549.1.1.8) — RFC 4055 §3.1
pub const MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");

// --- PQC OIDs (FIPS 204 — ML-DSA) ---

/// ML-DSA-44 (2.16.840.1.101.3.4.3.17)
#[cfg(feature = "pqc")]
pub const ML_DSA_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");

/// ML-DSA-65 (2.16.840.1.101.3.4.3.18)
#[cfg(feature = "pqc")]
pub const ML_DSA_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");

/// ML-DSA-87 (2.16.840.1.101.3.4.3.19)
#[cfg(feature = "pqc")]
pub const ML_DSA_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

// --- PQC OIDs (FIPS 205 — SLH-DSA) ---

/// SLH-DSA-SHA2-128s (2.16.840.1.101.3.4.3.20)
#[cfg(feature = "pqc")]
pub const SLH_DSA_SHA2_128S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.20");

/// SLH-DSA-SHA2-192s (2.16.840.1.101.3.4.3.22)
#[cfg(feature = "pqc")]
pub const SLH_DSA_SHA2_192S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.22");

/// SLH-DSA-SHA2-256s (2.16.840.1.101.3.4.3.24)
#[cfg(feature = "pqc")]
pub const SLH_DSA_SHA2_256S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.24");

// --- Hybrid composite OIDs (draft-ietf-lamps-pq-composite-sigs) ---

/// ML-DSA-44 + ECDSA-P256 composite (2.16.840.1.114027.80.8.1.1)
#[cfg(feature = "pqc")]
pub const ML_DSA_44_ECDSA_P256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.1");

/// ML-DSA-65 + ECDSA-P256 composite (2.16.840.1.114027.80.8.1.2)
#[cfg(feature = "pqc")]
pub const ML_DSA_65_ECDSA_P256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.2");

/// ML-DSA-65 + ECDSA-P384 composite (2.16.840.1.114027.80.8.1.3)
#[cfg(feature = "pqc")]
pub const ML_DSA_65_ECDSA_P384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.3");

/// ML-DSA-87 + ECDSA-P384 composite (2.16.840.1.114027.80.8.1.4)
#[cfg(feature = "pqc")]
pub const ML_DSA_87_ECDSA_P384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.114027.80.8.1.4");
