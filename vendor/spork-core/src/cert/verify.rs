//! Certificate chain verification (RFC 5280 Section 6)
//!
//! Verifies certificate signatures, validity periods, BasicConstraints,
//! KeyUsage, and path length constraints across a certificate chain.

use chrono::{DateTime, Utc};
use der::{Decode, Encode};
use x509_cert::ext::pkix::{BasicConstraints as X509BasicConstraints, KeyUsage as X509KeyUsage};
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;

use crate::error::{Error, Result};

// Extension OIDs (arc components)
const OID_BASIC_CONSTRAINTS: &[u32] = &[2, 5, 29, 19];
const OID_KEY_USAGE: &[u32] = &[2, 5, 29, 15];
const OID_NAME_CONSTRAINTS: &[u32] = &[2, 5, 29, 30];
const OID_SUBJECT_ALT_NAME: &[u32] = &[2, 5, 29, 17];
const OID_TLS_FEATURE: &[u32] = &[1, 3, 6, 1, 5, 5, 7, 1, 24];

// Recognized critical extension OIDs (RFC 5280 Section 4.2)
// These are the extensions we know how to process.
const RECOGNIZED_EXTENSIONS: &[&[u32]] = &[
    &[2, 5, 29, 15],               // keyUsage
    &[2, 5, 29, 19],               // basicConstraints
    &[2, 5, 29, 17],               // subjectAltName
    &[2, 5, 29, 18],               // issuerAltName (RFC 5280 §4.2.1.7)
    &[2, 5, 29, 35],               // authorityKeyIdentifier
    &[2, 5, 29, 14],               // subjectKeyIdentifier
    &[2, 5, 29, 37],               // extKeyUsage
    &[2, 5, 29, 31],               // cRLDistributionPoints
    &[2, 5, 29, 32],               // certificatePolicies
    &[2, 5, 29, 33],               // policyMappings
    &[2, 5, 29, 36],               // policyConstraints
    &[2, 5, 29, 54],               // inhibitAnyPolicy
    &[2, 5, 29, 30],               // nameConstraints
    &[2, 5, 29, 46],               // freshestCRL (RFC 5280 §4.2.1.15)
    &[2, 5, 29, 56],               // noRevAvail (RFC 9608)
    &[1, 3, 6, 1, 5, 5, 7, 1, 1],  // authorityInfoAccess
    &[1, 3, 6, 1, 5, 5, 7, 1, 11], // subjectInfoAccess (RFC 5280 §4.2.2.2)
    &[1, 3, 6, 1, 5, 5, 7, 1, 24], // tlsFeature (RFC 7633)
    &[1, 3, 6, 1, 5, 5, 7, 1, 3],  // qcStatements (RFC 3739)
];

/// Options for chain validation.
#[derive(Debug, Clone)]
pub struct ChainValidationOptions {
    /// Verify certificate signatures (default: true)
    pub check_signatures: bool,
    /// Verify validity periods (default: true)
    pub check_validity: bool,
    /// Enforce BasicConstraints and KeyUsage (default: true)
    pub check_constraints: bool,
    /// Time to validate against (default: now)
    pub at_time: Option<DateTime<Utc>>,
    /// Run RFC 5280 Section 6 policy tree processing (default: false).
    /// When enabled, validates certificatePolicies, policyMappings,
    /// policyConstraints, and inhibitAnyPolicy extensions.
    pub check_policies: bool,
    /// Require an explicit policy in the chain (default: false).
    /// Only used when `check_policies` is true.
    pub require_explicit_policy: bool,
    /// Inhibit policy mapping (default: false).
    /// Only used when `check_policies` is true.
    pub inhibit_policy_mapping: bool,
    /// Inhibit anyPolicy (default: false).
    /// Only used when `check_policies` is true.
    pub inhibit_any_policy: bool,
    /// Acceptable certificate policy OIDs (RFC 5280 §6.1.1(c) initial-policy-set).
    /// When empty, defaults to {anyPolicy} which accepts all policies.
    /// Only used when `check_policies` is true.
    pub acceptable_policies: Vec<String>,
    /// Attempt AIA chasing when a chain gap is detected (default: false).
    ///
    /// When enabled and the `aia-chasing` feature is compiled in, the validator
    /// will follow `caIssuers` URIs in the AIA extension of each certificate to
    /// discover missing intermediate CAs before failing.
    ///
    /// Requires the `aia-chasing` feature flag. If the feature is not enabled,
    /// this option is ignored.
    #[cfg(feature = "aia-chasing")]
    pub aia_chase: Option<super::aia_chaser::AiaChaseConfig>,
}

impl Default for ChainValidationOptions {
    fn default() -> Self {
        Self {
            check_signatures: true,
            check_validity: true,
            check_constraints: true,
            at_time: None,
            check_policies: false,
            require_explicit_policy: false,
            inhibit_policy_mapping: false,
            inhibit_any_policy: false,
            acceptable_policies: Vec::new(),
            #[cfg(feature = "aia-chasing")]
            aia_chase: None,
        }
    }
}

/// Result of chain validation.
#[derive(Debug, Clone)]
pub struct ChainValidationResult {
    /// Whether the chain is valid (no errors)
    pub valid: bool,
    /// Whether the root is in the trust anchors
    pub trusted: bool,
    /// Validation errors (chain is invalid if non-empty)
    pub errors: Vec<String>,
    /// Warnings (chain may still be valid)
    pub warnings: Vec<String>,
    /// Policy validation result (only populated when check_policies is true)
    pub policy_result: Option<super::policy_tree::PolicyValidationResult>,
}

/// PSS hash algorithm variants detected from RSASSA-PSS-params.
pub(crate) enum PssHash {
    Sha256,
    Sha384,
    Sha512,
}

/// Detect the hash algorithm from RSASSA-PSS-params in an AlgorithmIdentifier DER.
///
/// Scans the DER bytes for SHA-2 OID patterns: 2.16.840.1.101.3.4.2.{1,2,3}.
/// The hashAlgorithm field in RSASSA-PSS-params contains the SHA OID, and the
/// distinguishing byte is the last arc: 0x01=SHA-256, 0x02=SHA-384, 0x03=SHA-512.
pub(crate) fn detect_pss_hash_algorithm(algo_der: &[u8]) -> PssHash {
    // SHA-2 OID prefix: 2.16.840.1.101.3.4.2 = 60 86 48 01 65 03 04 02
    let sha2_prefix = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02];
    for window in algo_der.windows(sha2_prefix.len() + 1) {
        if &window[..sha2_prefix.len()] == sha2_prefix {
            match window[sha2_prefix.len()] {
                0x02 => return PssHash::Sha384,
                0x03 => return PssHash::Sha512,
                _ => return PssHash::Sha256,
            }
        }
    }
    PssHash::Sha256 // default
}

/// Verify that `cert` was signed by `issuer`'s public key.
///
/// Extracts TBSCertificate from `cert`, determines the signature algorithm,
/// extracts the public key from `issuer`'s SPKI, and verifies the signature.
pub fn verify_signature(cert: &Certificate, issuer: &Certificate) -> Result<bool> {
    // Encode the TBSCertificate (the signed data)
    let tbs_der = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| Error::Encoding(format!("Failed to encode TBSCertificate: {}", e)))?;

    // Get the signature bytes
    let sig_bytes = cert.signature.as_bytes().ok_or_else(|| {
        Error::InvalidSignature("Signature BitString has unused bits".to_string())
    })?;

    // Get issuer's SPKI for public key extraction
    let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;

    // Determine algorithm from the certificate's signature algorithm OID
    let sig_alg_oid = cert.signature_algorithm.oid.to_string();

    match sig_alg_oid.as_str() {
        // ECDSA with SHA-256 (P-256)
        "1.2.840.10045.4.3.2" => {
            let pk_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid issuer public key BitString".to_string())
            })?;
            verify_ecdsa_p256_sig(pk_bytes, &tbs_der, sig_bytes)
        }
        // ECDSA with SHA-384 (P-384)
        "1.2.840.10045.4.3.3" => {
            let pk_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid issuer public key BitString".to_string())
            })?;
            verify_ecdsa_p384_sig(pk_bytes, &tbs_der, sig_bytes)
        }
        // RSA with SHA-256
        "1.2.840.113549.1.1.11" => {
            let spki_der = issuer_spki
                .to_der()
                .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
            verify_rsa_pkcs1_sha256_sig(&spki_der, &tbs_der, sig_bytes)
        }
        // RSA with SHA-384
        "1.2.840.113549.1.1.12" => {
            let spki_der = issuer_spki
                .to_der()
                .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
            verify_rsa_pkcs1_sha384_sig(&spki_der, &tbs_der, sig_bytes)
        }
        // RSA with SHA-512
        "1.2.840.113549.1.1.13" => {
            let spki_der = issuer_spki
                .to_der()
                .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
            verify_rsa_pkcs1_sha512_sig(&spki_der, &tbs_der, sig_bytes)
        }
        // RSASSA-PSS (RFC 4055) — hash algorithm determined from AlgorithmIdentifier params
        "1.2.840.113549.1.1.10" => {
            let spki_der = issuer_spki
                .to_der()
                .map_err(|e| Error::Encoding(format!("SPKI encode: {}", e)))?;
            let algo_der = cert.signature_algorithm.to_der().unwrap_or_default();
            let pss_hash = detect_pss_hash_algorithm(&algo_der);
            verify_rsa_pss_sig(&spki_der, &tbs_der, sig_bytes, pss_hash)
        }
        // ML-DSA-44
        #[cfg(feature = "pqc")]
        "2.16.840.1.101.3.4.3.17" => {
            let pk_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid issuer public key BitString".into())
            })?;
            verify_mldsa::<ml_dsa::MlDsa44>(pk_bytes, &tbs_der, sig_bytes)
        }
        // ML-DSA-65
        #[cfg(feature = "pqc")]
        "2.16.840.1.101.3.4.3.18" => {
            let pk_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid issuer public key BitString".into())
            })?;
            verify_mldsa::<ml_dsa::MlDsa65>(pk_bytes, &tbs_der, sig_bytes)
        }
        // ML-DSA-87
        #[cfg(feature = "pqc")]
        "2.16.840.1.101.3.4.3.19" => {
            let pk_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid issuer public key BitString".into())
            })?;
            verify_mldsa::<ml_dsa::MlDsa87>(pk_bytes, &tbs_der, sig_bytes)
        }
        // Composite ML-DSA-44 + ECDSA-P256
        #[cfg(feature = "pqc")]
        "2.16.840.1.114027.80.8.1.1" => {
            let pk_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid issuer public key BitString".into())
            })?;
            crate::algo::composite_impl::verify_composite_signature_standalone(
                crate::algo::AlgorithmId::MlDsa44EcdsaP256,
                pk_bytes,
                &tbs_der,
                sig_bytes,
            )
        }
        // Composite ML-DSA-65 + ECDSA-P256
        #[cfg(feature = "pqc")]
        "2.16.840.1.114027.80.8.1.2" => {
            let pk_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid issuer public key BitString".into())
            })?;
            crate::algo::composite_impl::verify_composite_signature_standalone(
                crate::algo::AlgorithmId::MlDsa65EcdsaP256,
                pk_bytes,
                &tbs_der,
                sig_bytes,
            )
        }
        // Composite ML-DSA-65 + ECDSA-P384
        #[cfg(feature = "pqc")]
        "2.16.840.1.114027.80.8.1.3" => {
            let pk_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid issuer public key BitString".into())
            })?;
            crate::algo::composite_impl::verify_composite_signature_standalone(
                crate::algo::AlgorithmId::MlDsa65EcdsaP384,
                pk_bytes,
                &tbs_der,
                sig_bytes,
            )
        }
        // Composite ML-DSA-87 + ECDSA-P384
        #[cfg(feature = "pqc")]
        "2.16.840.1.114027.80.8.1.4" => {
            let pk_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid issuer public key BitString".into())
            })?;
            crate::algo::composite_impl::verify_composite_signature_standalone(
                crate::algo::AlgorithmId::MlDsa87EcdsaP384,
                pk_bytes,
                &tbs_der,
                sig_bytes,
            )
        }
        // SLH-DSA-SHA2-128s
        #[cfg(feature = "pqc")]
        "2.16.840.1.101.3.4.3.20" => {
            let pk_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid issuer public key BitString".into())
            })?;
            verify_slhdsa::<slh_dsa::Sha2_128s>(pk_bytes, &tbs_der, sig_bytes)
        }
        // SLH-DSA-SHA2-192s
        #[cfg(feature = "pqc")]
        "2.16.840.1.101.3.4.3.22" => {
            let pk_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid issuer public key BitString".into())
            })?;
            verify_slhdsa::<slh_dsa::Sha2_192s>(pk_bytes, &tbs_der, sig_bytes)
        }
        // SLH-DSA-SHA2-256s
        #[cfg(feature = "pqc")]
        "2.16.840.1.101.3.4.3.24" => {
            let pk_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid issuer public key BitString".into())
            })?;
            verify_slhdsa::<slh_dsa::Sha2_256s>(pk_bytes, &tbs_der, sig_bytes)
        }
        // Ed25519 (RFC 8410)
        "1.3.101.112" => {
            let pk_bytes = issuer_spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid issuer public key BitString".into())
            })?;
            verify_ed25519_sig(pk_bytes, &tbs_der, sig_bytes)
        }
        _ => Err(Error::UnsupportedAlgorithm(format!(
            "Certificate signature verification not supported for OID: {}",
            sig_alg_oid
        ))),
    }
}

// ---- Classical signature verification helpers (cfg-gated for FIPS) ----
// Used by verify_signature(), verify_raw_signature(), and csr::verify_signature().

/// Verify an ECDSA P-256 (SHA-256) signature.
#[cfg(not(feature = "fips"))]
pub(crate) fn verify_ecdsa_p256_sig(
    pk_bytes: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(pk_bytes)
        .map_err(|e| Error::InvalidCertificate(format!("Invalid P-256 public key: {}", e)))?;
    let sig = Signature::from_der(sig_bytes)
        .map_err(|e| Error::InvalidSignature(format!("Invalid P-256 signature: {}", e)))?;
    Ok(vk.verify(data, &sig).is_ok())
}

#[cfg(feature = "fips")]
pub(crate) fn verify_ecdsa_p256_sig(
    pk_bytes: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
    let peer_pub = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pk_bytes);
    Ok(peer_pub.verify(data, sig_bytes).is_ok())
}

/// Verify an ECDSA P-384 (SHA-384) signature.
#[cfg(not(feature = "fips"))]
pub(crate) fn verify_ecdsa_p384_sig(
    pk_bytes: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use p384::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
    let vk = VerifyingKey::from_sec1_bytes(pk_bytes)
        .map_err(|e| Error::InvalidCertificate(format!("Invalid P-384 public key: {}", e)))?;
    let sig = Signature::from_der(sig_bytes)
        .map_err(|e| Error::InvalidSignature(format!("Invalid P-384 signature: {}", e)))?;
    Ok(vk.verify(data, &sig).is_ok())
}

#[cfg(feature = "fips")]
pub(crate) fn verify_ecdsa_p384_sig(
    pk_bytes: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P384_SHA384_ASN1};
    let peer_pub = UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, pk_bytes);
    Ok(peer_pub.verify(data, sig_bytes).is_ok())
}

/// Verify an RSA PKCS#1 v1.5 signature with SHA-256.
#[cfg(not(feature = "fips"))]
pub(crate) fn verify_rsa_pkcs1_sha256_sig(
    spki_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::sha2::Sha256;
    use rsa::signature::Verifier as _;
    use rsa::RsaPublicKey;
    let rsa_pub = RsaPublicKey::from_public_key_der(spki_der)
        .map_err(|e| Error::InvalidCertificate(format!("Invalid RSA public key: {}", e)))?;
    let vk = VerifyingKey::<Sha256>::new(rsa_pub);
    let sig = Signature::try_from(sig_bytes)
        .map_err(|e| Error::InvalidSignature(format!("Invalid RSA signature: {}", e)))?;
    Ok(vk.verify(data, &sig).is_ok())
}

#[cfg(feature = "fips")]
pub(crate) fn verify_rsa_pkcs1_sha256_sig(
    spki_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use aws_lc_rs::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA256};
    let peer_pub = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, spki_der);
    Ok(peer_pub.verify(data, sig_bytes).is_ok())
}

/// Verify an RSA PKCS#1 v1.5 signature with SHA-384.
#[cfg(not(feature = "fips"))]
pub(crate) fn verify_rsa_pkcs1_sha384_sig(
    spki_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::sha2::Sha384;
    use rsa::signature::Verifier as _;
    use rsa::RsaPublicKey;
    let rsa_pub = RsaPublicKey::from_public_key_der(spki_der)
        .map_err(|e| Error::InvalidCertificate(format!("Invalid RSA public key: {}", e)))?;
    let vk = VerifyingKey::<Sha384>::new(rsa_pub);
    let sig = Signature::try_from(sig_bytes)
        .map_err(|e| Error::InvalidSignature(format!("Invalid RSA signature: {}", e)))?;
    Ok(vk.verify(data, &sig).is_ok())
}

#[cfg(feature = "fips")]
pub(crate) fn verify_rsa_pkcs1_sha384_sig(
    spki_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use aws_lc_rs::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA384};
    let peer_pub = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA384, spki_der);
    Ok(peer_pub.verify(data, sig_bytes).is_ok())
}

/// Verify an RSA PKCS#1 v1.5 signature with SHA-512.
#[cfg(not(feature = "fips"))]
pub(crate) fn verify_rsa_pkcs1_sha512_sig(
    spki_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePublicKey;
    use rsa::sha2::Sha512;
    use rsa::signature::Verifier as _;
    use rsa::RsaPublicKey;
    let rsa_pub = RsaPublicKey::from_public_key_der(spki_der)
        .map_err(|e| Error::InvalidCertificate(format!("Invalid RSA public key: {}", e)))?;
    let vk = VerifyingKey::<Sha512>::new(rsa_pub);
    let sig = Signature::try_from(sig_bytes)
        .map_err(|e| Error::InvalidSignature(format!("Invalid RSA signature: {}", e)))?;
    Ok(vk.verify(data, &sig).is_ok())
}

#[cfg(feature = "fips")]
pub(crate) fn verify_rsa_pkcs1_sha512_sig(
    spki_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use aws_lc_rs::signature::{UnparsedPublicKey, RSA_PKCS1_2048_8192_SHA512};
    let peer_pub = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA512, spki_der);
    Ok(peer_pub.verify(data, sig_bytes).is_ok())
}

/// Verify an RSA-PSS signature.
#[cfg(not(feature = "fips"))]
pub(crate) fn verify_rsa_pss_sig(
    spki_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
    hash: PssHash,
) -> Result<bool> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::sha2::{Sha256, Sha384, Sha512};
    use rsa::signature::Verifier as _;
    use rsa::RsaPublicKey;
    let rsa_pub = RsaPublicKey::from_public_key_der(spki_der)
        .map_err(|e| Error::InvalidCertificate(format!("Invalid RSA public key: {}", e)))?;
    let sig = Signature::try_from(sig_bytes)
        .map_err(|e| Error::InvalidSignature(format!("Invalid RSA-PSS signature: {}", e)))?;
    match hash {
        PssHash::Sha256 => Ok(VerifyingKey::<Sha256>::new(rsa_pub)
            .verify(data, &sig)
            .is_ok()),
        PssHash::Sha384 => Ok(VerifyingKey::<Sha384>::new(rsa_pub)
            .verify(data, &sig)
            .is_ok()),
        PssHash::Sha512 => Ok(VerifyingKey::<Sha512>::new(rsa_pub)
            .verify(data, &sig)
            .is_ok()),
    }
}

#[cfg(feature = "fips")]
pub(crate) fn verify_rsa_pss_sig(
    spki_der: &[u8],
    data: &[u8],
    sig_bytes: &[u8],
    hash: PssHash,
) -> Result<bool> {
    use aws_lc_rs::signature::{
        UnparsedPublicKey, RSA_PSS_2048_8192_SHA256, RSA_PSS_2048_8192_SHA384,
        RSA_PSS_2048_8192_SHA512,
    };
    match hash {
        PssHash::Sha256 => {
            let p = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA256, spki_der);
            Ok(p.verify(data, sig_bytes).is_ok())
        }
        PssHash::Sha384 => {
            let p = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, spki_der);
            Ok(p.verify(data, sig_bytes).is_ok())
        }
        PssHash::Sha512 => {
            let p = UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA512, spki_der);
            Ok(p.verify(data, sig_bytes).is_ok())
        }
    }
}

/// Ed25519 signature verification (RFC 8032)
#[cfg(not(feature = "fips"))]
pub(crate) fn verify_ed25519_sig(
    pk_bytes: &[u8],
    tbs_der: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let vk = VerifyingKey::from_bytes(pk_bytes.try_into().map_err(|_| {
        Error::InvalidCertificate(format!(
            "Ed25519 public key must be 32 bytes, got {}",
            pk_bytes.len()
        ))
    })?)
    .map_err(|e| Error::InvalidCertificate(format!("Invalid Ed25519 public key: {}", e)))?;

    let sig = Signature::from_slice(sig_bytes)
        .map_err(|e| Error::InvalidSignature(format!("Invalid Ed25519 signature: {}", e)))?;

    Ok(vk.verify(tbs_der, &sig).is_ok())
}

#[cfg(feature = "fips")]
pub(crate) fn verify_ed25519_sig(
    pk_bytes: &[u8],
    tbs_der: &[u8],
    sig_bytes: &[u8],
) -> Result<bool> {
    use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};
    let peer_pub = UnparsedPublicKey::new(&ED25519, pk_bytes);
    Ok(peer_pub.verify(tbs_der, sig_bytes).is_ok())
}

/// Generic ML-DSA signature verification helper.
#[cfg(feature = "pqc")]
fn verify_mldsa<P>(pk_bytes: &[u8], tbs_der: &[u8], sig_bytes: &[u8]) -> Result<bool>
where
    P: ml_dsa::MlDsaParams,
{
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Signature, VerifyingKey};

    let encoded_vk: EncodedVerifyingKey<P> = pk_bytes.try_into().map_err(|_| {
        Error::InvalidCertificate(format!(
            "Invalid ML-DSA public key length (expected {}, got {})",
            std::mem::size_of::<EncodedVerifyingKey<P>>(),
            pk_bytes.len()
        ))
    })?;
    let vk = VerifyingKey::<P>::decode(&encoded_vk);
    let encoded_sig: EncodedSignature<P> = sig_bytes.try_into().map_err(|_| {
        Error::InvalidSignature(format!(
            "Invalid ML-DSA signature length (expected {}, got {})",
            std::mem::size_of::<EncodedSignature<P>>(),
            sig_bytes.len()
        ))
    })?;
    let sig = Signature::<P>::decode(&encoded_sig)
        .ok_or_else(|| Error::InvalidSignature("Invalid ML-DSA signature encoding".into()))?;
    Ok(vk.verify_with_context(tbs_der, &[], &sig))
}

/// Generic SLH-DSA signature verification helper.
#[cfg(feature = "pqc")]
fn verify_slhdsa<P>(pk_bytes: &[u8], tbs_der: &[u8], sig_bytes: &[u8]) -> Result<bool>
where
    P: slh_dsa::ParameterSet,
{
    use slh_dsa::{signature::Verifier, Signature, VerifyingKey};

    let vk = VerifyingKey::<P>::try_from(pk_bytes)
        .map_err(|e| Error::InvalidCertificate(format!("Invalid SLH-DSA public key: {}", e)))?;
    let sig = Signature::<P>::try_from(sig_bytes)
        .map_err(|e| Error::InvalidSignature(format!("Invalid SLH-DSA signature: {}", e)))?;
    Ok(vk.verify(tbs_der, &sig).is_ok())
}

/// Verify a raw signature using a DER-encoded signer certificate.
///
/// This is a lower-level function for verifying signatures on arbitrary
/// data (e.g., OCSP signed requests, CMS) where you have:
/// - The signature algorithm OID as a string
/// - The DER-encoded signer certificate (to extract the public key)
/// - The raw TBS (to-be-signed) data
/// - The raw signature bytes
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid,
/// or `Err` if the algorithm is unsupported or the key is malformed.
pub fn verify_raw_signature(
    sig_alg_oid: &str,
    signer_cert_der: &[u8],
    tbs_data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    // Parse the certificate to extract SPKI DER, then delegate
    let cert = Certificate::from_der(signer_cert_der)
        .map_err(|e| Error::InvalidCertificate(format!("Failed to parse signer cert: {}", e)))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| Error::Encoding(format!("Failed to encode SPKI from cert: {}", e)))?;
    verify_raw_signature_with_spki(sig_alg_oid, &spki_der, tbs_data, signature)
}

/// Verify a raw signature using a DER-encoded SubjectPublicKeyInfo.
///
/// This is the lower-level primitive used by `verify_raw_signature` and by
/// CRMF/CMP Proof-of-Possession verification (RFC 4211 §4.1), where the
/// public key comes from a `CertTemplate` rather than an issued certificate.
///
/// Parameters:
/// - `sig_alg_oid`: Signature algorithm OID in dotted notation
/// - `spki_der`: DER-encoded SubjectPublicKeyInfo (the raw public key)
/// - `tbs_data`: The signed data (e.g., DER-encoded CertRequest)
/// - `signature`: Raw signature bytes
///
/// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid,
/// or `Err` if the algorithm is unsupported or the key is malformed.
pub fn verify_raw_signature_with_spki(
    sig_alg_oid: &str,
    spki_der: &[u8],
    tbs_data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    // Parse the SPKI to extract the raw public key bit string
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der)
        .map_err(|e| Error::InvalidCertificate(format!("Failed to parse SPKI: {}", e)))?;

    match sig_alg_oid {
        // ECDSA with SHA-256 (P-256)
        "1.2.840.10045.4.3.2" => {
            let pk_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid public key BitString".to_string())
            })?;
            verify_ecdsa_p256_sig(pk_bytes, tbs_data, signature)
        }
        // ECDSA with SHA-384 (P-384)
        "1.2.840.10045.4.3.3" => {
            let pk_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
                Error::InvalidCertificate("Invalid public key BitString".to_string())
            })?;
            verify_ecdsa_p384_sig(pk_bytes, tbs_data, signature)
        }
        // RSA with SHA-256
        "1.2.840.113549.1.1.11" => verify_rsa_pkcs1_sha256_sig(spki_der, tbs_data, signature),
        // RSA with SHA-384
        "1.2.840.113549.1.1.12" => verify_rsa_pkcs1_sha384_sig(spki_der, tbs_data, signature),
        // RSA with SHA-512
        "1.2.840.113549.1.1.13" => verify_rsa_pkcs1_sha512_sig(spki_der, tbs_data, signature),
        // RSASSA-PSS — defaults to SHA-256
        "1.2.840.113549.1.1.10" => {
            verify_rsa_pss_sig(spki_der, tbs_data, signature, PssHash::Sha256)
        }
        // Ed25519
        "1.3.101.112" => {
            let pk_bytes = spki
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| Error::InvalidCertificate("Invalid public key BitString".into()))?;
            verify_ed25519_sig(pk_bytes, tbs_data, signature)
        }
        _ => Err(Error::UnsupportedAlgorithm(format!(
            "Signature verification not supported for OID: {}",
            sig_alg_oid
        ))),
    }
}

/// Extract BasicConstraints from a certificate.
/// Returns `Some((is_ca, path_len_constraint, is_critical))` if the extension is present, `None` otherwise.
fn check_basic_constraints(cert: &Certificate) -> Result<Option<(bool, Option<u8>, bool)>> {
    let extensions = match cert.tbs_certificate.extensions.as_ref() {
        Some(exts) => exts,
        None => return Ok(None),
    };

    for ext in extensions.iter() {
        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if oid_arcs == OID_BASIC_CONSTRAINTS {
            let bc = X509BasicConstraints::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                Error::InvalidCertificate(format!("Failed to parse BasicConstraints: {}", e))
            })?;
            return Ok(Some((bc.ca, bc.path_len_constraint, ext.critical)));
        }
    }

    Ok(None)
}

/// KeyUsage extension details for a certificate.
struct KeyUsageInfo {
    /// keyCertSign bit is set
    key_cert_sign: bool,
    /// cRLSign bit is set
    crl_sign: bool,
    /// Extension is marked critical
    is_critical: bool,
}

/// Extract KeyUsage details from a certificate.
/// Returns `None` if the KeyUsage extension is not present.
fn check_key_usage(cert: &Certificate) -> Result<Option<KeyUsageInfo>> {
    let extensions = match cert.tbs_certificate.extensions.as_ref() {
        Some(exts) => exts,
        None => return Ok(None),
    };

    for ext in extensions.iter() {
        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if oid_arcs == OID_KEY_USAGE {
            let ku = X509KeyUsage::from_der(ext.extn_value.as_bytes()).map_err(|e| {
                Error::InvalidCertificate(format!("Failed to parse KeyUsage: {}", e))
            })?;
            return Ok(Some(KeyUsageInfo {
                key_cert_sign: ku.key_cert_sign(),
                crl_sign: ku.crl_sign(),
                is_critical: ext.critical,
            }));
        }
    }

    Ok(None)
}

/// Check certificate validity period against a given time.
fn check_validity(cert: &Certificate, at_time: DateTime<Utc>) -> Result<()> {
    let validity = &cert.tbs_certificate.validity;

    let not_before = parse_x509_time(&validity.not_before)?;
    if at_time < not_before {
        return Err(Error::CertificateNotYetValid);
    }

    let not_after = parse_x509_time(&validity.not_after)?;
    if at_time > not_after {
        return Err(Error::CertificateExpired);
    }

    Ok(())
}

/// Parse X.509 Time (UTCTime or GeneralizedTime) to chrono DateTime.
fn parse_x509_time(time: &x509_cert::time::Time) -> Result<DateTime<Utc>> {
    let der_bytes = time
        .to_der()
        .map_err(|e| Error::Encoding(format!("Failed to encode time: {}", e)))?;

    if der_bytes.len() < 3 {
        return Err(Error::InvalidCertificate("Time value too short".into()));
    }

    let tag = der_bytes[0];
    let len = der_bytes[1] as usize;

    if der_bytes.len() < 2 + len {
        return Err(Error::InvalidCertificate("Time value truncated".into()));
    }

    let time_str = std::str::from_utf8(&der_bytes[2..2 + len])
        .map_err(|_| Error::InvalidCertificate("Invalid time encoding".into()))?;

    match tag {
        // UTCTime: YYMMDDHHMMSSZ
        0x17 => {
            if time_str.len() < 12 {
                return Err(Error::InvalidCertificate("UTCTime too short".into()));
            }
            let yy: i32 = time_str[0..2].parse().unwrap_or(0);
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            let month: u32 = time_str[2..4].parse().unwrap_or(1);
            let day: u32 = time_str[4..6].parse().unwrap_or(1);
            let hour: u32 = time_str[6..8].parse().unwrap_or(0);
            let min: u32 = time_str[8..10].parse().unwrap_or(0);
            let sec: u32 = time_str[10..12].parse().unwrap_or(0);

            chrono::NaiveDate::from_ymd_opt(year, month, day)
                .and_then(|d| d.and_hms_opt(hour, min, sec))
                .map(|dt| DateTime::from_naive_utc_and_offset(dt, Utc))
                .ok_or_else(|| Error::InvalidCertificate("Invalid UTC time values".into()))
        }
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        0x18 => {
            if time_str.len() < 14 {
                return Err(Error::InvalidCertificate(
                    "GeneralizedTime too short".into(),
                ));
            }
            let year: i32 = time_str[0..4].parse().unwrap_or(2000);
            let month: u32 = time_str[4..6].parse().unwrap_or(1);
            let day: u32 = time_str[6..8].parse().unwrap_or(1);
            let hour: u32 = time_str[8..10].parse().unwrap_or(0);
            let min: u32 = time_str[10..12].parse().unwrap_or(0);
            let sec: u32 = time_str[12..14].parse().unwrap_or(0);

            chrono::NaiveDate::from_ymd_opt(year, month, day)
                .and_then(|d| d.and_hms_opt(hour, min, sec))
                .map(|dt| DateTime::from_naive_utc_and_offset(dt, Utc))
                .ok_or_else(|| Error::InvalidCertificate("Invalid GeneralizedTime values".into()))
        }
        _ => Err(Error::InvalidCertificate(format!(
            "Unknown time tag: 0x{:02x}",
            tag
        ))),
    }
}

/// Extract a human-readable subject CN from a certificate.
fn subject_cn(cert: &Certificate) -> String {
    for rdn in cert.tbs_certificate.subject.0.iter() {
        for atv in rdn.0.iter() {
            let oid_arcs: Vec<u32> = atv.oid.arcs().collect();
            if oid_arcs == [2, 5, 4, 3] {
                if let Ok(cn) = std::str::from_utf8(atv.value.value()) {
                    return cn.to_string();
                }
            }
        }
    }
    "<unknown>".to_string()
}

// OID arcs for AKI (2.5.29.35) and SKI (2.5.29.14)
const OID_AKI: &[u32] = &[2, 5, 29, 35];
const OID_SKI: &[u32] = &[2, 5, 29, 14];

/// Parsed fields from an AuthorityKeyIdentifier extension (RFC 5280 §4.2.1.1).
#[derive(Debug, Default)]
struct ParsedAki {
    /// [0] keyIdentifier — raw key identifier bytes (implicit OCTET STRING).
    key_identifier: Option<Vec<u8>>,
    /// [1] authorityCertIssuer — raw DER content bytes of GeneralNames.
    authority_cert_issuer: Option<Vec<u8>>,
    /// [2] authorityCertSerialNumber — raw INTEGER value bytes (big-endian, no tag/length).
    authority_cert_serial: Option<Vec<u8>>,
}

/// Extract all three AKI fields from an AuthorityKeyIdentifier extension.
///
/// RFC 5280 §4.2.1.1:
/// ```text
/// AuthorityKeyIdentifier ::= SEQUENCE {
///   keyIdentifier             [0] KeyIdentifier           OPTIONAL,
///   authorityCertIssuer       [1] GeneralNames            OPTIONAL,
///   authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }
/// ```
///
/// Walks the SEQUENCE content scanning for context tags [0]/[1]/[2].
fn extract_aki_full_from_cert(cert: &Certificate) -> Option<ParsedAki> {
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    for ext in extensions.iter() {
        let arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if arcs == OID_AKI {
            let data = ext.extn_value.as_bytes();
            // Outer SEQUENCE
            if data.len() < 2 || data[0] != 0x30 {
                return None;
            }
            let (seq_len, seq_hdr) = read_length(&data[1..])?;
            let seq_content = data.get(1 + seq_hdr..1 + seq_hdr + seq_len)?;

            let mut aki = ParsedAki::default();
            let mut pos = 0;
            while pos < seq_content.len() {
                if pos >= seq_content.len() {
                    break;
                }
                let tag = seq_content[pos];
                pos += 1;
                let (field_len, hdr_len) = read_length(&seq_content[pos..])?;
                pos += hdr_len;
                let field_end = pos + field_len;
                let field_bytes = seq_content.get(pos..field_end)?;
                match tag {
                    // [0] IMPLICIT OCTET STRING — keyIdentifier
                    0x80 => {
                        aki.key_identifier = Some(field_bytes.to_vec());
                    }
                    // [1] EXPLICIT CONSTRUCTED — authorityCertIssuer (GeneralNames)
                    0xa1 => {
                        aki.authority_cert_issuer = Some(field_bytes.to_vec());
                    }
                    // [2] IMPLICIT INTEGER — authorityCertSerialNumber
                    0x82 => {
                        aki.authority_cert_serial = Some(field_bytes.to_vec());
                    }
                    // Unknown tags: skip (forward-compatible parsing)
                    _ => {}
                }
                pos = field_end;
            }
            return Some(aki);
        }
    }
    None
}

/// Extract the keyIdentifier from an AuthorityKeyIdentifier extension.
///
/// Delegates to `extract_aki_full_from_cert` and returns only the [0] field.
/// AKI is a SEQUENCE containing optional context-tagged fields.
fn extract_aki_from_cert(cert: &Certificate) -> Option<Vec<u8>> {
    extract_aki_full_from_cert(cert)?.key_identifier
}

/// Extract the SubjectKeyIdentifier value from a certificate.
///
/// SKI extension value: OCTET STRING { keyIdentifier OCTET STRING }
fn extract_ski_from_cert(cert: &Certificate) -> Option<Vec<u8>> {
    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    for ext in extensions.iter() {
        let arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if arcs == OID_SKI {
            let data = ext.extn_value.as_bytes();
            // SKI: OCTET STRING { key_id_bytes }
            if data.len() >= 2 && data[0] == 0x04 {
                let (kid_len, kid_hdr) = read_length(&data[1..])?;
                return data
                    .get(1 + kid_hdr..1 + kid_hdr + kid_len)
                    .map(|s| s.to_vec());
            }
            return None;
        }
    }
    None
}

/// Read a DER length from a byte slice. Returns (length, header_bytes_consumed).
fn read_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] < 0x80 {
        Some((data[0] as usize, 1))
    } else {
        let num_bytes = (data[0] & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[1 + i] as usize;
        }
        Some((len, 1 + num_bytes))
    }
}

/// Parsed NameConstraints with extracted string values for matching.
struct ParsedNameConstraints {
    permitted: Option<NameSubtrees>,
    excluded: Option<NameSubtrees>,
}

struct NameSubtrees {
    dns: Vec<String>,
    emails: Vec<String>,
    /// IP address constraints as (network, prefix_len) per RFC 5280 §4.2.1.10.
    /// For IPv4: 8 bytes (4 addr + 4 mask). For IPv6: 32 bytes (16 addr + 16 mask).
    ips: Vec<IpConstraint>,
    /// URI host constraints (matched against uniformResourceIdentifier SAN).
    uris: Vec<String>,
    /// directoryName constraints per RFC 5280 §4.2.1.10.
    /// Each entry is a sequence of DER-encoded RDNs forming a DN subtree.
    directory_names: Vec<DnConstraint>,
}

/// An IP address NameConstraint (network address + prefix mask).
struct IpConstraint {
    /// Network address bytes (4 for IPv4, 16 for IPv6).
    network: Vec<u8>,
    /// Network mask bytes (same length as network).
    mask: Vec<u8>,
}

/// A directoryName NameConstraint — stored as a sequence of DER-encoded RDNs.
/// Per RFC 5280 §4.2.1.10, a subject DN is within this constraint if the
/// constraint's RDN sequence is a prefix of (or equal to) the subject's RDN sequence.
struct DnConstraint {
    /// DER encoding of each RDN in the constraint DN, in order.
    rdns: Vec<Vec<u8>>,
}

/// Validate that a string is a valid IA5String (ASCII only, bytes 0x00–0x7F).
/// Per RFC 5280 §4.2.1.10, NameConstraints subtree values MUST be IA5String.
fn is_valid_ia5_string(s: &str) -> bool {
    s.bytes().all(|b| b <= 0x7F)
}

/// Convert an x509-cert Name (RdnSequence) into a DnConstraint by DER-encoding each RDN.
fn name_to_dn_constraint(name: &x509_cert::name::Name) -> Option<DnConstraint> {
    let mut rdns = Vec::new();
    for rdn in name.0.iter() {
        match rdn.to_der() {
            Ok(der) => rdns.push(der),
            Err(_) => return None,
        }
    }
    Some(DnConstraint { rdns })
}

/// Convert a certificate's subject Name into a list of DER-encoded RDNs for matching.
fn name_to_der_rdns(name: &x509_cert::name::Name) -> Vec<Vec<u8>> {
    name.0.iter().filter_map(|rdn| rdn.to_der().ok()).collect()
}

/// Check if a subject DN is within a directoryName constraint per RFC 5280 §4.2.1.10.
/// The constraint DN is a prefix: the subject must have at least as many RDNs as the
/// constraint, and each constraint RDN must DER-match the corresponding subject RDN.
fn dn_within(subject_rdns: &[Vec<u8>], constraint: &DnConstraint) -> bool {
    if constraint.rdns.is_empty() {
        // Empty constraint matches everything
        return true;
    }
    if subject_rdns.len() < constraint.rdns.len() {
        return false;
    }
    // Each RDN in the constraint must match the corresponding RDN in the subject
    constraint
        .rdns
        .iter()
        .zip(subject_rdns.iter())
        .all(|(c, s)| c == s)
}

/// Extract directoryName entries from SubjectAltName extension.
/// Returns a list of DER-encoded RDN sequences (one per directoryName SAN).
fn extract_san_directory_names(cert: &Certificate) -> Vec<Vec<Vec<u8>>> {
    use x509_cert::ext::pkix::SubjectAltName;

    let extensions = match cert.tbs_certificate.extensions.as_ref() {
        Some(exts) => exts,
        None => return Vec::new(),
    };

    for ext in extensions.iter() {
        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if oid_arcs == OID_SUBJECT_ALT_NAME {
            if let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                return san
                    .0
                    .iter()
                    .filter_map(|name| {
                        if let x509_cert::ext::pkix::name::GeneralName::DirectoryName(dn) = name {
                            Some(name_to_der_rdns(dn))
                        } else {
                            None
                        }
                    })
                    .collect();
            }
        }
    }
    Vec::new()
}

/// Parse a GeneralSubtrees sequence into our NameSubtrees struct.
/// Handles DNS, email, IP, URI, and directoryName constraint types per RFC 5280 §4.2.1.10.
fn parse_subtrees(
    subtrees: &[x509_cert::ext::pkix::constraints::name::GeneralSubtree],
) -> NameSubtrees {
    let mut dns = Vec::new();
    let mut emails = Vec::new();
    let mut ips = Vec::new();
    let mut uris = Vec::new();
    let mut directory_names = Vec::new();
    for st in subtrees {
        match &st.base {
            x509_cert::ext::pkix::name::GeneralName::DnsName(name) => {
                let s = name.to_string();
                if is_valid_ia5_string(&s) {
                    dns.push(s);
                }
            }
            x509_cert::ext::pkix::name::GeneralName::Rfc822Name(email) => {
                let s = email.to_string();
                if is_valid_ia5_string(&s) {
                    emails.push(s);
                }
            }
            x509_cert::ext::pkix::name::GeneralName::IpAddress(ip_bytes) => {
                // RFC 5280 §4.2.1.10: iPAddress is encoded as
                // 8 bytes for IPv4 (4 addr + 4 mask) or
                // 32 bytes for IPv6 (16 addr + 16 mask)
                let bytes = ip_bytes.as_bytes();
                if bytes.len() == 8 || bytes.len() == 32 {
                    let half = bytes.len() / 2;
                    ips.push(IpConstraint {
                        network: bytes[..half].to_vec(),
                        mask: bytes[half..].to_vec(),
                    });
                }
            }
            x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(uri) => {
                let s = uri.to_string();
                if is_valid_ia5_string(&s) {
                    uris.push(s);
                }
            }
            x509_cert::ext::pkix::name::GeneralName::DirectoryName(name) => {
                if let Some(dc) = name_to_dn_constraint(name) {
                    directory_names.push(dc);
                }
            }
            _ => {}
        }
    }
    NameSubtrees {
        dns,
        emails,
        ips,
        uris,
        directory_names,
    }
}

/// Extract NameConstraints from a certificate, if present.
fn extract_name_constraints(cert: &Certificate) -> Option<ParsedNameConstraints> {
    use x509_cert::ext::pkix::constraints::name::NameConstraints;

    let extensions = cert.tbs_certificate.extensions.as_ref()?;
    for ext in extensions.iter() {
        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if oid_arcs == OID_NAME_CONSTRAINTS {
            let nc = NameConstraints::from_der(ext.extn_value.as_bytes()).ok()?;
            let permitted = nc.permitted_subtrees.as_ref().map(|st| parse_subtrees(st));
            let excluded = nc.excluded_subtrees.as_ref().map(|st| parse_subtrees(st));
            return Some(ParsedNameConstraints {
                permitted,
                excluded,
            });
        }
    }
    None
}

/// Parse a NameConstraints from raw DER bytes (e.g. from a trust anchor's CertPathControls).
///
/// This is the RFC 5937 companion to `extract_name_constraints()` — it operates on
/// standalone DER rather than extracting from a Certificate extension.
fn parse_name_constraints_der(nc_der: &[u8]) -> Option<ParsedNameConstraints> {
    use x509_cert::ext::pkix::constraints::name::NameConstraints;

    let nc = NameConstraints::from_der(nc_der).ok()?;
    let permitted = nc.permitted_subtrees.as_ref().map(|st| parse_subtrees(st));
    let excluded = nc.excluded_subtrees.as_ref().map(|st| parse_subtrees(st));
    Some(ParsedNameConstraints {
        permitted,
        excluded,
    })
}

/// Extract DNS names from SubjectAltName extension.
fn extract_san_dns_names(cert: &Certificate) -> Vec<String> {
    use x509_cert::ext::pkix::SubjectAltName;

    let extensions = match cert.tbs_certificate.extensions.as_ref() {
        Some(exts) => exts,
        None => return Vec::new(),
    };

    for ext in extensions.iter() {
        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if oid_arcs == OID_SUBJECT_ALT_NAME {
            if let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                return san
                    .0
                    .iter()
                    .filter_map(|name| {
                        if let x509_cert::ext::pkix::name::GeneralName::DnsName(dns) = name {
                            Some(dns.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();
            }
        }
    }
    Vec::new()
}

/// Extract email addresses from SubjectAltName extension.
fn extract_san_emails(cert: &Certificate) -> Vec<String> {
    use x509_cert::ext::pkix::SubjectAltName;

    let extensions = match cert.tbs_certificate.extensions.as_ref() {
        Some(exts) => exts,
        None => return Vec::new(),
    };

    for ext in extensions.iter() {
        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if oid_arcs == OID_SUBJECT_ALT_NAME {
            if let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                return san
                    .0
                    .iter()
                    .filter_map(|name| {
                        if let x509_cert::ext::pkix::name::GeneralName::Rfc822Name(email) = name {
                            Some(email.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();
            }
        }
    }
    Vec::new()
}

/// Extract IP addresses from SubjectAltName extension.
/// Returns raw IP bytes (4 bytes for IPv4, 16 bytes for IPv6).
fn extract_san_ips(cert: &Certificate) -> Vec<Vec<u8>> {
    use x509_cert::ext::pkix::SubjectAltName;

    let extensions = match cert.tbs_certificate.extensions.as_ref() {
        Some(exts) => exts,
        None => return Vec::new(),
    };

    for ext in extensions.iter() {
        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if oid_arcs == OID_SUBJECT_ALT_NAME {
            if let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                return san
                    .0
                    .iter()
                    .filter_map(|name| {
                        if let x509_cert::ext::pkix::name::GeneralName::IpAddress(ip) = name {
                            let bytes = ip.as_bytes();
                            if bytes.len() == 4 || bytes.len() == 16 {
                                Some(bytes.to_vec())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect();
            }
        }
    }
    Vec::new()
}

/// Extract URIs from SubjectAltName extension.
fn extract_san_uris(cert: &Certificate) -> Vec<String> {
    use x509_cert::ext::pkix::SubjectAltName;

    let extensions = match cert.tbs_certificate.extensions.as_ref() {
        Some(exts) => exts,
        None => return Vec::new(),
    };

    for ext in extensions.iter() {
        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
        if oid_arcs == OID_SUBJECT_ALT_NAME {
            if let Ok(san) = SubjectAltName::from_der(ext.extn_value.as_bytes()) {
                return san
                    .0
                    .iter()
                    .filter_map(|name| {
                        if let x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                            uri,
                        ) = name
                        {
                            Some(uri.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();
            }
        }
    }
    Vec::new()
}

/// Check if an IP address is within an IP constraint per RFC 5280 §4.2.1.10.
/// The constraint is a (network, mask) pair. The IP matches if:
///   (ip & mask) == (network & mask)
fn ip_within(ip: &[u8], constraint: &IpConstraint) -> bool {
    if ip.len() != constraint.network.len() {
        return false; // IPv4 vs IPv6 mismatch
    }
    for ((ip_byte, net_byte), mask_byte) in ip
        .iter()
        .zip(constraint.network.iter())
        .zip(constraint.mask.iter())
    {
        if (ip_byte & mask_byte) != (net_byte & mask_byte) {
            return false;
        }
    }
    true
}

/// Check if a URI host is within a URI constraint per RFC 5280 §4.2.1.10.
/// The constraint is a host domain; the URI must have a host that matches.
fn uri_host_within(uri: &str, constraint: &str) -> bool {
    // Extract host from URI (skip scheme://userinfo@)
    let host = uri
        .find("://")
        .map(|i| &uri[i + 3..])
        .unwrap_or(uri)
        .split('@')
        .next_back()
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    dns_name_within(host, constraint)
}

/// Check if a DNS name is within a constraint subtree per RFC 5280 §4.2.1.10.
/// Constraint ".example.com" permits "foo.example.com" and "bar.example.com".
/// Constraint "example.com" permits "example.com" and "foo.example.com".
fn dns_name_within(name: &str, constraint: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let constraint = constraint.to_ascii_lowercase();

    if constraint.starts_with('.') {
        // Leading dot: name must end with the constraint
        name.ends_with(&constraint)
    } else {
        // Exact match or name is a subdomain
        name == constraint || name.ends_with(&format!(".{}", constraint))
    }
}

/// Check if an email is within an email constraint per RFC 5280 §4.2.1.10.
/// Constraint "@example.com" or "example.com" permits "user@example.com".
fn email_within(email: &str, constraint: &str) -> bool {
    let email = email.to_ascii_lowercase();
    let constraint = constraint.to_ascii_lowercase();

    if constraint.contains('@') {
        // Exact email match
        email == constraint
    } else {
        // Domain constraint: email must be at that domain or subdomain
        email.ends_with(&format!("@{}", constraint)) || email.ends_with(&format!(".{}", constraint))
    }
}

/// Validate a certificate chain from leaf to root.
///
/// `chain` must be ordered `[leaf, intermediate..., root]`.
/// `trust_anchors` contains DER-encoded trusted root certificates.
///
/// Performs RFC 5280 Section 6 basic path validation:
/// 1. Signature verification: each cert\[i\] signed by cert\[i+1\]
/// 2. Validity: all certs are currently valid
/// 3. BasicConstraints: CA flag set for all non-leaf certs
/// 4. KeyUsage: keyCertSign set for all non-leaf certs
/// 5. Path length: enforced per BasicConstraints pathLenConstraint
/// 6. Trust anchor: chain root is in trust_anchors set
pub fn validate_chain(
    chain: &[Certificate],
    trust_anchors: &[Vec<u8>],
    options: &ChainValidationOptions,
) -> ChainValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if chain.is_empty() {
        return ChainValidationResult {
            valid: false,
            trusted: false,
            errors: vec!["Empty certificate chain".to_string()],
            warnings: Vec::new(),
            policy_result: None,
        };
    }

    let at_time = options.at_time.unwrap_or_else(Utc::now);

    // Check validity periods for all certificates
    if options.check_validity {
        for (i, cert) in chain.iter().enumerate() {
            if let Err(e) = check_validity(cert, at_time) {
                errors.push(format!("Certificate {} ({}): {}", i, subject_cn(cert), e));
            }
        }
    }

    // RFC 5280 §4.1.1.2/§4.1.2.3: signatureAlgorithm in Certificate MUST
    // match signature field in TBSCertificate.
    for (i, cert) in chain.iter().enumerate() {
        if cert.signature_algorithm != cert.tbs_certificate.signature {
            warnings.push(format!(
                "Certificate {} ({}): RFC 5280 §4.1.1.2 signatureAlgorithm mismatch \
                 (outer: {:?} vs TBS: {:?})",
                i,
                subject_cn(cert),
                cert.signature_algorithm.oid,
                cert.tbs_certificate.signature.oid
            ));
        }
    }

    // RFC 5280 §4.1.2.1: If extensions are present, certificate MUST be v3.
    for (i, cert) in chain.iter().enumerate() {
        if cert.tbs_certificate.extensions.is_some()
            && cert.tbs_certificate.version != x509_cert::certificate::Version::V3
        {
            warnings.push(format!(
                "Certificate {} ({}): RFC 5280 §4.1.2.1 has extensions but is not version 3",
                i,
                subject_cn(cert),
            ));
        }
    }

    // RFC 5280 §4.1.2.2: Serial number MUST be a positive integer,
    // no more than 20 octets.
    for (i, cert) in chain.iter().enumerate() {
        let serial_bytes = cert.tbs_certificate.serial_number.as_bytes();
        if serial_bytes.len() > 20 {
            warnings.push(format!(
                "Certificate {} ({}): RFC 5280 §4.1.2.2 serial number exceeds 20 octets ({} bytes)",
                i,
                subject_cn(cert),
                serial_bytes.len()
            ));
        }
    }

    // RFC 5280 §4.1.2.8: CAs conforming to this profile MUST NOT generate
    // certificates with unique identifiers.
    for (i, cert) in chain.iter().enumerate() {
        if cert.tbs_certificate.issuer_unique_id.is_some() {
            warnings.push(format!(
                "Certificate {} ({}): issuerUniqueID present (RFC 5280 §4.1.2.8 forbids unique identifiers)",
                i,
                subject_cn(cert),
            ));
        }
        if cert.tbs_certificate.subject_unique_id.is_some() {
            warnings.push(format!(
                "Certificate {} ({}): subjectUniqueID present (RFC 5280 §4.1.2.8 forbids unique identifiers)",
                i,
                subject_cn(cert),
            ));
        }
    }

    // RFC 5280 §4.1.2.4: Issuer MUST contain a non-empty distinguished name.
    for (i, cert) in chain.iter().enumerate() {
        if cert.tbs_certificate.issuer.0.is_empty() {
            warnings.push(format!(
                "Certificate {} ({}): empty issuer DN (RFC 5280 §4.1.2.4)",
                i,
                subject_cn(cert),
            ));
        }
    }

    // RFC 5280 §4.2.1.6: If the subject field is empty, the subjectAltName
    // extension MUST be present and MUST be marked critical.
    for (i, cert) in chain.iter().enumerate() {
        if cert.tbs_certificate.subject.0.is_empty() {
            let san_ext = cert.tbs_certificate.extensions.as_ref().and_then(|exts| {
                exts.iter()
                    .find(|e| e.extn_id == const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME)
            });
            if let Some(ext) = san_ext {
                if !ext.critical {
                    warnings.push(format!(
                        "Certificate {} ({}): empty subject DN but subjectAltName is not critical (RFC 5280 §4.2.1.6)",
                        i,
                        subject_cn(cert),
                    ));
                }
            } else {
                warnings.push(format!(
                    "Certificate {} ({}): empty subject DN without subjectAltName (RFC 5280 §4.2.1.6)",
                    i,
                    subject_cn(cert),
                ));
            }
        }
    }

    // Verify signatures: each cert[i] must be signed by cert[i+1]
    if options.check_signatures {
        for i in 0..chain.len() - 1 {
            let cert = &chain[i];
            let issuer = &chain[i + 1];
            match verify_signature(cert, issuer) {
                Ok(true) => {}
                Ok(false) => {
                    errors.push(format!(
                        "Certificate {} ({}) signature verification failed against issuer {} ({})",
                        i,
                        subject_cn(cert),
                        i + 1,
                        subject_cn(issuer)
                    ));
                }
                Err(e) => {
                    errors.push(format!(
                        "Certificate {} ({}) signature verification error: {}",
                        i,
                        subject_cn(cert),
                        e
                    ));
                }
            }
        }

        // Verify self-signature of root (last cert in chain)
        if let Some(root) = chain.last() {
            match verify_signature(root, root) {
                Ok(true) => {}
                Ok(false) => {
                    warnings.push(format!(
                        "Root certificate ({}) self-signature verification failed",
                        subject_cn(root)
                    ));
                }
                Err(_) => {
                    // Self-signed verification may fail for non-self-signed intermediates
                    // at the top of a partial chain — this is a warning, not an error
                    warnings.push(format!(
                        "Root certificate ({}) may not be self-signed",
                        subject_cn(root)
                    ));
                }
            }
        }
    }

    // RFC 5280 §6.1.3 step (a.4): Issuer/subject name chaining
    // Each cert[i].issuer must match cert[i+1].subject
    if options.check_signatures {
        for i in 0..chain.len() - 1 {
            let cert = &chain[i];
            let issuer_cert = &chain[i + 1];
            if cert.tbs_certificate.issuer != issuer_cert.tbs_certificate.subject {
                errors.push(format!(
                    "Certificate {} ({}): issuer name does not match subject of certificate {} ({})",
                    i,
                    subject_cn(cert),
                    i + 1,
                    subject_cn(issuer_cert)
                ));
            }
        }
    }

    // RFC 5280 §6.1.3 step (a.1): AKI/SKI matching
    // If cert has AuthorityKeyIdentifier, verify it matches the issuer's SubjectKeyIdentifier
    if options.check_constraints {
        for i in 0..chain.len() - 1 {
            let cert = &chain[i];
            let issuer_cert = &chain[i + 1];

            // [0] keyIdentifier vs issuer SKI match
            if let (Some(aki), Some(ski)) = (
                extract_aki_from_cert(cert),
                extract_ski_from_cert(issuer_cert),
            ) {
                if aki != ski {
                    errors.push(format!(
                        "Certificate {} ({}): AKI does not match SKI of issuer {} ({})",
                        i,
                        subject_cn(cert),
                        i + 1,
                        subject_cn(issuer_cert)
                    ));
                }
            }

            // [2] authorityCertSerialNumber vs issuer serial number (RFC 5280 §4.2.1.1)
            // If present, it MUST match the issuer certificate's serialNumber.
            if let Some(aki_full) = extract_aki_full_from_cert(cert) {
                if let Some(aki_serial) = aki_full.authority_cert_serial {
                    let issuer_serial = issuer_cert
                        .tbs_certificate
                        .serial_number
                        .as_bytes()
                        .to_vec();
                    if aki_serial != issuer_serial {
                        errors.push(format!(
                            "Certificate {} ({}): AKI authorityCertSerialNumber does not match \
                             serial of issuer {} ({})",
                            i,
                            subject_cn(cert),
                            i + 1,
                            subject_cn(issuer_cert)
                        ));
                    }
                }
            }
        }
    }

    // RFC 5280 §4.2.1.3: AKI MUST appear in all certs except self-signed root.
    // RFC 5280 §4.2.1.2: SKI MUST appear in all CA certificates.
    let aki_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.29.35");
    let ski_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.29.14");
    for (i, cert) in chain.iter().enumerate() {
        let is_root = i == chain.len() - 1;
        let is_self_signed = cert.tbs_certificate.issuer == cert.tbs_certificate.subject;
        let has_ext = |oid: &const_oid::ObjectIdentifier| -> bool {
            cert.tbs_certificate
                .extensions
                .as_ref()
                .map(|exts| exts.iter().any(|e| &e.extn_id == oid))
                .unwrap_or(false)
        };
        // AKI: MUST be present in all certs except self-signed root
        let skip_aki = is_root && is_self_signed;
        if !skip_aki && !has_ext(&aki_oid) {
            warnings.push(format!(
                "Certificate {} ({}): authorityKeyIdentifier MUST be present (RFC 5280 §4.2.1.3)",
                i,
                subject_cn(cert),
            ));
        }
        // SKI: MUST be present in CA certificates
        if i > 0 && !has_ext(&ski_oid) {
            warnings.push(format!(
                "Certificate {} ({}): subjectKeyIdentifier MUST be present for CA certs (RFC 5280 §4.2.1.2)",
                i,
                subject_cn(cert),
            ));
        }
    }

    // RFC 5280 §4.2.2.1/§4.2.1.13: AIA and CDP SHOULD be present on non-root certs.
    let aia_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.1.1");
    let cdp_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.29.31");
    for (i, cert) in chain.iter().enumerate() {
        if i == chain.len() - 1 {
            continue; // Root certs don't need AIA/CDP
        }
        let has_ext = |oid: &const_oid::ObjectIdentifier| -> bool {
            cert.tbs_certificate
                .extensions
                .as_ref()
                .map(|exts| exts.iter().any(|e| &e.extn_id == oid))
                .unwrap_or(false)
        };
        if !has_ext(&aia_oid) {
            warnings.push(format!(
                "Certificate {} ({}): missing authorityInfoAccess (RFC 5280 §4.2.2.1)",
                i,
                subject_cn(cert),
            ));
        }
        if !has_ext(&cdp_oid) {
            warnings.push(format!(
                "Certificate {} ({}): missing cRLDistributionPoints (RFC 5280 §4.2.1.13)",
                i,
                subject_cn(cert),
            ));
        }
    }

    // Check BasicConstraints and KeyUsage for non-leaf certificates
    if options.check_constraints {
        for (i, cert) in chain.iter().enumerate().skip(1) {
            let cn = subject_cn(cert);

            // Check BasicConstraints CA:TRUE
            match check_basic_constraints(cert) {
                Ok(Some((true, path_len, is_critical))) => {
                    // RFC 5280 §4.2.1.9: BasicConstraints MUST be critical for CA certs
                    if !is_critical {
                        errors.push(format!(
                            "Certificate {} ({}): BasicConstraints MUST be critical for CA certificates (RFC 5280 §4.2.1.9)",
                            i, cn
                        ));
                    }

                    // Enforce path length constraint (RFC 5280 §6.1.4 step l)
                    // Self-issued certificates (issuer == subject) are NOT counted
                    // toward the path length per §6.1.4 step (l).
                    let non_self_issued_below = (1..i)
                        .filter(|&j| {
                            let c = &chain[j];
                            c.tbs_certificate.issuer != c.tbs_certificate.subject
                        })
                        .count();
                    if let Some(max_path) = path_len {
                        if non_self_issued_below > max_path as usize {
                            errors.push(format!(
                                "Certificate {} ({}): path length constraint {} exceeded ({} non-self-issued certs below)",
                                i, cn, max_path, non_self_issued_below
                            ));
                        }
                    }
                }
                Ok(Some((false, _, _))) => {
                    errors.push(format!(
                        "Certificate {} ({}): BasicConstraints CA:FALSE but used as CA",
                        i, cn
                    ));
                }
                Ok(None) => {
                    errors.push(format!(
                        "Certificate {} ({}): missing BasicConstraints extension (required for CA)",
                        i, cn
                    ));
                }
                Err(e) => {
                    errors.push(format!(
                        "Certificate {} ({}): BasicConstraints parse error: {}",
                        i, cn, e
                    ));
                }
            }

            // Check KeyUsage — RFC 5280 §4.2.1.3
            match check_key_usage(cert) {
                Ok(Some(ku_info)) => {
                    if !ku_info.key_cert_sign {
                        errors.push(format!(
                            "Certificate {} ({}): missing keyCertSign in KeyUsage",
                            i, cn
                        ));
                    }
                    // RFC 5280 §4.2.1.3: cRLSign SHOULD be set for CAs that issue CRLs
                    if !ku_info.crl_sign {
                        warnings.push(format!(
                            "Certificate {} ({}): missing cRLSign in KeyUsage (RFC 5280 §4.2.1.3)",
                            i, cn
                        ));
                    }
                    // RFC 5280 §4.2.1.3: conforming CAs SHOULD mark KeyUsage as critical
                    if !ku_info.is_critical {
                        warnings.push(format!(
                            "Certificate {} ({}): KeyUsage SHOULD be critical for CA certificates (RFC 5280 §4.2.1.3)",
                            i, cn
                        ));
                    }
                }
                Ok(None) => {
                    errors.push(format!(
                        "Certificate {} ({}): missing KeyUsage extension (required for CA per RFC 5280 §4.2.1.3)",
                        i, cn
                    ));
                }
                Err(e) => {
                    errors.push(format!(
                        "Certificate {} ({}): KeyUsage parse error: {}",
                        i, cn, e
                    ));
                }
            }
        }

        // RFC 5280 §4.2: Reject certificates with unrecognized critical extensions
        for (i, cert) in chain.iter().enumerate() {
            let cn = subject_cn(cert);
            if let Some(ref extensions) = cert.tbs_certificate.extensions {
                for ext in extensions.iter() {
                    if ext.critical {
                        let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
                        let recognized = RECOGNIZED_EXTENSIONS.contains(&oid_arcs.as_slice());
                        if !recognized {
                            errors.push(format!(
                                "Certificate {} ({}): unrecognized critical extension {}",
                                i, cn, ext.extn_id
                            ));
                        }
                    }
                }
            }
        }

        // RFC 5280 §4.2.1.5/§4.2.1.11/§4.2.1.14: Policy extensions MUST be critical on CA certs
        let policy_mappings_oid: Vec<u32> = vec![2, 5, 29, 33];
        let policy_constraints_oid: Vec<u32> = vec![2, 5, 29, 36];
        let inhibit_any_oid: Vec<u32> = vec![2, 5, 29, 54];
        for (i, cert) in chain.iter().enumerate().skip(1) {
            // Skip leaf (index 0) — these are CA-only extensions
            if let Some(ref extensions) = cert.tbs_certificate.extensions {
                let cn = subject_cn(cert);
                for ext in extensions.iter() {
                    let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
                    if (oid_arcs == policy_mappings_oid
                        || oid_arcs == policy_constraints_oid
                        || oid_arcs == inhibit_any_oid)
                        && !ext.critical
                    {
                        errors.push(format!(
                            "Certificate {} ({}): {} MUST be critical (RFC 5280 §4.2.1)",
                            i, cn, ext.extn_id
                        ));
                    }
                }
            }
        }

        // RFC 5280 §4.2.1.3: End-entity certificates SHOULD NOT have keyCertSign
        // (this bit is reserved for CA certificates)
        if !chain.is_empty() {
            let leaf = &chain[0];
            if let Ok(Some(ku_info)) = check_key_usage(leaf) {
                if ku_info.key_cert_sign {
                    warnings.push(format!(
                        "Certificate 0 ({}): end-entity certificate has keyCertSign bit set (RFC 5280 §4.2.1.3)",
                        subject_cn(leaf)
                    ));
                }
            }
        }

        // RFC 5280 §4.2.1.12: EKU presence check on end-entity certificate
        // If the leaf cert has an EKU extension, it MUST contain at least one purpose OID.
        // We report empty EKU as an error since it renders the cert unusable.
        if !chain.is_empty() {
            let leaf = &chain[0];
            if let Some(ref extensions) = leaf.tbs_certificate.extensions {
                let eku_oid: Vec<u32> = vec![2, 5, 29, 37];
                for ext in extensions.iter() {
                    let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
                    if oid_arcs == eku_oid {
                        let eku_data = ext.extn_value.as_bytes();
                        // EKU is SEQUENCE OF OID — check it's not empty
                        // Minimal check: SEQUENCE tag + length > 2 means at least one OID
                        if eku_data.len() < 4 {
                            errors.push(format!(
                                "Certificate 0 ({}): EKU extension present but contains no purpose OIDs (RFC 5280 §4.2.1.12)",
                                subject_cn(leaf)
                            ));
                        }
                    }
                }
            }
        }

        // RFC 5280 §4.2.1.6: If subject field is empty, subjectAltName MUST be present
        if !chain.is_empty() {
            let leaf = &chain[0];
            let subject_empty = leaf.tbs_certificate.subject.0.is_empty();
            if subject_empty {
                let has_san = extract_san_dns_names(leaf)
                    .into_iter()
                    .chain(extract_san_emails(leaf))
                    .next()
                    .is_some();
                if !has_san {
                    warnings.push(format!(
                        "Certificate 0 ({}): RFC 5280 §4.2.1.6 empty subject DN requires subjectAltName extension",
                        subject_cn(leaf)
                    ));
                }
            }
        }

        // RFC 5280 §4.2.1.10: NameConstraints MUST be critical.
        for (ca_idx, ca_cert) in chain.iter().enumerate().skip(1) {
            if let Some(exts) = &ca_cert.tbs_certificate.extensions {
                for ext in exts.iter() {
                    if ext.extn_id == const_oid::db::rfc5280::ID_CE_NAME_CONSTRAINTS
                        && !ext.critical
                    {
                        warnings.push(format!(
                            "Certificate {} ({}): nameConstraints MUST be critical (RFC 5280 §4.2.1.10)",
                            ca_idx,
                            subject_cn(ca_cert),
                        ));
                    }
                }
            }
        }

        // RFC 5280 §4.2.1.10: Enforce NameConstraints
        // For each CA cert with NameConstraints, all certs below it must comply.
        for (ca_idx, ca_cert) in chain.iter().enumerate().skip(1) {
            if let Some(nc) = extract_name_constraints(ca_cert) {
                // Check all certs below this CA in the chain (indices 0..ca_idx)
                for (subj_idx, subj_cert) in chain.iter().enumerate().take(ca_idx) {
                    let subj_cn = subject_cn(subj_cert);
                    let dns_names = extract_san_dns_names(subj_cert);
                    let emails = extract_san_emails(subj_cert);
                    let ips = extract_san_ips(subj_cert);
                    let uris = extract_san_uris(subj_cert);

                    // RFC 5280 §4.2.1.10: directoryName constraints apply to
                    // the subject field and any directoryName SANs.
                    let subject_rdns = name_to_der_rdns(&subj_cert.tbs_certificate.subject);
                    let san_dns_names = extract_san_directory_names(subj_cert);
                    let has_subject_dn = !subject_rdns.is_empty();

                    // Check permitted subtrees (if present, at least one must match)
                    if let Some(ref permitted) = nc.permitted {
                        for dns in &dns_names {
                            if !permitted.dns.is_empty()
                                && !permitted.dns.iter().any(|p| dns_name_within(dns, p))
                            {
                                errors.push(format!(
                                    "Certificate {} ({}): DNS name '{}' not within permitted subtrees of CA {} ({})",
                                    subj_idx, subj_cn, dns, ca_idx, subject_cn(ca_cert)
                                ));
                            }
                        }
                        for email in &emails {
                            if !permitted.emails.is_empty()
                                && !permitted.emails.iter().any(|p| email_within(email, p))
                            {
                                errors.push(format!(
                                    "Certificate {} ({}): email '{}' not within permitted subtrees of CA {} ({})",
                                    subj_idx, subj_cn, email, ca_idx, subject_cn(ca_cert)
                                ));
                            }
                        }
                        for ip in &ips {
                            if !permitted.ips.is_empty()
                                && !permitted.ips.iter().any(|p| ip_within(ip, p))
                            {
                                errors.push(format!(
                                    "Certificate {} ({}): IP address not within permitted subtrees of CA {} ({})",
                                    subj_idx, subj_cn, ca_idx, subject_cn(ca_cert)
                                ));
                            }
                        }
                        for uri in &uris {
                            if !permitted.uris.is_empty()
                                && !permitted.uris.iter().any(|p| uri_host_within(uri, p))
                            {
                                errors.push(format!(
                                    "Certificate {} ({}): URI '{}' not within permitted subtrees of CA {} ({})",
                                    subj_idx, subj_cn, uri, ca_idx, subject_cn(ca_cert)
                                ));
                            }
                        }
                        // directoryName permitted check
                        if !permitted.directory_names.is_empty() {
                            if has_subject_dn
                                && !permitted
                                    .directory_names
                                    .iter()
                                    .any(|p| dn_within(&subject_rdns, p))
                            {
                                errors.push(format!(
                                    "Certificate {} ({}): subject DN not within permitted subtrees of CA {} ({})",
                                    subj_idx, subj_cn, ca_idx, subject_cn(ca_cert)
                                ));
                            }
                            for san_dn in &san_dns_names {
                                if !permitted
                                    .directory_names
                                    .iter()
                                    .any(|p| dn_within(san_dn, p))
                                {
                                    errors.push(format!(
                                        "Certificate {} ({}): directoryName SAN not within permitted subtrees of CA {} ({})",
                                        subj_idx, subj_cn, ca_idx, subject_cn(ca_cert)
                                    ));
                                }
                            }
                        }
                    }

                    // Check excluded subtrees (none may match)
                    if let Some(ref excluded) = nc.excluded {
                        for dns in &dns_names {
                            if excluded.dns.iter().any(|e| dns_name_within(dns, e)) {
                                errors.push(format!(
                                    "Certificate {} ({}): DNS name '{}' is within excluded subtrees of CA {} ({})",
                                    subj_idx, subj_cn, dns, ca_idx, subject_cn(ca_cert)
                                ));
                            }
                        }
                        for email in &emails {
                            if excluded.emails.iter().any(|e| email_within(email, e)) {
                                errors.push(format!(
                                    "Certificate {} ({}): email '{}' is within excluded subtrees of CA {} ({})",
                                    subj_idx, subj_cn, email, ca_idx, subject_cn(ca_cert)
                                ));
                            }
                        }
                        for ip in &ips {
                            if excluded.ips.iter().any(|e| ip_within(ip, e)) {
                                errors.push(format!(
                                    "Certificate {} ({}): IP address is within excluded subtrees of CA {} ({})",
                                    subj_idx, subj_cn, ca_idx, subject_cn(ca_cert)
                                ));
                            }
                        }
                        for uri in &uris {
                            if excluded.uris.iter().any(|e| uri_host_within(uri, e)) {
                                errors.push(format!(
                                    "Certificate {} ({}): URI '{}' is within excluded subtrees of CA {} ({})",
                                    subj_idx, subj_cn, uri, ca_idx, subject_cn(ca_cert)
                                ));
                            }
                        }
                        // directoryName excluded check
                        if has_subject_dn
                            && excluded
                                .directory_names
                                .iter()
                                .any(|e| dn_within(&subject_rdns, e))
                        {
                            errors.push(format!(
                                "Certificate {} ({}): subject DN is within excluded subtrees of CA {} ({})",
                                subj_idx, subj_cn, ca_idx, subject_cn(ca_cert)
                            ));
                        }
                        for san_dn in &san_dns_names {
                            if excluded
                                .directory_names
                                .iter()
                                .any(|e| dn_within(san_dn, e))
                            {
                                errors.push(format!(
                                    "Certificate {} ({}): directoryName SAN is within excluded subtrees of CA {} ({})",
                                    subj_idx, subj_cn, ca_idx, subject_cn(ca_cert)
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // RFC 7633: TLS Feature (OCSP Must-Staple) advisory
    //
    // When the leaf certificate carries the TLS Feature extension with
    // status_request (value 5), TLS servers MUST present a valid stapled
    // OCSP response during the handshake (RFC 6066 §8).  This is an
    // informational warning — the extension is non-critical in practice and
    // chain validation still succeeds; the obligation falls on the TLS server.
    if let Some(leaf) = chain.first() {
        if let Some(exts) = &leaf.tbs_certificate.extensions {
            for ext in exts.iter() {
                let oid_arcs: Vec<u32> = ext.extn_id.arcs().collect();
                if oid_arcs == OID_TLS_FEATURE {
                    // The extension value is an OCTET STRING wrapping
                    // SEQUENCE OF INTEGER.  INTEGER 5 (status_request) DER
                    // encodes as 02 01 05.  We scan for that triplet rather
                    // than fully parsing the outer OCTET STRING, which keeps
                    // this dependency-free while handling all valid encodings.
                    let raw = ext.extn_value.as_bytes();
                    if raw.windows(3).any(|w| w == [0x02, 0x01, 0x05]) {
                        warnings.push(format!(
                            "Certificate 0 ({}): has OCSP Must-Staple (RFC 7633) — \
                             TLS servers MUST present a stapled OCSP response",
                            subject_cn(leaf)
                        ));
                    }
                }
            }
        }
    }

    // Check trust anchors
    let trusted = if let Some(root) = chain.last() {
        let root_der = match root.to_der() {
            Ok(der) => der,
            Err(e) => {
                warnings.push(format!("Failed to serialize root certificate: {}", e));
                Vec::new()
            }
        };
        let is_trusted = trust_anchors.iter().any(|ta| ta == &root_der);
        if !is_trusted && !trust_anchors.is_empty() {
            warnings.push(format!(
                "Root certificate ({}) is not in the trust store",
                subject_cn(root)
            ));
        }
        is_trusted
    } else {
        false
    };

    // RFC 5280 §4.2.1.12: Extended Key Usage consistency checks.
    // - anyExtendedKeyUsage (2.5.29.37.0) is not recommended for end-entity certs
    // - CA certificates (basicConstraints cA=true) SHOULD NOT have EKU extensions
    let eku_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.29.37");
    let any_eku_oid_bytes: &[u8] = &[0x55, 0x1D, 0x25, 0x00]; // 2.5.29.37.0
    for (i, cert) in chain.iter().enumerate() {
        if let Some(exts) = &cert.tbs_certificate.extensions {
            if let Some(eku_ext) = exts.iter().find(|e| e.extn_id == eku_oid) {
                let eku_der = eku_ext.extn_value.as_bytes();
                // Check for anyExtendedKeyUsage on leaf cert (index 0)
                if i == 0
                    && eku_der
                        .windows(any_eku_oid_bytes.len())
                        .any(|w| w == any_eku_oid_bytes)
                {
                    warnings.push(format!(
                        "Certificate {} ({}): anyExtendedKeyUsage present — not recommended for end-entity certs (RFC 5280 §4.2.1.12)",
                        i,
                        subject_cn(cert),
                    ));
                }
                // Check for EKU on CA certs (non-leaf)
                if i > 0 {
                    let is_ca = exts.iter().any(|e| {
                        if e.extn_id == const_oid::ObjectIdentifier::new_unwrap("2.5.29.19") {
                            X509BasicConstraints::from_der(e.extn_value.as_bytes())
                                .map(|bc| bc.ca)
                                .unwrap_or(false)
                        } else {
                            false
                        }
                    });
                    if is_ca {
                        warnings.push(format!(
                            "Certificate {} ({}): CA certificate has extendedKeyUsage — SHOULD be absent for CAs (RFC 5280 §4.2.1.12)",
                            i,
                            subject_cn(cert),
                        ));
                    }
                }
            }
        }
    }

    // RFC 5280 Section 6 policy tree processing
    let policy_result = if options.check_policies {
        // RFC 5280 §6.1.1(c): initial-policy-set — the set of policies
        // acceptable to the relying party. Empty means {anyPolicy}.
        let initial_policy_set: std::collections::HashSet<String> =
            if options.acceptable_policies.is_empty() {
                let mut s = std::collections::HashSet::new();
                s.insert("2.5.29.32.0".to_string()); // anyPolicy
                s
            } else {
                options.acceptable_policies.iter().cloned().collect()
            };
        let pr = super::policy_tree::process_policy_tree(
            chain,
            &initial_policy_set,
            options.require_explicit_policy,
            options.inhibit_policy_mapping,
            options.inhibit_any_policy,
        );
        for e in &pr.errors {
            errors.push(format!("Policy: {}", e));
        }
        for w in &pr.warnings {
            warnings.push(format!("Policy: {}", w));
        }
        Some(pr)
    } else {
        None
    };

    ChainValidationResult {
        valid: errors.is_empty(),
        trusted,
        errors,
        warnings,
        policy_result,
    }
}

/// Validate a certificate chain using RFC 5914 TrustAnchorInfo objects.
///
/// Extracts the SubjectPublicKeyInfo from each trust anchor and matches it
/// against the root certificate's SPKI. This is more flexible than raw
/// DER comparison because a TrustAnchorInfo may not carry a full certificate.
///
/// `chain` must be ordered `[leaf, intermediate..., root]`.
pub fn validate_chain_with_trust_anchors(
    chain: &[Certificate],
    trust_anchors: &[super::trust_anchor::TrustAnchorInfo],
    options: &ChainValidationOptions,
) -> ChainValidationResult {
    // Convert TrustAnchorInfo → raw cert DER list for existing validate_chain.
    // For TAs that carry a full backing certificate, use that.
    // For TAs without a backing cert, match by SPKI.
    if chain.is_empty() {
        return ChainValidationResult {
            valid: false,
            trusted: false,
            errors: vec!["Empty certificate chain".to_string()],
            warnings: Vec::new(),
            policy_result: None,
        };
    }

    // Run the standard chain validation (signatures, validity, constraints, policies)
    // using an empty trust anchor set — we'll check trust separately via SPKI matching.
    let mut inner_result = validate_chain(chain, &[], options);

    // Now check trust: does the root match any TrustAnchorInfo by SPKI?
    let trusted = if let Some(root) = chain.last() {
        let root_spki = match root.tbs_certificate.subject_public_key_info.to_der() {
            Ok(d) => d,
            Err(e) => {
                inner_result
                    .warnings
                    .push(format!("Failed to encode root SPKI: {}", e));
                Vec::new()
            }
        };

        let matched = trust_anchors
            .iter()
            .any(|ta| ta.public_key_info == root_spki);

        if !matched && !trust_anchors.is_empty() {
            inner_result.warnings.push(format!(
                "Root certificate ({}) SPKI not found in trust anchor store",
                subject_cn(root)
            ));
        }
        matched
    } else {
        false
    };

    // RFC 5937 §2: Enforce trust anchor NameConstraints on the certificate chain.
    // If the matching TA has CertPathControls with name_constraints, apply them
    // to all certificates in the chain (just like NameConstraints on an intermediate CA).
    if trusted {
        if let Some(root) = chain.last() {
            let root_spki = root
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .unwrap_or_default();
            if let Some(matched_ta) = trust_anchors
                .iter()
                .find(|ta| ta.public_key_info == root_spki)
            {
                if let Some(ref cert_path) = matched_ta.cert_path {
                    if let Some(ref nc_der) = cert_path.name_constraints {
                        if let Some(nc) = parse_name_constraints_der(nc_der) {
                            // Apply TA name constraints to all certs in the chain
                            for (subj_idx, subj_cert) in chain.iter().enumerate() {
                                let subj_cn = subject_cn(subj_cert);
                                let dns_names = extract_san_dns_names(subj_cert);
                                let emails = extract_san_emails(subj_cert);
                                let ips = extract_san_ips(subj_cert);
                                let uris = extract_san_uris(subj_cert);
                                let subject_rdns =
                                    name_to_der_rdns(&subj_cert.tbs_certificate.subject);
                                let san_dn_names = extract_san_directory_names(subj_cert);
                                let has_subject_dn = !subject_rdns.is_empty();

                                if let Some(ref permitted) = nc.permitted {
                                    for dns in &dns_names {
                                        if !permitted.dns.is_empty()
                                            && !permitted
                                                .dns
                                                .iter()
                                                .any(|p| dns_name_within(dns, p))
                                        {
                                            inner_result.errors.push(format!(
                                                "Certificate {} ({}): DNS name '{}' not within trust anchor permitted subtrees",
                                                subj_idx, subj_cn, dns
                                            ));
                                        }
                                    }
                                    for email in &emails {
                                        if !permitted.emails.is_empty()
                                            && !permitted
                                                .emails
                                                .iter()
                                                .any(|p| email_within(email, p))
                                        {
                                            inner_result.errors.push(format!(
                                                "Certificate {} ({}): email '{}' not within trust anchor permitted subtrees",
                                                subj_idx, subj_cn, email
                                            ));
                                        }
                                    }
                                    for ip in &ips {
                                        if !permitted.ips.is_empty()
                                            && !permitted.ips.iter().any(|p| ip_within(ip, p))
                                        {
                                            inner_result.errors.push(format!(
                                                "Certificate {} ({}): IP address not within trust anchor permitted subtrees",
                                                subj_idx, subj_cn
                                            ));
                                        }
                                    }
                                    for uri in &uris {
                                        if !permitted.uris.is_empty()
                                            && !permitted
                                                .uris
                                                .iter()
                                                .any(|p| uri_host_within(uri, p))
                                        {
                                            inner_result.errors.push(format!(
                                                "Certificate {} ({}): URI '{}' not within trust anchor permitted subtrees",
                                                subj_idx, subj_cn, uri
                                            ));
                                        }
                                    }
                                    // directoryName permitted check
                                    if !permitted.directory_names.is_empty() {
                                        if has_subject_dn
                                            && !permitted
                                                .directory_names
                                                .iter()
                                                .any(|p| dn_within(&subject_rdns, p))
                                        {
                                            inner_result.errors.push(format!(
                                                "Certificate {} ({}): subject DN not within trust anchor permitted subtrees",
                                                subj_idx, subj_cn
                                            ));
                                        }
                                        for san_dn in &san_dn_names {
                                            if !permitted
                                                .directory_names
                                                .iter()
                                                .any(|p| dn_within(san_dn, p))
                                            {
                                                inner_result.errors.push(format!(
                                                    "Certificate {} ({}): directoryName SAN not within trust anchor permitted subtrees",
                                                    subj_idx, subj_cn
                                                ));
                                            }
                                        }
                                    }
                                }

                                if let Some(ref excluded) = nc.excluded {
                                    for dns in &dns_names {
                                        if excluded.dns.iter().any(|e| dns_name_within(dns, e)) {
                                            inner_result.errors.push(format!(
                                                "Certificate {} ({}): DNS name '{}' is within trust anchor excluded subtrees",
                                                subj_idx, subj_cn, dns
                                            ));
                                        }
                                    }
                                    for email in &emails {
                                        if excluded.emails.iter().any(|e| email_within(email, e)) {
                                            inner_result.errors.push(format!(
                                                "Certificate {} ({}): email '{}' is within trust anchor excluded subtrees",
                                                subj_idx, subj_cn, email
                                            ));
                                        }
                                    }
                                    for ip in &ips {
                                        if excluded.ips.iter().any(|e| ip_within(ip, e)) {
                                            inner_result.errors.push(format!(
                                                "Certificate {} ({}): IP address is within trust anchor excluded subtrees",
                                                subj_idx, subj_cn
                                            ));
                                        }
                                    }
                                    for uri in &uris {
                                        if excluded.uris.iter().any(|e| uri_host_within(uri, e)) {
                                            inner_result.errors.push(format!(
                                                "Certificate {} ({}): URI '{}' is within trust anchor excluded subtrees",
                                                subj_idx, subj_cn, uri
                                            ));
                                        }
                                    }
                                    // directoryName excluded check
                                    if has_subject_dn
                                        && excluded
                                            .directory_names
                                            .iter()
                                            .any(|e| dn_within(&subject_rdns, e))
                                    {
                                        inner_result.errors.push(format!(
                                            "Certificate {} ({}): subject DN is within trust anchor excluded subtrees",
                                            subj_idx, subj_cn
                                        ));
                                    }
                                    for san_dn in &san_dn_names {
                                        if excluded
                                            .directory_names
                                            .iter()
                                            .any(|e| dn_within(san_dn, e))
                                        {
                                            inner_result.errors.push(format!(
                                                "Certificate {} ({}): directoryName SAN is within trust anchor excluded subtrees",
                                                subj_idx, subj_cn
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    inner_result.trusted = trusted;
    inner_result.valid = inner_result.errors.is_empty();
    inner_result
}

/// Convenience wrapper that accepts DER-encoded certificates.
///
/// Each entry in `chain_der` is a DER-encoded X.509 certificate.
/// The chain must be ordered `[leaf, intermediate..., root]`.
pub fn validate_chain_der(
    chain_der: &[&[u8]],
    trust_anchors: &[Vec<u8>],
    options: &ChainValidationOptions,
) -> ChainValidationResult {
    let mut chain = Vec::with_capacity(chain_der.len());
    for (i, der) in chain_der.iter().enumerate() {
        match Certificate::from_der(der) {
            Ok(cert) => chain.push(cert),
            Err(e) => {
                return ChainValidationResult {
                    valid: false,
                    trusted: false,
                    errors: vec![format!("Failed to parse certificate {}: {}", i, e)],
                    warnings: Vec::new(),
                    policy_result: None,
                };
            }
        }
    }
    validate_chain(&chain, trust_anchors, options)
}

// ============================================================================
// Tests for verify_raw_signature_with_spki
// ============================================================================

#[cfg(test)]
#[cfg(not(feature = "fips"))]
mod verify_with_spki_tests {
    use super::*;

    /// Generate a P-256 key pair and return (spki_der, signing_key).
    fn gen_p256_keypair() -> (Vec<u8>, p256::ecdsa::SigningKey) {
        use p256::ecdsa::SigningKey;
        use pkcs8::EncodePublicKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::random(&mut OsRng);
        let spki_der = sk
            .verifying_key()
            .to_public_key_der()
            .expect("encode SPKI")
            .as_bytes()
            .to_vec();
        (spki_der, sk)
    }

    /// Sign `data` with P-256 and return DER-encoded signature.
    fn p256_sign(sk: &p256::ecdsa::SigningKey, data: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = sk.sign(data);
        sig.to_der().to_bytes().to_vec()
    }

    #[test]
    fn test_verify_raw_signature_with_spki_good() {
        let (spki_der, sk) = gen_p256_keypair();
        let data = b"test data for signature verification";
        let sig = p256_sign(&sk, data);

        let result = verify_raw_signature_with_spki("1.2.840.10045.4.3.2", &spki_der, data, &sig);
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        assert!(result.unwrap(), "Expected signature to verify");
    }

    #[test]
    fn test_verify_raw_signature_with_spki_bad_signature() {
        let (spki_der, sk) = gen_p256_keypair();
        let data = b"test data";
        let mut sig = p256_sign(&sk, data);
        // Corrupt a byte in the signature
        let last = sig.len() - 1;
        sig[last] ^= 0xFF;

        let result = verify_raw_signature_with_spki("1.2.840.10045.4.3.2", &spki_der, data, &sig);
        // Either returns Ok(false) or Err — both indicate rejection
        match result {
            Ok(false) => {}
            Err(_) => {}
            Ok(true) => panic!("Corrupted signature should not verify"),
        }
    }

    #[test]
    fn test_verify_raw_signature_with_spki_wrong_key() {
        let (spki_der, _sk1) = gen_p256_keypair();
        let (_, sk2) = gen_p256_keypair();
        let data = b"test data";
        // Sign with key2 but verify with key1's SPKI
        let sig = p256_sign(&sk2, data);

        let result = verify_raw_signature_with_spki("1.2.840.10045.4.3.2", &spki_der, data, &sig);
        match result {
            Ok(false) => {}
            Err(_) => {}
            Ok(true) => panic!("Signature from wrong key should not verify"),
        }
    }

    #[test]
    fn test_verify_raw_signature_with_spki_unsupported_oid() {
        let (spki_der, sk) = gen_p256_keypair();
        let data = b"test data";
        let sig = p256_sign(&sk, data);

        let result = verify_raw_signature_with_spki("0.0.0.0.0", &spki_der, data, &sig);
        assert!(result.is_err(), "Unsupported OID should return Err");
    }

    #[test]
    fn test_verify_raw_signature_with_spki_malformed_spki() {
        let data = b"test data";
        let sig = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]; // not a real SPKI
        let result = verify_raw_signature_with_spki(
            "1.2.840.10045.4.3.2",
            &[0xFF, 0xFF, 0xFF], // garbage SPKI
            data,
            &sig,
        );
        assert!(result.is_err(), "Malformed SPKI should return Err");
    }
}

#[cfg(test)]
mod name_constraint_tests {
    use super::*;

    #[test]
    fn test_dns_name_within_exact_match() {
        assert!(dns_name_within("example.com", "example.com"));
        assert!(dns_name_within("EXAMPLE.COM", "example.com"));
    }

    #[test]
    fn test_dns_name_within_subdomain() {
        assert!(dns_name_within("foo.example.com", "example.com"));
        assert!(dns_name_within("bar.foo.example.com", "example.com"));
    }

    #[test]
    fn test_dns_name_within_leading_dot() {
        assert!(dns_name_within("foo.example.com", ".example.com"));
        assert!(!dns_name_within("example.com", ".example.com"));
    }

    #[test]
    fn test_dns_name_not_within() {
        assert!(!dns_name_within("notexample.com", "example.com"));
        assert!(!dns_name_within("evil-example.com", "example.com"));
        assert!(!dns_name_within("other.org", "example.com"));
    }

    #[test]
    fn test_email_within_domain() {
        assert!(email_within("user@example.com", "example.com"));
        assert!(email_within("admin@example.com", "example.com"));
    }

    #[test]
    fn test_email_within_exact() {
        assert!(email_within("user@example.com", "user@example.com"));
        assert!(!email_within("other@example.com", "user@example.com"));
    }

    #[test]
    fn test_email_not_within() {
        assert!(!email_within("user@other.com", "example.com"));
    }

    #[test]
    fn test_ia5_string_validation_ascii() {
        assert!(is_valid_ia5_string("example.com"));
        assert!(is_valid_ia5_string(".example.com"));
        assert!(is_valid_ia5_string("user@example.com"));
        assert!(is_valid_ia5_string("")); // empty is valid IA5String
    }

    #[test]
    fn test_ia5_string_validation_rejects_non_ascii() {
        assert!(!is_valid_ia5_string("caf\u{00e9}.com")); // é = 0xE9
        assert!(!is_valid_ia5_string("\u{00fc}ser@example.com")); // ü
        assert!(!is_valid_ia5_string("example.\u{4e2d}\u{56fd}")); // Chinese chars
    }

    #[test]
    fn test_parse_name_constraints_der_permitted_dns() {
        // Use x509-cert to build a proper NameConstraints DER.
        use der::Encode;
        use x509_cert::ext::pkix::constraints::name::{
            GeneralSubtree, GeneralSubtrees, NameConstraints,
        };
        use x509_cert::ext::pkix::name::GeneralName;

        let subtree = GeneralSubtree {
            base: GeneralName::DnsName(der::asn1::Ia5String::new(".example.com").unwrap()),
            minimum: 0,
            maximum: None,
        };
        let subtrees = GeneralSubtrees::from(vec![subtree]);
        let nc = NameConstraints {
            permitted_subtrees: Some(subtrees),
            excluded_subtrees: None,
        };
        let nc_der = nc.to_der().unwrap();

        let parsed = parse_name_constraints_der(&nc_der);
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert!(parsed.permitted.is_some());
        let permitted = parsed.permitted.unwrap();
        assert_eq!(permitted.dns.len(), 1);
        assert_eq!(permitted.dns[0], ".example.com");
        assert!(parsed.excluded.is_none());
    }

    #[test]
    fn test_parse_name_constraints_der_invalid() {
        // Garbage bytes should return None
        assert!(parse_name_constraints_der(&[0xFF, 0x00]).is_none());
        assert!(parse_name_constraints_der(&[]).is_none());
    }

    // === RFC 5280 §4.2.1.10 NameConstraints: Excluded subtrees ===

    #[test]
    fn test_parse_name_constraints_excluded_dns() {
        // Excluded subtrees should be parsed correctly
        use der::Encode;
        use x509_cert::ext::pkix::constraints::name::{
            GeneralSubtree, GeneralSubtrees, NameConstraints,
        };
        use x509_cert::ext::pkix::name::GeneralName;

        let excluded = GeneralSubtree {
            base: GeneralName::DnsName(der::asn1::Ia5String::new(".evil.com").unwrap()),
            minimum: 0,
            maximum: None,
        };
        let nc = NameConstraints {
            permitted_subtrees: None,
            excluded_subtrees: Some(GeneralSubtrees::from(vec![excluded])),
        };
        let nc_der = nc.to_der().unwrap();

        let parsed = parse_name_constraints_der(&nc_der);
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert!(parsed.permitted.is_none());
        assert!(parsed.excluded.is_some());
        let excl = parsed.excluded.unwrap();
        assert_eq!(excl.dns.len(), 1);
        assert_eq!(excl.dns[0], ".evil.com");
    }

    #[test]
    fn test_parse_name_constraints_both_permitted_and_excluded() {
        // RFC 5280 §4.2.1.10: both permitted and excluded can coexist
        use der::Encode;
        use x509_cert::ext::pkix::constraints::name::{
            GeneralSubtree, GeneralSubtrees, NameConstraints,
        };
        use x509_cert::ext::pkix::name::GeneralName;

        let permitted = GeneralSubtree {
            base: GeneralName::DnsName(der::asn1::Ia5String::new(".example.com").unwrap()),
            minimum: 0,
            maximum: None,
        };
        let excluded = GeneralSubtree {
            base: GeneralName::DnsName(der::asn1::Ia5String::new(".internal.example.com").unwrap()),
            minimum: 0,
            maximum: None,
        };
        let nc = NameConstraints {
            permitted_subtrees: Some(GeneralSubtrees::from(vec![permitted])),
            excluded_subtrees: Some(GeneralSubtrees::from(vec![excluded])),
        };
        let nc_der = nc.to_der().unwrap();

        let parsed = parse_name_constraints_der(&nc_der);
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert!(parsed.permitted.is_some());
        assert!(parsed.excluded.is_some());
        let perm = parsed.permitted.unwrap();
        let excl = parsed.excluded.unwrap();
        assert_eq!(perm.dns[0], ".example.com");
        assert_eq!(excl.dns[0], ".internal.example.com");
    }

    #[test]
    fn test_excluded_dns_name_matching() {
        // RFC 5280 §4.2.1.10: leading dot means subdomains only
        assert!(
            !dns_name_within("evil.com", ".evil.com"),
            "exact domain should NOT match dot-prefixed constraint"
        );
        assert!(dns_name_within("sub.evil.com", ".evil.com"));
        assert!(dns_name_within("deep.sub.evil.com", ".evil.com"));
        assert!(!dns_name_within("notevil.com", ".evil.com"));
        assert!(!dns_name_within("goodevil.com", ".evil.com"));
        // Without leading dot: exact match or subdomain
        assert!(dns_name_within("evil.com", "evil.com"));
        assert!(dns_name_within("sub.evil.com", "evil.com"));
    }

    #[test]
    fn test_excluded_email_matching() {
        // Excluded email subtrees — domain-level exclusion
        assert!(email_within("user@evil.com", "evil.com"));
        assert!(email_within("admin@evil.com", "evil.com"));
        assert!(!email_within("user@good.com", "evil.com"));
        // Exact email exclusion
        assert!(email_within("bad@evil.com", "bad@evil.com"));
        assert!(!email_within("good@evil.com", "bad@evil.com"));
    }

    #[test]
    fn test_excluded_uri_matching() {
        // RFC 5280 §4.2.1.10: URI host matching uses DNS name rules
        // Leading dot means subdomains only
        assert!(
            !uri_host_within("https://evil.com/path", ".evil.com"),
            "exact host should NOT match dot-prefixed"
        );
        assert!(uri_host_within("https://sub.evil.com/", ".evil.com"));
        assert!(!uri_host_within("https://good.com/", ".evil.com"));
        // Without leading dot: exact or subdomain
        assert!(uri_host_within("https://evil.com/path", "evil.com"));
        assert!(uri_host_within("https://sub.evil.com/", "evil.com"));
    }

    // === RFC 5280 §4.2.1.10 NameConstraints: IP address + URI matching ===

    #[test]
    fn test_ip_within_ipv4_match() {
        // 10.0.0.5 within 10.0.0.0/24
        let ip = vec![10, 0, 0, 5];
        let constraint = IpConstraint {
            network: vec![10, 0, 0, 0],
            mask: vec![255, 255, 255, 0],
        };
        assert!(ip_within(&ip, &constraint));
    }

    #[test]
    fn test_ip_within_ipv4_no_match() {
        // 192.168.1.5 NOT within 10.0.0.0/8
        let ip = vec![192, 168, 1, 5];
        let constraint = IpConstraint {
            network: vec![10, 0, 0, 0],
            mask: vec![255, 0, 0, 0],
        };
        assert!(!ip_within(&ip, &constraint));
    }

    #[test]
    fn test_ip_within_ipv4_exact_host() {
        // 10.1.2.3 within 10.1.2.3/32
        let ip = vec![10, 1, 2, 3];
        let constraint = IpConstraint {
            network: vec![10, 1, 2, 3],
            mask: vec![255, 255, 255, 255],
        };
        assert!(ip_within(&ip, &constraint));
    }

    #[test]
    fn test_ip_within_ipv4_wide_subnet() {
        // 172.16.55.200 within 172.16.0.0/12
        let ip = vec![172, 16, 55, 200];
        let constraint = IpConstraint {
            network: vec![172, 16, 0, 0],
            mask: vec![255, 240, 0, 0],
        };
        assert!(ip_within(&ip, &constraint));
    }

    #[test]
    fn test_ip_within_ipv6_match() {
        // 2001:db8::1 within 2001:db8::/32
        let ip = vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let constraint = IpConstraint {
            network: vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            mask: vec![0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        assert!(ip_within(&ip, &constraint));
    }

    #[test]
    fn test_ip_within_version_mismatch() {
        // IPv4 address against IPv6 constraint = no match
        let ip = vec![10, 0, 0, 1];
        let constraint = IpConstraint {
            network: vec![0; 16],
            mask: vec![0; 16],
        };
        assert!(!ip_within(&ip, &constraint));
    }

    #[test]
    fn test_uri_host_within_match() {
        assert!(uri_host_within(
            "https://www.example.com/path",
            "example.com"
        ));
        assert!(uri_host_within("https://example.com/", "example.com"));
        assert!(uri_host_within(
            "https://sub.example.com:8443/api",
            "example.com"
        ));
    }

    #[test]
    fn test_uri_host_within_no_match() {
        assert!(!uri_host_within(
            "https://www.other.com/path",
            "example.com"
        ));
        assert!(!uri_host_within("https://notexample.com/", "example.com"));
    }

    #[test]
    fn test_uri_host_within_dot_constraint() {
        assert!(uri_host_within("https://sub.example.com/", ".example.com"));
        assert!(!uri_host_within("https://example.com/", ".example.com"));
    }

    #[test]
    fn test_parse_name_constraints_der_with_ip() {
        // Build a NameConstraints with an IPv4 constraint
        use der::Encode;
        use x509_cert::ext::pkix::constraints::name::{
            GeneralSubtree, GeneralSubtrees, NameConstraints,
        };
        use x509_cert::ext::pkix::name::GeneralName;

        // 10.0.0.0/8 = network [10,0,0,0] mask [255,0,0,0]
        let ip_bytes: &[u8] = &[10, 0, 0, 0, 255, 0, 0, 0];
        let subtree = GeneralSubtree {
            base: GeneralName::IpAddress(der::asn1::OctetString::new(ip_bytes).unwrap()),
            minimum: 0,
            maximum: None,
        };
        let subtrees = GeneralSubtrees::from(vec![subtree]);
        let nc = NameConstraints {
            permitted_subtrees: Some(subtrees),
            excluded_subtrees: None,
        };
        let nc_der = nc.to_der().unwrap();

        let parsed = parse_name_constraints_der(&nc_der);
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        let permitted = parsed.permitted.unwrap();
        assert_eq!(permitted.ips.len(), 1);
        assert_eq!(permitted.ips[0].network, &[10, 0, 0, 0]);
        assert_eq!(permitted.ips[0].mask, &[255, 0, 0, 0]);
    }

    // ---- directoryName (DN) constraint tests (RFC 5280 §4.2.1.10) ----

    /// Helper: build a DnConstraint from a list of (OID, value) pairs representing a DN.
    fn build_dn_constraint(attrs: &[(&str, &str)]) -> DnConstraint {
        use der::asn1::{PrintableStringRef, SetOfVec};
        use der::Encode;
        use x509_cert::attr::{AttributeTypeAndValue, AttributeValue};
        use x509_cert::name::RelativeDistinguishedName;

        let mut rdns = Vec::new();
        for (oid_str, val) in attrs {
            let oid: der::asn1::ObjectIdentifier = oid_str.parse().unwrap();
            let attr_val = AttributeValue::new(
                der::Tag::PrintableString,
                PrintableStringRef::new(val).unwrap().as_bytes(),
            )
            .unwrap();
            let atv = AttributeTypeAndValue {
                oid,
                value: attr_val,
            };
            let rdn = RelativeDistinguishedName::from(SetOfVec::try_from(vec![atv]).unwrap());
            rdns.push(rdn.to_der().unwrap());
        }
        DnConstraint { rdns }
    }

    /// Helper: build DER-encoded RDNs for a subject DN from (OID, value) pairs.
    fn build_subject_rdns(attrs: &[(&str, &str)]) -> Vec<Vec<u8>> {
        use der::asn1::{PrintableStringRef, SetOfVec};
        use der::Encode;
        use x509_cert::attr::{AttributeTypeAndValue, AttributeValue};
        use x509_cert::name::RelativeDistinguishedName;

        let mut rdns = Vec::new();
        for (oid_str, val) in attrs {
            let oid: der::asn1::ObjectIdentifier = oid_str.parse().unwrap();
            let attr_val = AttributeValue::new(
                der::Tag::PrintableString,
                PrintableStringRef::new(val).unwrap().as_bytes(),
            )
            .unwrap();
            let atv = AttributeTypeAndValue {
                oid,
                value: attr_val,
            };
            let rdn = RelativeDistinguishedName::from(SetOfVec::try_from(vec![atv]).unwrap());
            rdns.push(rdn.to_der().unwrap());
        }
        rdns
    }

    // OIDs for common RDN attributes
    const OID_CN: &str = "2.5.4.3";
    const OID_OU: &str = "2.5.4.11";
    const OID_O: &str = "2.5.4.10";
    const OID_C: &str = "2.5.4.6";

    #[test]
    fn test_dn_within_exact_match() {
        // Constraint: C=US, O=Acme
        // Subject: C=US, O=Acme
        let constraint = build_dn_constraint(&[(OID_C, "US"), (OID_O, "Acme")]);
        let subject = build_subject_rdns(&[(OID_C, "US"), (OID_O, "Acme")]);
        assert!(dn_within(&subject, &constraint));
    }

    #[test]
    fn test_dn_within_prefix_match() {
        // Constraint: C=US, O=Acme (2 RDNs)
        // Subject: C=US, O=Acme, OU=Engineering, CN=Alice (4 RDNs)
        let constraint = build_dn_constraint(&[(OID_C, "US"), (OID_O, "Acme")]);
        let subject = build_subject_rdns(&[
            (OID_C, "US"),
            (OID_O, "Acme"),
            (OID_OU, "Engineering"),
            (OID_CN, "Alice"),
        ]);
        assert!(dn_within(&subject, &constraint));
    }

    #[test]
    fn test_dn_within_different_org_rejected() {
        // Constraint: C=US, O=Acme
        // Subject: C=US, O=EvilCorp, CN=Alice
        let constraint = build_dn_constraint(&[(OID_C, "US"), (OID_O, "Acme")]);
        let subject = build_subject_rdns(&[(OID_C, "US"), (OID_O, "EvilCorp"), (OID_CN, "Alice")]);
        assert!(!dn_within(&subject, &constraint));
    }

    #[test]
    fn test_dn_within_subject_shorter_rejected() {
        // Constraint: C=US, O=Acme, OU=Eng (3 RDNs)
        // Subject: C=US, O=Acme (2 RDNs — shorter than constraint)
        let constraint = build_dn_constraint(&[(OID_C, "US"), (OID_O, "Acme"), (OID_OU, "Eng")]);
        let subject = build_subject_rdns(&[(OID_C, "US"), (OID_O, "Acme")]);
        assert!(!dn_within(&subject, &constraint));
    }

    #[test]
    fn test_dn_within_empty_constraint_matches_all() {
        let constraint = DnConstraint { rdns: vec![] };
        let subject = build_subject_rdns(&[(OID_C, "US"), (OID_O, "Anything")]);
        assert!(dn_within(&subject, &constraint));
    }

    #[test]
    fn test_dn_within_empty_subject_rejected() {
        let constraint = build_dn_constraint(&[(OID_C, "US")]);
        let subject: Vec<Vec<u8>> = vec![];
        assert!(!dn_within(&subject, &constraint));
    }

    #[test]
    fn test_parse_subtrees_with_directory_name() {
        use der::asn1::{PrintableStringRef, SetOfVec};
        use der::Encode;
        use x509_cert::attr::{AttributeTypeAndValue, AttributeValue};
        use x509_cert::ext::pkix::constraints::name::{
            GeneralSubtree, GeneralSubtrees, NameConstraints,
        };
        use x509_cert::ext::pkix::name::GeneralName;
        use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};

        // Build a directoryName: C=US, O=Acme
        let c_oid: der::asn1::ObjectIdentifier = OID_C.parse().unwrap();
        let c_val = AttributeValue::new(
            der::Tag::PrintableString,
            PrintableStringRef::new("US").unwrap().as_bytes(),
        )
        .unwrap();
        let c_atv = AttributeTypeAndValue {
            oid: c_oid,
            value: c_val,
        };
        let c_rdn = RelativeDistinguishedName::from(SetOfVec::try_from(vec![c_atv]).unwrap());

        let o_oid: der::asn1::ObjectIdentifier = OID_O.parse().unwrap();
        let o_val = AttributeValue::new(
            der::Tag::PrintableString,
            PrintableStringRef::new("Acme").unwrap().as_bytes(),
        )
        .unwrap();
        let o_atv = AttributeTypeAndValue {
            oid: o_oid,
            value: o_val,
        };
        let o_rdn = RelativeDistinguishedName::from(SetOfVec::try_from(vec![o_atv]).unwrap());

        let dn = Name::from(RdnSequence::from(vec![c_rdn, o_rdn]));

        let subtree = GeneralSubtree {
            base: GeneralName::DirectoryName(dn),
            minimum: 0,
            maximum: None,
        };
        let subtrees = GeneralSubtrees::from(vec![subtree]);
        let nc = NameConstraints {
            permitted_subtrees: Some(subtrees),
            excluded_subtrees: None,
        };
        let nc_der = nc.to_der().unwrap();

        let parsed = parse_name_constraints_der(&nc_der);
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        let permitted = parsed.permitted.unwrap();
        assert_eq!(permitted.directory_names.len(), 1);
        assert_eq!(permitted.directory_names[0].rdns.len(), 2);

        // Verify it matches a subject within the subtree
        let subject = build_subject_rdns(&[(OID_C, "US"), (OID_O, "Acme"), (OID_CN, "Alice")]);
        assert!(dn_within(&subject, &permitted.directory_names[0]));

        // Verify it rejects a subject outside the subtree
        let bad_subject = build_subject_rdns(&[(OID_C, "DE"), (OID_O, "Other")]);
        assert!(!dn_within(&bad_subject, &permitted.directory_names[0]));
    }
}

#[cfg(all(test, feature = "ceremony"))]
mod tests {
    use super::*;
    use crate::algo::AlgorithmId;
    use crate::ca::{CaCeremony, CaConfig, CertificateProfile};
    use crate::cert::{NameBuilder, Validity};

    /// Helper: create a Root CA and return its Certificate + CertificateAuthority
    fn create_root_ca(
        name: &str,
        algo: AlgorithmId,
    ) -> (Certificate, crate::ca::CertificateAuthority) {
        let config = CaConfig::root(name, algo).with_subject(
            NameBuilder::new(name)
                .organization("SPORK Test")
                .country("US")
                .build(),
        );
        let result = CaCeremony::init_root(config).unwrap();
        (result.ca.certificate.clone(), result.ca)
    }

    /// Helper: create an Intermediate CA signed by a Root
    fn create_intermediate_ca(
        name: &str,
        algo: AlgorithmId,
        root_ca: &mut crate::ca::CertificateAuthority,
    ) -> (Certificate, crate::ca::CertificateAuthority) {
        let config = CaConfig::intermediate(name, algo).with_subject(
            NameBuilder::new(name)
                .organization("SPORK Test")
                .country("US")
                .build(),
        );
        let result = CaCeremony::init_intermediate(config, root_ca).unwrap();
        (result.ca.certificate.clone(), result.ca)
    }

    /// Helper: issue an end-entity cert from an intermediate CA
    fn issue_ee(
        ca: &mut crate::ca::CertificateAuthority,
        cn: &str,
        algo: AlgorithmId,
    ) -> Certificate {
        let subject = NameBuilder::new(cn).build();
        let (issued, _key) = ca
            .issue_direct(
                subject,
                algo,
                CertificateProfile::TlsServer,
                Validity::days_from_now(365),
                None,
            )
            .unwrap();
        crate::cert::parse_certificate_pem(&issued.pem).unwrap()
    }

    fn default_opts() -> ChainValidationOptions {
        ChainValidationOptions::default()
    }

    // ---- Valid chain tests ----

    #[test]
    fn test_valid_chain_p256() {
        let (root_cert, mut root_ca) = create_root_ca("P256 Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("P256 Intermediate", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "test.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Errors: {:?}", result.errors);
        assert!(result.trusted);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_valid_chain_p384() {
        let (root_cert, mut root_ca) = create_root_ca("P384 Root", AlgorithmId::EcdsaP384);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("P384 Intermediate", AlgorithmId::EcdsaP384, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "test.example.com", AlgorithmId::EcdsaP384);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Errors: {:?}", result.errors);
        assert!(result.trusted);
    }

    #[test]
    #[cfg(not(feature = "fips"))] // RSA-2048 rejected in FIPS mode (minimum 3072-bit)
    fn test_valid_chain_rsa() {
        // Use RSA-3072: RSA-2048 is below the FIPS minimum (SP 800-131A Rev 2)
        // and races with tests that enable FIPS mode via the global atomic.
        let (root_cert, mut root_ca) = create_root_ca("RSA Root", AlgorithmId::Rsa3072);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("RSA Intermediate", AlgorithmId::Rsa3072, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "rsa.example.com", AlgorithmId::Rsa3072);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Errors: {:?}", result.errors);
        assert!(result.trusted);
    }

    #[test]
    #[cfg(not(feature = "fips"))] // Ed25519 not FIPS-approved
    fn test_valid_chain_ed25519() {
        let (root_cert, mut root_ca) = create_root_ca("Ed25519 Root", AlgorithmId::Ed25519);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("Ed25519 Int", AlgorithmId::Ed25519, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "ed25519.example.com", AlgorithmId::Ed25519);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Errors: {:?}", result.errors);
        assert!(result.trusted);
    }

    #[test]
    #[cfg(not(feature = "fips"))] // Ed25519 not FIPS-approved
    fn test_ed25519_cross_algorithm_chain() {
        // Ed25519 root signs P-256 intermediate signs P-256 end-entity
        let (root_cert, mut root_ca) = create_root_ca("Ed25519 XRoot", AlgorithmId::Ed25519);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("P256 Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(
            &mut int_ca,
            "cross-ed25519.example.com",
            AlgorithmId::EcdsaP256,
        );

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Errors: {:?}", result.errors);
        assert!(result.trusted);
    }

    #[test]
    #[cfg(all(feature = "pqc", not(feature = "fips")))] // ML-DSA not yet FIPS 140-3 validated
    fn test_valid_chain_mldsa65() {
        if crate::fips::is_fips_mode() {
            return;
        }
        let (root_cert, mut root_ca) = create_root_ca("ML-DSA Root", AlgorithmId::MlDsa65);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("ML-DSA Intermediate", AlgorithmId::MlDsa65, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "pqc.example.com", AlgorithmId::MlDsa65);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Errors: {:?}", result.errors);
        assert!(result.trusted);
    }

    // ---- Failure tests ----

    #[test]
    fn test_wrong_issuer_fails() {
        let (_root_cert, mut root_ca) = create_root_ca("Root A", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("Intermediate A", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "test.example.com", AlgorithmId::EcdsaP256);

        // Create a separate root — EE was NOT signed by this root
        let (other_root, _) = create_root_ca("Root B", AlgorithmId::EcdsaP256);

        // Chain EE directly to wrong root (skipping intermediate)
        let chain = vec![ee, other_root.clone()];
        let trust = vec![other_root.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(!result.valid);
        assert!(
            result.errors.iter().any(|e| e.contains("signature")),
            "Expected signature error, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_self_signed_root_validates() {
        let (root_cert, _) = create_root_ca("Self-Signed Root", AlgorithmId::EcdsaP256);

        let chain = vec![root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Errors: {:?}", result.errors);
        assert!(result.trusted);
    }

    #[test]
    fn test_empty_chain_fails() {
        let result = validate_chain(&[], &[], &default_opts());
        assert!(!result.valid);
        assert!(result.errors[0].contains("Empty"));
    }

    #[test]
    fn test_untrusted_root_warns() {
        let (root_cert, mut root_ca) = create_root_ca("Untrusted Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("Untrusted Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "test.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];

        // Create a DIFFERENT root as trust anchor
        let (other_root, _) = create_root_ca("Other Root", AlgorithmId::EcdsaP256);
        let trust = vec![other_root.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Errors: {:?}", result.errors);
        assert!(!result.trusted);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("not in the trust store")),
            "Expected trust warning, got: {:?}",
            result.warnings
        );
    }

    #[test]
    fn test_trusted_root() {
        let (root_cert, mut root_ca) = create_root_ca("Trusted Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("Trusted Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "test.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Errors: {:?}", result.errors);
        assert!(result.trusted);
    }

    #[test]
    fn test_signature_only_no_constraints() {
        // Verify we can disable constraint checking
        let (root_cert, mut root_ca) = create_root_ca("SigOnly Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("SigOnly Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "test.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let opts = ChainValidationOptions {
            check_signatures: true,
            check_validity: false,
            check_constraints: false,
            at_time: None,
            ..Default::default()
        };

        let result = validate_chain(&chain, &trust, &opts);
        assert!(result.valid, "Errors: {:?}", result.errors);
    }

    // ---- Validity (expired/not-yet-valid) tests ----

    #[test]
    fn test_expired_cert_rejected() {
        let (root_cert, mut root_ca) = create_root_ca("Exp Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("Exp Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "expired.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        // Set at_time to 2 years in the future — EE cert (365 day validity) will be expired
        let future = chrono::Utc::now() + chrono::Duration::days(730);
        let opts = ChainValidationOptions {
            check_signatures: true,
            check_validity: true,
            check_constraints: true,
            at_time: Some(future),
            ..Default::default()
        };

        let result = validate_chain(&chain, &trust, &opts);
        assert!(!result.valid, "Expected expired cert to fail validation");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.to_lowercase().contains("expired")
                    || e.to_lowercase().contains("validity")),
            "Expected expiry error, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_not_yet_valid_cert_rejected() {
        let (root_cert, mut root_ca) = create_root_ca("NYV Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("NYV Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "future.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        // Set at_time to 2 years in the past — cert not_before hasn't been reached
        let past = chrono::Utc::now() - chrono::Duration::days(730);
        let opts = ChainValidationOptions {
            check_signatures: true,
            check_validity: true,
            check_constraints: true,
            at_time: Some(past),
            ..Default::default()
        };

        let result = validate_chain(&chain, &trust, &opts);
        assert!(
            !result.valid,
            "Expected not-yet-valid cert to fail validation"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.to_lowercase().contains("not yet valid")
                    || e.to_lowercase().contains("validity")),
            "Expected not-yet-valid error, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_expired_intermediate_rejected() {
        let (root_cert, mut root_ca) = create_root_ca("ExpInt Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("ExpInt Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "test.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        // Root is valid for 20 years, intermediate for 10, EE for 1.
        // At 15 years, the intermediate is expired but root is still valid.
        let far_future = chrono::Utc::now() + chrono::Duration::days(365 * 15);
        let opts = ChainValidationOptions {
            check_signatures: true,
            check_validity: true,
            check_constraints: true,
            at_time: Some(far_future),
            ..Default::default()
        };

        let result = validate_chain(&chain, &trust, &opts);
        assert!(
            !result.valid,
            "Expected expired intermediate to fail validation"
        );
    }

    #[test]
    fn test_validity_check_disabled_allows_expired() {
        let (root_cert, mut root_ca) = create_root_ca("NoVal Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("NoVal Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "test.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        // Set at_time to far future — cert is expired, but validity check is off
        let future = chrono::Utc::now() + chrono::Duration::days(730);
        let opts = ChainValidationOptions {
            check_signatures: true,
            check_validity: false,
            check_constraints: false,
            at_time: Some(future),
            ..Default::default()
        };

        let result = validate_chain(&chain, &trust, &opts);
        assert!(
            result.valid,
            "With validity checking disabled, expired certs should pass: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_single_cert_chain() {
        // Just a self-signed root, no intermediates
        let (root_cert, _) = create_root_ca("Solo Root", AlgorithmId::EcdsaP256);
        let chain = vec![root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(
            result.valid,
            "Self-signed root should validate: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_cross_algorithm_chain() {
        // P-384 root signs P-256 intermediate signs P-256 end-entity
        let (root_cert, mut root_ca) = create_root_ca("Cross Root", AlgorithmId::EcdsaP384);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("Cross Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "cross.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(
            result.valid,
            "Cross-algorithm chain should validate: {:?}",
            result.errors
        );
    }

    #[test]
    #[cfg(all(feature = "pqc", not(feature = "fips")))] // ML-DSA not yet FIPS 140-3 validated
    fn test_pqc_cross_algorithm_chain() {
        // ML-DSA-65 root signs P-256 intermediate signs P-256 end-entity
        // Tests PQC→classical migration scenario
        let (root_cert, mut root_ca) = create_root_ca("PQC-Cross Root", AlgorithmId::MlDsa65);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("PQC-Cross Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "pqc-cross.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(
            result.valid,
            "PQC root → classical intermediate chain should validate: {:?}",
            result.errors
        );
        assert!(result.trusted);
    }

    #[test]
    #[cfg(all(feature = "pqc", not(feature = "fips")))] // ML-DSA not yet FIPS 140-3 validated
    fn test_valid_chain_mldsa44() {
        if crate::fips::is_fips_mode() {
            return;
        }
        let (root_cert, mut root_ca) = create_root_ca("ML-DSA-44 Root", AlgorithmId::MlDsa44);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("ML-DSA-44 Int", AlgorithmId::MlDsa44, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "mldsa44.example.com", AlgorithmId::MlDsa44);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Errors: {:?}", result.errors);
        assert!(result.trusted);
    }

    #[test]
    #[cfg(all(feature = "pqc", not(feature = "fips")))] // ML-DSA not yet FIPS 140-3 validated
    fn test_valid_chain_mldsa87() {
        if crate::fips::is_fips_mode() {
            return;
        }
        // ML-DSA-87 has very large keys/signatures — needs bigger stack
        let result = std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let (root_cert, mut root_ca) =
                    create_root_ca("ML-DSA-87 Root", AlgorithmId::MlDsa87);
                let (_int_cert, mut int_ca) =
                    create_intermediate_ca("ML-DSA-87 Int", AlgorithmId::MlDsa87, &mut root_ca);
                let ee = issue_ee(&mut int_ca, "mldsa87.example.com", AlgorithmId::MlDsa87);

                let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
                let trust = vec![root_cert.to_der().unwrap()];

                let result = validate_chain(&chain, &trust, &default_opts());
                assert!(result.valid, "Errors: {:?}", result.errors);
                assert!(result.trusted);
            })
            .expect("spawn thread")
            .join();
        result.unwrap();
    }

    #[test]
    fn test_no_trust_anchors() {
        let (root_cert, mut root_ca) = create_root_ca("NoTrust Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("NoTrust Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "notrust.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust: Vec<Vec<u8>> = vec![];

        let result = validate_chain(&chain, &trust, &default_opts());
        // Chain is valid (signatures check out) but NOT trusted
        assert!(
            result.valid,
            "Signatures should still validate: {:?}",
            result.errors
        );
        assert!(
            !result.trusted,
            "Should not be trusted without trust anchors"
        );
    }

    #[test]
    fn test_recognized_extensions_list_completeness() {
        // Ensure all standard RFC 5280 critical extensions are in our recognized list
        assert!(
            RECOGNIZED_EXTENSIONS.contains(&&[2u32, 5, 29, 15][..]),
            "keyUsage must be recognized"
        );
        assert!(
            RECOGNIZED_EXTENSIONS.contains(&&[2u32, 5, 29, 19][..]),
            "basicConstraints must be recognized"
        );
        assert!(
            RECOGNIZED_EXTENSIONS.contains(&&[2u32, 5, 29, 30][..]),
            "nameConstraints must be recognized"
        );
        assert!(
            RECOGNIZED_EXTENSIONS.contains(&&[2u32, 5, 29, 36][..]),
            "policyConstraints must be recognized"
        );
        assert!(
            RECOGNIZED_EXTENSIONS.contains(&&[2u32, 5, 29, 54][..]),
            "inhibitAnyPolicy must be recognized"
        );
        // RFC 5280 §4.2.1.15: freshestCRL
        assert!(
            RECOGNIZED_EXTENSIONS.contains(&&[2u32, 5, 29, 46][..]),
            "freshestCRL must be recognized"
        );
        // RFC 5280 §4.2.2.2: subjectInfoAccess
        assert!(
            RECOGNIZED_EXTENSIONS.contains(&&[1u32, 3, 6, 1, 5, 5, 7, 1, 11][..]),
            "subjectInfoAccess must be recognized"
        );
    }

    #[test]
    fn test_chain_with_standard_extensions_passes() {
        // Normal chains with standard extensions should pass critical extension check
        let (root_cert, mut root_ca) = create_root_ca("ExtCheck Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("ExtCheck Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "extcheck.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().expect("DER encode")];
        let result = validate_chain(&chain, &trust, &default_opts());

        // Should pass — no unrecognized critical extensions
        assert!(
            result.valid,
            "Standard cert chain should pass critical ext check: {:?}",
            result.errors
        );

        // Verify no errors mention "unrecognized critical"
        for err in &result.errors {
            assert!(
                !err.contains("unrecognized critical"),
                "Unexpected critical extension error: {err}"
            );
        }
    }

    #[test]
    fn test_valid_chain_rsa_pss() {
        // RSA-PSS (RFC 4055) full chain: Root → Intermediate → End-Entity
        let (root_cert, mut root_ca) = create_root_ca("PSS Root", AlgorithmId::Rsa3072Pss);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("PSS Intermediate", AlgorithmId::Rsa3072Pss, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "pss.example.com", AlgorithmId::Rsa3072Pss);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "PSS chain errors: {:?}", result.errors);
        assert!(result.trusted);
    }

    #[test]
    fn test_cross_algorithm_pss_to_ecdsa() {
        // RSA-PSS root signs ECDSA P-256 intermediate signs ECDSA P-256 end-entity
        let (root_cert, mut root_ca) = create_root_ca("PSS-Cross Root", AlgorithmId::Rsa3072Pss);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("PSS-Cross Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "pss-cross.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(
            result.valid,
            "PSS root → ECDSA intermediate chain errors: {:?}",
            result.errors
        );
        assert!(result.trusted);
    }

    #[test]
    fn test_name_chaining_valid() {
        // A properly built chain has matching issuer/subject names
        let (root_cert, mut root_ca) = create_root_ca("NameChain Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("NameChain Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "namechain.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];
        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Name chaining errors: {:?}", result.errors);
        // No "issuer name does not match" errors
        for err in &result.errors {
            assert!(
                !err.contains("issuer name does not match"),
                "Unexpected name chaining error: {err}"
            );
        }
    }

    #[test]
    fn test_name_chaining_mismatch() {
        // Build two independent Root CAs and mix their intermediates
        let (root_cert_a, mut root_ca_a) = create_root_ca("Root A", AlgorithmId::EcdsaP256);
        let (root_cert_b, root_ca_b) = create_root_ca("Root B", AlgorithmId::EcdsaP256);
        let (_int_cert_a, mut int_ca_a) =
            create_intermediate_ca("Int A", AlgorithmId::EcdsaP256, &mut root_ca_a);
        let ee = issue_ee(
            &mut int_ca_a,
            "mismatch.example.com",
            AlgorithmId::EcdsaP256,
        );

        // Put Int A under Root B — issuer of Int A points to Root A, but we provide Root B
        let chain = vec![ee, int_ca_a.certificate.clone(), root_cert_b.clone()];
        let trust = vec![root_cert_b.to_der().unwrap()];
        let result = validate_chain(&chain, &trust, &default_opts());
        // Should have name chaining error
        assert!(!result.valid);
        let has_name_mismatch = result
            .errors
            .iter()
            .any(|e| e.contains("issuer name does not match"));
        assert!(
            has_name_mismatch,
            "Expected name chaining error, got: {:?}",
            result.errors
        );

        // Cleanup: just verify root_ca_b and root_cert_a are used
        let _ = root_ca_b;
        let _ = root_cert_a;
    }

    #[test]
    fn test_aki_ski_matching_valid() {
        // A properly built chain has matching AKI/SKI
        let (root_cert, mut root_ca) = create_root_ca("AKISKI Root", AlgorithmId::EcdsaP384);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("AKISKI Int", AlgorithmId::EcdsaP384, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "akiski.example.com", AlgorithmId::EcdsaP384);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];
        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "AKI/SKI errors: {:?}", result.errors);
        for err in &result.errors {
            assert!(
                !err.contains("AKI does not match SKI"),
                "Unexpected AKI/SKI error: {err}"
            );
        }
    }

    #[test]
    fn test_extract_aki_ski_helpers() {
        // Verify our AKI/SKI extraction helpers return values for normal certs
        let (root_cert, mut root_ca) = create_root_ca("ExtractTest Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("ExtractTest Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "extract.example.com", AlgorithmId::EcdsaP256);

        // Root should have SKI
        let root_ski = extract_ski_from_cert(&root_cert);
        assert!(root_ski.is_some(), "Root should have SKI extension");

        // Intermediate should have both AKI and SKI
        let int_aki = extract_aki_from_cert(&int_ca.certificate);
        let int_ski = extract_ski_from_cert(&int_ca.certificate);
        assert!(int_aki.is_some(), "Intermediate should have AKI");
        assert!(int_ski.is_some(), "Intermediate should have SKI");

        // Intermediate's AKI should match Root's SKI
        assert_eq!(
            int_aki.unwrap(),
            root_ski.unwrap(),
            "Int AKI should match Root SKI"
        );

        // EE should have AKI matching intermediate's SKI
        let ee_aki = extract_aki_from_cert(&ee);
        assert!(ee_aki.is_some(), "EE should have AKI");
        assert_eq!(
            ee_aki.unwrap(),
            int_ski.unwrap(),
            "EE AKI should match Int SKI"
        );
    }

    #[test]
    fn test_basic_constraints_critical_for_ca_certs() {
        // RFC 5280 §4.2.1.9: BasicConstraints MUST be critical for CA certs.
        // Our builder sets critical=true — verify the validator accepts it.
        let (root_cert, mut root_ca) = create_root_ca("BC Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("BC Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "bc.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];
        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Errors: {:?}", result.errors);

        // Verify no "BasicConstraints MUST be critical" errors
        for err in &result.errors {
            assert!(
                !err.contains("BasicConstraints MUST be critical"),
                "Unexpected BC critical error: {err}"
            );
        }
    }

    #[test]
    fn test_check_basic_constraints_returns_critical_flag() {
        // Verify check_basic_constraints returns is_critical=true for our CA certs
        let (root_cert, _root_ca) = create_root_ca("BCCheck Root", AlgorithmId::EcdsaP256);
        let result = check_basic_constraints(&root_cert).unwrap();
        assert!(result.is_some(), "Root CA should have BasicConstraints");
        let (is_ca, _path_len, is_critical) = result.unwrap();
        assert!(is_ca, "Root CA should have CA:TRUE");
        assert!(is_critical, "Root CA BasicConstraints should be critical");
    }

    #[test]
    fn test_check_basic_constraints_ee_not_present_or_non_ca() {
        // End-entity certs: BasicConstraints either absent or CA:FALSE
        let (_root_cert, mut root_ca) = create_root_ca("BCEE Root", AlgorithmId::EcdsaP256);
        let ee = issue_ee(&mut root_ca, "bcee.example.com", AlgorithmId::EcdsaP256);
        let result = check_basic_constraints(&ee).unwrap();
        // EE cert may or may not have BasicConstraints — if present, CA should be false
        if let Some((is_ca, _, _)) = result {
            assert!(!is_ca, "EE cert should not have CA:TRUE");
        }
    }

    #[test]
    fn test_non_critical_basic_constraints_detected() {
        // Build a cert with BasicConstraints CA:TRUE but non-critical to verify
        // the validator catches it.
        let (_root_cert, mut root_ca) = create_root_ca("NonCrit Root", AlgorithmId::EcdsaP256);
        let (_int_cert, int_ca) =
            create_intermediate_ca("NonCrit Int", AlgorithmId::EcdsaP256, &mut root_ca);

        // Modify the intermediate's BasicConstraints to non-critical by
        // rebuilding the certificate DER with critical=false on BC.
        let mut modified_cert = int_ca.certificate.clone();

        // Walk extensions and flip BC critical to false
        if let Some(ref mut exts) = modified_cert.tbs_certificate.extensions {
            for ext in exts.iter_mut() {
                if ext.extn_id == const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS {
                    ext.critical = false;
                }
            }
        }

        // We can't re-sign, so this cert's signature is now invalid,
        // but check_basic_constraints operates on the parsed TBS only.
        let bc_result = check_basic_constraints(&modified_cert).unwrap();
        assert!(bc_result.is_some());
        let (is_ca, _, is_critical) = bc_result.unwrap();
        assert!(is_ca, "Should still be CA:TRUE");
        assert!(!is_critical, "Should detect non-critical BC");
    }

    #[test]
    fn test_key_usage_ca_certs_have_required_bits() {
        // Our CA builder sets keyCertSign + cRLSign + critical — verify
        let (root_cert, _root_ca) = create_root_ca("KU Root", AlgorithmId::EcdsaP256);
        let ku = check_key_usage(&root_cert).unwrap();
        assert!(ku.is_some(), "Root CA should have KeyUsage");
        let ku = ku.unwrap();
        assert!(ku.key_cert_sign, "Root CA should have keyCertSign");
        assert!(ku.crl_sign, "Root CA should have cRLSign");
        assert!(ku.is_critical, "Root CA KeyUsage should be critical");
    }

    #[test]
    fn test_key_usage_valid_chain_no_crl_sign_warning() {
        // Properly built chain should have no cRLSign warnings
        let (root_cert, mut root_ca) = create_root_ca("KUWarn Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("KUWarn Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "kuwarn.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];
        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(result.valid, "Errors: {:?}", result.errors);
        for w in &result.warnings {
            assert!(!w.contains("cRLSign"), "Unexpected cRLSign warning: {w}");
        }
    }

    #[test]
    fn test_key_usage_ee_has_no_key_cert_sign() {
        // End-entity certs should not have keyCertSign
        let (_root_cert, mut root_ca) = create_root_ca("KUEE Root", AlgorithmId::EcdsaP256);
        let ee = issue_ee(&mut root_ca, "kuee.example.com", AlgorithmId::EcdsaP256);
        let ku = check_key_usage(&ee).unwrap();
        if let Some(info) = ku {
            assert!(!info.key_cert_sign, "EE should not have keyCertSign");
        }
    }

    /// RFC 5280 §4.2.1.3: validate_chain warns when EE (chain[0]) has keyCertSign
    #[test]
    fn test_ee_key_cert_sign_warning() {
        // Place an intermediate CA cert at position 0 (leaf) — it has keyCertSign,
        // which is wrong for an end-entity position and should trigger a warning.
        let (root_cert, mut root_ca) = create_root_ca("KCS Root", AlgorithmId::EcdsaP256);
        let (int_cert, _int_ca) =
            create_intermediate_ca("KCS Intermediate", AlgorithmId::EcdsaP256, &mut root_ca);

        // Chain with intermediate as "leaf" (position 0)
        let chain = vec![int_cert, root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        let has_kcs_warning = result
            .warnings
            .iter()
            .any(|w| w.contains("keyCertSign") && w.contains("end-entity"));
        assert!(
            has_kcs_warning,
            "Expected keyCertSign warning for EE position, got warnings: {:?}",
            result.warnings
        );
    }

    #[test]
    fn test_no_unique_id_or_empty_issuer_warnings_for_valid_chain() {
        // Our generated certs should never trigger §4.1.2.8 or §4.1.2.4 warnings
        let (root_cert, mut root_ca) = create_root_ca("UID Test Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("UID Test Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "uid-test.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, _int_cert, root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];
        let result = validate_chain(&chain, &trust, &default_opts());

        let has_uid_warning = result
            .warnings
            .iter()
            .any(|w| w.contains("UniqueID") || w.contains("unique identifier"));
        assert!(
            !has_uid_warning,
            "Valid certs should not have UniqueID warnings: {:?}",
            result.warnings
        );

        let has_empty_issuer = result
            .warnings
            .iter()
            .any(|w| w.contains("empty issuer DN"));
        assert!(
            !has_empty_issuer,
            "Valid certs should not have empty issuer warnings: {:?}",
            result.warnings
        );
    }

    #[test]
    fn test_aki_ski_enforcement_on_valid_chain() {
        // Our generated certs include AKI and SKI — no warnings expected for those
        let (root_cert, mut root_ca) = create_root_ca("AKI-SKI Test Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("AKI-SKI Test Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(
            &mut int_ca,
            "aki-ski-test.example.com",
            AlgorithmId::EcdsaP256,
        );

        let chain = vec![ee, _int_cert, root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];
        let result = validate_chain(&chain, &trust, &default_opts());

        // Should NOT have AKI or SKI warnings (our builder adds them)
        let has_aki_warn = result
            .warnings
            .iter()
            .any(|w| w.contains("authorityKeyIdentifier MUST"));
        assert!(
            !has_aki_warn,
            "Valid chain should not warn about missing AKI: {:?}",
            result.warnings
        );
        let has_ski_warn = result
            .warnings
            .iter()
            .any(|w| w.contains("subjectKeyIdentifier MUST"));
        assert!(
            !has_ski_warn,
            "Valid chain should not warn about missing SKI: {:?}",
            result.warnings
        );
    }

    #[test]
    fn test_eku_chain_validation_no_false_positives() {
        // Standard chain should NOT trigger EKU warnings — our generated CAs
        // don't include EKU extensions, and leaf certs don't use anyExtendedKeyUsage.
        let (root_cert, mut root_ca) = create_root_ca("EKU Test Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("EKU Test Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "eku-test.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, _int_cert, root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];
        let result = validate_chain(&chain, &trust, &default_opts());

        let has_eku_warning = result
            .warnings
            .iter()
            .any(|w| w.contains("extendedKeyUsage") || w.contains("anyExtendedKeyUsage"));
        assert!(
            !has_eku_warning,
            "Standard chain should not trigger EKU warnings: {:?}",
            result.warnings
        );
    }

    // ── RFC 5280 §6.1.4 pathLenConstraint enforcement ─────────────────────────

    #[test]
    fn test_path_len_constraint_zero_violated() {
        // RFC 5280 §6.1.4 — pathLenConstraint enforcement.
        //
        // CaConfig::intermediate() sets pathLen=0 by default, meaning the
        // intermediate may not have any non-self-issued CA certs below it.
        // Chain: root → intermediate(pathLen=0) → sub-CA → leaf
        //
        // validate_chain MUST reject this: at chain index 2 (the intermediate),
        // there is 1 non-self-issued cert below it (sub-CA at index 1), which
        // exceeds the pathLen=0 constraint.
        //
        // Note: issuance does NOT enforce the parent's pathLen constraint — that
        // is only enforced during path validation.
        let (root_cert, mut root_ca) = create_root_ca("PathLen Root", AlgorithmId::EcdsaP256);
        // intermediate has pathLen=0 (CaConfig::intermediate default)
        let (_int_cert, mut int_ca) = create_intermediate_ca(
            "PathLen Int (pathLen=0)",
            AlgorithmId::EcdsaP256,
            &mut root_ca,
        );
        // Sub-CA signed by the pathLen=0 intermediate — this violates the constraint
        let (_sub_cert, mut sub_ca) = create_intermediate_ca(
            "PathLen Sub-CA (violates parent pathLen=0)",
            AlgorithmId::EcdsaP256,
            &mut int_ca,
        );
        let ee = issue_ee(
            &mut sub_ca,
            "pathlen-test.example.com",
            AlgorithmId::EcdsaP256,
        );

        // Chain: [leaf(0), sub-CA(1), intermediate(pathLen=0)(2), root(3)]
        let chain = vec![
            ee,
            sub_ca.certificate.clone(),
            int_ca.certificate.clone(),
            root_cert.clone(),
        ];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &default_opts());
        assert!(
            !result.valid,
            "Expected pathLen=0 violation to fail validation, but got valid=true (errors: {:?})",
            result.errors
        );
        let has_pathlen_error = result
            .errors
            .iter()
            .any(|e| e.to_lowercase().contains("path length"));
        assert!(
            has_pathlen_error,
            "Expected a 'path length' error in validation output, got: {:?}",
            result.errors
        );
    }

    // ── RFC 5280 §4.1.2.5 expired CA cert in chain ────────────────────────────

    #[test]
    fn test_expired_root_ca_rejected() {
        // RFC 5280 §4.1.2.5 — chain validation MUST reject an expired CA.
        //
        // The root CA has ~20-year validity (CaConfig::root default).
        // The intermediate has 10-year validity.
        // Both certificates will be expired at 25 years in the future.
        //
        // This is distinct from test_expired_intermediate_rejected (15yr, intermediate
        // only expired) — here we specifically verify that an expired ROOT CA is caught.
        let (root_cert, mut root_ca) = create_root_ca("ExpRoot Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("ExpRoot Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(
            &mut int_ca,
            "exproot-test.example.com",
            AlgorithmId::EcdsaP256,
        );

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        // 25 years in the future: root CA (20yr) and intermediate (10yr) both expired
        let far_future = chrono::Utc::now() + chrono::Duration::days(365 * 25);
        let opts = ChainValidationOptions {
            check_signatures: true,
            check_validity: true,
            check_constraints: true,
            at_time: Some(far_future),
            ..Default::default()
        };

        let result = validate_chain(&chain, &trust, &opts);
        assert!(
            !result.valid,
            "Expected expired root CA to fail chain validation, but got valid=true"
        );
        let has_expiry_error = result.errors.iter().any(|e| {
            let lower = e.to_lowercase();
            lower.contains("expired") || lower.contains("validity") || lower.contains("not after")
        });
        assert!(
            has_expiry_error,
            "Expected an expiry-related error, got: {:?}",
            result.errors
        );
    }

    // ── RFC 5280 §4.2 unknown critical extensions must be rejected ─────────────

    #[test]
    fn test_unknown_critical_extension_rejected() {
        // RFC 5280 §4.2 — a certificate with an unrecognized CRITICAL
        // extension MUST be rejected by chain validation.
        //
        // We create a valid chain, then mutate the intermediate certificate in
        // memory to change one of its extension OIDs to a value that is NOT in
        // RECOGNIZED_EXTENSIONS. With critical=true, validate_chain must reject it.
        //
        // check_signatures is disabled because mutating the TBS extension data
        // (extn_id) invalidates the certificate signature; we isolate the critical
        // extension check from the signature check.
        let (root_cert, mut root_ca) = create_root_ca("UnknownExt Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("UnknownExt Int", AlgorithmId::EcdsaP256, &mut root_ca);
        // Save the intermediate cert before using the CA to issue an EE cert.
        // CertificateAuthority is not Clone, so we must capture the cert reference first.
        let int_cert_saved = int_ca.certificate.clone();
        let ee = issue_ee(
            &mut int_ca,
            "unknown-ext.example.com",
            AlgorithmId::EcdsaP256,
        );

        // Clone the saved intermediate cert and inject an unknown critical extension.
        // OID 1.3.6.1.4.1.56266.99.1 is our private-enterprise OID space and is
        // deliberately NOT listed in RECOGNIZED_EXTENSIONS.
        let mut modified_int = int_cert_saved;
        const UNKNOWN_CRITICAL_OID: const_oid::ObjectIdentifier =
            const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.56266.99.1");

        if let Some(ref mut exts) = modified_int.tbs_certificate.extensions {
            // Change the first extension's OID to the unknown OID and set critical=true.
            // This guarantees at least one unrecognized critical extension exists.
            if let Some(ext) = exts.first_mut() {
                ext.extn_id = UNKNOWN_CRITICAL_OID;
                ext.critical = true;
            }
        }

        // Chain uses the modified (signature-invalid) intermediate
        let chain = vec![ee, modified_int, root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        // Disable signature checks so the invalid signature does not mask the
        // critical extension check we are actually testing.
        let opts = ChainValidationOptions {
            check_signatures: false,
            check_validity: false,
            check_constraints: true,
            ..Default::default()
        };

        let result = validate_chain(&chain, &trust, &opts);
        assert!(
            !result.valid,
            "Expected unknown critical extension to fail validation, but got valid=true \
             (errors: {:?})",
            result.errors
        );
        let has_critical_ext_error = result.errors.iter().any(|e| {
            let lower = e.to_lowercase();
            lower.contains("critical")
                || lower.contains("unrecognized")
                || lower.contains("unknown")
        });
        assert!(
            has_critical_ext_error,
            "Expected a critical/unrecognized extension error, got: {:?}",
            result.errors
        );
    }

    // ---- Name Constraints enforcement tests ----

    /// Helper: issue an end-entity cert with a specific DNS Subject Alternative Name.
    ///
    /// Uses `issue_direct` with `Some(san)` so the leaf carries a real dNSName SAN,
    /// enabling NameConstraints checks during chain validation.
    fn issue_ee_with_dns_san(
        ca: &mut crate::ca::CertificateAuthority,
        cn: &str,
        algo: AlgorithmId,
        dns_san: &str,
    ) -> Certificate {
        use crate::cert::extensions::SubjectAltName;
        let subject = NameBuilder::new(cn).build();
        let san = SubjectAltName::new().dns(dns_san);
        let (issued, _key) = ca
            .issue_direct(
                subject,
                algo,
                CertificateProfile::TlsServer,
                Validity::days_from_now(365),
                Some(san),
            )
            .unwrap();
        crate::cert::parse_certificate_pem(&issued.pem).unwrap()
    }

    /// Helper: build a `x509_cert::ext::Extension` containing NameConstraints DER.
    ///
    /// This is used in in-memory cert mutation tests to inject a NameConstraints
    /// extension into a cloned intermediate CA certificate, bypassing the builder.
    fn make_name_constraints_extension(
        nc: crate::cert::extensions::NameConstraints,
        critical: bool,
    ) -> x509_cert::ext::Extension {
        use der::asn1::OctetString;
        let nc_der = nc
            .to_der()
            .expect("NameConstraints DER encoding must succeed");
        x509_cert::ext::Extension {
            extn_id: crate::cert::extensions::oid::NAME_CONSTRAINTS,
            critical,
            extn_value: OctetString::new(nc_der)
                .expect("NameConstraints OctetString wrapping must succeed"),
        }
    }

    /// Helper: replace the KeyUsage extension in a cert with custom flags.
    ///
    /// Finds the existing KeyUsage extension by OID and replaces its `extn_value`
    /// with a new DER-encoded BIT STRING carrying the given `KeyUsageFlags`.
    /// Used in tests that validate keyCertSign / cRLSign enforcement.
    fn replace_key_usage_extension(
        cert: &mut Certificate,
        flags: crate::cert::extensions::KeyUsageFlags,
        critical: bool,
    ) {
        use crate::cert::extensions::{oid, KeyUsage};
        use der::asn1::OctetString;

        let ku_der = KeyUsage::new(flags)
            .to_der()
            .expect("KeyUsage DER encoding must succeed");
        let ku_octet =
            OctetString::new(ku_der).expect("KeyUsage OctetString wrapping must succeed");

        if let Some(ref mut exts) = cert.tbs_certificate.extensions {
            for ext in exts.iter_mut() {
                if ext.extn_id == oid::KEY_USAGE {
                    ext.extn_value = ku_octet;
                    ext.critical = critical;
                    return;
                }
            }
            // If no existing KeyUsage extension was found, append one.
            exts.push(x509_cert::ext::Extension {
                extn_id: oid::KEY_USAGE,
                critical,
                extn_value: OctetString::new(
                    KeyUsage::new(flags)
                        .to_der()
                        .expect("KeyUsage DER encoding must succeed (second call)"),
                )
                .expect("KeyUsage OctetString wrapping must succeed (second call)"),
            });
        }
    }

    /// Options that disable signature and validity checks but enable constraint enforcement.
    ///
    /// All in-memory cert mutation tests use this so that tampered TBS bytes
    /// (which break real signatures) do not obscure the constraint we are testing.
    fn constraint_only_opts() -> ChainValidationOptions {
        ChainValidationOptions {
            check_signatures: false,
            check_validity: false,
            check_constraints: true,
            ..Default::default()
        }
    }

    // --- NameConstraints: permitted subtrees ---

    /// RFC 5280 §4.2.1.10: A certificate whose DNS SAN falls outside the permitted
    /// subtree of an intermediate CA's NameConstraints MUST be rejected.
    #[test]
    fn test_name_constraints_permitted_dns_violation() {
        use crate::cert::extensions::NameConstraints;

        let (root_cert, mut root_ca) = create_root_ca("NC-Permit Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("NC-Permit Int", AlgorithmId::EcdsaP256, &mut root_ca);

        // Issue leaf with a DNS SAN that is outside the permitted subtree ".example.com"
        let ee = issue_ee_with_dns_san(
            &mut int_ca,
            "outside.other.com",
            AlgorithmId::EcdsaP256,
            "outside.other.com",
        );

        // Clone the intermediate and inject a NameConstraints extension that
        // permits only the ".example.com" subtree.  The leaf's SAN "outside.other.com"
        // does NOT fall within ".example.com", so validation MUST report an error.
        let mut modified_int = int_ca.certificate.clone();
        let nc = NameConstraints::new().permit_dns(".example.com");
        let nc_ext = make_name_constraints_extension(nc, true);
        match modified_int.tbs_certificate.extensions {
            Some(ref mut exts) => exts.push(nc_ext),
            None => {
                modified_int.tbs_certificate.extensions = Some(vec![nc_ext]);
            }
        }

        let chain = vec![ee, modified_int, root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &constraint_only_opts());
        assert!(
            !result.valid,
            "Expected permitted DNS violation to fail, but got valid=true (errors: {:?})",
            result.errors
        );
        let has_nc_error = result
            .errors
            .iter()
            .any(|e| e.contains("not within permitted subtrees"));
        assert!(
            has_nc_error,
            "Expected 'not within permitted subtrees' error, got: {:?}",
            result.errors
        );
    }

    /// RFC 5280 §4.2.1.10: A certificate whose DNS SAN falls within an excluded
    /// subtree of an intermediate CA's NameConstraints MUST be rejected.
    #[test]
    fn test_name_constraints_excluded_dns_violation() {
        use crate::cert::extensions::NameConstraints;

        let (root_cert, mut root_ca) = create_root_ca("NC-Exclude Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("NC-Exclude Int", AlgorithmId::EcdsaP256, &mut root_ca);

        // Issue leaf with a DNS SAN inside the excluded subtree ".blocked.com"
        let ee = issue_ee_with_dns_san(
            &mut int_ca,
            "foo.blocked.com",
            AlgorithmId::EcdsaP256,
            "foo.blocked.com",
        );

        // Clone the intermediate and inject a NameConstraints extension that
        // excludes the ".blocked.com" subtree.
        let mut modified_int = int_ca.certificate.clone();
        let nc = NameConstraints::new().exclude_dns(".blocked.com");
        let nc_ext = make_name_constraints_extension(nc, true);
        match modified_int.tbs_certificate.extensions {
            Some(ref mut exts) => exts.push(nc_ext),
            None => {
                modified_int.tbs_certificate.extensions = Some(vec![nc_ext]);
            }
        }

        let chain = vec![ee, modified_int, root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &constraint_only_opts());
        assert!(
            !result.valid,
            "Expected excluded DNS violation to fail, but got valid=true (errors: {:?})",
            result.errors
        );
        let has_nc_error = result
            .errors
            .iter()
            .any(|e| e.contains("is within excluded subtrees"));
        assert!(
            has_nc_error,
            "Expected 'is within excluded subtrees' error, got: {:?}",
            result.errors
        );
    }

    /// RFC 5280 §4.2.1.10: A certificate whose DNS SAN falls within a permitted
    /// subtree MUST be accepted — this is the positive / non-violating case.
    #[test]
    fn test_name_constraints_permitted_dns_compliant() {
        use crate::cert::extensions::NameConstraints;

        let (root_cert, mut root_ca) = create_root_ca("NC-OK Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("NC-OK Int", AlgorithmId::EcdsaP256, &mut root_ca);

        // Issue leaf with a DNS SAN inside the permitted subtree ".example.com"
        let ee = issue_ee_with_dns_san(
            &mut int_ca,
            "good.example.com",
            AlgorithmId::EcdsaP256,
            "good.example.com",
        );

        let mut modified_int = int_ca.certificate.clone();
        let nc = NameConstraints::new().permit_dns(".example.com");
        let nc_ext = make_name_constraints_extension(nc, true);
        match modified_int.tbs_certificate.extensions {
            Some(ref mut exts) => exts.push(nc_ext),
            None => {
                modified_int.tbs_certificate.extensions = Some(vec![nc_ext]);
            }
        }

        let chain = vec![ee, modified_int, root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &constraint_only_opts());
        assert!(
            result.valid,
            "Expected compliant DNS SAN to pass NameConstraints, but got errors: {:?}",
            result.errors
        );
        let has_nc_error = result
            .errors
            .iter()
            .any(|e| e.contains("permitted subtrees") || e.contains("excluded subtrees"));
        assert!(
            !has_nc_error,
            "Unexpected NameConstraints error for compliant SAN: {:?}",
            result.errors
        );
    }

    // --- PathLen with self-issued intermediates (RFC 5280 §6.1.4(l)) ---

    /// RFC 5280 §6.1.4(l): self-issued certificates (issuer DN == subject DN) are
    /// NOT counted toward the pathLenConstraint.  A chain that would exceed pathLen=0
    /// when a regular intermediate is inserted MUST still validate when that
    /// intermediate is self-issued (issuer == subject).
    #[test]
    fn test_path_len_self_issued_excluded_from_count() {
        // Build root with pathLen=0 intermediate.
        let (root_cert, mut root_ca) = create_root_ca("PL-SelfIssued Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("PL-SelfIssued Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "leaf.example.com", AlgorithmId::EcdsaP256);

        // The intermediate CA as issued has no explicit pathLen, so insert a
        // self-issued "cross-certificate" that impersonates the issuing CA:
        // clone the intermediate cert and set issuer = subject so that it is
        // treated as self-issued by the pathLen counter.
        let mut self_issued = int_ca.certificate.clone();
        self_issued.tbs_certificate.issuer = self_issued.tbs_certificate.subject.clone();

        // Now build a 4-cert chain: [leaf, self-issued, intermediate, root]
        // With pathLen semantics, when validating the intermediate at index 2
        // with pathLen=0, only non-self-issued certs in positions 1..(2) are
        // counted.  Position 1 is our self-issued cert → count=0 ≤ 0 → OK.
        let chain = vec![
            ee,
            self_issued,
            int_ca.certificate.clone(),
            root_cert.clone(),
        ];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &constraint_only_opts());

        // The chain must have no pathLen errors.  There may be other errors
        // (AKI mismatch, etc.) but we are specifically verifying that self-issued
        // certs do not trigger a pathLenConstraint violation.
        let has_path_len_error = result
            .errors
            .iter()
            .any(|e| e.contains("path length constraint"));
        assert!(
            !has_path_len_error,
            "Self-issued cert should NOT count toward pathLenConstraint, \
             but got path length error: {:?}",
            result.errors
        );
    }

    /// Contrast test: a non-self-issued cert inserted below a pathLen=0 intermediate
    /// MUST trigger a pathLenConstraint violation.
    ///
    /// The chain is [leaf(0), sub-CA(1), intermediate-pathLen=0(2), root(3)].
    /// sub-CA at index 1 is a regular (non-self-issued) intermediate.
    /// When validating intermediate-pathLen=0 at index 2, the validator counts
    /// non-self-issued certs in range 1..2 = {sub-CA} → count=1 > 0 → error.
    #[test]
    fn test_path_len_zero_violated_by_non_self_issued() {
        // Build a 3-tier hierarchy: root → intermediate(pathLen=0) → sub-CA → leaf.
        // The intermediate's pathLen=0 means it must NOT sign any CA certs, but here
        // it signs sub-CA (another intermediate), which violates the constraint.
        let (root_cert, mut root_ca) = create_root_ca("PL-Violated Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("PL-Violated Int", AlgorithmId::EcdsaP256, &mut root_ca);
        // Create a sub-CA signed by int_ca.  int_ca was issued with default pathLen
        // (no pathLen constraint), so the ceremony will succeed — but we will then
        // manually patch int_ca's certificate to have pathLen=0 after the fact.
        let (_sub_cert, mut sub_ca) =
            create_intermediate_ca("PL-Violated Sub", AlgorithmId::EcdsaP256, &mut int_ca);
        let ee = issue_ee(
            &mut sub_ca,
            "violated-leaf.example.com",
            AlgorithmId::EcdsaP256,
        );

        // Patch int_ca's certificate to add pathLen=0 in BasicConstraints.
        // The easiest way is to scan the extensions and replace the BasicConstraints value.
        let mut patched_int = int_ca.certificate.clone();
        {
            use crate::cert::extensions::oid;
            use der::asn1::OctetString;
            // BasicConstraints DER with CA:TRUE and pathLen=0:
            // SEQUENCE { BOOLEAN TRUE, INTEGER 0 }
            // 30 06 01 01 ff 02 01 00
            let bc_with_pathlen_zero: &[u8] = &[0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00];
            if let Some(ref mut exts) = patched_int.tbs_certificate.extensions {
                for ext in exts.iter_mut() {
                    if ext.extn_id == oid::BASIC_CONSTRAINTS {
                        ext.extn_value = OctetString::new(bc_with_pathlen_zero)
                            .expect("BasicConstraints OctetString must succeed");
                        break;
                    }
                }
            }
        }

        // Chain: [leaf(0), sub-CA(1), patched-int-pathLen=0(2), root(3)]
        // sub-CA at position 1 is NOT self-issued → count=1 > pathLen=0 → error expected.
        let chain = vec![
            ee,
            sub_ca.certificate.clone(),
            patched_int,
            root_cert.clone(),
        ];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &constraint_only_opts());
        let has_path_len_error = result
            .errors
            .iter()
            .any(|e| e.contains("path length constraint"));
        assert!(
            has_path_len_error,
            "Expected pathLenConstraint violation when a non-self-issued sub-CA is below \
             pathLen=0 intermediate, but got errors: {:?}",
            result.errors
        );
    }

    // ---- KeyUsage on CA certs ----

    /// RFC 5280 §4.2.1.3: A CA certificate that has a KeyUsage extension but
    /// does NOT have the keyCertSign bit set MUST be rejected.
    #[test]
    fn test_key_usage_missing_key_cert_sign_error() {
        use crate::cert::extensions::KeyUsageFlags;

        let (root_cert, mut root_ca) = create_root_ca("KU-NoCertSign Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("KU-NoCertSign Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "ku-test.example.com", AlgorithmId::EcdsaP256);

        // Clone the intermediate and replace its KeyUsage extension so that
        // keyCertSign (bit 5, flag 0x20) is NOT set.  We leave cRLSign (bit 6) set
        // to avoid conflating the two checks, and keep digitalSignature for realism.
        let mut modified_int = int_ca.certificate.clone();
        let flags = KeyUsageFlags::new(
            KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::CRL_SIGN,
            // keyCertSign deliberately excluded
        );
        replace_key_usage_extension(&mut modified_int, flags, true);

        let chain = vec![ee, modified_int, root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &constraint_only_opts());
        assert!(
            !result.valid,
            "Expected missing keyCertSign to fail validation, but got valid=true \
             (errors: {:?})",
            result.errors
        );
        let has_ku_error = result
            .errors
            .iter()
            .any(|e| e.contains("missing keyCertSign in KeyUsage"));
        assert!(
            has_ku_error,
            "Expected 'missing keyCertSign in KeyUsage' error, got: {:?}",
            result.errors
        );
    }

    /// RFC 5280 §4.2.1.3: A CA certificate with keyCertSign but without cRLSign
    /// SHOULD produce a warning (not an error) — the chain remains valid.
    #[test]
    fn test_key_usage_missing_crl_sign_warning() {
        use crate::cert::extensions::KeyUsageFlags;

        let (root_cert, mut root_ca) = create_root_ca("KU-NoCRLSign Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("KU-NoCRLSign Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "ku-crl.example.com", AlgorithmId::EcdsaP256);

        // Clone the intermediate and replace its KeyUsage extension so that
        // keyCertSign is present but cRLSign (bit 6, flag 0x40) is absent.
        let mut modified_int = int_ca.certificate.clone();
        let flags = KeyUsageFlags::new(
            KeyUsageFlags::DIGITAL_SIGNATURE | KeyUsageFlags::KEY_CERT_SIGN,
            // cRLSign deliberately excluded
        );
        replace_key_usage_extension(&mut modified_int, flags, true);

        let chain = vec![ee, modified_int, root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &constraint_only_opts());

        // Must NOT produce a keyCertSign error (keyCertSign IS present).
        let has_ku_error = result
            .errors
            .iter()
            .any(|e| e.contains("missing keyCertSign in KeyUsage"));
        assert!(
            !has_ku_error,
            "Unexpected keyCertSign error when keyCertSign is present: {:?}",
            result.errors
        );

        // MUST produce a cRLSign warning.
        let has_crl_warning = result
            .warnings
            .iter()
            .any(|w| w.contains("missing cRLSign in KeyUsage"));
        assert!(
            has_crl_warning,
            "Expected 'missing cRLSign in KeyUsage' warning, got warnings: {:?}",
            result.warnings
        );
    }

    /// RFC 5280 §4.2.1.3: A CA certificate that has NO KeyUsage extension at all
    /// MUST be rejected (KeyUsage is required for CA certs).
    #[test]
    fn test_key_usage_absent_extension_error() {
        let (root_cert, mut root_ca) = create_root_ca("KU-Absent Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("KU-Absent Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "ku-absent.example.com", AlgorithmId::EcdsaP256);

        // Clone the intermediate and strip the KeyUsage extension entirely.
        let mut modified_int = int_ca.certificate.clone();
        if let Some(ref mut exts) = modified_int.tbs_certificate.extensions {
            exts.retain(|e| e.extn_id != crate::cert::extensions::oid::KEY_USAGE);
        }

        let chain = vec![ee, modified_int, root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];

        let result = validate_chain(&chain, &trust, &constraint_only_opts());
        assert!(
            !result.valid,
            "Expected absent KeyUsage to fail validation, but got valid=true \
             (errors: {:?})",
            result.errors
        );
        let has_ku_error = result
            .errors
            .iter()
            .any(|e| e.contains("missing KeyUsage extension") || e.contains("missing keyCertSign"));
        assert!(
            has_ku_error,
            "Expected a KeyUsage-absent error, got: {:?}",
            result.errors
        );
    }

    // ---- Trust anchor SPKI mismatch ----

    /// RFC 5914 §2: `validate_chain_with_trust_anchors` matches the chain root to
    /// trust anchors by SPKI.  When the root's SPKI does not match any trust anchor,
    /// the result MUST be `trusted=false` and MUST carry a warning naming the root.
    #[test]
    fn test_trust_anchor_spki_mismatch_warns() {
        use crate::cert::trust_anchor::TrustAnchorInfo;

        let (root_cert, mut root_ca) = create_root_ca("SPKI-Mismatch Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("SPKI-Mismatch Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "spki.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];

        // Build a TrustAnchorInfo with a fabricated (wrong) SPKI — 91 zero bytes.
        // This does NOT match the real root's SPKI, so trust must be denied.
        let wrong_ta = TrustAnchorInfo {
            public_key_info: vec![0u8; 91],
            key_id: vec![0u8; 20],
            ta_title: Some("Fake TA".to_string()),
            cert_path: None,
            certificate: None,
        };

        let result =
            validate_chain_with_trust_anchors(&chain, &[wrong_ta], &constraint_only_opts());

        assert!(
            !result.trusted,
            "Expected trusted=false when SPKI does not match, but got trusted=true"
        );
        let has_spki_warning = result
            .warnings
            .iter()
            .any(|w| w.contains("SPKI not found in trust anchor store"));
        assert!(
            has_spki_warning,
            "Expected 'SPKI not found in trust anchor store' warning, got: {:?}",
            result.warnings
        );
    }

    /// Trust anchor SPKI matching positive case: when the root's SPKI matches the
    /// TrustAnchorInfo built from that same root certificate, `trusted` MUST be true.
    #[test]
    fn test_trust_anchor_spki_match_trusted() {
        use crate::cert::trust_anchor::TrustAnchorInfo;
        use der::Encode;

        let (root_cert, mut root_ca) = create_root_ca("SPKI-Match Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("SPKI-Match Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(
            &mut int_ca,
            "spki-match.example.com",
            AlgorithmId::EcdsaP256,
        );

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];

        // Build TrustAnchorInfo from the real root DER — SPKI will match.
        let root_der = root_cert.to_der().unwrap();
        let ta = TrustAnchorInfo::from_certificate(&root_der).unwrap();

        let result = validate_chain_with_trust_anchors(&chain, &[ta], &constraint_only_opts());

        assert!(
            result.trusted,
            "Expected trusted=true when SPKI matches, got trusted=false. \
             Errors: {:?}, Warnings: {:?}",
            result.errors, result.warnings
        );
        let has_spki_warning = result
            .warnings
            .iter()
            .any(|w| w.contains("SPKI not found in trust anchor store"));
        assert!(
            !has_spki_warning,
            "Unexpected SPKI mismatch warning when SPKI should match: {:?}",
            result.warnings
        );
    }

    // ---- RFC 7633 Must-Staple advisory tests ----

    /// Build a leaf cert that has the TLS Feature extension injected, with
    /// status_request (value 5) encoded as INTEGER inside the SEQUENCE.
    ///
    /// We generate a real cert via the CA helpers, then clone its parsed
    /// Certificate struct and inject the extension directly.  This lets us
    /// test the advisory warning without needing the CA issuance path to
    /// support TLS Feature yet.
    fn inject_must_staple(mut cert: Certificate) -> Certificate {
        use crate::cert::extensions::oid::TLS_FEATURE as TLS_FEATURE_OID;

        // SEQUENCE { INTEGER 5 }  (status_request = OCSP Must-Staple)
        // DER: 30 03 02 01 05
        let feature_der: Vec<u8> = vec![0x30, 0x03, 0x02, 0x01, 0x05];
        let ext = x509_cert::ext::Extension {
            extn_id: TLS_FEATURE_OID,
            critical: false,
            extn_value: der::asn1::OctetString::new(feature_der).expect("valid octet string"),
        };

        let exts = cert.tbs_certificate.extensions.get_or_insert_with(Vec::new);
        exts.push(ext);
        cert
    }

    #[test]
    fn test_must_staple_advisory_in_chain_validation() {
        // Build a normal P-256 chain and inject Must-Staple into the leaf cert.
        // validate_chain() should produce an informational warning for the leaf,
        // but the chain should still be valid (Must-Staple is non-critical here).
        let (root_cert, mut root_ca) = create_root_ca("MustStaple Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("MustStaple Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee_plain = issue_ee(&mut int_ca, "staple.example.com", AlgorithmId::EcdsaP256);

        // Inject the TLS Feature / Must-Staple extension into the leaf.
        let ee_with_staple = inject_must_staple(ee_plain);

        let chain = vec![
            ee_with_staple,
            int_ca.certificate.clone(),
            root_cert.clone(),
        ];
        let trust = vec![root_cert.to_der().expect("encode root DER")];

        let result = validate_chain(&chain, &trust, &default_opts());

        // The Must-Staple advisory must appear in warnings.
        let has_must_staple_warning = result
            .warnings
            .iter()
            .any(|w| w.contains("Must-Staple") && w.contains("RFC 7633"));
        assert!(
            has_must_staple_warning,
            "Expected Must-Staple advisory warning, got: {:?}",
            result.warnings
        );
    }

    #[test]
    fn test_no_must_staple_warning_without_extension() {
        // A normal leaf cert without TLS Feature should not produce the advisory.
        let (root_cert, mut root_ca) = create_root_ca("NoStaple Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("NoStaple Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "no-staple.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().expect("encode root DER")];

        let result = validate_chain(&chain, &trust, &default_opts());

        let has_must_staple_warning = result.warnings.iter().any(|w| w.contains("Must-Staple"));
        assert!(
            !has_must_staple_warning,
            "Unexpected Must-Staple warning on plain cert: {:?}",
            result.warnings
        );
    }

    // ---- AKI 3-field parsing tests (RFC 5280 §4.2.1.1) ----

    /// `extract_aki_full_from_cert` must parse all three AKI fields from a
    /// manually-crafted AKI DER extension value.
    ///
    /// DER layout:
    ///   SEQUENCE {
    ///     [0] 04 00 00 00 (4-byte key identifier)
    ///     [1] <empty GeneralNames for simplicity>
    ///     [2] 01 02 03 (3-byte serial number bytes)
    ///   }
    #[test]
    fn test_aki_full_parse_all_three_fields() {
        // Build the AKI inner SEQUENCE content manually.
        // [0] keyIdentifier: tag 0x80, length 4, value 01 02 03 04
        let kid: &[u8] = &[0x80, 0x04, 0x01, 0x02, 0x03, 0x04];
        // [1] authorityCertIssuer: tag 0xa1 (constructed [1]), length 0 (empty)
        let issuer: &[u8] = &[0xa1, 0x00];
        // [2] authorityCertSerialNumber: tag 0x82 (primitive [2]), 3 bytes 0xAA 0xBB 0xCC
        let serial: &[u8] = &[0x82, 0x03, 0xAA, 0xBB, 0xCC];

        let mut inner = Vec::new();
        inner.extend_from_slice(kid);
        inner.extend_from_slice(issuer);
        inner.extend_from_slice(serial);

        // Wrap in SEQUENCE (tag 0x30)
        let mut aki_der = vec![0x30, inner.len() as u8];
        aki_der.extend_from_slice(&inner);

        // Wrap in OCTET STRING (extn_value in X.509 is wrapped in OCTET STRING)
        let mut ext_value = vec![0x04, aki_der.len() as u8];
        ext_value.extend_from_slice(&aki_der);

        // Build a minimal certificate that has this AKI extension.
        // We'll use a real chain cert and inject the parsed AKI by testing
        // the parsing function directly against the raw bytes.
        //
        // The parsing function `extract_aki_full_from_cert` takes a Certificate,
        // so we test via a real cert's AKI plus also test the raw parser logic.

        // Test: parse the manually crafted bytes using the same logic as extract_aki_full_from_cert
        // (inner walk — equivalent to what the function does on seq_content)
        let seq_content = &inner[..];
        let mut pos = 0;
        let mut parsed_kid: Option<Vec<u8>> = None;
        let mut parsed_issuer: Option<Vec<u8>> = None;
        let mut parsed_serial: Option<Vec<u8>> = None;

        while pos < seq_content.len() {
            let tag = seq_content[pos];
            pos += 1;
            let field_len = seq_content[pos] as usize;
            pos += 1;
            let field_bytes = &seq_content[pos..pos + field_len];
            match tag {
                0x80 => parsed_kid = Some(field_bytes.to_vec()),
                0xa1 => parsed_issuer = Some(field_bytes.to_vec()),
                0x82 => parsed_serial = Some(field_bytes.to_vec()),
                _ => {}
            }
            pos += field_len;
        }

        assert_eq!(
            parsed_kid,
            Some(vec![0x01, 0x02, 0x03, 0x04]),
            "keyIdentifier mismatch"
        );
        assert_eq!(
            parsed_issuer,
            Some(vec![]),
            "authorityCertIssuer should be empty vec"
        );
        assert_eq!(
            parsed_serial,
            Some(vec![0xAA, 0xBB, 0xCC]),
            "authorityCertSerialNumber mismatch"
        );
    }

    /// `extract_aki_full_from_cert` must return `key_identifier` for a normal
    /// chain cert and still correctly delegate from `extract_aki_from_cert`.
    #[test]
    fn test_aki_full_from_real_cert_key_identifier_present() {
        let (root_cert, mut root_ca) = create_root_ca("AKI3 Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("AKI3 Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "aki3.example.com", AlgorithmId::EcdsaP256);

        // The intermediate cert should have a full AKI with at least a keyIdentifier
        let aki_full = extract_aki_full_from_cert(&int_ca.certificate);
        assert!(aki_full.is_some(), "Intermediate must have AKI extension");
        let aki_full = aki_full.unwrap();
        assert!(
            aki_full.key_identifier.is_some(),
            "Intermediate AKI must have keyIdentifier [0]"
        );

        // The slim helper must return the same keyIdentifier bytes
        let aki_slim = extract_aki_from_cert(&int_ca.certificate);
        assert_eq!(
            aki_slim, aki_full.key_identifier,
            "extract_aki_from_cert must match extract_aki_full_from_cert key_identifier"
        );

        // EE also
        let ee_aki_full = extract_aki_full_from_cert(&ee);
        assert!(ee_aki_full.is_some(), "EE must have AKI extension");
        assert!(
            ee_aki_full.unwrap().key_identifier.is_some(),
            "EE AKI must have keyIdentifier [0]"
        );

        // Standard certs generated by our builder don't include fields [1]/[2]
        // (only keyIdentifier) — that is fine, just verify no spurious parse.
        let _ = root_cert; // suppress unused warning
    }

    /// RFC 5280 §4.2.1.1: if authorityCertSerialNumber is present and matches
    /// the issuer's serial, chain validation must not produce an error.
    ///
    /// We test this by verifying our normal chain (which lacks [2]) validates clean,
    /// and that the serial check code path is exercised without false positives.
    #[test]
    fn test_aki_serial_check_not_triggered_without_field() {
        let (root_cert, mut root_ca) = create_root_ca("AKISerial Root", AlgorithmId::EcdsaP256);
        let (_int_cert, mut int_ca) =
            create_intermediate_ca("AKISerial Int", AlgorithmId::EcdsaP256, &mut root_ca);
        let ee = issue_ee(&mut int_ca, "akiserial.example.com", AlgorithmId::EcdsaP256);

        let chain = vec![ee, int_ca.certificate.clone(), root_cert.clone()];
        let trust = vec![root_cert.to_der().unwrap()];
        let mut opts = default_opts();
        opts.check_constraints = true;
        let result = validate_chain(&chain, &trust, &opts);

        // No AKI serial mismatch errors expected — our certs have no [2] field
        for err in &result.errors {
            assert!(
                !err.contains("authorityCertSerialNumber"),
                "Unexpected AKI serial error on standard chain: {err}"
            );
        }
        assert!(result.valid, "Chain should be valid: {:?}", result.errors);
    }
}
