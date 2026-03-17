//! Algorithm validation — RFC 4055 and NIST SP 800-57
//!
//! Provides:
//! - RSA-PSS AlgorithmIdentifier parameter validation (RFC 4055 §3.3 / §5)
//! - Algorithm strength validation per NIST SP 800-57 Part 1 Rev 5

use const_oid::ObjectIdentifier;

use crate::algo::oid;
use crate::algo::AlgorithmId;
use crate::error::Error;

// ──────────────────────────────────────────────────────────────────────────────
// RSA-PSS parameter validation (RFC 4055 §3.3 / §5)
// ──────────────────────────────────────────────────────────────────────────────

/// Parsed and validated RSASSA-PSS parameters per RFC 4055 §3.3.
///
/// ```text
/// RSASSA-PSS-params ::= SEQUENCE {
///     hashAlgorithm      [0] HashAlgorithm DEFAULT sha1,
///     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
///     saltLength         [2] INTEGER DEFAULT 20,
///     trailerField       [3] TrailerField DEFAULT trailerFieldBC
/// }
/// ```
///
/// Validation enforces:
/// - hashAlgorithm must be SHA-256, SHA-384, or SHA-512 (rejects SHA-1, MD5)
/// - maskGenAlgorithm must be id-mgf1 with the same hash as hashAlgorithm
/// - saltLength must equal the hash output length (32/48/64 bytes)
/// - trailerField must be 1 (trailerFieldBC, the only standardized value)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPssParams {
    pub hash_algorithm: HashAlgorithm,
    pub salt_length: u32,
    pub trailer_field: u8,
}

/// Approved hash algorithms for RSA-PSS (RFC 4055 §3.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    /// Output length in bytes (used to verify saltLength)
    pub fn output_len(self) -> u32 {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn oid(self) -> ObjectIdentifier {
        match self {
            Self::Sha256 => oid::SHA256,
            Self::Sha384 => oid::SHA384,
            Self::Sha512 => oid::SHA512,
        }
    }
}

/// Errors specific to RSA-PSS parameter validation
#[derive(Debug, thiserror::Error)]
pub enum PssParamError {
    #[error("RSA-PSS parameters are absent (required for RSASSA-PSS AlgorithmIdentifier)")]
    Absent,

    #[error("truncated DER at offset {0}")]
    Truncated(usize),

    #[error("invalid DER encoding: {0}")]
    InvalidDer(String),

    #[error("unsupported hash algorithm OID {0}: only SHA-256/384/512 are permitted")]
    UnsupportedHash(String),

    #[error("hash algorithm mismatch: hashAlgorithm is {hash} but mgf1 uses {mgf1_hash}")]
    HashMismatch { hash: String, mgf1_hash: String },

    #[error("maskGenAlgorithm must be id-mgf1 (1.2.840.113549.1.1.8), got {0}")]
    UnsupportedMgf(String),

    #[error("saltLength {actual} does not match hash output length {expected} (RFC 4055 §3.3)")]
    SaltLengthMismatch { actual: u32, expected: u32 },

    #[error("trailerField must be 1 (trailerFieldBC), got {0}")]
    InvalidTrailerField(u32),
}

impl From<PssParamError> for Error {
    fn from(e: PssParamError) -> Self {
        Error::Encoding(e.to_string())
    }
}

/// Validate the DER-encoded RSASSA-PSS-params from an AlgorithmIdentifier.
///
/// `params_der` must be the raw bytes of the parameters field — i.e. the
/// content of the SEQUENCE that follows the RSASSA-PSS OID in an
/// AlgorithmIdentifier. Do not include the outer AlgorithmIdentifier SEQUENCE
/// itself; pass only the parameters SEQUENCE.
///
/// Returns `Ok(RsaPssParams)` if all parameters are present and valid.
/// Returns `Err` if absent, malformed, or violate RFC 4055 §3.3 constraints.
pub fn validate_rsa_pss_params(
    params_der: &[u8],
) -> std::result::Result<RsaPssParams, PssParamError> {
    if params_der.is_empty() {
        return Err(PssParamError::Absent);
    }

    // Outer SEQUENCE
    let (seq_body, _) = parse_sequence(params_der, 0)?;
    let mut pos = 0usize;

    // Default values per RFC 4055 §3.3
    let mut hash = HashAlgorithm::Sha256; // RFC says default is sha1 but we require explicit
    let mut mgf_hash: Option<HashAlgorithm> = None;
    let mut salt_length: u32 = hash.output_len();
    let mut trailer_field: u8 = 1;
    let mut hash_explicit = false;

    while pos < seq_body.len() {
        let tag = seq_body[pos];
        match tag {
            // [0] EXPLICIT hashAlgorithm
            0xA0 => {
                let (content, consumed) = parse_context_explicit(seq_body, pos)?;
                hash = parse_hash_algorithm(content)?;
                hash_explicit = true;
                pos += consumed;
            }
            // [1] EXPLICIT maskGenAlgorithm
            0xA1 => {
                let (content, consumed) = parse_context_explicit(seq_body, pos)?;
                mgf_hash = Some(parse_mgf1_algorithm(content)?);
                pos += consumed;
            }
            // [2] EXPLICIT saltLength INTEGER
            0xA2 => {
                let (content, consumed) = parse_context_explicit(seq_body, pos)?;
                salt_length = parse_integer_u32(content)?;
                pos += consumed;
            }
            // [3] EXPLICIT trailerField INTEGER
            0xA3 => {
                let (content, consumed) = parse_context_explicit(seq_body, pos)?;
                let val = parse_integer_u32(content)?;
                if val > 255 {
                    return Err(PssParamError::InvalidTrailerField(val));
                }
                trailer_field = val as u8;
                pos += consumed;
            }
            _ => {
                // Unknown tag — skip using DER length
                let (len, lbytes) = parse_der_length(seq_body, pos + 1)?;
                pos += 1 + lbytes + len;
            }
        }
    }

    // If hash was not explicit, default is SHA-1 which we reject
    if !hash_explicit {
        return Err(PssParamError::UnsupportedHash(
            "sha-1 (default)".to_string(),
        ));
    }

    // MGF must use the same hash as hashAlgorithm (RFC 4055 §3.3)
    if let Some(mh) = mgf_hash {
        if mh != hash {
            return Err(PssParamError::HashMismatch {
                hash: format!("{:?}", hash),
                mgf1_hash: format!("{:?}", mh),
            });
        }
    }

    // saltLength must equal hash output length
    let expected_salt = hash.output_len();
    if salt_length != expected_salt {
        return Err(PssParamError::SaltLengthMismatch {
            actual: salt_length,
            expected: expected_salt,
        });
    }

    // trailerField must be 1 (trailerFieldBC)
    if trailer_field != 1 {
        return Err(PssParamError::InvalidTrailerField(trailer_field as u32));
    }

    Ok(RsaPssParams {
        hash_algorithm: hash,
        salt_length,
        trailer_field,
    })
}

// Parse an AlgorithmIdentifier SEQUENCE and extract the hash OID.
// Returns the HashAlgorithm if the OID is SHA-256/384/512.
fn parse_hash_algorithm(der: &[u8]) -> std::result::Result<HashAlgorithm, PssParamError> {
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
    let (seq_body, _) = parse_sequence(der, 0)?;
    let oid = parse_oid(seq_body, 0)?;

    if oid == oid::SHA256 {
        Ok(HashAlgorithm::Sha256)
    } else if oid == oid::SHA384 {
        Ok(HashAlgorithm::Sha384)
    } else if oid == oid::SHA512 {
        Ok(HashAlgorithm::Sha512)
    } else if oid == oid::SHA1 {
        Err(PssParamError::UnsupportedHash(
            "sha-1 (1.3.14.3.2.26)".to_string(),
        ))
    } else if oid == oid::MD5 {
        Err(PssParamError::UnsupportedHash(
            "md5 (1.2.840.113549.2.5)".to_string(),
        ))
    } else if oid == oid::SHA224 {
        Err(PssParamError::UnsupportedHash(
            "sha-224 (2.16.840.1.101.3.4.2.4)".to_string(),
        ))
    } else {
        Err(PssParamError::UnsupportedHash(format!("{}", oid)))
    }
}

// Parse a MaskGenAlgorithm SEQUENCE and extract the hash inside mgf1.
// Per RFC 4055: MaskGenAlgorithm ::= AlgorithmIdentifier { { PKCS1MGFAlgorithms } }
// where id-mgf1 is used and its parameter is an AlgorithmIdentifier for the hash.
fn parse_mgf1_algorithm(der: &[u8]) -> std::result::Result<HashAlgorithm, PssParamError> {
    let (seq_body, _) = parse_sequence(der, 0)?;
    if seq_body.is_empty() {
        return Err(PssParamError::InvalidDer(
            "empty mgf1 AlgorithmIdentifier".into(),
        ));
    }

    let mgf_oid = parse_oid(seq_body, 0)?;
    if mgf_oid != oid::MGF1 {
        return Err(PssParamError::UnsupportedMgf(format!("{}", mgf_oid)));
    }

    // Skip OID to reach the parameter (hash AlgorithmIdentifier)
    let (oid_len, oid_lbytes) = parse_der_length(seq_body, 1)?;
    let after_oid = 1 + oid_lbytes + oid_len;
    if after_oid >= seq_body.len() {
        return Err(PssParamError::InvalidDer("mgf1 parameters absent".into()));
    }

    parse_hash_algorithm(&seq_body[after_oid..])
}

// Returns (sequence_body, total_bytes_consumed_including_tag_and_length)
fn parse_sequence(der: &[u8], pos: usize) -> std::result::Result<(&[u8], usize), PssParamError> {
    if pos >= der.len() {
        return Err(PssParamError::Truncated(pos));
    }
    if der[pos] != 0x30 {
        return Err(PssParamError::InvalidDer(format!(
            "expected SEQUENCE (0x30) at offset {}, got 0x{:02X}",
            pos, der[pos]
        )));
    }
    let (len, lbytes) = parse_der_length(der, pos + 1)?;
    let body_start = pos + 1 + lbytes;
    let body_end = body_start + len;
    if body_end > der.len() {
        return Err(PssParamError::Truncated(body_end));
    }
    Ok((&der[body_start..body_end], 1 + lbytes + len))
}

// Returns (context_content_bytes, total_bytes_consumed_including_tag_and_length)
fn parse_context_explicit(
    der: &[u8],
    pos: usize,
) -> std::result::Result<(&[u8], usize), PssParamError> {
    if pos >= der.len() {
        return Err(PssParamError::Truncated(pos));
    }
    let (len, lbytes) = parse_der_length(der, pos + 1)?;
    let body_start = pos + 1 + lbytes;
    let body_end = body_start + len;
    if body_end > der.len() {
        return Err(PssParamError::Truncated(body_end));
    }
    Ok((&der[body_start..body_end], 1 + lbytes + len))
}

// Returns (oid, _) — parses the first OID tag+length+value starting at `pos`.
fn parse_oid(der: &[u8], pos: usize) -> std::result::Result<ObjectIdentifier, PssParamError> {
    if pos >= der.len() {
        return Err(PssParamError::Truncated(pos));
    }
    if der[pos] != 0x06 {
        return Err(PssParamError::InvalidDer(format!(
            "expected OID (0x06) at offset {}, got 0x{:02X}",
            pos, der[pos]
        )));
    }
    let (len, lbytes) = parse_der_length(der, pos + 1)?;
    let val_start = pos + 1 + lbytes;
    let val_end = val_start + len;
    if val_end > der.len() {
        return Err(PssParamError::Truncated(val_end));
    }
    ObjectIdentifier::from_bytes(&der[val_start..val_end])
        .map_err(|e| PssParamError::InvalidDer(format!("invalid OID encoding: {}", e)))
}

// Returns (integer_value_as_u32, ...)  — parses an INTEGER tag+length+value.
fn parse_integer_u32(der: &[u8]) -> std::result::Result<u32, PssParamError> {
    if der.len() < 2 {
        return Err(PssParamError::Truncated(0));
    }
    if der[0] != 0x02 {
        return Err(PssParamError::InvalidDer(format!(
            "expected INTEGER (0x02), got 0x{:02X}",
            der[0]
        )));
    }
    let (len, lbytes) = parse_der_length(der, 1)?;
    let val_start = 1 + lbytes;
    let val_end = val_start + len;
    if val_end > der.len() {
        return Err(PssParamError::Truncated(val_end));
    }
    let bytes = &der[val_start..val_end];
    if bytes.is_empty() || bytes.len() > 5 {
        return Err(PssParamError::InvalidDer(format!(
            "INTEGER length {} out of range for u32",
            bytes.len()
        )));
    }
    let mut val: u32 = 0;
    for &b in bytes {
        val = (val << 8) | b as u32;
    }
    Ok(val)
}

// Returns (length_value, bytes_consumed_for_length_field)
fn parse_der_length(der: &[u8], pos: usize) -> std::result::Result<(usize, usize), PssParamError> {
    if pos >= der.len() {
        return Err(PssParamError::Truncated(pos));
    }
    if der[pos] < 128 {
        Ok((der[pos] as usize, 1))
    } else {
        let num_bytes = (der[pos] & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 4 || pos + 1 + num_bytes > der.len() {
            return Err(PssParamError::InvalidDer(format!(
                "invalid long-form DER length at offset {}",
                pos
            )));
        }
        let mut length: usize = 0;
        for i in 0..num_bytes {
            length = (length << 8) | (der[pos + 1 + i] as usize);
        }
        Ok((length, 1 + num_bytes))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Algorithm strength validation (NIST SP 800-57 Part 1 Rev 5)
// ──────────────────────────────────────────────────────────────────────────────

/// A non-blocking warning about algorithm or key strength.
///
/// These are advisory — the caller decides whether to reject or warn.
/// Use `validate_algorithm_strength` to generate a list of warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrengthWarning {
    pub level: WarningLevel,
    pub message: String,
}

/// Severity of a strength warning
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WarningLevel {
    /// Informational — algorithm is compliant but approaching end of recommended use
    Advisory,
    /// The algorithm or key size does not meet current NIST SP 800-57 recommendations
    NonCompliant,
    /// Rejected — the algorithm must not be used (e.g., key too small, weak hash in FIPS mode)
    Rejected,
}

/// Validate algorithm and key size against NIST SP 800-57 Part 1 Rev 5.
///
/// Returns a list of warnings. An empty list means no issues found.
///
/// `key_bits` is the key size in bits for RSA; `None` for ECC/PQC algorithms
/// (curve/parameter set implies the key size).
///
/// `fips_mode` additionally enforces FIPS 140-3 / SP 800-131A Rev 2 restrictions:
/// - RSA < 3072 bits → Rejected
/// - SHA-1 use → Rejected
pub fn validate_algorithm_strength(
    algo: &AlgorithmId,
    key_bits: Option<usize>,
    fips_mode: bool,
) -> Vec<StrengthWarning> {
    let mut warnings = Vec::new();

    match algo {
        AlgorithmId::Rsa2048
        | AlgorithmId::Rsa3072
        | AlgorithmId::Rsa4096
        | AlgorithmId::Rsa3072Pss
        | AlgorithmId::Rsa4096Pss => {
            let bits = key_bits.unwrap_or(match algo {
                AlgorithmId::Rsa2048 => 2048,
                AlgorithmId::Rsa3072 | AlgorithmId::Rsa3072Pss => 3072,
                AlgorithmId::Rsa4096 | AlgorithmId::Rsa4096Pss => 4096,
                _ => 0,
            });

            if bits < 2048 {
                warnings.push(StrengthWarning {
                    level: WarningLevel::Rejected,
                    message: format!(
                        "RSA key size {} bits is below the minimum of 2048 bits (NIST SP 800-57 §5.6.1)",
                        bits
                    ),
                });
            } else if bits == 2048 && fips_mode {
                warnings.push(StrengthWarning {
                    level: WarningLevel::Rejected,
                    message: "RSA-2048 is below the FIPS minimum of 3072 bits for new signatures \
                               (NIST SP 800-131A Rev 2 §2)"
                        .to_string(),
                });
            } else if bits == 2048 {
                warnings.push(StrengthWarning {
                    level: WarningLevel::Advisory,
                    message: "RSA-2048 provides ~112-bit security; NIST SP 800-57 recommends \
                               3072+ bits for post-2030 use"
                        .to_string(),
                });
            }
        }

        AlgorithmId::EcdsaP256 | AlgorithmId::EcdsaP384 => {
            // P-256 and P-384 are both NIST-approved; no sub-P-256 curves are supported
            // Advisory only: P-256 provides ~128-bit, P-384 provides ~192-bit
        }

        AlgorithmId::Ed25519 => {
            if fips_mode {
                warnings.push(StrengthWarning {
                    level: WarningLevel::Rejected,
                    message: "Ed25519 is not FIPS-approved (RFC 8032 / RFC 8410); \
                               use ECDSA P-256/P-384 in FIPS mode"
                        .to_string(),
                });
            }
        }

        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa44
        | AlgorithmId::MlDsa65
        | AlgorithmId::MlDsa87
        | AlgorithmId::SlhDsaSha2_128s
        | AlgorithmId::SlhDsaSha2_192s
        | AlgorithmId::SlhDsaSha2_256s
        | AlgorithmId::MlDsa44EcdsaP256
        | AlgorithmId::MlDsa65EcdsaP256
        | AlgorithmId::MlDsa65EcdsaP384
        | AlgorithmId::MlDsa87EcdsaP384 => {
            if fips_mode {
                warnings.push(StrengthWarning {
                    level: WarningLevel::Rejected,
                    message: format!("{} is not yet validated in a FIPS 140-3 module", algo),
                });
            }
        }
    }

    warnings
}

/// Returns true if the algorithm meets minimum strength requirements.
///
/// Convenience wrapper around `validate_algorithm_strength` that returns
/// `false` if any `Rejected`-level warnings are present.
pub fn meets_minimum_strength(
    algo: &AlgorithmId,
    key_bits: Option<usize>,
    fips_mode: bool,
) -> bool {
    validate_algorithm_strength(algo, key_bits, fips_mode)
        .iter()
        .all(|w| w.level < WarningLevel::Rejected)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algo::AlgorithmId;

    // ── RSA-PSS parameter validation ─────────────────────────────────────────

    /// Build a minimal RSASSA-PSS-params SEQUENCE with SHA-256.
    ///
    /// ```text
    /// SEQUENCE {
    ///   [0] SEQUENCE { OID sha-256, NULL }
    ///   [1] SEQUENCE { OID mgf1, SEQUENCE { OID sha-256, NULL } }
    ///   [2] INTEGER 32
    ///   [3] INTEGER 1
    /// }
    /// ```
    fn pss_params_sha256() -> Vec<u8> {
        crate::algo::AlgorithmId::pss_sha256_params()
    }

    #[test]
    fn test_pss_params_sha256_valid() {
        let der = pss_params_sha256();
        let params = validate_rsa_pss_params(&der).unwrap();
        assert_eq!(params.hash_algorithm, HashAlgorithm::Sha256);
        assert_eq!(params.salt_length, 32);
        assert_eq!(params.trailer_field, 1);
    }

    #[test]
    fn test_pss_params_empty_rejected() {
        let result = validate_rsa_pss_params(&[]);
        assert!(matches!(result, Err(PssParamError::Absent)));
    }

    #[test]
    fn test_pss_params_sha384_valid() {
        // Build params with SHA-384: salt = 48
        let der = build_pss_params_for_hash(HashAlgorithm::Sha384);
        let params = validate_rsa_pss_params(&der).unwrap();
        assert_eq!(params.hash_algorithm, HashAlgorithm::Sha384);
        assert_eq!(params.salt_length, 48);
        assert_eq!(params.trailer_field, 1);
    }

    #[test]
    fn test_pss_params_sha512_valid() {
        let der = build_pss_params_for_hash(HashAlgorithm::Sha512);
        let params = validate_rsa_pss_params(&der).unwrap();
        assert_eq!(params.hash_algorithm, HashAlgorithm::Sha512);
        assert_eq!(params.salt_length, 64);
        assert_eq!(params.trailer_field, 1);
    }

    #[test]
    fn test_pss_params_sha1_rejected() {
        let der = build_pss_params_sha1();
        let err = validate_rsa_pss_params(&der).unwrap_err();
        assert!(matches!(err, PssParamError::UnsupportedHash(_)));
        let msg = err.to_string();
        assert!(msg.contains("sha-1") || msg.contains("SHA-1") || msg.contains("1.3.14"));
    }

    #[test]
    fn test_pss_params_salt_mismatch_rejected() {
        // SHA-256 but salt=20 (sha-1 default) — should fail
        let der = build_pss_params_wrong_salt();
        let err = validate_rsa_pss_params(&der).unwrap_err();
        assert!(
            matches!(
                err,
                PssParamError::SaltLengthMismatch {
                    actual: 20,
                    expected: 32
                }
            ),
            "Expected SaltLengthMismatch(20, 32), got: {:?}",
            err
        );
    }

    #[test]
    fn test_pss_params_trailer_not_1_rejected() {
        let der = build_pss_params_bad_trailer();
        let err = validate_rsa_pss_params(&der).unwrap_err();
        assert!(matches!(err, PssParamError::InvalidTrailerField(2)));
    }

    #[test]
    fn test_pss_params_hash_mismatch_rejected() {
        // hashAlgorithm = SHA-256, mgf1 hash = SHA-384
        let der = build_pss_params_mismatched_hash();
        let err = validate_rsa_pss_params(&der).unwrap_err();
        assert!(matches!(err, PssParamError::HashMismatch { .. }));
    }

    #[test]
    fn test_pss_params_default_sha1_rejected() {
        // No [0] tag — hash defaults to sha-1, which must be rejected
        let der = build_pss_params_no_hash_tag();
        let err = validate_rsa_pss_params(&der).unwrap_err();
        assert!(
            matches!(err, PssParamError::UnsupportedHash(_)),
            "Default SHA-1 should be rejected, got: {:?}",
            err
        );
    }

    // ── Algorithm strength validation ─────────────────────────────────────────

    #[test]
    fn test_strength_rsa2048_advisory_non_fips() {
        let warnings = validate_algorithm_strength(&AlgorithmId::Rsa2048, None, false);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].level, WarningLevel::Advisory);
        assert!(warnings[0].message.contains("112-bit") || warnings[0].message.contains("3072"));
    }

    #[test]
    fn test_strength_rsa2048_rejected_fips() {
        let warnings = validate_algorithm_strength(&AlgorithmId::Rsa2048, None, true);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].level, WarningLevel::Rejected);
        assert!(warnings[0].message.contains("3072") || warnings[0].message.contains("FIPS"));
    }

    #[test]
    fn test_strength_rsa3072_no_warnings() {
        let warnings = validate_algorithm_strength(&AlgorithmId::Rsa3072, None, false);
        assert!(
            warnings.is_empty(),
            "RSA-3072 should have no warnings, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_strength_rsa3072_no_warnings_fips() {
        let warnings = validate_algorithm_strength(&AlgorithmId::Rsa3072, None, true);
        assert!(
            warnings.is_empty(),
            "RSA-3072 should be clean in FIPS mode too"
        );
    }

    #[test]
    fn test_strength_rsa4096_no_warnings() {
        let warnings = validate_algorithm_strength(&AlgorithmId::Rsa4096, None, false);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_strength_rsa1024_rejected() {
        let warnings = validate_algorithm_strength(&AlgorithmId::Rsa2048, Some(1024), false);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].level, WarningLevel::Rejected);
        assert!(warnings[0].message.contains("1024") || warnings[0].message.contains("2048"));
    }

    #[test]
    fn test_strength_ecdsa_p256_no_warnings() {
        let warnings = validate_algorithm_strength(&AlgorithmId::EcdsaP256, None, false);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_strength_ecdsa_p384_no_warnings() {
        let warnings = validate_algorithm_strength(&AlgorithmId::EcdsaP384, None, false);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_strength_ed25519_ok_non_fips() {
        let warnings = validate_algorithm_strength(&AlgorithmId::Ed25519, None, false);
        assert!(warnings.is_empty(), "Ed25519 is fine outside FIPS mode");
    }

    #[test]
    fn test_strength_ed25519_rejected_fips() {
        let warnings = validate_algorithm_strength(&AlgorithmId::Ed25519, None, true);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].level, WarningLevel::Rejected);
        assert!(warnings[0].message.contains("FIPS") || warnings[0].message.contains("Ed25519"));
    }

    #[test]
    fn test_meets_minimum_strength_rsa2048_non_fips() {
        // Advisory is not Rejected — passes minimum
        assert!(meets_minimum_strength(&AlgorithmId::Rsa2048, None, false));
    }

    #[test]
    fn test_meets_minimum_strength_rsa2048_fips_fails() {
        assert!(!meets_minimum_strength(&AlgorithmId::Rsa2048, None, true));
    }

    #[test]
    fn test_meets_minimum_strength_rsa3072_passes() {
        assert!(meets_minimum_strength(&AlgorithmId::Rsa3072, None, false));
        assert!(meets_minimum_strength(&AlgorithmId::Rsa3072, None, true));
    }

    #[test]
    fn test_meets_minimum_strength_too_small() {
        assert!(!meets_minimum_strength(
            &AlgorithmId::Rsa2048,
            Some(1024),
            false
        ));
    }

    // ── Helper builders for test vectors ─────────────────────────────────────

    fn build_pss_params_for_hash(hash: HashAlgorithm) -> Vec<u8> {
        let oid_ident = hash.oid();
        let oid_bytes = oid_ident.as_bytes();
        let salt = hash.output_len() as u8;

        // Build hash AlgorithmIdentifier: SEQUENCE { OID, NULL }
        let hash_ai = build_algorithm_identifier(oid_bytes, true);
        // Build mgf1 AlgorithmIdentifier: SEQUENCE { OID mgf1, SEQUENCE { OID hash, NULL } }
        let mgf_inner_ai = build_algorithm_identifier(oid_bytes, true);
        let mgf1_oid = oid::MGF1.as_bytes();
        let mgf1_ai = build_mgf1_ai(mgf1_oid, &mgf_inner_ai);

        let mut inner = Vec::new();
        // [0] hashAlgorithm
        inner.push(0xA0);
        inner.push(hash_ai.len() as u8);
        inner.extend_from_slice(&hash_ai);
        // [1] mgf
        inner.push(0xA1);
        inner.push(mgf1_ai.len() as u8);
        inner.extend_from_slice(&mgf1_ai);
        // [2] saltLength
        inner.push(0xA2);
        inner.push(0x03);
        inner.push(0x02); // INTEGER
        inner.push(0x01); // length 1
        inner.push(salt);
        // [3] trailerField = 1
        inner.push(0xA3);
        inner.push(0x03);
        inner.push(0x02); // INTEGER
        inner.push(0x01); // length 1
        inner.push(0x01);

        let mut result = vec![0x30, inner.len() as u8];
        result.extend_from_slice(&inner);
        result
    }

    fn build_algorithm_identifier(oid_bytes: &[u8], with_null: bool) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.push(0x06);
        inner.push(oid_bytes.len() as u8);
        inner.extend_from_slice(oid_bytes);
        if with_null {
            inner.push(0x05);
            inner.push(0x00);
        }
        let mut result = vec![0x30, inner.len() as u8];
        result.extend_from_slice(&inner);
        result
    }

    fn build_mgf1_ai(mgf1_oid: &[u8], inner_hash_ai: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.push(0x06);
        inner.push(mgf1_oid.len() as u8);
        inner.extend_from_slice(mgf1_oid);
        inner.extend_from_slice(inner_hash_ai);
        let mut result = vec![0x30, inner.len() as u8];
        result.extend_from_slice(&inner);
        result
    }

    fn build_pss_params_sha1() -> Vec<u8> {
        // SHA-1 OID: 1.3.14.3.2.26
        let sha1_oid = oid::SHA1.as_bytes();
        let hash_ai = build_algorithm_identifier(sha1_oid, true);
        let mgf_inner_ai = build_algorithm_identifier(sha1_oid, true);
        let mgf1_oid = oid::MGF1.as_bytes();
        let mgf1_ai = build_mgf1_ai(mgf1_oid, &mgf_inner_ai);

        let mut inner = Vec::new();
        inner.push(0xA0);
        inner.push(hash_ai.len() as u8);
        inner.extend_from_slice(&hash_ai);
        inner.push(0xA1);
        inner.push(mgf1_ai.len() as u8);
        inner.extend_from_slice(&mgf1_ai);
        inner.push(0xA2);
        inner.push(0x03);
        inner.push(0x02);
        inner.push(0x01);
        inner.push(0x14); // 20 bytes (sha-1 output)
        inner.push(0xA3);
        inner.push(0x03);
        inner.push(0x02);
        inner.push(0x01);
        inner.push(0x01);

        let mut result = vec![0x30, inner.len() as u8];
        result.extend_from_slice(&inner);
        result
    }

    fn build_pss_params_wrong_salt() -> Vec<u8> {
        // SHA-256 hash but salt = 20 (wrong)
        let sha256_oid = oid::SHA256.as_bytes();
        let hash_ai = build_algorithm_identifier(sha256_oid, true);
        let mgf_inner = build_algorithm_identifier(sha256_oid, true);
        let mgf1_oid = oid::MGF1.as_bytes();
        let mgf1_ai = build_mgf1_ai(mgf1_oid, &mgf_inner);

        let mut inner = Vec::new();
        inner.push(0xA0);
        inner.push(hash_ai.len() as u8);
        inner.extend_from_slice(&hash_ai);
        inner.push(0xA1);
        inner.push(mgf1_ai.len() as u8);
        inner.extend_from_slice(&mgf1_ai);
        inner.push(0xA2);
        inner.push(0x03);
        inner.push(0x02);
        inner.push(0x01);
        inner.push(0x14); // 20 instead of 32

        let mut result = vec![0x30, inner.len() as u8];
        result.extend_from_slice(&inner);
        result
    }

    fn build_pss_params_bad_trailer() -> Vec<u8> {
        let sha256_oid = oid::SHA256.as_bytes();
        let hash_ai = build_algorithm_identifier(sha256_oid, true);
        let mgf_inner = build_algorithm_identifier(sha256_oid, true);
        let mgf1_oid = oid::MGF1.as_bytes();
        let mgf1_ai = build_mgf1_ai(mgf1_oid, &mgf_inner);

        let mut inner = Vec::new();
        inner.push(0xA0);
        inner.push(hash_ai.len() as u8);
        inner.extend_from_slice(&hash_ai);
        inner.push(0xA1);
        inner.push(mgf1_ai.len() as u8);
        inner.extend_from_slice(&mgf1_ai);
        inner.push(0xA2);
        inner.push(0x03);
        inner.push(0x02);
        inner.push(0x01);
        inner.push(0x20); // correct salt 32
        inner.push(0xA3);
        inner.push(0x03);
        inner.push(0x02);
        inner.push(0x01);
        inner.push(0x02); // trailer = 2 (invalid)

        let mut result = vec![0x30, inner.len() as u8];
        result.extend_from_slice(&inner);
        result
    }

    fn build_pss_params_mismatched_hash() -> Vec<u8> {
        // hashAlgorithm = SHA-256, mgf1 inner hash = SHA-384
        let sha256_oid = oid::SHA256.as_bytes();
        let sha384_oid = oid::SHA384.as_bytes();
        let hash_ai = build_algorithm_identifier(sha256_oid, true);
        let mgf_inner = build_algorithm_identifier(sha384_oid, true); // mismatch
        let mgf1_oid = oid::MGF1.as_bytes();
        let mgf1_ai = build_mgf1_ai(mgf1_oid, &mgf_inner);

        let mut inner = Vec::new();
        inner.push(0xA0);
        inner.push(hash_ai.len() as u8);
        inner.extend_from_slice(&hash_ai);
        inner.push(0xA1);
        inner.push(mgf1_ai.len() as u8);
        inner.extend_from_slice(&mgf1_ai);
        inner.push(0xA2);
        inner.push(0x03);
        inner.push(0x02);
        inner.push(0x01);
        inner.push(0x20); // salt = 32 (matches SHA-256)

        let mut result = vec![0x30, inner.len() as u8];
        result.extend_from_slice(&inner);
        result
    }

    fn build_pss_params_no_hash_tag() -> Vec<u8> {
        // SEQUENCE with only [2] saltLength — no [0] hashAlgorithm
        // hashAlgorithm defaults to sha-1 which must be rejected
        let inner = vec![
            0xA2, 0x03, 0x02, 0x01, 0x14, // [2] saltLength = 20 (sha-1 default)
        ];

        let mut result = vec![0x30, inner.len() as u8];
        result.extend_from_slice(&inner);
        result
    }
}
