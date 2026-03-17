//! NIST SP 800-56A/B/C — Key Establishment Scheme Validation
//!
//! Validates key agreement (SP 800-56A) and key transport (SP 800-56B) parameters
//! before use in CMS EnvelopedData, TLS handshakes, or key wrap operations.
//!
//! ## SP 800-56A — Discrete Logarithm-Based Key Agreement
//!
//! Validates ECDH key agreement parameters including curve selection and KDF hash.
//! Only NIST-approved curves (P-256, P-384) are permitted per FIPS 186-5.
//!
//! ## SP 800-56B — RSA Key Transport
//!
//! Validates RSA key transport algorithm selection and key size. RSA-OAEP is
//! preferred over PKCS#1 v1.5 per SP 800-131A Rev 2.
//!
//! ## SP 800-56C — Key Derivation
//!
//! Validates KDF hash algorithm selection for key derivation after agreement.
//!
//! ## References
//!
//! - NIST SP 800-56A Rev 3 (Discrete Log-Based Key-Establishment Schemes)
//! - NIST SP 800-56B Rev 2 (RSA-Based Key Transport)
//! - NIST SP 800-56C Rev 2 (Key-Derivation Methods)
//! - NIST SP 800-131A Rev 2 (Transitioning Cryptographic Algorithms)

/// Elliptic curve for key agreement per SP 800-56A.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgreementCurve {
    /// NIST P-256 (128-bit security)
    P256,
    /// NIST P-384 (192-bit security)
    P384,
}

impl AgreementCurve {
    /// Security strength in bits per SP 800-57 Table 2.
    pub fn security_bits(self) -> u32 {
        match self {
            Self::P256 => 128,
            Self::P384 => 192,
        }
    }
}

impl std::fmt::Display for AgreementCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P256 => write!(f, "P-256"),
            Self::P384 => write!(f, "P-384"),
        }
    }
}

/// Hash algorithm for key derivation per SP 800-56C.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfHash {
    Sha256,
    Sha384,
    Sha512,
}

impl KdfHash {
    /// Output length in bits.
    pub fn output_bits(self) -> u32 {
        match self {
            Self::Sha256 => 256,
            Self::Sha384 => 384,
            Self::Sha512 => 512,
        }
    }

    /// Whether this hash is approved for key derivation per SP 800-56C.
    pub fn is_approved(self) -> bool {
        // All SHA-2 family hashes are approved per SP 800-56C §4
        true
    }
}

impl std::fmt::Display for KdfHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha256 => write!(f, "SHA-256"),
            Self::Sha384 => write!(f, "SHA-384"),
            Self::Sha512 => write!(f, "SHA-512"),
        }
    }
}

/// RSA key transport padding scheme per SP 800-56B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaKeyTransportPadding {
    /// RSAES-PKCS1-v1_5 (RFC 8017 §7.2.1) — legacy, discouraged
    Pkcs1v15,
    /// RSAES-OAEP (RFC 8017 §7.1) — preferred per SP 800-131A
    Oaep,
}

impl std::fmt::Display for RsaKeyTransportPadding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pkcs1v15 => write!(f, "RSAES-PKCS1-v1_5"),
            Self::Oaep => write!(f, "RSAES-OAEP"),
        }
    }
}

/// A finding from key establishment validation.
#[derive(Debug, Clone)]
pub struct KeyEstablishmentFinding {
    /// Finding code (e.g., "KE-001").
    pub code: &'static str,
    /// Whether this finding is a pass or failure.
    pub pass: bool,
    /// Description of the check.
    pub description: String,
    /// Reference to the governing standard.
    pub reference: &'static str,
}

/// Result of key agreement validation.
#[derive(Debug, Clone)]
pub struct KeyAgreementAssurance {
    /// Whether the key agreement configuration is approved.
    pub approved: bool,
    /// Security strength in bits.
    pub security_bits: u32,
    /// Findings from the validation.
    pub findings: Vec<KeyEstablishmentFinding>,
}

/// Result of RSA key transport validation.
#[derive(Debug, Clone)]
pub struct KeyTransportAssurance {
    /// Whether the key transport configuration is approved.
    pub approved: bool,
    /// Security strength in bits.
    pub security_bits: u32,
    /// Findings from the validation.
    pub findings: Vec<KeyEstablishmentFinding>,
}

/// Validate ECDH key agreement parameters per SP 800-56A.
///
/// Checks that the curve, KDF hash, and derived key length are approved.
///
/// # Parameters
///
/// - `curve` — The elliptic curve for key agreement
/// - `kdf_hash` — The hash algorithm for key derivation (SP 800-56C)
/// - `derived_key_bits` — Length of the derived key material in bits
pub fn validate_key_agreement(
    curve: AgreementCurve,
    kdf_hash: KdfHash,
    derived_key_bits: u32,
) -> KeyAgreementAssurance {
    let mut findings = Vec::new();

    // KE-001: Curve is NIST-approved per FIPS 186-5
    findings.push(KeyEstablishmentFinding {
        code: "KE-001",
        pass: true, // Both P-256 and P-384 are approved
        description: format!(
            "Curve {} is approved for key agreement (FIPS 186-5, SP 800-56A §5.6.1)",
            curve
        ),
        reference: "SP 800-56A Rev 3 §5.6.1; FIPS 186-5",
    });

    // KE-002: KDF hash is approved per SP 800-56C
    let kdf_approved = kdf_hash.is_approved();
    findings.push(KeyEstablishmentFinding {
        code: "KE-002",
        pass: kdf_approved,
        description: format!(
            "KDF hash {} is {}approved for key derivation",
            kdf_hash,
            if kdf_approved { "" } else { "NOT " }
        ),
        reference: "SP 800-56C Rev 2 §4",
    });

    // KE-003: KDF hash security strength >= curve security strength
    // Per SP 800-57 Pt.1 Table 3, SHA-256 provides 128-bit security,
    // SHA-384 provides 192-bit, SHA-512 provides 256-bit.
    let hash_security_bits = match kdf_hash {
        KdfHash::Sha256 => 128,
        KdfHash::Sha384 => 192,
        KdfHash::Sha512 => 256,
    };
    let hash_adequate = hash_security_bits >= curve.security_bits();
    findings.push(KeyEstablishmentFinding {
        code: "KE-003",
        pass: hash_adequate,
        description: format!(
            "KDF hash {} ({}-bit security) {} adequate for {} ({}-bit security)",
            kdf_hash,
            hash_security_bits,
            if hash_adequate { "is" } else { "is NOT" },
            curve,
            curve.security_bits()
        ),
        reference: "SP 800-56C Rev 2 §4; SP 800-57 Pt.1 Table 3",
    });

    // KE-004: Derived key length is sufficient
    let min_key_bits = 128u32; // Minimum 128-bit key per SP 800-131A
    let key_adequate = derived_key_bits >= min_key_bits;
    findings.push(KeyEstablishmentFinding {
        code: "KE-004",
        pass: key_adequate,
        description: format!(
            "Derived key length {}-bit {} minimum {}-bit requirement",
            derived_key_bits,
            if key_adequate {
                "meets"
            } else {
                "does NOT meet"
            },
            min_key_bits
        ),
        reference: "SP 800-131A Rev 2 §2",
    });

    // KE-005: Derived key bits don't exceed curve security strength
    let key_bounded = derived_key_bits <= curve.security_bits() * 2;
    findings.push(KeyEstablishmentFinding {
        code: "KE-005",
        pass: key_bounded,
        description: format!(
            "Derived key {}-bit is {} curve {} maximum security ({}-bit)",
            derived_key_bits,
            if key_bounded { "within" } else { "beyond" },
            curve,
            curve.security_bits()
        ),
        reference: "SP 800-56A Rev 3 §5.8.1",
    });

    let approved = kdf_approved && hash_adequate && key_adequate && key_bounded;

    KeyAgreementAssurance {
        approved,
        security_bits: curve.security_bits(),
        findings,
    }
}

/// Validate RSA key transport parameters per SP 800-56B.
///
/// Checks that the RSA key size, padding scheme, and transport parameters
/// are approved for key transport operations.
///
/// # Parameters
///
/// - `padding` — The RSA padding scheme (OAEP preferred)
/// - `rsa_key_bits` — RSA key size in bits
/// - `require_post_2030` — If true, enforces SP 800-131A Rev 2 post-2030 requirements
pub fn validate_key_transport(
    padding: RsaKeyTransportPadding,
    rsa_key_bits: u32,
    require_post_2030: bool,
) -> KeyTransportAssurance {
    let mut findings = Vec::new();

    // KT-001: RSA key size meets minimum per SP 800-56B §6.3
    let min_bits = if require_post_2030 { 3072 } else { 2048 };
    let size_ok = rsa_key_bits >= min_bits;
    findings.push(KeyEstablishmentFinding {
        code: "KT-001",
        pass: size_ok,
        description: format!(
            "RSA key size {}-bit {} minimum {}-bit{}",
            rsa_key_bits,
            if size_ok { "meets" } else { "does NOT meet" },
            min_bits,
            if require_post_2030 {
                " (post-2030 requirement)"
            } else {
                ""
            }
        ),
        reference: "SP 800-56B Rev 2 §6.3; SP 800-131A Rev 2 §2",
    });

    // KT-002: Padding scheme preference
    let padding_preferred = padding == RsaKeyTransportPadding::Oaep;
    findings.push(KeyEstablishmentFinding {
        code: "KT-002",
        pass: true, // Both are still allowed, but OAEP is preferred
        description: format!(
            "RSA padding {} is {}(OAEP preferred per SP 800-131A)",
            padding,
            if padding_preferred {
                "the preferred scheme "
            } else {
                "legacy — OAEP recommended "
            }
        ),
        reference: "SP 800-56B Rev 2 §7.1; SP 800-131A Rev 2 §4",
    });

    // KT-003: PKCS#1 v1.5 deprecated for key transport post-2030
    let pkcs1_post_2030_ok = !(require_post_2030 && padding == RsaKeyTransportPadding::Pkcs1v15);
    findings.push(KeyEstablishmentFinding {
        code: "KT-003",
        pass: pkcs1_post_2030_ok,
        description: if !pkcs1_post_2030_ok {
            "RSAES-PKCS1-v1_5 is disallowed for key transport after 2030 per SP 800-131A"
                .to_string()
        } else {
            format!(
                "Key transport padding {} is approved for current period",
                padding
            )
        },
        reference: "SP 800-131A Rev 2 §4; SP 800-56B Rev 2 §7.1",
    });

    let security_bits = match rsa_key_bits {
        ..=2047 => 0,
        2048..=3071 => 112,
        3072..=7679 => 128,
        7680..=15359 => 192,
        _ => 256,
    };

    let approved = size_ok && pkcs1_post_2030_ok;

    KeyTransportAssurance {
        approved,
        security_bits,
        findings,
    }
}

/// Quick check: is this ECDH curve approved for key agreement?
pub fn is_curve_approved(curve: AgreementCurve) -> bool {
    // Both P-256 and P-384 are approved per FIPS 186-5
    matches!(curve, AgreementCurve::P256 | AgreementCurve::P384)
}

/// Recommend the minimum RSA key size for key transport.
///
/// Returns the minimum RSA key size in bits per SP 800-56B and SP 800-131A.
pub fn recommended_rsa_key_transport_bits(require_post_2030: bool) -> u32 {
    if require_post_2030 {
        3072
    } else {
        2048
    }
}

/// Recommend the preferred key transport padding scheme.
///
/// Always returns OAEP per SP 800-131A preference.
pub fn recommended_key_transport_padding() -> RsaKeyTransportPadding {
    RsaKeyTransportPadding::Oaep
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Key Agreement (SP 800-56A) ----

    #[test]
    fn test_p256_sha256_128bit_approved() {
        let result = validate_key_agreement(AgreementCurve::P256, KdfHash::Sha256, 128);
        assert!(result.approved);
        assert_eq!(result.security_bits, 128);
        assert!(result.findings.iter().all(|f| f.pass));
    }

    #[test]
    fn test_p256_sha256_256bit_approved() {
        let result = validate_key_agreement(AgreementCurve::P256, KdfHash::Sha256, 256);
        assert!(result.approved);
    }

    #[test]
    fn test_p384_sha384_192bit_approved() {
        let result = validate_key_agreement(AgreementCurve::P384, KdfHash::Sha384, 192);
        assert!(result.approved);
        assert_eq!(result.security_bits, 192);
    }

    #[test]
    fn test_p384_sha384_256bit_approved() {
        let result = validate_key_agreement(AgreementCurve::P384, KdfHash::Sha384, 256);
        assert!(result.approved);
    }

    #[test]
    fn test_p384_sha256_insufficient_hash() {
        let result = validate_key_agreement(AgreementCurve::P384, KdfHash::Sha256, 192);
        assert!(!result.approved);
        let ke003 = result.findings.iter().find(|f| f.code == "KE-003").unwrap();
        assert!(!ke003.pass);
    }

    #[test]
    fn test_p256_sha512_approved() {
        let result = validate_key_agreement(AgreementCurve::P256, KdfHash::Sha512, 256);
        assert!(result.approved);
    }

    #[test]
    fn test_derived_key_too_small() {
        let result = validate_key_agreement(AgreementCurve::P256, KdfHash::Sha256, 64);
        assert!(!result.approved);
        let ke004 = result.findings.iter().find(|f| f.code == "KE-004").unwrap();
        assert!(!ke004.pass);
    }

    #[test]
    fn test_derived_key_exceeds_curve_strength() {
        // P-256 provides 128-bit security, max derived key should be 256 bits
        let result = validate_key_agreement(AgreementCurve::P256, KdfHash::Sha256, 512);
        assert!(!result.approved);
        let ke005 = result.findings.iter().find(|f| f.code == "KE-005").unwrap();
        assert!(!ke005.pass);
    }

    // ---- RSA Key Transport (SP 800-56B) ----

    #[test]
    fn test_rsa3072_oaep_approved() {
        let result = validate_key_transport(RsaKeyTransportPadding::Oaep, 3072, false);
        assert!(result.approved);
        assert_eq!(result.security_bits, 128);
    }

    #[test]
    fn test_rsa4096_oaep_approved() {
        let result = validate_key_transport(RsaKeyTransportPadding::Oaep, 4096, false);
        assert!(result.approved);
        assert_eq!(result.security_bits, 128);
    }

    #[test]
    fn test_rsa2048_oaep_pre2030_approved() {
        let result = validate_key_transport(RsaKeyTransportPadding::Oaep, 2048, false);
        assert!(result.approved);
        assert_eq!(result.security_bits, 112);
    }

    #[test]
    fn test_rsa2048_oaep_post2030_rejected() {
        let result = validate_key_transport(RsaKeyTransportPadding::Oaep, 2048, true);
        assert!(!result.approved);
        let kt001 = result.findings.iter().find(|f| f.code == "KT-001").unwrap();
        assert!(!kt001.pass);
    }

    #[test]
    fn test_rsa3072_pkcs1_pre2030_approved() {
        let result = validate_key_transport(RsaKeyTransportPadding::Pkcs1v15, 3072, false);
        assert!(result.approved);
    }

    #[test]
    fn test_rsa3072_pkcs1_post2030_rejected() {
        let result = validate_key_transport(RsaKeyTransportPadding::Pkcs1v15, 3072, true);
        assert!(!result.approved);
        let kt003 = result.findings.iter().find(|f| f.code == "KT-003").unwrap();
        assert!(!kt003.pass);
    }

    #[test]
    fn test_rsa1024_rejected() {
        let result = validate_key_transport(RsaKeyTransportPadding::Oaep, 1024, false);
        assert!(!result.approved);
        assert_eq!(result.security_bits, 0);
    }

    #[test]
    fn test_rsa7680_192bit_security() {
        let result = validate_key_transport(RsaKeyTransportPadding::Oaep, 7680, false);
        assert!(result.approved);
        assert_eq!(result.security_bits, 192);
    }

    // ---- Convenience functions ----

    #[test]
    fn test_is_curve_approved() {
        assert!(is_curve_approved(AgreementCurve::P256));
        assert!(is_curve_approved(AgreementCurve::P384));
    }

    #[test]
    fn test_recommended_rsa_bits() {
        assert_eq!(recommended_rsa_key_transport_bits(false), 2048);
        assert_eq!(recommended_rsa_key_transport_bits(true), 3072);
    }

    #[test]
    fn test_recommended_padding() {
        assert_eq!(
            recommended_key_transport_padding(),
            RsaKeyTransportPadding::Oaep
        );
    }

    // ---- Display tests ----

    #[test]
    fn test_curve_display() {
        assert_eq!(AgreementCurve::P256.to_string(), "P-256");
        assert_eq!(AgreementCurve::P384.to_string(), "P-384");
    }

    #[test]
    fn test_kdf_hash_display() {
        assert_eq!(KdfHash::Sha256.to_string(), "SHA-256");
        assert_eq!(KdfHash::Sha384.to_string(), "SHA-384");
        assert_eq!(KdfHash::Sha512.to_string(), "SHA-512");
    }

    #[test]
    fn test_padding_display() {
        assert_eq!(
            RsaKeyTransportPadding::Pkcs1v15.to_string(),
            "RSAES-PKCS1-v1_5"
        );
        assert_eq!(RsaKeyTransportPadding::Oaep.to_string(), "RSAES-OAEP");
    }

    #[test]
    fn test_curve_security_bits() {
        assert_eq!(AgreementCurve::P256.security_bits(), 128);
        assert_eq!(AgreementCurve::P384.security_bits(), 192);
    }

    #[test]
    fn test_kdf_hash_output_bits() {
        assert_eq!(KdfHash::Sha256.output_bits(), 256);
        assert_eq!(KdfHash::Sha384.output_bits(), 384);
        assert_eq!(KdfHash::Sha512.output_bits(), 512);
    }

    #[test]
    fn test_all_findings_have_references() {
        let ka = validate_key_agreement(AgreementCurve::P256, KdfHash::Sha256, 128);
        for f in &ka.findings {
            assert!(
                !f.reference.is_empty(),
                "Finding {} missing reference",
                f.code
            );
        }
        let kt = validate_key_transport(RsaKeyTransportPadding::Oaep, 3072, false);
        for f in &kt.findings {
            assert!(
                !f.reference.is_empty(),
                "Finding {} missing reference",
                f.code
            );
        }
    }
}
