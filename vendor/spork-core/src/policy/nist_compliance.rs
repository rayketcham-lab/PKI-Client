//! NIST SP 800-175B Rev.1 — Guideline for Using Cryptographic Standards
//!
//! Validates that a CA's cryptographic configuration complies with
//! NIST SP 800-175B guidelines for approved algorithm usage.
//!
//! Also covers SP 800-57 Part 2 Rev.1 — Recommendation for Key Management:
//! Part 2 — Best Practices for Key Management Organizations.
//!
//! ## SP 800-175B Requirements
//!
//! - Only NIST-approved algorithms for government use (FIPS 186-5, SP 800-131A)
//! - Minimum security strengths per SP 800-57 Part 1
//! - Key protection commensurate with the data being protected
//! - Dual-control and split knowledge for CA keys (SP 800-57 Pt.2 §6)
//!
//! ## References
//!
//! - NIST SP 800-175B Rev.1 (March 2020)
//! - NIST SP 800-57 Part 2 Rev.1 (May 2019)

use chrono::Datelike;

use crate::algo::AlgorithmId;

/// A single compliance finding from the NIST validation.
#[derive(Debug, Clone)]
pub struct NistFinding {
    /// Finding code (e.g., "NST-001")
    pub code: &'static str,
    /// Whether the check passed
    pub pass: bool,
    /// Human-readable description
    pub description: String,
    /// NIST reference (SP number and section)
    pub reference: &'static str,
}

/// Result of NIST SP 800-175B compliance validation.
#[derive(Debug, Clone)]
pub struct NistComplianceReport {
    /// All findings from the validation
    pub findings: Vec<NistFinding>,
}

impl NistComplianceReport {
    /// Returns `true` if all findings passed.
    pub fn is_compliant(&self) -> bool {
        self.findings.iter().all(|f| f.pass)
    }

    /// Count of passing findings.
    pub fn pass_count(&self) -> usize {
        self.findings.iter().filter(|f| f.pass).count()
    }

    /// Count of failing findings.
    pub fn fail_count(&self) -> usize {
        self.findings.iter().filter(|f| !f.pass).count()
    }
}

/// CA configuration input for NIST compliance validation.
#[derive(Debug, Clone)]
pub struct CaComplianceConfig {
    /// Algorithms configured for this CA
    pub algorithms: Vec<AlgorithmId>,
    /// Whether FIPS mode is enabled
    pub fips_mode: bool,
    /// Minimum key security strength in bits (e.g., 128, 192, 256)
    pub min_security_bits: u32,
    /// Whether dual-control key ceremony is configured
    pub dual_control: bool,
    /// Whether M-of-N split knowledge is configured for CA keys
    pub split_knowledge: bool,
    /// Whether CA private keys are stored in hardware (HSM/TPM)
    pub hardware_key_storage: bool,
    /// Whether key backup uses approved encryption
    pub approved_backup_encryption: bool,
    /// Certificate validity period in days
    pub cert_validity_days: u32,
    /// Whether audit logging is enabled for key operations
    pub audit_logging: bool,
}

/// Validate a CA configuration against NIST SP 800-175B and SP 800-57 Pt.2.
///
/// Returns a compliance report with individual findings.
pub fn validate_nist_compliance(config: &CaComplianceConfig) -> NistComplianceReport {
    let mut findings = Vec::new();

    // NST-001: All algorithms must be NIST-approved (SP 800-175B §4)
    let all_approved = config.algorithms.iter().all(is_nist_approved);
    findings.push(NistFinding {
        code: "NST-001",
        pass: all_approved,
        description: if all_approved {
            "All configured algorithms are NIST-approved".into()
        } else {
            let non_approved: Vec<String> = config
                .algorithms
                .iter()
                .filter(|a| !is_nist_approved(a))
                .map(|a| format!("{a:?}"))
                .collect();
            format!("Non-approved algorithms found: {}", non_approved.join(", "))
        },
        reference: "SP 800-175B §4",
    });

    // NST-002: Minimum security strength (SP 800-175B §3, SP 800-57 Pt.1 Table 2)
    let strength_ok = config.min_security_bits >= 112;
    findings.push(NistFinding {
        code: "NST-002",
        pass: strength_ok,
        description: if strength_ok {
            format!(
                "Minimum security strength ({}-bit) meets NIST floor (112-bit)",
                config.min_security_bits
            )
        } else {
            format!(
                "Security strength ({}-bit) below NIST minimum (112-bit)",
                config.min_security_bits
            )
        },
        reference: "SP 800-57 Pt.1 Table 2",
    });

    // NST-003: Post-2030 readiness (SP 800-131A Rev.2)
    let post_2030_ready = config.min_security_bits >= 128;
    findings.push(NistFinding {
        code: "NST-003",
        pass: post_2030_ready,
        description: if post_2030_ready {
            "Configuration meets post-2030 security requirements (128-bit+)".into()
        } else {
            "Configuration does not meet post-2030 requirements (need 128-bit+)".into()
        },
        reference: "SP 800-131A Rev.2",
    });

    // NST-004: FIPS mode for government deployments (SP 800-175B §2)
    findings.push(NistFinding {
        code: "NST-004",
        pass: config.fips_mode,
        description: if config.fips_mode {
            "FIPS mode enabled — algorithm selection restricted to approved set".into()
        } else {
            "FIPS mode not enabled — required for government deployments".into()
        },
        reference: "SP 800-175B §2",
    });

    // KMO-001: Dual control for CA key generation (SP 800-57 Pt.2 §6.1)
    findings.push(NistFinding {
        code: "KMO-001",
        pass: config.dual_control,
        description: if config.dual_control {
            "Dual-control key ceremony configured for CA key generation".into()
        } else {
            "Dual-control not configured — required for CA key generation (SP 800-57 Pt.2 §6.1)"
                .into()
        },
        reference: "SP 800-57 Pt.2 §6.1",
    });

    // KMO-002: Split knowledge for CA private keys (SP 800-57 Pt.2 §6.1)
    findings.push(NistFinding {
        code: "KMO-002",
        pass: config.split_knowledge,
        description: if config.split_knowledge {
            "M-of-N split knowledge configured for CA key protection".into()
        } else {
            "Split knowledge not configured — recommended for CA keys".into()
        },
        reference: "SP 800-57 Pt.2 §6.1",
    });

    // KMO-003: Hardware key storage (SP 800-57 Pt.2 §6.2)
    findings.push(NistFinding {
        code: "KMO-003",
        pass: config.hardware_key_storage,
        description: if config.hardware_key_storage {
            "CA private keys stored in hardware security module (HSM/TPM)".into()
        } else {
            "CA keys in software storage — hardware storage recommended (SP 800-57 Pt.2 §6.2)"
                .into()
        },
        reference: "SP 800-57 Pt.2 §6.2",
    });

    // KMO-004: Key backup encryption (SP 800-57 Pt.2 §6.3)
    findings.push(NistFinding {
        code: "KMO-004",
        pass: config.approved_backup_encryption,
        description: if config.approved_backup_encryption {
            "Key backups use approved encryption (AES-256)".into()
        } else {
            "Key backup encryption not verified — must use approved algorithms".into()
        },
        reference: "SP 800-57 Pt.2 §6.3",
    });

    // KMO-005: Audit logging for key operations (SP 800-57 Pt.2 §6.7)
    findings.push(NistFinding {
        code: "KMO-005",
        pass: config.audit_logging,
        description: if config.audit_logging {
            "Audit logging enabled for all key lifecycle operations".into()
        } else {
            "Audit logging not enabled — required for key management accountability".into()
        },
        reference: "SP 800-57 Pt.2 §6.7",
    });

    // KMO-006: CA certificate validity period (SP 800-57 Pt.1 Table 1)
    // NIST recommends issuing CA cert validity ≤ 3 years for subordinate CAs,
    // root CAs may have longer validity up to 25 years.
    // We check that cert_validity_days doesn't exceed 10 years (conservative default).
    let max_validity_days = 3652; // ~10 years
    let validity_ok = config.cert_validity_days <= max_validity_days;
    findings.push(NistFinding {
        code: "KMO-006",
        pass: validity_ok,
        description: if validity_ok {
            format!(
                "CA certificate validity ({} days) within NIST recommended limits",
                config.cert_validity_days
            )
        } else {
            format!(
                "CA certificate validity ({} days) exceeds 10-year NIST recommendation — review SP 800-57 Pt.1 Table 1",
                config.cert_validity_days
            )
        },
        reference: "SP 800-57 Pt.1 Table 1",
    });

    // NST-005: Runtime deprecation check (SP 800-131A Rev.2 Table 1)
    // Verify that all configured algorithms are not deprecated for the current year.
    let current_year = chrono::Utc::now().date_naive().year_ce().1;
    let has_deprecated = config
        .algorithms
        .iter()
        .any(|a| is_algorithm_deprecated(a, current_year));
    findings.push(NistFinding {
        code: "NST-005",
        pass: !has_deprecated,
        description: if !has_deprecated {
            format!(
                "No configured algorithms are deprecated for {} (SP 800-131A Rev.2)",
                current_year
            )
        } else {
            let deprecated: Vec<String> = config
                .algorithms
                .iter()
                .filter(|a| is_algorithm_deprecated(a, current_year))
                .map(|a| format!("{a:?}"))
                .collect();
            format!(
                "Deprecated algorithms configured for {} (SP 800-131A Rev.2): {}",
                current_year,
                deprecated.join(", ")
            )
        },
        reference: "SP 800-131A Rev.2 Table 1",
    });

    // NST-006: Generation vs processing approval (FIPS 140-3 Appendix A)
    // Check that all algorithms used for key generation (not just verification)
    // are approved for initial key establishment.
    let all_gen_approved = config
        .algorithms
        .iter()
        .all(|a| is_approved_for_generation(a, current_year));
    findings.push(NistFinding {
        code: "NST-006",
        pass: all_gen_approved,
        description: if all_gen_approved {
            "All algorithms approved for new key generation in current year".into()
        } else {
            let not_gen_approved: Vec<String> = config
                .algorithms
                .iter()
                .filter(|a| !is_approved_for_generation(a, current_year))
                .map(|a| format!("{a:?}"))
                .collect();
            format!(
                "Algorithms not approved for new key generation (may still be used for verification): {}",
                not_gen_approved.join(", ")
            )
        },
        reference: "FIPS 140-3 Appendix A",
    });

    NistComplianceReport { findings }
}

/// Check if an algorithm is approved for new key generation in the given year.
///
/// Per FIPS 140-3 Appendix A, an algorithm may be approved for "processing"
/// (verifying existing signatures) but not for "applying" (generating new ones)
/// after its deprecation year. This is stricter than `is_nist_approved`.
pub fn is_approved_for_generation(algorithm: &AlgorithmId, year: u32) -> bool {
    if !is_nist_approved(algorithm) {
        return false;
    }
    !is_algorithm_deprecated(algorithm, year)
}

/// Check if an algorithm is NIST-approved for digital signatures.
///
/// SP 800-175B §4 references FIPS 186-5 and SP 800-131A for approved algorithms.
pub fn is_nist_approved(algorithm: &AlgorithmId) -> bool {
    #[allow(unreachable_patterns)]
    match algorithm {
        AlgorithmId::EcdsaP256
        | AlgorithmId::EcdsaP384
        | AlgorithmId::Rsa2048
        | AlgorithmId::Rsa3072
        | AlgorithmId::Rsa4096
        | AlgorithmId::Rsa3072Pss
        | AlgorithmId::Rsa4096Pss
        | AlgorithmId::Ed25519 => true,
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa44
        | AlgorithmId::MlDsa65
        | AlgorithmId::MlDsa87
        | AlgorithmId::SlhDsaSha2_128s
        | AlgorithmId::SlhDsaSha2_192s
        | AlgorithmId::SlhDsaSha2_256s => true,
        _ => false, // Composite or unknown
    }
}

/// Get the security strength in bits for a NIST-approved algorithm.
///
/// Per SP 800-57 Part 1, Table 2.
pub fn algorithm_security_bits(algorithm: &AlgorithmId) -> u32 {
    #[allow(unreachable_patterns)]
    match algorithm {
        AlgorithmId::Rsa2048 => 112,
        AlgorithmId::EcdsaP256 | AlgorithmId::Rsa3072 | AlgorithmId::Rsa3072Pss => 128,
        AlgorithmId::EcdsaP384 | AlgorithmId::Rsa4096 | AlgorithmId::Rsa4096Pss => 192,
        AlgorithmId::Ed25519 => 128,
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa44 => 128,
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa65 => 192,
        #[cfg(feature = "pqc")]
        AlgorithmId::MlDsa87 | AlgorithmId::SlhDsaSha2_256s => 256,
        #[cfg(feature = "pqc")]
        AlgorithmId::SlhDsaSha2_128s => 128,
        #[cfg(feature = "pqc")]
        AlgorithmId::SlhDsaSha2_192s => 192,
        _ => 0, // Composite or unknown
    }
}

/// SP 800-131A Rev.2 Table 1 — year after which an algorithm is disallowed
/// for new digital signatures.  Returns `None` for algorithms with no
/// currently-scheduled deprecation (e.g. P-384, PQC).
pub fn algorithm_deprecation_year(algorithm: &AlgorithmId) -> Option<u32> {
    #[allow(unreachable_patterns)]
    match algorithm {
        AlgorithmId::Rsa2048 => Some(2030), // SP 800-131A §2, Table 1
        AlgorithmId::Rsa3072 | AlgorithmId::Rsa3072Pss => Some(2040),
        AlgorithmId::EcdsaP256 | AlgorithmId::Ed25519 => None, // 128-bit, no scheduled deprecation
        AlgorithmId::EcdsaP384 | AlgorithmId::Rsa4096 | AlgorithmId::Rsa4096Pss => None, // 192-bit, no scheduled deprecation
        _ => None, // PQC and composite algorithms — no scheduled deprecation
    }
}

/// Check whether an algorithm is deprecated for new signatures in the given year.
pub fn is_algorithm_deprecated(algorithm: &AlgorithmId, year: u32) -> bool {
    algorithm_deprecation_year(algorithm).is_some_and(|cutoff| year >= cutoff)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> CaComplianceConfig {
        CaComplianceConfig {
            algorithms: vec![AlgorithmId::EcdsaP256, AlgorithmId::EcdsaP384],
            fips_mode: true,
            min_security_bits: 128,
            dual_control: true,
            split_knowledge: true,
            hardware_key_storage: true,
            approved_backup_encryption: true,
            cert_validity_days: 3650,
            audit_logging: true,
        }
    }

    #[test]
    fn test_fully_compliant_config() {
        let report = validate_nist_compliance(&default_config());
        assert!(report.is_compliant());
        assert_eq!(report.fail_count(), 0);
        assert_eq!(report.pass_count(), 12);
    }

    #[test]
    fn test_all_approved_algorithms_pass() {
        let config = default_config();
        let report = validate_nist_compliance(&config);
        let nst001 = report
            .findings
            .iter()
            .find(|f| f.code == "NST-001")
            .unwrap();
        assert!(nst001.pass);
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn test_non_approved_composite_algorithm() {
        let mut config = default_config();
        config.algorithms.push(AlgorithmId::MlDsa44EcdsaP256);
        let report = validate_nist_compliance(&config);
        let nst001 = report
            .findings
            .iter()
            .find(|f| f.code == "NST-001")
            .unwrap();
        assert!(!nst001.pass);
        assert!(nst001.description.contains("Non-approved"));
    }

    #[test]
    fn test_low_security_strength() {
        let mut config = default_config();
        config.min_security_bits = 80;
        let report = validate_nist_compliance(&config);
        let nst002 = report
            .findings
            .iter()
            .find(|f| f.code == "NST-002")
            .unwrap();
        assert!(!nst002.pass);
        let nst003 = report
            .findings
            .iter()
            .find(|f| f.code == "NST-003")
            .unwrap();
        assert!(!nst003.pass);
    }

    #[test]
    fn test_no_fips_mode() {
        let mut config = default_config();
        config.fips_mode = false;
        let report = validate_nist_compliance(&config);
        let nst004 = report
            .findings
            .iter()
            .find(|f| f.code == "NST-004")
            .unwrap();
        assert!(!nst004.pass);
    }

    #[test]
    fn test_no_dual_control() {
        let mut config = default_config();
        config.dual_control = false;
        let report = validate_nist_compliance(&config);
        let kmo001 = report
            .findings
            .iter()
            .find(|f| f.code == "KMO-001")
            .unwrap();
        assert!(!kmo001.pass);
    }

    #[test]
    fn test_no_split_knowledge() {
        let mut config = default_config();
        config.split_knowledge = false;
        let report = validate_nist_compliance(&config);
        let kmo002 = report
            .findings
            .iter()
            .find(|f| f.code == "KMO-002")
            .unwrap();
        assert!(!kmo002.pass);
    }

    #[test]
    fn test_software_key_storage() {
        let mut config = default_config();
        config.hardware_key_storage = false;
        let report = validate_nist_compliance(&config);
        let kmo003 = report
            .findings
            .iter()
            .find(|f| f.code == "KMO-003")
            .unwrap();
        assert!(!kmo003.pass);
    }

    #[test]
    fn test_no_audit_logging() {
        let mut config = default_config();
        config.audit_logging = false;
        let report = validate_nist_compliance(&config);
        let kmo005 = report
            .findings
            .iter()
            .find(|f| f.code == "KMO-005")
            .unwrap();
        assert!(!kmo005.pass);
    }

    #[test]
    fn test_is_nist_approved_classical() {
        assert!(is_nist_approved(&AlgorithmId::EcdsaP256));
        assert!(is_nist_approved(&AlgorithmId::EcdsaP384));
        assert!(is_nist_approved(&AlgorithmId::Rsa2048));
        assert!(is_nist_approved(&AlgorithmId::Rsa4096));
        assert!(is_nist_approved(&AlgorithmId::Rsa3072Pss));
        assert!(is_nist_approved(&AlgorithmId::Ed25519));
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn test_is_nist_approved_pqc() {
        assert!(is_nist_approved(&AlgorithmId::MlDsa44));
        assert!(is_nist_approved(&AlgorithmId::MlDsa65));
        assert!(is_nist_approved(&AlgorithmId::MlDsa87));
        assert!(is_nist_approved(&AlgorithmId::SlhDsaSha2_128s));
        assert!(is_nist_approved(&AlgorithmId::SlhDsaSha2_256s));
        // Composites are not individually approved
        assert!(!is_nist_approved(&AlgorithmId::MlDsa44EcdsaP256));
    }

    #[test]
    fn test_algorithm_security_bits_classical() {
        assert_eq!(algorithm_security_bits(&AlgorithmId::Rsa2048), 112);
        assert_eq!(algorithm_security_bits(&AlgorithmId::EcdsaP256), 128);
        assert_eq!(algorithm_security_bits(&AlgorithmId::EcdsaP384), 192);
        assert_eq!(algorithm_security_bits(&AlgorithmId::Rsa4096), 192);
        assert_eq!(algorithm_security_bits(&AlgorithmId::Ed25519), 128);
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn test_algorithm_security_bits_pqc() {
        assert_eq!(algorithm_security_bits(&AlgorithmId::MlDsa44), 128);
        assert_eq!(algorithm_security_bits(&AlgorithmId::MlDsa65), 192);
        assert_eq!(algorithm_security_bits(&AlgorithmId::MlDsa87), 256);
        assert_eq!(algorithm_security_bits(&AlgorithmId::SlhDsaSha2_128s), 128);
    }

    #[test]
    fn test_post_2030_readiness() {
        // 112-bit is not post-2030 ready
        let mut config = default_config();
        config.min_security_bits = 112;
        let report = validate_nist_compliance(&config);
        let nst003 = report
            .findings
            .iter()
            .find(|f| f.code == "NST-003")
            .unwrap();
        assert!(!nst003.pass);

        // 128-bit is post-2030 ready
        config.min_security_bits = 128;
        let report = validate_nist_compliance(&config);
        let nst003 = report
            .findings
            .iter()
            .find(|f| f.code == "NST-003")
            .unwrap();
        assert!(nst003.pass);
    }

    #[test]
    fn test_report_counts() {
        let mut config = default_config();
        config.fips_mode = false;
        config.dual_control = false;
        let report = validate_nist_compliance(&config);
        assert_eq!(report.fail_count(), 2);
        assert_eq!(report.pass_count(), 10);
        assert!(!report.is_compliant());
    }

    #[test]
    fn test_kmo006_cert_validity_within_limit() {
        // Default config: 3650 days (~10 years) — should pass
        let config = default_config();
        let report = validate_nist_compliance(&config);
        let kmo006 = report
            .findings
            .iter()
            .find(|f| f.code == "KMO-006")
            .unwrap();
        assert!(kmo006.pass);
        assert!(kmo006.description.contains("within NIST"));
    }

    #[test]
    fn test_kmo006_cert_validity_exceeds_limit() {
        let mut config = default_config();
        config.cert_validity_days = 7300; // ~20 years — too long
        let report = validate_nist_compliance(&config);
        let kmo006 = report
            .findings
            .iter()
            .find(|f| f.code == "KMO-006")
            .unwrap();
        assert!(!kmo006.pass);
        assert!(kmo006.description.contains("exceeds"));
    }

    #[test]
    fn test_nst005_no_deprecated_algorithms() {
        let config = default_config();
        let report = validate_nist_compliance(&config);
        let nst005 = report
            .findings
            .iter()
            .find(|f| f.code == "NST-005")
            .unwrap();
        assert!(nst005.pass);
    }

    #[test]
    fn test_nst006_generation_approved() {
        let config = default_config();
        let report = validate_nist_compliance(&config);
        let nst006 = report
            .findings
            .iter()
            .find(|f| f.code == "NST-006")
            .unwrap();
        assert!(nst006.pass);
    }

    #[test]
    fn test_is_approved_for_generation_p256() {
        assert!(is_approved_for_generation(&AlgorithmId::EcdsaP256, 2026));
        assert!(is_approved_for_generation(&AlgorithmId::EcdsaP256, 2050));
    }

    #[test]
    fn test_is_approved_for_generation_rsa2048_before_2030() {
        assert!(is_approved_for_generation(&AlgorithmId::Rsa2048, 2026));
    }

    #[test]
    fn test_is_not_approved_for_generation_rsa2048_after_2030() {
        assert!(!is_approved_for_generation(&AlgorithmId::Rsa2048, 2031));
    }

    #[test]
    fn test_rsa2048_deprecated_after_2030() {
        assert!(!is_algorithm_deprecated(&AlgorithmId::Rsa2048, 2029));
        assert!(is_algorithm_deprecated(&AlgorithmId::Rsa2048, 2030));
        assert!(is_algorithm_deprecated(&AlgorithmId::Rsa2048, 2031));
    }

    #[test]
    fn test_rsa3072_deprecated_after_2040() {
        assert!(!is_algorithm_deprecated(&AlgorithmId::Rsa3072, 2039));
        assert!(is_algorithm_deprecated(&AlgorithmId::Rsa3072, 2040));
    }

    #[test]
    fn test_p256_no_deprecation() {
        assert!(!is_algorithm_deprecated(&AlgorithmId::EcdsaP256, 2050));
        assert!(algorithm_deprecation_year(&AlgorithmId::EcdsaP256).is_none());
    }

    #[test]
    fn test_p384_no_deprecation() {
        assert!(!is_algorithm_deprecated(&AlgorithmId::EcdsaP384, 2050));
        assert!(algorithm_deprecation_year(&AlgorithmId::EcdsaP384).is_none());
    }

    #[test]
    fn test_security_bits_coverage() {
        assert_eq!(algorithm_security_bits(&AlgorithmId::Rsa2048), 112);
        assert_eq!(algorithm_security_bits(&AlgorithmId::EcdsaP256), 128);
        assert_eq!(algorithm_security_bits(&AlgorithmId::Rsa3072), 128);
        assert_eq!(algorithm_security_bits(&AlgorithmId::EcdsaP384), 192);
        assert_eq!(algorithm_security_bits(&AlgorithmId::Rsa4096), 192);
        assert_eq!(algorithm_security_bits(&AlgorithmId::Ed25519), 128);
    }
}
