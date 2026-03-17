//! Security Level Framework — NIST SP 800-63 / FIPS 140-3 / FBCA Aligned
//!
//! Defines formal assurance levels that map to:
//! - NIST SP 800-63 Identity Assurance Levels (IAL1-3)
//! - NIST SP 800-63 Authenticator Assurance Levels (AAL1-3)
//! - FIPS 140-3 cryptographic module security levels (Level 1-4)
//! - Federal Bridge CA certificate policy assurance tiers
//! - Ogjos/SPORK certificate policy OIDs
//!
//! ## Level Mapping
//!
//! | SPORK Level | NIST IAL | FIPS 140-3 | FBCA Policy | Key Protection |
//! |-------------|----------|------------|-------------|----------------|
//! | Level1      | IAL1     | Level 1    | Rudimentary | Software       |
//! | Level2      | IAL2     | Level 1-2  | Medium      | Software       |
//! | Level3      | IAL2     | Level 2    | Medium HW   | TPM/HSM L2+    |
//! | Level4      | IAL3     | Level 3    | High        | HSM L3+        |
//!
//! ## References
//!
//! - NIST SP 800-63-3 (Digital Identity Guidelines)
//! - NIST SP 800-131A Rev 2 (Transitioning the Use of Cryptographic Algorithms)
//! - NIST SP 800-57 Part 1 Rev 5 (Key Management)
//! - FIPS 140-3 (Security Requirements for Cryptographic Modules)
//! - X.509 Certificate Policy for the U.S. Federal PKI Common Policy Framework

use serde::{Deserialize, Serialize};

use crate::algo::AlgorithmId;
use crate::policy::fpki;

/// Security assurance level for CA operations and certificate issuance.
///
/// Each level defines increasingly stringent requirements for key protection,
/// identity proofing, algorithm selection, and operational controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLevel {
    /// Level 1 — Rudimentary assurance.
    ///
    /// Suitable for development, testing, and low-risk internal services.
    /// - Software key storage permitted
    /// - No identity proofing required beyond domain control
    /// - All SPORK-supported algorithms permitted
    /// - Maps to NIST IAL1, FIPS 140-3 Level 1
    Level1,

    /// Level 2 — Medium assurance (software keys).
    ///
    /// Suitable for production TLS, internal services, automated enrollment.
    /// - Software key storage permitted
    /// - Identity proofing required (equivalent to IAL2)
    /// - FIPS-approved algorithms required (no RSA-2048 for new certs)
    /// - Maps to NIST IAL2, FIPS 140-3 Level 1-2, FBCA Medium
    Level2,

    /// Level 3 — Medium Hardware assurance.
    ///
    /// Suitable for privileged access, sensitive systems, CA signing keys.
    /// - Hardware key protection required (TPM or HSM, FIPS 140-3 Level 2+)
    /// - Identity proofing required (IAL2 with hardware authenticator)
    /// - FIPS-approved algorithms only, minimum RSA-3072
    /// - Key attestation recommended
    /// - Maps to NIST IAL2 + AAL2, FIPS 140-3 Level 2, FBCA Medium Hardware
    Level3,

    /// Level 4 — High assurance.
    ///
    /// Suitable for root CAs, high-value transactions, critical infrastructure.
    /// - HSM key protection required (FIPS 140-3 Level 3+)
    /// - In-person identity proofing required (IAL3)
    /// - FIPS-approved algorithms only, ECDSA P-384+ or RSA-4096
    /// - Key attestation required
    /// - Dual control for key operations
    /// - Maps to NIST IAL3 + AAL3, FIPS 140-3 Level 3, FBCA High
    Level4,
}

impl SecurityLevel {
    /// Return the human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Level1 => "Level 1 (Rudimentary)",
            Self::Level2 => "Level 2 (Medium)",
            Self::Level3 => "Level 3 (Medium Hardware)",
            Self::Level4 => "Level 4 (High)",
        }
    }

    /// Return the numeric level (1-4).
    pub fn numeric(&self) -> u8 {
        match self {
            Self::Level1 => 1,
            Self::Level2 => 2,
            Self::Level3 => 3,
            Self::Level4 => 4,
        }
    }

    /// Parse from numeric level.
    pub fn from_numeric(level: u8) -> Option<Self> {
        match level {
            1 => Some(Self::Level1),
            2 => Some(Self::Level2),
            3 => Some(Self::Level3),
            4 => Some(Self::Level4),
            _ => None,
        }
    }

    /// Get the corresponding NIST SP 800-63 Identity Assurance Level.
    pub fn nist_ial(&self) -> &'static str {
        match self {
            Self::Level1 => "IAL1",
            Self::Level2 | Self::Level3 => "IAL2",
            Self::Level4 => "IAL3",
        }
    }

    /// Get the corresponding NIST SP 800-63 Authenticator Assurance Level.
    pub fn nist_aal(&self) -> &'static str {
        match self {
            Self::Level1 => "AAL1",
            Self::Level2 => "AAL1",
            Self::Level3 => "AAL2",
            Self::Level4 => "AAL3",
        }
    }

    /// Get the minimum FIPS 140-3 module level required.
    pub fn fips_module_level(&self) -> u8 {
        match self {
            Self::Level1 => 1,
            Self::Level2 => 1,
            Self::Level3 => 2,
            Self::Level4 => 3,
        }
    }

    /// Get the corresponding Ogjos/SPORK certificate policy OID.
    pub fn ogjos_policy_oid(&self) -> &'static str {
        match self {
            Self::Level1 => fpki::ID_OGJOS_CP_RUDIMENTARY,
            Self::Level2 => fpki::ID_OGJOS_CP_MEDIUM,
            Self::Level3 => fpki::ID_OGJOS_CP_MEDIUM_HARDWARE,
            Self::Level4 => fpki::ID_OGJOS_CP_HIGH,
        }
    }

    /// Get the corresponding FPKI certificate policy OID (for bridge mapping).
    pub fn fpki_policy_oid(&self) -> &'static str {
        match self {
            Self::Level1 => fpki::ID_FPKI_COMMON_POLICY,
            Self::Level2 => fpki::ID_FPKI_CERTPOLICY_MEDIUM_ASSURANCE,
            Self::Level3 => fpki::ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE,
            Self::Level4 => fpki::ID_FPKI_COMMON_HIGH,
        }
    }

    /// Get the key protection requirement for this level.
    pub fn key_protection(&self) -> KeyProtection {
        match self {
            Self::Level1 | Self::Level2 => KeyProtection::Software,
            Self::Level3 => KeyProtection::Hardware,
            Self::Level4 => KeyProtection::HardwareLevel3,
        }
    }

    /// Whether FIPS-approved algorithms are required at this level.
    pub fn requires_fips_algorithms(&self) -> bool {
        matches!(self, Self::Level2 | Self::Level3 | Self::Level4)
    }

    /// Whether hardware key protection is required at this level.
    pub fn requires_hardware_keys(&self) -> bool {
        matches!(self, Self::Level3 | Self::Level4)
    }

    /// Whether key attestation is required.
    pub fn requires_key_attestation(&self) -> bool {
        matches!(self, Self::Level4)
    }

    /// Whether dual control is required for key operations.
    pub fn requires_dual_control(&self) -> bool {
        matches!(self, Self::Level4)
    }

    /// Get the minimum RSA key size (bits) for this level.
    pub fn min_rsa_bits(&self) -> u32 {
        match self {
            Self::Level1 => 2048,
            Self::Level2 | Self::Level3 => 3072,
            Self::Level4 => 4096,
        }
    }

    /// Get the maximum certificate validity period (days) for CA certs at this level.
    pub fn max_ca_validity_days(&self) -> u32 {
        match self {
            Self::Level1 => 3650, // 10 years
            Self::Level2 => 3650, // 10 years
            Self::Level3 => 7300, // 20 years (hardware-protected)
            Self::Level4 => 7300, // 20 years (root CA)
        }
    }

    /// Get the maximum certificate validity period (days) for end-entity certs.
    pub fn max_ee_validity_days(&self) -> u32 {
        match self {
            Self::Level1 => 825, // ~27 months
            Self::Level2 => 397, // ~13 months (CAB Forum baseline)
            Self::Level3 => 397, // ~13 months
            Self::Level4 => 397, // ~13 months
        }
    }

    /// Check whether an algorithm is permitted at this security level.
    pub fn is_algorithm_permitted(&self, algo: &AlgorithmId) -> bool {
        match self {
            Self::Level1 => true, // All algorithms permitted
            Self::Level2 | Self::Level3 => {
                // FIPS-approved: ECDSA P-256/P-384, RSA 3072+, RSA-PSS 3072+
                matches!(
                    algo,
                    AlgorithmId::EcdsaP256
                        | AlgorithmId::EcdsaP384
                        | AlgorithmId::Rsa3072
                        | AlgorithmId::Rsa4096
                        | AlgorithmId::Rsa3072Pss
                        | AlgorithmId::Rsa4096Pss
                )
            }
            Self::Level4 => {
                // High assurance: only strongest classical algorithms
                matches!(
                    algo,
                    AlgorithmId::EcdsaP384 | AlgorithmId::Rsa4096 | AlgorithmId::Rsa4096Pss
                )
            }
        }
    }

    /// Get the list of permitted algorithms at this level.
    pub fn permitted_algorithms(&self) -> Vec<AlgorithmId> {
        match self {
            Self::Level1 => {
                #[allow(unused_mut)]
                let mut algos = vec![
                    AlgorithmId::EcdsaP256,
                    AlgorithmId::EcdsaP384,
                    AlgorithmId::Rsa2048,
                    AlgorithmId::Rsa3072,
                    AlgorithmId::Rsa4096,
                    AlgorithmId::Rsa3072Pss,
                    AlgorithmId::Rsa4096Pss,
                ];
                #[cfg(feature = "pqc")]
                {
                    algos.extend([
                        AlgorithmId::MlDsa44,
                        AlgorithmId::MlDsa65,
                        AlgorithmId::MlDsa87,
                        AlgorithmId::SlhDsaSha2_128s,
                        AlgorithmId::SlhDsaSha2_192s,
                        AlgorithmId::SlhDsaSha2_256s,
                        AlgorithmId::MlDsa44EcdsaP256,
                        AlgorithmId::MlDsa65EcdsaP256,
                        AlgorithmId::MlDsa65EcdsaP384,
                        AlgorithmId::MlDsa87EcdsaP384,
                    ]);
                }
                algos
            }
            Self::Level2 | Self::Level3 => {
                vec![
                    AlgorithmId::EcdsaP256,
                    AlgorithmId::EcdsaP384,
                    AlgorithmId::Rsa3072,
                    AlgorithmId::Rsa4096,
                    AlgorithmId::Rsa3072Pss,
                    AlgorithmId::Rsa4096Pss,
                ]
            }
            Self::Level4 => {
                vec![
                    AlgorithmId::EcdsaP384,
                    AlgorithmId::Rsa4096,
                    AlgorithmId::Rsa4096Pss,
                ]
            }
        }
    }
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Key protection mechanism required at each security level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProtection {
    /// Software key storage (file-based, encrypted at rest).
    Software,

    /// Hardware key protection — FIPS 140-3 Level 2+ (TPM or HSM).
    Hardware,

    /// Hardware key protection — FIPS 140-3 Level 3+ (HSM only, tamper-resistant).
    HardwareLevel3,
}

impl KeyProtection {
    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Software => "Software (encrypted file)",
            Self::Hardware => "Hardware (FIPS 140-3 Level 2+ TPM/HSM)",
            Self::HardwareLevel3 => "Hardware (FIPS 140-3 Level 3+ HSM)",
        }
    }

    /// Minimum FIPS 140-3 module level for this protection class.
    pub fn min_fips_level(&self) -> u8 {
        match self {
            Self::Software => 1,
            Self::Hardware => 2,
            Self::HardwareLevel3 => 3,
        }
    }

    /// Whether this protection level satisfies the given requirement.
    pub fn satisfies(&self, required: &KeyProtection) -> bool {
        self >= required
    }
}

impl std::fmt::Display for KeyProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Requirements for a specific security level, used for compliance checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelRequirements {
    /// The security level.
    pub level: SecurityLevel,

    /// Required key protection mechanism.
    pub key_protection: KeyProtection,

    /// Whether FIPS-approved algorithms are mandatory.
    pub fips_algorithms_required: bool,

    /// Minimum RSA key size (bits).
    pub min_rsa_bits: u32,

    /// Minimum EC curve size (bits of security).
    pub min_ec_security_bits: u32,

    /// Maximum CA certificate validity (days).
    pub max_ca_validity_days: u32,

    /// Maximum end-entity certificate validity (days).
    pub max_ee_validity_days: u32,

    /// Whether key attestation is required.
    pub key_attestation_required: bool,

    /// Whether dual control is required for key operations.
    pub dual_control_required: bool,

    /// Whether audit logging of crypto operations is required.
    pub crypto_audit_required: bool,

    /// Whether CRL issuance must be automated.
    pub automated_crl_required: bool,

    /// Maximum CRL interval (hours). 0 means no requirement.
    pub max_crl_interval_hours: u32,

    /// Whether OCSP must be available.
    pub ocsp_required: bool,

    /// Corresponding FPKI policy OID (for bridge cross-certification).
    pub fpki_policy_oid: String,

    /// Corresponding Ogjos/SPORK policy OID.
    pub ogjos_policy_oid: String,
}

impl LevelRequirements {
    /// Build the requirements for a given security level.
    pub fn for_level(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::Level1 => Self {
                level,
                key_protection: KeyProtection::Software,
                fips_algorithms_required: false,
                min_rsa_bits: 2048,
                min_ec_security_bits: 128, // P-256
                max_ca_validity_days: 3650,
                max_ee_validity_days: 825,
                key_attestation_required: false,
                dual_control_required: false,
                crypto_audit_required: false,
                automated_crl_required: false,
                max_crl_interval_hours: 0,
                ocsp_required: false,
                fpki_policy_oid: fpki::ID_FPKI_COMMON_POLICY.to_string(),
                ogjos_policy_oid: fpki::ID_OGJOS_CP_RUDIMENTARY.to_string(),
            },
            SecurityLevel::Level2 => Self {
                level,
                key_protection: KeyProtection::Software,
                fips_algorithms_required: true,
                min_rsa_bits: 3072,
                min_ec_security_bits: 128,
                max_ca_validity_days: 3650,
                max_ee_validity_days: 397,
                key_attestation_required: false,
                dual_control_required: false,
                crypto_audit_required: true,
                automated_crl_required: true,
                max_crl_interval_hours: 24,
                ocsp_required: true,
                fpki_policy_oid: fpki::ID_FPKI_CERTPOLICY_MEDIUM_ASSURANCE.to_string(),
                ogjos_policy_oid: fpki::ID_OGJOS_CP_MEDIUM.to_string(),
            },
            SecurityLevel::Level3 => Self {
                level,
                key_protection: KeyProtection::Hardware,
                fips_algorithms_required: true,
                min_rsa_bits: 3072,
                min_ec_security_bits: 128,
                max_ca_validity_days: 7300,
                max_ee_validity_days: 397,
                key_attestation_required: false,
                dual_control_required: false,
                crypto_audit_required: true,
                automated_crl_required: true,
                max_crl_interval_hours: 12,
                ocsp_required: true,
                fpki_policy_oid: fpki::ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE.to_string(),
                ogjos_policy_oid: fpki::ID_OGJOS_CP_MEDIUM_HARDWARE.to_string(),
            },
            SecurityLevel::Level4 => Self {
                level,
                key_protection: KeyProtection::HardwareLevel3,
                fips_algorithms_required: true,
                min_rsa_bits: 4096,
                min_ec_security_bits: 192, // P-384
                max_ca_validity_days: 7300,
                max_ee_validity_days: 397,
                key_attestation_required: true,
                dual_control_required: true,
                crypto_audit_required: true,
                automated_crl_required: true,
                max_crl_interval_hours: 6,
                ocsp_required: true,
                fpki_policy_oid: fpki::ID_FPKI_COMMON_HIGH.to_string(),
                ogjos_policy_oid: fpki::ID_OGJOS_CP_HIGH.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SecurityLevel basics ----

    #[test]
    fn test_level_ordering() {
        assert!(SecurityLevel::Level1 < SecurityLevel::Level2);
        assert!(SecurityLevel::Level2 < SecurityLevel::Level3);
        assert!(SecurityLevel::Level3 < SecurityLevel::Level4);
    }

    #[test]
    fn test_level_numeric_roundtrip() {
        for level in [
            SecurityLevel::Level1,
            SecurityLevel::Level2,
            SecurityLevel::Level3,
            SecurityLevel::Level4,
        ] {
            let n = level.numeric();
            assert_eq!(SecurityLevel::from_numeric(n), Some(level));
        }
    }

    #[test]
    fn test_level_from_numeric_invalid() {
        assert_eq!(SecurityLevel::from_numeric(0), None);
        assert_eq!(SecurityLevel::from_numeric(5), None);
        assert_eq!(SecurityLevel::from_numeric(255), None);
    }

    #[test]
    fn test_level_display() {
        assert_eq!(SecurityLevel::Level1.to_string(), "Level 1 (Rudimentary)");
        assert_eq!(SecurityLevel::Level2.to_string(), "Level 2 (Medium)");
        assert_eq!(
            SecurityLevel::Level3.to_string(),
            "Level 3 (Medium Hardware)"
        );
        assert_eq!(SecurityLevel::Level4.to_string(), "Level 4 (High)");
    }

    // ---- NIST mappings ----

    #[test]
    fn test_nist_ial_mapping() {
        assert_eq!(SecurityLevel::Level1.nist_ial(), "IAL1");
        assert_eq!(SecurityLevel::Level2.nist_ial(), "IAL2");
        assert_eq!(SecurityLevel::Level3.nist_ial(), "IAL2");
        assert_eq!(SecurityLevel::Level4.nist_ial(), "IAL3");
    }

    #[test]
    fn test_nist_aal_mapping() {
        assert_eq!(SecurityLevel::Level1.nist_aal(), "AAL1");
        assert_eq!(SecurityLevel::Level2.nist_aal(), "AAL1");
        assert_eq!(SecurityLevel::Level3.nist_aal(), "AAL2");
        assert_eq!(SecurityLevel::Level4.nist_aal(), "AAL3");
    }

    // ---- FIPS module level ----

    #[test]
    fn test_fips_module_level() {
        assert_eq!(SecurityLevel::Level1.fips_module_level(), 1);
        assert_eq!(SecurityLevel::Level2.fips_module_level(), 1);
        assert_eq!(SecurityLevel::Level3.fips_module_level(), 2);
        assert_eq!(SecurityLevel::Level4.fips_module_level(), 3);
    }

    // ---- Policy OID mappings ----

    #[test]
    fn test_ogjos_policy_oid() {
        assert_eq!(
            SecurityLevel::Level1.ogjos_policy_oid(),
            fpki::ID_OGJOS_CP_RUDIMENTARY
        );
        assert_eq!(
            SecurityLevel::Level2.ogjos_policy_oid(),
            fpki::ID_OGJOS_CP_MEDIUM
        );
        assert_eq!(
            SecurityLevel::Level3.ogjos_policy_oid(),
            fpki::ID_OGJOS_CP_MEDIUM_HARDWARE
        );
        assert_eq!(
            SecurityLevel::Level4.ogjos_policy_oid(),
            fpki::ID_OGJOS_CP_HIGH
        );
    }

    #[test]
    fn test_fpki_policy_oid() {
        assert_eq!(
            SecurityLevel::Level1.fpki_policy_oid(),
            fpki::ID_FPKI_COMMON_POLICY
        );
        assert_eq!(
            SecurityLevel::Level2.fpki_policy_oid(),
            fpki::ID_FPKI_CERTPOLICY_MEDIUM_ASSURANCE
        );
        assert_eq!(
            SecurityLevel::Level3.fpki_policy_oid(),
            fpki::ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE
        );
        assert_eq!(
            SecurityLevel::Level4.fpki_policy_oid(),
            fpki::ID_FPKI_COMMON_HIGH
        );
    }

    // ---- Key protection ----

    #[test]
    fn test_key_protection_by_level() {
        assert_eq!(
            SecurityLevel::Level1.key_protection(),
            KeyProtection::Software
        );
        assert_eq!(
            SecurityLevel::Level2.key_protection(),
            KeyProtection::Software
        );
        assert_eq!(
            SecurityLevel::Level3.key_protection(),
            KeyProtection::Hardware
        );
        assert_eq!(
            SecurityLevel::Level4.key_protection(),
            KeyProtection::HardwareLevel3
        );
    }

    #[test]
    fn test_key_protection_ordering() {
        assert!(KeyProtection::Software < KeyProtection::Hardware);
        assert!(KeyProtection::Hardware < KeyProtection::HardwareLevel3);
    }

    #[test]
    fn test_key_protection_satisfies() {
        // HardwareLevel3 satisfies all
        assert!(KeyProtection::HardwareLevel3.satisfies(&KeyProtection::Software));
        assert!(KeyProtection::HardwareLevel3.satisfies(&KeyProtection::Hardware));
        assert!(KeyProtection::HardwareLevel3.satisfies(&KeyProtection::HardwareLevel3));

        // Hardware satisfies Software and Hardware, not Level3
        assert!(KeyProtection::Hardware.satisfies(&KeyProtection::Software));
        assert!(KeyProtection::Hardware.satisfies(&KeyProtection::Hardware));
        assert!(!KeyProtection::Hardware.satisfies(&KeyProtection::HardwareLevel3));

        // Software only satisfies Software
        assert!(KeyProtection::Software.satisfies(&KeyProtection::Software));
        assert!(!KeyProtection::Software.satisfies(&KeyProtection::Hardware));
    }

    #[test]
    fn test_key_protection_fips_level() {
        assert_eq!(KeyProtection::Software.min_fips_level(), 1);
        assert_eq!(KeyProtection::Hardware.min_fips_level(), 2);
        assert_eq!(KeyProtection::HardwareLevel3.min_fips_level(), 3);
    }

    // ---- Algorithm restrictions ----

    #[test]
    fn test_level1_allows_all_classical() {
        let level = SecurityLevel::Level1;
        assert!(level.is_algorithm_permitted(&AlgorithmId::EcdsaP256));
        assert!(level.is_algorithm_permitted(&AlgorithmId::EcdsaP384));
        assert!(level.is_algorithm_permitted(&AlgorithmId::Rsa2048));
        assert!(level.is_algorithm_permitted(&AlgorithmId::Rsa3072));
        assert!(level.is_algorithm_permitted(&AlgorithmId::Rsa4096));
    }

    #[test]
    fn test_level2_rejects_rsa2048() {
        let level = SecurityLevel::Level2;
        assert!(level.is_algorithm_permitted(&AlgorithmId::EcdsaP256));
        assert!(level.is_algorithm_permitted(&AlgorithmId::Rsa3072));
        assert!(!level.is_algorithm_permitted(&AlgorithmId::Rsa2048));
    }

    #[test]
    fn test_level3_same_as_level2() {
        let l2 = SecurityLevel::Level2;
        let l3 = SecurityLevel::Level3;
        // Level 3 has same algorithm set as Level 2 (difference is key protection)
        for algo in l2.permitted_algorithms() {
            assert!(
                l3.is_algorithm_permitted(&algo),
                "{:?} should be permitted at Level 3",
                algo
            );
        }
    }

    #[test]
    fn test_level4_only_strongest() {
        let level = SecurityLevel::Level4;
        assert!(!level.is_algorithm_permitted(&AlgorithmId::EcdsaP256));
        assert!(level.is_algorithm_permitted(&AlgorithmId::EcdsaP384));
        assert!(!level.is_algorithm_permitted(&AlgorithmId::Rsa3072));
        assert!(level.is_algorithm_permitted(&AlgorithmId::Rsa4096));
        assert!(level.is_algorithm_permitted(&AlgorithmId::Rsa4096Pss));
        assert!(!level.is_algorithm_permitted(&AlgorithmId::Rsa2048));
    }

    #[test]
    fn test_permitted_algorithms_count() {
        // Level 1 has at least 7 classical algorithms
        assert!(SecurityLevel::Level1.permitted_algorithms().len() >= 7);
        // Level 2/3 have exactly 6
        assert_eq!(SecurityLevel::Level2.permitted_algorithms().len(), 6);
        assert_eq!(SecurityLevel::Level3.permitted_algorithms().len(), 6);
        // Level 4 has exactly 3
        assert_eq!(SecurityLevel::Level4.permitted_algorithms().len(), 3);
    }

    // ---- Boolean requirements ----

    #[test]
    fn test_requires_fips_algorithms() {
        assert!(!SecurityLevel::Level1.requires_fips_algorithms());
        assert!(SecurityLevel::Level2.requires_fips_algorithms());
        assert!(SecurityLevel::Level3.requires_fips_algorithms());
        assert!(SecurityLevel::Level4.requires_fips_algorithms());
    }

    #[test]
    fn test_requires_hardware_keys() {
        assert!(!SecurityLevel::Level1.requires_hardware_keys());
        assert!(!SecurityLevel::Level2.requires_hardware_keys());
        assert!(SecurityLevel::Level3.requires_hardware_keys());
        assert!(SecurityLevel::Level4.requires_hardware_keys());
    }

    #[test]
    fn test_requires_key_attestation() {
        assert!(!SecurityLevel::Level1.requires_key_attestation());
        assert!(!SecurityLevel::Level2.requires_key_attestation());
        assert!(!SecurityLevel::Level3.requires_key_attestation());
        assert!(SecurityLevel::Level4.requires_key_attestation());
    }

    #[test]
    fn test_requires_dual_control() {
        assert!(!SecurityLevel::Level1.requires_dual_control());
        assert!(!SecurityLevel::Level2.requires_dual_control());
        assert!(!SecurityLevel::Level3.requires_dual_control());
        assert!(SecurityLevel::Level4.requires_dual_control());
    }

    // ---- RSA minimums ----

    #[test]
    fn test_min_rsa_bits() {
        assert_eq!(SecurityLevel::Level1.min_rsa_bits(), 2048);
        assert_eq!(SecurityLevel::Level2.min_rsa_bits(), 3072);
        assert_eq!(SecurityLevel::Level3.min_rsa_bits(), 3072);
        assert_eq!(SecurityLevel::Level4.min_rsa_bits(), 4096);
    }

    // ---- Validity periods ----

    #[test]
    fn test_max_ca_validity() {
        assert_eq!(SecurityLevel::Level1.max_ca_validity_days(), 3650);
        assert_eq!(SecurityLevel::Level2.max_ca_validity_days(), 3650);
        assert_eq!(SecurityLevel::Level3.max_ca_validity_days(), 7300);
        assert_eq!(SecurityLevel::Level4.max_ca_validity_days(), 7300);
    }

    #[test]
    fn test_max_ee_validity() {
        assert_eq!(SecurityLevel::Level1.max_ee_validity_days(), 825);
        assert_eq!(SecurityLevel::Level2.max_ee_validity_days(), 397);
        assert_eq!(SecurityLevel::Level3.max_ee_validity_days(), 397);
        assert_eq!(SecurityLevel::Level4.max_ee_validity_days(), 397);
    }

    // ---- LevelRequirements ----

    #[test]
    fn test_level_requirements_level1() {
        let req = LevelRequirements::for_level(SecurityLevel::Level1);
        assert_eq!(req.level, SecurityLevel::Level1);
        assert_eq!(req.key_protection, KeyProtection::Software);
        assert!(!req.fips_algorithms_required);
        assert_eq!(req.min_rsa_bits, 2048);
        assert!(!req.key_attestation_required);
        assert!(!req.dual_control_required);
        assert!(!req.crypto_audit_required);
        assert!(!req.ocsp_required);
    }

    #[test]
    fn test_level_requirements_level2() {
        let req = LevelRequirements::for_level(SecurityLevel::Level2);
        assert_eq!(req.level, SecurityLevel::Level2);
        assert!(req.fips_algorithms_required);
        assert_eq!(req.min_rsa_bits, 3072);
        assert!(req.crypto_audit_required);
        assert!(req.automated_crl_required);
        assert_eq!(req.max_crl_interval_hours, 24);
        assert!(req.ocsp_required);
    }

    #[test]
    fn test_level_requirements_level3() {
        let req = LevelRequirements::for_level(SecurityLevel::Level3);
        assert_eq!(req.key_protection, KeyProtection::Hardware);
        assert!(req.fips_algorithms_required);
        assert_eq!(req.max_crl_interval_hours, 12);
    }

    #[test]
    fn test_level_requirements_level4() {
        let req = LevelRequirements::for_level(SecurityLevel::Level4);
        assert_eq!(req.key_protection, KeyProtection::HardwareLevel3);
        assert!(req.fips_algorithms_required);
        assert_eq!(req.min_rsa_bits, 4096);
        assert_eq!(req.min_ec_security_bits, 192);
        assert!(req.key_attestation_required);
        assert!(req.dual_control_required);
        assert_eq!(req.max_crl_interval_hours, 6);
    }

    #[test]
    fn test_level_requirements_policy_oids() {
        for level in [
            SecurityLevel::Level1,
            SecurityLevel::Level2,
            SecurityLevel::Level3,
            SecurityLevel::Level4,
        ] {
            let req = LevelRequirements::for_level(level);
            assert_eq!(req.ogjos_policy_oid, level.ogjos_policy_oid());
            assert_eq!(req.fpki_policy_oid, level.fpki_policy_oid());
        }
    }

    // ---- Serde roundtrip ----

    #[test]
    fn test_security_level_serde() {
        for level in [
            SecurityLevel::Level1,
            SecurityLevel::Level2,
            SecurityLevel::Level3,
            SecurityLevel::Level4,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let restored: SecurityLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, level);
        }
    }

    #[test]
    fn test_key_protection_serde() {
        for kp in [
            KeyProtection::Software,
            KeyProtection::Hardware,
            KeyProtection::HardwareLevel3,
        ] {
            let json = serde_json::to_string(&kp).unwrap();
            let restored: KeyProtection = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, kp);
        }
    }

    #[test]
    fn test_level_requirements_serde() {
        let req = LevelRequirements::for_level(SecurityLevel::Level3);
        let json = serde_json::to_string(&req).unwrap();
        let restored: LevelRequirements = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.level, SecurityLevel::Level3);
        assert_eq!(restored.key_protection, KeyProtection::Hardware);
    }
}
