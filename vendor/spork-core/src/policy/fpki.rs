//! FPKI (Federal Public Key Infrastructure) Policy OID Definitions
//!
//! This module defines the certificate policy OIDs used in the U.S. Federal PKI
//! ecosystem, including the Federal Bridge CA (FBCA) and Common Policy CA (CPCA),
//! as well as SPORK/Ogjos policy OIDs under our registered Private Enterprise Number.
//!
//! ## FPKI Policy Framework
//!
//! The Federal PKI is a trust framework for U.S. government certificate authorities.
//! It consists of:
//!
//! - **Common Policy CA (CPCA):** Issues certificates to federal agencies under the
//!   `id-fpki-common-*` policy OID namespace (`2.16.840.1.101.3.2.1.3.*`).
//!
//! - **Federal Bridge CA (FBCA):** Provides cross-certification between the CPCA and
//!   commercial/state/external PKIs. Uses `id-fpki-certpolicy-*` OIDs.
//!
//! - **PIV (Personal Identity Verification):** Defined in FIPS 201, PIV cards use
//!   hardware-backed keys and specific policy OIDs for authentication and signing.
//!
//! - **PIVI (PIV-Interoperable):** Extends PIV to non-federal users and devices.
//!
//! ## Policy Mapping
//!
//! When a cross-certified CA issues certificates, the `PolicyMappings` extension
//! (RFC 5280 §4.2.1.5) maps issuer-domain policy OIDs to subject-domain policy OIDs.
//! The [`PolicyMapping`] struct represents a single such mapping pair.
//!
//! ## References
//!
//! - X.509 Certificate Policy for the U.S. Federal PKI Common Policy Framework
//! - NIST SP 800-76 (Biometric Specifications for Personal Identity Verification)
//! - FIPS 201 (Personal Identity Verification)
//! - RFC 5280 §4.2.1.5 (Policy Mappings)
//! - RFC 5280 §4.2.1.4 (Certificate Policies)

use serde::{Deserialize, Serialize};

// ============================================================================
// Federal Common Policy CA (CPCA) OIDs — 2.16.840.1.101.3.2.1.3.*
//
// These are issued under the U.S. Government's Common Policy root. Certificates
// asserting these policies are issued to federal employees, contractors, and
// devices operating under the Common Policy framework.
// ============================================================================

/// Federal Common Policy — baseline federal certificate assurance.
///
/// OID: `2.16.840.1.101.3.2.1.3.6`
///
/// The foundational policy level for software-key federal certificates.
/// Certificates at this level meet the minimum security requirements for
/// federal systems access.
pub const ID_FPKI_COMMON_POLICY: &str = "2.16.840.1.101.3.2.1.3.6";

/// Federal Common Policy — hardware-key (PIV card) certificate assurance.
///
/// OID: `2.16.840.1.101.3.2.1.3.7`
///
/// Requires the private key to be stored in FIPS 140-2 Level 2 or higher
/// hardware (typically a PIV card). Used for employee identity certificates.
pub const ID_FPKI_COMMON_HARDWARE: &str = "2.16.840.1.101.3.2.1.3.7";

/// Federal Common Policy — device certificates (software key).
///
/// OID: `2.16.840.1.101.3.2.1.3.8`
///
/// Policy for certificates issued to federal devices and automated processes
/// where the private key is stored in software.
pub const ID_FPKI_COMMON_DEVICES: &str = "2.16.840.1.101.3.2.1.3.8";

/// Federal Common Policy — device certificates with hardware key.
///
/// OID: `2.16.840.1.101.3.2.1.3.36`
///
/// Policy for certificates issued to federal devices where the private key
/// is stored in hardware (HSM or TPM).
pub const ID_FPKI_COMMON_DEVICES_HARDWARE: &str = "2.16.840.1.101.3.2.1.3.36";

/// Federal Common Policy — PIV authentication certificate.
///
/// OID: `2.16.840.1.101.3.2.1.3.13`
///
/// Used for the Authentication certificate on a PIV card. This certificate
/// is used for network logon, physical access, and digital signature
/// verification of the cardholder's identity.
pub const ID_FPKI_COMMON_AUTHENTICATION: &str = "2.16.840.1.101.3.2.1.3.13";

/// Federal Common Policy — High Assurance (deprecated, legacy).
///
/// OID: `2.16.840.1.101.3.2.1.3.16`
///
/// Legacy high-assurance policy level. New issuances should prefer
/// `id-fpki-common-hardware` for equivalent hardware-backed assurance.
pub const ID_FPKI_COMMON_HIGH: &str = "2.16.840.1.101.3.2.1.3.16";

/// Federal Common Policy — PIV Card Authentication certificate.
///
/// OID: `2.16.840.1.101.3.2.1.3.17`
///
/// Used for contactless card authentication (e.g., physical access control).
/// This policy covers the Card Authentication Key (CAK) certificate on a PIV card,
/// which does not require PIN entry for authentication.
pub const ID_FPKI_COMMON_CARD_AUTH: &str = "2.16.840.1.101.3.2.1.3.17";

/// Federal Common Policy — PIV content signing certificate.
///
/// OID: `2.16.840.1.101.3.2.1.3.39`
///
/// Used by the Card Management System (CMS) to sign data objects stored on
/// PIV cards, such as biometric templates and security objects.
pub const ID_FPKI_COMMON_PIV_CONTENT_SIGNING: &str = "2.16.840.1.101.3.2.1.3.39";

// ============================================================================
// Federal Bridge CA (FBCA) Certificate Policy OIDs — 2.16.840.1.101.3.2.1.3.*
//
// These OIDs are used in the Federal Bridge, which provides cross-certification
// between the Common Policy CA and other PKIs (commercial, state, foreign).
// ============================================================================

/// Federal Bridge — Medium Assurance certificate policy.
///
/// OID: `2.16.840.1.101.3.2.1.3.12`
///
/// The medium assurance level in the Federal Bridge. Software-based keys
/// with identity proofing equivalent to NIST SP 800-63 IAL2.
pub const ID_FPKI_CERTPOLICY_MEDIUM_ASSURANCE: &str = "2.16.840.1.101.3.2.1.3.12";

/// Federal Bridge — Medium Hardware certificate policy.
///
/// OID: `2.16.840.1.101.3.2.1.3.12.2`
///
/// Medium assurance level with hardware-protected keys. Provides the same
/// identity assurance as medium, with the added protection of FIPS 140-2
/// Level 2 or higher hardware key storage.
pub const ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE: &str = "2.16.840.1.101.3.2.1.3.12.2";

/// Federal Bridge — PIV-I Hardware certificate policy.
///
/// OID: `2.16.840.1.101.3.2.1.3.18`
///
/// PIV-Interoperable (PIV-I) identity certificate with hardware-protected key.
/// PIV-I extends the PIV model to non-federal organizations while maintaining
/// cross-PKI interoperability through the Federal Bridge.
pub const ID_FPKI_CERTPOLICY_PIVI_HARDWARE: &str = "2.16.840.1.101.3.2.1.3.18";

/// Federal Bridge — PIV-I Card Authentication certificate policy.
///
/// OID: `2.16.840.1.101.3.2.1.3.19`
///
/// PIV-I card authentication for contactless access. Analogous to
/// `id-fpki-common-cardAuth` but for non-federal PIV-I deployments.
pub const ID_FPKI_CERTPOLICY_PIVI_CARD_AUTH: &str = "2.16.840.1.101.3.2.1.3.19";

/// Federal Bridge — PIV-I content signing certificate policy.
///
/// OID: `2.16.840.1.101.3.2.1.3.20`
///
/// PIV-I content signing for signing data objects stored on PIV-I cards.
/// Analogous to `id-fpki-common-piv-contentSigning` for non-federal deployments.
pub const ID_FPKI_CERTPOLICY_PIVI_CONTENT_SIGNING: &str = "2.16.840.1.101.3.2.1.3.20";

// ============================================================================
// Ogjos/SPORK Policy OIDs — 1.3.6.1.4.1.56266.1.1.*
//
// Issued under Ogjos PEN 56266 (IANA-registered).
// Arc: iso(1).org(3).dod(6).internet(1).private(4).enterprise(1).ogjos(56266)
//      .policy(1).certificatePolicy(1).*
//
// These OIDs define SPORK CA's assurance levels, aligned with the NIST SP 800-63
// identity assurance levels and the FPKI medium/high framework.
// ============================================================================

/// Ogjos/SPORK — Rudimentary certificate policy.
///
/// OID: `1.3.6.1.4.1.56266.1.1.1`
///
/// The lowest assurance level. No identity verification beyond domain control
/// validation. Suitable for internal testing, development, and evaluation
/// deployments. Keys may be software-generated with no custody requirements.
pub const ID_OGJOS_CP_RUDIMENTARY: &str = "1.3.6.1.4.1.56266.1.1.1";

/// Ogjos/SPORK — Basic certificate policy.
///
/// OID: `1.3.6.1.4.1.56266.1.1.2`
///
/// Basic identity verification, equivalent to NIST SP 800-63 IAL1.
/// Suitable for low-risk applications, internal services, and automated
/// device enrollment where organizational affiliation is verified.
pub const ID_OGJOS_CP_BASIC: &str = "1.3.6.1.4.1.56266.1.1.2";

/// Ogjos/SPORK — Medium Assurance certificate policy.
///
/// OID: `1.3.6.1.4.1.56266.1.1.3`
///
/// Medium identity verification, equivalent to NIST SP 800-63 IAL2.
/// Requires verified identity proofing. Suitable for access to sensitive
/// (but not classified) systems and services. Keys may be software-based.
pub const ID_OGJOS_CP_MEDIUM: &str = "1.3.6.1.4.1.56266.1.1.3";

/// Ogjos/SPORK — Medium Hardware certificate policy.
///
/// OID: `1.3.6.1.4.1.56266.1.1.4`
///
/// Medium assurance with hardware-protected keys. Extends `id-ogjos-cp-medium`
/// by requiring the private key to reside in a FIPS 140-2 Level 2 or higher
/// hardware device (HSM, TPM, or smart card). Suitable for privileged access
/// and sensitive system authentication.
pub const ID_OGJOS_CP_MEDIUM_HARDWARE: &str = "1.3.6.1.4.1.56266.1.1.4";

/// Ogjos/SPORK — High Assurance certificate policy.
///
/// OID: `1.3.6.1.4.1.56266.1.1.5`
///
/// The highest SPORK assurance level, equivalent to NIST SP 800-63 IAL3.
/// Requires in-person identity proofing and hardware-protected keys in a
/// FIPS 140-2 Level 3 or higher device. Suitable for CA signing certificates,
/// high-value transactions, and critical infrastructure access.
pub const ID_OGJOS_CP_HIGH: &str = "1.3.6.1.4.1.56266.1.1.5";

// ============================================================================
// Policy Mapping
// ============================================================================

/// A certificate policy mapping between two PKI domains.
///
/// Defined in RFC 5280 §4.2.1.5, the `PolicyMappings` extension contains
/// one or more policy mappings. Each mapping declares that the CA considers
/// the issuerDomainPolicy to be equivalent to the subjectDomainPolicy in
/// the subject CA's domain.
///
/// ## Example: FPKI Bridge Mapping
///
/// When a SPORK CA cross-certifies with the Federal Bridge, policy mappings
/// allow relying parties to traverse the trust boundary. For instance:
///
/// ```
/// # use spork_core::policy::fpki::{PolicyMapping, ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE, ID_OGJOS_CP_MEDIUM_HARDWARE};
/// let mapping = PolicyMapping {
///     issuer_domain_policy: ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE.to_string(),
///     subject_domain_policy: ID_OGJOS_CP_MEDIUM_HARDWARE.to_string(),
///     description: Some("FPKI Medium Hardware maps to SPORK Medium Hardware".to_string()),
/// };
/// assert_eq!(mapping.issuer_domain_policy, "2.16.840.1.101.3.2.1.3.12.2");
/// assert_eq!(mapping.subject_domain_policy, "1.3.6.1.4.1.56266.1.1.4");
/// ```
///
/// This would appear in the subject CA's certificate as:
/// `PolicyMappings { issuerDomainPolicy: id-fpki-certpolicy-mediumHardware,
///                   subjectDomainPolicy: id-ogjos-cp-medium-hardware }`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyMapping {
    /// The policy OID as understood in the issuer CA's domain.
    ///
    /// This is the policy OID that appears in certificates issued by the
    /// cross-certified CA (the "foreign" PKI).
    pub issuer_domain_policy: String,

    /// The policy OID as understood in the subject CA's domain.
    ///
    /// This is the equivalent policy OID in the subject CA's own framework.
    /// Relying parties in the subject's domain will see this OID.
    pub subject_domain_policy: String,

    /// Optional human-readable description of this mapping.
    pub description: Option<String>,
}

impl PolicyMapping {
    /// Create a new policy mapping between two policy OIDs.
    pub fn new(
        issuer_domain_policy: impl Into<String>,
        subject_domain_policy: impl Into<String>,
    ) -> Self {
        Self {
            issuer_domain_policy: issuer_domain_policy.into(),
            subject_domain_policy: subject_domain_policy.into(),
            description: None,
        }
    }

    /// Add a human-readable description to this mapping.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// Returns all FPKI Common Policy OID constants as a slice of `(oid, name)` pairs.
///
/// Useful for populating registries or validation tables.
pub fn fpki_common_policy_oids() -> &'static [(&'static str, &'static str)] {
    &[
        (ID_FPKI_COMMON_POLICY, "id-fpki-common-policy"),
        (ID_FPKI_COMMON_HARDWARE, "id-fpki-common-hardware"),
        (ID_FPKI_COMMON_DEVICES, "id-fpki-common-devices"),
        (
            ID_FPKI_COMMON_DEVICES_HARDWARE,
            "id-fpki-common-devicesHardware",
        ),
        (
            ID_FPKI_COMMON_AUTHENTICATION,
            "id-fpki-common-authentication",
        ),
        (ID_FPKI_COMMON_HIGH, "id-fpki-common-High"),
        (ID_FPKI_COMMON_CARD_AUTH, "id-fpki-common-cardAuth"),
        (
            ID_FPKI_COMMON_PIV_CONTENT_SIGNING,
            "id-fpki-common-piv-contentSigning",
        ),
    ]
}

/// Returns all FPKI Bridge/Cert Policy OID constants as a slice of `(oid, name)` pairs.
pub fn fpki_certpolicy_oids() -> &'static [(&'static str, &'static str)] {
    &[
        (
            ID_FPKI_CERTPOLICY_MEDIUM_ASSURANCE,
            "id-fpki-certpolicy-mediumAssurance",
        ),
        (
            ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE,
            "id-fpki-certpolicy-mediumHardware",
        ),
        (
            ID_FPKI_CERTPOLICY_PIVI_HARDWARE,
            "id-fpki-certpolicy-pivi-hardware",
        ),
        (
            ID_FPKI_CERTPOLICY_PIVI_CARD_AUTH,
            "id-fpki-certpolicy-pivi-cardAuth",
        ),
        (
            ID_FPKI_CERTPOLICY_PIVI_CONTENT_SIGNING,
            "id-fpki-certpolicy-pivi-contentSigning",
        ),
    ]
}

/// Returns all Ogjos/SPORK policy OID constants as a slice of `(oid, name)` pairs.
pub fn ogjos_policy_oids() -> &'static [(&'static str, &'static str)] {
    &[
        (ID_OGJOS_CP_RUDIMENTARY, "id-ogjos-cp-rudimentary"),
        (ID_OGJOS_CP_BASIC, "id-ogjos-cp-basic"),
        (ID_OGJOS_CP_MEDIUM, "id-ogjos-cp-medium"),
        (ID_OGJOS_CP_MEDIUM_HARDWARE, "id-ogjos-cp-medium-hardware"),
        (ID_OGJOS_CP_HIGH, "id-ogjos-cp-high"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- OID value correctness ----

    #[test]
    fn test_fpki_common_policy_oid_values() {
        assert_eq!(ID_FPKI_COMMON_POLICY, "2.16.840.1.101.3.2.1.3.6");
        assert_eq!(ID_FPKI_COMMON_HARDWARE, "2.16.840.1.101.3.2.1.3.7");
        assert_eq!(ID_FPKI_COMMON_DEVICES, "2.16.840.1.101.3.2.1.3.8");
        assert_eq!(ID_FPKI_COMMON_DEVICES_HARDWARE, "2.16.840.1.101.3.2.1.3.36");
        assert_eq!(ID_FPKI_COMMON_AUTHENTICATION, "2.16.840.1.101.3.2.1.3.13");
        assert_eq!(ID_FPKI_COMMON_HIGH, "2.16.840.1.101.3.2.1.3.16");
        assert_eq!(ID_FPKI_COMMON_CARD_AUTH, "2.16.840.1.101.3.2.1.3.17");
        assert_eq!(
            ID_FPKI_COMMON_PIV_CONTENT_SIGNING,
            "2.16.840.1.101.3.2.1.3.39"
        );
    }

    #[test]
    fn test_fpki_certpolicy_oid_values() {
        assert_eq!(
            ID_FPKI_CERTPOLICY_MEDIUM_ASSURANCE,
            "2.16.840.1.101.3.2.1.3.12"
        );
        assert_eq!(
            ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE,
            "2.16.840.1.101.3.2.1.3.12.2"
        );
        assert_eq!(
            ID_FPKI_CERTPOLICY_PIVI_HARDWARE,
            "2.16.840.1.101.3.2.1.3.18"
        );
        assert_eq!(
            ID_FPKI_CERTPOLICY_PIVI_CARD_AUTH,
            "2.16.840.1.101.3.2.1.3.19"
        );
        assert_eq!(
            ID_FPKI_CERTPOLICY_PIVI_CONTENT_SIGNING,
            "2.16.840.1.101.3.2.1.3.20"
        );
    }

    #[test]
    fn test_ogjos_policy_oid_values() {
        assert_eq!(ID_OGJOS_CP_RUDIMENTARY, "1.3.6.1.4.1.56266.1.1.1");
        assert_eq!(ID_OGJOS_CP_BASIC, "1.3.6.1.4.1.56266.1.1.2");
        assert_eq!(ID_OGJOS_CP_MEDIUM, "1.3.6.1.4.1.56266.1.1.3");
        assert_eq!(ID_OGJOS_CP_MEDIUM_HARDWARE, "1.3.6.1.4.1.56266.1.1.4");
        assert_eq!(ID_OGJOS_CP_HIGH, "1.3.6.1.4.1.56266.1.1.5");
    }

    // ---- OID namespace uniqueness ----

    #[test]
    fn test_all_fpki_common_oids_unique() {
        let oids = fpki_common_policy_oids();
        let mut seen = std::collections::HashSet::new();
        for (oid, name) in oids {
            assert!(
                seen.insert(*oid),
                "Duplicate FPKI common OID: {} ({})",
                oid,
                name
            );
        }
    }

    #[test]
    fn test_all_fpki_certpolicy_oids_unique() {
        let oids = fpki_certpolicy_oids();
        let mut seen = std::collections::HashSet::new();
        for (oid, name) in oids {
            assert!(
                seen.insert(*oid),
                "Duplicate FPKI certpolicy OID: {} ({})",
                oid,
                name
            );
        }
    }

    #[test]
    fn test_all_ogjos_oids_unique() {
        let oids = ogjos_policy_oids();
        let mut seen = std::collections::HashSet::new();
        for (oid, name) in oids {
            assert!(seen.insert(*oid), "Duplicate Ogjos OID: {} ({})", oid, name);
        }
    }

    #[test]
    fn test_fpki_oids_under_correct_arc() {
        // All FPKI OIDs must be under 2.16.840.1.101.3.2.1.3
        let prefix = "2.16.840.1.101.3.2.1.3.";
        for (oid, name) in fpki_common_policy_oids()
            .iter()
            .chain(fpki_certpolicy_oids().iter())
        {
            assert!(
                oid.starts_with(prefix),
                "FPKI OID {} ({}) does not start with expected arc {}",
                oid,
                name,
                prefix
            );
        }
    }

    #[test]
    fn test_ogjos_oids_under_correct_arc() {
        // All Ogjos policy OIDs must be under 1.3.6.1.4.1.56266.1.1
        let prefix = "1.3.6.1.4.1.56266.1.1.";
        for (oid, name) in ogjos_policy_oids() {
            assert!(
                oid.starts_with(prefix),
                "Ogjos OID {} ({}) does not start with expected arc {}",
                oid,
                name,
                prefix
            );
        }
    }

    // ---- OID dot-notation format validation ----

    fn is_valid_oid_format(oid: &str) -> bool {
        // OID components must be non-negative integers separated by dots
        if oid.is_empty() {
            return false;
        }
        oid.split('.')
            .all(|component| !component.is_empty() && component.chars().all(|c| c.is_ascii_digit()))
    }

    #[test]
    fn test_all_oid_formats_valid() {
        let all_oids = [
            ID_FPKI_COMMON_POLICY,
            ID_FPKI_COMMON_HARDWARE,
            ID_FPKI_COMMON_DEVICES,
            ID_FPKI_COMMON_DEVICES_HARDWARE,
            ID_FPKI_COMMON_AUTHENTICATION,
            ID_FPKI_COMMON_HIGH,
            ID_FPKI_COMMON_CARD_AUTH,
            ID_FPKI_COMMON_PIV_CONTENT_SIGNING,
            ID_FPKI_CERTPOLICY_MEDIUM_ASSURANCE,
            ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE,
            ID_FPKI_CERTPOLICY_PIVI_HARDWARE,
            ID_FPKI_CERTPOLICY_PIVI_CARD_AUTH,
            ID_FPKI_CERTPOLICY_PIVI_CONTENT_SIGNING,
            ID_OGJOS_CP_RUDIMENTARY,
            ID_OGJOS_CP_BASIC,
            ID_OGJOS_CP_MEDIUM,
            ID_OGJOS_CP_MEDIUM_HARDWARE,
            ID_OGJOS_CP_HIGH,
        ];
        for oid in all_oids {
            assert!(
                is_valid_oid_format(oid),
                "OID '{}' has invalid dot-notation format",
                oid
            );
        }
    }

    // ---- PolicyMapping ----

    #[test]
    fn test_policy_mapping_new() {
        let mapping = PolicyMapping::new(
            ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE,
            ID_OGJOS_CP_MEDIUM_HARDWARE,
        );
        assert_eq!(mapping.issuer_domain_policy, "2.16.840.1.101.3.2.1.3.12.2");
        assert_eq!(mapping.subject_domain_policy, "1.3.6.1.4.1.56266.1.1.4");
        assert!(mapping.description.is_none());
    }

    #[test]
    fn test_policy_mapping_with_description() {
        let mapping = PolicyMapping::new(ID_FPKI_CERTPOLICY_MEDIUM_ASSURANCE, ID_OGJOS_CP_MEDIUM)
            .with_description("FPKI Medium Assurance ↔ SPORK Medium");
        assert_eq!(
            mapping.description.as_deref(),
            Some("FPKI Medium Assurance ↔ SPORK Medium")
        );
    }

    #[test]
    fn test_policy_mapping_serde_roundtrip() {
        let mapping = PolicyMapping::new(ID_FPKI_COMMON_HARDWARE, ID_OGJOS_CP_HIGH)
            .with_description(
                "FPKI Common Hardware maps to SPORK High Assurance for bridge cross-cert",
            );
        let json = serde_json::to_string(&mapping).unwrap();
        let restored: PolicyMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, mapping);
        assert_eq!(restored.issuer_domain_policy, ID_FPKI_COMMON_HARDWARE);
        assert_eq!(restored.subject_domain_policy, ID_OGJOS_CP_HIGH);
    }

    #[test]
    fn test_policy_mapping_equality() {
        let m1 = PolicyMapping::new(ID_FPKI_COMMON_POLICY, ID_OGJOS_CP_BASIC);
        let m2 = PolicyMapping::new(ID_FPKI_COMMON_POLICY, ID_OGJOS_CP_BASIC);
        let m3 = PolicyMapping::new(ID_FPKI_COMMON_HIGH, ID_OGJOS_CP_HIGH);
        assert_eq!(m1, m2);
        assert_ne!(m1, m3);
    }

    #[test]
    fn test_policy_mapping_clone() {
        let mapping = PolicyMapping::new(ID_FPKI_CERTPOLICY_PIVI_HARDWARE, ID_OGJOS_CP_HIGH)
            .with_description("PIV-I Hardware ↔ SPORK High");
        let cloned = mapping.clone();
        assert_eq!(cloned, mapping);
    }

    // ---- Collection helper functions ----

    #[test]
    fn test_fpki_common_policy_oids_count() {
        assert_eq!(fpki_common_policy_oids().len(), 8);
    }

    #[test]
    fn test_fpki_certpolicy_oids_count() {
        assert_eq!(fpki_certpolicy_oids().len(), 5);
    }

    #[test]
    fn test_ogjos_policy_oids_count() {
        assert_eq!(ogjos_policy_oids().len(), 5);
    }

    #[test]
    fn test_fpki_common_oids_contains_known_entries() {
        let oids = fpki_common_policy_oids();
        let oid_strings: Vec<&str> = oids.iter().map(|(oid, _)| *oid).collect();
        assert!(oid_strings.contains(&ID_FPKI_COMMON_POLICY));
        assert!(oid_strings.contains(&ID_FPKI_COMMON_HARDWARE));
        assert!(oid_strings.contains(&ID_FPKI_COMMON_CARD_AUTH));
        assert!(oid_strings.contains(&ID_FPKI_COMMON_PIV_CONTENT_SIGNING));
    }

    #[test]
    fn test_ogjos_oids_ordered_by_assurance_level() {
        // Verify that the OIDs reflect ascending assurance (rudimentary → high)
        let oids = ogjos_policy_oids();
        // The last digit in each OID encodes the assurance level (1–5)
        let levels: Vec<u32> = oids
            .iter()
            .map(|(oid, _)| oid.split('.').next_back().unwrap().parse::<u32>().unwrap())
            .collect();
        let mut sorted = levels.clone();
        sorted.sort();
        assert_eq!(levels, sorted, "Ogjos OIDs should be in ascending order");
    }

    // ---- Medium Assurance vs Medium Hardware distinction ----

    #[test]
    fn test_medium_assurance_and_hardware_are_distinct() {
        assert_ne!(
            ID_FPKI_CERTPOLICY_MEDIUM_ASSURANCE,
            ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE
        );
        // Medium Hardware extends Medium Assurance in the OID arc
        assert!(ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE.starts_with(ID_FPKI_CERTPOLICY_MEDIUM_ASSURANCE));
    }

    #[test]
    fn test_ogjos_medium_and_medium_hardware_distinct() {
        assert_ne!(ID_OGJOS_CP_MEDIUM, ID_OGJOS_CP_MEDIUM_HARDWARE);
    }
}
