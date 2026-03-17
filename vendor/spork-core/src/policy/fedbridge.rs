//! Federal Bridge CA Cross-Certification Support
//!
//! Implements the certificate profile and operational requirements for
//! cross-certification with the U.S. Federal Bridge CA (FBCA).
//!
//! ## Cross-Certification Model
//!
//! The Federal Bridge provides trust between PKI domains through bilateral
//! cross-certification. When SPORK CA cross-certifies with the FBCA:
//!
//! 1. The FBCA issues a cross-certificate to the SPORK CA, asserting that
//!    the SPORK CA meets the mapped policy requirements.
//! 2. The SPORK CA issues a cross-certificate to the FBCA, enabling SPORK
//!    relying parties to validate federal certificates.
//!
//! ## Certificate Profile Requirements (per FBCA CP §7)
//!
//! Cross-certificates issued to/from the Federal Bridge must include:
//! - `PolicyMappings` extension mapping issuer policies to subject policies
//! - `NameConstraints` extension restricting the cross-certified CA's namespace
//! - `BasicConstraints` with `pathLenConstraint` limiting chain depth
//! - `InhibitAnyPolicy` to prevent `anyPolicy` from crossing the bridge
//! - `PolicyConstraints` with `requireExplicitPolicy` and/or `inhibitPolicyMapping`
//!
//! ## References
//!
//! - X.509 Certificate Policy for the U.S. Federal PKI Common Policy Framework
//! - RFC 5280 §4.2.1.5 (Policy Mappings)
//! - RFC 5280 §4.2.1.10 (Name Constraints)
//! - RFC 5280 §4.2.1.11 (Policy Constraints)
//! - RFC 5280 §4.2.1.14 (Inhibit anyPolicy)

use serde::{Deserialize, Serialize};

use super::fpki::PolicyMapping;
use super::security_level::SecurityLevel;

/// Configuration for Federal Bridge cross-certification.
///
/// Defines the parameters used when generating cross-certificates
/// between a SPORK CA and the Federal Bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedBridgeConfig {
    /// Security level the SPORK CA operates at.
    pub security_level: SecurityLevel,

    /// Policy mappings from FPKI domain to SPORK domain.
    pub policy_mappings: Vec<PolicyMapping>,

    /// Permitted DNS name subtrees (e.g., `.quantumnexum.com`).
    ///
    /// Included in the cross-certificate's `NameConstraints` extension as
    /// `permittedSubtrees`. If empty, no DNS name constraint is applied.
    pub permitted_dns_subtrees: Vec<String>,

    /// Excluded DNS name subtrees.
    ///
    /// Included in `NameConstraints` as `excludedSubtrees`.
    pub excluded_dns_subtrees: Vec<String>,

    /// Permitted directory name subtrees (DN prefixes).
    ///
    /// Restrict the cross-certified CA to only issue certificates under
    /// these DN namespaces. Each entry is a DN prefix string, e.g.,
    /// `DC=quantumnexum, DC=com`.
    pub permitted_dn_subtrees: Vec<String>,

    /// Maximum path length for the cross-certificate.
    ///
    /// Limits how many intermediate CAs can appear below the cross-certified
    /// CA in the chain. A value of 0 means the cross-certified CA can only
    /// issue end-entity certificates (no sub-CAs).
    pub max_path_length: Option<u32>,

    /// Whether to include `inhibitAnyPolicy` in the cross-certificate.
    ///
    /// When `true`, the `anyPolicy` OID (2.5.29.32.0) is not valid past
    /// this cross-certificate. This is a standard FBCA requirement.
    pub inhibit_any_policy: bool,

    /// Skip-certs value for `inhibitAnyPolicy` (0 = immediate).
    pub inhibit_any_policy_skip_certs: u32,

    /// Whether to set `requireExplicitPolicy` in `PolicyConstraints`.
    ///
    /// When `true`, certificates in the chain must carry an explicit
    /// certificate policy OID — `anyPolicy` alone is not sufficient.
    pub require_explicit_policy: bool,

    /// Skip-certs value for `requireExplicitPolicy`.
    pub require_explicit_policy_skip_certs: u32,

    /// Whether to set `inhibitPolicyMapping` in `PolicyConstraints`.
    ///
    /// When `true`, policy mapping is inhibited past this point in the chain.
    pub inhibit_policy_mapping: bool,

    /// Skip-certs value for `inhibitPolicyMapping`.
    pub inhibit_policy_mapping_skip_certs: u32,
}

impl FedBridgeConfig {
    /// Create a new Federal Bridge configuration for the given security level.
    ///
    /// Generates default policy mappings and constraints appropriate for
    /// the specified assurance level.
    pub fn new(security_level: SecurityLevel) -> Self {
        let policy_mappings = default_policy_mappings(security_level);
        Self {
            security_level,
            policy_mappings,
            permitted_dns_subtrees: Vec::new(),
            excluded_dns_subtrees: Vec::new(),
            permitted_dn_subtrees: Vec::new(),
            max_path_length: Some(1), // Default: allow one intermediate
            inhibit_any_policy: true,
            inhibit_any_policy_skip_certs: 0,
            require_explicit_policy: true,
            require_explicit_policy_skip_certs: 0,
            inhibit_policy_mapping: false,
            inhibit_policy_mapping_skip_certs: 0,
        }
    }

    /// Set the permitted DNS subtrees for name constraints.
    pub fn with_dns_subtrees(mut self, permitted: Vec<String>) -> Self {
        self.permitted_dns_subtrees = permitted;
        self
    }

    /// Set the permitted DN subtrees for name constraints.
    pub fn with_dn_subtrees(mut self, permitted: Vec<String>) -> Self {
        self.permitted_dn_subtrees = permitted;
        self
    }

    /// Set the maximum path length constraint.
    pub fn with_max_path_length(mut self, max: Option<u32>) -> Self {
        self.max_path_length = max;
        self
    }

    /// Add a custom policy mapping.
    pub fn with_policy_mapping(mut self, mapping: PolicyMapping) -> Self {
        self.policy_mappings.push(mapping);
        self
    }

    /// Enable inhibitPolicyMapping with the given skip-certs value.
    pub fn with_inhibit_policy_mapping(mut self, skip_certs: u32) -> Self {
        self.inhibit_policy_mapping = true;
        self.inhibit_policy_mapping_skip_certs = skip_certs;
        self
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.policy_mappings.is_empty() {
            errors.push("At least one policy mapping is required for cross-certification".into());
        }

        // FBCA requires inhibitAnyPolicy
        if !self.inhibit_any_policy {
            errors.push("inhibitAnyPolicy should be set for FBCA cross-certification".into());
        }

        // At Level 3+, require explicit policy
        if self.security_level >= SecurityLevel::Level3 && !self.require_explicit_policy {
            errors
                .push("requireExplicitPolicy should be set at Level 3+ for FBCA compliance".into());
        }

        // Level 4 should have name constraints
        if self.security_level >= SecurityLevel::Level4
            && self.permitted_dns_subtrees.is_empty()
            && self.permitted_dn_subtrees.is_empty()
        {
            errors.push("Level 4 cross-certificates should include name constraints".into());
        }

        // Validate DNS subtree format
        for subtree in &self.permitted_dns_subtrees {
            if !subtree.starts_with('.') && !subtree.contains('.') {
                errors.push(format!(
                    "DNS subtree '{}' should be a domain suffix starting with '.'",
                    subtree
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Cross-certificate profile describing the extensions and fields
/// for a cross-certificate issued between SPORK CA and a bridge CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossCertProfile {
    /// Policy mappings for the PolicyMappings extension.
    pub policy_mappings: Vec<PolicyMapping>,

    /// Name constraints: permitted DNS subtrees.
    pub permitted_dns_subtrees: Vec<String>,

    /// Name constraints: excluded DNS subtrees.
    pub excluded_dns_subtrees: Vec<String>,

    /// Name constraints: permitted DN subtrees.
    pub permitted_dn_subtrees: Vec<String>,

    /// BasicConstraints pathLenConstraint.
    pub path_len_constraint: Option<u32>,

    /// InhibitAnyPolicy skip-certs (None = extension not present).
    pub inhibit_any_policy: Option<u32>,

    /// PolicyConstraints: requireExplicitPolicy skip-certs.
    pub require_explicit_policy: Option<u32>,

    /// PolicyConstraints: inhibitPolicyMapping skip-certs.
    pub inhibit_policy_mapping: Option<u32>,

    /// Certificate policies to include (OID strings).
    pub certificate_policies: Vec<String>,

    /// Maximum validity period (days) for the cross-certificate.
    pub max_validity_days: u32,
}

impl CrossCertProfile {
    /// Build a cross-certificate profile from a Federal Bridge configuration.
    pub fn from_config(config: &FedBridgeConfig) -> Self {
        let certificate_policies: Vec<String> = config
            .policy_mappings
            .iter()
            .map(|m| m.subject_domain_policy.clone())
            .collect();

        Self {
            policy_mappings: config.policy_mappings.clone(),
            permitted_dns_subtrees: config.permitted_dns_subtrees.clone(),
            excluded_dns_subtrees: config.excluded_dns_subtrees.clone(),
            permitted_dn_subtrees: config.permitted_dn_subtrees.clone(),
            path_len_constraint: config.max_path_length,
            inhibit_any_policy: if config.inhibit_any_policy {
                Some(config.inhibit_any_policy_skip_certs)
            } else {
                None
            },
            require_explicit_policy: if config.require_explicit_policy {
                Some(config.require_explicit_policy_skip_certs)
            } else {
                None
            },
            inhibit_policy_mapping: if config.inhibit_policy_mapping {
                Some(config.inhibit_policy_mapping_skip_certs)
            } else {
                None
            },
            certificate_policies,
            max_validity_days: cross_cert_validity_days(config.security_level),
        }
    }

    /// Check whether this profile has name constraints.
    pub fn has_name_constraints(&self) -> bool {
        !self.permitted_dns_subtrees.is_empty()
            || !self.excluded_dns_subtrees.is_empty()
            || !self.permitted_dn_subtrees.is_empty()
    }

    /// Check whether this profile has policy constraints.
    pub fn has_policy_constraints(&self) -> bool {
        self.require_explicit_policy.is_some() || self.inhibit_policy_mapping.is_some()
    }
}

/// Get the default cross-certificate validity period (days) for a security level.
fn cross_cert_validity_days(level: SecurityLevel) -> u32 {
    match level {
        SecurityLevel::Level1 => 1095, // 3 years
        SecurityLevel::Level2 => 1095, // 3 years
        SecurityLevel::Level3 => 1825, // 5 years
        SecurityLevel::Level4 => 1825, // 5 years
    }
}

/// Generate default policy mappings for a given security level.
///
/// Maps the appropriate FPKI policy OID to the corresponding Ogjos/SPORK OID.
fn default_policy_mappings(level: SecurityLevel) -> Vec<PolicyMapping> {
    use super::fpki::*;

    match level {
        SecurityLevel::Level1 => {
            vec![
                PolicyMapping::new(ID_FPKI_COMMON_POLICY, ID_OGJOS_CP_RUDIMENTARY)
                    .with_description("FPKI Common Policy maps to SPORK Rudimentary"),
            ]
        }
        SecurityLevel::Level2 => {
            vec![
                PolicyMapping::new(ID_FPKI_CERTPOLICY_MEDIUM_ASSURANCE, ID_OGJOS_CP_MEDIUM)
                    .with_description("FPKI Medium Assurance maps to SPORK Medium"),
                PolicyMapping::new(ID_FPKI_COMMON_POLICY, ID_OGJOS_CP_BASIC)
                    .with_description("FPKI Common Policy maps to SPORK Basic"),
            ]
        }
        SecurityLevel::Level3 => {
            vec![
                PolicyMapping::new(
                    ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE,
                    ID_OGJOS_CP_MEDIUM_HARDWARE,
                )
                .with_description("FPKI Medium Hardware maps to SPORK Medium Hardware"),
                PolicyMapping::new(ID_FPKI_CERTPOLICY_MEDIUM_ASSURANCE, ID_OGJOS_CP_MEDIUM)
                    .with_description("FPKI Medium Assurance maps to SPORK Medium"),
            ]
        }
        SecurityLevel::Level4 => {
            vec![
                PolicyMapping::new(ID_FPKI_COMMON_HIGH, ID_OGJOS_CP_HIGH)
                    .with_description("FPKI High maps to SPORK High"),
                PolicyMapping::new(
                    ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE,
                    ID_OGJOS_CP_MEDIUM_HARDWARE,
                )
                .with_description("FPKI Medium Hardware maps to SPORK Medium Hardware"),
                PolicyMapping::new(ID_FPKI_CERTPOLICY_MEDIUM_ASSURANCE, ID_OGJOS_CP_MEDIUM)
                    .with_description("FPKI Medium Assurance maps to SPORK Medium"),
            ]
        }
    }
}

/// Standard excluded DNS subtrees for federal bridge cross-certs.
///
/// These domains should typically be excluded from SPORK cross-certificates
/// to prevent namespace overlap with existing federal PKIs.
pub fn standard_excluded_dns() -> Vec<String> {
    vec![".gov".to_string(), ".mil".to_string()]
}

/// Generate the recommended name constraint DN subtree for a SPORK CA
/// operating under the Quantum Nexum namespace.
pub fn quantum_nexum_dn_subtree() -> String {
    "DC=quantumnexum, DC=com".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::fpki;

    // ---- FedBridgeConfig creation ----

    #[test]
    fn test_config_new_level2() {
        let config = FedBridgeConfig::new(SecurityLevel::Level2);
        assert_eq!(config.security_level, SecurityLevel::Level2);
        assert!(!config.policy_mappings.is_empty());
        assert!(config.inhibit_any_policy);
        assert!(config.require_explicit_policy);
        assert_eq!(config.max_path_length, Some(1));
    }

    #[test]
    fn test_config_new_level3() {
        let config = FedBridgeConfig::new(SecurityLevel::Level3);
        assert_eq!(config.security_level, SecurityLevel::Level3);
        // Level 3 should have Medium Hardware mapping
        let has_medium_hw = config
            .policy_mappings
            .iter()
            .any(|m| m.issuer_domain_policy == fpki::ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE);
        assert!(has_medium_hw, "Level 3 should map FPKI Medium Hardware");
    }

    #[test]
    fn test_config_new_level4() {
        let config = FedBridgeConfig::new(SecurityLevel::Level4);
        assert_eq!(config.policy_mappings.len(), 3);
        // Should include High mapping
        let has_high = config
            .policy_mappings
            .iter()
            .any(|m| m.issuer_domain_policy == fpki::ID_FPKI_COMMON_HIGH);
        assert!(has_high, "Level 4 should map FPKI High");
    }

    // ---- Builder methods ----

    #[test]
    fn test_config_with_dns_subtrees() {
        let config = FedBridgeConfig::new(SecurityLevel::Level2)
            .with_dns_subtrees(vec![".quantumnexum.com".into()]);
        assert_eq!(config.permitted_dns_subtrees, vec![".quantumnexum.com"]);
    }

    #[test]
    fn test_config_with_dn_subtrees() {
        let config = FedBridgeConfig::new(SecurityLevel::Level3)
            .with_dn_subtrees(vec!["DC=quantumnexum, DC=com".into()]);
        assert_eq!(config.permitted_dn_subtrees.len(), 1);
    }

    #[test]
    fn test_config_with_path_length() {
        let config = FedBridgeConfig::new(SecurityLevel::Level2).with_max_path_length(Some(2));
        assert_eq!(config.max_path_length, Some(2));
    }

    #[test]
    fn test_config_with_inhibit_policy_mapping() {
        let config = FedBridgeConfig::new(SecurityLevel::Level3).with_inhibit_policy_mapping(1);
        assert!(config.inhibit_policy_mapping);
        assert_eq!(config.inhibit_policy_mapping_skip_certs, 1);
    }

    #[test]
    fn test_config_with_custom_mapping() {
        let config = FedBridgeConfig::new(SecurityLevel::Level2).with_policy_mapping(
            PolicyMapping::new("1.2.3.4", "1.2.3.5").with_description("Custom mapping"),
        );
        assert!(config.policy_mappings.len() > 2);
    }

    // ---- Validation ----

    #[test]
    fn test_config_validate_default_level2() {
        let config = FedBridgeConfig::new(SecurityLevel::Level2);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_default_level3() {
        let config = FedBridgeConfig::new(SecurityLevel::Level3);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_empty_mappings() {
        let mut config = FedBridgeConfig::new(SecurityLevel::Level2);
        config.policy_mappings.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_validate_level4_needs_name_constraints() {
        let config = FedBridgeConfig::new(SecurityLevel::Level4);
        // Default has no name constraints — should warn
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("name constraints")));
    }

    #[test]
    fn test_config_validate_level4_with_name_constraints() {
        let config = FedBridgeConfig::new(SecurityLevel::Level4)
            .with_dns_subtrees(vec![".quantumnexum.com".into()]);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_bad_dns_subtree() {
        let config =
            FedBridgeConfig::new(SecurityLevel::Level2).with_dns_subtrees(vec!["badformat".into()]);
        let result = config.validate();
        assert!(result.is_err());
    }

    // ---- CrossCertProfile ----

    #[test]
    fn test_cross_cert_profile_from_config() {
        let config = FedBridgeConfig::new(SecurityLevel::Level3)
            .with_dns_subtrees(vec![".quantumnexum.com".into()])
            .with_dn_subtrees(vec!["DC=quantumnexum, DC=com".into()]);

        let profile = CrossCertProfile::from_config(&config);
        assert!(!profile.policy_mappings.is_empty());
        assert!(profile.has_name_constraints());
        assert!(profile.has_policy_constraints());
        assert_eq!(profile.path_len_constraint, Some(1));
        assert_eq!(profile.inhibit_any_policy, Some(0));
        assert_eq!(profile.require_explicit_policy, Some(0));
        assert_eq!(profile.max_validity_days, 1825);
    }

    #[test]
    fn test_cross_cert_profile_policies() {
        let config = FedBridgeConfig::new(SecurityLevel::Level2);
        let profile = CrossCertProfile::from_config(&config);
        // Should contain the subject-domain OIDs from mappings
        assert!(!profile.certificate_policies.is_empty());
        assert!(profile
            .certificate_policies
            .contains(&fpki::ID_OGJOS_CP_MEDIUM.to_string()));
    }

    #[test]
    fn test_cross_cert_profile_no_name_constraints() {
        let config = FedBridgeConfig::new(SecurityLevel::Level1);
        let profile = CrossCertProfile::from_config(&config);
        assert!(!profile.has_name_constraints());
    }

    #[test]
    fn test_cross_cert_profile_no_inhibit_mapping() {
        let config = FedBridgeConfig::new(SecurityLevel::Level2);
        let profile = CrossCertProfile::from_config(&config);
        assert!(profile.inhibit_policy_mapping.is_none());
    }

    #[test]
    fn test_cross_cert_profile_with_inhibit_mapping() {
        let config = FedBridgeConfig::new(SecurityLevel::Level3).with_inhibit_policy_mapping(2);
        let profile = CrossCertProfile::from_config(&config);
        assert_eq!(profile.inhibit_policy_mapping, Some(2));
    }

    // ---- Validity periods ----

    #[test]
    fn test_cross_cert_validity() {
        assert_eq!(cross_cert_validity_days(SecurityLevel::Level1), 1095);
        assert_eq!(cross_cert_validity_days(SecurityLevel::Level2), 1095);
        assert_eq!(cross_cert_validity_days(SecurityLevel::Level3), 1825);
        assert_eq!(cross_cert_validity_days(SecurityLevel::Level4), 1825);
    }

    // ---- Default policy mappings ----

    #[test]
    fn test_default_mappings_level1() {
        let mappings = default_policy_mappings(SecurityLevel::Level1);
        assert_eq!(mappings.len(), 1);
        assert_eq!(
            mappings[0].issuer_domain_policy,
            fpki::ID_FPKI_COMMON_POLICY
        );
        assert_eq!(
            mappings[0].subject_domain_policy,
            fpki::ID_OGJOS_CP_RUDIMENTARY
        );
    }

    #[test]
    fn test_default_mappings_level2() {
        let mappings = default_policy_mappings(SecurityLevel::Level2);
        assert_eq!(mappings.len(), 2);
    }

    #[test]
    fn test_default_mappings_level3() {
        let mappings = default_policy_mappings(SecurityLevel::Level3);
        assert_eq!(mappings.len(), 2);
        // First mapping should be Medium Hardware
        assert_eq!(
            mappings[0].issuer_domain_policy,
            fpki::ID_FPKI_CERTPOLICY_MEDIUM_HARDWARE
        );
    }

    #[test]
    fn test_default_mappings_level4() {
        let mappings = default_policy_mappings(SecurityLevel::Level4);
        assert_eq!(mappings.len(), 3);
        // First mapping should be High
        assert_eq!(mappings[0].issuer_domain_policy, fpki::ID_FPKI_COMMON_HIGH);
    }

    // ---- Helper functions ----

    #[test]
    fn test_standard_excluded_dns() {
        let excluded = standard_excluded_dns();
        assert!(excluded.contains(&".gov".to_string()));
        assert!(excluded.contains(&".mil".to_string()));
    }

    #[test]
    fn test_quantum_nexum_dn_subtree() {
        let dn = quantum_nexum_dn_subtree();
        assert!(dn.contains("quantumnexum"));
        assert!(dn.contains("DC="));
    }

    // ---- Serde ----

    #[test]
    fn test_config_serde_roundtrip() {
        let config = FedBridgeConfig::new(SecurityLevel::Level3)
            .with_dns_subtrees(vec![".quantumnexum.com".into()])
            .with_inhibit_policy_mapping(1);
        let json = serde_json::to_string(&config).unwrap();
        let restored: FedBridgeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.security_level, SecurityLevel::Level3);
        assert_eq!(restored.policy_mappings.len(), config.policy_mappings.len());
        assert!(restored.inhibit_policy_mapping);
    }

    #[test]
    fn test_cross_cert_profile_serde_roundtrip() {
        let config = FedBridgeConfig::new(SecurityLevel::Level2);
        let profile = CrossCertProfile::from_config(&config);
        let json = serde_json::to_string(&profile).unwrap();
        let restored: CrossCertProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.max_validity_days, profile.max_validity_days);
    }
}
