//! Built-in certificate profile definitions
//!
//! This module defines the RFC-compliant default configurations for each template type.

use crate::cert::extensions::{BasicConstraints, ExtendedKeyUsage, KeyUsageFlags};

use super::{
    AllowedAlgorithm, KeyConstraints, SanType, Template, TemplateConfig, ValidityConstraints,
};

/// Built-in profile definitions
pub struct BuiltinProfiles;

impl BuiltinProfiles {
    /// Get the configuration for a built-in template
    pub fn get(template: Template) -> TemplateConfig {
        match template {
            Template::TlsServer => Self::tls_server(),
            Template::TlsClient => Self::tls_client(),
            Template::TlsDual => Self::tls_dual(),
            Template::CodeSigning => Self::code_signing(),
            Template::EmailSigning => Self::email_signing(),
            Template::RootCa => Self::root_ca(),
            Template::SubordinateCa => Self::subordinate_ca(),
            Template::OcspSigning => Self::ocsp_signing(),
            Template::Timestamp => Self::timestamp(),
            Template::ShortLived => Self::short_lived(),
        }
    }

    /// TLS Server Authentication profile
    ///
    /// For web servers, API endpoints, and other TLS server use cases.
    /// Key Usage: Digital Signature, Key Encipherment
    /// Extended Key Usage: serverAuth (1.3.6.1.5.5.7.3.1)
    pub fn tls_server() -> TemplateConfig {
        TemplateConfig {
            name: "tls-server".to_string(),
            display_name: "TLS Server".to_string(),
            description: "TLS server authentication for web servers and API endpoints".to_string(),
            validity: ValidityConstraints {
                default_days: 365,
                max_days: 398, // ~13 months per Apple/Mozilla requirements
            },
            key_constraints: KeyConstraints {
                allowed_algorithms: vec![
                    AllowedAlgorithm::Rsa { min_bits: 2048 },
                    AllowedAlgorithm::EcdsaP256,
                    AllowedAlgorithm::EcdsaP384,
                ],
                min_rsa_bits: 2048,
            },
            extensions: super::ExtensionConfig {
                key_usage: KeyUsageFlags::tls_server(),
                extended_key_usage: Some(ExtendedKeyUsage::tls_server()),
                basic_constraints: BasicConstraints::end_entity(),
                include_cdp: true,
                include_aia: true,
                custom_cdp_urls: None,
                custom_aia_ocsp: None,
                custom_aia_issuer: None,
            },
            subject: super::SubjectConstraints {
                require_cn: true,
                require_org: false,
                allowed_san_types: [SanType::Dns, SanType::Ip].into_iter().collect(),
            },
            certificate_policies: Vec::new(),
            is_builtin: true,
        }
    }

    /// TLS Client Authentication profile
    ///
    /// For client certificates used in mutual TLS (mTLS).
    /// Key Usage: Digital Signature
    /// Extended Key Usage: clientAuth (1.3.6.1.5.5.7.3.2)
    pub fn tls_client() -> TemplateConfig {
        TemplateConfig {
            name: "tls-client".to_string(),
            display_name: "TLS Client".to_string(),
            description: "TLS client authentication for mutual TLS (mTLS)".to_string(),
            validity: ValidityConstraints {
                default_days: 365,
                max_days: 730, // 2 years
            },
            key_constraints: KeyConstraints {
                allowed_algorithms: vec![
                    AllowedAlgorithm::Rsa { min_bits: 2048 },
                    AllowedAlgorithm::EcdsaP256,
                    AllowedAlgorithm::EcdsaP384,
                    AllowedAlgorithm::Ed25519,
                ],
                min_rsa_bits: 2048,
            },
            extensions: super::ExtensionConfig {
                key_usage: KeyUsageFlags::tls_client(),
                extended_key_usage: Some(ExtendedKeyUsage::tls_client()),
                basic_constraints: BasicConstraints::end_entity(),
                include_cdp: true,
                include_aia: true,
                custom_cdp_urls: None,
                custom_aia_ocsp: None,
                custom_aia_issuer: None,
            },
            subject: super::SubjectConstraints {
                require_cn: true,
                require_org: false,
                allowed_san_types: [SanType::Dns, SanType::Ip, SanType::Email]
                    .into_iter()
                    .collect(),
            },
            certificate_policies: Vec::new(),
            is_builtin: true,
        }
    }

    /// TLS Dual-Use profile (Server + Client)
    ///
    /// For certificates that need both server and client authentication.
    /// Key Usage: Digital Signature, Key Encipherment
    /// Extended Key Usage: serverAuth, clientAuth
    pub fn tls_dual() -> TemplateConfig {
        TemplateConfig {
            name: "tls-dual".to_string(),
            display_name: "TLS Dual-Use".to_string(),
            description: "TLS server and client authentication (dual-use)".to_string(),
            validity: ValidityConstraints {
                default_days: 365,
                max_days: 398,
            },
            key_constraints: KeyConstraints {
                allowed_algorithms: vec![
                    AllowedAlgorithm::Rsa { min_bits: 2048 },
                    AllowedAlgorithm::EcdsaP256,
                    AllowedAlgorithm::EcdsaP384,
                ],
                min_rsa_bits: 2048,
            },
            extensions: super::ExtensionConfig {
                key_usage: KeyUsageFlags::tls_server(),
                extended_key_usage: Some(ExtendedKeyUsage::tls_server_client()),
                basic_constraints: BasicConstraints::end_entity(),
                include_cdp: true,
                include_aia: true,
                custom_cdp_urls: None,
                custom_aia_ocsp: None,
                custom_aia_issuer: None,
            },
            subject: super::SubjectConstraints {
                require_cn: true,
                require_org: false,
                allowed_san_types: [SanType::Dns, SanType::Ip].into_iter().collect(),
            },
            certificate_policies: Vec::new(),
            is_builtin: true,
        }
    }

    /// Code Signing profile
    ///
    /// For signing software, drivers, and executables.
    /// Key Usage: Digital Signature
    /// Extended Key Usage: codeSigning (1.3.6.1.5.5.7.3.3)
    pub fn code_signing() -> TemplateConfig {
        TemplateConfig {
            name: "code-signing".to_string(),
            display_name: "Code Signing".to_string(),
            description: "Code signing for software and executables".to_string(),
            validity: ValidityConstraints {
                default_days: 365,
                max_days: 1095, // 3 years
            },
            key_constraints: KeyConstraints {
                allowed_algorithms: vec![
                    AllowedAlgorithm::Rsa { min_bits: 3072 },
                    AllowedAlgorithm::EcdsaP256,
                    AllowedAlgorithm::EcdsaP384,
                ],
                min_rsa_bits: 3072, // Higher for code signing
            },
            extensions: super::ExtensionConfig {
                key_usage: KeyUsageFlags::code_signing(),
                extended_key_usage: Some(ExtendedKeyUsage::code_signing()),
                basic_constraints: BasicConstraints::end_entity(),
                include_cdp: true,
                include_aia: true,
                custom_cdp_urls: None,
                custom_aia_ocsp: None,
                custom_aia_issuer: None,
            },
            subject: super::SubjectConstraints {
                require_cn: true,
                require_org: true, // Code signing typically requires organization
                allowed_san_types: [SanType::Email].into_iter().collect(),
            },
            certificate_policies: Vec::new(),
            is_builtin: true,
        }
    }

    /// Email Signing (S/MIME) profile
    ///
    /// For email encryption and signing.
    /// Key Usage: Digital Signature, Key Encipherment, Non-Repudiation
    /// Extended Key Usage: emailProtection (1.3.6.1.5.5.7.3.4)
    pub fn email_signing() -> TemplateConfig {
        TemplateConfig {
            name: "email-signing".to_string(),
            display_name: "Email (S/MIME)".to_string(),
            description: "Email signing and encryption (S/MIME)".to_string(),
            validity: ValidityConstraints {
                default_days: 365,
                max_days: 1095, // 3 years
            },
            key_constraints: KeyConstraints {
                allowed_algorithms: vec![
                    AllowedAlgorithm::Rsa { min_bits: 2048 },
                    AllowedAlgorithm::EcdsaP256,
                    AllowedAlgorithm::EcdsaP384,
                ],
                min_rsa_bits: 2048,
            },
            extensions: super::ExtensionConfig {
                key_usage: KeyUsageFlags::new(
                    KeyUsageFlags::DIGITAL_SIGNATURE
                        | KeyUsageFlags::KEY_ENCIPHERMENT
                        | KeyUsageFlags::NON_REPUDIATION,
                ),
                extended_key_usage: Some(ExtendedKeyUsage::new(vec![
                    crate::cert::extensions::oid::EKU_EMAIL_PROTECTION,
                ])),
                basic_constraints: BasicConstraints::end_entity(),
                include_cdp: true,
                include_aia: true,
                custom_cdp_urls: None,
                custom_aia_ocsp: None,
                custom_aia_issuer: None,
            },
            subject: super::SubjectConstraints {
                require_cn: true,
                require_org: false,
                allowed_san_types: [SanType::Email].into_iter().collect(),
            },
            certificate_policies: Vec::new(),
            is_builtin: true,
        }
    }

    /// Root CA profile
    ///
    /// For self-signed root CA certificates.
    /// Root CAs should NOT have CDP or AIA extensions (they are trust anchors).
    /// Key Usage: Key Cert Sign, CRL Sign, Digital Signature (for self-signed)
    /// Extended Key Usage: None (CA doesn't need EKU)
    pub fn root_ca() -> TemplateConfig {
        TemplateConfig {
            name: "root-ca".to_string(),
            display_name: "Root CA".to_string(),
            description: "Self-signed Root Certificate Authority".to_string(),
            validity: ValidityConstraints {
                default_days: 7300, // 20 years
                max_days: 10950,    // 30 years
            },
            key_constraints: KeyConstraints {
                allowed_algorithms: vec![
                    AllowedAlgorithm::Rsa { min_bits: 3072 },
                    AllowedAlgorithm::Rsa { min_bits: 4096 },
                    AllowedAlgorithm::EcdsaP384,
                ],
                min_rsa_bits: 3072, // Enterprise standard
            },
            extensions: super::ExtensionConfig {
                key_usage: KeyUsageFlags::ca_default(),
                extended_key_usage: None, // CAs typically don't have EKU
                basic_constraints: BasicConstraints::ca(), // No pathLen for root
                include_cdp: false,       // Root CAs do NOT have CDP
                include_aia: false,       // Root CAs do NOT have AIA
                custom_cdp_urls: None,
                custom_aia_ocsp: None,
                custom_aia_issuer: None,
            },
            subject: super::SubjectConstraints {
                require_cn: true,
                require_org: true, // CAs require organization
                allowed_san_types: std::collections::HashSet::new(), // No SANs for CA
            },
            certificate_policies: Vec::new(),
            is_builtin: true,
        }
    }

    /// Subordinate CA profile
    ///
    /// For issuing intermediate/subordinate CA certificates.
    /// Key Usage: Key Cert Sign, CRL Sign
    /// Extended Key Usage: None (CA doesn't need EKU)
    pub fn subordinate_ca() -> TemplateConfig {
        TemplateConfig {
            name: "subordinate-ca".to_string(),
            display_name: "Subordinate CA".to_string(),
            description: "Subordinate/Intermediate Certificate Authority".to_string(),
            validity: ValidityConstraints {
                default_days: 3650, // 10 years
                max_days: 7300,     // 20 years
            },
            key_constraints: KeyConstraints {
                allowed_algorithms: vec![
                    AllowedAlgorithm::Rsa { min_bits: 3072 },
                    AllowedAlgorithm::Rsa { min_bits: 4096 },
                    AllowedAlgorithm::EcdsaP384,
                ],
                min_rsa_bits: 3072, // Enterprise standard (3072 or 4096)
            },
            extensions: super::ExtensionConfig {
                key_usage: KeyUsageFlags::ca_default(),
                extended_key_usage: None, // CAs typically don't have EKU
                basic_constraints: BasicConstraints::ca_with_path_len(1), // pathLen:1 allows issuing Sub CAs
                include_cdp: true,                                        // Sub CAs MUST have CDP
                include_aia: true,                                        // Sub CAs MUST have AIA
                custom_cdp_urls: None,
                custom_aia_ocsp: None,
                custom_aia_issuer: None,
            },
            subject: super::SubjectConstraints {
                require_cn: true,
                require_org: true, // CAs require organization
                allowed_san_types: std::collections::HashSet::new(), // No SANs for CA
            },
            certificate_policies: Vec::new(),
            is_builtin: true,
        }
    }

    /// OCSP Responder profile
    ///
    /// For OCSP responder certificates.
    /// Key Usage: Digital Signature
    /// Extended Key Usage: ocspSigning (1.3.6.1.5.5.7.3.9)
    pub fn ocsp_signing() -> TemplateConfig {
        TemplateConfig {
            name: "ocsp-signing".to_string(),
            display_name: "OCSP Responder".to_string(),
            description: "OCSP responder for certificate status".to_string(),
            validity: ValidityConstraints {
                default_days: 365,
                max_days: 730, // 2 years
            },
            key_constraints: KeyConstraints {
                allowed_algorithms: vec![
                    AllowedAlgorithm::Rsa { min_bits: 2048 },
                    AllowedAlgorithm::EcdsaP256,
                    AllowedAlgorithm::EcdsaP384,
                ],
                min_rsa_bits: 2048,
            },
            extensions: super::ExtensionConfig {
                key_usage: KeyUsageFlags::new(KeyUsageFlags::DIGITAL_SIGNATURE),
                extended_key_usage: Some(ExtendedKeyUsage::new(vec![
                    crate::cert::extensions::oid::EKU_OCSP_SIGNING,
                ])),
                basic_constraints: BasicConstraints::end_entity(),
                include_cdp: true,
                include_aia: true,
                custom_cdp_urls: None,
                custom_aia_ocsp: None,
                custom_aia_issuer: None,
            },
            subject: super::SubjectConstraints {
                require_cn: true,
                require_org: false,
                allowed_san_types: [SanType::Dns].into_iter().collect(),
            },
            certificate_policies: Vec::new(),
            is_builtin: true,
        }
    }

    /// Timestamping profile
    ///
    /// For timestamping authority certificates.
    /// Key Usage: Digital Signature
    /// Extended Key Usage: timeStamping (1.3.6.1.5.5.7.3.8)
    pub fn timestamp() -> TemplateConfig {
        TemplateConfig {
            name: "timestamp".to_string(),
            display_name: "Timestamping".to_string(),
            description: "Timestamping authority for code and document signing".to_string(),
            validity: ValidityConstraints {
                default_days: 1095, // 3 years
                max_days: 3650,     // 10 years
            },
            key_constraints: KeyConstraints {
                allowed_algorithms: vec![
                    AllowedAlgorithm::Rsa { min_bits: 3072 },
                    AllowedAlgorithm::EcdsaP256,
                    AllowedAlgorithm::EcdsaP384,
                ],
                min_rsa_bits: 3072,
            },
            extensions: super::ExtensionConfig {
                key_usage: KeyUsageFlags::new(KeyUsageFlags::DIGITAL_SIGNATURE),
                extended_key_usage: Some(ExtendedKeyUsage::new(vec![
                    crate::cert::extensions::oid::EKU_TIME_STAMPING,
                ])),
                basic_constraints: BasicConstraints::end_entity(),
                include_cdp: true,
                include_aia: true,
                custom_cdp_urls: None,
                custom_aia_ocsp: None,
                custom_aia_issuer: None,
            },
            subject: super::SubjectConstraints {
                require_cn: true,
                require_org: true,
                allowed_san_types: [SanType::Dns].into_iter().collect(),
            },
            certificate_policies: Vec::new(),
            is_builtin: true,
        }
    }

    /// Short-lived / ephemeral certificate profile
    ///
    /// For zero-trust architectures, service mesh workloads, CI/CD pipelines,
    /// and any scenario where certificates should expire quickly rather than
    /// rely on revocation. Default 1 day, max 7 days.
    ///
    /// Key design: no CDP/AIA extensions — revocation is unnecessary because
    /// the certificate expires before CRL propagation would complete.
    /// Key Usage: Digital Signature
    /// Extended Key Usage: serverAuth + clientAuth (mTLS workloads)
    pub fn short_lived() -> TemplateConfig {
        TemplateConfig {
            name: "short-lived".to_string(),
            display_name: "Short-Lived / Ephemeral".to_string(),
            description: "Short-lived certificates for zero-trust, service mesh, and CI/CD workloads. Expires before revocation is needed.".to_string(),
            validity: ValidityConstraints {
                default_days: 1,   // 24 hours
                max_days: 7,       // 1 week hard cap
            },
            key_constraints: KeyConstraints {
                allowed_algorithms: vec![
                    AllowedAlgorithm::EcdsaP256,
                    AllowedAlgorithm::EcdsaP384,
                ],
                min_rsa_bits: 2048,
            },
            extensions: super::ExtensionConfig {
                key_usage: KeyUsageFlags::new(
                    KeyUsageFlags::DIGITAL_SIGNATURE,
                ),
                extended_key_usage: Some(ExtendedKeyUsage::new(vec![
                    crate::cert::extensions::oid::EKU_SERVER_AUTH,
                    crate::cert::extensions::oid::EKU_CLIENT_AUTH,
                ])),
                basic_constraints: BasicConstraints::end_entity(),
                include_cdp: false,  // No CRL — expires before revocation propagates
                include_aia: false,  // No OCSP — unnecessary for short-lived certs
                custom_cdp_urls: None,
                custom_aia_ocsp: None,
                custom_aia_issuer: None,
            },
            subject: super::SubjectConstraints {
                require_cn: true,
                require_org: false,
                allowed_san_types: [SanType::Dns, SanType::Ip].into_iter().collect(),
            },
            certificate_policies: Vec::new(),
            is_builtin: true,
        }
    }

    /// Get all built-in template configurations
    pub fn all() -> Vec<TemplateConfig> {
        Template::all().iter().map(|t| Self::get(*t)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_server_profile() {
        let config = BuiltinProfiles::tls_server();
        assert_eq!(config.name, "tls-server");
        assert!(config.is_builtin);
        assert!(config
            .extensions
            .key_usage
            .contains(KeyUsageFlags::DIGITAL_SIGNATURE));
        assert!(config
            .extensions
            .key_usage
            .contains(KeyUsageFlags::KEY_ENCIPHERMENT));
        assert!(config.extensions.extended_key_usage.is_some());
    }

    #[test]
    fn test_root_ca_profile() {
        let config = BuiltinProfiles::root_ca();
        assert_eq!(config.name, "root-ca");
        assert!(config
            .extensions
            .key_usage
            .contains(KeyUsageFlags::KEY_CERT_SIGN));
        assert!(config
            .extensions
            .key_usage
            .contains(KeyUsageFlags::CRL_SIGN));
        assert!(config.extensions.basic_constraints.ca);
        // Root CAs should NOT have CDP or AIA
        assert!(!config.extensions.include_cdp);
        assert!(!config.extensions.include_aia);
    }

    #[test]
    fn test_subordinate_ca_profile() {
        let config = BuiltinProfiles::subordinate_ca();
        assert_eq!(config.name, "subordinate-ca");
        assert!(config
            .extensions
            .key_usage
            .contains(KeyUsageFlags::KEY_CERT_SIGN));
        assert!(config
            .extensions
            .key_usage
            .contains(KeyUsageFlags::CRL_SIGN));
        assert!(config.extensions.basic_constraints.ca);
        // Subordinate CAs MUST have CDP and AIA
        assert!(config.extensions.include_cdp);
        assert!(config.extensions.include_aia);
    }

    #[test]
    fn test_all_profiles_builtin() {
        for config in BuiltinProfiles::all() {
            assert!(
                config.is_builtin,
                "{} should be marked as builtin",
                config.name
            );
        }
    }

    #[test]
    fn test_code_signing_eku_no_tls() {
        // Code-signing cert must NOT include serverAuth or clientAuth EKU
        let config = BuiltinProfiles::code_signing();
        let eku = config.extensions.extended_key_usage.as_ref().unwrap();
        assert!(
            eku.usages
                .contains(&crate::cert::extensions::oid::EKU_CODE_SIGNING),
            "Code signing must include codeSigning EKU"
        );
        assert!(
            !eku.usages
                .contains(&crate::cert::extensions::oid::EKU_SERVER_AUTH),
            "Code signing must NOT include serverAuth"
        );
        assert!(
            !eku.usages
                .contains(&crate::cert::extensions::oid::EKU_CLIENT_AUTH),
            "Code signing must NOT include clientAuth"
        );
    }

    #[test]
    fn test_timestamp_eku_only_timestamping() {
        // Timestamp cert should have timeStamping as the only EKU
        let config = BuiltinProfiles::timestamp();
        let eku = config.extensions.extended_key_usage.as_ref().unwrap();
        assert_eq!(eku.usages.len(), 1, "Timestamp should have exactly one EKU");
        assert!(
            eku.usages
                .contains(&crate::cert::extensions::oid::EKU_TIME_STAMPING),
            "Timestamp must include timeStamping EKU"
        );
    }

    #[test]
    fn test_email_signing_eku() {
        let config = BuiltinProfiles::email_signing();
        let eku = config.extensions.extended_key_usage.as_ref().unwrap();
        assert!(
            eku.usages
                .contains(&crate::cert::extensions::oid::EKU_EMAIL_PROTECTION),
            "Email signing must include emailProtection EKU"
        );
        // Email SAN should be allowed
        assert!(
            config.subject.allowed_san_types.contains(&SanType::Email),
            "Email signing must allow email SANs"
        );
    }

    #[test]
    fn test_ocsp_signing_eku() {
        let config = BuiltinProfiles::ocsp_signing();
        let eku = config.extensions.extended_key_usage.as_ref().unwrap();
        assert_eq!(eku.usages.len(), 1, "OCSP should have exactly one EKU");
        assert!(
            eku.usages
                .contains(&crate::cert::extensions::oid::EKU_OCSP_SIGNING),
            "OCSP signing must include ocspSigning EKU"
        );
    }

    #[test]
    fn test_tls_server_includes_cdp_and_aia() {
        let config = BuiltinProfiles::tls_server();
        assert!(config.extensions.include_cdp, "TLS server must include CDP");
        assert!(config.extensions.include_aia, "TLS server must include AIA");
    }

    #[test]
    fn test_tls_server_max_validity_398_days() {
        // CA/Browser Forum baseline requirement
        let config = BuiltinProfiles::tls_server();
        assert_eq!(
            config.validity.max_days, 398,
            "TLS server max validity must be 398 days per CA/B Forum"
        );
    }

    #[test]
    fn test_all_ee_profiles_are_not_ca() {
        // All end-entity profiles must have basicConstraints.ca = false
        let ee_profiles = [
            BuiltinProfiles::tls_server(),
            BuiltinProfiles::tls_client(),
            BuiltinProfiles::tls_dual(),
            BuiltinProfiles::code_signing(),
            BuiltinProfiles::email_signing(),
            BuiltinProfiles::ocsp_signing(),
            BuiltinProfiles::timestamp(),
            BuiltinProfiles::short_lived(),
        ];
        for config in &ee_profiles {
            assert!(
                !config.extensions.basic_constraints.ca,
                "{} must have basicConstraints.ca = false",
                config.name
            );
        }
    }

    #[test]
    fn test_ca_profiles_have_key_cert_sign() {
        for config in [
            BuiltinProfiles::root_ca(),
            BuiltinProfiles::subordinate_ca(),
        ] {
            assert!(
                config
                    .extensions
                    .key_usage
                    .contains(KeyUsageFlags::KEY_CERT_SIGN),
                "{} must have keyCertSign",
                config.name
            );
            assert!(
                config
                    .extensions
                    .key_usage
                    .contains(KeyUsageFlags::CRL_SIGN),
                "{} must have crlSign",
                config.name
            );
        }
    }

    #[test]
    fn test_all_profiles_count() {
        // We should have exactly 10 built-in profiles
        let all = BuiltinProfiles::all();
        assert_eq!(all.len(), 10, "Expected 10 built-in profiles");
    }

    #[test]
    fn test_short_lived_profile() {
        let config = BuiltinProfiles::short_lived();
        assert_eq!(config.name, "short-lived");
        assert!(config.is_builtin);
        assert_eq!(config.validity.default_days, 1, "Default should be 1 day");
        assert_eq!(config.validity.max_days, 7, "Max should be 7 days");
    }

    #[test]
    fn test_short_lived_no_cdp_aia() {
        // Short-lived certs should NOT include CDP or AIA — they expire before revocation
        let config = BuiltinProfiles::short_lived();
        assert!(
            !config.extensions.include_cdp,
            "Short-lived must NOT include CDP"
        );
        assert!(
            !config.extensions.include_aia,
            "Short-lived must NOT include AIA"
        );
    }

    #[test]
    fn test_short_lived_dual_eku() {
        // Short-lived certs should have both serverAuth + clientAuth for mTLS workloads
        let config = BuiltinProfiles::short_lived();
        let eku = config.extensions.extended_key_usage.as_ref().unwrap();
        assert!(
            eku.usages
                .contains(&crate::cert::extensions::oid::EKU_SERVER_AUTH),
            "Short-lived must include serverAuth"
        );
        assert!(
            eku.usages
                .contains(&crate::cert::extensions::oid::EKU_CLIENT_AUTH),
            "Short-lived must include clientAuth"
        );
    }

    #[test]
    fn test_short_lived_ecdsa_only() {
        // Short-lived certs should prefer ECDSA (fast key gen, small certs)
        let config = BuiltinProfiles::short_lived();
        assert!(
            config
                .key_constraints
                .allowed_algorithms
                .contains(&AllowedAlgorithm::EcdsaP256),
            "Short-lived should allow ECDSA P-256"
        );
        // Should NOT allow RSA (slow key gen is bad for ephemeral certs)
        assert!(
            !config
                .key_constraints
                .allowed_algorithms
                .iter()
                .any(|a| matches!(a, AllowedAlgorithm::Rsa { .. })),
            "Short-lived should NOT allow RSA (slow key gen)"
        );
    }

    #[test]
    fn test_short_lived_template_from_id() {
        assert_eq!(Template::from_id("short-lived"), Some(Template::ShortLived));
        assert_eq!(Template::from_id("ephemeral"), Some(Template::ShortLived));
    }
}
