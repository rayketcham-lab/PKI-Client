//! Certificate Templates
//!
//! This module provides configurable certificate templates for different use cases.
//! Templates define constraints and defaults for certificate issuance.

mod builder;
mod profiles;

pub use builder::{TemplateBuilder, TemplateRegistry, ValidatedRequest};
pub use profiles::BuiltinProfiles;

use std::collections::HashSet;

use crate::cert::extensions::{BasicConstraints, ExtendedKeyUsage, KeyUsageFlags};

/// Certificate template types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Template {
    /// TLS server authentication
    TlsServer,
    /// TLS client authentication
    TlsClient,
    /// TLS server and client (dual-use)
    TlsDual,
    /// Code signing
    CodeSigning,
    /// Email signing (S/MIME)
    EmailSigning,
    /// Root CA (self-signed, no CDP/AIA)
    RootCa,
    /// Subordinate CA (issued by Root or another Sub CA, has CDP/AIA)
    SubordinateCa,
    /// OCSP responder
    OcspSigning,
    /// Timestamping
    Timestamp,
    /// Short-lived / ephemeral (zero-trust, service mesh, CI/CD)
    ShortLived,
}

impl Template {
    /// Get the template identifier string
    pub fn id(&self) -> &'static str {
        match self {
            Template::TlsServer => "tls-server",
            Template::TlsClient => "tls-client",
            Template::TlsDual => "tls-dual",
            Template::CodeSigning => "code-signing",
            Template::EmailSigning => "email-signing",
            Template::RootCa => "root-ca",
            Template::SubordinateCa => "subordinate-ca",
            Template::OcspSigning => "ocsp-signing",
            Template::Timestamp => "timestamp",
            Template::ShortLived => "short-lived",
        }
    }

    /// Parse template from string identifier
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "tls-server" => Some(Template::TlsServer),
            "tls-client" => Some(Template::TlsClient),
            "tls-dual" => Some(Template::TlsDual),
            "code-signing" => Some(Template::CodeSigning),
            "email-signing" => Some(Template::EmailSigning),
            "root-ca" => Some(Template::RootCa),
            "subordinate-ca" => Some(Template::SubordinateCa),
            "ocsp-signing" => Some(Template::OcspSigning),
            "timestamp" => Some(Template::Timestamp),
            "short-lived" | "ephemeral" => Some(Template::ShortLived),
            _ => None,
        }
    }

    /// Get the default configuration for this template
    pub fn default_config(&self) -> TemplateConfig {
        BuiltinProfiles::get(*self)
    }

    /// List all built-in templates
    pub fn all() -> &'static [Template] {
        &[
            Template::TlsServer,
            Template::TlsClient,
            Template::TlsDual,
            Template::CodeSigning,
            Template::EmailSigning,
            Template::RootCa,
            Template::SubordinateCa,
            Template::OcspSigning,
            Template::Timestamp,
            Template::ShortLived,
        ]
    }
}

impl std::fmt::Display for Template {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id())
    }
}

/// Subject Alternative Name types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SanType {
    /// DNS name
    Dns,
    /// IP address
    Ip,
    /// Email address (RFC 822)
    Email,
    /// URI
    Uri,
}

impl SanType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SanType::Dns => "dns",
            SanType::Ip => "ip",
            SanType::Email => "email",
            SanType::Uri => "uri",
        }
    }
}

/// Allowed algorithms for a template
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedAlgorithm {
    /// RSA with specified minimum key size
    Rsa { min_bits: u32 },
    /// ECDSA with P-256
    EcdsaP256,
    /// ECDSA with P-384
    EcdsaP384,
    /// Ed25519
    Ed25519,
}

impl AllowedAlgorithm {
    /// Check if a key size is valid for this algorithm
    pub fn is_valid_key_size(&self, bits: u32) -> bool {
        match self {
            AllowedAlgorithm::Rsa { min_bits } => bits >= *min_bits,
            AllowedAlgorithm::EcdsaP256 => bits == 256,
            AllowedAlgorithm::EcdsaP384 => bits == 384,
            AllowedAlgorithm::Ed25519 => bits == 256,
        }
    }
}

/// Validity constraints for certificates
#[derive(Debug, Clone)]
pub struct ValidityConstraints {
    /// Default validity period in days
    pub default_days: u32,
    /// Maximum allowed validity period in days
    pub max_days: u32,
}

impl Default for ValidityConstraints {
    fn default() -> Self {
        Self {
            default_days: 365,
            max_days: 825, // ~27 months, common for TLS
        }
    }
}

/// Key constraints for certificates
#[derive(Debug, Clone)]
pub struct KeyConstraints {
    /// Allowed algorithms
    pub allowed_algorithms: Vec<AllowedAlgorithm>,
    /// Minimum RSA key size in bits
    pub min_rsa_bits: u32,
}

impl Default for KeyConstraints {
    fn default() -> Self {
        Self {
            allowed_algorithms: vec![
                AllowedAlgorithm::Rsa { min_bits: 2048 },
                AllowedAlgorithm::EcdsaP256,
                AllowedAlgorithm::EcdsaP384,
                AllowedAlgorithm::Ed25519,
            ],
            min_rsa_bits: 2048,
        }
    }
}

/// Extension configuration for certificates
#[derive(Debug, Clone)]
pub struct ExtensionConfig {
    /// Key usage flags
    pub key_usage: KeyUsageFlags,
    /// Extended key usage OIDs
    pub extended_key_usage: Option<ExtendedKeyUsage>,
    /// Basic constraints
    pub basic_constraints: BasicConstraints,
    /// Include CRL Distribution Points extension using CA's CDP base URL
    pub include_cdp: bool,
    /// Include Authority Information Access extension using CA's AIA config
    pub include_aia: bool,
    /// Custom CDP URLs (overrides CA's default if provided)
    pub custom_cdp_urls: Option<Vec<String>>,
    /// Custom OCSP responder URL (overrides CA's default if provided)
    pub custom_aia_ocsp: Option<String>,
    /// Custom CA issuer URL (overrides CA's default if provided)
    pub custom_aia_issuer: Option<String>,
}

/// Subject constraints for certificates
#[derive(Debug, Clone)]
pub struct SubjectConstraints {
    /// Require common name in subject
    pub require_cn: bool,
    /// Require organization in subject
    pub require_org: bool,
    /// Allowed SAN types
    pub allowed_san_types: HashSet<SanType>,
}

impl Default for SubjectConstraints {
    fn default() -> Self {
        let mut allowed_san_types = HashSet::new();
        allowed_san_types.insert(SanType::Dns);
        allowed_san_types.insert(SanType::Ip);

        Self {
            require_cn: true,
            require_org: false,
            allowed_san_types,
        }
    }
}

/// Complete template configuration
#[derive(Debug, Clone)]
pub struct TemplateConfig {
    /// Template identifier
    pub name: String,
    /// Human-readable display name
    pub display_name: String,
    /// Template description
    pub description: String,
    /// Validity constraints
    pub validity: ValidityConstraints,
    /// Key constraints
    pub key_constraints: KeyConstraints,
    /// Extension configuration
    pub extensions: ExtensionConfig,
    /// Subject constraints
    pub subject: SubjectConstraints,
    /// Certificate policy OIDs
    pub certificate_policies: Vec<String>,
    /// Whether this is a built-in template
    pub is_builtin: bool,
}

impl TemplateConfig {
    /// Create a new template configuration
    pub fn new(
        name: impl Into<String>,
        display_name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            description: description.into(),
            validity: ValidityConstraints::default(),
            key_constraints: KeyConstraints::default(),
            extensions: ExtensionConfig {
                key_usage: KeyUsageFlags::new(KeyUsageFlags::DIGITAL_SIGNATURE),
                extended_key_usage: None,
                basic_constraints: BasicConstraints::end_entity(),
                include_cdp: true,
                include_aia: true,
                custom_cdp_urls: None,
                custom_aia_ocsp: None,
                custom_aia_issuer: None,
            },
            subject: SubjectConstraints::default(),
            certificate_policies: Vec::new(),
            is_builtin: false,
        }
    }

    /// Set validity constraints
    pub fn with_validity(mut self, default_days: u32, max_days: u32) -> Self {
        self.validity = ValidityConstraints {
            default_days,
            max_days,
        };
        self
    }

    /// Set key usage
    pub fn with_key_usage(mut self, key_usage: KeyUsageFlags) -> Self {
        self.extensions.key_usage = key_usage;
        self
    }

    /// Set extended key usage
    pub fn with_extended_key_usage(mut self, eku: ExtendedKeyUsage) -> Self {
        self.extensions.extended_key_usage = Some(eku);
        self
    }

    /// Set basic constraints
    pub fn with_basic_constraints(mut self, bc: BasicConstraints) -> Self {
        self.extensions.basic_constraints = bc;
        self
    }

    /// Enable or disable CDP extension
    pub fn with_cdp(mut self, include: bool) -> Self {
        self.extensions.include_cdp = include;
        self
    }

    /// Enable or disable AIA extension
    pub fn with_aia(mut self, include: bool) -> Self {
        self.extensions.include_aia = include;
        self
    }

    /// Set custom CDP URLs (overrides CA default)
    pub fn with_custom_cdp_urls(mut self, urls: Vec<String>) -> Self {
        self.extensions.custom_cdp_urls = Some(urls);
        self
    }

    /// Set custom OCSP responder URL (overrides CA default)
    pub fn with_custom_ocsp(mut self, url: impl Into<String>) -> Self {
        self.extensions.custom_aia_ocsp = Some(url.into());
        self
    }

    /// Set custom CA issuer URL (overrides CA default)
    pub fn with_custom_ca_issuer(mut self, url: impl Into<String>) -> Self {
        self.extensions.custom_aia_issuer = Some(url.into());
        self
    }

    /// Set allowed SAN types
    pub fn with_san_types(mut self, types: impl IntoIterator<Item = SanType>) -> Self {
        self.subject.allowed_san_types = types.into_iter().collect();
        self
    }

    /// Mark as built-in
    pub fn as_builtin(mut self) -> Self {
        self.is_builtin = true;
        self
    }

    /// Check if a requested validity period is allowed
    pub fn validate_validity(&self, days: u32) -> Result<u32, String> {
        if days > self.validity.max_days {
            Err(format!(
                "Requested validity {} days exceeds maximum {} days for template '{}'",
                days, self.validity.max_days, self.name
            ))
        } else {
            Ok(days)
        }
    }

    /// Check if a SAN type is allowed
    pub fn is_san_type_allowed(&self, san_type: SanType) -> bool {
        self.subject.allowed_san_types.contains(&san_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::extensions::KeyUsageFlags;

    #[test]
    fn test_template_id_roundtrip() {
        for template in Template::all() {
            let id = template.id();
            let parsed = Template::from_id(id);
            assert_eq!(Some(*template), parsed);
        }
    }

    #[test]
    fn test_template_config_validity() {
        let config = TemplateConfig::new("test", "Test", "Test template").with_validity(365, 730);

        assert!(config.validate_validity(365).is_ok());
        assert!(config.validate_validity(730).is_ok());
        assert!(config.validate_validity(731).is_err());
    }

    #[test]
    fn test_san_type_allowed() {
        let config = TemplateConfig::new("test", "Test", "Test template")
            .with_san_types([SanType::Dns, SanType::Ip]);

        assert!(config.is_san_type_allowed(SanType::Dns));
        assert!(config.is_san_type_allowed(SanType::Ip));
        assert!(!config.is_san_type_allowed(SanType::Email));
    }

    // ── Certificate Profile Verification Tests ──────────────────────────

    #[test]
    fn test_tls_server_cdp_and_aia_included() {
        let config = BuiltinProfiles::tls_server();
        assert!(
            config.extensions.include_cdp,
            "TLS Server should include CDPs"
        );
        assert!(
            config.extensions.include_aia,
            "TLS Server should include AIA"
        );
    }

    #[test]
    fn test_code_signing_no_server_or_client_auth() {
        let config = BuiltinProfiles::code_signing();
        let eku = config.extensions.extended_key_usage.as_ref().unwrap();

        // OIDs for serverAuth and clientAuth
        let server_auth: const_oid::ObjectIdentifier = "1.3.6.1.5.5.7.3.1".parse().unwrap();
        let client_auth: const_oid::ObjectIdentifier = "1.3.6.1.5.5.7.3.2".parse().unwrap();
        let code_signing: const_oid::ObjectIdentifier = "1.3.6.1.5.5.7.3.3".parse().unwrap();

        assert!(
            eku.usages.contains(&code_signing),
            "Code Signing should have codeSigning EKU"
        );
        assert!(
            !eku.usages.contains(&server_auth),
            "Code Signing must NOT have serverAuth EKU"
        );
        assert!(
            !eku.usages.contains(&client_auth),
            "Code Signing must NOT have clientAuth EKU"
        );
    }

    #[test]
    fn test_email_requires_email_san() {
        let config = BuiltinProfiles::email_signing();
        assert!(
            config.is_san_type_allowed(SanType::Email),
            "Email template should allow email SAN type"
        );
    }

    #[test]
    fn test_timestamp_only_timestamp_eku() {
        let config = BuiltinProfiles::timestamp();
        let eku = config.extensions.extended_key_usage.as_ref().unwrap();
        let timestamp: const_oid::ObjectIdentifier = "1.3.6.1.5.5.7.3.8".parse().unwrap();

        assert_eq!(eku.usages.len(), 1, "Timestamp should have exactly one EKU");
        assert!(
            eku.usages.contains(&timestamp),
            "Timestamp EKU should be timeStamping"
        );
    }

    #[test]
    fn test_tls_server_max_validity_398_days() {
        let config = BuiltinProfiles::tls_server();
        assert_eq!(
            config.validity.max_days, 398,
            "TLS Server max validity should be 398 days per CA/B Forum BR"
        );
    }

    #[test]
    fn test_all_profiles_have_min_rsa_2048() {
        for template in Template::all() {
            let config = BuiltinProfiles::get(*template);
            assert!(
                config.key_constraints.min_rsa_bits >= 2048,
                "Template {:?} has min_rsa_bits < 2048: {}",
                template,
                config.key_constraints.min_rsa_bits
            );
        }
    }

    #[test]
    fn test_all_end_entity_templates_not_ca() {
        let ee_templates = [
            Template::TlsServer,
            Template::TlsClient,
            Template::TlsDual,
            Template::CodeSigning,
            Template::EmailSigning,
            Template::OcspSigning,
            Template::Timestamp,
        ];
        for template in ee_templates {
            let config = BuiltinProfiles::get(template);
            assert!(
                !config.extensions.basic_constraints.ca,
                "End-entity template {:?} must not be CA",
                template
            );
        }
    }

    #[test]
    fn test_ca_templates_are_ca() {
        let ca_templates = [Template::RootCa, Template::SubordinateCa];
        for template in ca_templates {
            let config = BuiltinProfiles::get(template);
            assert!(
                config.extensions.basic_constraints.ca,
                "CA template {:?} must be CA",
                template
            );
            assert!(
                config
                    .extensions
                    .key_usage
                    .contains(KeyUsageFlags::KEY_CERT_SIGN),
                "CA template {:?} must have keyCertSign",
                template
            );
            assert!(
                config
                    .extensions
                    .key_usage
                    .contains(KeyUsageFlags::CRL_SIGN),
                "CA template {:?} must have cRLSign",
                template
            );
        }
    }

    #[test]
    fn test_ocsp_signing_has_digital_signature() {
        let config = BuiltinProfiles::ocsp_signing();
        assert!(
            config
                .extensions
                .key_usage
                .contains(KeyUsageFlags::DIGITAL_SIGNATURE),
            "OCSP Signing must have digitalSignature key usage"
        );
    }

    #[test]
    fn test_all_templates_have_unique_names() {
        let mut names = std::collections::HashSet::new();
        for template in Template::all() {
            let config = BuiltinProfiles::get(*template);
            assert!(
                names.insert(config.name.clone()),
                "Duplicate template name: {}",
                config.name
            );
        }
    }
}
