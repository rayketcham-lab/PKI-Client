//! Hierarchy TOML configuration schema

use serde::Deserialize;

/// Top-level hierarchy configuration
#[derive(Debug, Clone, Deserialize)]
pub struct HierarchyConfig {
    /// Hierarchy metadata
    pub hierarchy: HierarchyMeta,
    /// CA entries (ordered list)
    #[serde(default)]
    pub ca: Vec<CaEntry>,
}

/// Hierarchy metadata
#[derive(Debug, Clone, Deserialize)]
pub struct HierarchyMeta {
    /// Hierarchy name (used in output directory naming)
    pub name: String,
    /// Base output directory for generated files
    #[serde(default = "default_output_dir")]
    pub output_dir: String,
    /// Distribution URL configuration
    pub distribution: Option<DistributionConfig>,
    /// Default DN fields applied to all CAs
    pub defaults: Option<DefaultsConfig>,
}

/// Distribution URLs for CDP/AIA auto-generation
#[derive(Debug, Clone, Deserialize)]
pub struct DistributionConfig {
    /// Base URL for CRL and cert distribution
    pub base_url: String,
    /// OCSP responder URL
    pub ocsp_url: Option<String>,
}

/// Default DN fields inherited by all CAs
#[derive(Debug, Clone, Deserialize)]
pub struct DefaultsConfig {
    pub country: Option<String>,
    pub state: Option<String>,
    pub organization: Option<String>,
    /// Domain components for LDAP-style DNs (e.g., ["com", "quantumnexum"])
    /// Ordered TLD-first: DC=com, DC=quantumnexum
    #[serde(default)]
    pub domain_components: Vec<String>,
    /// Convenience: domain name auto-split into DCs (e.g., "quantumnexum.com")
    pub domain: Option<String>,
}

/// Individual CA entry in the hierarchy
#[derive(Debug, Clone, Deserialize)]
pub struct CaEntry {
    /// Unique identifier for this CA (used as parent reference)
    pub id: String,
    /// CA type: "root" or "intermediate"
    #[serde(rename = "type")]
    pub ca_type: String,
    /// Parent CA id (required for intermediate CAs)
    pub parent: Option<String>,
    /// Cryptographic algorithm
    pub algorithm: String,
    /// Common Name for the CA certificate
    pub common_name: String,
    /// Organizational Unit (optional)
    pub ou: Option<String>,
    /// Validity period in years
    pub validity_years: u32,
    /// Path length constraint (None = unlimited)
    pub path_length: Option<u8>,
    /// CRL Distribution Point configuration
    pub cdp: Option<CdpConfig>,
    /// Authority Information Access configuration
    pub aia: Option<AiaConfig>,
    /// Certificate policy OIDs
    pub policies: Option<Vec<String>>,
    /// Extended Key Usage OIDs
    pub eku: Option<Vec<String>>,
}

/// CRL Distribution Point configuration
#[derive(Debug, Clone, Deserialize)]
pub struct CdpConfig {
    /// CRL distribution URLs
    pub urls: Vec<String>,
}

/// Authority Information Access configuration
#[derive(Debug, Clone, Deserialize)]
pub struct AiaConfig {
    /// OCSP responder URLs
    #[serde(default)]
    pub ocsp_urls: Vec<String>,
    /// CA issuer certificate URLs
    #[serde(default)]
    pub ca_issuer_urls: Vec<String>,
}

fn default_output_dir() -> String {
    "./pki-output".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_hierarchy() {
        let toml = r#"
[hierarchy]
name = "test-pki"
output_dir = "./test-output"

[hierarchy.defaults]
country = "US"
organization = "Test Org"

[[ca]]
id = "root"
type = "root"
algorithm = "ecdsa-p256"
common_name = "Test Root CA"
validity_years = 20

[[ca]]
id = "issuing"
type = "intermediate"
parent = "root"
algorithm = "ecdsa-p256"
common_name = "Test Issuing CA"
validity_years = 10
path_length = 0

[ca.cdp]
urls = ["http://crl.example.com/issuing.crl"]

[ca.aia]
ocsp_urls = ["http://ocsp.example.com"]
ca_issuer_urls = ["http://ca.example.com/root.cer"]
"#;
        let config: HierarchyConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.hierarchy.name, "test-pki");
        assert_eq!(config.ca.len(), 2);
        assert_eq!(config.ca[0].ca_type, "root");
        assert_eq!(config.ca[1].parent.as_deref(), Some("root"));
        assert!(config.ca[1].cdp.is_some());
        assert!(config.ca[1].aia.is_some());
    }

    #[test]
    fn test_parse_with_distribution() {
        let toml = r#"
[hierarchy]
name = "dist-test"

[hierarchy.distribution]
base_url = "https://example.com/pki"
ocsp_url = "https://ocsp.example.com"

[[ca]]
id = "root"
type = "root"
algorithm = "ecdsa-p256"
common_name = "Root"
validity_years = 20
"#;
        let config: HierarchyConfig = toml::from_str(toml).unwrap();
        let dist = config.hierarchy.distribution.unwrap();
        assert_eq!(dist.base_url, "https://example.com/pki");
        assert_eq!(dist.ocsp_url.as_deref(), Some("https://ocsp.example.com"));
    }

    #[test]
    fn test_default_output_dir() {
        let toml = r#"
[hierarchy]
name = "minimal"

[[ca]]
id = "root"
type = "root"
algorithm = "ecdsa-p256"
common_name = "Root"
validity_years = 10
"#;
        let config: HierarchyConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.hierarchy.output_dir, "./pki-output");
    }

    #[test]
    fn test_parse_domain_components() {
        let toml = r#"
[hierarchy]
name = "dc-test"

[hierarchy.defaults]
domain_components = ["com", "quantumnexum"]
"#;
        let config: HierarchyConfig = toml::from_str(toml).unwrap();
        let defaults = config.hierarchy.defaults.unwrap();
        assert_eq!(defaults.domain_components, vec!["com", "quantumnexum"]);
    }

    #[test]
    fn test_parse_domain_shorthand() {
        let toml = r#"
[hierarchy]
name = "domain-test"

[hierarchy.defaults]
domain = "quantumnexum.com"
"#;
        let config: HierarchyConfig = toml::from_str(toml).unwrap();
        let defaults = config.hierarchy.defaults.unwrap();
        assert_eq!(defaults.domain.as_deref(), Some("quantumnexum.com"));
    }

    #[test]
    fn test_parse_ca_with_policies_and_eku() {
        let toml = r#"
[hierarchy]
name = "policy-test"

[[ca]]
id = "root"
type = "root"
algorithm = "ecdsa-p384"
common_name = "Root CA"
validity_years = 25
path_length = 2
policies = ["2.23.140.1.1", "1.3.6.1.4.1.56266.1.1.0"]
eku = ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"]
"#;
        let config: HierarchyConfig = toml::from_str(toml).unwrap();
        let ca = &config.ca[0];
        assert_eq!(ca.algorithm, "ecdsa-p384");
        assert_eq!(ca.path_length, Some(2));
        let policies = ca.policies.as_ref().unwrap();
        assert_eq!(policies.len(), 2);
        let ekus = ca.eku.as_ref().unwrap();
        assert_eq!(ekus.len(), 2);
    }

    #[test]
    fn test_parse_ca_with_ou() {
        let toml = r#"
[hierarchy]
name = "ou-test"

[[ca]]
id = "issuing"
type = "intermediate"
parent = "root"
algorithm = "ecdsa-p256"
common_name = "Issuing CA"
ou = "PKI Operations"
validity_years = 10
"#;
        let config: HierarchyConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.ca[0].ou.as_deref(), Some("PKI Operations"));
    }

    #[test]
    fn test_parse_empty_ca_list() {
        let toml = r#"
[hierarchy]
name = "empty"
"#;
        let config: HierarchyConfig = toml::from_str(toml).unwrap();
        assert!(config.ca.is_empty());
    }

    #[test]
    fn test_parse_no_defaults() {
        let toml = r#"
[hierarchy]
name = "no-defaults"

[[ca]]
id = "root"
type = "root"
algorithm = "ecdsa-p256"
common_name = "Root"
validity_years = 10
"#;
        let config: HierarchyConfig = toml::from_str(toml).unwrap();
        assert!(config.hierarchy.defaults.is_none());
        assert!(config.hierarchy.distribution.is_none());
    }

    #[test]
    fn test_ca_optional_fields_absent() {
        let toml = r#"
[hierarchy]
name = "minimal-ca"

[[ca]]
id = "root"
type = "root"
algorithm = "rsa-4096"
common_name = "Minimal Root"
validity_years = 20
"#;
        let config: HierarchyConfig = toml::from_str(toml).unwrap();
        let ca = &config.ca[0];
        assert!(ca.parent.is_none());
        assert!(ca.ou.is_none());
        assert!(ca.path_length.is_none());
        assert!(ca.cdp.is_none());
        assert!(ca.aia.is_none());
        assert!(ca.policies.is_none());
        assert!(ca.eku.is_none());
    }
}
