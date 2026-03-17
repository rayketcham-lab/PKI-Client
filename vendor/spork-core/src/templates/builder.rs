//! Template Builder
//!
//! This module provides a builder that applies template configurations
//! to certificate issuance requests.

use crate::cert::extensions::{BasicConstraints, ExtendedKeyUsage, KeyUsageFlags};
use crate::error::Error;

use super::{SanType, Template, TemplateConfig};

/// A validated certificate request after template application
#[derive(Debug, Clone)]
pub struct ValidatedRequest {
    /// The template used
    pub template: TemplateConfig,
    /// Validated validity period in days
    pub validity_days: u32,
    /// Key usage flags to apply
    pub key_usage: KeyUsageFlags,
    /// Extended key usage (if any)
    pub extended_key_usage: Option<ExtendedKeyUsage>,
    /// Basic constraints
    pub basic_constraints: BasicConstraints,
    /// Validated DNS SANs
    pub san_dns: Vec<String>,
    /// Validated IP SANs
    pub san_ip: Vec<String>,
    /// Validated Email SANs
    pub san_email: Vec<String>,
    /// Common name
    pub common_name: String,
    /// Organization (if provided)
    pub organization: Option<String>,
}

/// Builder for applying template constraints to certificate requests
pub struct TemplateBuilder {
    config: TemplateConfig,
    validity_days: Option<u32>,
    common_name: Option<String>,
    organization: Option<String>,
    san_dns: Vec<String>,
    san_ip: Vec<String>,
    san_email: Vec<String>,
    override_key_usage: Option<KeyUsageFlags>,
    override_eku: Option<ExtendedKeyUsage>,
}

impl TemplateBuilder {
    /// Create a new builder from a template type
    pub fn new(template: Template) -> Self {
        Self::from_config(template.default_config())
    }

    /// Create a new builder from a template configuration
    pub fn from_config(config: TemplateConfig) -> Self {
        Self {
            config,
            validity_days: None,
            common_name: None,
            organization: None,
            san_dns: Vec::new(),
            san_ip: Vec::new(),
            san_email: Vec::new(),
            override_key_usage: None,
            override_eku: None,
        }
    }

    /// Set the validity period in days
    pub fn validity_days(mut self, days: u32) -> Self {
        self.validity_days = Some(days);
        self
    }

    /// Set the common name
    pub fn common_name(mut self, cn: impl Into<String>) -> Self {
        self.common_name = Some(cn.into());
        self
    }

    /// Set the organization
    pub fn organization(mut self, org: impl Into<String>) -> Self {
        self.organization = Some(org.into());
        self
    }

    /// Add a DNS SAN
    pub fn add_dns_san(mut self, dns: impl Into<String>) -> Self {
        self.san_dns.push(dns.into());
        self
    }

    /// Add multiple DNS SANs
    pub fn add_dns_sans(mut self, dns_names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.san_dns.extend(dns_names.into_iter().map(|s| s.into()));
        self
    }

    /// Add an IP SAN
    pub fn add_ip_san(mut self, ip: impl Into<String>) -> Self {
        self.san_ip.push(ip.into());
        self
    }

    /// Add multiple IP SANs
    pub fn add_ip_sans(mut self, ips: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.san_ip.extend(ips.into_iter().map(|s| s.into()));
        self
    }

    /// Add an email SAN
    pub fn add_email_san(mut self, email: impl Into<String>) -> Self {
        self.san_email.push(email.into());
        self
    }

    /// Override the key usage (use with caution)
    ///
    /// This allows overriding the template's default key usage.
    /// The override must be a subset of what the template allows.
    pub fn override_key_usage(mut self, key_usage: KeyUsageFlags) -> Self {
        self.override_key_usage = Some(key_usage);
        self
    }

    /// Override the extended key usage (use with caution)
    pub fn override_extended_key_usage(mut self, eku: ExtendedKeyUsage) -> Self {
        self.override_eku = Some(eku);
        self
    }

    /// Validate and build the request
    pub fn build(self) -> Result<ValidatedRequest, Error> {
        // Validate common name
        let common_name = match self.common_name {
            Some(cn) if !cn.is_empty() => cn,
            _ if self.config.subject.require_cn => {
                return Err(Error::PolicyViolation(
                    "Common name is required for this template".to_string(),
                ));
            }
            _ => String::new(),
        };

        // Validate organization
        let organization = match self.organization {
            Some(org) if !org.is_empty() => Some(org),
            _ if self.config.subject.require_org => {
                return Err(Error::PolicyViolation(
                    "Organization is required for this template".to_string(),
                ));
            }
            _ => None,
        };

        // Validate validity
        let validity_days = self
            .validity_days
            .unwrap_or(self.config.validity.default_days);
        if validity_days > self.config.validity.max_days {
            return Err(Error::PolicyViolation(format!(
                "Validity period {} days exceeds maximum {} days for template '{}'",
                validity_days, self.config.validity.max_days, self.config.name
            )));
        }

        // Validate DNS SANs
        if !self.san_dns.is_empty() && !self.config.is_san_type_allowed(SanType::Dns) {
            return Err(Error::PolicyViolation(format!(
                "DNS SANs are not allowed for template '{}'",
                self.config.name
            )));
        }

        // Validate IP SANs
        if !self.san_ip.is_empty() && !self.config.is_san_type_allowed(SanType::Ip) {
            return Err(Error::PolicyViolation(format!(
                "IP SANs are not allowed for template '{}'",
                self.config.name
            )));
        }

        // Validate email SANs
        if !self.san_email.is_empty() && !self.config.is_san_type_allowed(SanType::Email) {
            return Err(Error::PolicyViolation(format!(
                "Email SANs are not allowed for template '{}'",
                self.config.name
            )));
        }

        // Validate DNS SAN format
        for dns in &self.san_dns {
            if !Self::is_valid_dns_name(dns) {
                return Err(Error::PolicyViolation(format!("Invalid DNS name: {}", dns)));
            }
        }

        // Validate IP SAN format
        for ip in &self.san_ip {
            if !Self::is_valid_ip(ip) {
                return Err(Error::PolicyViolation(format!(
                    "Invalid IP address: {}",
                    ip
                )));
            }
        }

        // Validate email SAN format
        for email in &self.san_email {
            if !Self::is_valid_email(email) {
                return Err(Error::PolicyViolation(format!(
                    "Invalid email address: {}",
                    email
                )));
            }
        }

        // Determine key usage
        let key_usage = self
            .override_key_usage
            .unwrap_or(self.config.extensions.key_usage);

        // Determine EKU
        let extended_key_usage = self
            .override_eku
            .or_else(|| self.config.extensions.extended_key_usage.clone());

        Ok(ValidatedRequest {
            template: self.config.clone(),
            validity_days,
            key_usage,
            extended_key_usage,
            basic_constraints: self.config.extensions.basic_constraints.clone(),
            san_dns: self.san_dns,
            san_ip: self.san_ip,
            san_email: self.san_email,
            common_name,
            organization,
        })
    }

    /// Basic DNS name validation
    fn is_valid_dns_name(name: &str) -> bool {
        if name.is_empty() || name.len() > 253 {
            return false;
        }

        // Allow wildcard prefix
        let name = name.strip_prefix("*.").unwrap_or(name);

        // Check each label
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return false;
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return false;
            }
            if label.starts_with('-') || label.ends_with('-') {
                return false;
            }
        }

        true
    }

    /// Basic IP address validation
    fn is_valid_ip(ip: &str) -> bool {
        ip.parse::<std::net::IpAddr>().is_ok()
    }

    /// Basic email validation
    fn is_valid_email(email: &str) -> bool {
        // Simple check: contains @ and has content on both sides
        let parts: Vec<&str> = email.split('@').collect();
        parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() && parts[1].contains('.')
    }
}

/// Registry for managing templates (built-in and custom)
pub struct TemplateRegistry {
    templates: std::collections::HashMap<String, TemplateConfig>,
}

impl TemplateRegistry {
    /// Create a new registry with built-in templates
    pub fn new() -> Self {
        let mut templates = std::collections::HashMap::new();

        // Add all built-in templates
        for template in Template::all() {
            let config = template.default_config();
            templates.insert(config.name.clone(), config);
        }

        Self { templates }
    }

    /// Get a template by name
    pub fn get(&self, name: &str) -> Option<&TemplateConfig> {
        self.templates.get(name)
    }

    /// Add a custom template
    pub fn add_custom(&mut self, config: TemplateConfig) -> Result<(), Error> {
        if config.is_builtin {
            return Err(Error::PolicyViolation(
                "Cannot add a template marked as built-in".to_string(),
            ));
        }
        if self.templates.contains_key(&config.name) {
            return Err(Error::PolicyViolation(format!(
                "Template '{}' already exists",
                config.name
            )));
        }
        self.templates.insert(config.name.clone(), config);
        Ok(())
    }

    /// Remove a custom template
    pub fn remove_custom(&mut self, name: &str) -> Result<TemplateConfig, Error> {
        let config = self
            .templates
            .get(name)
            .ok_or_else(|| Error::PolicyViolation(format!("Template '{}' not found", name)))?;

        if config.is_builtin {
            return Err(Error::PolicyViolation(
                "Cannot remove built-in template".to_string(),
            ));
        }

        self.templates
            .remove(name)
            .ok_or_else(|| Error::PolicyViolation(format!("Template '{}' not found", name)))
    }

    /// List all templates
    pub fn list(&self) -> Vec<&TemplateConfig> {
        self.templates.values().collect()
    }

    /// List only built-in templates
    pub fn list_builtin(&self) -> Vec<&TemplateConfig> {
        self.templates.values().filter(|t| t.is_builtin).collect()
    }

    /// List only custom templates
    pub fn list_custom(&self) -> Vec<&TemplateConfig> {
        self.templates.values().filter(|t| !t.is_builtin).collect()
    }
}

impl Default for TemplateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_basic() {
        let request = TemplateBuilder::new(Template::TlsServer)
            .common_name("example.com")
            .add_dns_san("example.com")
            .add_dns_san("www.example.com")
            .validity_days(365)
            .build()
            .unwrap();

        assert_eq!(request.common_name, "example.com");
        assert_eq!(request.san_dns.len(), 2);
        assert_eq!(request.validity_days, 365);
    }

    #[test]
    fn test_builder_missing_cn() {
        let result = TemplateBuilder::new(Template::TlsServer).build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_validity_exceeds_max() {
        let result = TemplateBuilder::new(Template::TlsServer)
            .common_name("example.com")
            .validity_days(1000) // Exceeds 398 max
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_disallowed_san_type() {
        // Subordinate CA doesn't allow any SANs
        let result = TemplateBuilder::new(Template::SubordinateCa)
            .common_name("My CA")
            .organization("My Org")
            .add_dns_san("ca.example.com")
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_dns_validation() {
        assert!(TemplateBuilder::is_valid_dns_name("example.com"));
        assert!(TemplateBuilder::is_valid_dns_name("sub.example.com"));
        assert!(TemplateBuilder::is_valid_dns_name("*.example.com"));
        assert!(!TemplateBuilder::is_valid_dns_name(""));
        assert!(!TemplateBuilder::is_valid_dns_name("-example.com"));
    }

    #[test]
    fn test_ip_validation() {
        assert!(TemplateBuilder::is_valid_ip("192.168.1.1"));
        assert!(TemplateBuilder::is_valid_ip("::1"));
        assert!(!TemplateBuilder::is_valid_ip("not-an-ip"));
    }

    #[test]
    fn test_registry() {
        let registry = TemplateRegistry::new();
        assert!(registry.get("tls-server").is_some());
        assert!(registry.get("root-ca").is_some());
        assert!(registry.get("nonexistent").is_none());
        assert_eq!(registry.list_builtin().len(), 10);
    }

    #[test]
    fn test_registry_custom_template() {
        let mut registry = TemplateRegistry::new();

        let custom = TemplateConfig::new("my-template", "My Template", "Custom template");

        registry.add_custom(custom).unwrap();
        assert!(registry.get("my-template").is_some());
        assert_eq!(registry.list_custom().len(), 1);
    }

    // ── Issue #34: TemplateRegistry custom template registration ─────────

    #[test]
    fn test_registry_custom_template_with_constraints() {
        let mut registry = TemplateRegistry::new();

        let custom = TemplateConfig::new(
            "iot-device",
            "IoT Device",
            "Short-lived certificate for IoT devices",
        )
        .with_validity(30, 90)
        .with_key_usage(KeyUsageFlags::new(KeyUsageFlags::DIGITAL_SIGNATURE))
        .with_san_types([super::SanType::Dns, super::SanType::Ip]);

        registry.add_custom(custom).unwrap();

        let retrieved = registry.get("iot-device").unwrap();
        assert_eq!(retrieved.name, "iot-device");
        assert_eq!(retrieved.display_name, "IoT Device");
        assert_eq!(retrieved.validity.default_days, 30);
        assert_eq!(retrieved.validity.max_days, 90);
        assert!(!retrieved.is_builtin);
    }

    #[test]
    fn test_registry_cannot_add_duplicate() {
        let mut registry = TemplateRegistry::new();

        let custom1 = TemplateConfig::new("custom-a", "Custom A", "First custom");
        let custom2 = TemplateConfig::new("custom-a", "Custom A Dup", "Duplicate name");

        registry.add_custom(custom1).unwrap();
        let result = registry.add_custom(custom2);
        assert!(
            result.is_err(),
            "Adding duplicate template name should fail"
        );
    }

    #[test]
    fn test_registry_cannot_add_builtin_marked_template() {
        let mut registry = TemplateRegistry::new();

        let fake_builtin =
            TemplateConfig::new("fake-builtin", "Fake", "Pretending to be builtin").as_builtin();

        let result = registry.add_custom(fake_builtin);
        assert!(
            result.is_err(),
            "Cannot add a template marked as built-in via add_custom"
        );
    }

    #[test]
    fn test_registry_cannot_overwrite_builtin() {
        let mut registry = TemplateRegistry::new();

        // Try to add a custom template with the same name as a built-in
        let overwrite = TemplateConfig::new("tls-server", "Fake TLS", "Overwrite attempt");
        let result = registry.add_custom(overwrite);
        assert!(
            result.is_err(),
            "Cannot overwrite built-in template with custom"
        );
    }

    #[test]
    fn test_registry_remove_custom_template() {
        let mut registry = TemplateRegistry::new();

        let custom = TemplateConfig::new("removable", "Removable", "Can be removed");
        registry.add_custom(custom).unwrap();
        assert!(registry.get("removable").is_some());

        let removed = registry.remove_custom("removable").unwrap();
        assert_eq!(removed.name, "removable");
        assert!(
            registry.get("removable").is_none(),
            "Removed template should no longer be found"
        );
    }

    #[test]
    fn test_registry_cannot_remove_builtin() {
        let mut registry = TemplateRegistry::new();

        let result = registry.remove_custom("tls-server");
        assert!(result.is_err(), "Cannot remove built-in template");

        // Verify it is still there
        assert!(registry.get("tls-server").is_some());
    }

    #[test]
    fn test_registry_remove_nonexistent() {
        let mut registry = TemplateRegistry::new();

        let result = registry.remove_custom("ghost-template");
        assert!(result.is_err(), "Removing nonexistent template should fail");
    }

    #[test]
    fn test_registry_list_builtin_vs_custom() {
        let mut registry = TemplateRegistry::new();

        let builtin_count = registry.list_builtin().len();
        assert_eq!(builtin_count, 10, "Should have 10 built-in templates");
        assert_eq!(
            registry.list_custom().len(),
            0,
            "Should have 0 custom templates initially"
        );

        // Add custom templates
        registry
            .add_custom(TemplateConfig::new("custom-1", "Custom 1", "First"))
            .unwrap();
        registry
            .add_custom(TemplateConfig::new("custom-2", "Custom 2", "Second"))
            .unwrap();

        assert_eq!(
            registry.list_builtin().len(),
            10,
            "Built-in count should not change"
        );
        assert_eq!(
            registry.list_custom().len(),
            2,
            "Should have 2 custom templates"
        );
        assert_eq!(
            registry.list().len(),
            12,
            "Total should be 10 builtin + 2 custom"
        );
    }

    #[test]
    fn test_registry_custom_template_validity_enforcement() {
        let mut registry = TemplateRegistry::new();

        let custom = TemplateConfig::new("custom-short", "Custom Short", "Very short validity")
            .with_validity(7, 30);
        registry.add_custom(custom).unwrap();

        let config = registry.get("custom-short").unwrap();

        // Within limits should succeed
        assert!(config.validate_validity(7).is_ok());
        assert!(config.validate_validity(30).is_ok());

        // Exceeding max should fail
        assert!(config.validate_validity(31).is_err());
    }

    #[test]
    fn test_custom_template_with_custom_cdp_and_aia() {
        let mut registry = TemplateRegistry::new();

        let custom = TemplateConfig::new("custom-pki", "Custom PKI", "Template with custom URLs")
            .with_custom_cdp_urls(vec!["http://crl.example.com/ca.crl".to_string()])
            .with_custom_ocsp("http://ocsp.example.com")
            .with_custom_ca_issuer("http://ca.example.com/ca.crt");

        registry.add_custom(custom).unwrap();

        let config = registry.get("custom-pki").unwrap();
        assert!(config.extensions.custom_cdp_urls.is_some());
        assert_eq!(config.extensions.custom_cdp_urls.as_ref().unwrap().len(), 1);
        assert_eq!(
            config.extensions.custom_aia_ocsp.as_ref().unwrap(),
            "http://ocsp.example.com"
        );
        assert_eq!(
            config.extensions.custom_aia_issuer.as_ref().unwrap(),
            "http://ca.example.com/ca.crt"
        );
    }
}
