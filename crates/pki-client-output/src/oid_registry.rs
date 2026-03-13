//! OID Registry - maps OIDs to human-readable names.
//!
//! Features:
//! - Built-in names for common OIDs (EKU, policies, extensions)
//! - Custom OID names loaded from TOML file
//! - Hot-reload: automatically reloads when file changes
//!
//! ## TOML Format
//!
//! ```toml
//! # oid-names.toml
//! [eku]
//! "1.3.6.1.4.1.56266.1.3.1" = "Device Attestation"
//!
//! [policy]
//! "1.3.6.1.4.1.56266.1.1.1" = "Internal Systems"
//!
//! [extension]
//! "1.3.6.1.4.1.56266.1.2.1" = "Asset Tag"
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use serde::Deserialize;

/// Global OID registry instance.
static REGISTRY: std::sync::OnceLock<Arc<RwLock<OidRegistry>>> = std::sync::OnceLock::new();

/// OID Registry with built-in and custom names.
#[derive(Debug)]
pub struct OidRegistry {
    /// Custom OID names from TOML file.
    custom: CustomOidNames,
    /// Path to the TOML file (if any).
    toml_path: Option<PathBuf>,
    /// Last modification time of the TOML file.
    last_modified: Option<SystemTime>,
}

/// Custom OID names loaded from TOML.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct CustomOidNames {
    /// Extended Key Usage OIDs.
    #[serde(default)]
    pub eku: HashMap<String, String>,
    /// Certificate Policy OIDs.
    #[serde(default)]
    pub policy: HashMap<String, String>,
    /// X.509 Extension OIDs.
    #[serde(default)]
    pub extension: HashMap<String, String>,
    /// Signature Algorithm OIDs.
    #[serde(default)]
    pub signature: HashMap<String, String>,
    /// Key Algorithm OIDs.
    #[serde(default)]
    pub key: HashMap<String, String>,
}

impl OidRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            custom: CustomOidNames::default(),
            toml_path: None,
            last_modified: None,
        }
    }

    /// Load custom OID names from a TOML file.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read OID names file: {}", e))?;

        let custom: CustomOidNames = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse OID names TOML: {}", e))?;

        let mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());

        Ok(Self {
            custom,
            toml_path: Some(path.to_path_buf()),
            last_modified: mtime,
        })
    }

    /// Check if the TOML file has been modified and reload if needed.
    fn check_reload(&mut self) {
        if let Some(ref path) = self.toml_path {
            let current_mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());

            // Reload if mtime changed
            if current_mtime != self.last_modified {
                if let Ok(content) = std::fs::read_to_string(path) {
                    if let Ok(custom) = toml::from_str(&content) {
                        self.custom = custom;
                        self.last_modified = current_mtime;
                    }
                }
            }
        }
    }

    /// Look up an EKU OID name.
    pub fn eku_name(&self, oid: &str) -> String {
        // Check custom first
        if let Some(name) = self.custom.eku.get(oid) {
            return format!("{} ({})", name, oid);
        }

        // Fall back to built-in
        match oid {
            "1.3.6.1.5.5.7.3.1" => "Server Authentication (1.3.6.1.5.5.7.3.1)".to_string(),
            "1.3.6.1.5.5.7.3.2" => "Client Authentication (1.3.6.1.5.5.7.3.2)".to_string(),
            "1.3.6.1.5.5.7.3.3" => "Code Signing (1.3.6.1.5.5.7.3.3)".to_string(),
            "1.3.6.1.5.5.7.3.4" => "Email Protection (1.3.6.1.5.5.7.3.4)".to_string(),
            "1.3.6.1.5.5.7.3.5" => "IPSec End System (1.3.6.1.5.5.7.3.5)".to_string(),
            "1.3.6.1.5.5.7.3.6" => "IPSec Tunnel (1.3.6.1.5.5.7.3.6)".to_string(),
            "1.3.6.1.5.5.7.3.7" => "IPSec User (1.3.6.1.5.5.7.3.7)".to_string(),
            "1.3.6.1.5.5.7.3.8" => "Time Stamping (1.3.6.1.5.5.7.3.8)".to_string(),
            "1.3.6.1.5.5.7.3.9" => "OCSP Signing (1.3.6.1.5.5.7.3.9)".to_string(),
            "1.3.6.1.5.5.7.3.17" => "iKE Intermediate (1.3.6.1.5.5.7.3.17)".to_string(),
            "1.3.6.1.4.1.311.10.3.3" => "SGC (1.3.6.1.4.1.311.10.3.3)".to_string(),
            "1.3.6.1.4.1.311.10.3.4" => "EFS (1.3.6.1.4.1.311.10.3.4)".to_string(),
            "1.3.6.1.4.1.311.20.2.2" => "Smart Card Logon (1.3.6.1.4.1.311.20.2.2)".to_string(),
            "1.3.6.1.4.1.311.10.3.12" => "Document Signing (1.3.6.1.4.1.311.10.3.12)".to_string(),
            "2.16.840.1.113730.4.1" => "Netscape SGC (2.16.840.1.113730.4.1)".to_string(),
            "1.3.6.1.4.1.311.76.59.1.1" => "Windows Hello (1.3.6.1.4.1.311.76.59.1.1)".to_string(),
            _ => oid.to_string(),
        }
    }

    /// Look up a policy OID name.
    pub fn policy_name(&self, oid: &str) -> String {
        // Check custom first
        if let Some(name) = self.custom.policy.get(oid) {
            return format!("{} ({})", name, oid);
        }

        // Fall back to built-in
        match oid {
            // CA/Browser Forum baseline requirements
            "2.23.140.1.1" => "Extended Validation (2.23.140.1.1)".to_string(),
            "2.23.140.1.2.1" => "Domain Validated (2.23.140.1.2.1)".to_string(),
            "2.23.140.1.2.2" => "Organization Validated (2.23.140.1.2.2)".to_string(),
            "2.23.140.1.2.3" => "Individual Validated (2.23.140.1.2.3)".to_string(),
            "2.5.29.32.0" => "Any Policy (2.5.29.32.0)".to_string(),

            // Let's Encrypt
            "1.3.6.1.4.1.44947.1.1.1" => "Let's Encrypt CP (1.3.6.1.4.1.44947.1.1.1)".to_string(),

            // DigiCert
            "2.16.840.1.114412.1.1" => "DigiCert EV (2.16.840.1.114412.1.1)".to_string(),
            "2.16.840.1.114412.1.2" => "DigiCert OV (2.16.840.1.114412.1.2)".to_string(),
            "2.16.840.1.114412.2.1" => "DigiCert DV (2.16.840.1.114412.2.1)".to_string(),

            // GlobalSign
            "1.3.6.1.4.1.4146.1.1" => "GlobalSign EV (1.3.6.1.4.1.4146.1.1)".to_string(),

            // Comodo/Sectigo
            "1.3.6.1.4.1.6449.1.2.1.5.1" => "Sectigo EV (1.3.6.1.4.1.6449.1.2.1.5.1)".to_string(),

            // GoDaddy
            "2.16.840.1.114413.1.7.23.3" => "GoDaddy EV (2.16.840.1.114413.1.7.23.3)".to_string(),

            // FPKI Common Policy CA (U.S. Federal PKI)
            "2.16.840.1.101.3.2.1.3.6" => {
                "id-fpki-common-policy (2.16.840.1.101.3.2.1.3.6)".to_string()
            }
            "2.16.840.1.101.3.2.1.3.7" => {
                "id-fpki-common-hardware (2.16.840.1.101.3.2.1.3.7)".to_string()
            }
            "2.16.840.1.101.3.2.1.3.8" => {
                "id-fpki-common-devices (2.16.840.1.101.3.2.1.3.8)".to_string()
            }
            "2.16.840.1.101.3.2.1.3.36" => {
                "id-fpki-common-devicesHardware (2.16.840.1.101.3.2.1.3.36)".to_string()
            }
            "2.16.840.1.101.3.2.1.3.13" => {
                "id-fpki-common-authentication (2.16.840.1.101.3.2.1.3.13)".to_string()
            }
            "2.16.840.1.101.3.2.1.3.16" => {
                "id-fpki-common-High (2.16.840.1.101.3.2.1.3.16)".to_string()
            }
            "2.16.840.1.101.3.2.1.3.17" => {
                "id-fpki-common-cardAuth (2.16.840.1.101.3.2.1.3.17)".to_string()
            }
            "2.16.840.1.101.3.2.1.3.39" => {
                "id-fpki-common-piv-contentSigning (2.16.840.1.101.3.2.1.3.39)".to_string()
            }

            // FPKI Bridge / Federal Bridge CA (FBCA) certificate policies
            "2.16.840.1.101.3.2.1.3.12" => {
                "id-fpki-certpolicy-mediumAssurance (2.16.840.1.101.3.2.1.3.12)".to_string()
            }
            "2.16.840.1.101.3.2.1.3.12.2" => {
                "id-fpki-certpolicy-mediumHardware (2.16.840.1.101.3.2.1.3.12.2)".to_string()
            }
            "2.16.840.1.101.3.2.1.3.18" => {
                "id-fpki-certpolicy-pivi-hardware (2.16.840.1.101.3.2.1.3.18)".to_string()
            }
            "2.16.840.1.101.3.2.1.3.19" => {
                "id-fpki-certpolicy-pivi-cardAuth (2.16.840.1.101.3.2.1.3.19)".to_string()
            }
            "2.16.840.1.101.3.2.1.3.20" => {
                "id-fpki-certpolicy-pivi-contentSigning (2.16.840.1.101.3.2.1.3.20)".to_string()
            }

            // Ogjos/PKI-CA policy OIDs (PEN 56266)
            "1.3.6.1.4.1.56266.1.1.0" => "SPORK Evaluation (1.3.6.1.4.1.56266.1.1.0)".to_string(),
            "1.3.6.1.4.1.56266.1.1.1" => {
                "id-ogjos-cp-rudimentary (1.3.6.1.4.1.56266.1.1.1)".to_string()
            }
            "1.3.6.1.4.1.56266.1.1.2" => "id-ogjos-cp-basic (1.3.6.1.4.1.56266.1.1.2)".to_string(),
            "1.3.6.1.4.1.56266.1.1.3" => "id-ogjos-cp-medium (1.3.6.1.4.1.56266.1.1.3)".to_string(),
            "1.3.6.1.4.1.56266.1.1.4" => {
                "id-ogjos-cp-medium-hardware (1.3.6.1.4.1.56266.1.1.4)".to_string()
            }
            "1.3.6.1.4.1.56266.1.1.5" => "id-ogjos-cp-high (1.3.6.1.4.1.56266.1.1.5)".to_string(),

            // Ogjos/PKI Signing Service policy OIDs (PEN 56266)
            "1.3.6.1.4.1.56266.1.1.10" => {
                "id-ogjos-cp-code-signing (1.3.6.1.4.1.56266.1.1.10)".to_string()
            }
            "1.3.6.1.4.1.56266.1.1.11" => {
                "id-ogjos-cp-document-signing (1.3.6.1.4.1.56266.1.1.11)".to_string()
            }
            "1.3.6.1.4.1.56266.1.1.12" => {
                "id-ogjos-cp-timestamping (1.3.6.1.4.1.56266.1.1.12)".to_string()
            }

            _ => oid.to_string(),
        }
    }

    /// Look up an extension OID name.
    pub fn extension_name(&self, oid: &str) -> String {
        // Check custom first
        if let Some(name) = self.custom.extension.get(oid) {
            return format!("{} ({})", name, oid);
        }

        // Fall back to built-in X.509 extensions
        match oid {
            "2.5.29.14" => "Subject Key Identifier".to_string(),
            "2.5.29.15" => "Key Usage".to_string(),
            "2.5.29.17" => "Subject Alternative Name".to_string(),
            "2.5.29.18" => "Issuer Alternative Name".to_string(),
            "2.5.29.19" => "Basic Constraints".to_string(),
            "2.5.29.30" => "Name Constraints".to_string(),
            "2.5.29.31" => "CRL Distribution Points".to_string(),
            "2.5.29.32" => "Certificate Policies".to_string(),
            "2.5.29.33" => "Policy Mappings".to_string(),
            "2.5.29.35" => "Authority Key Identifier".to_string(),
            "2.5.29.36" => "Policy Constraints".to_string(),
            "2.5.29.37" => "Extended Key Usage".to_string(),
            "2.5.29.46" => "Freshest CRL (Delta CRL)".to_string(),
            "2.5.29.54" => "Inhibit Any Policy".to_string(),
            "1.3.6.1.5.5.7.1.1" => "Authority Information Access".to_string(),
            "1.3.6.1.5.5.7.1.11" => "Subject Information Access".to_string(),
            "1.3.6.1.5.5.7.1.24" => "TLS Feature (OCSP Must-Staple)".to_string(),
            "1.3.6.1.4.1.11129.2.4.2" => "CT Precertificate SCTs".to_string(),
            "1.3.6.1.4.1.11129.2.4.3" => "CT Precertificate Poison".to_string(),
            "1.3.6.1.4.1.11129.2.4.5" => "CT Certificate SCTs".to_string(),
            _ => oid.to_string(),
        }
    }

    /// Look up a signature algorithm OID name.
    pub fn signature_name(&self, oid: &str) -> String {
        // Check custom first
        if let Some(name) = self.custom.signature.get(oid) {
            return name.clone();
        }

        // Fall back to built-in
        match oid {
            "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption".to_string(),
            "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption".to_string(),
            "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption".to_string(),
            "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption".to_string(),
            "1.2.840.113549.1.1.10" => "rsassaPss".to_string(),
            "1.2.840.10045.4.1" => "ecdsa-with-SHA1".to_string(),
            "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256".to_string(),
            "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384".to_string(),
            "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512".to_string(),
            "1.3.101.112" => "Ed25519".to_string(),
            "1.3.101.113" => "Ed448".to_string(),
            // ML-DSA (FIPS 204)
            "2.16.840.1.101.3.4.3.17" => "ML-DSA-44".to_string(),
            "2.16.840.1.101.3.4.3.18" => "ML-DSA-65".to_string(),
            "2.16.840.1.101.3.4.3.19" => "ML-DSA-87".to_string(),
            // SLH-DSA (FIPS 205)
            "2.16.840.1.101.3.4.3.20" => "SLH-DSA-SHA2-128s".to_string(),
            "2.16.840.1.101.3.4.3.21" => "SLH-DSA-SHA2-128f".to_string(),
            "2.16.840.1.101.3.4.3.22" => "SLH-DSA-SHA2-192s".to_string(),
            "2.16.840.1.101.3.4.3.23" => "SLH-DSA-SHA2-192f".to_string(),
            "2.16.840.1.101.3.4.3.24" => "SLH-DSA-SHA2-256s".to_string(),
            "2.16.840.1.101.3.4.3.25" => "SLH-DSA-SHA2-256f".to_string(),
            _ => oid.to_string(),
        }
    }
}

impl Default for OidRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global registry functions
// ============================================================================

/// Initialize the global OID registry with an optional TOML file path.
///
/// Call this at startup to enable custom OID names.
/// If the file doesn't exist, only built-in names will be used.
pub fn init_registry(toml_path: Option<&Path>) {
    let registry = if let Some(path) = toml_path {
        if path.exists() {
            OidRegistry::load_from_file(path).unwrap_or_else(|_| OidRegistry::new())
        } else {
            let mut reg = OidRegistry::new();
            reg.toml_path = Some(path.to_path_buf());
            reg
        }
    } else {
        OidRegistry::new()
    };

    let _ = REGISTRY.set(Arc::new(RwLock::new(registry)));
}

/// Get the global registry, initializing with defaults if needed.
fn get_registry() -> Arc<RwLock<OidRegistry>> {
    REGISTRY
        .get_or_init(|| Arc::new(RwLock::new(OidRegistry::new())))
        .clone()
}

/// Look up an EKU OID name (global function).
pub fn eku_name(oid: &str) -> String {
    let registry = get_registry();
    let mut reg = registry.write().unwrap_or_else(|e| e.into_inner());
    reg.check_reload();
    reg.eku_name(oid)
}

/// Look up a policy OID name (global function).
pub fn policy_name(oid: &str) -> String {
    let registry = get_registry();
    let mut reg = registry.write().unwrap_or_else(|e| e.into_inner());
    reg.check_reload();
    reg.policy_name(oid)
}

/// Look up an extension OID name (global function).
pub fn extension_name(oid: &str) -> String {
    let registry = get_registry();
    let mut reg = registry.write().unwrap_or_else(|e| e.into_inner());
    reg.check_reload();
    reg.extension_name(oid)
}

/// Look up a signature algorithm OID name (global function).
pub fn signature_name(oid: &str) -> String {
    let registry = get_registry();
    let mut reg = registry.write().unwrap_or_else(|e| e.into_inner());
    reg.check_reload();
    reg.signature_name(oid)
}

/// Reload the registry from its TOML file (if configured).
pub fn reload_registry() {
    let registry = get_registry();
    let mut reg = registry.write().unwrap_or_else(|e| e.into_inner());
    if let Some(ref path) = reg.toml_path.clone() {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(custom) = toml::from_str(&content) {
                reg.custom = custom;
                reg.last_modified = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_eku_names() {
        let reg = OidRegistry::new();
        assert!(reg
            .eku_name("1.3.6.1.5.5.7.3.1")
            .contains("Server Authentication"));
        assert!(reg
            .eku_name("1.3.6.1.5.5.7.3.2")
            .contains("Client Authentication"));
        assert!(reg.eku_name("1.3.6.1.5.5.7.3.3").contains("Code Signing"));
    }

    #[test]
    fn test_builtin_policy_names() {
        let reg = OidRegistry::new();
        assert!(reg
            .policy_name("2.23.140.1.1")
            .contains("Extended Validation"));
        assert!(reg
            .policy_name("2.23.140.1.2.1")
            .contains("Domain Validated"));
    }

    #[test]
    fn test_unknown_oid() {
        let reg = OidRegistry::new();
        assert_eq!(reg.eku_name("1.2.3.4.5"), "1.2.3.4.5");
    }

    #[test]
    fn test_custom_oid_names() {
        let mut reg = OidRegistry::new();
        reg.custom.eku.insert(
            "1.3.6.1.4.1.56266.1.3.1".to_string(),
            "Device Attestation".to_string(),
        );
        assert!(reg
            .eku_name("1.3.6.1.4.1.56266.1.3.1")
            .contains("Device Attestation"));
    }

    #[test]
    fn test_builtin_extension_names() {
        let reg = OidRegistry::new();
        assert_eq!(reg.extension_name("2.5.29.14"), "Subject Key Identifier");
        assert_eq!(reg.extension_name("2.5.29.15"), "Key Usage");
        assert_eq!(reg.extension_name("2.5.29.17"), "Subject Alternative Name");
        assert_eq!(reg.extension_name("2.5.29.19"), "Basic Constraints");
        assert_eq!(reg.extension_name("2.5.29.31"), "CRL Distribution Points");
        assert_eq!(reg.extension_name("2.5.29.35"), "Authority Key Identifier");
        assert_eq!(reg.extension_name("2.5.29.37"), "Extended Key Usage");
    }

    #[test]
    fn test_builtin_signature_names() {
        let reg = OidRegistry::new();
        assert_eq!(
            reg.signature_name("1.2.840.113549.1.1.11"),
            "sha256WithRSAEncryption"
        );
        assert_eq!(
            reg.signature_name("1.2.840.10045.4.3.2"),
            "ecdsa-with-SHA256"
        );
        assert_eq!(reg.signature_name("2.16.840.1.101.3.4.3.17"), "ML-DSA-44");
        assert_eq!(
            reg.signature_name("2.16.840.1.101.3.4.3.20"),
            "SLH-DSA-SHA2-128s"
        );
        assert_eq!(reg.signature_name("1.3.101.112"), "Ed25519");
    }

    #[test]
    fn test_unknown_policy_oid() {
        let reg = OidRegistry::new();
        assert_eq!(reg.policy_name("9.9.9.9.9"), "9.9.9.9.9");
    }

    #[test]
    fn test_unknown_extension_oid() {
        let reg = OidRegistry::new();
        assert_eq!(reg.extension_name("9.9.9.9.9"), "9.9.9.9.9");
    }

    #[test]
    fn test_unknown_signature_oid() {
        let reg = OidRegistry::new();
        assert_eq!(reg.signature_name("9.9.9.9.9"), "9.9.9.9.9");
    }

    #[test]
    fn test_custom_policy_names() {
        let mut reg = OidRegistry::new();
        reg.custom.policy.insert(
            "1.3.6.1.4.1.56266.99.1".to_string(),
            "Internal Testing".to_string(),
        );
        let name = reg.policy_name("1.3.6.1.4.1.56266.99.1");
        assert!(name.contains("Internal Testing"));
        assert!(name.contains("1.3.6.1.4.1.56266.99.1"));
    }

    #[test]
    fn test_custom_extension_names() {
        let mut reg = OidRegistry::new();
        reg.custom.extension.insert(
            "1.3.6.1.4.1.56266.1.2.99".to_string(),
            "Custom Extension".to_string(),
        );
        let name = reg.extension_name("1.3.6.1.4.1.56266.1.2.99");
        assert!(name.contains("Custom Extension"));
    }

    #[test]
    fn test_custom_signature_names() {
        let mut reg = OidRegistry::new();
        reg.custom
            .signature
            .insert("1.2.3.4.5".to_string(), "CustomSignAlgo".to_string());
        assert_eq!(reg.signature_name("1.2.3.4.5"), "CustomSignAlgo");
    }

    #[test]
    fn test_custom_overrides_builtin() {
        let mut reg = OidRegistry::new();
        // Override the built-in EKU name
        reg.custom.eku.insert(
            "1.3.6.1.5.5.7.3.1".to_string(),
            "Custom TLS Server".to_string(),
        );
        let name = reg.eku_name("1.3.6.1.5.5.7.3.1");
        assert!(name.contains("Custom TLS Server"));
        // Should NOT contain the built-in name
        assert!(!name.contains("Server Authentication"));
    }

    #[test]
    fn test_spork_policy_oids() {
        let reg = OidRegistry::new();
        assert!(reg
            .policy_name("1.3.6.1.4.1.56266.1.1.0")
            .contains("SPORK Evaluation"));
        assert!(reg
            .policy_name("1.3.6.1.4.1.56266.1.1.1")
            .contains("id-ogjos-cp-rudimentary"));
        assert!(reg
            .policy_name("1.3.6.1.4.1.56266.1.1.2")
            .contains("id-ogjos-cp-basic"));
        assert!(reg
            .policy_name("1.3.6.1.4.1.56266.1.1.3")
            .contains("id-ogjos-cp-medium"));
        assert!(reg
            .policy_name("1.3.6.1.4.1.56266.1.1.4")
            .contains("id-ogjos-cp-medium-hardware"));
        assert!(reg
            .policy_name("1.3.6.1.4.1.56266.1.1.5")
            .contains("id-ogjos-cp-high"));
    }

    #[test]
    fn test_fpki_common_policy_oids_in_registry() {
        let reg = OidRegistry::new();
        assert!(reg
            .policy_name("2.16.840.1.101.3.2.1.3.6")
            .contains("id-fpki-common-policy"));
        assert!(reg
            .policy_name("2.16.840.1.101.3.2.1.3.7")
            .contains("id-fpki-common-hardware"));
        assert!(reg
            .policy_name("2.16.840.1.101.3.2.1.3.8")
            .contains("id-fpki-common-devices"));
        assert!(reg
            .policy_name("2.16.840.1.101.3.2.1.3.36")
            .contains("id-fpki-common-devicesHardware"));
        assert!(reg
            .policy_name("2.16.840.1.101.3.2.1.3.13")
            .contains("id-fpki-common-authentication"));
        assert!(reg
            .policy_name("2.16.840.1.101.3.2.1.3.16")
            .contains("id-fpki-common-High"));
        assert!(reg
            .policy_name("2.16.840.1.101.3.2.1.3.17")
            .contains("id-fpki-common-cardAuth"));
        assert!(reg
            .policy_name("2.16.840.1.101.3.2.1.3.39")
            .contains("id-fpki-common-piv-contentSigning"));
    }

    #[test]
    fn test_fpki_certpolicy_oids_in_registry() {
        let reg = OidRegistry::new();
        assert!(reg
            .policy_name("2.16.840.1.101.3.2.1.3.12")
            .contains("id-fpki-certpolicy-mediumAssurance"));
        assert!(reg
            .policy_name("2.16.840.1.101.3.2.1.3.12.2")
            .contains("id-fpki-certpolicy-mediumHardware"));
        assert!(reg
            .policy_name("2.16.840.1.101.3.2.1.3.18")
            .contains("id-fpki-certpolicy-pivi-hardware"));
        assert!(reg
            .policy_name("2.16.840.1.101.3.2.1.3.19")
            .contains("id-fpki-certpolicy-pivi-cardAuth"));
        assert!(reg
            .policy_name("2.16.840.1.101.3.2.1.3.20")
            .contains("id-fpki-certpolicy-pivi-contentSigning"));
    }

    #[test]
    fn test_fpki_policy_oids_include_oid_in_output() {
        let reg = OidRegistry::new();
        // Each named OID should include the OID string in its display output
        let result = reg.policy_name("2.16.840.1.101.3.2.1.3.7");
        assert!(
            result.contains("2.16.840.1.101.3.2.1.3.7"),
            "Registry output should include the raw OID"
        );
    }

    #[test]
    fn test_default_registry() {
        let reg = OidRegistry::default();
        assert!(reg.toml_path.is_none());
        assert!(reg.last_modified.is_none());
        assert!(reg.custom.eku.is_empty());
    }

    #[test]
    fn test_custom_oid_names_toml_parse() {
        let toml_str = r#"
[eku]
"1.2.3.4" = "Test EKU"

[policy]
"1.2.3.5" = "Test Policy"

[extension]
"1.2.3.6" = "Test Extension"

[signature]
"1.2.3.7" = "Test Signature"

[key]
"1.2.3.8" = "Test Key"
"#;
        let custom: CustomOidNames = toml::from_str(toml_str).unwrap();
        assert_eq!(custom.eku.get("1.2.3.4").unwrap(), "Test EKU");
        assert_eq!(custom.policy.get("1.2.3.5").unwrap(), "Test Policy");
        assert_eq!(custom.extension.get("1.2.3.6").unwrap(), "Test Extension");
        assert_eq!(custom.signature.get("1.2.3.7").unwrap(), "Test Signature");
        assert_eq!(custom.key.get("1.2.3.8").unwrap(), "Test Key");
    }
}
