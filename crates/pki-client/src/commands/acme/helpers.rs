//! Shared helper functions for ACME commands.

use crate::acme::AcmeClient;
use anyhow::{anyhow, Result};
use std::fs;
use std::path::PathBuf;

pub(super) fn create_client(
    staging: bool,
    directory: Option<String>,
    insecure: bool,
    ca_cert: Option<&std::path::Path>,
) -> AcmeClient {
    match directory {
        Some(url) => AcmeClient::with_options(url, insecure, ca_cert),
        None if staging => AcmeClient::letsencrypt_staging(),
        None => AcmeClient::letsencrypt(),
    }
}

/// Validate an email address per RFC 5321 rules.
/// Returns Ok(()) if valid, Err with description if not.
pub(super) fn validate_email(email: &str) -> Result<()> {
    // Total length: RFC 5321 §4.5.3.1.3 — max 320 octets for <addr-spec>
    if email.len() > 320 {
        return Err(anyhow!("Email address exceeds 320 character limit"));
    }

    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Email address must contain exactly one '@'"));
    }
    let (local, domain) = (parts[0], parts[1]);

    // Local-part: RFC 5321 §4.5.3.1.1 — max 64 octets
    if local.is_empty() {
        return Err(anyhow!("Email local-part (before @) cannot be empty"));
    }
    if local.len() > 64 {
        return Err(anyhow!("Email local-part exceeds 64 character limit"));
    }
    if local.starts_with('.') || local.ends_with('.') {
        return Err(anyhow!("Email local-part cannot start or end with a dot"));
    }
    if local.contains("..") {
        return Err(anyhow!("Email local-part cannot contain consecutive dots"));
    }

    // Domain: RFC 5321 §4.5.3.1.2 — max 255 octets, must have TLD
    if domain.is_empty() {
        return Err(anyhow!("Email domain (after @) cannot be empty"));
    }
    if domain.len() > 255 {
        return Err(anyhow!("Email domain exceeds 255 character limit"));
    }
    if !domain.contains('.') {
        return Err(anyhow!(
            "Email domain must contain a dot (bare hostnames not allowed)"
        ));
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return Err(anyhow!("Email domain cannot start or end with a dot"));
    }
    if domain.starts_with('-') || domain.ends_with('-') {
        return Err(anyhow!("Email domain cannot start or end with a hyphen"));
    }

    // Domain labels: each label 1-63 chars, alphanumeric + hyphens
    for label in domain.split('.') {
        if label.is_empty() {
            return Err(anyhow!(
                "Email domain contains empty label (consecutive dots)"
            ));
        }
        if label.len() > 63 {
            return Err(anyhow!(
                "Email domain label '{}' exceeds 63 character limit",
                label
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(anyhow!(
                "Email domain label '{}' cannot start or end with a hyphen",
                label
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(anyhow!(
                "Email domain label '{}' contains invalid characters",
                label
            ));
        }
    }

    Ok(())
}

/// Get the default pki-client cert storage directory.
pub(super) fn pki_certs_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Cannot determine home directory"))?;
    Ok(home.join(".pki-client").join("certs"))
}

/// Get the default account key path.
pub(super) fn default_account_key_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Cannot determine home directory"))?;
    let dir = home.join(".pki-client");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("account.key"))
}

/// Generate a P-256 private key in PEM format (SEC1 DER encoding for CSR).
pub(super) fn generate_domain_key() -> Result<String> {
    use p256::pkcs8::EncodePrivateKey;
    use p256::SecretKey;
    use rand_core::OsRng;

    let secret_key = SecretKey::random(&mut OsRng);
    // Use PKCS#8 format for OpenSSL 3.x compatibility (SEC1 deprecated)
    let pkcs8_doc = secret_key
        .to_pkcs8_der()
        .context("Failed to encode private key as PKCS#8")?;
    let pem_obj = pem::Pem::new("PRIVATE KEY", pkcs8_doc.as_bytes().to_vec());
    Ok(pem::encode(&pem_obj))
}

use anyhow::Context;

/// Renewal configuration persisted per domain for automated renewals.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub(super) struct RenewalConfig {
    /// ACME server directory URL
    pub server: String,
    /// Contact email (optional)
    pub email: Option<String>,
    /// Challenge method: "http", "dns", or "standalone"
    pub challenge_method: String,
    /// Webroot path for HTTP-01 challenges
    pub webroot: Option<PathBuf>,
    /// All domains in the certificate
    pub domains: Vec<String>,
    /// Skip TLS verification
    pub insecure: bool,
    /// Custom CA certificate path
    pub ca_cert: Option<PathBuf>,
    /// Timestamp of last successful issuance
    pub last_renewed: Option<String>,
}

impl RenewalConfig {
    /// Create a new renewal config from certonly parameters.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        server: &str,
        email: Option<&str>,
        webroot: Option<&std::path::Path>,
        standalone: bool,
        dns: bool,
        domains: &[String],
        insecure: bool,
        ca_cert: Option<&std::path::Path>,
    ) -> Self {
        let challenge_method = if dns {
            "dns".to_string()
        } else if standalone {
            "standalone".to_string()
        } else if webroot.is_some() {
            "http".to_string()
        } else {
            "manual".to_string()
        };
        Self {
            server: server.to_string(),
            email: email.map(String::from),
            challenge_method,
            webroot: webroot.map(|p| p.to_path_buf()),
            domains: domains.to_vec(),
            insecure,
            ca_cert: ca_cert.map(|p| p.to_path_buf()),
            last_renewed: None,
        }
    }

    /// Save renewal config to the cert directory.
    pub fn save(&self, cert_dir: &std::path::Path) -> Result<()> {
        let path = cert_dir.join("renewal.json");
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        Ok(())
    }

    /// Load renewal config from a cert directory.
    pub fn load(cert_dir: &std::path::Path) -> Result<Self> {
        let path = cert_dir.join("renewal.json");
        let data = fs::read_to_string(&path)
            .with_context(|| format!("No renewal config at {}", path.display()))?;
        let config: Self = serde_json::from_str(&data)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email_valid() {
        assert!(validate_email("admin@example.com").is_ok());
        assert!(validate_email("user.name@sub.domain.org").is_ok());
        assert!(validate_email("a@b.co").is_ok());
        assert!(validate_email("user+tag@example.com").is_ok());
        assert!(validate_email("test123@mail-server.example.com").is_ok());
    }

    #[test]
    fn test_validate_email_missing_at() {
        assert!(validate_email("noatsign").is_err());
        assert!(validate_email("").is_err());
    }

    #[test]
    fn test_validate_email_empty_parts() {
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
    }

    #[test]
    fn test_validate_email_no_tld() {
        assert!(validate_email("user@localhost").is_err());
        assert!(validate_email("user@hostname").is_err());
    }

    #[test]
    fn test_validate_email_consecutive_dots() {
        assert!(validate_email("user..name@example.com").is_err());
        assert!(validate_email("user@example..com").is_err());
    }

    #[test]
    fn test_validate_email_leading_trailing_dots() {
        assert!(validate_email(".user@example.com").is_err());
        assert!(validate_email("user.@example.com").is_err());
        assert!(validate_email("user@.example.com").is_err());
        assert!(validate_email("user@example.com.").is_err());
    }

    #[test]
    fn test_validate_email_hyphen_rules() {
        assert!(validate_email("user@-example.com").is_err());
        assert!(validate_email("user@example-.com").is_err());
        // Hyphens in the middle are fine
        assert!(validate_email("user@ex-ample.com").is_ok());
    }

    #[test]
    fn test_validate_email_length_limits() {
        // Local-part max 64 chars
        let long_local = "a".repeat(65);
        assert!(validate_email(&format!("{}@example.com", long_local)).is_err());

        // 64 chars is OK
        let max_local = "a".repeat(64);
        assert!(validate_email(&format!("{}@example.com", max_local)).is_ok());

        // Domain label max 63 chars
        let long_label = "a".repeat(64);
        assert!(validate_email(&format!("user@{}.com", long_label)).is_err());
    }

    #[test]
    fn test_validate_email_invalid_domain_chars() {
        assert!(validate_email("user@exam ple.com").is_err());
        assert!(validate_email("user@exam_ple.com").is_err());
        assert!(validate_email("user@exam!ple.com").is_err());
    }

    #[test]
    fn test_renewal_config_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let rc = RenewalConfig::new(
            "https://acme.example.com/directory",
            Some("admin@example.com"),
            Some(std::path::Path::new("/var/www/html")),
            false,
            false,
            &["example.com".to_string(), "www.example.com".to_string()],
            false,
            None,
        );
        assert_eq!(rc.challenge_method, "http");
        assert_eq!(rc.server, "https://acme.example.com/directory");
        assert_eq!(rc.email.as_deref(), Some("admin@example.com"));
        assert_eq!(rc.domains.len(), 2);

        rc.save(tmp.path()).unwrap();
        let loaded = RenewalConfig::load(tmp.path()).unwrap();
        assert_eq!(loaded.server, rc.server);
        assert_eq!(loaded.email, rc.email);
        assert_eq!(loaded.challenge_method, rc.challenge_method);
        assert_eq!(loaded.domains, rc.domains);
    }

    #[test]
    fn test_renewal_config_challenge_methods() {
        let dns = RenewalConfig::new("https://a.com", None, None, false, true, &[], false, None);
        assert_eq!(dns.challenge_method, "dns");

        let standalone =
            RenewalConfig::new("https://a.com", None, None, true, false, &[], false, None);
        assert_eq!(standalone.challenge_method, "standalone");

        let manual =
            RenewalConfig::new("https://a.com", None, None, false, false, &[], false, None);
        assert_eq!(manual.challenge_method, "manual");
    }

    #[test]
    fn test_renewal_config_load_missing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(RenewalConfig::load(tmp.path()).is_err());
    }
}
