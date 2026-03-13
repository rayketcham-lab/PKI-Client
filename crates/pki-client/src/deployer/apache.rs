//! Apache HTTP Server deployer.
//!
//! Detects Apache installations, finds vhost configurations,
//! deploys certificates, and manages config with backup/rollback.

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::backup::{self, BackupManifest};
use super::WebServerDeployer;

/// Apache web server deployer.
pub struct ApacheDeployer {
    /// Path to apache config root (e.g., /etc/apache2 or /etc/httpd).
    config_root: Option<PathBuf>,
    /// Name of the systemctl service.
    service_name: String,
    /// Path to apachectl binary.
    apachectl: String,
}

impl ApacheDeployer {
    pub fn new() -> Self {
        let (config_root, service_name, apachectl) = detect_apache_paths();
        Self {
            config_root,
            service_name,
            apachectl,
        }
    }

    /// Find the vhost config file for a domain.
    fn find_vhost_config(&self, domain: &str) -> Result<PathBuf> {
        let config_root = self
            .config_root
            .as_ref()
            .ok_or_else(|| anyhow!("Apache config root not found"))?;

        // Check sites-enabled (Debian/Ubuntu) then conf.d (RHEL/CentOS)
        let search_dirs = [
            config_root.join("sites-enabled"),
            config_root.join("conf.d"),
        ];

        for dir in &search_dirs {
            if !dir.exists() {
                continue;
            }

            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("conf") {
                    let content = fs::read_to_string(&path).unwrap_or_default();
                    // Look for ServerName or ServerAlias matching the domain
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if (trimmed.starts_with("ServerName") || trimmed.starts_with("ServerAlias"))
                            && trimmed.contains(domain)
                        {
                            return Ok(path);
                        }
                    }
                }
            }
        }

        Err(anyhow!(
            "No Apache vhost found for domain '{}'. Use --certonly instead and configure manually.",
            domain
        ))
    }

    /// Extract SSL certificate and key paths from a vhost config.
    fn extract_ssl_paths(&self, config_path: &Path) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
        let content = fs::read_to_string(config_path)?;
        let mut cert_path = None;
        let mut key_path = None;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("SSLCertificateFile") {
                cert_path = trimmed.split_whitespace().nth(1).map(PathBuf::from);
            }
            if trimmed.starts_with("SSLCertificateKeyFile") {
                key_path = trimmed.split_whitespace().nth(1).map(PathBuf::from);
            }
        }

        Ok((cert_path, key_path))
    }

    /// Update SSL directives in a vhost config file.
    fn update_ssl_directives(
        &self,
        config_path: &Path,
        cert_path: &Path,
        key_path: &Path,
        chain_path: Option<&Path>,
    ) -> Result<()> {
        let content = fs::read_to_string(config_path)?;
        let mut new_lines = Vec::new();
        let mut found_cert = false;
        let mut found_key = false;
        let mut found_chain = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("SSLCertificateFile") {
                new_lines.push(format!("    SSLCertificateFile {}", cert_path.display()));
                found_cert = true;
            } else if trimmed.starts_with("SSLCertificateKeyFile") {
                new_lines.push(format!("    SSLCertificateKeyFile {}", key_path.display()));
                found_key = true;
            } else if trimmed.starts_with("SSLCertificateChainFile") {
                if let Some(chain) = chain_path {
                    new_lines.push(format!("    SSLCertificateChainFile {}", chain.display()));
                }
                found_chain = true;
            } else {
                new_lines.push(line.to_string());
            }
        }

        // If chain path provided but directive didn't exist, add it after SSLCertificateKeyFile
        if !found_chain {
            if let Some(chain) = chain_path {
                // Find the SSLCertificateKeyFile line and insert after it
                let mut final_lines = Vec::new();
                for line in &new_lines {
                    final_lines.push(line.clone());
                    if line.trim().starts_with("SSLCertificateKeyFile") {
                        final_lines
                            .push(format!("    SSLCertificateChainFile {}", chain.display()));
                    }
                }
                new_lines = final_lines;
            }
        }

        if !found_cert || !found_key {
            return Err(anyhow!(
                "Could not find SSLCertificateFile/SSLCertificateKeyFile directives in {}. \
                 Use --certonly instead and configure Apache manually.",
                config_path.display()
            ));
        }

        let content_out = new_lines.join("\n") + "\n";
        let tmp_path = config_path.with_extension("tmp");
        fs::write(&tmp_path, &content_out)
            .with_context(|| format!("Failed to write temp config {}", tmp_path.display()))?;
        fs::rename(&tmp_path, config_path).with_context(|| {
            format!("Failed to rename temp config to {}", config_path.display())
        })?;
        Ok(())
    }
}

impl WebServerDeployer for ApacheDeployer {
    fn detect(&self) -> Result<bool> {
        Ok(self.config_root.is_some())
    }

    fn backup(&self, domain: &str, backup_dir: &Path) -> Result<BackupManifest> {
        let (dir, id) = backup::create_backup_dir(backup_dir)?;
        let mut files = Vec::new();

        // Backup vhost config
        let vhost_config = self.find_vhost_config(domain)?;
        files.push(backup::backup_file(&vhost_config, &dir)?);

        // Backup existing cert/key files if they exist
        let (cert_path, key_path) = self.extract_ssl_paths(&vhost_config)?;
        if let Some(cert) = cert_path {
            if cert.exists() {
                files.push(backup::backup_file(&cert, &dir)?);
            }
        }
        if let Some(key) = key_path {
            if key.exists() {
                files.push(backup::backup_file(&key, &dir)?);
            }
        }

        let manifest = BackupManifest {
            id,
            timestamp: chrono::Utc::now(),
            server_type: "apache".to_string(),
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
        chain_path: Option<&Path>,
        domain: &str,
    ) -> Result<()> {
        // Create cert directory
        let cert_dir = PathBuf::from(format!("/etc/ssl/pki-client/{}", domain));
        fs::create_dir_all(&cert_dir)
            .with_context(|| format!("Failed to create cert directory: {}", cert_dir.display()))?;

        // Copy cert and key to standard locations
        let dest_cert = cert_dir.join("fullchain.pem");
        let dest_key = cert_dir.join("privkey.pem");

        fs::copy(cert_path, &dest_cert)
            .with_context(|| format!("Failed to copy cert to {}", dest_cert.display()))?;
        let key_data = fs::read(key_path)
            .with_context(|| format!("Failed to read key from {}", key_path.display()))?;
        crate::util::write_sensitive_file(&dest_key, &key_data)
            .with_context(|| format!("Failed to write key to {}", dest_key.display()))?;

        let dest_chain = chain_path
            .map(|cp| -> Result<PathBuf> {
                let dest = cert_dir.join("chain.pem");
                fs::copy(cp, &dest)
                    .with_context(|| format!("Failed to copy chain to {}", dest.display()))?;
                Ok(dest)
            })
            .transpose()?;

        // Update Apache config
        let vhost_config = self.find_vhost_config(domain)?;
        self.update_ssl_directives(&vhost_config, &dest_cert, &dest_key, dest_chain.as_deref())?;

        Ok(())
    }

    fn test_config(&self) -> Result<()> {
        let output = Command::new(&self.apachectl)
            .arg("configtest")
            .output()
            .context("Failed to run apachectl configtest")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Apache config test failed:\n{}", stderr));
        }

        Ok(())
    }

    fn reload(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .args(["reload", &self.service_name])
            .output()
            .context("Failed to reload Apache")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Apache reload failed:\n{}", stderr));
        }

        Ok(())
    }

    fn rollback(&self, manifest: &BackupManifest) -> Result<()> {
        backup::restore_from_manifest(manifest)?;
        self.test_config()?;
        self.reload()?;
        Ok(())
    }

    fn name(&self) -> &str {
        "Apache"
    }
}

#[cfg(test)]
impl ApacheDeployer {
    /// Create an ApacheDeployer with a custom config root (for testing).
    fn with_config_root(config_root: PathBuf) -> Self {
        Self {
            config_root: Some(config_root),
            service_name: "apache2".to_string(),
            apachectl: "apachectl".to_string(),
        }
    }
}

/// Detect Apache installation paths.
fn detect_apache_paths() -> (Option<PathBuf>, String, String) {
    // Debian/Ubuntu
    let debian_path = PathBuf::from("/etc/apache2");
    if debian_path.exists() {
        return (
            Some(debian_path),
            "apache2".to_string(),
            "apachectl".to_string(),
        );
    }

    // RHEL/CentOS/Rocky
    let rhel_path = PathBuf::from("/etc/httpd");
    if rhel_path.exists() {
        return (
            Some(rhel_path),
            "httpd".to_string(),
            "apachectl".to_string(),
        );
    }

    (None, "apache2".to_string(), "apachectl".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper: create a mock Apache vhost file in sites-enabled.
    fn setup_apache_vhost(tmp: &TempDir, filename: &str, content: &str) -> PathBuf {
        let sites_enabled = tmp.path().join("sites-enabled");
        fs::create_dir_all(&sites_enabled).unwrap();
        let vhost_path = sites_enabled.join(filename);
        fs::write(&vhost_path, content).unwrap();
        vhost_path
    }

    // ---- find_vhost_config tests ----

    #[test]
    fn test_find_vhost_by_server_name() {
        let tmp = TempDir::new().unwrap();
        let vhost_content = "\
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/example
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/example.pem
    SSLCertificateKeyFile /etc/ssl/private/example.key
</VirtualHost>";
        let expected = setup_apache_vhost(&tmp, "example.com.conf", vhost_content);
        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());

        let found = deployer.find_vhost_config("example.com").unwrap();
        assert_eq!(found, expected);
    }

    #[test]
    fn test_find_vhost_by_server_alias() {
        let tmp = TempDir::new().unwrap();
        let vhost_content = "\
<VirtualHost *:443>
    ServerName primary.com
    ServerAlias www.primary.com alias.primary.com
    SSLCertificateFile /etc/ssl/certs/primary.pem
    SSLCertificateKeyFile /etc/ssl/private/primary.key
</VirtualHost>";
        setup_apache_vhost(&tmp, "primary.conf", vhost_content);
        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());

        let result = deployer.find_vhost_config("alias.primary.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_vhost_in_conf_d() {
        let tmp = TempDir::new().unwrap();
        let conf_d = tmp.path().join("conf.d");
        fs::create_dir_all(&conf_d).unwrap();
        let vhost_path = conf_d.join("mysite.conf");
        fs::write(
            &vhost_path,
            "<VirtualHost *:443>\n    ServerName rhel.example.com\n</VirtualHost>\n",
        )
        .unwrap();

        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());
        let found = deployer.find_vhost_config("rhel.example.com").unwrap();
        assert_eq!(found, vhost_path);
    }

    #[test]
    fn test_find_vhost_not_found() {
        let tmp = TempDir::new().unwrap();
        let sites_enabled = tmp.path().join("sites-enabled");
        fs::create_dir_all(&sites_enabled).unwrap();
        fs::write(
            sites_enabled.join("other.conf"),
            "<VirtualHost *:443>\n    ServerName other.com\n</VirtualHost>\n",
        )
        .unwrap();

        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());
        let result = deployer.find_vhost_config("notfound.com");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No Apache vhost found"));
    }

    #[test]
    fn test_find_vhost_skips_non_conf_files() {
        let tmp = TempDir::new().unwrap();
        let sites_enabled = tmp.path().join("sites-enabled");
        fs::create_dir_all(&sites_enabled).unwrap();
        fs::write(
            sites_enabled.join("example.com.bak"),
            "<VirtualHost *:443>\n    ServerName example.com\n</VirtualHost>\n",
        )
        .unwrap();

        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());
        let result = deployer.find_vhost_config("example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_find_vhost_no_config_root() {
        let deployer = ApacheDeployer {
            config_root: None,
            service_name: "apache2".to_string(),
            apachectl: "apachectl".to_string(),
        };
        let result = deployer.find_vhost_config("example.com");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("config root not found"));
    }

    // ---- extract_ssl_paths tests ----

    #[test]
    fn test_extract_ssl_paths_both_present() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("ssl.conf");
        fs::write(
            &config,
            "\
<VirtualHost *:443>
    ServerName secure.example.com
    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/secure.pem
    SSLCertificateKeyFile /etc/ssl/private/secure.key
</VirtualHost>",
        )
        .unwrap();

        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());
        let (cert, key) = deployer.extract_ssl_paths(&config).unwrap();
        assert_eq!(cert.unwrap(), PathBuf::from("/etc/ssl/certs/secure.pem"));
        assert_eq!(key.unwrap(), PathBuf::from("/etc/ssl/private/secure.key"));
    }

    #[test]
    fn test_extract_ssl_paths_none_present() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("nossl.conf");
        fs::write(
            &config,
            "\
<VirtualHost *:80>
    ServerName plain.example.com
    DocumentRoot /var/www/plain
</VirtualHost>",
        )
        .unwrap();

        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());
        let (cert, key) = deployer.extract_ssl_paths(&config).unwrap();
        assert!(cert.is_none());
        assert!(key.is_none());
    }

    #[test]
    fn test_extract_ssl_paths_with_leading_whitespace() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("indented.conf");
        fs::write(
            &config,
            "\
<VirtualHost *:443>
        SSLCertificateFile /certs/indented.pem
        SSLCertificateKeyFile /certs/indented.key
</VirtualHost>",
        )
        .unwrap();

        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());
        let (cert, key) = deployer.extract_ssl_paths(&config).unwrap();
        assert_eq!(cert.unwrap(), PathBuf::from("/certs/indented.pem"));
        assert_eq!(key.unwrap(), PathBuf::from("/certs/indented.key"));
    }

    // ---- update_ssl_directives tests ----

    #[test]
    fn test_update_ssl_directives_replaces_existing() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("update.conf");
        fs::write(
            &config,
            "\
<VirtualHost *:443>
    ServerName update.example.com
    SSLCertificateFile /old/cert.pem
    SSLCertificateKeyFile /old/key.pem
</VirtualHost>",
        )
        .unwrap();

        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());
        deployer
            .update_ssl_directives(
                &config,
                Path::new("/new/cert.pem"),
                Path::new("/new/key.pem"),
                None,
            )
            .unwrap();

        let result = fs::read_to_string(&config).unwrap();
        assert!(result.contains("SSLCertificateFile /new/cert.pem"));
        assert!(result.contains("SSLCertificateKeyFile /new/key.pem"));
        assert!(!result.contains("/old/"));
    }

    #[test]
    fn test_update_ssl_directives_replaces_chain() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("chain.conf");
        fs::write(
            &config,
            "\
<VirtualHost *:443>
    SSLCertificateFile /old/cert.pem
    SSLCertificateKeyFile /old/key.pem
    SSLCertificateChainFile /old/chain.pem
</VirtualHost>",
        )
        .unwrap();

        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());
        deployer
            .update_ssl_directives(
                &config,
                Path::new("/new/cert.pem"),
                Path::new("/new/key.pem"),
                Some(Path::new("/new/chain.pem")),
            )
            .unwrap();

        let result = fs::read_to_string(&config).unwrap();
        assert!(result.contains("SSLCertificateChainFile /new/chain.pem"));
        assert!(!result.contains("/old/chain.pem"));
    }

    #[test]
    fn test_update_ssl_directives_adds_chain_when_missing() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("nochain.conf");
        fs::write(
            &config,
            "\
<VirtualHost *:443>
    SSLCertificateFile /old/cert.pem
    SSLCertificateKeyFile /old/key.pem
</VirtualHost>",
        )
        .unwrap();

        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());
        deployer
            .update_ssl_directives(
                &config,
                Path::new("/new/cert.pem"),
                Path::new("/new/key.pem"),
                Some(Path::new("/new/chain.pem")),
            )
            .unwrap();

        let result = fs::read_to_string(&config).unwrap();
        assert!(result.contains("SSLCertificateChainFile /new/chain.pem"));
        let key_pos = result.find("SSLCertificateKeyFile").unwrap();
        let chain_pos = result.find("SSLCertificateChainFile").unwrap();
        assert!(chain_pos > key_pos, "chain should come after key directive");
    }

    #[test]
    fn test_update_ssl_directives_fails_without_ssl_directives() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("nossl.conf");
        fs::write(
            &config,
            "\
<VirtualHost *:80>
    ServerName plain.example.com
</VirtualHost>",
        )
        .unwrap();

        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());
        let result = deployer.update_ssl_directives(
            &config,
            Path::new("/new/cert.pem"),
            Path::new("/new/key.pem"),
            None,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Could not find SSLCertificateFile"));
    }

    #[test]
    fn test_update_ssl_directives_drops_chain_when_not_provided() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("dropchain.conf");
        fs::write(
            &config,
            "\
<VirtualHost *:443>
    SSLCertificateFile /old/cert.pem
    SSLCertificateKeyFile /old/key.pem
    SSLCertificateChainFile /old/chain.pem
</VirtualHost>",
        )
        .unwrap();

        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());
        deployer
            .update_ssl_directives(
                &config,
                Path::new("/new/cert.pem"),
                Path::new("/new/key.pem"),
                None,
            )
            .unwrap();

        let result = fs::read_to_string(&config).unwrap();
        assert!(!result.contains("SSLCertificateChainFile"));
        assert!(result.contains("SSLCertificateFile /new/cert.pem"));
    }

    // ---- detect / name tests ----

    #[test]
    fn test_detect_with_config_root() {
        let tmp = TempDir::new().unwrap();
        let deployer = ApacheDeployer::with_config_root(tmp.path().to_path_buf());
        assert!(deployer.detect().unwrap());
    }

    #[test]
    fn test_detect_without_config_root() {
        let deployer = ApacheDeployer {
            config_root: None,
            service_name: "apache2".to_string(),
            apachectl: "apachectl".to_string(),
        };
        assert!(!deployer.detect().unwrap());
    }

    #[test]
    fn test_name() {
        let deployer = ApacheDeployer::with_config_root(PathBuf::from("/tmp"));
        assert_eq!(deployer.name(), "Apache");
    }
}
