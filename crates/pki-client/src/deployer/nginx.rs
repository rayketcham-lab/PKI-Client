//! Nginx deployer.
//!
//! Detects Nginx installations, finds server block configurations,
//! deploys certificates, and manages config with backup/rollback.

use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::backup::{self, BackupManifest};
use super::WebServerDeployer;

/// Nginx web server deployer.
pub struct NginxDeployer {
    /// Path to nginx config root (e.g., /etc/nginx).
    config_root: Option<PathBuf>,
}

impl NginxDeployer {
    pub fn new() -> Self {
        let config_root = detect_nginx_root();
        Self { config_root }
    }

    /// Find the server block config file for a domain.
    fn find_server_block(&self, domain: &str) -> Result<PathBuf> {
        let config_root = self
            .config_root
            .as_ref()
            .ok_or_else(|| anyhow!("Nginx config root not found"))?;

        // Check sites-enabled then conf.d
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
                if path.is_file() {
                    let content = fs::read_to_string(&path).unwrap_or_default();
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("server_name") && trimmed.contains(domain) {
                            return Ok(path);
                        }
                    }
                }
            }
        }

        Err(anyhow!(
            "No Nginx server block found for domain '{}'. Use --certonly instead and configure manually.",
            domain
        ))
    }

    /// Extract SSL certificate and key paths from a server block config.
    fn extract_ssl_paths(&self, config_path: &Path) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
        let content = fs::read_to_string(config_path)?;
        let mut cert_path = None;
        let mut key_path = None;

        for line in content.lines() {
            let trimmed = line.trim().trim_end_matches(';');
            if trimmed.starts_with("ssl_certificate ")
                && !trimmed.starts_with("ssl_certificate_key")
            {
                cert_path = trimmed.split_whitespace().nth(1).map(PathBuf::from);
            }
            if trimmed.starts_with("ssl_certificate_key") {
                key_path = trimmed.split_whitespace().nth(1).map(PathBuf::from);
            }
        }

        Ok((cert_path, key_path))
    }

    /// Update SSL directives in a server block config file.
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
        let mut found_trusted = false;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("ssl_certificate ")
                && !trimmed.starts_with("ssl_certificate_key")
            {
                new_lines.push(format!("    ssl_certificate {};", cert_path.display()));
                found_cert = true;
            } else if trimmed.starts_with("ssl_certificate_key") {
                new_lines.push(format!("    ssl_certificate_key {};", key_path.display()));
                found_key = true;
            } else if trimmed.starts_with("ssl_trusted_certificate") {
                if let Some(chain) = chain_path {
                    new_lines.push(format!("    ssl_trusted_certificate {};", chain.display()));
                }
                found_trusted = true;
            } else {
                new_lines.push(line.to_string());
            }
        }

        if !found_cert || !found_key {
            return Err(anyhow!(
                "Could not find ssl_certificate/ssl_certificate_key directives in {}. \
                 Use --certonly instead and configure Nginx manually.",
                config_path.display()
            ));
        }

        // If chain path provided but ssl_trusted_certificate didn't exist, add it after ssl_certificate_key
        if !found_trusted {
            if let Some(chain) = chain_path {
                let mut final_lines = Vec::new();
                for line in &new_lines {
                    final_lines.push(line.clone());
                    if line.trim().starts_with("ssl_certificate_key") {
                        final_lines
                            .push(format!("    ssl_trusted_certificate {};", chain.display()));
                    }
                }
                new_lines = final_lines;
            }
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

impl WebServerDeployer for NginxDeployer {
    fn detect(&self) -> Result<bool> {
        Ok(self.config_root.is_some())
    }

    fn backup(&self, domain: &str, backup_dir: &Path) -> Result<BackupManifest> {
        let (dir, id) = backup::create_backup_dir(backup_dir)?;
        let mut files = Vec::new();

        // Backup server block config
        let server_block = self.find_server_block(domain)?;
        files.push(backup::backup_file(&server_block, &dir)?);

        // Backup existing cert/key files
        let (cert_path, key_path) = self.extract_ssl_paths(&server_block)?;
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
            server_type: "nginx".to_string(),
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

        // Copy chain file for OCSP stapling
        let dest_chain = chain_path
            .map(|cp| -> Result<PathBuf> {
                let dest = cert_dir.join("chain.pem");
                fs::copy(cp, &dest)
                    .with_context(|| format!("Failed to copy chain to {}", dest.display()))?;
                Ok(dest)
            })
            .transpose()?;

        // Update Nginx config
        let server_block = self.find_server_block(domain)?;
        self.update_ssl_directives(&server_block, &dest_cert, &dest_key, dest_chain.as_deref())?;

        Ok(())
    }

    fn test_config(&self) -> Result<()> {
        let output = Command::new("nginx")
            .arg("-t")
            .output()
            .context("Failed to run nginx -t")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Nginx config test failed:\n{}", stderr));
        }

        Ok(())
    }

    fn reload(&self) -> Result<()> {
        let output = Command::new("systemctl")
            .args(["reload", "nginx"])
            .output()
            .context("Failed to reload Nginx")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Nginx reload failed:\n{}", stderr));
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
        "Nginx"
    }
}

#[cfg(test)]
impl NginxDeployer {
    /// Create a NginxDeployer with a custom config root (for testing).
    fn with_config_root(config_root: PathBuf) -> Self {
        Self {
            config_root: Some(config_root),
        }
    }
}

/// Detect Nginx config root.
fn detect_nginx_root() -> Option<PathBuf> {
    let nginx_path = PathBuf::from("/etc/nginx");
    if nginx_path.exists() {
        Some(nginx_path)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper: create a mock Nginx config file in sites-enabled.
    fn setup_nginx_server_block(tmp: &TempDir, filename: &str, content: &str) -> PathBuf {
        let sites_enabled = tmp.path().join("sites-enabled");
        fs::create_dir_all(&sites_enabled).unwrap();
        let config_path = sites_enabled.join(filename);
        fs::write(&config_path, content).unwrap();
        config_path
    }

    // ---- find_server_block tests ----

    #[test]
    fn test_find_server_block_by_server_name() {
        let tmp = TempDir::new().unwrap();
        let config_content = "\
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate /etc/ssl/certs/example.pem;
    ssl_certificate_key /etc/ssl/private/example.key;
}";
        let expected = setup_nginx_server_block(&tmp, "example.com", config_content);
        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());

        let found = deployer.find_server_block("example.com").unwrap();
        assert_eq!(found, expected);
    }

    #[test]
    fn test_find_server_block_multiple_names() {
        let tmp = TempDir::new().unwrap();
        let config_content = "\
server {
    listen 443 ssl;
    server_name primary.com www.primary.com;
    ssl_certificate /etc/ssl/certs/primary.pem;
    ssl_certificate_key /etc/ssl/private/primary.key;
}";
        setup_nginx_server_block(&tmp, "primary.com", config_content);
        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());

        let result = deployer.find_server_block("www.primary.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_find_server_block_in_conf_d() {
        let tmp = TempDir::new().unwrap();
        let conf_d = tmp.path().join("conf.d");
        fs::create_dir_all(&conf_d).unwrap();
        let config_path = conf_d.join("rhel-site.conf");
        fs::write(
            &config_path,
            "server {\n    server_name rhel.example.com;\n}\n",
        )
        .unwrap();

        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
        let found = deployer.find_server_block("rhel.example.com").unwrap();
        assert_eq!(found, config_path);
    }

    #[test]
    fn test_find_server_block_not_found() {
        let tmp = TempDir::new().unwrap();
        let sites_enabled = tmp.path().join("sites-enabled");
        fs::create_dir_all(&sites_enabled).unwrap();
        fs::write(
            sites_enabled.join("other.conf"),
            "server {\n    server_name other.com;\n}\n",
        )
        .unwrap();

        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
        let result = deployer.find_server_block("notfound.com");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No Nginx server block found"));
    }

    #[test]
    fn test_find_server_block_no_config_root() {
        let deployer = NginxDeployer { config_root: None };
        let result = deployer.find_server_block("example.com");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("config root not found"));
    }

    #[test]
    fn test_find_server_block_empty_dirs() {
        let tmp = TempDir::new().unwrap();
        // Create empty sites-enabled and conf.d
        fs::create_dir_all(tmp.path().join("sites-enabled")).unwrap();
        fs::create_dir_all(tmp.path().join("conf.d")).unwrap();

        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
        let result = deployer.find_server_block("example.com");
        assert!(result.is_err());
    }

    // ---- extract_ssl_paths tests ----

    #[test]
    fn test_extract_ssl_paths_both_present() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("ssl.conf");
        fs::write(
            &config,
            "\
server {
    listen 443 ssl;
    server_name secure.example.com;
    ssl_certificate /etc/ssl/certs/secure.pem;
    ssl_certificate_key /etc/ssl/private/secure.key;
}",
        )
        .unwrap();

        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
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
server {
    listen 80;
    server_name plain.example.com;
}",
        )
        .unwrap();

        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
        let (cert, key) = deployer.extract_ssl_paths(&config).unwrap();
        assert!(cert.is_none());
        assert!(key.is_none());
    }

    #[test]
    fn test_extract_ssl_paths_strips_semicolons() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("semi.conf");
        fs::write(
            &config,
            "\
server {
    ssl_certificate /certs/test.pem;
    ssl_certificate_key /certs/test.key;
}",
        )
        .unwrap();

        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
        let (cert, key) = deployer.extract_ssl_paths(&config).unwrap();
        // Semicolons should be stripped by trim_end_matches
        assert_eq!(cert.unwrap(), PathBuf::from("/certs/test.pem"));
        assert_eq!(key.unwrap(), PathBuf::from("/certs/test.key"));
    }

    #[test]
    fn test_extract_ssl_paths_does_not_confuse_cert_and_key() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("order.conf");
        // ssl_certificate_key comes before ssl_certificate
        fs::write(
            &config,
            "\
server {
    ssl_certificate_key /private/key.pem;
    ssl_certificate /certs/cert.pem;
}",
        )
        .unwrap();

        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
        let (cert, key) = deployer.extract_ssl_paths(&config).unwrap();
        assert_eq!(cert.unwrap(), PathBuf::from("/certs/cert.pem"));
        assert_eq!(key.unwrap(), PathBuf::from("/private/key.pem"));
    }

    // ---- update_ssl_directives tests ----

    #[test]
    fn test_update_ssl_directives_replaces_existing() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("update.conf");
        fs::write(
            &config,
            "\
server {
    listen 443 ssl;
    server_name update.example.com;
    ssl_certificate /old/cert.pem;
    ssl_certificate_key /old/key.pem;
}",
        )
        .unwrap();

        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
        deployer
            .update_ssl_directives(
                &config,
                Path::new("/new/cert.pem"),
                Path::new("/new/key.pem"),
                None,
            )
            .unwrap();

        let result = fs::read_to_string(&config).unwrap();
        assert!(result.contains("ssl_certificate /new/cert.pem;"));
        assert!(result.contains("ssl_certificate_key /new/key.pem;"));
        assert!(!result.contains("/old/"));
    }

    #[test]
    fn test_update_ssl_directives_replaces_trusted_cert() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("trusted.conf");
        fs::write(
            &config,
            "\
server {
    ssl_certificate /old/cert.pem;
    ssl_certificate_key /old/key.pem;
    ssl_trusted_certificate /old/chain.pem;
}",
        )
        .unwrap();

        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
        deployer
            .update_ssl_directives(
                &config,
                Path::new("/new/cert.pem"),
                Path::new("/new/key.pem"),
                Some(Path::new("/new/chain.pem")),
            )
            .unwrap();

        let result = fs::read_to_string(&config).unwrap();
        assert!(result.contains("ssl_trusted_certificate /new/chain.pem;"));
        assert!(!result.contains("/old/chain.pem"));
    }

    #[test]
    fn test_update_ssl_directives_adds_trusted_cert_when_missing() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("notrusted.conf");
        fs::write(
            &config,
            "\
server {
    ssl_certificate /old/cert.pem;
    ssl_certificate_key /old/key.pem;
}",
        )
        .unwrap();

        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
        deployer
            .update_ssl_directives(
                &config,
                Path::new("/new/cert.pem"),
                Path::new("/new/key.pem"),
                Some(Path::new("/new/chain.pem")),
            )
            .unwrap();

        let result = fs::read_to_string(&config).unwrap();
        assert!(result.contains("ssl_trusted_certificate /new/chain.pem;"));
        let key_pos = result.find("ssl_certificate_key").unwrap();
        let chain_pos = result.find("ssl_trusted_certificate").unwrap();
        assert!(
            chain_pos > key_pos,
            "trusted cert should come after key directive"
        );
    }

    #[test]
    fn test_update_ssl_directives_fails_without_ssl_directives() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("nossl.conf");
        fs::write(
            &config,
            "\
server {
    listen 80;
    server_name plain.example.com;
}",
        )
        .unwrap();

        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
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
            .contains("Could not find ssl_certificate"));
    }

    #[test]
    fn test_update_ssl_directives_drops_trusted_when_not_provided() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("droptrusted.conf");
        fs::write(
            &config,
            "\
server {
    ssl_certificate /old/cert.pem;
    ssl_certificate_key /old/key.pem;
    ssl_trusted_certificate /old/chain.pem;
}",
        )
        .unwrap();

        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
        deployer
            .update_ssl_directives(
                &config,
                Path::new("/new/cert.pem"),
                Path::new("/new/key.pem"),
                None,
            )
            .unwrap();

        let result = fs::read_to_string(&config).unwrap();
        assert!(!result.contains("ssl_trusted_certificate"));
        assert!(result.contains("ssl_certificate /new/cert.pem;"));
    }

    #[test]
    fn test_update_preserves_non_ssl_lines() {
        let tmp = TempDir::new().unwrap();
        let config = tmp.path().join("preserve.conf");
        fs::write(
            &config,
            "\
server {
    listen 443 ssl;
    server_name preserve.example.com;
    root /var/www/preserve;
    ssl_certificate /old/cert.pem;
    ssl_certificate_key /old/key.pem;
    location / {
        proxy_pass http://backend;
    }
}",
        )
        .unwrap();

        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
        deployer
            .update_ssl_directives(
                &config,
                Path::new("/new/cert.pem"),
                Path::new("/new/key.pem"),
                None,
            )
            .unwrap();

        let result = fs::read_to_string(&config).unwrap();
        assert!(result.contains("listen 443 ssl;"));
        assert!(result.contains("server_name preserve.example.com;"));
        assert!(result.contains("root /var/www/preserve;"));
        assert!(result.contains("proxy_pass http://backend;"));
    }

    // ---- detect / name tests ----

    #[test]
    fn test_detect_with_config_root() {
        let tmp = TempDir::new().unwrap();
        let deployer = NginxDeployer::with_config_root(tmp.path().to_path_buf());
        assert!(deployer.detect().unwrap());
    }

    #[test]
    fn test_detect_without_config_root() {
        let deployer = NginxDeployer { config_root: None };
        assert!(!deployer.detect().unwrap());
    }

    #[test]
    fn test_name() {
        let deployer = NginxDeployer::with_config_root(PathBuf::from("/tmp"));
        assert_eq!(deployer.name(), "Nginx");
    }
}
