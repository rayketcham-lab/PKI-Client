//! ACME install command — certonly + deploy to web server with backup.

use super::certonly::cmd_certonly;
use super::helpers::{pki_certs_dir, validate_email};
use crate::commands::CmdResult;
use crate::config::GlobalConfig;
use crate::deployer;
#[allow(unused_imports)]
use crate::deployer::WebServerDeployer;
use anyhow::{anyhow, Result};
use colored::Colorize;
use std::fs;
use std::path::Path;

#[cfg(not(target_os = "windows"))]
#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_install(
    domains: &[String],
    server: &str,
    email: Option<&str>,
    webroot: Option<&Path>,
    apache: bool,
    nginx: bool,
    backup_dir_opt: Option<&Path>,
    agree_tos: bool,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    use deployer::ServerType;

    if let Some(e) = email {
        validate_email(e)?;
    }

    let primary_domain = domains
        .first()
        .ok_or_else(|| anyhow!("At least one domain is required"))?;

    // Determine web server
    let server_type = if apache {
        ServerType::Apache
    } else if nginx {
        ServerType::Nginx
    } else {
        // Auto-detect
        let detected = deployer::detect_servers();
        if detected.is_empty() {
            return Err(anyhow!(
                "No web server detected. Use --apache or --nginx, or use 'certonly' instead."
            ));
        }
        if detected.len() > 1 {
            return Err(anyhow!(
                "Multiple web servers detected ({}). Please specify --apache or --nginx.",
                detected
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        detected.into_iter().next().unwrap()
    };

    let deployer_impl = deployer::get_deployer(&server_type);

    if !config.quiet {
        println!();
        println!("{}", "EXPERIMENTAL: Web server integration".yellow().bold());
        println!(
            "This will modify your {} configuration. A backup will be created.",
            deployer_impl.name()
        );
        println!("Use 'pki acme rollback' to restore if anything goes wrong.");
        println!();
    }

    // Step 1: Get certificate via certonly flow
    let cert_dir = pki_certs_dir()?.join(primary_domain);
    fs::create_dir_all(&cert_dir)?;

    cmd_certonly(
        domains,
        server,
        email,
        webroot,
        false,
        false,
        Some(&cert_dir),
        agree_tos,
        insecure,
        ca_cert,
        config,
    )?;

    let cert_path = cert_dir.join("fullchain.pem");
    let key_path = cert_dir.join("privkey.pem");

    if !cert_path.exists() || !key_path.exists() {
        return Err(anyhow!("Certificate files not found after issuance"));
    }

    // Step 2: Backup current config
    let backup_root = match backup_dir_opt {
        Some(dir) => dir.to_path_buf(),
        None => deployer::backup::default_backup_root()?,
    };

    if !config.quiet {
        println!("Creating backup of {} config...", deployer_impl.name());
    }
    let manifest = deployer_impl.backup(primary_domain, &backup_root)?;

    if !config.quiet {
        println!("  Backup saved: {}", manifest.backup_dir.display());
    }

    // Step 3: Deploy certificate
    if !config.quiet {
        println!("Deploying certificate to {}...", deployer_impl.name());
    }
    if let Err(e) = deployer_impl.deploy_cert(&cert_path, &key_path, None, primary_domain) {
        eprintln!("{}: {}", "Deploy failed".red().bold(), e);
        eprintln!("Rolling back...");
        deployer_impl.rollback(&manifest)?;
        eprintln!("{}", "Rollback complete.".green());
        return Err(e);
    }

    // Step 4: Test configuration
    if !config.quiet {
        println!("Testing {} configuration...", deployer_impl.name());
    }
    if let Err(e) = deployer_impl.test_config() {
        eprintln!("{}: {}", "Config test failed".red().bold(), e);
        eprintln!("Rolling back...");
        deployer_impl.rollback(&manifest)?;
        eprintln!("{}", "Rollback complete.".green());
        return Err(e);
    }

    // Step 5: Reload web server
    if !config.quiet {
        println!("Reloading {}...", deployer_impl.name());
    }
    if let Err(e) = deployer_impl.reload() {
        eprintln!("{}: {}", "Reload failed".red().bold(), e);
        eprintln!("Rolling back...");
        deployer_impl.rollback(&manifest)?;
        eprintln!("{}", "Rollback complete.".green());
        return Err(e);
    }

    // Cleanup old backups
    let _ = deployer::backup::cleanup_old_backups(&backup_root);

    if !config.quiet {
        println!();
        println!("{}", "Certificate installed successfully!".green().bold());
        println!();
        println!(
            "  EXPERIMENTAL: Backup saved to {}",
            manifest.backup_dir.display()
        );
        println!("  Run 'pki acme rollback' to restore previous configuration.");
    }

    Ok(CmdResult::Success)
}

#[cfg(target_os = "windows")]
#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_install_windows(
    domains: &[String],
    server: &str,
    email: Option<&str>,
    webroot: Option<&Path>,
    iis: bool,
    backup_dir_opt: Option<&Path>,
    agree_tos: bool,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    use deployer::ServerType;

    if let Some(e) = email {
        validate_email(e)?;
    }

    let primary_domain = domains
        .first()
        .ok_or_else(|| anyhow!("At least one domain is required"))?;

    if !iis {
        let detected = deployer::detect_servers();
        if detected.is_empty() {
            return Err(anyhow!(
                "No web server detected. Use --iis, or use 'certonly' instead."
            ));
        }
    }

    let server_type = ServerType::Iis;
    let deployer_impl = deployer::get_deployer(&server_type);

    if !config.quiet {
        println!();
        println!("{}", "EXPERIMENTAL: IIS integration".yellow().bold());
        println!("This will modify your IIS configuration. A backup will be created.");
        println!("Use 'pki acme rollback' to restore if anything goes wrong.");
        println!();
    }

    // Get certificate
    let cert_dir = pki_certs_dir()?.join(primary_domain);
    fs::create_dir_all(&cert_dir)?;

    cmd_certonly(
        domains,
        server,
        email,
        webroot,
        false,
        false,
        Some(&cert_dir),
        agree_tos,
        insecure,
        ca_cert,
        config,
    )?;

    let cert_path = cert_dir.join("fullchain.pem");
    let key_path = cert_dir.join("privkey.pem");

    // Backup
    let backup_root = match backup_dir_opt {
        Some(dir) => dir.to_path_buf(),
        None => deployer::backup::default_backup_root()?,
    };
    let manifest = deployer_impl.backup(primary_domain, &backup_root)?;

    // Deploy
    if let Err(e) = deployer_impl.deploy_cert(&cert_path, &key_path, None, primary_domain) {
        eprintln!("{}: {}", "Deploy failed".red().bold(), e);
        deployer_impl.rollback(&manifest)?;
        return Err(e);
    }

    // Test
    if let Err(e) = deployer_impl.test_config() {
        eprintln!("{}: {}", "Config test failed".red().bold(), e);
        deployer_impl.rollback(&manifest)?;
        return Err(e);
    }

    // Reload
    deployer_impl.reload()?;

    let _ = deployer::backup::cleanup_old_backups(&backup_root);

    if !config.quiet {
        println!();
        println!(
            "{}",
            "Certificate installed to IIS successfully!".green().bold()
        );
        println!(
            "  Backup: {}. Use 'pki acme rollback' to restore.",
            manifest.backup_dir.display()
        );
    }

    Ok(CmdResult::Success)
}
