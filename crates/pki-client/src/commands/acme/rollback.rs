//! ACME rollback and backups commands — restore config from backup.

use crate::commands::CmdResult;
use crate::config::GlobalConfig;
use crate::deployer;
#[allow(unused_imports)]
use crate::deployer::WebServerDeployer;
use anyhow::{anyhow, Result};
use colored::Colorize;
use pki_client_output::OutputFormat;
use std::path::Path;

pub(super) fn cmd_rollback(
    backup_id: Option<&str>,
    backup_dir: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let backup_root = match backup_dir {
        Some(dir) => dir.to_path_buf(),
        None => deployer::backup::default_backup_root()?,
    };

    let backups = deployer::backup::list_backups(&backup_root)?;

    if backups.is_empty() {
        return Err(anyhow!("No backups found in {}", backup_root.display()));
    }

    let manifest = if let Some(id) = backup_id {
        backups
            .iter()
            .find(|b| b.id == id)
            .ok_or_else(|| anyhow!("Backup '{}' not found", id))?
    } else {
        &backups[0] // Most recent
    };

    if !config.quiet {
        println!(
            "Restoring backup '{}' ({})",
            manifest.id, manifest.server_type
        );
        println!("  Domain:    {}", manifest.domain);
        println!("  Timestamp: {}", manifest.timestamp);
        println!("  Files:     {}", manifest.files.len());
    }

    // Restore files
    deployer::backup::restore_from_manifest(manifest)?;

    // Try to test and reload the web server
    #[cfg(not(target_os = "windows"))]
    {
        match manifest.server_type.as_str() {
            "apache" => {
                let deployer_impl = deployer::apache::ApacheDeployer::new();
                if deployer_impl.detect().unwrap_or(false) {
                    deployer_impl.test_config()?;
                    deployer_impl.reload()?;
                }
            }
            "nginx" => {
                let deployer_impl = deployer::nginx::NginxDeployer::new();
                if deployer_impl.detect().unwrap_or(false) {
                    deployer_impl.test_config()?;
                    deployer_impl.reload()?;
                }
            }
            _ => {}
        }
    }

    #[cfg(target_os = "windows")]
    {
        if manifest.server_type == "iis" {
            let deployer_impl = deployer::iis::IisDeployer::new();
            if deployer_impl.detect().unwrap_or(false) {
                deployer_impl.test_config()?;
                deployer_impl.reload()?;
            }
        }
    }

    if !config.quiet {
        println!();
        println!("{}", "Rollback complete!".green().bold());
    }

    Ok(CmdResult::Success)
}

pub(super) fn cmd_backups(backup_dir: Option<&Path>, config: &GlobalConfig) -> Result<CmdResult> {
    let backup_root = match backup_dir {
        Some(dir) => dir.to_path_buf(),
        None => deployer::backup::default_backup_root()?,
    };

    let backups = deployer::backup::list_backups(&backup_root)?;

    if backups.is_empty() {
        if !config.quiet {
            println!("No backups found.");
        }
        return Ok(CmdResult::Success);
    }

    match config.format {
        OutputFormat::Json => {
            let json: Vec<_> = backups
                .iter()
                .map(|b| {
                    serde_json::json!({
                        "id": b.id,
                        "timestamp": b.timestamp.to_string(),
                        "server_type": b.server_type,
                        "domain": b.domain,
                        "files": b.files.len(),
                        "path": b.backup_dir,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text
        | OutputFormat::Forensic
        | OutputFormat::Compact
        | OutputFormat::Openssl => {
            println!();
            println!("{}", "Available Backups".bold());
            println!();
            for (i, backup) in backups.iter().enumerate() {
                let marker = if i == 0 { " (latest)" } else { "" };
                println!(
                    "  [{}] {}{} — {} / {} ({} files)",
                    i + 1,
                    backup.id,
                    marker,
                    backup.server_type,
                    backup.domain,
                    backup.files.len()
                );
            }
            println!();
            println!("Restore with: pki acme rollback --backup-id <ID>");
        }
    }

    Ok(CmdResult::Success)
}
