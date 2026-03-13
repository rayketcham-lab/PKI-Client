//! Revocation checking commands.

use crate::commands::CmdResult;
use crate::compat::{
    load_crl, Certificate, CrlChecker, OcspChecker, RevocationChecker, RevocationMethod,
    RevocationStatus,
};
use crate::config::GlobalConfig;
use anyhow::{anyhow, Context, Result};
use clap::Subcommand;
use colored::Colorize;
use pki_client_output::OutputFormat;
use std::path::PathBuf;

/// Revocation checking commands.
#[derive(Subcommand)]
pub enum RevokeCommands {
    /// Check certificate revocation status (OCSP + CRL)
    #[command(after_help = "Examples:
  pki revoke check server.pem              Check using OCSP, fall back to CRL
  pki revoke check server.pem --ocsp-only  Check using OCSP only
  pki revoke check server.pem --crl-only   Check using CRL only
  pki revoke check server.pem --issuer ca.pem  Specify issuer for OCSP")]
    Check {
        /// Certificate file to check
        file: PathBuf,

        /// Issuer certificate (required for OCSP)
        #[arg(long, short = 'i')]
        issuer: Option<PathBuf>,

        /// Use OCSP only (no CRL fallback)
        #[arg(long, conflicts_with = "crl_only")]
        ocsp_only: bool,

        /// Use CRL only (no OCSP)
        #[arg(long, conflicts_with = "ocsp_only")]
        crl_only: bool,

        /// Timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,
    },

    /// Show contents of a local CRL file
    #[command(after_help = "Examples:
  pki revoke crl-show ca.crl
  pki revoke crl-show ca.crl --format json")]
    CrlShow {
        /// CRL file to display
        file: PathBuf,
    },
}

/// Run revoke command.
pub fn run(cmd: RevokeCommands, config: &GlobalConfig) -> Result<CmdResult> {
    match cmd {
        RevokeCommands::Check {
            file,
            issuer,
            ocsp_only,
            crl_only,
            timeout,
        } => check_revocation(file, issuer, ocsp_only, crl_only, timeout, config),
        RevokeCommands::CrlShow { file } => show_crl(file, config),
    }
}

/// Check certificate revocation status.
fn check_revocation(
    file: PathBuf,
    issuer_file: Option<PathBuf>,
    ocsp_only: bool,
    crl_only: bool,
    timeout: u64,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    // Load certificate
    let cert_data = std::fs::read(&file)
        .with_context(|| format!("Failed to read certificate: {}", file.display()))?;

    let cert_str = String::from_utf8_lossy(&cert_data);
    let cert = Certificate::from_pem(&cert_str)
        .or_else(|_| Certificate::from_der(&cert_data))
        .map_err(|e| anyhow!("Failed to parse certificate: {}", e))?;

    // Load issuer if provided
    let issuer = if let Some(issuer_path) = &issuer_file {
        let issuer_data = std::fs::read(issuer_path).with_context(|| {
            format!(
                "Failed to read issuer certificate: {}",
                issuer_path.display()
            )
        })?;

        let issuer_str = String::from_utf8_lossy(&issuer_data);
        let issuer_cert = Certificate::from_pem(&issuer_str)
            .or_else(|_| Certificate::from_der(&issuer_data))
            .map_err(|e| anyhow!("Failed to parse issuer certificate: {}", e))?;

        Some(issuer_cert)
    } else {
        None
    };

    // Perform revocation check
    let (status, method) = if ocsp_only {
        // OCSP only - requires issuer
        let issuer = issuer
            .as_ref()
            .ok_or_else(|| anyhow!("Issuer certificate required for OCSP check (use --issuer)"))?;

        let checker = OcspChecker::new().with_timeout(std::time::Duration::from_secs(timeout));
        match checker.check(&cert, issuer) {
            Ok(s) => (s, RevocationMethod::Ocsp),
            Err(e) => (
                RevocationStatus::Unknown {
                    reason: e.to_string(),
                },
                RevocationMethod::Ocsp,
            ),
        }
    } else if crl_only {
        // CRL only
        let checker = CrlChecker::new().with_timeout(timeout);
        match checker.check(&cert) {
            Ok(s) => (s, RevocationMethod::Crl),
            Err(e) => (
                RevocationStatus::Unknown {
                    reason: e.to_string(),
                },
                RevocationMethod::Crl,
            ),
        }
    } else {
        // Both OCSP and CRL
        let checker = RevocationChecker::new();
        (
            checker.check(&cert, issuer.as_ref()),
            RevocationMethod::Both,
        )
    };

    // Output result
    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "status": format!("{}", status),
                "method": format!("{}", method),
                "serial": cert.serial,
                "subject": cert.subject,
                "checked_at": chrono::Utc::now().to_rfc3339(),
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Compact => {
            print_revocation_result(&status, &method, &cert, config);
        }
    }

    // Return appropriate exit code
    Ok(CmdResult::ExitCode(status.exit_code()))
}

/// Print revocation result in text format.
fn print_revocation_result(
    status: &RevocationStatus,
    method: &RevocationMethod,
    cert: &Certificate,
    config: &GlobalConfig,
) {
    if !config.quiet {
        println!("{}", "Revocation Check Result".bold());
        println!();
    }

    // Status with color
    let status_str = match status {
        RevocationStatus::Good => "GOOD".green().bold().to_string(),
        RevocationStatus::Revoked { revoked_at, reason } => {
            let mut s = "REVOKED".to_string();
            if let Some(time) = revoked_at {
                s.push_str(&format!(" on {}", time.format("%Y-%m-%d %H:%M:%S UTC")));
            }
            if let Some(r) = reason {
                s.push_str(&format!(" ({})", r));
            }
            s.red().bold().to_string()
        }
        RevocationStatus::Unknown { reason } => {
            format!("UNKNOWN: {}", reason).yellow().bold().to_string()
        }
        RevocationStatus::Error(e) => format!("ERROR: {}", e).red().bold().to_string(),
    };

    println!("  Status:  {status_str}");
    println!("  Subject: {}", cert.subject);
    println!("  Serial:  {}", cert.serial);
    println!("  Method:  {}", method);
    println!();

    // Exit code hint
    if !config.quiet {
        let exit_code = status.exit_code();
        match exit_code {
            0 => println!("{}", "Exit code: 0 (not revoked)".dimmed()),
            1 => println!("{}", "Exit code: 1 (REVOKED)".red()),
            2 => println!("{}", "Exit code: 2 (status unknown)".yellow()),
            3 => println!("{}", "Exit code: 3 (error)".red()),
            _ => println!("Exit code: {exit_code}"),
        }
    }
}

/// Show a local CRL file.
fn show_crl(file: PathBuf, config: &GlobalConfig) -> Result<CmdResult> {
    let crl = load_crl(&file).with_context(|| format!("Failed to load CRL: {}", file.display()))?;

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "issuer": crl.issuer,
                "this_update": crl.this_update.to_rfc3339(),
                "next_update": crl.next_update.map(|d| d.to_rfc3339()),
                "signature_algorithm": crl.signature_algorithm,
                "revoked_count": crl.revoked_count(),
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Compact => {
            println!("{}", "CRL Information".bold());
            println!();
            println!("  Issuer:      {}", crl.issuer);
            println!(
                "  This Update: {}",
                crl.this_update.format("%Y-%m-%d %H:%M:%S UTC")
            );

            if let Some(next_update) = crl.next_update {
                let expired = crl.is_expired();
                let next_str = if expired {
                    format!("{} (EXPIRED)", next_update.format("%Y-%m-%d %H:%M:%S UTC"))
                        .red()
                        .to_string()
                } else {
                    next_update.format("%Y-%m-%d %H:%M:%S UTC").to_string()
                };
                println!("  Next Update: {next_str}");
            }

            println!("  Algorithm:   {}", crl.signature_algorithm);
            println!(
                "  Entries:     {} revoked certificates",
                crl.revoked_count()
            );

            if crl.revoked_count() > 0 && !config.quiet {
                println!();
                println!("{}", "Revoked Certificates:".bold());
                println!();

                // Show up to 20 entries
                let display_count = crl.revoked_certificates.len().min(20);
                for entry in crl.revoked_certificates.iter().take(display_count) {
                    let reason_str = entry
                        .reason
                        .as_ref()
                        .map(|r| format!(" ({})", r))
                        .unwrap_or_default();

                    println!(
                        "  {} - {}{}",
                        entry.serial,
                        entry.revocation_date.format("%Y-%m-%d"),
                        reason_str
                    );
                }

                if crl.revoked_certificates.len() > 20 {
                    println!();
                    println!(
                        "  ... and {} more entries",
                        crl.revoked_certificates.len() - 20
                    );
                }
            }
        }
    }

    Ok(CmdResult::Success)
}
