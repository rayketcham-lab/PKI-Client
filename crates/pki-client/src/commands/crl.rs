//! CRL (Certificate Revocation List) commands.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

use crate::compat::{load_crl, Crl};

use crate::commands::CmdResult;
use crate::config::GlobalConfig;

/// CRL operations.
#[derive(Subcommand)]
pub enum CrlCommands {
    /// Display CRL details
    Show(ShowArgs),
    /// Check if a serial number is revoked
    Check(CheckArgs),
}

/// Arguments for the show command.
#[derive(Args)]
pub struct ShowArgs {
    /// CRL file (PEM or DER)
    pub file: PathBuf,

    /// Show all revoked certificates
    #[arg(long, short = 'a')]
    pub all: bool,

    /// Show only revoked certificate count
    #[arg(long)]
    pub count_only: bool,

    /// Search for a specific serial number
    #[arg(long, short = 's')]
    pub serial: Option<String>,
}

/// Arguments for the check command.
#[derive(Args)]
pub struct CheckArgs {
    /// CRL file (PEM or DER)
    pub file: PathBuf,

    /// Serial number to check (hex)
    pub serial: String,
}

/// Run a CRL command.
pub fn run(cmd: CrlCommands, _config: &GlobalConfig) -> Result<CmdResult> {
    match cmd {
        CrlCommands::Show(args) => show(args),
        CrlCommands::Check(args) => check(args),
    }
}

fn show(args: ShowArgs) -> Result<CmdResult> {
    let crl = load_crl(&args.file)
        .with_context(|| format!("Failed to load CRL: {}", args.file.display()))?;

    // Count only mode
    if args.count_only {
        println!("{}", crl.revoked_count());
        return Ok(CmdResult::Success);
    }

    // Search for specific serial
    if let Some(ref search_serial) = args.serial {
        let search_upper = search_serial.to_uppercase().replace(":", "");
        let found = crl
            .revoked_certificates
            .iter()
            .find(|rc| rc.serial.replace(":", "").to_uppercase() == search_upper);

        if let Some(entry) = found {
            println!();
            println!(
                "{} {}",
                "✗".red().bold(),
                "REVOKED CERTIFICATE FOUND".red().bold()
            );
            println!();
            println!("    Serial Number:      {}", entry.serial.red().bold());
            println!(
                "    Revocation Date:    {}",
                entry.revocation_date.to_string().white()
            );
            if let Some(ref reason) = entry.reason {
                println!("    Revocation Reason:  {}", reason.yellow());
            }
            if let Some(inv_date) = entry.invalidity_date {
                println!("    Invalidity Date:    {}", inv_date.to_string().white());
            }
            println!();
            return Ok(CmdResult::ExitCode(1)); // Found = revoked
        } else {
            println!();
            println!(
                "{} {} Serial {} is {} in this CRL",
                "✓".green().bold(),
                "OK".green().bold(),
                search_serial.white().bold(),
                "NOT REVOKED".green()
            );
            println!();
            return Ok(CmdResult::Success);
        }
    }

    // Full display
    print_crl_summary(&crl);

    if args.all && !crl.revoked_certificates.is_empty() {
        println!();
        println!(
            "{} {}:",
            "Revoked Certificates".cyan().bold(),
            format!("({} total)", crl.revoked_certificates.len()).dimmed()
        );

        for (i, entry) in crl.revoked_certificates.iter().enumerate() {
            let reason_str = entry.reason.as_deref().unwrap_or("Unspecified");
            let reason_color = match reason_str {
                "Key Compromise" | "CA Compromise" => reason_str.red().to_string(),
                "Superseded" | "Affiliation Changed" => reason_str.yellow().to_string(),
                "Certificate Hold" => reason_str.cyan().to_string(),
                _ => reason_str.white().to_string(),
            };

            println!();
            println!(
                "    {} Serial: {} {}",
                "✗".red(),
                entry.serial.red().bold(),
                format!("[{}]", i + 1).dimmed()
            );
            println!(
                "        Revocation Date:    {}",
                entry.revocation_date.to_string().white()
            );
            println!("        Reason:             {}", reason_color);
            if let Some(inv_date) = entry.invalidity_date {
                println!(
                    "        Invalidity Date:    {}",
                    inv_date.to_string().dimmed()
                );
            }
        }
    }

    Ok(CmdResult::Success)
}

fn check(args: CheckArgs) -> Result<CmdResult> {
    let crl = load_crl(&args.file)
        .with_context(|| format!("Failed to load CRL: {}", args.file.display()))?;

    let search_upper = args.serial.to_uppercase().replace(":", "");
    let found = crl
        .revoked_certificates
        .iter()
        .find(|rc| rc.serial.replace(":", "").to_uppercase() == search_upper);

    if let Some(entry) = found {
        println!();
        println!(
            "{} {} Certificate {} is {}",
            "✗".red().bold(),
            "REVOKED".red().bold(),
            args.serial.white().bold(),
            "REVOKED".red().bold()
        );
        println!();
        println!(
            "    Revocation Date:    {}",
            entry.revocation_date.to_string().white()
        );
        if let Some(ref reason) = entry.reason {
            println!("    Reason:             {}", reason.yellow());
        }
        if let Some(inv_date) = entry.invalidity_date {
            println!("    Invalidity Date:    {}", inv_date.to_string().dimmed());
        }
        println!();
        Ok(CmdResult::ExitCode(1))
    } else {
        println!();
        println!(
            "{} {} Certificate {} is {} in this CRL",
            "✓".green().bold(),
            "OK".green().bold(),
            args.serial.white().bold(),
            "NOT REVOKED".green()
        );
        println!();
        Ok(CmdResult::Success)
    }
}

fn print_crl_summary(crl: &Crl) {
    // Header with color
    println!("{}", "Certificate Revocation List (CRL):".cyan().bold());

    if let Some(v) = crl.version {
        println!(
            "    Version:            {} {}",
            format!("{}", v).white().bold(),
            format!("(0x{:x})", v - 1).dimmed()
        );
    }

    // Signature Algorithm
    println!(
        "    Signature Algorithm: {} {}",
        crl.signature_algorithm.white().bold(),
        format!("({})", crl.signature_oid).dimmed()
    );

    println!();
    println!("{}:", "Issuer".cyan().bold());
    println!("    {}", crl.issuer.white());

    println!();
    println!("{}:", "Validity".cyan().bold());
    println!(
        "    Last Update:        {}",
        crl.this_update.to_string().white()
    );

    if let Some(ref next) = crl.next_update {
        let (status_icon, status_text) = if crl.is_expired() {
            (
                "✗".red().bold().to_string(),
                "EXPIRED".red().bold().to_string(),
            )
        } else if let Some(days) = crl.days_until_next_update() {
            if days < 0 {
                (
                    "✗".red().bold().to_string(),
                    format!("{} days ago - EXPIRED", -days).red().to_string(),
                )
            } else if days < 7 {
                (
                    "⚠".yellow().bold().to_string(),
                    format!("{} days remaining", days).yellow().to_string(),
                )
            } else {
                (
                    "✓".green().bold().to_string(),
                    format!("{} days remaining", days).green().to_string(),
                )
            }
        } else {
            (String::new(), String::new())
        };
        println!("    Next Update:        {}", next.to_string().white());
        if !status_text.is_empty() {
            println!("    Status:             {} {}", status_icon, status_text);
        }
    }

    // CRL Extensions
    if !crl.extensions.is_empty() {
        println!();
        println!("{}:", "CRL Extensions".cyan().bold());

        // CRL Number
        if let Some(ref num) = crl.crl_number {
            println!("    X509v3 CRL Number:  {}", num.green().bold());
        }

        // Authority Key Identifier
        if let Some(ref aki) = crl.authority_key_id {
            println!("    X509v3 Authority Key Identifier:");
            println!("        keyid:{}", aki.yellow());
        }

        // Delta CRL Indicator
        if let Some(ref delta) = crl.delta_crl_indicator {
            println!(
                "    X509v3 Delta CRL Indicator: {}",
                "critical".red().bold()
            );
            println!("        Base CRL #{}", delta.white());
        }

        // Issuing Distribution Point
        if let Some(ref idp) = crl.issuing_dist_point {
            println!("    X509v3 Issuing Distribution Point:");
            println!("        {}", idp.dimmed());
        }

        // Other extensions (Microsoft, etc.)
        for ext in &crl.extensions {
            if ext.name != "CRL Number"
                && ext.name != "Authority Key Identifier"
                && ext.name != "Delta CRL Indicator"
                && ext.name != "Issuing Distribution Point"
            {
                let critical_str = if ext.critical {
                    format!(" {}", "critical".red().bold())
                } else {
                    String::new()
                };
                println!("    {}{}:", ext.name.white(), critical_str);
                println!("        {}", ext.value.dimmed());
            }
        }
    }

    // Revoked Certificates Section
    println!();
    println!("{}:", "Revoked Certificates".cyan().bold());
    if crl.revoked_count() == 0 {
        println!(
            "    {} {}",
            "✓".green().bold(),
            "No Revoked Certificates".green()
        );
    } else {
        println!(
            "    {} {} certificate(s) revoked",
            "✗".red().bold(),
            crl.revoked_count().to_string().red().bold()
        );
        println!();
        println!(
            "    {}",
            "Use --all to list all revoked certificates".dimmed()
        );
        println!(
            "    {}",
            "Use --serial <hex> to search for a specific serial".dimmed()
        );
    }

    // Fingerprints
    println!();
    println!("{}:", "Fingerprints".cyan().bold());
    println!(
        "    SHA-256:            {}",
        crl.fingerprint_sha256.yellow()
    );
    println!("    SHA-1:              {}", crl.fingerprint_sha1.dimmed());

    // Size info
    println!();
    println!(
        "{}:             {} bytes",
        "CRL Size".cyan().bold(),
        crl.raw_der().len().to_string().white().bold()
    );
}
