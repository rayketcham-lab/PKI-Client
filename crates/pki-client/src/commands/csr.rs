//! CSR commands - create, show, verify.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

use crate::compat::{load_csr, load_private_key, CsrBuilder};

use super::CmdResult;
use crate::config::GlobalConfig;

/// CSR operations
#[derive(Subcommand)]
pub enum CsrCommands {
    /// Create a Certificate Signing Request
    ///
    /// Generate a CSR from a private key with the specified subject and SANs.
    #[command(
        name = "create",
        after_help = "Examples:
  pki csr create --key server.key --cn example.com
  pki csr create --key server.key --cn example.com --san dns:www.example.com
  pki csr create --key server.key --cn example.com -o server.csr
  pki csr create --key server.key --cn example.com --org \"My Company\" --country US"
    )]
    Create(CreateArgs),

    /// Show CSR details
    ///
    /// Display the contents of a Certificate Signing Request.
    #[command(after_help = "Examples:
  pki csr show server.csr              Show CSR details
  pki csr show server.csr -f json      JSON output")]
    Show(ShowArgs),
}

/// Arguments for 'csr create' command
#[derive(Args)]
pub struct CreateArgs {
    /// Private key file
    #[arg(long, short = 'k', value_name = "FILE")]
    pub key: PathBuf,

    /// Common Name (CN) - usually the domain name
    #[arg(long, value_name = "NAME")]
    pub cn: String,

    /// Organization (O)
    #[arg(long, value_name = "ORG")]
    pub org: Option<String>,

    /// Organizational Unit (OU)
    #[arg(long, value_name = "UNIT")]
    pub ou: Option<String>,

    /// Country (C) - two letter code
    #[arg(long, value_name = "CODE")]
    pub country: Option<String>,

    /// State/Province (ST)
    #[arg(long, value_name = "STATE")]
    pub state: Option<String>,

    /// Locality/City (L)
    #[arg(long, value_name = "CITY")]
    pub locality: Option<String>,

    /// Subject Alternative Names (can be repeated)
    /// Format: dns:example.com, ip:192.168.1.1, email:user@example.com
    #[arg(long, value_name = "SAN")]
    pub san: Vec<String>,

    /// Output file (stdout if not specified)
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<PathBuf>,
}

/// Arguments for 'csr show' command
#[derive(Args)]
pub struct ShowArgs {
    /// CSR file (PEM or DER)
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// Run a CSR command.
pub fn run(cmd: CsrCommands, config: &GlobalConfig) -> Result<CmdResult> {
    match cmd {
        CsrCommands::Create(args) => create(args, config),
        CsrCommands::Show(args) => show(args, config),
    }
}

fn create(args: CreateArgs, config: &GlobalConfig) -> Result<CmdResult> {
    // Load the private key
    let key = load_private_key(&args.key)
        .with_context(|| format!("Failed to load key: {}", args.key.display()))?;

    if !config.quiet {
        eprintln!(
            "{} Creating CSR for {} using {} key...",
            "●".cyan(),
            args.cn.green(),
            key.algorithm
        );
    }

    // Build the CSR
    let mut builder = CsrBuilder::new().common_name(&args.cn);

    if let Some(org) = &args.org {
        builder = builder.organization(org);
    }
    if let Some(ou) = &args.ou {
        builder = builder.organizational_unit(ou);
    }
    if let Some(country) = &args.country {
        builder = builder.country(country);
    }
    if let Some(state) = &args.state {
        builder = builder.state(state);
    }
    if let Some(locality) = &args.locality {
        builder = builder.locality(locality);
    }

    // Add SANs
    // Always add CN as a DNS SAN (best practice)
    builder = builder.add_dns_san(&args.cn);

    for san in &args.san {
        // Parse SAN format: type:value (e.g., dns:example.com, ip:192.168.1.1)
        if let Some((san_type, san_value)) = san.split_once(':') {
            match san_type.to_lowercase().as_str() {
                "dns" => builder = builder.add_dns_san(san_value),
                "ip" => builder = builder.add_ip_san(san_value),
                "email" => builder = builder.add_email_san(san_value),
                _ => builder = builder.add_dns_san(san), // Default to DNS
            }
        } else {
            // No type prefix - assume DNS
            builder = builder.add_dns_san(san);
        }
    }

    let csr = builder.build_with_key(&key)?;

    // Output the CSR
    if let Some(output_path) = args.output {
        std::fs::write(&output_path, &csr.pem)
            .with_context(|| format!("Failed to write CSR to {}", output_path.display()))?;

        if !config.quiet {
            eprintln!("{} CSR saved to {}", "✓".green(), output_path.display());
            eprintln!("  Subject: CN={}", args.cn);
            if !args.san.is_empty() {
                eprintln!("  SANs: {}", args.san.join(", "));
            }
        }
    } else {
        print!("{}", csr.pem);
    }

    Ok(CmdResult::Success)
}

fn show(args: ShowArgs, config: &GlobalConfig) -> Result<CmdResult> {
    let csr = load_csr(&args.file)
        .with_context(|| format!("Failed to load CSR: {}", args.file.display()))?;

    if config.format == pki_client_output::OutputFormat::Json {
        // Build a JSON representation manually since Csr doesn't implement Serialize
        let json = serde_json::json!({
            "subject": csr.subject,
            "key_algorithm": csr.key_algorithm,
            "key_size": csr.key_size,
            "signature_algorithm": csr.signature_algorithm,
            "san": csr.san,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        println!("{}", "Certificate Signing Request:".bold().cyan());
        println!("  {}: {}", "Subject".bold(), csr.subject);

        // Extract CN from subject string
        if let Some(cn) = csr.subject.split(", ").find_map(|p| p.strip_prefix("CN=")) {
            println!("  {}: {}", "Common Name".bold(), cn.green());
        }

        println!("\n{}", "Public Key:".bold().cyan());
        println!("  {}: {}", "Algorithm".bold(), csr.key_algorithm);
        if let Some(size) = csr.key_size {
            if size > 0 {
                println!("  {}: {} bits", "Size".bold(), size);
            }
        }

        println!("\n{}", "Signature:".bold().cyan());
        println!("  {}: {}", "Algorithm".bold(), csr.signature_algorithm);

        if !csr.san.is_empty() {
            println!("\n{}", "Subject Alternative Names:".bold().cyan());
            for san in &csr.san {
                println!("  - {}", san.blue());
            }
        }

        println!("\n{}: {}", "File".dimmed(), args.file.display());
    }

    Ok(CmdResult::Success)
}
