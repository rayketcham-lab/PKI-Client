//! CSR commands - create, show, verify.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

use crate::compat::{load_csr, load_private_key, CsrBuilder};

use super::CmdResult;
use crate::config::GlobalConfig;

/// Lightweight CSR output for both classical and PQC paths.
struct CsrOutput {
    pem: String,
}

/// Map PQC algorithm name to spork-core AlgorithmId.
/// Returns None for non-PQC algorithms (classical path handles those).
fn pqc_algorithm_id(name: &str) -> Option<spork_core::AlgorithmId> {
    match name.to_lowercase().as_str() {
        #[cfg(feature = "pqc")]
        "ml-dsa-44" => Some(spork_core::AlgorithmId::MlDsa44),
        #[cfg(feature = "pqc")]
        "ml-dsa-65" => Some(spork_core::AlgorithmId::MlDsa65),
        #[cfg(feature = "pqc")]
        "ml-dsa-87" => Some(spork_core::AlgorithmId::MlDsa87),
        #[cfg(feature = "pqc")]
        "slh-dsa-128s" => Some(spork_core::AlgorithmId::SlhDsaSha2_128s),
        #[cfg(feature = "pqc")]
        "slh-dsa-192s" => Some(spork_core::AlgorithmId::SlhDsaSha2_192s),
        #[cfg(feature = "pqc")]
        "slh-dsa-256s" => Some(spork_core::AlgorithmId::SlhDsaSha2_256s),
        _ => None,
    }
}

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
    Create(Box<CreateArgs>),

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

    /// Key algorithm override (required for PQC keys)
    ///
    /// PQC keys cannot be auto-detected from the key file.
    /// Specify: ml-dsa-44, ml-dsa-65, ml-dsa-87, slh-dsa-128s, slh-dsa-192s, slh-dsa-256s
    #[arg(long, value_name = "ALGO")]
    pub algorithm: Option<String>,

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
        CsrCommands::Create(args) => create(*args, config),
        CsrCommands::Show(args) => show(args, config),
    }
}

fn create(args: CreateArgs, config: &GlobalConfig) -> Result<CmdResult> {
    // Determine if this is a PQC CSR (--algorithm specified)
    let pqc_algo = args.algorithm.as_deref().and_then(pqc_algorithm_id);

    let algo_display: String;
    let csr;

    if let Some(algo_id) = pqc_algo {
        // PQC path: load key PEM directly, use spork-core KeyPair
        let key_pem = std::fs::read_to_string(&args.key)
            .with_context(|| format!("Failed to read key: {}", args.key.display()))?;
        algo_display = args.algorithm.as_ref().unwrap().to_uppercase();

        if !config.quiet {
            eprintln!(
                "{} Creating CSR for {} using {} key...",
                "●".cyan(),
                args.cn.green(),
                algo_display.cyan(),
            );
        }

        let key_pair = spork_core::KeyPair::from_pem(&key_pem, algo_id)
            .with_context(|| "Failed to parse PQC private key")?;

        let mut name_builder = spork_core::NameBuilder::new(&args.cn);
        if let Some(ref org) = args.org {
            name_builder = name_builder.organization(org);
        }
        if let Some(ref country) = args.country {
            name_builder = name_builder.country(country);
        }

        let request = spork_core::CsrBuilder::new(name_builder.build())
            .build_and_sign(&key_pair)
            .with_context(|| "Failed to build and sign PQC CSR")?;

        csr = CsrOutput {
            pem: request.to_pem(),
        };
    } else {
        // Classical path: auto-detect algorithm from key file
        let key = load_private_key(&args.key)
            .with_context(|| format!("Failed to load key: {}", args.key.display()))?;
        algo_display = key.algorithm.to_string();

        if !config.quiet {
            eprintln!(
                "{} Creating CSR for {} using {} key...",
                "●".cyan(),
                args.cn.green(),
                algo_display,
            );
        }

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
        builder = builder.add_dns_san(&args.cn);

        for san in &args.san {
            if let Some((san_type, san_value)) = san.split_once(':') {
                match san_type.to_lowercase().as_str() {
                    "dns" => builder = builder.add_dns_san(san_value),
                    "ip" => builder = builder.add_ip_san(san_value),
                    "email" => builder = builder.add_email_san(san_value),
                    _ => builder = builder.add_dns_san(san),
                }
            } else {
                builder = builder.add_dns_san(san);
            }
        }

        let built = builder.build_with_key(&key)?;
        csr = CsrOutput { pem: built.pem };
    };

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
