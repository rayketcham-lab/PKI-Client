//! Key commands - generate, convert, inspect.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

use crate::compat::{generate_ec, generate_ed25519, generate_rsa, load_private_key, KeyAlgorithm};

use super::CmdResult;
use crate::config::GlobalConfig;

/// Key operations
#[derive(Subcommand)]
pub enum KeyCommands {
    /// Generate a new private key
    ///
    /// Generate RSA, EC, or Ed25519 private keys with secure defaults.
    /// Keys are output in PKCS#8 PEM format.
    #[command(
        name = "gen",
        after_help = "Examples:
  pki key gen ec                       EC P-384 key (recommended)
  pki key gen ec --curve p256          EC P-256 key
  pki key gen ed25519                  Ed25519 key (modern)
  pki key gen rsa                      RSA 4096-bit key
  pki key gen ec -o server.key         Save to file"
    )]
    Gen(GenArgs),

    /// Show key information
    ///
    /// Display key type, size, algorithm, and security assessment.
    #[command(after_help = "Examples:
  pki key show private.key             Show key details
  pki key show private.key --public    Extract public key
  pki key show private.key -f json     JSON output")]
    Show(ShowArgs),

    /// Check if key matches a certificate
    ///
    /// Verify that a private key corresponds to a certificate's public key.
    #[command(
        name = "match",
        after_help = "Examples:
  pki key match server.key server.crt  Check if key matches cert"
    )]
    Match(MatchArgs),
}

/// Arguments for 'key gen' command
#[derive(Args)]
pub struct GenArgs {
    /// Key algorithm: ec, ed25519, rsa
    #[arg(value_name = "ALGORITHM")]
    pub algorithm: String,

    /// RSA key size in bits (3072 or 4096)
    #[arg(long, default_value = "4096")]
    pub bits: u32,

    /// EC curve name (p256, p384)
    #[arg(long, default_value = "p384")]
    pub curve: String,

    /// Output file (stdout if not specified)
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
}

/// Arguments for 'key show' command
#[derive(Args)]
pub struct ShowArgs {
    /// Key file (PEM or DER)
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Output just the public key in PEM format
    #[arg(long)]
    pub public: bool,
}

/// Arguments for 'key match' command
#[derive(Args)]
pub struct MatchArgs {
    /// Private key file
    #[arg(value_name = "KEY")]
    pub key: PathBuf,

    /// Certificate file
    #[arg(value_name = "CERT")]
    pub cert: PathBuf,
}

/// Run a key command.
pub fn run(cmd: KeyCommands, config: &GlobalConfig) -> Result<CmdResult> {
    match cmd {
        KeyCommands::Gen(args) => gen(args, config),
        KeyCommands::Show(args) => show(args, config),
        KeyCommands::Match(args) => key_match(args, config),
    }
}

fn gen(args: GenArgs, config: &GlobalConfig) -> Result<CmdResult> {
    let algo = args.algorithm.to_lowercase();

    let generated = match algo.as_str() {
        "ec" | "ecdsa" => {
            if !config.quiet {
                eprintln!(
                    "{} Generating EC {} key...",
                    "●".cyan(),
                    args.curve.to_uppercase()
                );
            }
            generate_ec(&args.curve)?
        }
        "ed25519" | "eddsa" => {
            if !config.quiet {
                eprintln!("{} Generating Ed25519 key...", "●".cyan());
            }
            generate_ed25519()?
        }
        "rsa" => {
            if args.bits < 2048 {
                anyhow::bail!(
                    "RSA key size {} is too small. Minimum is 2048 bits.\n\
                     Recommended: 3072 or 4096 bits.",
                    args.bits
                );
            }
            if args.bits > 16384 {
                anyhow::bail!(
                    "RSA key size {} is too large. Maximum is 16384 bits.",
                    args.bits
                );
            }
            if args.bits < 3072 && !config.quiet {
                eprintln!(
                    "{} RSA-{} is below recommended minimum of 3072 bits",
                    "⚠".yellow(),
                    args.bits
                );
            }
            if !config.quiet {
                eprintln!("{} Generating RSA-{} key...", "●".cyan(), args.bits);
            }
            generate_rsa(args.bits)?
        }
        other => {
            anyhow::bail!(
                "Unknown algorithm: {}\n\nSupported algorithms:\n  \
                 ec       - ECDSA (P-256 or P-384)\n  \
                 ed25519  - Edwards curve (modern)\n  \
                 rsa      - RSA (3072 or 4096 bits)",
                other
            );
        }
    };

    let pem = generated.to_pem();

    if let Some(output_path) = args.output {
        crate::util::write_sensitive_file(&output_path, pem)
            .with_context(|| format!("Failed to write key to {}", output_path.display()))?;

        if !config.quiet {
            eprintln!(
                "{} Key saved to {} (mode 0600)",
                "✓".green(),
                output_path.display()
            );
            eprintln!("  Algorithm: {}", generated.algorithm);
            eprintln!("  Security:  {}", generated.algorithm.security_level());
        }
    } else {
        // Output to stdout
        print!("{pem}");
    }

    Ok(CmdResult::Success)
}

fn show(args: ShowArgs, config: &GlobalConfig) -> Result<CmdResult> {
    let key = load_private_key(&args.file)
        .with_context(|| format!("Failed to load key: {}", args.file.display()))?;

    if args.public {
        // Extract public key from private key via spork-core
        let pem_data = std::fs::read_to_string(&args.file)
            .with_context(|| format!("Failed to read key file: {}", args.file.display()))?;

        let algo_id = match key.algorithm {
            KeyAlgorithm::EcP256 => spork_core::algo::AlgorithmId::EcdsaP256,
            KeyAlgorithm::EcP384 => spork_core::algo::AlgorithmId::EcdsaP384,
            KeyAlgorithm::Rsa(2048) => spork_core::algo::AlgorithmId::Rsa2048,
            KeyAlgorithm::Rsa(3072) => spork_core::algo::AlgorithmId::Rsa3072,
            KeyAlgorithm::Rsa(_) => spork_core::algo::AlgorithmId::Rsa4096,
            _ => {
                eprintln!(
                    "Public key extraction not supported for {:?}",
                    key.algorithm
                );
                return Ok(CmdResult::Success);
            }
        };

        match spork_core::algo::KeyPair::from_pem(&pem_data, algo_id) {
            Ok(kp) => match kp.public_key_pem() {
                Ok(pub_pem) => {
                    print!("{pub_pem}");
                    return Ok(CmdResult::Success);
                }
                Err(e) => {
                    eprintln!("Failed to extract public key: {}", e);
                    return Ok(CmdResult::Success);
                }
            },
            Err(e) => {
                eprintln!("Failed to parse private key: {}", e);
                return Ok(CmdResult::Success);
            }
        }
    }

    if config.format == pki_client_output::OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&key)?);
    } else {
        println!("{}", "Private Key:".bold().cyan());
        println!("  {}: {}", "Algorithm".bold(), key.algorithm);
        println!("  {}: {} bits", "Size".bold(), key.bits);

        let security = key.security_assessment();
        let security_colored = if security.contains("WEAK") {
            security.red().to_string()
        } else if security.contains("LEGACY") {
            security.yellow().to_string()
        } else {
            security.green().to_string()
        };
        println!("  {}: {}", "Security".bold(), security_colored);

        if key.encrypted {
            println!("  {}: Yes", "Encrypted".bold());
        }

        println!("\n{}: {}", "File".dimmed(), args.file.display());
    }

    Ok(CmdResult::Success)
}

fn key_match(args: MatchArgs, config: &GlobalConfig) -> Result<CmdResult> {
    use crate::compat::{load_certificate, DetectedFileType};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let key = load_private_key(&args.key)
        .with_context(|| format!("Failed to load key: {}", args.key.display()))?;

    // Detect file type before parsing to give clear errors for CSRs
    let cert_data = std::fs::read(&args.cert)
        .with_context(|| format!("Failed to read: {}", args.cert.display()))?;
    let detected = DetectedFileType::detect_with_confidence(&cert_data, &args.cert);
    if detected.file_type == DetectedFileType::Csr {
        anyhow::bail!(
            "{} is a CSR, not a certificate. \
             key match compares a private key against a certificate.\n\
             Try: pki csr show {} to inspect the CSR instead",
            args.cert.display(),
            args.cert.display()
        );
    }

    let cert = load_certificate(&args.cert)
        .with_context(|| format!("Failed to load certificate: {}", args.cert.display()))?;

    let key_algo = match key.algorithm {
        KeyAlgorithm::Rsa(_) => "RSA",
        KeyAlgorithm::EcP256 | KeyAlgorithm::EcP384 => "EC",
        KeyAlgorithm::Ed25519 => "Ed25519",
        KeyAlgorithm::Ed448 => "Ed448",
    };

    let cert_algo = if cert.key_algorithm.contains("1.2.840.113549.1.1") {
        "RSA"
    } else if cert.key_algorithm.contains("1.2.840.10045") {
        "EC"
    } else if cert.key_algorithm.contains("1.3.101.112") {
        "Ed25519"
    } else {
        "Unknown"
    };

    let algo_match = key_algo == cert_algo;

    // Try SPKI pin comparison for a definitive match
    let spki_match = if algo_match && !key.encrypted {
        // Map KeyAlgorithm to AlgorithmId for spork-core
        let algo_id = match key.algorithm {
            KeyAlgorithm::Rsa(bits) if bits >= 4096 => Some(spork_core::algo::AlgorithmId::Rsa4096),
            KeyAlgorithm::Rsa(bits) if bits >= 3072 => Some(spork_core::algo::AlgorithmId::Rsa3072),
            KeyAlgorithm::Rsa(_) => Some(spork_core::algo::AlgorithmId::Rsa2048),
            KeyAlgorithm::EcP256 => Some(spork_core::algo::AlgorithmId::EcdsaP256),
            KeyAlgorithm::EcP384 => Some(spork_core::algo::AlgorithmId::EcdsaP384),
            _ => None,
        };

        if let Some(algo) = algo_id {
            match spork_core::algo::KeyPair::from_pem(&key.pem, algo) {
                Ok(kp) => match kp.public_key_der() {
                    Ok(spki_der) => {
                        let hash = Sha256::digest(&spki_der);
                        let key_pin = B64.encode(hash);
                        Some(key_pin == cert.spki_sha256_b64)
                    }
                    Err(_) => None,
                },
                Err(_) => None,
            }
        } else {
            None
        }
    } else {
        None
    };

    let matched = spki_match.unwrap_or(algo_match);

    if !config.quiet {
        println!("{}", "Key-Certificate Match Check".bold().cyan());
        println!("  Key:  {} ({})", args.key.display(), key.algorithm);
        println!(
            "  Cert: {} ({})",
            args.cert.display(),
            cert.common_name().unwrap_or(&cert.subject)
        );
        println!();

        if !algo_match {
            println!(
                "  {} Algorithm mismatch: key is {}, cert is {}",
                "✗".red(),
                key_algo,
                cert_algo
            );
        } else {
            println!("  {} Algorithm types match ({})", "✓".green(), key_algo);
            match spki_match {
                Some(true) => {
                    println!("  {} Public key match confirmed (SPKI pin)", "✓".green());
                }
                Some(false) => {
                    println!(
                        "  {} Public keys do NOT match (SPKI pin mismatch)",
                        "✗".red()
                    );
                }
                None => {
                    if key.encrypted {
                        println!(
                            "  {} Key is encrypted — cannot verify public key match",
                            "○".yellow()
                        );
                    } else {
                        println!(
                            "  {} Could not extract public key for comparison",
                            "○".yellow()
                        );
                    }
                }
            }
        }
    }

    if matched {
        Ok(CmdResult::Success)
    } else {
        Ok(CmdResult::ExitCode(1))
    }
}
