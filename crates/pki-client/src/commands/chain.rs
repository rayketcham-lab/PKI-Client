//! Chain commands - build, verify, display.

use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use std::path::Path;

use crate::compat::{load_certificate, Certificate, ChainBuilder, ChainValidation, TrustStore};

use super::CmdResult;
use crate::config::GlobalConfig;

/// Chain operations
#[derive(Subcommand)]
pub enum ChainCommands {
    /// Build a certificate chain
    ///
    /// Automatically find and assemble the certificate chain from leaf to root,
    /// fetching missing intermediates via AIA if needed.
    #[command(after_help = "Examples:
  pki chain build server.pem              Build chain from server cert
  pki chain build server.pem --output chain.pem  Save chain to file
  pki chain build server.pem --no-fetch   Don't fetch from network")]
    Build {
        /// Certificate file
        file: String,

        /// Output file for the chain
        #[arg(long, short = 'o')]
        output: Option<String>,

        /// Don't fetch missing certs from network
        #[arg(long)]
        no_fetch: bool,

        /// Custom CA bundle for trust
        #[arg(long)]
        ca: Option<String>,
    },

    /// Show certificate chain
    ///
    /// Display the certificate chain as an ASCII tree.
    #[command(after_help = "Examples:
  pki chain show chain.pem               Show chain as tree
  pki chain show chain.pem --verify      Verify signatures")]
    Show {
        /// Chain file (PEM bundle)
        file: String,

        /// Verify chain signatures
        #[arg(long)]
        verify: bool,
    },

    /// Verify certificate chain
    ///
    /// Validate chain integrity and trust.
    #[command(after_help = "Examples:
  pki chain verify server.pem            Verify against system trust store
  pki chain verify server.pem --ca ca.pem  Verify against custom CA")]
    Verify {
        /// Certificate or chain file
        file: String,

        /// Custom CA certificate
        #[arg(long)]
        ca: Option<String>,

        /// Don't check revocation status
        #[arg(long)]
        no_revocation: bool,

        /// Don't check certificate validity periods (useful for clock-skewed certs)
        #[arg(long)]
        no_check_time: bool,
    },
}

/// Run a chain command.
pub fn run(cmd: ChainCommands, config: &GlobalConfig) -> Result<CmdResult> {
    match cmd {
        ChainCommands::Build {
            file,
            output,
            no_fetch,
            ca,
        } => build_chain(&file, output.as_deref(), no_fetch, ca.as_deref(), config),
        ChainCommands::Show { file, verify } => show_chain(&file, verify, config),
        ChainCommands::Verify {
            file,
            ca,
            no_revocation: _,
            no_check_time,
        } => verify_chain(&file, ca.as_deref(), no_check_time, config),
    }
}

fn build_chain(
    file: &str,
    output: Option<&str>,
    no_fetch: bool,
    ca: Option<&str>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let cert = load_certificate(Path::new(file))
        .with_context(|| format!("Failed to load certificate: {file}"))?;

    if !config.quiet {
        println!("{}", "Building certificate chain...".cyan());
        println!("  Leaf: {}", cert.subject);
    }

    // Build chain builder
    let mut builder = ChainBuilder::new().follow_aia(!no_fetch);

    // Load trust store
    if let Some(ca_path) = ca {
        builder = builder
            .with_trust_bundle(Path::new(ca_path))
            .with_context(|| format!("Failed to load CA bundle: {ca_path}"))?;
    } else {
        match builder.clone().with_system_trust() {
            Ok(b) => builder = b,
            Err(e) => {
                if !config.quiet {
                    eprintln!(
                        "{} Could not load system trust store: {e}",
                        "Warning:".yellow()
                    );
                }
            }
        }
    }

    // Build the chain
    let result = builder
        .build(&cert)
        .with_context(|| "Failed to build certificate chain")?;

    // Print results
    if !config.quiet {
        println!();
        println!("{}", "Chain:".bold().cyan());
        print_chain_tree(&result.chain);

        if !result.warnings.is_empty() {
            println!();
            println!("{}", "Warnings:".yellow());
            for warning in &result.warnings {
                println!("  {} {}", "⚠".yellow(), warning);
            }
        }

        println!();
        if result.trusted {
            println!("  {} Chain terminates at trusted root", "✓".green());
        } else {
            println!("  {} Chain does not terminate at trusted root", "✗".red());
        }
    }

    // Write output if requested
    if let Some(output_path) = output {
        let mut pem_output = String::new();
        for cert in &result.chain {
            let pem = ::pem::Pem::new("CERTIFICATE", cert.raw_der().to_vec());
            pem_output.push_str(&::pem::encode(&pem));
        }
        std::fs::write(output_path, &pem_output)
            .with_context(|| format!("Failed to write chain to: {output_path}"))?;

        if !config.quiet {
            println!("  {} Chain saved to {}", "✓".green(), output_path);
        }
    }

    if result.trusted {
        Ok(CmdResult::Success)
    } else {
        Ok(CmdResult::ExitCode(4)) // Validation failure
    }
}

fn show_chain(file: &str, verify: bool, config: &GlobalConfig) -> Result<CmdResult> {
    let data = std::fs::read(file).with_context(|| format!("Failed to read: {file}"))?;
    let data_str = String::from_utf8_lossy(&data);

    let certs = Certificate::all_from_pem(&data_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse certificates from {file}: {e}"))?;

    if certs.is_empty() {
        println!("{}", "No certificates found in file".red());
        return Ok(CmdResult::ExitCode(3));
    }

    if !config.quiet {
        println!(
            "{}",
            format!("Certificate Chain ({} certificates)", certs.len())
                .bold()
                .cyan()
        );
        println!();
    }

    print_chain_tree(&certs);

    if verify {
        println!();
        println!("{}", "Validation:".bold().cyan());

        let mut store = TrustStore::new();
        let _ = store.load_system(); // Best effort

        let validation = ChainValidation::new().with_trust_store(store);
        let result = validation.validate(&certs);

        if result.valid {
            println!("  {} Chain is valid", "✓".green());
        } else {
            println!("  {} Chain validation failed:", "✗".red());
            for err in &result.errors {
                println!("    {} {}", "•".red(), err);
            }
        }

        for warning in &result.warnings {
            println!("  {} {}", "⚠".yellow(), warning);
        }

        if !result.valid {
            return Ok(CmdResult::ExitCode(4));
        }
    }

    Ok(CmdResult::Success)
}

fn verify_chain(
    file: &str,
    ca: Option<&str>,
    no_check_time: bool,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let data = std::fs::read(file).with_context(|| format!("Failed to read: {file}"))?;
    let data_str = String::from_utf8_lossy(&data);

    let certs = Certificate::all_from_pem(&data_str)
        .or_else(|_| {
            // Try as single certificate
            load_certificate(Path::new(file))
                .map(|c| vec![c])
                .map_err(|e| e.to_string())
        })
        .map_err(|e| anyhow::anyhow!("Failed to parse certificates from {file}: {e}"))?;

    if certs.is_empty() {
        println!("{}", "No certificates found in file".red());
        return Ok(CmdResult::ExitCode(3));
    }

    if !config.quiet {
        println!("{}", "Verifying certificate chain...".cyan());
    }

    // Load trust store
    let mut store = TrustStore::new();
    if let Some(ca_path) = ca {
        store
            .load_pem_bundle(Path::new(ca_path))
            .with_context(|| format!("Failed to load CA bundle: {ca_path}"))?;
    } else {
        match store.load_system() {
            Ok(()) => {
                if !config.quiet {
                    println!("  Loaded system root certificates");
                }
            }
            Err(e) => {
                if !config.quiet {
                    eprintln!(
                        "{} Could not load system trust store: {e}",
                        "Warning:".yellow()
                    );
                }
            }
        }
    }

    let mut validation = ChainValidation::new().with_trust_store(store);
    if no_check_time {
        validation = validation.skip_time_check();
    }
    let result = validation.validate(&certs);

    println!();
    if result.valid {
        println!("  {} Certificate chain is valid", "✓".green());
        if let Some(root) = &result.trusted_root {
            println!("  {} Trusted root: {}", "✓".green(), root.subject);
        }
    } else {
        println!("  {} Certificate chain validation failed:", "✗".red());
        for err in &result.errors {
            println!("    {} {}", "•".red(), err);
        }
    }

    for warning in &result.warnings {
        println!("  {} {}", "⚠".yellow(), warning);
    }

    if result.valid {
        Ok(CmdResult::Success)
    } else {
        Ok(CmdResult::ExitCode(4))
    }
}

/// Print a certificate chain as an ASCII tree.
fn print_chain_tree(chain: &[Certificate]) {
    for (i, cert) in chain.iter().enumerate() {
        let is_last = i == chain.len() - 1;
        let prefix = if i == 0 {
            "".to_string()
        } else {
            "  ".repeat(i)
        };

        let connector = if i == 0 {
            "◉"
        } else if is_last {
            "└── ◯"
        } else {
            "├── ○"
        };

        let status = if cert.is_expired() {
            " [EXPIRED]".red().to_string()
        } else if cert.is_self_signed() {
            " [ROOT]".blue().to_string()
        } else if cert.is_ca {
            " [CA]".yellow().to_string()
        } else {
            String::new()
        };

        println!(
            "{}{} {}{}",
            prefix,
            connector.cyan(),
            cert.subject.bold(),
            status
        );

        // Show key info
        if i == 0 {
            let key_info = format!("    {} ({} bits)", cert.key_algorithm, cert.key_size);
            println!("{}", key_info.dimmed());
        }
    }
}
