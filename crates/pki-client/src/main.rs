#![forbid(unsafe_code)]
//! PKI Client - Modern PKI Operations Tool
//!
//! A modern PKI CLI tool that makes certificate operations human-friendly.
//! Pure Rust PKI for the modern era.

#![allow(clippy::print_literal)]
#![allow(clippy::collapsible_else_if)]

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;

mod acme;
mod commands;
mod compat;
mod config;
mod deployer;
mod est;
mod scep;
mod shell;
mod standalone;
mod util;

use clap_complete::Shell;
use commands::{
    acme as acme_cmd, cert, chain, completions, compliance, convert, crl, csr, dane, diff,
    est as est_cmd, key, pki, probe, revoke, scep as scep_cmd, show, CmdResult,
};
use config::GlobalConfig;
use std::path::PathBuf;

/// PKI - PKI operations made human
///
/// Modern pure Rust PKI operations - no external dependencies.
/// Cleaner output, helpful errors, sane defaults.
#[derive(Parser)]
#[command(name = "pki")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
#[command(after_help = "Examples:
  pki cert show server.pem              Show certificate details
  pki cert expires *.pem --within 30d   Check which certs expire soon
  pki key gen rsa --bits 4096           Generate RSA key
  pki chain build server.pem            Build certificate chain
  pki                                   Enter interactive shell")]
pub struct Cli {
    /// Output format
    #[arg(long, short = 'f', global = true, default_value = "text")]
    format: OutputFormat,

    /// Suppress non-essential output
    #[arg(long, short = 'q', global = true)]
    quiet: bool,

    /// Show verbose output
    #[arg(long, short = 'v', global = true)]
    verbose: bool,

    /// Control color output
    #[arg(long, global = true, default_value = "auto")]
    color: ColorMode,

    /// Enable FIPS-compliant mode (restricts algorithms)
    #[arg(long, global = true)]
    fips: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// Output format options
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum OutputFormat {
    /// Human-readable text with colors
    #[default]
    Text,
    /// JSON output for scripting
    Json,
    /// Compact single-line output
    Compact,
    /// Forensic deep-dive — every field, hex dumps, security notes
    Forensic,
}

impl From<OutputFormat> for pki_client_output::OutputFormat {
    fn from(f: OutputFormat) -> Self {
        match f {
            OutputFormat::Text => Self::Text,
            OutputFormat::Json => Self::Json,
            OutputFormat::Compact => Self::Compact,
            OutputFormat::Forensic => Self::Forensic,
        }
    }
}

/// Color output mode
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ColorMode {
    /// Auto-detect based on terminal
    #[default]
    Auto,
    /// Always use colors
    Always,
    /// Never use colors
    Never,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Quick view of any PKI file (auto-detects type)
    ///
    /// Automatically detects: certificates, CRLs, keys, CSRs, PKCS#7, PKCS#12
    #[command(
        after_help = "Automatically detects file type and shows appropriate output.

Examples:
  pki show server.pem           Show certificate details
  pki show ca.crl               Show CRL details
  pki show private.key          Show key information
  pki show request.csr          Show CSR details"
    )]
    Show {
        /// PKI file (certificate, CRL, key, CSR - auto-detected)
        #[arg(value_name = "FILE")]
        file: PathBuf,

        /// Check revocation status via OCSP/CRL
        #[arg(long, short = 'c')]
        check: bool,

        /// Issuer certificate (for OCSP check)
        #[arg(long, short = 'i', value_name = "ISSUER_FILE")]
        issuer_cert: Option<PathBuf>,

        /// Run security linting checks
        #[arg(long, short = 'l')]
        lint: bool,

        /// Interactive mode - menu-driven exploration
        #[arg(long, short = 'I')]
        interactive: bool,

        /// Full analysis: show all details, lint, and check revocation
        #[arg(long, short = 'a')]
        all: bool,

        /// Skip fetching and displaying certificate chain
        #[arg(long)]
        no_chain: bool,
    },

    /// Certificate operations - view, verify, convert
    #[command(subcommand)]
    Cert(cert::CertCommands),

    /// Private key operations - generate, convert, inspect
    #[command(subcommand)]
    Key(key::KeyCommands),

    /// Certificate chain operations - build, verify, fetch
    #[command(subcommand)]
    Chain(chain::ChainCommands),

    /// CSR operations - create, inspect
    #[command(subcommand)]
    Csr(csr::CsrCommands),

    /// CRL operations - view, check revocation status
    #[command(
        subcommand,
        after_help = "Examples:
  pki crl show myca.crl                   View CRL details
  pki crl show myca.crl --all             List all revoked certs
  pki crl show myca.crl --serial 01AB     Search for serial
  pki crl check myca.crl 01AB             Check if serial is revoked"
    )]
    Crl(crl::CrlCommands),

    /// Revocation checking - OCSP, CRL
    #[command(subcommand)]
    Revoke(revoke::RevokeCommands),

    /// Server probing - TLS inspection and certificate linting
    #[command(subcommand)]
    Probe(probe::ProbeCommands),

    /// ACME client - automatic certificate issuance (Let's Encrypt compatible)
    #[command(
        subcommand,
        after_help = "Examples:
  pki acme register --email admin@example.com    Register account
  pki acme order example.com www.example.com     Create certificate order
  pki acme challenges ORDER_URL                  List pending challenges
  pki acme http-token TOKEN                      Get HTTP-01 response
  pki acme respond CHALLENGE_URL                 Respond to challenge
  pki acme finalize FINALIZE_URL CSR_FILE        Finalize with CSR
  pki acme download CERT_URL -o cert.pem         Download certificate"
    )]
    Acme(acme_cmd::AcmeCommands),

    /// EST client - certificate enrollment over secure transport (RFC 7030)
    #[command(
        subcommand,
        after_help = "Examples:
  pki est cacerts https://est.example.com            Get CA certificates
  pki est enroll https://est.example.com -c req.csr  Enroll with CSR
  pki est reenroll https://est.example.com -c req.csr  Renew certificate
  pki est serverkeygen https://est.example.com -c template.csr  Server keygen
  pki est csrattrs https://est.example.com           Get CSR requirements"
    )]
    Est(est_cmd::EstCommands),

    /// SCEP client - simple certificate enrollment protocol (RFC 8894)
    #[command(
        subcommand,
        after_help = "Examples:
  pki scep cacaps https://scep.example.com/scep     Get CA capabilities
  pki scep cacert https://scep.example.com/scep     Get CA certificate
  pki scep pkiop https://scep.example.com -m req.p7 Send enrollment request"
    )]
    Scep(scep_cmd::ScepCommands),

    /// PKI hierarchy operations — build CA hierarchies from TOML config
    #[command(
        subcommand,
        after_help = "Examples:
  pki pki validate hierarchy.toml          Validate configuration
  pki pki preview hierarchy.toml           Show hierarchy tree
  pki pki build hierarchy.toml             Build all CAs
  pki pki build hierarchy.toml -o ./pki    Build to custom directory"
    )]
    Pki(pki::PkiCommands),

    /// Compliance validation — FIPS 140-3, NIST, Federal Bridge
    ///
    /// Check CA configurations against security level requirements,
    /// show NIST/FIPS/FBCA compliance levels, and generate Federal
    /// Bridge cross-certificate profiles.
    #[command(
        subcommand,
        after_help = "Examples:
  pki compliance check --level 2 --algo ecdsa-p384 --ocsp --auto-crl --audit
  pki compliance levels
  pki compliance bridge --level 3 --dns .quantumnexum.com"
    )]
    Compliance(compliance::ComplianceCommands),

    /// Compare two certificates
    #[command(after_help = "Examples:
  pki diff cert1.pem cert2.pem              Compare two certificates
  pki diff cert1.pem cert2.pem --interactive  Interactive comparison
  pki diff cert1.pem cert2.pem --only-diff    Show only differences
  pki diff cert1.pem cert2.pem --side-by-side Side-by-side view")]
    Diff(diff::DiffArgs),

    /// Convert PKI files between formats
    ///
    /// Auto-detects input type and converts to PEM, DER, or Base64.
    #[command(after_help = "Examples:
  pki convert cert.der -t pem               DER to PEM
  pki convert cert.pem -t der -o cert.der   PEM to DER
  pki convert cert.cer -t base64            Any format to Base64
  pki convert file.crl -t pem               CRL to PEM
  pki convert --from cert input -t der      Force input type")]
    Convert(convert::ConvertArgs),

    /// DANE operations — TLSA record generation and verification (RFC 6698)
    #[command(
        subcommand,
        after_help = "Examples:
  pki dane generate --cert server.pem                    Generate TLSA record
  pki dane generate --cert ca.pem --usage dane-ta        Generate CA TLSA record
  pki dane verify --cert server.pem --rdata '3 1 1 ab..' Verify certificate"
    )]
    Dane(dane::DaneCommands),

    /// Generate shell completions
    #[command(after_help = "Examples:
  pki completions bash > /etc/bash_completion.d/pki
  pki completions zsh > ~/.zfunc/_pki
  pki completions fish > ~/.config/fish/completions/pki.fish")]
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Generate man pages
    #[command(after_help = "Examples:
  pki manpages /usr/local/share/man/man1
  pki manpages ./docs/man")]
    Manpages {
        /// Output directory for man pages
        #[arg(default_value = "./man")]
        output: PathBuf,
    },

    /// Enter interactive shell mode
    Shell,

    /// Run commands from a script file (batch mode)
    ///
    /// Reads commands line-by-line from a file and executes each one.
    /// Errors don't halt execution — all commands run. Comments (#) and
    /// blank lines are skipped.
    #[command(after_help = "Examples:
  pki batch commands.txt              Run all commands from file
  pki batch deploy-certs.txt          Automate certificate deployment")]
    Batch {
        /// Script file containing pki commands (one per line)
        #[arg(value_name = "FILE")]
        file: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Configure colors
    match cli.color {
        ColorMode::Always => colored::control::set_override(true),
        ColorMode::Never => colored::control::set_override(false),
        ColorMode::Auto => {} // Let colored auto-detect
    }

    // Initialize OID registry with optional custom names
    // Checks ~/.config/pki-client/oid-names.toml and /etc/pki-client/oid-names.toml
    let oid_path = dirs::config_dir()
        .map(|p| p.join("pki-client/oid-names.toml"))
        .filter(|p| p.exists())
        .or_else(|| {
            let etc_path = std::path::PathBuf::from("/etc/pki-client/oid-names.toml");
            if etc_path.exists() {
                Some(etc_path)
            } else {
                None
            }
        });
    pki_client_output::init_registry(oid_path.as_deref());

    // Enable FIPS mode if requested
    if cli.fips {
        spork_core::enable_fips_mode();
        if !cli.quiet {
            eprintln!("FIPS 140-3 mode enabled: restricting to approved algorithms");
        }
    }

    let config = GlobalConfig {
        format: cli.format.into(),
        quiet: cli.quiet,
        verbose: cli.verbose,
        colored: !matches!(cli.color, ColorMode::Never),
        fips: cli.fips,
    };

    let result = match cli.command {
        Some(Commands::Show {
            file,
            check,
            issuer_cert,
            lint,
            interactive,
            all,
            no_chain,
        }) => {
            // Auto-detect file type and show appropriate output
            match show::auto_show(&file, &config)? {
                Some(result) => Ok(result),
                None => {
                    // File is a certificate (or unknown), use cert show with full options
                    cert::run(
                        cert::CertCommands::Show(cert::ShowArgs {
                            file,
                            subject: false,
                            san: false,
                            issuer: false,
                            check,
                            issuer_cert,
                            lint,
                            interactive,
                            all,
                            no_chain,
                        }),
                        &config,
                    )
                }
            }
        }
        Some(Commands::Cert(cmd)) => cert::run(cmd, &config),
        Some(Commands::Key(cmd)) => key::run(cmd, &config),
        Some(Commands::Chain(cmd)) => chain::run(cmd, &config),
        Some(Commands::Csr(cmd)) => csr::run(cmd, &config),
        Some(Commands::Crl(cmd)) => crl::run(cmd, &config),
        Some(Commands::Revoke(cmd)) => revoke::run(cmd, &config),
        Some(Commands::Probe(cmd)) => probe::run(cmd, &config),
        Some(Commands::Acme(cmd)) => acme_cmd::run(cmd, &config),
        Some(Commands::Est(cmd)) => est_cmd::run(cmd, &config),
        Some(Commands::Scep(cmd)) => scep_cmd::run(cmd, &config),
        Some(Commands::Pki(cmd)) => pki::run(cmd, &config),
        Some(Commands::Compliance(cmd)) => {
            compliance::execute(cmd)?;
            Ok(CmdResult::Success)
        }
        Some(Commands::Dane(cmd)) => dane::run(cmd, &config),
        Some(Commands::Diff(args)) => diff::run(args, &config),
        Some(Commands::Convert(args)) => convert::run(args, &config),
        Some(Commands::Completions { shell }) => completions::run(shell),
        Some(Commands::Manpages { output }) => completions::generate_manpages(&output),
        Some(Commands::Batch { file }) => shell::run_batch(&file, &config),
        Some(Commands::Shell) | None => shell::run(&config),
    };

    match result {
        Ok(CmdResult::Success) => std::process::exit(0),
        Ok(CmdResult::ExitCode(code)) => std::process::exit(code),
        Err(e) => {
            if !cli.quiet {
                eprintln!("{}: {e}", "error".red().bold());
                // Always show the error chain for helpful messages
                for cause in e.chain().skip(1) {
                    let cause_str = cause.to_string();
                    // Check if this looks like a suggestion (contains "Try:")
                    if cause_str.contains("Try:") {
                        // Split and format nicely
                        for line in cause_str.lines() {
                            if line.starts_with("Try:") {
                                eprintln!("\n{}", line.cyan());
                            } else {
                                eprintln!("{}", line);
                            }
                        }
                    } else {
                        eprintln!("{}: {cause}", "caused by".dimmed());
                    }
                }
            }
            std::process::exit(1)
        }
    }
}

/// Run a CLI command from pre-built args (used by the interactive shell).
///
/// Parses the args as if they were passed on the command line, then dispatches.
/// Does NOT call `std::process::exit` — returns errors for the shell to handle.
pub fn run_from_args(args: &[String], config: &GlobalConfig) -> Result<()> {
    let cli = Cli::try_parse_from(args).map_err(|e| {
        // Print clap's help/error message directly (don't wrap in anyhow)
        let _ = e.print();
        anyhow::anyhow!("") // empty error since clap already printed
    })?;

    let result = match cli.command {
        Some(Commands::Show {
            file,
            check,
            issuer_cert,
            lint,
            interactive,
            all,
            no_chain,
        }) => match show::auto_show(&file, config)? {
            Some(result) => Ok(result),
            None => cert::run(
                cert::CertCommands::Show(cert::ShowArgs {
                    file,
                    subject: false,
                    san: false,
                    issuer: false,
                    check,
                    issuer_cert,
                    lint,
                    interactive,
                    all,
                    no_chain,
                }),
                config,
            ),
        },
        Some(Commands::Cert(cmd)) => cert::run(cmd, config),
        Some(Commands::Key(cmd)) => key::run(cmd, config),
        Some(Commands::Chain(cmd)) => chain::run(cmd, config),
        Some(Commands::Csr(cmd)) => csr::run(cmd, config),
        Some(Commands::Crl(cmd)) => crl::run(cmd, config),
        Some(Commands::Revoke(cmd)) => revoke::run(cmd, config),
        Some(Commands::Probe(cmd)) => probe::run(cmd, config),
        Some(Commands::Acme(cmd)) => acme_cmd::run(cmd, config),
        Some(Commands::Est(cmd)) => est_cmd::run(cmd, config),
        Some(Commands::Scep(cmd)) => scep_cmd::run(cmd, config),
        Some(Commands::Pki(cmd)) => pki::run(cmd, config),
        Some(Commands::Compliance(cmd)) => {
            compliance::execute(cmd)?;
            Ok(CmdResult::Success)
        }
        Some(Commands::Dane(cmd)) => dane::run(cmd, config),
        Some(Commands::Diff(args)) => diff::run(args, config),
        Some(Commands::Convert(args)) => convert::run(args, config),
        Some(Commands::Completions { .. }) | Some(Commands::Manpages { .. }) => {
            Ok(CmdResult::Success)
        }
        Some(Commands::Batch { file }) => shell::run_batch(&file, config),
        Some(Commands::Shell) | None => Ok(CmdResult::Success),
    };

    result.map(|_| ())
}
