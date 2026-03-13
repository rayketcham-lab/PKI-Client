//! SCEP Client Commands - RFC 8894
//!
//! Commands for Simple Certificate Enrollment Protocol.

use crate::commands::CmdResult;
use crate::config::GlobalConfig;
use crate::scep::ScepClient;
use anyhow::{Context, Result};
use base64::Engine;
use clap::Subcommand;
use colored::Colorize;
use pki_client_output::OutputFormat;
use std::path::{Path, PathBuf};

/// SCEP client commands.
#[derive(Subcommand)]
pub enum ScepCommands {
    /// Get CA capabilities from SCEP server.
    #[command(after_help = "Examples:
  pki scep cacaps https://scep.example.com/scep
  pki scep cacaps https://scep.example.com/scep -f json")]
    Cacaps {
        /// SCEP server URL
        #[arg(value_name = "URL")]
        url: String,

        /// Accept invalid TLS certificates (for self-signed servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Get CA certificate(s) from SCEP server.
    #[command(after_help = "Examples:
  pki scep cacert https://scep.example.com/scep
  pki scep cacert https://scep.example.com/scep -o ca-cert.pem")]
    Cacert {
        /// SCEP server URL
        #[arg(value_name = "URL")]
        url: String,

        /// Output file for CA certificate(s)
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,

        /// Accept invalid TLS certificates (for self-signed servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Get next CA certificate (for rollover).
    #[command(after_help = "Examples:
  pki scep nextcacert https://scep.example.com/scep
  pki scep nextcacert https://scep.example.com/scep -o next-ca.pem")]
    Nextcacert {
        /// SCEP server URL
        #[arg(value_name = "URL")]
        url: String,

        /// Output file for next CA certificate
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,

        /// Accept invalid TLS certificates (for self-signed servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Send PKI operation message (enrollment/query).
    ///
    /// Note: The message must be a properly formatted PKCS#7 SignedData
    /// containing an enveloped CSR. SCEP message generation is planned
    /// for a future pki-client release.
    #[command(after_help = "Examples:
  pki scep pkiop https://scep.example.com/scep -m request.p7 -o response.p7
  pki scep pkiop https://scep.example.com/scep -m request.p7 --method post")]
    Pkiop {
        /// SCEP server URL
        #[arg(value_name = "URL")]
        url: String,

        /// PKCS#7 message file (DER or PEM)
        #[arg(long, short = 'm', value_name = "FILE")]
        message: PathBuf,

        /// Output file for response
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,

        /// Use POST method (default is GET)
        #[arg(long)]
        post: bool,

        /// Accept invalid TLS certificates (for self-signed servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },
}

/// Run SCEP command.
pub fn run(cmd: ScepCommands, config: &GlobalConfig) -> Result<CmdResult> {
    match cmd {
        ScepCommands::Cacaps {
            url,
            insecure,
            ca_cert,
        } => get_cacaps(&url, insecure, ca_cert.as_deref(), config),
        ScepCommands::Cacert {
            url,
            output,
            insecure,
            ca_cert,
        } => get_cacert(
            &url,
            output.as_deref(),
            insecure,
            ca_cert.as_deref(),
            config,
        ),
        ScepCommands::Nextcacert {
            url,
            output,
            insecure,
            ca_cert,
        } => get_nextcacert(
            &url,
            output.as_deref(),
            insecure,
            ca_cert.as_deref(),
            config,
        ),
        ScepCommands::Pkiop {
            url,
            message,
            output,
            post,
            insecure,
            ca_cert,
        } => pki_operation(
            &url,
            &message,
            output.as_deref(),
            post,
            insecure,
            ca_cert.as_deref(),
            config,
        ),
    }
}

fn get_cacaps(
    url: &str,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    if !config.quiet {
        println!("Fetching CA capabilities from {}...", url);
    }

    let client = ScepClient::with_options(url, insecure, ca_cert);
    let caps = client.get_ca_caps()?;

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "capabilities": caps.capabilities,
                "supports_post": caps.supports_post(),
                "supports_sha256": caps.supports_sha256(),
                "supports_aes": caps.supports_aes(),
                "supports_renewal": caps.supports_renewal(),
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            println!("{}", "CA Capabilities:".bold());
            for cap in &caps.capabilities {
                println!("  - {}", cap);
            }
            println!();
            println!("{}", "Supported Features:".bold());
            println!("  POST PKIOperation: {}", format_bool(caps.supports_post()));
            println!(
                "  SHA-256:           {}",
                format_bool(caps.supports_sha256())
            );
            println!("  AES Encryption:    {}", format_bool(caps.supports_aes()));
            println!(
                "  Renewal:           {}",
                format_bool(caps.supports_renewal())
            );
        }
    }

    Ok(CmdResult::Success)
}

fn get_cacert(
    url: &str,
    output: Option<&Path>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    if !config.quiet {
        println!("Fetching CA certificate(s) from {}...", url);
    }

    let client = ScepClient::with_options(url, insecure, ca_cert);
    let cert_pem = client.get_ca_cert()?;

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "certificate": cert_pem,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            if let Some(out_path) = output {
                std::fs::write(out_path, &cert_pem)
                    .with_context(|| format!("Failed to write: {}", out_path.display()))?;
                println!("CA certificate saved to {}", out_path.display());
            } else {
                println!("{}", cert_pem);
            }
        }
    }

    Ok(CmdResult::Success)
}

fn get_nextcacert(
    url: &str,
    output: Option<&Path>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    if !config.quiet {
        println!("Fetching next CA certificate from {}...", url);
    }

    let client = ScepClient::with_options(url, insecure, ca_cert);
    let cert_pem = client.get_next_ca_cert()?;

    match cert_pem {
        Some(pem) => match config.format {
            OutputFormat::Json => {
                let json = serde_json::json!({
                    "available": true,
                    "certificate": pem,
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
                if let Some(out_path) = output {
                    std::fs::write(out_path, &pem)
                        .with_context(|| format!("Failed to write: {}", out_path.display()))?;
                    println!("Next CA certificate saved to {}", out_path.display());
                } else {
                    println!("{}", pem);
                }
            }
        },
        None => match config.format {
            OutputFormat::Json => {
                let json = serde_json::json!({
                    "available": false,
                });
                println!("{}", serde_json::to_string_pretty(&json)?);
            }
            OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
                println!("No next CA certificate available (no rollover in progress).");
            }
        },
    }

    Ok(CmdResult::Success)
}

fn pki_operation(
    url: &str,
    message_path: &Path,
    output: Option<&Path>,
    use_post: bool,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    if !config.quiet {
        println!(
            "Sending PKI operation to {} via {}...",
            url,
            if use_post { "POST" } else { "GET" }
        );
    }

    let message = ScepClient::load_message(message_path)
        .with_context(|| format!("Failed to load message: {}", message_path.display()))?;

    let client = ScepClient::with_options(url, insecure, ca_cert);
    let response = if use_post {
        client.pki_operation_post(&message)?
    } else {
        client.pki_operation_get(&message)?
    };

    match config.format {
        OutputFormat::Json => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&response);
            let json = serde_json::json!({
                "response_base64": encoded,
                "response_size": response.len(),
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            if let Some(out_path) = output {
                ScepClient::save_response(out_path, &response)?;
                if !config.quiet {
                    println!(
                        "{} Response saved to {} ({} bytes)",
                        "Success!".green().bold(),
                        out_path.display(),
                        response.len()
                    );
                }
            } else {
                // Try to output as PEM
                let pem = pem::Pem::new("PKCS7", response);
                println!("{}", pem::encode(&pem));
            }
        }
    }

    Ok(CmdResult::Success)
}

fn format_bool(b: bool) -> colored::ColoredString {
    if b {
        "Yes".green()
    } else {
        "No".red()
    }
}
