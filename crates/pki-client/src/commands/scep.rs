//! SCEP Client Commands - RFC 8894
//!
//! Commands for Simple Certificate Enrollment Protocol.

use crate::commands::CmdResult;
use crate::config::GlobalConfig;
use crate::scep::envelope::ScepKeyType;
use crate::scep::{EnrollConfig, ScepClient};
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

    /// Enroll for a certificate via SCEP (RFC 8894).
    ///
    /// Performs automated SCEP enrollment: generates a key pair, builds a CSR,
    /// constructs the PKCS#7 PKCSReq message, submits it, and retrieves the
    /// issued certificate. If the request is pending, polls automatically.
    #[command(after_help = "Examples:
  pki scep enroll https://scep.example.com/scep -s device.corp.example.com
  pki scep enroll https://scep.example.com/scep -s device.corp --challenge secret -o /tmp/certs
  pki scep enroll https://scep.example.com/scep -s host --key-type rsa4096 --san host.example.com")]
    Enroll {
        /// SCEP server URL
        #[arg(value_name = "URL")]
        url: String,

        /// Subject Common Name (CN) for the certificate
        #[arg(long, short = 's', value_name = "CN")]
        subject: String,

        /// Challenge password for enrollment authorization
        #[arg(long, value_name = "PASSWORD")]
        challenge: Option<String>,

        /// Key type: rsa2048 (default), rsa4096, ec-p256
        #[arg(long, default_value = "rsa2048", value_name = "TYPE")]
        key_type: String,

        /// Subject Alternative Name (DNS name, repeatable)
        #[arg(long, value_name = "DNS")]
        san: Vec<String>,

        /// Output directory for certificate and private key files
        #[arg(long, short = 'o', value_name = "DIR")]
        output: Option<PathBuf>,

        /// Seconds between polling attempts when enrollment is pending
        #[arg(long, default_value = "10", value_name = "SECONDS")]
        poll_interval: u64,

        /// Maximum number of polling attempts
        #[arg(long, default_value = "30", value_name = "COUNT")]
        max_polls: u32,

        /// Accept invalid TLS certificates (for self-signed servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Send PKI operation message (enrollment/query).
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
        ScepCommands::Enroll {
            url,
            subject,
            challenge,
            key_type,
            san,
            output,
            poll_interval,
            max_polls,
            insecure,
            ca_cert,
        } => enroll(
            &url,
            &subject,
            challenge.as_deref(),
            &key_type,
            &san,
            output.as_deref(),
            poll_interval,
            max_polls,
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

#[allow(clippy::too_many_arguments)]
fn enroll(
    url: &str,
    subject: &str,
    challenge: Option<&str>,
    key_type_str: &str,
    san_names: &[String],
    output_dir: Option<&Path>,
    poll_interval_secs: u64,
    max_polls: u32,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let key_type: ScepKeyType = key_type_str
        .parse()
        .with_context(|| format!("Invalid key type: {}", key_type_str))?;

    let enroll_config = EnrollConfig {
        subject_cn: subject.to_string(),
        challenge: challenge.map(|s| s.to_string()),
        san_names: san_names.to_vec(),
        key_type,
        poll_interval_secs,
        max_polls,
    };

    if !config.quiet {
        println!("Starting SCEP enrollment for '{}' at {}...", subject, url);
    }

    let client = ScepClient::with_options(url, insecure, ca_cert);
    let response = client
        .enroll(&enroll_config)
        .context("SCEP enrollment failed")?;

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "transaction_id": response.transaction_id,
                "status": response.status.to_string(),
                "certificate": response.certificate,
                "private_key": response.private_key_pem,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            println!("{} SCEP enrollment succeeded!", "Success!".green().bold());
            println!("  Transaction ID: {}", response.transaction_id);

            if let Some(dir) = &output_dir {
                save_enrollment_files(dir, subject, &response)?;
                if !config.quiet {
                    println!(
                        "  Certificate: {}/{}.pem",
                        dir.display(),
                        sanitize_filename(subject)
                    );
                    println!(
                        "  Private key: {}/{}-key.pem",
                        dir.display(),
                        sanitize_filename(subject)
                    );
                }
            } else {
                // Print to stdout
                if let Some(ref cert) = response.certificate {
                    println!("\n{}", cert);
                }
                if !config.quiet {
                    if let Some(ref key) = response.private_key_pem {
                        println!("{}", key);
                    }
                }
            }
        }
    }

    Ok(CmdResult::Success)
}

/// Save certificate and private key to output directory.
fn save_enrollment_files(
    dir: &Path,
    subject: &str,
    response: &crate::scep::EnrollmentResponse,
) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create output directory: {}", dir.display()))?;

    let base = sanitize_filename(subject);

    if let Some(ref cert_pem) = response.certificate {
        let cert_path = dir.join(format!("{}.pem", base));
        std::fs::write(&cert_path, cert_pem)
            .with_context(|| format!("Failed to write certificate: {}", cert_path.display()))?;
    }

    if let Some(ref key_pem) = response.private_key_pem {
        let key_path = dir.join(format!("{}-key.pem", base));
        std::fs::write(&key_path, key_pem)
            .with_context(|| format!("Failed to write private key: {}", key_path.display()))?;

        // Set restrictive permissions on the key file (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&key_path, perms).with_context(|| {
                format!("Failed to set key file permissions: {}", key_path.display())
            })?;
        }
    }

    Ok(())
}

/// Convert a subject CN to a safe filename.
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn format_bool(b: bool) -> colored::ColoredString {
    if b {
        "Yes".green()
    } else {
        "No".red()
    }
}
