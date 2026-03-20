//! EST Client Commands - RFC 7030
//!
//! Commands for Enrollment over Secure Transport protocol.

use crate::commands::CmdResult;
use crate::config::GlobalConfig;
use crate::est::EstClient;
use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use pki_client_output::OutputFormat;
use std::path::{Path, PathBuf};

/// EST client commands.
#[derive(Subcommand)]
pub enum EstCommands {
    /// Get CA certificates from EST server.
    #[command(after_help = "Examples:
  pki est cacerts https://est.example.com
  pki est cacerts https://est.example.com -o ca-certs.pem")]
    Cacerts {
        /// EST server URL
        #[arg(value_name = "URL")]
        url: String,

        /// Output file for CA certificates
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,

        /// Custom EST label (for `/.well-known/est/<label>/` paths)
        #[arg(long)]
        label: Option<String>,

        /// Accept invalid TLS certificates (for self-signed servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Simple enrollment - request a new certificate.
    #[command(after_help = "Examples:
  pki est enroll https://est.example.com -c request.csr -u admin -p secret
  pki est enroll https://est.example.com -c request.csr -o cert.pem")]
    Enroll {
        /// EST server URL
        #[arg(value_name = "URL")]
        url: String,

        /// CSR file (PEM or DER)
        #[arg(long, short = 'c', value_name = "CSR_FILE")]
        csr: PathBuf,

        /// Output file for certificate
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,

        /// Username for HTTP Basic Auth
        #[arg(long, short = 'u')]
        username: Option<String>,

        /// Password for HTTP Basic Auth
        #[arg(long, short = 'p')]
        password: Option<String>,

        /// Custom EST label
        #[arg(long)]
        label: Option<String>,

        /// Accept invalid TLS certificates (for self-signed servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Re-enrollment - renew an existing certificate.
    #[command(after_help = "Examples:
  pki est reenroll https://est.example.com -c renew.csr -u admin -p secret
  pki est reenroll https://est.example.com -c renew.csr -o renewed.pem")]
    Reenroll {
        /// EST server URL
        #[arg(value_name = "URL")]
        url: String,

        /// CSR file (PEM or DER)
        #[arg(long, short = 'c', value_name = "CSR_FILE")]
        csr: PathBuf,

        /// Output file for certificate
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,

        /// Username for HTTP Basic Auth
        #[arg(long, short = 'u')]
        username: Option<String>,

        /// Password for HTTP Basic Auth
        #[arg(long, short = 'p')]
        password: Option<String>,

        /// Custom EST label
        #[arg(long)]
        label: Option<String>,

        /// Accept invalid TLS certificates (for self-signed servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Server key generation - let server generate the keypair.
    #[command(after_help = "Examples:
  pki est serverkeygen https://est.example.com -c template.csr -u admin -p secret
  pki est serverkeygen https://est.example.com -c template.csr -o cert.pem -k key.pem")]
    Serverkeygen {
        /// EST server URL
        #[arg(value_name = "URL")]
        url: String,

        /// CSR file with subject info (PEM or DER)
        #[arg(long, short = 'c', value_name = "CSR_FILE")]
        csr: PathBuf,

        /// Output file for certificate
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,

        /// Output file for private key
        #[arg(long, short = 'k', value_name = "FILE")]
        key_output: Option<PathBuf>,

        /// Username for HTTP Basic Auth
        #[arg(long, short = 'u')]
        username: Option<String>,

        /// Password for HTTP Basic Auth
        #[arg(long, short = 'p')]
        password: Option<String>,

        /// Custom EST label
        #[arg(long)]
        label: Option<String>,

        /// Accept invalid TLS certificates (for self-signed servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },

    /// Get CSR attributes (template requirements).
    #[command(after_help = "Examples:
  pki est csrattrs https://est.example.com
  pki est csrattrs https://est.example.com -u admin -p secret")]
    Csrattrs {
        /// EST server URL
        #[arg(value_name = "URL")]
        url: String,

        /// Username for HTTP Basic Auth
        #[arg(long, short = 'u')]
        username: Option<String>,

        /// Password for HTTP Basic Auth
        #[arg(long, short = 'p')]
        password: Option<String>,

        /// Custom EST label
        #[arg(long)]
        label: Option<String>,

        /// Accept invalid TLS certificates (for self-signed servers)
        #[arg(long)]
        insecure: bool,

        /// CA certificate for server TLS verification (PEM file)
        #[arg(long, value_name = "FILE")]
        ca_cert: Option<PathBuf>,
    },
}

/// Run EST command.
pub fn run(cmd: EstCommands, config: &GlobalConfig) -> Result<CmdResult> {
    match cmd {
        EstCommands::Cacerts {
            url,
            output,
            label,
            insecure,
            ca_cert,
        } => get_cacerts(
            &url,
            output.as_deref(),
            label,
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        EstCommands::Enroll {
            url,
            csr,
            output,
            username,
            password,
            label,
            insecure,
            ca_cert,
        } => simple_enroll(
            &url,
            &csr,
            output.as_deref(),
            username.as_deref(),
            password.as_deref(),
            label,
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        EstCommands::Reenroll {
            url,
            csr,
            output,
            username,
            password,
            label,
            insecure,
            ca_cert,
        } => simple_reenroll(
            &url,
            &csr,
            output.as_deref(),
            username.as_deref(),
            password.as_deref(),
            label,
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        EstCommands::Serverkeygen {
            url,
            csr,
            output,
            key_output,
            username,
            password,
            label,
            insecure,
            ca_cert,
        } => server_keygen(
            &url,
            &csr,
            output.as_deref(),
            key_output.as_deref(),
            username.as_deref(),
            password.as_deref(),
            label,
            insecure,
            ca_cert.as_deref(),
            config,
        ),

        EstCommands::Csrattrs {
            url,
            username,
            password,
            label,
            insecure,
            ca_cert,
        } => get_csrattrs(
            &url,
            username.as_deref(),
            password.as_deref(),
            label,
            insecure,
            ca_cert.as_deref(),
            config,
        ),
    }
}

fn create_client(
    url: &str,
    username: Option<&str>,
    password: Option<&str>,
    label: Option<String>,
    insecure: bool,
    ca_cert: Option<&Path>,
) -> EstClient {
    let mut client = EstClient::with_options(url, insecure, ca_cert);

    if let (Some(u), Some(p)) = (username, password) {
        client = client.with_basic_auth(u, p);
    }

    if let Some(l) = label {
        client = client.with_label(&l);
    }

    client
}

fn get_cacerts(
    url: &str,
    output: Option<&Path>,
    label: Option<String>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    if !config.quiet {
        println!("Fetching CA certificates from {}...", url);
    }

    let client = create_client(url, None, None, label, insecure, ca_cert);
    let certs = client.get_ca_certs()?;

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "certificates": certs,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            if let Some(out_path) = output {
                EstClient::save_cert(out_path, &certs)?;
                println!("CA certificates saved to {}", out_path.display());
            } else {
                println!("{}", certs);
            }
        }
    }

    Ok(CmdResult::Success)
}

#[allow(clippy::too_many_arguments)]
fn simple_enroll(
    url: &str,
    csr_path: &Path,
    output: Option<&Path>,
    username: Option<&str>,
    password: Option<&str>,
    label: Option<String>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    if !config.quiet {
        println!("Requesting certificate enrollment from {}...", url);
    }

    let csr_data = EstClient::load_csr(csr_path)
        .with_context(|| format!("Failed to load CSR: {}", csr_path.display()))?;

    let client = create_client(url, username, password, label, insecure, ca_cert);
    let cert = client.simple_enroll(&csr_data)?;

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "certificate": cert,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            if let Some(out_path) = output {
                EstClient::save_cert(out_path, &cert)?;
                if !config.quiet {
                    println!(
                        "{} Certificate saved to {}",
                        "Success!".green().bold(),
                        out_path.display()
                    );
                }
            } else {
                println!("{}", cert);
            }
        }
    }

    Ok(CmdResult::Success)
}

#[allow(clippy::too_many_arguments)]
fn simple_reenroll(
    url: &str,
    csr_path: &Path,
    output: Option<&Path>,
    username: Option<&str>,
    password: Option<&str>,
    label: Option<String>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    if !config.quiet {
        println!("Requesting certificate re-enrollment from {}...", url);
    }

    let csr_data = EstClient::load_csr(csr_path)
        .with_context(|| format!("Failed to load CSR: {}", csr_path.display()))?;

    let client = create_client(url, username, password, label, insecure, ca_cert);
    let cert = client.simple_reenroll(&csr_data)?;

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "certificate": cert,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            if let Some(out_path) = output {
                EstClient::save_cert(out_path, &cert)?;
                if !config.quiet {
                    println!(
                        "{} Renewed certificate saved to {}",
                        "Success!".green().bold(),
                        out_path.display()
                    );
                }
            } else {
                println!("{}", cert);
            }
        }
    }

    Ok(CmdResult::Success)
}

#[allow(clippy::too_many_arguments)]
fn server_keygen(
    url: &str,
    csr_path: &Path,
    cert_output: Option<&Path>,
    key_output: Option<&Path>,
    username: Option<&str>,
    password: Option<&str>,
    label: Option<String>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    if !config.quiet {
        println!("Requesting server key generation from {}...", url);
    }

    let csr_data = EstClient::load_csr(csr_path)
        .with_context(|| format!("Failed to load CSR: {}", csr_path.display()))?;

    let client = create_client(url, username, password, label, insecure, ca_cert);
    let response = client.server_keygen(&csr_data)?;

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "certificate": response.certificate,
                "private_key": response.private_key,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            if let Some(cert_path) = cert_output {
                EstClient::save_cert(cert_path, &response.certificate)?;
                if !config.quiet {
                    println!("Certificate saved to {}", cert_path.display());
                }
            } else {
                println!("--- Certificate ---");
                println!("{}", response.certificate);
            }

            if let Some(key_path) = key_output {
                crate::util::write_sensitive_file(key_path, &response.private_key).with_context(
                    || format!("Failed to write private key: {}", key_path.display()),
                )?;

                if !config.quiet {
                    println!("Private key saved to {}", key_path.display());
                }
            } else {
                println!("--- Private Key ---");
                println!("{}", response.private_key);
            }

            if !config.quiet && (cert_output.is_some() || key_output.is_some()) {
                println!("{}", "Success!".green().bold());
            }
        }
    }

    Ok(CmdResult::Success)
}

fn get_csrattrs(
    url: &str,
    username: Option<&str>,
    password: Option<&str>,
    label: Option<String>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    if !config.quiet {
        println!("Fetching CSR attributes from {}...", url);
    }

    let client = create_client(url, username, password, label, insecure, ca_cert);
    let attrs = client.get_csr_attrs()?;

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "csr_attributes": attrs,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => match attrs {
            Some(a) => {
                println!("{}", "CSR Attributes:".bold());
                println!("{}", a);
            }
            None => {
                println!("No CSR attributes required by server.");
            }
        },
    }

    Ok(CmdResult::Success)
}
