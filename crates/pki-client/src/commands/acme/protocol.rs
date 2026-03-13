//! ACME protocol operations: register, order, challenges, finalize, download, revoke, directory.

use super::helpers::{create_client, validate_email};
use crate::acme::{AcmeClient, ChallengeType};
use crate::commands::CmdResult;
use crate::config::GlobalConfig;
use anyhow::{Context, Result};
use colored::Colorize;
use pki_client_output::OutputFormat;
use std::path::Path;
use std::time::Duration;

#[allow(clippy::too_many_arguments)]
pub(super) fn register_account(
    email: Option<&str>,
    key_file: &Path,
    agree_tos: bool,
    staging: bool,
    directory: Option<String>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    if let Some(e) = email {
        validate_email(e)?;
    }

    let mut client = create_client(staging, directory, insecure, ca_cert);

    // Load or generate account key
    if key_file.exists() {
        client.load_account_key(key_file)?;
        if !config.quiet {
            println!("Loaded account key from {}", key_file.display());
        }
    } else {
        client.generate_account_key();
        client.save_account_key(key_file)?;
        if !config.quiet {
            println!("Generated new account key: {}", key_file.display());
        }
    }

    let account = client.create_account(email, agree_tos)?;

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "status": format!("{:?}", account.status),
                "contact": account.contact,
                "account_url": client.account_url(),
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            if !config.quiet {
                println!();
                println!("{}", "ACME Account".bold());
                println!();
            }
            println!("  Status:      {:?}", account.status);
            if !account.contact.is_empty() {
                println!("  Contact:     {}", account.contact.join(", "));
            }
            if let Some(url) = client.account_url() {
                println!("  Account URL: {}", url);
            }
            println!("  Key File:    {}", key_file.display());
        }
    }

    Ok(CmdResult::Success)
}

pub(super) fn create_order(
    domains: &[String],
    key_file: &Path,
    staging: bool,
    directory: Option<String>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let mut client = create_client(staging, directory, insecure, ca_cert);
    client.load_account_key(key_file)?;

    // First register/lookup the account
    let _account = client.create_account(None, true)?;

    let (order, order_url) = client.create_order(domains)?;

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "status": format!("{:?}", order.status),
                "order_url": order_url,
                "identifiers": order.identifiers,
                "authorizations": order.authorizations,
                "finalize": order.finalize,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            if !config.quiet {
                println!();
                println!("{}", "ACME Order".bold());
                println!();
            }
            println!("  Status:     {:?}", order.status);
            println!("  Order URL:  {}", order_url);
            println!("  Finalize:   {}", order.finalize);
            println!();
            println!("  {}", "Authorizations:".bold());
            for (i, authz_url) in order.authorizations.iter().enumerate() {
                println!("    [{}] {}", i + 1, authz_url);
            }
            println!();
            println!("Next steps:");
            println!("  1. Get challenges: pki acme challenges <authz_url>");
            println!("  2. Set up challenge response (HTTP or DNS)");
            println!("  3. Respond: pki acme respond <challenge_url>");
            println!(
                "  4. Finalize: pki acme finalize {} -c request.csr",
                order.finalize
            );
        }
    }

    Ok(CmdResult::Success)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn show_challenges(
    url: &str,
    key_file: &Path,
    filter_type: Option<&str>,
    staging: bool,
    directory: Option<String>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let mut client = create_client(staging, directory, insecure, ca_cert);
    client.load_account_key(key_file)?;
    let _account = client.create_account(None, true)?;

    let authz = client.get_authorization(url)?;

    match config.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&authz)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            if !config.quiet {
                println!();
                println!("{}", "Authorization".bold());
                println!();
            }
            println!("  Status:     {:?}", authz.status);
            println!(
                "  Identifier: {} ({})",
                authz.identifier.value, authz.identifier.id_type
            );
            if let Some(wildcard) = authz.wildcard {
                println!("  Wildcard:   {}", wildcard);
            }
            println!();
            println!("  {}", "Challenges:".bold());
            for challenge in &authz.challenges {
                let type_str = format!("{}", challenge.challenge_type);
                if let Some(filter) = filter_type {
                    if !type_str.contains(filter) {
                        continue;
                    }
                }
                println!();
                println!("    Type:   {}", type_str);
                println!("    Status: {:?}", challenge.status);
                println!("    Token:  {}", challenge.token);
                println!("    URL:    {}", challenge.url);

                // Show challenge-specific instructions
                match challenge.challenge_type {
                    ChallengeType::Http01 => {
                        if let Ok(key_authz) = client.key_authorization(&challenge.token) {
                            println!();
                            println!("    HTTP-01 Instructions:");
                            println!("    Serve this content at:");
                            println!(
                                "      http://{}/.well-known/acme-challenge/{}",
                                authz.identifier.value, challenge.token
                            );
                            println!("    Content:");
                            println!("      {}", key_authz);
                        }
                    }
                    ChallengeType::Dns01 => {
                        if let Ok(value) = client.dns_challenge_value(&challenge.token) {
                            println!();
                            println!("    DNS-01 Instructions:");
                            println!("    Create TXT record:");
                            println!("      _acme-challenge.{}", authz.identifier.value);
                            println!("    Value:");
                            println!("      {}", value);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(CmdResult::Success)
}

pub(super) fn show_http_token(
    token: &str,
    key_file: &Path,
    _config: &GlobalConfig,
) -> Result<CmdResult> {
    let mut client = AcmeClient::new("https://example.com");
    client.load_account_key(key_file)?;

    let key_authz = client.key_authorization(token)?;
    println!("{}", key_authz);

    Ok(CmdResult::Success)
}

pub(super) fn show_dns_record(
    token: &str,
    key_file: &Path,
    _config: &GlobalConfig,
) -> Result<CmdResult> {
    let mut client = AcmeClient::new("https://example.com");
    client.load_account_key(key_file)?;

    let value = client.dns_challenge_value(token)?;
    println!("{}", value);

    Ok(CmdResult::Success)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn respond_to_challenge(
    url: &str,
    key_file: &Path,
    timeout: u64,
    staging: bool,
    directory: Option<String>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let mut client = create_client(staging, directory, insecure, ca_cert);
    client.load_account_key(key_file)?;
    let _account = client.create_account(None, true)?;

    if !config.quiet {
        println!("Responding to challenge...");
    }

    client.respond_to_challenge(url)?;

    if !config.quiet {
        println!("Waiting for validation (timeout: {}s)...", timeout);
    }

    let challenge = client.wait_for_challenge(url, Duration::from_secs(timeout))?;

    match config.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&challenge)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            println!();
            println!("Challenge Status: {:?}", challenge.status);
            if challenge.status == crate::acme::ChallengeStatus::Valid {
                println!("{}", "Challenge validated successfully!".green());
            }
        }
    }

    Ok(CmdResult::Success)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finalize_order(
    url: &str,
    csr_path: &std::path::PathBuf,
    key_file: &Path,
    staging: bool,
    directory: Option<String>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let mut client = create_client(staging, directory, insecure, ca_cert);
    client.load_account_key(key_file)?;
    let _account = client.create_account(None, true)?;

    // Load CSR
    let csr_data = std::fs::read(csr_path)
        .with_context(|| format!("Failed to read CSR: {}", csr_path.display()))?;

    // Convert PEM to DER if needed
    let csr_der = if csr_data.starts_with(b"-----BEGIN") {
        let pem = pem::parse(&csr_data).context("Failed to parse CSR PEM")?;
        pem.into_contents()
    } else {
        csr_data
    };

    if !config.quiet {
        println!("Finalizing order...");
    }

    let order = client.finalize_order(url, &csr_der)?;

    match config.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&order)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            println!();
            println!("Order Status: {:?}", order.status);
            if let Some(cert_url) = &order.certificate {
                println!("Certificate URL: {}", cert_url);
                println!();
                println!("Download with: pki acme download {}", cert_url);
            }
        }
    }

    Ok(CmdResult::Success)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn download_cert(
    url: &str,
    output: &std::path::PathBuf,
    key_file: &Path,
    staging: bool,
    directory: Option<String>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let mut client = create_client(staging, directory, insecure, ca_cert);
    client.load_account_key(key_file)?;
    let _account = client.create_account(None, true)?;

    if !config.quiet {
        println!("Downloading certificate...");
    }

    let cert_pem = client.download_certificate(url)?;

    std::fs::write(output, &cert_pem)
        .with_context(|| format!("Failed to write certificate: {}", output.display()))?;

    if !config.quiet {
        println!("{}", "Certificate downloaded successfully!".green());
        println!("Saved to: {}", output.display());
    }

    Ok(CmdResult::Success)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn revoke_cert(
    cert_path: &std::path::PathBuf,
    reason: Option<u8>,
    key_file: &Path,
    staging: bool,
    directory: Option<String>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let mut client = create_client(staging, directory, insecure, ca_cert);
    client.load_account_key(key_file)?;
    let _account = client.create_account(None, true)?;

    // Load certificate
    let cert_data = std::fs::read(cert_path)
        .with_context(|| format!("Failed to read certificate: {}", cert_path.display()))?;

    let cert_der = if cert_data.starts_with(b"-----BEGIN") {
        let pem = pem::parse(&cert_data).context("Failed to parse certificate PEM")?;
        pem.into_contents()
    } else {
        cert_data
    };

    if !config.quiet {
        println!("Revoking certificate...");
    }

    client.revoke_certificate(&cert_der, reason)?;

    if !config.quiet {
        println!("{}", "Certificate revoked successfully!".green());
    }

    Ok(CmdResult::Success)
}

pub(super) fn show_directory(
    staging: bool,
    url: Option<&str>,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let mut client = match url {
        Some(u) => AcmeClient::with_options(u, insecure, ca_cert),
        None if staging => AcmeClient::letsencrypt_staging(),
        None => AcmeClient::letsencrypt(),
    };

    let directory = client.directory()?;

    match config.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(directory)?);
        }
        OutputFormat::Text | OutputFormat::Forensic | OutputFormat::Compact => {
            if !config.quiet {
                println!();
                println!("{}", "ACME Directory".bold());
                println!();
            }
            println!("  New Nonce:   {}", directory.new_nonce);
            println!("  New Account: {}", directory.new_account);
            println!("  New Order:   {}", directory.new_order);
            if let Some(url) = &directory.revoke_cert {
                println!("  Revoke Cert: {}", url);
            }
            if let Some(meta) = &directory.meta {
                println!();
                println!("  {}", "Metadata:".bold());
                if let Some(tos) = &meta.terms_of_service {
                    println!("    Terms of Service: {}", tos);
                }
                if let Some(website) = &meta.website {
                    println!("    Website: {}", website);
                }
            }
        }
    }

    Ok(CmdResult::Success)
}
