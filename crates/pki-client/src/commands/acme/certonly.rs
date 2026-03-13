//! ACME certonly command — full ACME flow: register, order, challenge, finalize, download.

use super::csr::generate_csr_der;
use super::helpers::{
    default_account_key_path, generate_domain_key, pki_certs_dir, validate_email, RenewalConfig,
};
use crate::acme::{AcmeClient, ChallengeType};
use crate::commands::CmdResult;
use crate::config::GlobalConfig;
use crate::standalone::{self, StandaloneServer};
use anyhow::{anyhow, Result};
use colored::Colorize;
use pki_client_output::OutputFormat;
use std::fs;
use std::path::Path;
use std::time::Duration;

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_certonly(
    domains: &[String],
    server: &str,
    email: Option<&str>,
    webroot: Option<&Path>,
    standalone: bool,
    dns: bool,
    output_dir: Option<&Path>,
    agree_tos: bool,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    if let Some(e) = email {
        validate_email(e)?;
    }

    let primary_domain = domains
        .first()
        .ok_or_else(|| anyhow!("At least one domain is required"))?;

    // Validate all domain names
    for d in domains {
        if !standalone::is_valid_domain(d) {
            return Err(anyhow!(
                "Invalid domain name: '{}'. Only letters, digits, hyphens, dots, and wildcards are allowed.",
                d
            ));
        }
    }

    // Determine output directory
    let cert_dir = match output_dir {
        Some(dir) => dir.to_path_buf(),
        None => pki_certs_dir()?.join(primary_domain),
    };
    fs::create_dir_all(&cert_dir)?;

    // Standalone server (started on demand, stopped after validation)
    let mut standalone_server: Option<StandaloneServer> = None;

    // Load or generate account key
    let account_key_path = default_account_key_path()?;
    let mut client = AcmeClient::with_options(server, insecure, ca_cert);

    if account_key_path.exists() {
        client.load_account_key(&account_key_path)?;
        if !config.quiet {
            println!("Loaded account key from {}", account_key_path.display());
        }
    } else {
        client.generate_account_key();
        client.save_account_key(&account_key_path)?;
        if !config.quiet {
            println!("Generated new account key: {}", account_key_path.display());
        }
    }

    // Register account
    if !config.quiet {
        println!("Registering ACME account...");
    }
    let _account = client.create_account(email, agree_tos)?;

    // Create order
    if !config.quiet {
        println!("Creating order for: {}", domains.join(", "));
    }
    let (order, order_url) = client.create_order(domains)?;

    // Process each authorization
    for authz_url in &order.authorizations {
        let authz = client.get_authorization(authz_url)?;
        let domain_name = &authz.identifier.value;

        if !config.quiet {
            println!("Authorizing {}...", domain_name);
        }

        // Find the preferred challenge type
        let challenge = if dns {
            authz
                .challenges
                .iter()
                .find(|c| c.challenge_type == ChallengeType::Dns01)
                .ok_or_else(|| anyhow!("DNS-01 challenge not available for {}", domain_name))?
        } else {
            // Prefer HTTP-01, fall back to DNS-01
            authz
                .challenges
                .iter()
                .find(|c| c.challenge_type == ChallengeType::Http01)
                .or_else(|| {
                    authz
                        .challenges
                        .iter()
                        .find(|c| c.challenge_type == ChallengeType::Dns01)
                })
                .ok_or_else(|| anyhow!("No supported challenge type for {}", domain_name))?
        };

        match challenge.challenge_type {
            ChallengeType::Http01 => {
                let key_authz = client.key_authorization(&challenge.token)?;

                if let Some(webroot_dir) = webroot {
                    // Validate challenge token before using as filename
                    if !standalone::is_valid_token(&challenge.token) {
                        return Err(anyhow!(
                            "Invalid challenge token from server: '{}'",
                            challenge.token
                        ));
                    }

                    // Write challenge file to webroot
                    let challenge_dir = webroot_dir.join(".well-known").join("acme-challenge");
                    fs::create_dir_all(&challenge_dir)?;
                    let challenge_file = challenge_dir.join(&challenge.token);
                    fs::write(&challenge_file, &key_authz)?;

                    if !config.quiet {
                        println!("  Wrote HTTP-01 challenge to {}", challenge_file.display());
                    }
                } else if standalone {
                    // Validate challenge token
                    if !standalone::is_valid_token(&challenge.token) {
                        return Err(anyhow!(
                            "Invalid challenge token from server: '{}'",
                            challenge.token
                        ));
                    }

                    // Start standalone server on first challenge
                    if standalone_server.is_none() {
                        if !config.quiet {
                            println!("  Starting standalone HTTP server on port 80...");
                        }
                        standalone_server = Some(StandaloneServer::start(80)?);
                    }
                    standalone_server
                        .as_ref()
                        .unwrap()
                        .add_challenge(&challenge.token, &key_authz);

                    if !config.quiet {
                        println!(
                            "  Serving HTTP-01 challenge at http://{}/.well-known/acme-challenge/{}",
                            domain_name, challenge.token
                        );
                    }
                } else {
                    println!("  HTTP-01 challenge for {}:", domain_name);
                    println!("  Token: {}", challenge.token);
                    println!("  Key authorization: {}", key_authz);
                    println!(
                        "  Serve at: http://{}/.well-known/acme-challenge/{}",
                        domain_name, challenge.token
                    );
                    println!("  Press Enter when ready...");
                    let mut input = String::new();
                    std::io::stdin().read_line(&mut input)?;
                }
            }
            ChallengeType::Dns01 => {
                let dns_value = client.dns_challenge_value(&challenge.token)?;
                println!("  DNS-01 challenge for {}:", domain_name);
                println!("  Create TXT record:");
                println!("    _acme-challenge.{} TXT \"{}\"", domain_name, dns_value);
                println!("  Press Enter when the DNS record is in place...");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
            }
            _ => {
                return Err(anyhow!(
                    "Unsupported challenge type: {}",
                    challenge.challenge_type
                ));
            }
        }

        // Respond to challenge
        client.respond_to_challenge(&challenge.url)?;

        // Wait for validation
        if !config.quiet {
            println!("  Waiting for validation...");
        }
        client.wait_for_challenge(&challenge.url, Duration::from_secs(120))?;

        if !config.quiet {
            println!("  {} validated!", domain_name);
        }

        // Clean up webroot challenge file
        if let Some(webroot_dir) = webroot {
            let challenge_file = webroot_dir
                .join(".well-known")
                .join("acme-challenge")
                .join(&challenge.token);
            let _ = fs::remove_file(challenge_file);
        }
    }

    // Shut down standalone server if running
    if let Some(server) = standalone_server.take() {
        if !config.quiet {
            println!("Stopping standalone HTTP server...");
        }
        server.stop()?;
    }

    // Wait for order to be ready
    if !config.quiet {
        println!("Waiting for order to be ready...");
    }
    let ready_order = client.wait_for_order_ready(&order_url, Duration::from_secs(60))?;

    // Generate domain key and CSR
    if !config.quiet {
        println!("Generating domain key and CSR...");
    }
    let domain_key_pem = generate_domain_key()?;
    let csr_der = generate_csr_der(&domain_key_pem, domains)?;

    // Finalize order
    if !config.quiet {
        println!("Finalizing order...");
    }
    let finalized = client.finalize_order(&ready_order.finalize, &csr_der)?;

    // Wait for certificate
    let cert_order = if finalized.certificate.is_some() {
        finalized
    } else {
        client.wait_for_certificate(&order_url, Duration::from_secs(60))?
    };

    let cert_url = cert_order
        .certificate
        .ok_or_else(|| anyhow!("No certificate URL in finalized order"))?;

    // Download certificate
    if !config.quiet {
        println!("Downloading certificate...");
    }
    let cert_pem = client.download_certificate(&cert_url)?;

    // Save files
    let cert_file = cert_dir.join("fullchain.pem");
    let key_file = cert_dir.join("privkey.pem");

    fs::write(&cert_file, &cert_pem)?;
    crate::util::write_sensitive_file(&key_file, &domain_key_pem)?;

    // Save renewal configuration for automated renewals
    let mut renewal = RenewalConfig::new(
        server, email, webroot, standalone, dns, domains, insecure, ca_cert,
    );
    renewal.last_renewed = Some(chrono::Utc::now().to_rfc3339());
    if let Err(e) = renewal.save(&cert_dir) {
        eprintln!("Warning: could not save renewal config: {}", e);
    }

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "domain": primary_domain,
                "cert_path": cert_file,
                "key_path": key_file,
                "domains": domains,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text | OutputFormat::Compact => {
            println!();
            println!("{}", "Certificate issued successfully!".green().bold());
            println!();
            println!("  Domain:      {}", primary_domain);
            println!("  Certificate: {}", cert_file.display());
            println!("  Private Key: {}", key_file.display());
            if domains.len() > 1 {
                println!("  SANs:        {}", domains[1..].join(", "));
            }
        }
    }

    Ok(CmdResult::Success)
}
