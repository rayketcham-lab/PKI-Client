//! ACME renew command — re-request a certificate.

use super::certonly::cmd_certonly;
use super::helpers::{pki_certs_dir, RenewalConfig};
use crate::commands::CmdResult;
use crate::config::GlobalConfig;
use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use std::fs;
use std::path::Path;

#[allow(clippy::too_many_arguments)]
pub(super) fn cmd_renew(
    domain: Option<&str>,
    cert_path: Option<&Path>,
    server: &str,
    force: bool,
    dry_run: bool,
    insecure: bool,
    ca_cert: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    // Determine cert directory
    let cert_dir = match (cert_path, domain) {
        (Some(p), _) => p.to_path_buf(),
        (_, Some(d)) => pki_certs_dir()?.join(d),
        _ => return Err(anyhow!("Specify --domain or --cert-path")),
    };

    let cert_file = cert_dir.join("fullchain.pem");
    if !cert_file.exists() {
        return Err(anyhow!(
            "No certificate found at {}. Use 'certonly' first.",
            cert_file.display()
        ));
    }

    // Load saved renewal config (has server URL, email, challenge method, etc.)
    let renewal_cfg = RenewalConfig::load(&cert_dir).ok();

    // Check expiry
    let cert_data = fs::read(&cert_file)?;
    let pem_data = pem::parse(&cert_data).context("Failed to parse certificate PEM")?;
    let (_, cert) = x509_parser::parse_x509_certificate(pem_data.contents())
        .map_err(|e| anyhow!("Failed to parse certificate: {}", e))?;

    let not_after = cert.validity().not_after;
    let now = x509_parser::time::ASN1Time::now();
    let days_remaining = (not_after.timestamp() - now.timestamp()) / 86400;

    if !config.quiet {
        println!("Certificate: {}", cert_file.display());
        println!("Expires:     {}", not_after);
        println!("Days left:   {}", days_remaining);
        if let Some(ref rc) = renewal_cfg {
            println!("Server:      {}", rc.server);
            println!("Challenge:   {}", rc.challenge_method);
        }
    }

    if days_remaining > 30 && !force {
        if !config.quiet {
            println!();
            println!(
                "Certificate has {} days remaining (threshold: 30). No renewal needed.",
                days_remaining
            );
            println!("Use --force to renew anyway.");
        }
        return Ok(CmdResult::Success);
    }

    if dry_run {
        println!();
        println!("{}", "Dry run: would renew certificate".yellow());
        return Ok(CmdResult::Success);
    }

    // Extract domains from renewal config (preferred) or certificate SANs (fallback)
    let domains: Vec<String> = if let Some(ref rc) = renewal_cfg {
        if !rc.domains.is_empty() {
            rc.domains.clone()
        } else {
            extract_domains_from_cert(&cert)?
        }
    } else {
        extract_domains_from_cert(&cert)?
    };

    if domains.is_empty() {
        return Err(anyhow!("Could not determine domains from certificate"));
    }

    // Use renewal config values, falling back to CLI args
    let effective_server = if let Some(ref rc) = renewal_cfg {
        rc.server.as_str()
    } else {
        server
    };
    let effective_insecure = if let Some(ref rc) = renewal_cfg {
        rc.insecure
    } else {
        insecure
    };

    // Reconstruct challenge method from renewal config
    let (use_standalone, use_dns, use_webroot) = if let Some(ref rc) = renewal_cfg {
        match rc.challenge_method.as_str() {
            "standalone" => (true, false, rc.webroot.clone()),
            "dns" => (false, true, None),
            "http" => (false, false, rc.webroot.clone()),
            _ => (false, false, None),
        }
    } else {
        (false, false, None)
    };

    let email_str = renewal_cfg.as_ref().and_then(|rc| rc.email.clone());
    let ca_cert_buf = renewal_cfg
        .as_ref()
        .and_then(|rc| rc.ca_cert.clone())
        .or_else(|| ca_cert.map(|p| p.to_path_buf()));

    if !config.quiet {
        println!("Renewing certificate for: {}", domains.join(", "));
    }

    cmd_certonly(
        &domains,
        effective_server,
        email_str.as_deref(),
        use_webroot.as_deref(),
        use_standalone,
        use_dns,
        Some(&cert_dir),
        true,
        effective_insecure,
        ca_cert_buf.as_deref(),
        config,
    )
}

fn extract_domains_from_cert(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<Vec<String>> {
    let san_ext = cert.subject_alternative_name().ok().flatten();

    if let Some(san) = san_ext {
        let domains: Vec<String> = san
            .value
            .general_names
            .iter()
            .filter_map(|name| {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    Some(dns.to_string())
                } else {
                    None
                }
            })
            .collect();
        if !domains.is_empty() {
            return Ok(domains);
        }
    }

    // Fall back to CN
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("");
    if cn.is_empty() {
        return Err(anyhow!("No domains found in certificate"));
    }
    Ok(vec![cn.to_string()])
}

/// Renew all domains that have renewal configs and are expiring within threshold.
pub(super) fn cmd_renew_all(
    force: bool,
    dry_run: bool,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let certs_dir = pki_certs_dir()?;
    if !certs_dir.exists() {
        return Err(anyhow!("No certificates found at {}", certs_dir.display()));
    }

    let mut renewed = 0u32;
    let mut failed = 0u32;

    let entries: Vec<_> = fs::read_dir(&certs_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();

    if entries.is_empty() {
        if !config.quiet {
            println!("No certificate directories found.");
        }
        return Ok(CmdResult::Success);
    }

    for entry in &entries {
        let domain_dir = entry.path();
        let renewal_path = domain_dir.join("renewal.json");
        if !renewal_path.exists() {
            continue;
        }

        let domain_name = entry.file_name().to_string_lossy().to_string();

        if !config.quiet {
            println!("Checking {}...", domain_name);
        }

        let rc = match RenewalConfig::load(&domain_dir) {
            Ok(rc) => rc,
            Err(e) => {
                eprintln!("  Skipping {}: {}", domain_name, e);
                failed += 1;
                continue;
            }
        };

        match cmd_renew(
            Some(&domain_name),
            None,
            &rc.server,
            force,
            dry_run,
            rc.insecure,
            rc.ca_cert.as_deref(),
            config,
        ) {
            Ok(_) => renewed += 1,
            Err(e) => {
                eprintln!("  Failed to renew {}: {}", domain_name, e);
                failed += 1;
            }
        }
    }

    let skipped = entries.len() as u32 - renewed - failed;

    if !config.quiet {
        println!();
        println!(
            "Renewal complete: {} renewed, {} skipped, {} failed",
            renewed, skipped, failed
        );
    }

    if failed > 0 {
        Err(anyhow!("{} renewal(s) failed", failed))
    } else {
        Ok(CmdResult::Success)
    }
}
