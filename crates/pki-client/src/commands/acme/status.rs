//! ACME status command — show cert info for a domain.

use super::helpers::pki_certs_dir;
use crate::commands::CmdResult;
use crate::config::GlobalConfig;
use anyhow::{anyhow, Context, Result};
use colored::Colorize;
use pki_client_output::OutputFormat;
use std::fs;
use std::path::Path;

pub(super) fn cmd_status(
    domain: Option<&str>,
    cert_path: Option<&Path>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let cert_dir = match (cert_path, domain) {
        (Some(p), _) => p.to_path_buf(),
        (_, Some(d)) => pki_certs_dir()?.join(d),
        _ => return Err(anyhow!("Specify --domain or --cert-path")),
    };

    let cert_file = cert_dir.join("fullchain.pem");
    if !cert_file.exists() {
        return Err(anyhow!("No certificate found at {}", cert_file.display()));
    }

    let cert_data = fs::read(&cert_file)?;
    let pem_data = pem::parse(&cert_data).context("Failed to parse certificate PEM")?;
    let (_, cert) = x509_parser::parse_x509_certificate(pem_data.contents())
        .map_err(|e| anyhow!("Failed to parse certificate: {}", e))?;

    let not_before = cert.validity().not_before;
    let not_after = cert.validity().not_after;
    let now = x509_parser::time::ASN1Time::now();
    let days_remaining = (not_after.timestamp() - now.timestamp()) / 86400;

    let subject_cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("(unknown)");

    let san_names: Vec<String> = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|name| {
                    if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                        Some(dns.to_string())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::json!({
                "subject_cn": subject_cn,
                "sans": san_names,
                "not_before": not_before.to_string(),
                "not_after": not_after.to_string(),
                "days_remaining": days_remaining,
                "cert_path": cert_file,
                "key_path": cert_dir.join("privkey.pem"),
                "needs_renewal": days_remaining <= 30,
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Text
        | OutputFormat::Forensic
        | OutputFormat::Compact
        | OutputFormat::Openssl => {
            println!();
            println!("{}", "Certificate Status".bold());
            println!();
            println!("  Subject:     {}", subject_cn);
            if !san_names.is_empty() {
                println!("  SANs:        {}", san_names.join(", "));
            }
            println!("  Valid From:  {}", not_before);
            println!("  Valid Until: {}", not_after);
            println!("  Days Left:   {}", days_remaining);
            println!("  Cert File:   {}", cert_file.display());
            println!("  Key File:    {}", cert_dir.join("privkey.pem").display());
            println!();
            if days_remaining <= 0 {
                println!("  {}", "EXPIRED".red().bold());
            } else if days_remaining <= 30 {
                println!("  {}", "Renewal recommended (less than 30 days)".yellow());
            } else {
                println!("  {}", "OK".green());
            }
        }
    }

    Ok(CmdResult::Success)
}
