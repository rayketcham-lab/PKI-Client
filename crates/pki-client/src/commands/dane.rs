//! DANE command — TLSA record generation and verification (RFC 6698/7671)

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

use spork_core::cert::dane;

use super::CmdResult;
use crate::config::GlobalConfig;

/// DANE TLSA operations
#[derive(Subcommand)]
pub enum DaneCommands {
    /// Generate a TLSA record from a certificate
    ///
    /// Produces DNS zone file content for DANE certificate pinning.
    #[command(after_help = "Examples:
  pki dane generate --cert server.pem
  pki dane generate --cert ca.pem --usage 2 --selector 1 --matching 1
  pki dane generate --cert server.pem --port 25 --hostname mail.example.com")]
    Generate(GenerateArgs),

    /// Verify a certificate against TLSA record parameters
    #[command(after_help = "Examples:
  pki dane verify --cert server.pem --data abcdef1234... --usage 3 --selector 1 --matching 1
  pki dane verify --cert server.pem --rdata '3 1 1 abcdef1234...'")]
    Verify(VerifyArgs),
}

/// Arguments for TLSA record generation
#[derive(Args)]
pub struct GenerateArgs {
    /// Certificate file (PEM or DER)
    #[arg(long, short = 'c', value_name = "FILE")]
    cert: PathBuf,

    /// TLSA usage (default: DANE-EE)
    #[arg(long, short = 'u', value_name = "USAGE", default_value = "dane-ee")]
    usage: UsageArg,

    /// TLSA selector (default: SPKI)
    #[arg(long, short = 's', value_name = "SELECTOR", default_value = "spki")]
    selector: SelectorArg,

    /// TLSA matching type (default: SHA-256)
    #[arg(long, short = 'm', value_name = "MATCHING", default_value = "sha256")]
    matching: MatchingArg,

    /// Port number for DNS name (default: 443)
    #[arg(long, short = 'p', default_value = "443")]
    port: u16,

    /// Hostname for DNS name (extracted from cert CN/SAN if omitted)
    #[arg(long, short = 'H')]
    hostname: Option<String>,

    /// Protocol (default: tcp)
    #[arg(long, default_value = "tcp")]
    protocol: String,
}

/// Arguments for TLSA verification
#[derive(Args)]
pub struct VerifyArgs {
    /// Certificate file (PEM or DER)
    #[arg(long, short = 'c', value_name = "FILE")]
    cert: PathBuf,

    /// TLSA RDATA string (e.g., "3 1 1 abcdef...")
    #[arg(long, conflicts_with_all = ["data", "usage", "selector", "matching"])]
    rdata: Option<String>,

    /// Certificate association data (hex)
    #[arg(long, short = 'd', required_unless_present = "rdata")]
    data: Option<String>,

    /// TLSA usage
    #[arg(long, short = 'u', default_value = "dane-ee")]
    usage: UsageArg,

    /// TLSA selector
    #[arg(long, short = 's', default_value = "spki")]
    selector: SelectorArg,

    /// TLSA matching type
    #[arg(long, short = 'm', default_value = "sha256")]
    matching: MatchingArg,
}

/// CLI-friendly TLSA usage values
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum UsageArg {
    /// PKIX-TA (0) — CA constraint with PKIX validation
    PkixTa,
    /// PKIX-EE (1) — EE constraint with PKIX validation
    PkixEe,
    /// DANE-TA (2) — CA constraint, DANE-only trust
    DaneTa,
    /// DANE-EE (3) — EE constraint, DANE-only trust
    DaneEe,
}

impl From<UsageArg> for dane::TlsaUsage {
    fn from(u: UsageArg) -> Self {
        match u {
            UsageArg::PkixTa => Self::PkixTa,
            UsageArg::PkixEe => Self::PkixEe,
            UsageArg::DaneTa => Self::DaneTa,
            UsageArg::DaneEe => Self::DaneEe,
        }
    }
}

/// CLI-friendly TLSA selector values
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SelectorArg {
    /// Full certificate (0)
    Cert,
    /// SubjectPublicKeyInfo (1)
    Spki,
}

impl From<SelectorArg> for dane::TlsaSelector {
    fn from(s: SelectorArg) -> Self {
        match s {
            SelectorArg::Cert => Self::FullCertificate,
            SelectorArg::Spki => Self::SubjectPublicKeyInfo,
        }
    }
}

/// CLI-friendly TLSA matching type values
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum MatchingArg {
    /// Exact match (0)
    Exact,
    /// SHA-256 (1)
    Sha256,
    /// SHA-512 (2)
    Sha512,
}

impl From<MatchingArg> for dane::TlsaMatchingType {
    fn from(m: MatchingArg) -> Self {
        match m {
            MatchingArg::Exact => Self::Exact,
            MatchingArg::Sha256 => Self::Sha256,
            MatchingArg::Sha512 => Self::Sha512,
        }
    }
}

/// Load a certificate as DER bytes from a PEM or DER file.
fn load_cert_der(path: &PathBuf) -> Result<Vec<u8>> {
    let data = fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;

    // Try PEM first
    if let Ok(text) = std::str::from_utf8(&data) {
        if text.contains("BEGIN CERTIFICATE") {
            let pem = pem::parse(text)
                .with_context(|| format!("Failed to parse PEM from {}", path.display()))?;
            return Ok(pem.into_contents());
        }
    }

    // Assume DER
    Ok(data)
}

pub fn run(cmd: DaneCommands, config: &GlobalConfig) -> Result<CmdResult> {
    match cmd {
        DaneCommands::Generate(args) => run_generate(args, config),
        DaneCommands::Verify(args) => run_verify(args, config),
    }
}

fn run_generate(args: GenerateArgs, config: &GlobalConfig) -> Result<CmdResult> {
    let cert_der = load_cert_der(&args.cert)?;

    let usage: dane::TlsaUsage = args.usage.into();
    let selector: dane::TlsaSelector = args.selector.into();
    let matching: dane::TlsaMatchingType = args.matching.into();

    let record = dane::generate_tlsa_record(&cert_der, usage, selector, matching)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Determine hostname
    let hostname = if let Some(h) = &args.hostname {
        h.clone()
    } else {
        // Try to extract from certificate CN or SAN
        extract_hostname_from_cert(&cert_der).unwrap_or_else(|| "example.com".to_string())
    };

    let dns_name = dane::tlsa_domain_name(&hostname, args.port, &args.protocol);
    let rdata = dane::format_tlsa_rdata(&record);

    if config.format == pki_client_output::OutputFormat::Json {
        let json = serde_json::json!({
            "dns_name": dns_name,
            "usage": usage as u8,
            "selector": selector as u8,
            "matching_type": matching as u8,
            "association_data": hex::encode(&record.cert_association_data),
            "rdata": rdata,
            "zone_line": format!("{}. IN TLSA {}", dns_name, rdata),
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        if !config.quiet {
            println!("{}", "DANE TLSA Record".bold());
            println!("{}", "─".repeat(60).dimmed());
            println!("  {} {}", "Usage:".bold(), usage);
            println!("  {} {}", "Selector:".bold(), selector);
            println!("  {} {}", "Matching:".bold(), matching);
            println!(
                "  {} {}",
                "Data:".bold(),
                hex::encode(&record.cert_association_data)
            );
            println!();
            println!("{}", "DNS Zone Entry".bold());
            println!("{}", "─".repeat(60).dimmed());
        }
        println!("{}. IN TLSA {}", dns_name, rdata);
    }

    Ok(CmdResult::Success)
}

fn run_verify(args: VerifyArgs, config: &GlobalConfig) -> Result<CmdResult> {
    let cert_der = load_cert_der(&args.cert)?;

    let record = if let Some(rdata_str) = &args.rdata {
        dane::parse_tlsa_rdata(rdata_str).map_err(|e| anyhow::anyhow!("{}", e))?
    } else {
        let data_hex = args.data.as_deref().unwrap();
        let data = hex::decode(data_hex).context("Invalid hex in --data")?;
        dane::TlsaRecord::new(
            args.usage.into(),
            args.selector.into(),
            args.matching.into(),
            data,
        )
    };

    let matched =
        dane::match_certificate(&cert_der, &record).map_err(|e| anyhow::anyhow!("{}", e))?;

    if config.format == pki_client_output::OutputFormat::Json {
        let json = serde_json::json!({
            "matched": matched,
            "usage": record.usage as u8,
            "selector": record.selector as u8,
            "matching_type": record.matching_type as u8,
        });
        println!("{}", serde_json::to_string_pretty(&json)?);
    } else {
        if matched {
            println!(
                "{} Certificate matches TLSA record ({})",
                "PASS".green().bold(),
                record.usage
            );
        } else {
            println!(
                "{} Certificate does NOT match TLSA record ({})",
                "FAIL".red().bold(),
                record.usage
            );
        }
    }

    if matched {
        Ok(CmdResult::Success)
    } else {
        Ok(CmdResult::ExitCode(1))
    }
}

/// Try to extract a hostname from certificate CN or SAN.
fn extract_hostname_from_cert(cert_der: &[u8]) -> Option<String> {
    // Try SANs first
    if let Ok((dns_names, _, _)) = spork_core::cert::extract_sans_from_der(cert_der) {
        if let Some(name) = dns_names.into_iter().find(|n| !n.starts_with('*')) {
            return Some(name);
        }
    }

    // Fall back to CN extraction
    if let Ok(cert) = spork_core::cert::parse_certificate_der(cert_der) {
        for rdn in cert.tbs_certificate.subject.0.iter() {
            for atv in rdn.0.iter() {
                // CN OID = 2.5.4.3
                if atv.oid.to_string() == "2.5.4.3" {
                    if let Ok(cn) = std::str::from_utf8(atv.value.value()) {
                        return Some(cn.to_string());
                    }
                }
            }
        }
    }

    None
}
