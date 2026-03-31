//! Universal show command - auto-detects PKI file types.

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::Path;

use crate::compat::{load_crl, load_csr, load_private_key, DetectedFileType, KeyAlgorithm};

use super::CmdResult;
use crate::config::GlobalConfig;

/// Auto-detect file type and show appropriate output.
///
/// Uses smart content-based detection:
/// - PEM headers are definitive
/// - DER files are parsed to determine type (tries cert, CRL, CSR)
///
/// Returns:
/// - `Ok(Some(result))` if file was handled
/// - `Ok(None)` if file type is Certificate (caller should handle with full options)
/// - `Err(...)` on error
pub fn auto_show(path: &Path, config: &GlobalConfig) -> Result<Option<CmdResult>> {
    // Support reading from stdin with "-"
    let data = if path == Path::new("-") {
        use std::io::Read;
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("Failed to read from stdin")?;
        buf
    } else {
        std::fs::read(path).with_context(|| format!("Failed to read file: {}", path.display()))?
    };

    // Smart detection - analyzes content, tries parsing
    let detection = DetectedFileType::detect_with_confidence(&data, path);
    let file_type = detection.file_type;

    let result = show_by_type(path, &data, file_type, config);

    // For stdin ("-"), never return None — write to temp file and show as cert
    if path == Path::new("-") {
        if let Ok(None) = result {
            let tmp = std::env::temp_dir().join(format!("pki-stdin-{}.pem", std::process::id()));
            std::fs::write(&tmp, &data)?;
            let show_result = super::cert::run(
                super::cert::CertCommands::Show(super::cert::ShowArgs {
                    file: tmp.clone(),
                    subject: false,
                    san: false,
                    issuer: false,
                    check: false,
                    issuer_cert: None,
                    lint: false,
                    interactive: false,
                    all: false,
                    no_chain: false,
                }),
                config,
            );
            let _ = std::fs::remove_file(&tmp);
            return show_result.map(Some);
        }
    }

    result
}

/// Get human-readable name for file type.
pub fn type_name(t: DetectedFileType) -> &'static str {
    match t {
        DetectedFileType::Certificate => "X.509 Certificate",
        DetectedFileType::Crl => "Certificate Revocation List (CRL)",
        DetectedFileType::PrivateKey => "Private Key",
        DetectedFileType::PublicKey => "Public Key",
        DetectedFileType::Csr => "Certificate Signing Request (CSR)",
        DetectedFileType::Pkcs7 => "PKCS#7 Container",
        DetectedFileType::Pkcs12 => "PKCS#12/PFX Container",
        DetectedFileType::Unknown => "Unknown",
    }
}

/// Show file based on detected type.
fn show_by_type(
    path: &Path,
    data: &[u8],
    file_type: DetectedFileType,
    config: &GlobalConfig,
) -> Result<Option<CmdResult>> {
    match file_type {
        DetectedFileType::Certificate => {
            // Return None to let the caller handle certificates with full options
            Ok(None)
        }
        DetectedFileType::Crl => {
            show_crl(path, config)?;
            Ok(Some(CmdResult::Success))
        }
        DetectedFileType::PrivateKey | DetectedFileType::PublicKey => {
            show_key(path, data, file_type, config)?;
            Ok(Some(CmdResult::Success))
        }
        DetectedFileType::Csr => {
            show_csr(path, config)?;
            Ok(Some(CmdResult::Success))
        }
        DetectedFileType::Pkcs7 => {
            println!("{}: PKCS#7 container", "Detected".cyan().bold());
            println!("    {}", "PKCS#7 parsing support coming soon.".dimmed());
            Ok(Some(CmdResult::Success))
        }
        DetectedFileType::Pkcs12 => {
            println!("{}: PKCS#12/PFX container", "Detected".cyan().bold());
            println!("    {}", "PKCS#12 parsing support coming soon.".dimmed());
            Ok(Some(CmdResult::Success))
        }
        DetectedFileType::Unknown => {
            // Try to parse as certificate anyway
            Ok(None)
        }
    }
}

/// Show CRL details.
fn show_crl(path: &Path, _config: &GlobalConfig) -> Result<()> {
    let crl = load_crl(path).with_context(|| format!("Failed to load CRL: {}", path.display()))?;

    // Print header
    println!("{}", "Certificate Revocation List (CRL):".cyan().bold());

    if let Some(v) = crl.version {
        println!(
            "    Version:            {} {}",
            format!("{}", v).white().bold(),
            format!("(0x{:x})", v - 1).dimmed()
        );
    }

    println!(
        "    Signature Algorithm: {} {}",
        crl.signature_algorithm.white().bold(),
        format!("({})", crl.signature_oid).dimmed()
    );

    println!();
    println!("{}:", "Issuer".cyan().bold());
    println!("    {}", crl.issuer.white());

    println!();
    println!("{}:", "Validity".cyan().bold());
    println!(
        "    Last Update:        {}",
        crl.this_update.to_string().white()
    );

    if let Some(ref next) = crl.next_update {
        let (status_icon, status_text) = if crl.is_expired() {
            (
                "✗".red().bold().to_string(),
                "EXPIRED".red().bold().to_string(),
            )
        } else if let Some(days) = crl.days_until_next_update() {
            if days < 0 {
                (
                    "✗".red().bold().to_string(),
                    format!("{} days ago - EXPIRED", -days).red().to_string(),
                )
            } else if days < 7 {
                (
                    "⚠".yellow().bold().to_string(),
                    format!("{} days remaining", days).yellow().to_string(),
                )
            } else {
                (
                    "✓".green().bold().to_string(),
                    format!("{} days remaining", days).green().to_string(),
                )
            }
        } else {
            (String::new(), String::new())
        };
        println!("    Next Update:        {}", next.to_string().white());
        if !status_text.is_empty() {
            println!("    Status:             {} {}", status_icon, status_text);
        }
    }

    // CRL Extensions
    if !crl.extensions.is_empty() {
        println!();
        println!("{}:", "CRL Extensions".cyan().bold());

        if let Some(ref num) = crl.crl_number {
            println!("    X509v3 CRL Number:  {}", num.green().bold());
        }

        if let Some(ref aki) = crl.authority_key_id {
            println!("    X509v3 Authority Key Identifier:");
            println!("        keyid:{}", aki.yellow());
        }

        // Other extensions
        for ext in &crl.extensions {
            if ext.name != "CRL Number"
                && ext.name != "Authority Key Identifier"
                && ext.name != "Delta CRL Indicator"
                && ext.name != "Issuing Distribution Point"
            {
                let critical_str = if ext.critical {
                    format!(" {}", "critical".red().bold())
                } else {
                    String::new()
                };
                println!("    {}{}:", ext.name.white(), critical_str);
                println!("        {}", ext.value.dimmed());
            }
        }
    }

    // Revoked Certificates Section
    println!();
    println!("{}:", "Revoked Certificates".cyan().bold());
    if crl.revoked_count() == 0 {
        println!(
            "    {} {}",
            "✓".green().bold(),
            "No Revoked Certificates".green()
        );
    } else {
        println!(
            "    {} {} certificate(s) revoked",
            "✗".red().bold(),
            crl.revoked_count().to_string().red().bold()
        );
        println!();
        println!(
            "    {}",
            "Use 'pki crl show <file> --all' to list all revoked certificates".dimmed()
        );
    }

    // Fingerprints
    println!();
    println!("{}:", "Fingerprints".cyan().bold());
    println!(
        "    SHA-256:            {}",
        crl.fingerprint_sha256.yellow()
    );
    println!("    SHA-1:              {}", crl.fingerprint_sha1.dimmed());

    // Size info
    println!();
    println!(
        "{}:             {} bytes",
        "CRL Size".cyan().bold(),
        crl.raw_der().len().to_string().white().bold()
    );

    Ok(())
}

/// Show key details.
fn show_key(
    path: &Path,
    _data: &[u8],
    file_type: DetectedFileType,
    _config: &GlobalConfig,
) -> Result<()> {
    let key_type = if file_type == DetectedFileType::PrivateKey {
        "Private Key"
    } else {
        "Public Key"
    };

    // Try to load and parse the key
    match load_private_key(path) {
        Ok(key) => {
            println!("{}:", key_type.cyan().bold());
            println!();

            let algo_str = key.algorithm.to_string();
            println!("    Algorithm:          {}", algo_str.white().bold());

            let bits = key.bits;
            let strength = match key.algorithm {
                KeyAlgorithm::Rsa(_) => {
                    if bits >= 3072 {
                        "STRONG".green()
                    } else if bits >= 2048 {
                        "OK".yellow()
                    } else {
                        "WEAK".red().bold()
                    }
                }
                KeyAlgorithm::EcP256 | KeyAlgorithm::EcP384 => "STRONG".green(),
                KeyAlgorithm::Ed25519 | KeyAlgorithm::Ed448 => "STRONG".green(),
                #[cfg(feature = "pqc")]
                KeyAlgorithm::MlDsa(_) | KeyAlgorithm::SlhDsa(_) => "STRONG".green(),
            };
            println!(
                "    Key Size:           {} bits {}",
                bits.to_string().white().bold(),
                strength
            );

            if key.encrypted {
                println!(
                    "    Encryption:         {}",
                    "Encrypted (password protected)".yellow()
                );
            }

            // Show security assessment
            println!();
            println!(
                "    Security:           {}",
                key.security_assessment().green()
            );
        }
        Err(e) => {
            // Still show what we know
            println!("{}:", key_type.cyan().bold());
            println!();
            println!(
                "    {}",
                format!("Could not parse key details: {}", e).dimmed()
            );
            println!(
                "    {}",
                "The file appears to be a valid key but may be encrypted or in an unsupported format.".dimmed()
            );
        }
    }

    Ok(())
}

/// Show CSR details.
fn show_csr(path: &Path, _config: &GlobalConfig) -> Result<()> {
    let csr = load_csr(path).with_context(|| format!("Failed to load CSR: {}", path.display()))?;

    println!("{}", "Certificate Signing Request (CSR):".cyan().bold());
    println!();
    println!("    Subject:            {}", csr.subject.white().bold());

    let key_size_str = csr
        .key_size
        .map(|s| format!("({} bits)", s))
        .unwrap_or_default();
    println!(
        "    Key Algorithm:      {} {}",
        csr.key_algorithm.white().bold(),
        key_size_str.dimmed()
    );
    println!(
        "    Signature Algorithm: {}",
        csr.signature_algorithm.white()
    );

    if !csr.san.is_empty() {
        println!();
        println!("{}:", "Subject Alternative Names".cyan().bold());
        for san in &csr.san {
            println!("    - {}", san.white());
        }
    }

    // Show CSR size
    let der_len = csr.raw_der().len();
    if der_len > 0 {
        println!();
        println!(
            "{}:            {} bytes",
            "CSR Size".cyan().bold(),
            der_len.to_string().white().bold()
        );
    }

    Ok(())
}
