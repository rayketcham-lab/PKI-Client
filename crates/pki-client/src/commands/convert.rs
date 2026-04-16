//! Convert command - convert PKI files between formats.

use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use colored::Colorize;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use crate::compat::{Certificate, Crl, Csr, DetectedFileType};

use super::CmdResult;
use crate::config::GlobalConfig;

/// Output format for conversion.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum OutputFormat {
    /// PEM format (Base64 with headers)
    #[default]
    Pem,
    /// DER format (binary)
    Der,
    /// Base64 (no headers)
    Base64,
    /// Text (human-readable, where applicable)
    Text,
}

/// Arguments for the convert command.
#[derive(Args)]
pub struct ConvertArgs {
    /// Input file (or - for stdin)
    #[arg(value_name = "INPUT")]
    pub input: PathBuf,

    /// Output file (or - for stdout, default)
    #[arg(short = 'o', long, value_name = "OUTPUT")]
    pub output: Option<PathBuf>,

    /// Output format
    #[arg(short = 't', long = "to", value_name = "FORMAT", default_value = "pem")]
    pub to_format: OutputFormat,

    /// Force input type (skip auto-detection)
    #[arg(long = "from", value_name = "TYPE")]
    pub from_type: Option<InputType>,
}

/// Input file type hint.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum InputType {
    /// X.509 Certificate
    Cert,
    /// Certificate Revocation List
    Crl,
    /// Certificate Signing Request
    Csr,
    /// Private Key
    Key,
}

/// Run the convert command.
pub fn run(args: ConvertArgs, config: &GlobalConfig) -> Result<CmdResult> {
    // Read input
    let input_data = if args.input.to_string_lossy() == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        buf
    } else {
        fs::read(&args.input)
            .with_context(|| format!("Failed to read input: {}", args.input.display()))?
    };

    // Detect or use specified type
    let file_type = if let Some(hint) = args.from_type {
        match hint {
            InputType::Cert => DetectedFileType::Certificate,
            InputType::Crl => DetectedFileType::Crl,
            InputType::Csr => DetectedFileType::Csr,
            InputType::Key => DetectedFileType::PrivateKey,
        }
    } else {
        let detection = DetectedFileType::detect_with_confidence(&input_data, &args.input);
        detection.file_type
    };

    // Convert based on type
    let output_data = match file_type {
        DetectedFileType::Certificate => convert_certificate(&input_data, args.to_format)?,
        DetectedFileType::Crl => convert_crl(&input_data, args.to_format)?,
        DetectedFileType::Csr => convert_csr(&input_data, args.to_format)?,
        DetectedFileType::PrivateKey | DetectedFileType::PublicKey => {
            convert_key(&input_data, args.to_format)?
        }
        _ => {
            return Err(anyhow::anyhow!(
                "Cannot convert file type: {}. Supported: cert, crl, csr, key.\n\
                 Hint: DER-encoded files cannot always be auto-detected. \
                 Try specifying the type with --from (e.g. --from key)",
                super::show::type_name(file_type)
            ));
        }
    };

    // Write output
    if let Some(ref output_path) = args.output {
        if output_path.to_string_lossy() == "-" {
            io::stdout().write_all(&output_data)?;
        } else {
            fs::write(output_path, &output_data)
                .with_context(|| format!("Failed to write output: {}", output_path.display()))?;

            if !config.quiet {
                println!(
                    "{} Converted {} → {} ({})",
                    "✓".green().bold(),
                    args.input.display().to_string().white(),
                    output_path.display().to_string().white().bold(),
                    format_name(args.to_format).cyan()
                );
            }
        }
    } else {
        // Default to stdout
        io::stdout().write_all(&output_data)?;
    }

    Ok(CmdResult::Success)
}

/// Get format name.
fn format_name(fmt: OutputFormat) -> &'static str {
    match fmt {
        OutputFormat::Pem => "PEM",
        OutputFormat::Der => "DER",
        OutputFormat::Base64 => "Base64",
        OutputFormat::Text => "Text",
    }
}

/// Convert certificate to specified format.
fn convert_certificate(data: &[u8], to: OutputFormat) -> Result<Vec<u8>> {
    // Parse certificate (handles both PEM and DER input)
    let data_str = String::from_utf8_lossy(data);
    let cert = Certificate::from_pem(&data_str)
        .or_else(|_| Certificate::from_der(data))
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {e}"))?;

    match to {
        OutputFormat::Pem => {
            let pem = pem::Pem::new("CERTIFICATE", cert.raw_der().to_vec());
            Ok(pem::encode(&pem).into_bytes())
        }
        OutputFormat::Der => Ok(cert.raw_der().to_vec()),
        OutputFormat::Base64 => {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(cert.raw_der());
            Ok(format!("{}\n", b64).into_bytes())
        }
        OutputFormat::Text => {
            // Return basic text representation
            let mut out = String::new();
            out.push_str(&format!("Subject: {}\n", cert.subject));
            out.push_str(&format!("Issuer: {}\n", cert.issuer));
            out.push_str(&format!("Serial: {}\n", cert.serial));
            out.push_str(&format!("Not Before: {}\n", cert.not_before));
            out.push_str(&format!("Not After: {}\n", cert.not_after));
            out.push_str(&format!(
                "Fingerprint (SHA-256): {}\n",
                cert.fingerprint_sha256
            ));
            Ok(out.into_bytes())
        }
    }
}

/// Convert CRL to specified format.
fn convert_crl(data: &[u8], to: OutputFormat) -> Result<Vec<u8>> {
    let crl = Crl::from_pem(data)
        .or_else(|_| Crl::from_der(data))
        .map_err(|e| anyhow::anyhow!("Failed to parse CRL: {e}"))?;

    match to {
        OutputFormat::Pem => {
            let pem = pem::Pem::new("X509 CRL", crl.raw_der().to_vec());
            Ok(pem::encode(&pem).into_bytes())
        }
        OutputFormat::Der => Ok(crl.raw_der().to_vec()),
        OutputFormat::Base64 => {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(crl.raw_der());
            Ok(format!("{}\n", b64).into_bytes())
        }
        OutputFormat::Text => {
            let mut out = String::new();
            out.push_str(&format!("Issuer: {}\n", crl.issuer));
            out.push_str(&format!("This Update: {}\n", crl.this_update));
            if let Some(ref next) = crl.next_update {
                out.push_str(&format!("Next Update: {}\n", next));
            }
            out.push_str(&format!("Revoked Count: {}\n", crl.revoked_count()));
            Ok(out.into_bytes())
        }
    }
}

/// Convert CSR to specified format.
fn convert_csr(data: &[u8], to: OutputFormat) -> Result<Vec<u8>> {
    let csr = Csr::from_pem(data)
        .or_else(|_| Csr::from_der(data))
        .map_err(|e| anyhow::anyhow!("Failed to parse CSR: {e}"))?;

    match to {
        OutputFormat::Pem => {
            let pem = pem::Pem::new("CERTIFICATE REQUEST", csr.raw_der().to_vec());
            Ok(pem::encode(&pem).into_bytes())
        }
        OutputFormat::Der => Ok(csr.raw_der().to_vec()),
        OutputFormat::Base64 => {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(csr.raw_der());
            Ok(format!("{}\n", b64).into_bytes())
        }
        OutputFormat::Text => {
            let mut out = String::new();
            out.push_str(&format!("Subject: {}\n", csr.subject));
            out.push_str(&format!(
                "Key Algorithm: {} ({} bits)\n",
                csr.key_algorithm,
                csr.key_size.unwrap_or(0)
            ));
            out.push_str(&format!(
                "Signature Algorithm: {}\n",
                csr.signature_algorithm
            ));
            if !csr.san.is_empty() {
                let sans = csr
                    .san
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                out.push_str(&format!("SANs: {sans}\n"));
            }
            Ok(out.into_bytes())
        }
    }
}

/// Convert a private key to specified format.
fn convert_key(data: &[u8], to: OutputFormat) -> Result<Vec<u8>> {
    // Try to parse as PEM first
    if let Ok(pem) = pem::parse(data) {
        let der_data = pem.contents();
        let tag = pem.tag();

        match to {
            OutputFormat::Pem => Ok(data.to_vec()),
            OutputFormat::Der => Ok(der_data.to_vec()),
            OutputFormat::Base64 => {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(der_data);
                Ok(format!("{}\n", b64).into_bytes())
            }
            OutputFormat::Text => {
                let mut out = String::new();
                out.push_str(&format!("Type: {}\n", tag));
                out.push_str(&format!("Size: {} bytes\n", der_data.len()));
                Ok(out.into_bytes())
            }
        }
    } else {
        // Assume DER input
        match to {
            OutputFormat::Pem => {
                // Guess the type - default to PRIVATE KEY
                let pem = pem::Pem::new("PRIVATE KEY", data);
                Ok(pem::encode(&pem).into_bytes())
            }
            OutputFormat::Der => Ok(data.to_vec()),
            OutputFormat::Base64 => {
                use base64::Engine;
                let b64 = base64::engine::general_purpose::STANDARD.encode(data);
                Ok(format!("{}\n", b64).into_bytes())
            }
            OutputFormat::Text => {
                let mut out = String::new();
                out.push_str("Type: Private Key (DER)\n");
                out.push_str(&format!("Size: {} bytes\n", data.len()));
                Ok(out.into_bytes())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_name() {
        assert_eq!(format_name(OutputFormat::Pem), "PEM");
        assert_eq!(format_name(OutputFormat::Der), "DER");
        assert_eq!(format_name(OutputFormat::Base64), "Base64");
        assert_eq!(format_name(OutputFormat::Text), "Text");
    }

    #[test]
    fn test_convert_key_pem_to_der() {
        let pem_data = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n";
        let result = convert_key(pem_data, OutputFormat::Der).unwrap();
        // DER should not contain PEM markers
        assert!(!result.starts_with(b"-----"));
    }

    #[test]
    fn test_convert_key_pem_to_pem() {
        let pem_data = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n";
        let result = convert_key(pem_data, OutputFormat::Pem).unwrap();
        assert!(result.starts_with(b"-----BEGIN"));
    }

    #[test]
    fn test_convert_key_pem_to_base64() {
        let pem_data = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END PRIVATE KEY-----\n";
        let result = convert_key(pem_data, OutputFormat::Base64).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        // Should be pure base64 without PEM headers
        assert!(!result_str.contains("-----BEGIN"));
        assert!(!result_str.trim().is_empty());
    }

    #[test]
    fn test_convert_key_pem_to_text() {
        let pem_data = b"-----BEGIN EC PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n-----END EC PRIVATE KEY-----\n";
        let result = convert_key(pem_data, OutputFormat::Text).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("Type: EC PRIVATE KEY"));
        assert!(result_str.contains("Size:"));
    }

    #[test]
    fn test_convert_key_der_to_pem() {
        let der_data = vec![0x30, 0x82, 0x01, 0x22]; // fake DER
        let result = convert_key(&der_data, OutputFormat::Pem).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn test_convert_key_der_to_text() {
        let der_data = vec![0x30, 0x82, 0x01, 0x22];
        let result = convert_key(&der_data, OutputFormat::Text).unwrap();
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("Private Key (DER)"));
        assert!(result_str.contains("4 bytes"));
    }

    /// Issue #59: DER-encoded private keys should be auto-detected without --from flag.
    #[test]
    fn test_der_private_key_autodetect_roundtrip() {
        use spork_core::{AlgorithmId, KeyPair};

        // Generate a real ECDSA P-256 key and export as PKCS#8 DER
        let kp = KeyPair::generate(AlgorithmId::EcdsaP256).unwrap();
        let der_bytes = kp.private_key_der().unwrap();

        // Auto-detection should identify it as a private key
        let detection =
            DetectedFileType::detect_with_confidence(&der_bytes, std::path::Path::new("key.der"));
        assert_eq!(
            detection.file_type,
            DetectedFileType::PrivateKey,
            "DER private key should be auto-detected as PrivateKey, got {:?}",
            detection.file_type,
        );

        // Converting DER -> PEM should produce valid PEM output
        let pem_output = convert_key(&der_bytes, OutputFormat::Pem).unwrap();
        let pem_str = String::from_utf8_lossy(&pem_output);
        assert!(
            pem_str.contains("-----BEGIN PRIVATE KEY-----"),
            "DER->PEM conversion should produce PEM with PRIVATE KEY header",
        );
    }
}
