//! Server probing commands.

use crate::commands::CmdResult;
use crate::compat::{CertLinter, LintSeverity, ServerProbe};
use crate::config::GlobalConfig;
use anyhow::{Context, Result};
use clap::Subcommand;
use colored::Colorize;
use pki_client_output::OutputFormat;
use std::path::PathBuf;
use std::time::Duration;

/// Server probing commands.
#[derive(Subcommand)]
pub enum ProbeCommands {
    /// Probe a server's TLS configuration
    #[command(after_help = "Examples:
  pki probe server google.com
  pki probe server example.com:8443 --timeout 30
  pki probe server https://api.example.com --no-lint
  pki probe server pqc-server.com:6443 --no-verify")]
    Server {
        /// Target to probe (hostname, hostname:port, or URL)
        target: String,

        /// Connection timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// Skip certificate linting
        #[arg(long)]
        no_lint: bool,

        /// Check all supported protocol versions
        #[arg(long)]
        check_protocols: bool,

        /// SNI hostname (if different from target)
        #[arg(long)]
        sni: Option<String>,

        /// Skip certificate verification (for PQC servers with unsupported sig algs)
        #[arg(long)]
        no_verify: bool,
    },

    /// Lint certificates for issues
    #[command(after_help = "Examples:
  pki probe lint cert.pem
  pki probe lint chain.pem --skip-info
  pki probe lint *.pem --format json")]
    Lint {
        /// Certificate file(s) to lint
        files: Vec<PathBuf>,

        /// Skip informational findings
        #[arg(long)]
        skip_info: bool,

        /// Skip specific rules (comma-separated)
        #[arg(long)]
        skip_rules: Option<String>,
    },

    /// Quick TLS check
    #[command(after_help = "Examples:
  pki probe check example.com
  pki probe check example.com:443 --timeout 5")]
    Check {
        /// Target to check
        target: String,

        /// Connection timeout in seconds
        #[arg(long, default_value = "5")]
        timeout: u64,
    },

    /// Fetch server certificate chain
    #[command(after_help = "Examples:
  pki probe fetch example.com --output chain.pem
  pki probe fetch example.com:443")]
    Fetch {
        /// Target server
        target: String,

        /// Output file for certificate chain
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,

        /// Connection timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,
    },
}

/// Run probe command.
pub fn run(cmd: ProbeCommands, config: &GlobalConfig) -> Result<CmdResult> {
    match cmd {
        ProbeCommands::Server {
            target,
            timeout,
            no_lint,
            check_protocols,
            sni,
            no_verify,
        } => probe_server(
            target,
            timeout,
            !no_lint,
            check_protocols,
            sni,
            no_verify,
            config,
        ),
        ProbeCommands::Lint {
            files,
            skip_info,
            skip_rules,
        } => lint_certs(files, skip_info, skip_rules, config),
        ProbeCommands::Check { target, timeout } => quick_check(target, timeout, config),
        ProbeCommands::Fetch {
            target,
            output,
            timeout,
        } => fetch_chain(target, output, timeout, config),
    }
}

/// Probe a server's TLS configuration.
fn probe_server(
    target: String,
    timeout: u64,
    lint: bool,
    check_protocols: bool,
    sni: Option<String>,
    no_verify: bool,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let mut probe = ServerProbe::new()
        .with_timeout(Duration::from_secs(timeout))
        .with_lint(lint)
        .with_protocol_check(check_protocols)
        .with_no_verify(no_verify);

    if let Some(sni_host) = sni {
        probe = probe.with_sni(sni_host);
    }

    if !config.quiet {
        println!("Probing: {target}");
        println!();
    }

    let result = probe
        .probe(&target)
        .with_context(|| format!("Failed to probe {target}"))?;

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&result)?;
            println!("{json}");
        }
        OutputFormat::Text | OutputFormat::Compact => {
            println!("{}", "TLS Configuration".bold());
            println!();

            println!("  Host:          {}:{}", result.hostname, result.port);
            if let Some(ref proto) = result.protocol_version {
                println!("  Protocol:      {proto}");
            }
            if let Some(ref cipher) = result.cipher_suite {
                println!("  Cipher:        {cipher}");
            }
            if let Some(ref kx) = result.key_exchange {
                // Format key exchange with PQ indicator
                let kx_display = format_key_exchange(kx);
                println!("  Key Exchange:  {kx_display}");
            }
            println!("  Connect Time:  {} ms", result.connection_time_ms);
            println!("  Handshake:     {} ms", result.handshake_time_ms);

            if !result.supported_protocols.is_empty() {
                println!("  Supported:     {}", result.supported_protocols.join(", "));
            }

            // Certificate chain
            if !result.certificate_chain.is_empty() {
                println!();
                println!("{}", "Certificate Chain".bold());

                for cert in &result.certificate_chain {
                    println!();
                    let position = if cert.chain_position == 0 {
                        "Leaf".to_string()
                    } else if cert.is_ca {
                        format!("CA [{}]", cert.chain_position)
                    } else {
                        format!("Intermediate [{}]", cert.chain_position)
                    };

                    println!("  {} {}", position.cyan(), cert.subject);
                    println!("    Issuer:     {}", cert.issuer);
                    println!("    Serial:     {}", cert.serial);
                    println!("    Algorithm:  {} {:?}", cert.key_algorithm, cert.key_size);
                    println!(
                        "    Valid:      {} to {}",
                        cert.not_before.format("%Y-%m-%d"),
                        cert.not_after.format("%Y-%m-%d")
                    );

                    let expiry_str = if cert.days_until_expiry < 0 {
                        format!("EXPIRED {} days ago", -cert.days_until_expiry)
                            .red()
                            .to_string()
                    } else if cert.days_until_expiry < 30 {
                        format!("{} days", cert.days_until_expiry)
                            .yellow()
                            .to_string()
                    } else {
                        format!("{} days", cert.days_until_expiry)
                            .green()
                            .to_string()
                    };
                    println!("    Expires in: {expiry_str}");

                    if !cert.san.is_empty() && cert.chain_position == 0 {
                        println!("    SANs:       {}", cert.san.join(", "));
                    }
                }
            }

            // Warnings
            if !result.warnings.is_empty() {
                println!();
                println!("{}", "Security Warnings".yellow().bold());
                for warning in &result.warnings {
                    println!("  {} {warning}", "⚠".yellow());
                }
            }

            // Lint results
            if !result.lint_results.is_empty() {
                println!();
                println!("{}", "Lint Results".bold());
                for lint in &result.lint_results {
                    let severity_str = match lint.severity {
                        LintSeverity::Critical => {
                            lint.severity.to_string().red().bold().to_string()
                        }
                        LintSeverity::Error => lint.severity.to_string().red().to_string(),
                        LintSeverity::Warning => lint.severity.to_string().yellow().to_string(),
                        LintSeverity::Info => lint.severity.to_string().dimmed().to_string(),
                    };

                    println!("  [{severity_str}] {}: {}", lint.rule_id, lint.message);
                    if let Some(ref details) = lint.details {
                        println!("           {}", details.dimmed());
                    }
                }
            }
        }
    }

    // Return appropriate exit code based on findings
    let has_critical = result
        .lint_results
        .iter()
        .any(|r| r.severity == LintSeverity::Critical);
    let has_error = result
        .lint_results
        .iter()
        .any(|r| r.severity == LintSeverity::Error);

    if has_critical {
        Ok(CmdResult::ExitCode(2))
    } else if has_error {
        Ok(CmdResult::ExitCode(1))
    } else {
        Ok(CmdResult::Success)
    }
}

/// Lint certificate files.
fn lint_certs(
    files: Vec<PathBuf>,
    skip_info: bool,
    skip_rules: Option<String>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    let mut linter = CertLinter::new();

    if skip_info {
        linter = linter.skip_info();
    }

    if let Some(rules) = skip_rules {
        let rules: Vec<String> = rules.split(',').map(|s| s.trim().to_string()).collect();
        linter = linter.skip_rules(rules);
    }

    let mut all_results = Vec::new();
    let mut total_certs = 0;

    for file in &files {
        if !config.quiet {
            println!("Linting: {}", file.display());
        }

        let pem_data = std::fs::read_to_string(file)
            .with_context(|| format!("Failed to read {}", file.display()))?;

        // Parse all certificates from file
        let certs: Vec<Vec<u8>> = pem::parse_many(&pem_data)
            .map_err(|e| anyhow::anyhow!("Failed to parse PEM: {e}"))?
            .into_iter()
            .filter(|p| p.tag() == "CERTIFICATE")
            .map(|p| p.contents().to_vec())
            .collect();

        total_certs += certs.len();

        let results = linter.lint_chain(&certs);
        all_results.extend(results);
    }

    if !config.quiet {
        println!();
        println!("Checked {} certificate(s)", total_certs);
        println!();
    }

    match config.format {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&all_results)?;
            println!("{json}");
        }
        OutputFormat::Text | OutputFormat::Compact => {
            if all_results.is_empty() {
                println!("{}", "No issues found!".green().bold());
            } else {
                println!("{} issue(s) found:", all_results.len());
                println!();

                for lint in &all_results {
                    let severity_str = match lint.severity {
                        LintSeverity::Critical => {
                            lint.severity.to_string().red().bold().to_string()
                        }
                        LintSeverity::Error => lint.severity.to_string().red().to_string(),
                        LintSeverity::Warning => lint.severity.to_string().yellow().to_string(),
                        LintSeverity::Info => lint.severity.to_string().dimmed().to_string(),
                    };

                    let cert_info = lint
                        .cert_index
                        .map(|i| format!(" (cert {})", i))
                        .unwrap_or_default();

                    println!(
                        "[{severity_str}] {}{cert_info}: {}",
                        lint.rule_id, lint.message
                    );
                    if let Some(ref details) = lint.details {
                        println!("         {}", details.dimmed());
                    }
                }
            }
        }
    }

    // Return exit code based on findings
    let has_critical = all_results
        .iter()
        .any(|r| r.severity == LintSeverity::Critical);
    let has_error = all_results
        .iter()
        .any(|r| r.severity == LintSeverity::Error);

    if has_critical {
        Ok(CmdResult::ExitCode(2))
    } else if has_error {
        Ok(CmdResult::ExitCode(1))
    } else {
        Ok(CmdResult::Success)
    }
}

/// Quick TLS check.
fn quick_check(target: String, timeout: u64, config: &GlobalConfig) -> Result<CmdResult> {
    let probe = ServerProbe::new()
        .with_timeout(Duration::from_secs(timeout))
        .with_lint(false)
        .with_protocol_check(false);

    if !config.quiet {
        print!("Checking {target}... ");
    }

    match probe.check_tls(&target) {
        Ok(true) => {
            if !config.quiet {
                println!("{}", "TLS OK".green().bold());
            }

            if config.format == OutputFormat::Json {
                let result = serde_json::json!({
                    "target": target,
                    "tls_supported": true
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            }

            Ok(CmdResult::Success)
        }
        Ok(false) => {
            if !config.quiet {
                println!("{}", "TLS FAILED".red().bold());
            }

            if config.format == OutputFormat::Json {
                let result = serde_json::json!({
                    "target": target,
                    "tls_supported": false
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            }

            Ok(CmdResult::ExitCode(1))
        }
        Err(e) => {
            if !config.quiet {
                println!("{}", "TLS FAILED".red().bold());
            }
            if config.verbose {
                eprintln!("  Error: {e}");
            }

            if config.format == OutputFormat::Json {
                let result = serde_json::json!({
                    "target": target,
                    "tls_supported": false,
                    "error": e.to_string()
                });
                println!("{}", serde_json::to_string_pretty(&result)?);
            }

            Ok(CmdResult::ExitCode(1))
        }
    }
}

/// Fetch certificate chain from server.
fn fetch_chain(
    target: String,
    output: Option<PathBuf>,
    timeout: u64,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let probe = ServerProbe::new()
        .with_timeout(Duration::from_secs(timeout))
        .with_lint(false)
        .with_protocol_check(false);

    if !config.quiet {
        println!("Fetching certificate chain from: {target}");
        println!();
    }

    let result = probe
        .probe(&target)
        .with_context(|| format!("Failed to probe {target}"))?;

    if result.raw_certificates.is_empty() {
        if !config.quiet {
            println!("{}", "No certificates received".yellow());
        }
        return Ok(CmdResult::ExitCode(1));
    }

    if !config.quiet {
        println!(
            "Retrieved {} certificate(s):",
            result.certificate_chain.len()
        );
        for (i, cert) in result.certificate_chain.iter().enumerate() {
            println!("  {}. {}", i + 1, cert.subject);
        }
    }

    // Convert DER certificates to PEM format
    let mut pem_output = String::new();
    for der in &result.raw_certificates {
        let b64 = STANDARD.encode(der);
        pem_output.push_str("-----BEGIN CERTIFICATE-----\n");
        // Wrap at 64 characters per line
        for chunk in b64.as_bytes().chunks(64) {
            pem_output.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            pem_output.push('\n');
        }
        pem_output.push_str("-----END CERTIFICATE-----\n\n");
    }

    if let Some(output_path) = output {
        std::fs::write(&output_path, &pem_output)
            .with_context(|| format!("Failed to write {}", output_path.display()))?;

        if !config.quiet {
            println!();
            println!(
                "{} Certificate chain saved to: {}",
                "✓".green(),
                output_path.display()
            );
        }
    } else {
        // Print to stdout
        println!();
        print!("{pem_output}");
    }

    Ok(CmdResult::Success)
}

/// Format key exchange group with PQ indicator.
fn format_key_exchange(kx: &str) -> String {
    // Check if this is a post-quantum hybrid key exchange
    let is_pqc = kx.contains("MLKEM") || kx.contains("Kyber");

    // Format the name more readably
    let name = match kx {
        "X25519MLKEM768" => "X25519 + ML-KEM-768",
        "SECP256R1MLKEM768" => "P-256 + ML-KEM-768",
        "secp256r1MLKEM768" => "P-256 + ML-KEM-768",
        "X25519" => "X25519",
        "secp256r1" => "P-256 (secp256r1)",
        "secp384r1" => "P-384 (secp384r1)",
        "secp521r1" => "P-521 (secp521r1)",
        other => other,
    };

    if is_pqc {
        format!("{} {}", name, "(PQ Hybrid)".cyan())
    } else {
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_key_exchange_x25519() {
        let result = format_key_exchange("X25519");
        assert_eq!(result, "X25519");
    }

    #[test]
    fn test_format_key_exchange_p256() {
        let result = format_key_exchange("secp256r1");
        assert_eq!(result, "P-256 (secp256r1)");
    }

    #[test]
    fn test_format_key_exchange_p384() {
        let result = format_key_exchange("secp384r1");
        assert_eq!(result, "P-384 (secp384r1)");
    }

    #[test]
    fn test_format_key_exchange_p521() {
        let result = format_key_exchange("secp521r1");
        assert_eq!(result, "P-521 (secp521r1)");
    }

    #[test]
    fn test_format_key_exchange_pq_hybrid_x25519_mlkem() {
        let result = format_key_exchange("X25519MLKEM768");
        assert!(result.contains("X25519 + ML-KEM-768"));
        assert!(result.contains("PQ Hybrid"));
    }

    #[test]
    fn test_format_key_exchange_pq_hybrid_p256_mlkem() {
        let result = format_key_exchange("SECP256R1MLKEM768");
        assert!(result.contains("P-256 + ML-KEM-768"));
        assert!(result.contains("PQ Hybrid"));
    }

    #[test]
    fn test_format_key_exchange_pq_hybrid_lowercase_p256_mlkem() {
        let result = format_key_exchange("secp256r1MLKEM768");
        assert!(result.contains("P-256 + ML-KEM-768"));
        assert!(result.contains("PQ Hybrid"));
    }

    #[test]
    fn test_format_key_exchange_unknown() {
        let result = format_key_exchange("some_new_kex");
        assert_eq!(result, "some_new_kex");
    }

    #[test]
    fn test_format_key_exchange_kyber_is_pqc() {
        // Any string containing "Kyber" should be flagged as PQ
        let result = format_key_exchange("X25519Kyber768");
        assert!(result.contains("PQ Hybrid"));
    }
}
