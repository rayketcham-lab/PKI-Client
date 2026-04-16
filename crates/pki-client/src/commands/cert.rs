//! Certificate commands - view, verify, convert, compare.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use colored::Colorize;
use std::io::{self, Read, Write};
use std::path::PathBuf;

use super::show as show_cmd;
use crate::compat::{
    load_certificate, CertLinter, Certificate, CrlChecker, DetectedFileType, LintSeverity,
    OcspChecker, RevocationStatus,
};
use pki_client_output::{Formatter, OutputFormat};

use super::CmdResult;
use crate::config::GlobalConfig;

/// Load a certificate from file, stdin (-), or inline PEM content.
fn load_cert_flexible(path: &std::path::Path) -> Result<Certificate> {
    let path_str = path.to_string_lossy();

    // Check for stdin
    if path_str == "-" {
        let mut buffer = Vec::new();
        io::stdin()
            .read_to_end(&mut buffer)
            .context("Failed to read from stdin")?;
        let text = String::from_utf8_lossy(&buffer);
        return Certificate::from_pem(&text)
            .or_else(|_| Certificate::from_der(&buffer))
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate from stdin: {}", e));
    }

    // Check if it looks like inline PEM content
    if path_str.starts_with("-----BEGIN") {
        return Certificate::from_pem(&path_str)
            .map_err(|e| anyhow::anyhow!("Failed to parse inline PEM certificate: {}", e));
    }

    // Otherwise, load from file
    load_certificate(path)
}

/// Certificate operations
#[derive(Subcommand)]
pub enum CertCommands {
    /// Show certificate details
    ///
    /// Display human-readable certificate information including subject, issuer,
    /// validity dates, SANs, key info, and fingerprints.
    #[command(after_help = "Examples:
  pki cert show server.pem              Full certificate details
  pki cert show server.pem --subject    Just the subject DN
  pki cert show server.pem --san        Just the SANs
  pki cert show server.pem -f json      JSON output for scripting")]
    Show(ShowArgs),

    /// Check certificate expiration
    ///
    /// Check if certificates expire within a given time window.
    /// Returns exit code 0 if OK, 10 if expiring soon, 4 if already expired.
    #[command(after_help = "Examples:
  pki cert expires server.pem               Show days until expiry
  pki cert expires server.pem --within 30d  Check if expires in 30 days
  pki cert expires *.pem --within 90d       Check multiple certificates
  pki cert expires server.pem --epoch       Show expiry as Unix timestamp")]
    Expires(ExpiresArgs),

    /// Show certificate fingerprint
    ///
    /// Calculate and display certificate fingerprints (SHA-256 and SHA-1).
    #[command(after_help = "Examples:
  pki cert fingerprint server.pem           SHA-256 fingerprint
  pki cert fingerprint server.pem --sha1    SHA-1 fingerprint
  pki cert fingerprint server.pem --raw     No colons, just hex")]
    Fingerprint(FingerprintArgs),
    // Future commands:
    // /// Verify certificate signature
    // Verify(VerifyArgs),
    //
    // /// Convert certificate format
    // Convert(ConvertArgs),
    //
    // /// Compare two certificates
    // Diff(DiffArgs),
}

/// Arguments for 'cert show' command
#[derive(Args)]
pub struct ShowArgs {
    /// Certificate file (PEM or DER format, auto-detected)
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Show only the subject DN
    #[arg(long, conflicts_with_all = &["san", "issuer"])]
    pub subject: bool,

    /// Show only Subject Alternative Names
    #[arg(long, conflicts_with_all = &["subject", "issuer"])]
    pub san: bool,

    /// Show only the issuer DN
    #[arg(long, conflicts_with_all = &["subject", "san"])]
    pub issuer: bool,

    /// Check revocation status via OCSP/CRL
    #[arg(long, short = 'c')]
    pub check: bool,

    /// Issuer certificate (for OCSP check)
    #[arg(long, short = 'i', value_name = "ISSUER_FILE")]
    pub issuer_cert: Option<PathBuf>,

    /// Run security linting checks
    #[arg(long, short = 'l')]
    pub lint: bool,

    /// Interactive mode - menu-driven exploration
    #[arg(long, short = 'I')]
    pub interactive: bool,

    /// Full analysis: show all details, lint, and check revocation
    #[arg(long, short = 'a')]
    pub all: bool,

    /// Skip fetching and displaying certificate chain
    #[arg(long)]
    pub no_chain: bool,
}

/// Arguments for 'cert expires' command
#[derive(Args)]
pub struct ExpiresArgs {
    /// Certificate file(s) to check
    #[arg(value_name = "FILE", required = true)]
    pub files: Vec<PathBuf>,

    /// Check if expires within this duration (e.g., "30d", "2w", "6months")
    #[arg(long, short = 'w', value_name = "DURATION")]
    pub within: Option<String>,

    /// Output expiry time as Unix epoch timestamp
    #[arg(long)]
    pub epoch: bool,
}

/// Arguments for 'cert fingerprint' command
#[derive(Args)]
pub struct FingerprintArgs {
    /// Certificate file
    #[arg(value_name = "FILE")]
    pub file: PathBuf,

    /// Use SHA-1 instead of SHA-256 (not recommended for security)
    #[arg(long)]
    pub sha1: bool,

    /// Output without colons (raw hex)
    #[arg(long)]
    pub raw: bool,
}

/// Run a certificate command.
pub fn run(cmd: CertCommands, config: &GlobalConfig) -> Result<CmdResult> {
    match cmd {
        CertCommands::Show(args) => show(args, config),
        CertCommands::Expires(args) => expires(args, config),
        CertCommands::Fingerprint(args) => fingerprint(args, config),
    }
}

fn show(args: ShowArgs, config: &GlobalConfig) -> Result<CmdResult> {
    // Try to load as certificate first
    let cert = match load_cert_flexible(&args.file) {
        Ok(cert) => cert,
        Err(_) => {
            // Detect actual file type and show it with a tip
            let data = std::fs::read(&args.file)
                .with_context(|| format!("Failed to read file: {}", args.file.display()))?;
            let detection = DetectedFileType::detect_with_confidence(&data, &args.file);

            // If it's a different PKI type, show it and suggest the right command
            if detection.file_type != DetectedFileType::Certificate
                && detection.file_type != DetectedFileType::Unknown
            {
                // Show the file using auto-detection
                if let Some(result) = show_cmd::auto_show(&args.file, config)? {
                    // Add a helpful tip
                    if !config.quiet {
                        println!();
                        let cmd = match detection.file_type {
                            DetectedFileType::Crl => "pki crl show",
                            DetectedFileType::Csr => "pki csr show",
                            DetectedFileType::PrivateKey | DetectedFileType::PublicKey => {
                                "pki key show"
                            }
                            DetectedFileType::Pkcs7 => "pki p7 show",
                            DetectedFileType::Pkcs12 => "pki p12 show",
                            _ => "pki show",
                        };
                        println!(
                            "{} For {} files, you can also use: {}",
                            "Tip:".cyan().bold(),
                            show_cmd::type_name(detection.file_type).dimmed(),
                            cmd.white().bold()
                        );
                    }
                    return Ok(result);
                }
            }
            // Re-attempt load to get the original error message
            return Err(anyhow::anyhow!(
                "Failed to load certificate: {}",
                args.file.display()
            ));
        }
    };

    // Handle interactive mode
    if args.interactive {
        return run_interactive_mode(&cert, args.issuer_cert.as_ref(), config);
    }

    // Handle --all flag (full analysis)
    let (do_lint, do_check) = if args.all {
        (true, true)
    } else {
        (args.lint, args.check)
    };

    let output = if args.subject {
        cert.subject.clone()
    } else if args.san {
        if cert.san.is_empty() {
            "No Subject Alternative Names".to_string()
        } else {
            cert.san
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        }
    } else if args.issuer {
        cert.issuer.clone()
    } else {
        cert.format(config.format, config.colored)
    };

    println!("{output}");

    // Show certificate chain tree (unless quiet, --no-chain, or showing single field)
    let showing_full_cert = !args.subject && !args.san && !args.issuer;
    if showing_full_cert && !config.quiet && !args.no_chain {
        let chain = build_chain_from_cert(&cert);
        display_chain_tree(&chain, config.colored);
    }

    // Run lint checks if requested
    if do_lint {
        println!();
        run_lint_check(&cert, config);
    }

    // Perform revocation check if requested
    if do_check {
        println!();
        let revoke_result = check_revocation_inline(&cert, args.issuer_cert.as_ref(), config)?;

        // Return appropriate exit code based on revocation status
        return Ok(CmdResult::ExitCode(revoke_result.status.exit_code()));
    }

    Ok(CmdResult::Success)
}

/// Run lint checks on a certificate.
fn run_lint_check(cert: &Certificate, config: &GlobalConfig) {
    let linter = CertLinter::new();
    let der_vec = cert.raw_der().to_vec();
    let results = linter.lint_chain(&[der_vec]);

    if config.quiet {
        return;
    }

    println!("{}:", "Security Analysis".cyan().bold());

    if results.is_empty() {
        println!(
            "    Result:     {} No security issues found",
            "✓".green().bold()
        );
    } else {
        let critical = results
            .iter()
            .filter(|r| r.severity == LintSeverity::Critical)
            .count();
        let errors = results
            .iter()
            .filter(|r| r.severity == LintSeverity::Error)
            .count();
        let warnings = results
            .iter()
            .filter(|r| r.severity == LintSeverity::Warning)
            .count();
        let info = results
            .iter()
            .filter(|r| r.severity == LintSeverity::Info)
            .count();

        println!(
            "    Result:     {} issues ({} critical, {} errors, {} warnings, {} info)",
            results.len(),
            critical.to_string().red().bold(),
            errors.to_string().red(),
            warnings.to_string().yellow(),
            info.to_string().dimmed()
        );
        println!();

        for result in &results {
            let severity_icon = match result.severity {
                LintSeverity::Critical => "✗".red().bold(),
                LintSeverity::Error => "✗".red(),
                LintSeverity::Warning => "⚠".yellow().bold(),
                LintSeverity::Info => "i".dimmed(),
            };

            let severity_str = match result.severity {
                LintSeverity::Critical => "CRITICAL".red().bold(),
                LintSeverity::Error => "ERROR".red(),
                LintSeverity::Warning => "WARN".yellow(),
                LintSeverity::Info => "INFO".dimmed(),
            };

            println!(
                "    {} {}  [{}]",
                severity_icon,
                severity_str,
                result.rule_id.dimmed()
            );
            println!("            {}", result.message);

            if let Some(details) = &result.details {
                println!("            {}", details.dimmed());
            }
            println!();
        }
    }

    // Add security recommendations
    print_security_recommendations(cert);
}

/// Print security recommendations based on certificate analysis.
fn print_security_recommendations(cert: &Certificate) {
    let mut recommendations = Vec::new();

    // Check key strength
    if cert.key_algorithm_name == "RSA" && cert.key_size < 2048 {
        recommendations
            .push("Upgrade to RSA 2048+ bits (current key is critically weak)".to_string());
    } else if cert.key_algorithm_name == "RSA" && cert.key_size == 2048 {
        recommendations.push("Consider RSA 3072+ or ECDSA P-256 for improved security".to_string());
    }

    // Check signature algorithm
    if cert.signature_algorithm_name.contains("SHA-1") {
        recommendations.push("Replace certificate - SHA-1 signatures are broken".to_string());
    }

    // Check validity period and lifetime
    let days = cert.days_until_expiry();
    let lifetime_pct = cert.lifetime_used_percent();
    if days < 0 {
        recommendations.push("Certificate is EXPIRED - replace immediately".to_string());
    } else if days < 30 {
        recommendations.push(format!(
            "Certificate expires in {} days - renew immediately",
            days
        ));
    } else if lifetime_pct >= 70.0 {
        recommendations.push(format!(
            "Certificate is {:.0}% through its lifetime - start renewal process",
            lifetime_pct
        ));
    }

    // Check for SANs
    if cert.san.is_empty() && !cert.is_ca {
        recommendations.push("Add Subject Alternative Names (browsers require SANs)".to_string());
    }

    // Check for Certificate Transparency
    if cert.ct_scts.is_empty() && !cert.is_ca && !cert.is_self_signed() {
        recommendations.push("Consider Certificate Transparency for public trust".to_string());
    }

    // Check for revocation endpoints
    if cert.ocsp_urls.is_empty() && cert.crl_distribution_points.is_empty() {
        recommendations.push("No revocation endpoints - consider adding OCSP/CRL".to_string());
    }

    if recommendations.is_empty() {
        println!(
            "    {} Certificate follows security best practices",
            "✓".green().bold()
        );
    } else {
        println!("    {}:", "Recommendations".bold());
        for rec in recommendations {
            println!("        • {}", rec);
        }
    }
}

/// Interactive menu mode for certificate exploration.
fn run_interactive_mode(
    cert: &Certificate,
    issuer_path: Option<&PathBuf>,
    config: &GlobalConfig,
) -> Result<CmdResult> {
    // Show brief summary first
    let cn = cert.common_name().unwrap_or(&cert.subject);
    let days = cert.days_until_expiry();
    let lifetime_pct = cert.lifetime_used_percent();
    let status = if days < 0 {
        "EXPIRED".red().bold()
    } else if days < 30 {
        "EXPIRING".yellow().bold()
    } else if lifetime_pct >= 70.0 {
        "RENEW SOON".yellow().bold()
    } else {
        "OK".green().bold()
    };

    // Build lifetime bar
    let bar_width = 20;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let filled = ((lifetime_pct / 100.0) * bar_width as f64).clamp(0.0, bar_width as f64) as usize;
    let empty = bar_width - filled;
    let bar = if lifetime_pct >= 100.0 {
        format!("{}", "█".repeat(bar_width).red())
    } else if lifetime_pct >= 70.0 {
        format!(
            "{}{}",
            "█".repeat(filled).yellow(),
            "░".repeat(empty).dimmed()
        )
    } else {
        format!(
            "{}{}",
            "█".repeat(filled).green(),
            "░".repeat(empty).dimmed()
        )
    };

    println!();
    println!("{}:", "Certificate Quick View".cyan().bold());
    println!("    Subject:    {}", cn.bold());
    println!(
        "    Issuer:     {}",
        cert.issuer.chars().take(55).collect::<String>()
    );
    println!("    Status:     {} ({} days remaining)", status, days);
    println!("    Lifetime:   [{}] {:.1}%", bar, lifetime_pct.min(100.0));
    println!(
        "    Key:        {} {} bits",
        cert.key_algorithm_name, cert.key_size
    );
    println!();

    loop {
        println!("{}:", "Actions".cyan().bold());
        println!("    1. Show full details");
        println!("    2. Security lint");
        println!("    3. Check revocation");
        println!("    4. Show SANs");
        println!("    5. Fingerprints");
        println!("    6. Extensions");
        println!("    7. Export JSON");
        println!("    8. Full analysis");
        println!("    q. Quit");
        println!();
        print!("{} ", "Select:".cyan());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let choice = input.trim().to_lowercase();

        println!();

        match choice.as_str() {
            "1" => {
                println!("{}", cert.format(config.format, config.colored));
            }
            "2" => {
                run_lint_check(cert, config);
            }
            "3" => {
                let _ = check_revocation_inline(cert, issuer_path, config);
            }
            "4" => {
                println!("{}:", "Subject Alternative Names".cyan().bold());
                if cert.san.is_empty() {
                    println!("    (none)");
                } else {
                    for san in &cert.san {
                        println!("    {}", san);
                    }
                }
            }
            "5" => {
                println!("{}:", "Fingerprints".cyan().bold());
                println!("    SHA-256:    {}", cert.fingerprint_sha256.cyan());
                println!("    SHA-1:      {}", cert.fingerprint_sha1.dimmed());
                println!("    SPKI Pin:   {}", cert.spki_sha256_b64.green());
            }
            "6" => {
                print_extensions(cert);
            }
            "7" => {
                println!("{}", cert.format(OutputFormat::Json, false));
            }
            "8" => {
                // Full analysis
                println!();
                println!("{}", "FULL CERTIFICATE ANALYSIS".cyan().bold());
                println!();

                println!("{}", "Certificate Details".bold().underline());
                println!("{}", cert.format(config.format, config.colored));

                println!();
                run_lint_check(cert, config);

                println!();
                println!("{}", "Revocation Status".bold().underline());
                let _ = check_revocation_inline(cert, issuer_path, config);
                println!();
            }
            "q" | "quit" | "exit" => {
                println!("{}", "Goodbye!".dimmed());
                break;
            }
            _ => {
                println!("{}", "Invalid choice. Enter 1-8 or q.".yellow());
            }
        }

        println!();
    }

    Ok(CmdResult::Success)
}

/// Print certificate extensions.
fn print_extensions(cert: &Certificate) {
    println!("{}", "X509v3 Extensions:".bold());

    // Basic Constraints
    if cert.is_ca || cert.basic_constraints_critical {
        print!("  Basic Constraints");
        if cert.basic_constraints_critical {
            print!(" {}", "(critical)".yellow());
        }
        println!(":");
        println!(
            "    CA: {}",
            if cert.is_ca {
                "TRUE".green()
            } else {
                "FALSE".red()
            }
        );
        if cert.path_length >= 0 {
            println!("    Path Length: {}", cert.path_length);
        }
    }

    // Key Usage
    if !cert.key_usage.is_empty() {
        print!("  Key Usage");
        if cert.key_usage_critical {
            print!(" {}", "(critical)".yellow());
        }
        println!(":");
        println!("    {}", cert.key_usage.join(", "));
    }

    // Extended Key Usage
    if !cert.extended_key_usage.is_empty() {
        println!("  Extended Key Usage:");
        println!("    {}", cert.extended_key_usage.join(", "));
    }

    // SANs
    if !cert.san.is_empty() {
        println!("  Subject Alternative Names:");
        for san in &cert.san {
            println!("    {}", san);
        }
    }

    // Key Identifiers
    if let Some(ref ski) = cert.subject_key_id {
        println!("  Subject Key Identifier:");
        println!("    {}", ski);
    }
    if let Some(ref aki) = cert.authority_key_id {
        println!("  Authority Key Identifier:");
        println!("    {}", aki);
    }

    // OCSP/CRL
    if !cert.ocsp_urls.is_empty() || !cert.ca_issuer_urls.is_empty() {
        println!("  Authority Information Access:");
        for url in &cert.ocsp_urls {
            println!("    OCSP: {}", url);
        }
        for url in &cert.ca_issuer_urls {
            println!("    CA Issuers: {}", url);
        }
    }

    if !cert.crl_distribution_points.is_empty() {
        println!("  CRL Distribution Points:");
        for url in &cert.crl_distribution_points {
            println!("    {}", url);
        }
    }

    // Certificate Policies
    if !cert.certificate_policies.is_empty() {
        println!("  Certificate Policies:");
        for policy in &cert.certificate_policies {
            println!("    {}", format_policy_oid(policy));
        }
    }

    // CT SCTs
    if !cert.ct_scts.is_empty() {
        println!(
            "  Certificate Transparency SCTs: {} embedded",
            cert.ct_scts.len()
        );
    }
}

/// Format a policy OID to a human-readable name.
fn format_policy_oid(oid: &str) -> String {
    match oid {
        "2.23.140.1.2.1" => format!("{} (Domain Validated - DV)", oid),
        "2.23.140.1.2.2" => format!("{} (Organization Validated - OV)", oid),
        "2.23.140.1.1" => format!("{} (Extended Validation - EV)", oid),
        "2.23.140.1.2.3" => format!("{} (Individual Validated - IV)", oid),
        "2.5.29.32.0" => format!("{} (Any Policy)", oid),
        _ => oid.to_string(),
    }
}

/// Check revocation status inline during cert show.
fn check_revocation_inline(
    cert: &Certificate,
    issuer_path: Option<&PathBuf>,
    config: &GlobalConfig,
) -> Result<crate::compat::RevocationCheckResult> {
    // Load issuer if provided
    let issuer = if let Some(path) = issuer_path {
        let issuer_data = std::fs::read(path)
            .with_context(|| format!("Failed to read issuer: {}", path.display()))?;
        let issuer_text = String::from_utf8_lossy(&issuer_data);
        Some(
            Certificate::from_pem(&issuer_text)
                .or_else(|_| Certificate::from_der(&issuer_data))
                .map_err(|e| {
                    anyhow::anyhow!("Failed to parse issuer: {}: {}", path.display(), e)
                })?,
        )
    } else {
        None
    };

    // Check if cert has OCSP or CRL endpoints
    let has_ocsp = !cert.ocsp_urls.is_empty();
    let has_crl = !cert.crl_distribution_points.is_empty();

    if !has_ocsp && !has_crl {
        if !config.quiet {
            println!("{}:", "Revocation Status".cyan().bold());
            println!(
                "    Status:     {} - No OCSP or CRL endpoints in certificate",
                "? UNKNOWN".yellow().bold()
            );
        }
        let result = crate::compat::RevocationCheckResult {
            status: RevocationStatus::Unknown {
                reason: "No OCSP or CRL endpoints in certificate".to_string(),
            },
            method: crate::compat::RevocationMethod::Crl, // Placeholder
            response_time_ms: None,
            url: None,
            checked_at: chrono::Utc::now(),
            source_url: None,
            valid_until: None,
            serial: cert.serial.clone(),
            subject: cert.subject.clone(),
        };
        return Ok(result);
    }

    if !config.quiet {
        println!("{}:", "Revocation Status".cyan().bold());
    }

    // Try OCSP first if available (and we have issuer), then fall back to CRL
    let result = if let (true, Some(issuer_cert)) = (has_ocsp, issuer.as_ref()) {
        if !config.quiet {
            println!(
                "    Checking:   OCSP {}...",
                cert.ocsp_urls.first().unwrap_or(&String::new()).dimmed()
            );
        }
        let checker = OcspChecker::new().with_timeout(std::time::Duration::from_secs(10));
        match checker.check(cert, issuer_cert) {
            Ok(status) => crate::compat::RevocationCheckResult {
                status,
                method: crate::compat::RevocationMethod::Ocsp,
                response_time_ms: None,
                url: cert.ocsp_urls.first().cloned(),
                checked_at: chrono::Utc::now(),
                source_url: cert.ocsp_urls.first().cloned(),
                valid_until: None,
                serial: cert.serial.clone(),
                subject: cert.subject.clone(),
            },
            Err(e) if has_crl => {
                if !config.quiet {
                    println!(
                        "    OCSP:       {} ({}), trying CRL...",
                        "failed".yellow(),
                        e.to_string().chars().take(40).collect::<String>().dimmed()
                    );
                }
                check_crl(cert)?
            }
            Err(e) => crate::compat::RevocationCheckResult {
                status: RevocationStatus::Unknown {
                    reason: format!("OCSP check failed: {e}"),
                },
                method: crate::compat::RevocationMethod::Ocsp,
                response_time_ms: None,
                url: cert.ocsp_urls.first().cloned(),
                checked_at: chrono::Utc::now(),
                source_url: cert.ocsp_urls.first().cloned(),
                valid_until: None,
                serial: cert.serial.clone(),
                subject: cert.subject.clone(),
            },
        }
    } else if has_crl {
        if !config.quiet && has_ocsp && issuer.is_none() {
            println!("    Note:       Provide --issuer-cert for OCSP check");
        }
        if !config.quiet {
            println!(
                "    Checking:   CRL {}...",
                cert.crl_distribution_points
                    .first()
                    .unwrap_or(&String::new())
                    .dimmed()
            );
        }
        check_crl(cert)?
    } else {
        // Shouldn't reach here, but just in case
        crate::compat::RevocationCheckResult {
            status: RevocationStatus::Unknown {
                reason: "No revocation check method available".to_string(),
            },
            method: crate::compat::RevocationMethod::Crl,
            response_time_ms: None,
            url: None,
            checked_at: chrono::Utc::now(),
            source_url: None,
            valid_until: None,
            serial: cert.serial.clone(),
            subject: cert.subject.clone(),
        }
    };

    print_revocation_status(&result, config);

    Ok(result)
}

/// Check CRL for certificate.
fn check_crl(cert: &Certificate) -> Result<crate::compat::RevocationCheckResult> {
    let checker = CrlChecker::new().with_timeout(15);
    match checker.check(cert) {
        Ok(status) => Ok(crate::compat::RevocationCheckResult {
            status,
            method: crate::compat::RevocationMethod::Crl,
            response_time_ms: None,
            url: cert.crl_distribution_points.first().cloned(),
            checked_at: chrono::Utc::now(),
            source_url: cert.crl_distribution_points.first().cloned(),
            valid_until: None,
            serial: cert.serial.clone(),
            subject: cert.subject.clone(),
        }),
        Err(e) => Ok(crate::compat::RevocationCheckResult {
            status: RevocationStatus::Unknown {
                reason: format!("CRL check failed: {e}"),
            },
            method: crate::compat::RevocationMethod::Crl,
            response_time_ms: None,
            url: cert.crl_distribution_points.first().cloned(),
            checked_at: chrono::Utc::now(),
            source_url: cert.crl_distribution_points.first().cloned(),
            valid_until: None,
            serial: cert.serial.clone(),
            subject: cert.subject.clone(),
        }),
    }
}

/// Print revocation status.
fn print_revocation_status(result: &crate::compat::RevocationCheckResult, config: &GlobalConfig) {
    if config.quiet {
        return;
    }

    match config.format {
        OutputFormat::Json => {
            if let Ok(json) = serde_json::to_string_pretty(result) {
                println!("{json}");
            }
        }
        OutputFormat::Text
        | OutputFormat::Forensic
        | OutputFormat::Compact
        | OutputFormat::Openssl => {
            let status_str = match &result.status {
                RevocationStatus::Good => format!(
                    "    Status:     {} - Certificate is NOT revoked",
                    "✓ GOOD".green().bold()
                ),
                RevocationStatus::Revoked { revoked_at, reason } => {
                    let reason_str = reason
                        .as_ref()
                        .map(|r| format!(" ({})", r))
                        .unwrap_or_default();
                    let time_str = revoked_at
                        .map(|t| t.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                        .unwrap_or_else(|| "unknown time".to_string());
                    format!(
                        "    Status:     {} - Revoked on {}{}",
                        "✗ REVOKED".red().bold(),
                        time_str,
                        reason_str
                    )
                }
                RevocationStatus::Unknown { reason } => {
                    format!(
                        "    Status:     {} - {}",
                        "? UNKNOWN".yellow().bold(),
                        reason
                    )
                }
                RevocationStatus::Error(e) => {
                    format!("    Status:     {} - {}", "✗ ERROR".red().bold(), e)
                }
            };

            println!("{status_str}");
            println!("    Method:     {}", result.method);

            if let Some(url) = &result.source_url {
                println!("    Source:     {}", url.dimmed());
            }

            if let Some(valid) = result.valid_until {
                println!("    Valid:      {}", valid.format("%Y-%m-%d %H:%M:%S UTC"));
            }
        }
    }
}

fn expires(args: ExpiresArgs, config: &GlobalConfig) -> Result<CmdResult> {
    use chrono::Duration;
    use humantime::parse_duration;

    let check_duration = args.within.as_ref().map(|s| {
        parse_duration(s)
            .map(|d| Duration::from_std(d).unwrap_or(Duration::days(0)))
            .unwrap_or_else(|_| {
                // Try parsing simple formats like "30d"
                if let Some(days) = s.strip_suffix('d').and_then(|n| n.parse::<i64>().ok()) {
                    Duration::days(days)
                } else if let Some(weeks) = s.strip_suffix('w').and_then(|n| n.parse::<i64>().ok())
                {
                    Duration::weeks(weeks)
                } else {
                    Duration::days(30) // Default
                }
            })
    });

    let mut any_expiring = false;
    let mut any_expired = false;

    for file in &args.files {
        let cert = load_certificate(file)
            .with_context(|| format!("Failed to load: {}", file.display()))?;

        let cn = cert.common_name().unwrap_or("unknown");
        let days = cert.days_until_expiry();

        if args.epoch {
            println!("{}", cert.not_after.timestamp());
        } else if let Some(duration) = check_duration {
            if cert.is_expired() {
                any_expired = true;
                if !config.quiet {
                    use colored::Colorize;
                    println!(
                        "{}: {} (expired {} days ago)",
                        file.display(),
                        "EXPIRED".red().bold(),
                        -days
                    );
                }
            } else if cert.expires_within(duration) {
                any_expiring = true;
                if !config.quiet {
                    use colored::Colorize;
                    println!(
                        "{}: {} (expires in {} days)",
                        file.display(),
                        "EXPIRING".yellow().bold(),
                        days
                    );
                }
            } else if config.verbose {
                use colored::Colorize;
                println!(
                    "{}: {} ({} days remaining)",
                    file.display(),
                    "OK".green(),
                    days
                );
            }
        } else {
            // Just show expiration info
            use colored::Colorize;
            let status = if cert.is_expired() {
                any_expired = true;
                format!("{}", "EXPIRED".red().bold())
            } else if days < 30 {
                any_expiring = true;
                format!("{}", "EXPIRING SOON".yellow().bold())
            } else {
                format!("{}", "OK".green())
            };

            println!(
                "{}: {} | {} | {} days",
                cn,
                status,
                cert.not_after.format("%Y-%m-%d"),
                days
            );
        }
    }

    // Exit codes: 0 = OK, 4 = expired, 10 = expiring soon
    if any_expired {
        Ok(CmdResult::ExitCode(4))
    } else if any_expiring {
        Ok(CmdResult::ExitCode(10))
    } else {
        Ok(CmdResult::Success)
    }
}

fn fingerprint(args: FingerprintArgs, _config: &GlobalConfig) -> Result<CmdResult> {
    let cert = load_certificate(&args.file)
        .with_context(|| format!("Failed to load: {}", args.file.display()))?;

    let fp = if args.sha1 {
        &cert.fingerprint_sha1
    } else {
        &cert.fingerprint_sha256
    };

    let output = if args.raw {
        fp.replace(':', "")
    } else {
        fp.clone()
    };

    println!("{output}");
    Ok(CmdResult::Success)
}

/// Build a certificate chain by fetching issuer certificates from AIA URLs.
/// Returns a Vec where index 0 is the leaf cert and the last index is the root (or furthest we could fetch).
fn build_chain_from_cert(cert: &Certificate) -> Vec<Certificate> {
    use std::collections::HashSet;

    let mut chain: Vec<Certificate> = vec![cert.clone()];
    let mut seen_subjects: HashSet<String> = HashSet::new();
    seen_subjects.insert(cert.subject.clone());

    let mut current = cert.clone();
    let mut depth = 0;
    const MAX_DEPTH: usize = 10;

    while depth < MAX_DEPTH {
        // Check if self-signed (root)
        if current.subject == current.issuer {
            break;
        }

        // Try to fetch issuer from CA Issuers URL
        if current.ca_issuer_urls.is_empty() {
            break;
        }

        let issuer_url = &current.ca_issuer_urls[0];

        match fetch_issuer_cert(issuer_url) {
            Ok(issuer_cert) => {
                // Check for loops
                if seen_subjects.contains(&issuer_cert.subject) {
                    break;
                }
                seen_subjects.insert(issuer_cert.subject.clone());
                chain.push(issuer_cert.clone());
                current = issuer_cert;
                depth += 1;
            }
            Err(_) => {
                break;
            }
        }
    }

    chain
}

/// Check if a certificate appears to be a bridge CA or cross-cert.
fn is_bridge_or_crosscert(cert: &Certificate) -> bool {
    let cn_lower = cert.subject.to_lowercase();
    let keywords = [
        "bridge",
        "certipath",
        "federal bridge",
        "fpki",
        "cross-cert",
    ];
    keywords.iter().any(|k| cn_lower.contains(k))
}

/// Infer organizational chain structure from an issuer DN.
/// Returns a vec of (name, description) tuples representing the inferred hierarchy.
fn infer_org_chain_from_dn(issuer_dn: &str) -> Vec<(String, String)> {
    let mut chain = Vec::new();

    // Parse DN components
    // Example: DC=com, DC=rtx, O=CAs, OU=Class3-G3, CN=Raytheon Technologies Medium Assurance CA
    let mut org_name = String::new();
    let mut ou_name = String::new();
    let mut cn_name = String::new();
    let mut dc_parts: Vec<String> = Vec::new();

    for part in issuer_dn.split(',').map(|s| s.trim()) {
        if let Some(val) = part.strip_prefix("DC=") {
            dc_parts.push(val.to_string());
        } else if let Some(val) = part.strip_prefix("O=") {
            org_name = val.to_string();
        } else if let Some(val) = part.strip_prefix("OU=") {
            ou_name = val.to_string();
        } else if let Some(val) = part.strip_prefix("CN=") {
            cn_name = val.to_string();
        }
    }

    // Build inferred chain (root to leaf)
    // Root: derived from DC components
    if !dc_parts.is_empty() {
        dc_parts.reverse(); // com, rtx -> rtx, com -> "RTX"
        let root_name = if dc_parts.len() >= 2 {
            format!("{} Root CA", dc_parts[0].to_uppercase())
        } else {
            format!("{} Root CA", dc_parts.join("."))
        };
        chain.push((root_name, "inferred from DC".to_string()));
    }

    // Intermediate: from OU or O
    if !ou_name.is_empty() {
        let int_name = if ou_name.contains('-') || ou_name.contains("Class") {
            format!("{} CA", ou_name)
        } else {
            ou_name.clone()
        };
        chain.push((int_name, "from OU".to_string()));
    } else if !org_name.is_empty() && org_name != "CAs" {
        chain.push((org_name.clone(), "from O".to_string()));
    }

    // Issuing CA: from CN (this is the direct issuer)
    if !cn_name.is_empty() {
        chain.push((cn_name, "issuing CA".to_string()));
    }

    chain
}

/// Display a certificate chain with side-by-side comparison of inferred org chain vs AIA path.
fn display_chain_tree(chain: &[Certificate], colored: bool) {
    if chain.is_empty() {
        return;
    }

    let leaf = &chain[0];

    // Check if AIA chain contains bridge CAs
    let has_bridge = chain.iter().any(is_bridge_or_crosscert);

    // Infer organizational chain from leaf's issuer DN
    let inferred = infer_org_chain_from_dn(&leaf.issuer);

    println!();
    if colored {
        println!("{}:", "Certificate Chain".cyan().bold());
    } else {
        println!("Certificate Chain:");
    }
    println!();

    // Column widths
    let col_width = 52;

    // Headers
    if has_bridge && !inferred.is_empty() {
        if colored {
            println!(
                "    {:<width$}    {}",
                "Organizational (inferred)".yellow(),
                "AIA Path (fetched)".cyan(),
                width = col_width
            );
            println!(
                "    {:<width$}    {}",
                "─".repeat(col_width - 2).yellow(),
                "─".repeat(col_width - 2).cyan(),
                width = col_width
            );
        } else {
            println!(
                "    {:<width$}    {}",
                "Organizational (inferred)",
                "AIA Path (fetched)",
                width = col_width
            );
            println!(
                "    {:<width$}    {}",
                "─".repeat(col_width - 2),
                "─".repeat(col_width - 2),
                width = col_width
            );
        }
        println!();

        // Build AIA chain entries (reversed: root to leaf)
        let aia_entries: Vec<_> = chain.iter().rev().collect();

        // Determine max rows needed
        let max_rows = std::cmp::max(inferred.len() + 1, aia_entries.len()); // +1 for leaf cert

        for row in 0..max_rows {
            // Left column: inferred org chain
            let left_line1: String;
            let left_line2: String;

            if row < inferred.len() {
                let (name, _desc) = &inferred[row];
                let prefix = if row == 0 { "" } else { "└─► " };
                let indent = "    ".repeat(row);
                left_line1 = format!("{}{}{}", indent, prefix, truncate_str(name, 45));
                left_line2 = format!("{}    (inferred)", indent);
            } else if row == inferred.len() {
                // Leaf cert in left column
                let prefix = if row == 0 { "" } else { "└─► " };
                let indent = "    ".repeat(row);
                let cn = leaf.common_name().unwrap_or(&leaf.subject);
                left_line1 = format!("{}{}{}", indent, prefix, truncate_str(cn, 45));
                left_line2 = format!(
                    "{}    {} days | {} {}",
                    indent,
                    leaf.days_until_expiry(),
                    leaf.key_algorithm_name,
                    leaf.key_size
                );
            } else {
                left_line1 = String::new();
                left_line2 = String::new();
            }

            // Right column: AIA chain
            let right_line1: String;
            let right_line2: String;

            if row < aia_entries.len() {
                let cert = aia_entries[row];
                let is_leaf = row == aia_entries.len() - 1;
                let cn = cert.common_name().unwrap_or(&cert.subject);
                let prefix = if row == 0 { "" } else { "└─► " };
                let indent = "    ".repeat(row);
                let days = cert.days_until_expiry();

                // Add bridge marker
                let marker = if is_bridge_or_crosscert(cert) {
                    if colored {
                        format!(" {}", "(bridge)".yellow())
                    } else {
                        " (bridge)".to_string()
                    }
                } else if is_leaf {
                    if colored {
                        format!(" {}", "← this cert".dimmed())
                    } else {
                        " ← this cert".to_string()
                    }
                } else {
                    String::new()
                };

                right_line1 = format!("{}{}{}{}", indent, prefix, truncate_str(cn, 42), marker);

                let validity = if days < 0 {
                    if colored {
                        "EXPIRED".red().to_string()
                    } else {
                        "EXPIRED".to_string()
                    }
                } else if days < 30 {
                    if colored {
                        format!("{} days", days).yellow().to_string()
                    } else {
                        format!("{} days", days)
                    }
                } else {
                    if colored {
                        format!("{} days", days).green().to_string()
                    } else {
                        format!("{} days", days)
                    }
                };
                right_line2 = format!(
                    "{}    {} | {} {}",
                    indent, validity, cert.key_algorithm_name, cert.key_size
                );
            } else {
                right_line1 = String::new();
                right_line2 = String::new();
            }

            // Print both columns
            println!(
                "    {:<width$}    {}",
                left_line1,
                right_line1,
                width = col_width
            );
            if !left_line2.is_empty() || !right_line2.is_empty() {
                println!(
                    "    {:<width$}    {}",
                    left_line2,
                    right_line2,
                    width = col_width
                );
            }

            // Connector line
            if row < max_rows - 1 {
                let left_conn = if row < inferred.len() {
                    format!("{}    │", "    ".repeat(row))
                } else {
                    String::new()
                };
                let right_conn = if row < aia_entries.len() - 1 {
                    format!("{}    │", "    ".repeat(row))
                } else {
                    String::new()
                };
                if !left_conn.is_empty() || !right_conn.is_empty() {
                    println!(
                        "    {:<width$}    {}",
                        left_conn,
                        right_conn,
                        width = col_width
                    );
                }
            }
        }

        // Warning about bridge path
        println!();
        if colored {
            println!(
                "    {} AIA path traverses bridge/cross-certification",
                "⚠".yellow()
            );
        } else {
            println!("    ! AIA path traverses bridge/cross-certification");
        }
    } else {
        // No bridge detected - show simple tree
        for (i, cert) in chain.iter().rev().enumerate() {
            let is_root = cert.subject == cert.issuer;
            let is_leaf = i == chain.len() - 1;
            let depth = i;

            let indent = "    ".repeat(depth);
            let connector = if depth == 0 { "" } else { "└─► " };

            let days = cert.days_until_expiry();
            let status_str = if days < 0 {
                "EXPIRED".to_string()
            } else {
                format!("{} days", days)
            };

            let status_colored = if colored {
                if days < 0 {
                    status_str.red().to_string()
                } else if days < 30 {
                    status_str.yellow().to_string()
                } else {
                    status_str.green().to_string()
                }
            } else {
                status_str
            };

            let cn = cert.common_name().unwrap_or(&cert.subject);

            let marker = if is_root && is_leaf {
                "(Self-signed)"
            } else if is_root {
                "(Root)"
            } else if is_leaf {
                "← this certificate"
            } else {
                ""
            };

            if colored {
                println!(
                    "    {}{}{} {}",
                    indent,
                    connector,
                    cn.bold(),
                    marker.dimmed()
                );
            } else {
                println!("    {}{}{} {}", indent, connector, cn, marker);
            }

            let details = format!(
                "    {}    Valid: {} | {} {}",
                indent, status_colored, cert.key_algorithm_name, cert.key_size
            );
            println!("{}", details);

            if !is_leaf {
                println!("    {}    │", indent);
            }
        }
    }
}

/// Truncate a string to max length, adding "..." if truncated.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Fetch an issuer certificate from a URL.
fn fetch_issuer_cert(url: &str) -> Result<Certificate> {
    use std::time::Duration;

    // Use a blocking HTTP client
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("Failed to create HTTP client")?;

    let response = client
        .get(url)
        .send()
        .with_context(|| format!("Failed to fetch: {url}"))?;

    if !response.status().is_success() {
        anyhow::bail!("HTTP {}: {}", response.status(), url);
    }

    let bytes = response.bytes().context("Failed to read response body")?;

    // Try to parse as DER first (most CA Issuers URLs return DER/PKCS7)
    Certificate::from_der(&bytes)
        .or_else(|_| {
            // Try as PEM
            let text = String::from_utf8_lossy(&bytes);
            Certificate::from_pem(&text)
        })
        .or_else(|_| {
            // Try to extract from PKCS7 (p7c/p7b)
            parse_pkcs7_cert(&bytes)
        })
        .with_context(|| format!("Failed to parse certificate from: {url}"))
}

/// Try to parse a certificate from PKCS7 container.
fn parse_pkcs7_cert(data: &[u8]) -> Result<Certificate> {
    // PKCS7 files often have the cert at a known offset
    // Look for the certificate sequence marker
    // This is a simplified approach - just try DER at various offsets

    // First, try to find the certificate sequence in the PKCS7
    // Certificate sequences typically start with 0x30 0x82
    for i in 0..data.len().saturating_sub(4) {
        if data[i] == 0x30 && data[i + 1] == 0x82 {
            // Try to parse from this offset
            if let Ok(cert) = Certificate::from_der(&data[i..]) {
                return Ok(cert);
            }
        }
    }

    anyhow::bail!("Could not extract certificate from PKCS7")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== format_policy_oid ==========

    #[test]
    fn test_format_policy_oid_dv() {
        let result = format_policy_oid("2.23.140.1.2.1");
        assert!(result.contains("Domain Validated"));
        assert!(result.contains("2.23.140.1.2.1"));
    }

    #[test]
    fn test_format_policy_oid_ov() {
        let result = format_policy_oid("2.23.140.1.2.2");
        assert!(result.contains("Organization Validated"));
    }

    #[test]
    fn test_format_policy_oid_ev() {
        let result = format_policy_oid("2.23.140.1.1");
        assert!(result.contains("Extended Validation"));
    }

    #[test]
    fn test_format_policy_oid_iv() {
        let result = format_policy_oid("2.23.140.1.2.3");
        assert!(result.contains("Individual Validated"));
    }

    #[test]
    fn test_format_policy_oid_any_policy() {
        let result = format_policy_oid("2.5.29.32.0");
        assert!(result.contains("Any Policy"));
    }

    #[test]
    fn test_format_policy_oid_unknown() {
        let result = format_policy_oid("1.2.3.4.5");
        assert_eq!(result, "1.2.3.4.5");
    }

    // ========== truncate_str ==========

    #[test]
    fn test_truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_str_exact() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_str_long() {
        let result = truncate_str("hello world", 8);
        assert_eq!(result, "hello...");
        assert_eq!(result.len(), 8);
    }

    #[test]
    fn test_truncate_str_empty() {
        assert_eq!(truncate_str("", 5), "");
    }

    // ========== infer_org_chain_from_dn ==========

    #[test]
    fn test_infer_org_chain_from_dc_dn() {
        let chain = infer_org_chain_from_dn(
            "DC=com, DC=rtx, O=CAs, OU=Class3-G3, CN=Raytheon Technologies Medium Assurance CA",
        );
        assert!(!chain.is_empty());
        // Should have root from DC, intermediate from OU, and issuing from CN
        assert!(chain.len() >= 2);
        // First entry should be root from DC
        assert!(chain[0].0.contains("Root CA"));
        // Last entry should be from CN
        assert!(chain.last().unwrap().0.contains("Raytheon Technologies"));
    }

    #[test]
    fn test_infer_org_chain_from_simple_dn() {
        let chain = infer_org_chain_from_dn("CN=My Issuing CA");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].0, "My Issuing CA");
        assert_eq!(chain[0].1, "issuing CA");
    }

    #[test]
    fn test_infer_org_chain_empty() {
        let chain = infer_org_chain_from_dn("");
        assert!(chain.is_empty());
    }

    #[test]
    fn test_infer_org_chain_dc_only() {
        let chain = infer_org_chain_from_dn("DC=com, DC=example");
        assert_eq!(chain.len(), 1);
        assert!(chain[0].0.contains("Root CA"));
    }

    #[test]
    fn test_infer_org_chain_with_ou_class() {
        let chain = infer_org_chain_from_dn("OU=Class3-G3, CN=Test CA");
        assert_eq!(chain.len(), 2);
        assert!(chain[0].0.contains("Class3-G3 CA"));
        assert_eq!(chain[0].1, "from OU");
    }

    #[test]
    fn test_infer_org_chain_org_not_cas() {
        // O= value that is NOT "CAs" should create an intermediate entry
        let chain = infer_org_chain_from_dn("O=Acme Corp, CN=Acme Issuing CA");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].0, "Acme Corp");
        assert_eq!(chain[0].1, "from O");
    }

    #[test]
    fn test_infer_org_chain_org_is_cas() {
        // O=CAs should NOT create an intermediate entry
        let chain = infer_org_chain_from_dn("O=CAs, CN=Test CA");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].0, "Test CA");
    }

    // ========== is_bridge_or_crosscert ==========

    fn make_test_cert(subject: &str) -> Certificate {
        let mut cert = Certificate::test_stub(subject);
        cert.is_ca = true;
        cert.basic_constraints_critical = true;
        cert
    }

    #[test]
    fn test_is_bridge_cert() {
        let cert = make_test_cert("CN=Federal Bridge CA G4");
        assert!(is_bridge_or_crosscert(&cert));
    }

    #[test]
    fn test_is_certipath_bridge() {
        let cert = make_test_cert("CN=CertiPath Bridge CA");
        assert!(is_bridge_or_crosscert(&cert));
    }

    #[test]
    fn test_is_fpki_cert() {
        let cert = make_test_cert("CN=FPKI Trust Root");
        assert!(is_bridge_or_crosscert(&cert));
    }

    #[test]
    fn test_is_cross_cert() {
        let cert = make_test_cert("CN=DigiCert cross-cert");
        assert!(is_bridge_or_crosscert(&cert));
    }

    #[test]
    fn test_not_bridge_cert() {
        let cert = make_test_cert("CN=DigiCert Global Root G2");
        assert!(!is_bridge_or_crosscert(&cert));
    }

    #[test]
    fn test_bridge_case_insensitive() {
        let cert = make_test_cert("CN=FEDERAL BRIDGE CA");
        assert!(is_bridge_or_crosscert(&cert));
    }
}
