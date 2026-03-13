//! `pki compliance` — Validate CA configuration against FIPS/FBCA/NIST requirements.

use anyhow::Result;
use clap::Subcommand;
use colored::Colorize;

use spork_core::algo::AlgorithmId;
use spork_core::policy::compliance::{
    validate_compliance, CaComplianceInput, ComplianceCategory, ComplianceReport, FindingSeverity,
};
use spork_core::policy::cps::{generate_cps, CpsConfig};
use spork_core::policy::fedbridge::{CrossCertProfile, FedBridgeConfig};
use spork_core::policy::security_level::{KeyProtection, SecurityLevel};

/// Compliance validation commands.
#[derive(Subcommand)]
pub enum ComplianceCommands {
    /// Check a CA configuration against a target security level.
    ///
    /// Validates algorithm, key protection, validity periods, revocation
    /// services, and operational controls against FIPS 140-3, NIST SP 800-57,
    /// and Federal Bridge requirements.
    #[command(after_help = "Examples:
  pki compliance check --level 2 --algo ecdsa-p384 --crl-hours 12 --ocsp
  pki compliance check --level 3 --algo ecdsa-p384 --hardware --crl-hours 12 --ocsp
  pki compliance check --level 4 --algo ecdsa-p384 --hardware-l3 --attestation --dual-control")]
    Check {
        /// Target security level (1-4).
        ///
        /// Level 1: Rudimentary (dev/test)
        /// Level 2: Medium (production, software keys, FIPS algorithms)
        /// Level 3: Medium Hardware (TPM/HSM Level 2+)
        /// Level 4: High (HSM Level 3+, dual control, attestation)
        #[arg(long, short = 'l', default_value = "2")]
        level: u8,

        /// Signing algorithm (ecdsa-p256, ecdsa-p384, rsa-3072, rsa-4096, rsa-4096-pss).
        #[arg(long, short = 'a', default_value = "ecdsa-p384")]
        algo: String,

        /// Key is hardware-protected (FIPS 140-3 Level 2+).
        #[arg(long)]
        hardware: bool,

        /// Key is in FIPS 140-3 Level 3 HSM.
        #[arg(long)]
        hardware_l3: bool,

        /// CA certificate validity (days).
        #[arg(long, default_value = "3650")]
        ca_days: u32,

        /// Max end-entity certificate validity (days).
        #[arg(long, default_value = "397")]
        ee_days: u32,

        /// CRL automated.
        #[arg(long)]
        auto_crl: bool,

        /// CRL publication interval (hours).
        #[arg(long, default_value = "24")]
        crl_hours: u32,

        /// OCSP responder available.
        #[arg(long)]
        ocsp: bool,

        /// Crypto operations audit-logged.
        #[arg(long)]
        audit: bool,

        /// Key attestation present.
        #[arg(long)]
        attestation: bool,

        /// Dual control enforced.
        #[arg(long)]
        dual_control: bool,

        /// Certificate policy OIDs (comma-separated).
        #[arg(long, value_delimiter = ',')]
        policy_oids: Vec<String>,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Show requirements for a security level.
    #[command(after_help = "Examples:
  pki compliance levels           Show all levels
  pki compliance levels --level 3 Show Level 3 requirements")]
    Levels {
        /// Show only this level (1-4). Omit to show all.
        #[arg(long, short = 'l')]
        level: Option<u8>,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Generate a CP/CPS document (RFC 3647) from security level config.
    ///
    /// Produces a Markdown skeleton with all RFC 3647 sections populated
    /// from the security level requirements. The output can be redirected
    /// to a file for editing and review.
    #[command(after_help = "Examples:
  pki compliance cps --level 2 --org 'Acme Corp' --ca 'Acme TLS CA'
  pki compliance cps --level 3 --org 'Gov Agency' --ca 'Gov Root CA' --version 2.0 > cps.md")]
    Cps {
        /// Target security level (1-4).
        #[arg(long, short = 'l', default_value = "2")]
        level: u8,

        /// Organization name.
        #[arg(long, default_value = "My Organization")]
        org: String,

        /// CA common name.
        #[arg(long, default_value = "My CA")]
        ca: String,

        /// Document version.
        #[arg(long, default_value = "1.0")]
        version: String,
    },

    /// Generate a Federal Bridge cross-certificate profile.
    #[command(after_help = "Examples:
  pki compliance bridge --level 3 --dns .quantumnexum.com
  pki compliance bridge --level 4 --dns .quantumnexum.com --dn 'DC=quantumnexum, DC=com'")]
    Bridge {
        /// Security level for the cross-certificate (2-4).
        #[arg(long, short = 'l', default_value = "3")]
        level: u8,

        /// Permitted DNS name subtrees (e.g., .quantumnexum.com).
        #[arg(long, value_delimiter = ',')]
        dns: Vec<String>,

        /// Permitted DN subtrees (e.g., DC=quantumnexum, DC=com).
        #[arg(long)]
        dn: Vec<String>,

        /// Maximum path length.
        #[arg(long, default_value = "1")]
        path_len: u32,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

pub fn execute(cmd: ComplianceCommands) -> Result<()> {
    match cmd {
        ComplianceCommands::Check {
            level,
            algo,
            hardware,
            hardware_l3,
            ca_days,
            ee_days,
            auto_crl,
            crl_hours,
            ocsp,
            audit,
            attestation,
            dual_control,
            policy_oids,
            json,
        } => {
            let target = parse_level(level)?;
            let algorithm = parse_algorithm(&algo)?;
            let key_protection = if hardware_l3 {
                KeyProtection::HardwareLevel3
            } else if hardware {
                KeyProtection::Hardware
            } else {
                KeyProtection::Software
            };

            let input = CaComplianceInput {
                algorithm,
                key_protection,
                ca_validity_days: ca_days,
                max_ee_validity_days: ee_days,
                automated_crl: auto_crl,
                crl_interval_hours: crl_hours,
                ocsp_available: ocsp,
                crypto_audit_enabled: audit,
                key_attestation_present: attestation,
                dual_control_enabled: dual_control,
                certificate_policy_oids: if policy_oids.is_empty() {
                    vec![target.ogjos_policy_oid().to_string()]
                } else {
                    policy_oids
                },
                key_lifecycle: None,
            };

            let report = validate_compliance(&input, target);

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_report(&report);
            }

            if report.compliant {
                Ok(())
            } else {
                std::process::exit(1);
            }
        }
        ComplianceCommands::Levels { level, json } => {
            let levels: Vec<SecurityLevel> = if let Some(n) = level {
                vec![parse_level(n)?]
            } else {
                vec![
                    SecurityLevel::Level1,
                    SecurityLevel::Level2,
                    SecurityLevel::Level3,
                    SecurityLevel::Level4,
                ]
            };

            if json {
                let reqs: Vec<_> = levels
                    .iter()
                    .map(|l| spork_core::policy::security_level::LevelRequirements::for_level(*l))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&reqs)?);
            } else {
                for (i, l) in levels.iter().enumerate() {
                    if i > 0 {
                        println!();
                    }
                    print_level_requirements(*l);
                }
            }
            Ok(())
        }
        ComplianceCommands::Cps {
            level,
            org,
            ca,
            version,
        } => {
            let target = parse_level(level)?;
            let config = CpsConfig::new(target, &org, &ca).with_version(&version);
            let doc = generate_cps(&config);
            print!("{}", doc);
            Ok(())
        }
        ComplianceCommands::Bridge {
            level,
            dns,
            dn,
            path_len,
            json,
        } => {
            let target = parse_level(level)?;
            if target < SecurityLevel::Level2 {
                anyhow::bail!("Federal Bridge cross-certification requires Level 2+");
            }

            let config = FedBridgeConfig::new(target)
                .with_dns_subtrees(dns)
                .with_dn_subtrees(dn)
                .with_max_path_length(Some(path_len));

            if let Err(errors) = config.validate() {
                eprintln!("{}", "Validation errors:".red().bold());
                for err in &errors {
                    eprintln!("  {} {}", "x".red(), err);
                }
                std::process::exit(1);
            }

            let profile = CrossCertProfile::from_config(&config);

            if json {
                println!("{}", serde_json::to_string_pretty(&profile)?);
            } else {
                print_bridge_profile(&config, &profile);
            }
            Ok(())
        }
    }
}

fn parse_level(n: u8) -> Result<SecurityLevel> {
    SecurityLevel::from_numeric(n)
        .ok_or_else(|| anyhow::anyhow!("Invalid security level: {}. Must be 1-4.", n))
}

fn parse_algorithm(s: &str) -> Result<AlgorithmId> {
    match s.to_lowercase().as_str() {
        "ecdsa-p256" | "p256" | "ec256" => Ok(AlgorithmId::EcdsaP256),
        "ecdsa-p384" | "p384" | "ec384" => Ok(AlgorithmId::EcdsaP384),
        "rsa-2048" | "rsa2048" => Ok(AlgorithmId::Rsa2048),
        "rsa-3072" | "rsa3072" => Ok(AlgorithmId::Rsa3072),
        "rsa-4096" | "rsa4096" => Ok(AlgorithmId::Rsa4096),
        "rsa-3072-pss" | "rsa3072pss" => Ok(AlgorithmId::Rsa3072Pss),
        "rsa-4096-pss" | "rsa4096pss" => Ok(AlgorithmId::Rsa4096Pss),
        _ => Err(anyhow::anyhow!(
            "Unknown algorithm: '{}'. Options: ecdsa-p256, ecdsa-p384, rsa-3072, rsa-4096, rsa-3072-pss, rsa-4096-pss",
            s
        )),
    }
}

fn print_report(report: &ComplianceReport) {
    let status = if report.compliant {
        "COMPLIANT".green().bold()
    } else {
        "NON-COMPLIANT".red().bold()
    };

    println!(
        "\n{} Compliance Report — {}",
        "PKI".cyan().bold(),
        report.target_level
    );
    println!("{}", "=".repeat(60));
    println!(
        "Status: {}  ({} pass, {} warn, {} fail)",
        status,
        report.pass_count.to_string().green(),
        report.warning_count.to_string().yellow(),
        report.fail_count.to_string().red(),
    );
    println!();

    let categories = [
        ComplianceCategory::Algorithm,
        ComplianceCategory::KeyProtection,
        ComplianceCategory::Validity,
        ComplianceCategory::Revocation,
        ComplianceCategory::Policy,
        ComplianceCategory::Operational,
    ];

    for cat in categories {
        let findings = report.findings_by_category(cat);
        if findings.is_empty() {
            continue;
        }
        println!("  {}", cat.name().bold().underline());
        for f in findings {
            let icon = match f.severity {
                FindingSeverity::Pass => "✓".green(),
                FindingSeverity::Warning => "⚠".yellow(),
                FindingSeverity::Fail => "✗".red(),
            };
            println!("    {} [{}] {}", icon, f.code.dimmed(), f.title);
            println!("      {}", f.detail.dimmed());
            if let Some(ref rem) = f.remediation {
                println!("      {} {}", "Fix:".yellow(), rem);
            }
        }
        println!();
    }
}

fn print_level_requirements(level: SecurityLevel) {
    let req = spork_core::policy::security_level::LevelRequirements::for_level(level);

    println!("{}", level.to_string().cyan().bold());
    println!("{}", "-".repeat(50));
    println!("  NIST IAL:           {}", level.nist_ial());
    println!("  NIST AAL:           {}", level.nist_aal());
    println!("  FIPS Module Level:  {}", level.fips_module_level());
    println!("  Key Protection:     {}", req.key_protection);
    println!(
        "  FIPS Algorithms:    {}",
        if req.fips_algorithms_required {
            "Required"
        } else {
            "Optional"
        }
    );
    println!("  Min RSA bits:       {}", req.min_rsa_bits);
    println!("  Min EC security:    {} bits", req.min_ec_security_bits);
    println!(
        "  Max CA validity:    {} days ({:.0} years)",
        req.max_ca_validity_days,
        req.max_ca_validity_days as f64 / 365.25
    );
    println!(
        "  Max EE validity:    {} days ({:.0} months)",
        req.max_ee_validity_days,
        req.max_ee_validity_days as f64 / 30.44
    );
    println!(
        "  Automated CRL:      {}",
        if req.automated_crl_required {
            "Required"
        } else {
            "Optional"
        }
    );
    if req.max_crl_interval_hours > 0 {
        println!("  Max CRL interval:   {} hours", req.max_crl_interval_hours);
    }
    println!(
        "  OCSP:               {}",
        if req.ocsp_required {
            "Required"
        } else {
            "Optional"
        }
    );
    println!(
        "  Key attestation:    {}",
        if req.key_attestation_required {
            "Required"
        } else {
            "Optional"
        }
    );
    println!(
        "  Dual control:       {}",
        if req.dual_control_required {
            "Required"
        } else {
            "Optional"
        }
    );
    println!(
        "  Crypto audit:       {}",
        if req.crypto_audit_required {
            "Required"
        } else {
            "Optional"
        }
    );
    println!("  FPKI Policy OID:    {}", req.fpki_policy_oid);
    println!("  Ogjos Policy OID:   {}", req.ogjos_policy_oid);

    // Show permitted algorithms
    let algos = level.permitted_algorithms();
    println!("  Algorithms ({}):", algos.len());
    for algo in algos {
        println!("    - {}", algo);
    }
}

fn print_bridge_profile(config: &FedBridgeConfig, profile: &CrossCertProfile) {
    println!(
        "\n{} Federal Bridge Cross-Certificate Profile",
        "PKI".cyan().bold()
    );
    println!("{}", "=".repeat(60));
    println!("  Security Level:     {}", config.security_level);
    println!("  Max Validity:       {} days", profile.max_validity_days);
    println!(
        "  Path Length:        {}",
        profile
            .path_len_constraint
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unlimited".into())
    );

    println!("\n  {}", "Policy Mappings:".bold());
    for mapping in &profile.policy_mappings {
        println!(
            "    {} → {}",
            mapping.issuer_domain_policy.dimmed(),
            mapping.subject_domain_policy.cyan(),
        );
        if let Some(ref desc) = mapping.description {
            println!("      {}", desc.dimmed());
        }
    }

    if profile.has_name_constraints() {
        println!("\n  {}", "Name Constraints:".bold());
        for dns in &profile.permitted_dns_subtrees {
            println!("    {} DNS: {}", "permit".green(), dns);
        }
        for dns in &profile.excluded_dns_subtrees {
            println!("    {} DNS: {}", "exclude".red(), dns);
        }
        for dn in &profile.permitted_dn_subtrees {
            println!("    {} DN: {}", "permit".green(), dn);
        }
    }

    if profile.has_policy_constraints() {
        println!("\n  {}", "Policy Constraints:".bold());
        if let Some(n) = profile.require_explicit_policy {
            println!("    requireExplicitPolicy: skip {}", n);
        }
        if let Some(n) = profile.inhibit_policy_mapping {
            println!("    inhibitPolicyMapping: skip {}", n);
        }
    }

    if let Some(n) = profile.inhibit_any_policy {
        println!("\n  {}: skip {}", "InhibitAnyPolicy".bold(), n);
    }

    println!("\n  {}", "Certificate Policies:".bold());
    for oid in &profile.certificate_policies {
        println!("    {}", oid);
    }
}
