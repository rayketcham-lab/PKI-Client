//! Certificate output formatting - familiar display style with modern enhancements.

use crate::format::Formatter;
use crate::oid_registry;
use crate::Certificate;
use colored::Colorize;

/// Certificate formatter with enhanced PKI-style display.
pub struct CertFormatter;

impl CertFormatter {
    /// Format a certificate for display.
    #[must_use]
    pub fn format(cert: &Certificate, colored: bool) -> String {
        if colored {
            Self::format_colored(cert)
        } else {
            Self::format_plain(cert)
        }
    }

    /// Detect validation type from certificate policies.
    fn detect_validation_type(cert: &Certificate) -> &'static str {
        for policy in &cert.certificate_policies {
            match policy.as_str() {
                "2.23.140.1.1" => return "EV",   // Extended Validation
                "2.23.140.1.2.2" => return "OV", // Organization Validated
                "2.23.140.1.2.1" => return "DV", // Domain Validated
                "2.23.140.1.2.3" => return "IV", // Individual Validated
                _ => {}
            }
        }
        "Unknown"
    }

    /// Detect well-known Certificate Authority from issuer.
    fn detect_ca_vendor(issuer: &str) -> Option<&'static str> {
        let issuer_lower = issuer.to_lowercase();
        if issuer_lower.contains("let's encrypt") || issuer_lower.contains("letsencrypt") {
            Some("Let's Encrypt")
        } else if issuer_lower.contains("digicert") {
            Some("DigiCert")
        } else if issuer_lower.contains("comodo") || issuer_lower.contains("sectigo") {
            Some("Sectigo")
        } else if issuer_lower.contains("globalsign") {
            Some("GlobalSign")
        } else if issuer_lower.contains("godaddy") {
            Some("GoDaddy")
        } else if issuer_lower.contains("entrust") {
            Some("Entrust")
        } else if issuer_lower.contains("geotrust") {
            Some("GeoTrust")
        } else if issuer_lower.contains("thawte") {
            Some("Thawte")
        } else if issuer_lower.contains("verisign") || issuer_lower.contains("symantec") {
            Some("Symantec/VeriSign")
        } else if issuer_lower.contains("amazon") || issuer_lower.contains("aws") {
            Some("Amazon/AWS")
        } else if issuer_lower.contains("microsoft") || issuer_lower.contains("azure") {
            Some("Microsoft")
        } else if issuer_lower.contains("google") {
            Some("Google Trust Services")
        } else if issuer_lower.contains("cloudflare") {
            Some("Cloudflare")
        } else if issuer_lower.contains("zerossl") {
            Some("ZeroSSL")
        } else if issuer_lower.contains("buypass") {
            Some("Buypass")
        } else if issuer_lower.contains("ssl.com") {
            Some("SSL.com")
        } else if issuer_lower.contains("raytheon") || issuer_lower.contains("rtx") {
            Some("Raytheon/RTX")
        } else {
            None
        }
    }

    /// Get certificate purpose/usage summary.
    fn get_cert_purpose(cert: &Certificate) -> String {
        let mut purposes = Vec::new();

        // Check extended key usage first
        for eku in &cert.extended_key_usage {
            match eku.as_str() {
                "TLS Web Server Authentication" | "Server Authentication"
                    if !purposes.contains(&"Server") =>
                {
                    purposes.push("Server")
                }
                "TLS Web Client Authentication" | "Client Authentication"
                    if !purposes.contains(&"Client") =>
                {
                    purposes.push("Client")
                }
                "Code Signing" => purposes.push("Code Signing"),
                "Email Protection" | "E-mail Protection" => purposes.push("Email/S-MIME"),
                "Time Stamping" => purposes.push("Timestamping"),
                "OCSP Signing" => purposes.push("OCSP"),
                _ => {}
            }
        }

        // Check if it's a CA
        if cert.is_ca {
            purposes.insert(0, "CA");
        }

        if purposes.is_empty() {
            "General Purpose".to_string()
        } else {
            purposes.join(", ")
        }
    }

    /// Check if certificate is self-signed.
    fn is_self_signed(cert: &Certificate) -> bool {
        cert.subject == cert.issuer
    }

    /// Check if any SAN is a wildcard.
    fn has_wildcard(cert: &Certificate) -> bool {
        cert.san.iter().any(|s| match s {
            crate::SanEntry::Dns(name) => name.starts_with("*."),
            _ => false,
        })
    }

    /// Calculate a PKI grade (A-F) for the certificate.
    ///
    /// CA certificates (root and intermediate) use a simplified scoring that only
    /// checks key strength, signature algorithm, and expiry — they are trust anchors
    /// in a self-hosted deployment and should not be penalized for lacking CT logs,
    /// public OCSP/CRL endpoints, or SANs.
    fn calculate_grade(cert: &Certificate) -> (&'static str, &'static str) {
        let mut score: i32 = 100;
        let mut reasons = Vec::new();
        let self_signed = Self::is_self_signed(cert);

        // Key strength (applies to all certs)
        if cert.key_algorithm_name == "RSA" {
            if cert.key_size < 2048 {
                score -= 40;
                reasons.push("weak key");
            } else if cert.key_size == 2048 {
                score -= 5;
            }
        } else if cert.key_algorithm_name == "EC" && cert.key_size > 0 && cert.key_size < 256 {
            score -= 40;
            reasons.push("weak key");
        }

        // Signature algorithm (applies to all certs)
        if cert.signature_algorithm_name.contains("SHA-1") {
            score -= 30;
            reasons.push("SHA-1");
        } else if cert.signature_algorithm_name.contains("MD5") {
            score -= 50;
            reasons.push("MD5");
        }

        // Expiry (applies to all certs)
        if cert.is_expired() {
            score -= 100;
            reasons.push("expired");
        } else if cert.days_until_expiry() < 7 {
            score -= 20;
            reasons.push("expiring");
        } else if cert.lifetime_used_percent() >= 70.0 {
            score -= 10;
        }

        // The following penalties only apply to end-entity certs, not CA/trust anchors
        if !cert.is_ca && !self_signed {
            // CT
            if cert.ct_scts.is_empty() {
                score -= 5;
            }

            // Revocation endpoints
            if cert.ocsp_urls.is_empty() && cert.crl_distribution_points.is_empty() {
                score -= 10;
            }

            // No SANs
            if cert.san.is_empty() {
                score -= 15;
                reasons.push("no SAN");
            }
        }

        let grade = match score {
            90..=100 => "A",
            80..=89 => "B",
            70..=79 => "C",
            50..=69 => "D",
            _ => "F",
        };

        let reason = if reasons.is_empty() {
            ""
        } else {
            match reasons.first() {
                Some(&r) => r,
                None => "",
            }
        };

        (grade, reason)
    }

    /// Format a certificate with colors (OpenSSL-style with modern enhancements).
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn format_colored(cert: &Certificate) -> String {
        let mut output = String::new();

        // Gather certificate metadata
        let validation = Self::detect_validation_type(cert);
        let purpose = Self::get_cert_purpose(cert);
        let self_signed = Self::is_self_signed(cert);
        let ca_vendor = Self::detect_ca_vendor(&cert.issuer);
        let (grade, grade_reason) = Self::calculate_grade(cert);
        let has_wildcard = Self::has_wildcard(cert);

        // Certificate Summary (OpenSSL-style indentation)
        output.push_str(&format!("{}:\n", "Certificate Summary".cyan().bold()));

        // Type line
        let type_str = if cert.is_ca {
            "CA Certificate".magenta().bold()
        } else if self_signed {
            "Self-Signed".yellow().bold()
        } else {
            "End Entity".green().bold()
        };

        let validation_str = match validation {
            "EV" => "Extended Validation".green(),
            "OV" => "Organization Validated".cyan(),
            "DV" => "Domain Validated".blue(),
            "IV" => "Individual Validated".yellow(),
            _ => "Unknown".dimmed(),
        };

        output.push_str(&format!(
            "    Type:           {} ({})\n",
            type_str, validation_str
        ));

        // Grade line — CA certs show trust status, end-entity shows letter grade
        let grade_colored = match grade {
            "A" => "A".green().bold(),
            "B" => "B".cyan().bold(),
            "C" => "C".yellow().bold(),
            "D" => "D".red(),
            _ => "F".red().bold(),
        };

        let wildcard_str = if has_wildcard {
            "Yes".magenta()
        } else {
            "No".dimmed()
        };

        if cert.is_ca && self_signed {
            output.push_str(&format!(
                "    Trust:          {}    Wildcard: {}\n",
                "Trusted Root".green().bold(),
                wildcard_str
            ));
        } else if cert.is_ca {
            output.push_str(&format!(
                "    Trust:          {}    Wildcard: {}\n",
                "Trusted CA".green().bold(),
                wildcard_str
            ));
        } else {
            output.push_str(&format!(
                "    Grade:          {}    Wildcard: {}\n",
                grade_colored, wildcard_str
            ));
        }

        // Grade warning if not A (only for non-CA certs, or if CA has actual issues)
        if grade != "A" && !grade_reason.is_empty() {
            output.push_str(&format!(
                "                    {} {}\n",
                "⚠".yellow().bold(),
                format!("({})", grade_reason).yellow()
            ));
        }

        // Subject line
        let cn = cert.common_name().unwrap_or(&cert.subject);
        output.push_str(&format!("    Subject:        {}\n", cn.white().bold()));

        // Issuer line
        let issuer_display = if let Some(vendor) = ca_vendor {
            format!("{} ({})", cert.issuer.yellow(), vendor.cyan())
        } else {
            cert.issuer.yellow().to_string()
        };
        output.push_str(&format!("    Issuer:         {}\n", issuer_display));

        // Purpose line
        output.push_str(&format!("    Purpose:        {}\n", purpose.green()));

        output.push('\n');

        // Key information
        let key_display = if let Some(ref curve) = cert.ec_curve {
            let strength = if cert.key_size >= 256 {
                "STRONG".green()
            } else {
                "WEAK".red().bold()
            };
            format!("EC {} ({}) {}", curve.cyan(), cert.key_size, strength)
        } else if cert.key_algorithm_name == "RSA" {
            let strength = if cert.key_size >= 3072 {
                "STRONG".green()
            } else if cert.key_size >= 2048 {
                "OK".yellow()
            } else {
                "WEAK".red().bold()
            };
            format!("RSA {}-bit {}", cert.key_size.to_string().cyan(), strength)
        } else if cert.key_algorithm_name == "Ed25519" {
            format!("Ed25519 {}", "STRONG".green())
        } else if cert.key_algorithm_name.starts_with("ML-DSA") {
            let nist_level = match cert.key_algorithm_name.as_str() {
                "ML-DSA-44" => "2",
                "ML-DSA-65" => "3",
                "ML-DSA-87" => "5",
                _ => "?",
            };
            format!(
                "{} (NIST Level {}) {}",
                cert.key_algorithm_name,
                nist_level,
                "QUANTUM-SAFE".green().bold()
            )
        } else {
            format!("{} {}-bit", cert.key_algorithm_name, cert.key_size)
        };
        output.push_str(&format!("    Key:            {}\n", key_display));

        // Validity period
        let validity_days = (cert.not_after - cert.not_before).num_days();
        let days_left = cert.days_until_expiry();
        let validity_display = if validity_days >= 365 {
            let years = validity_days / 365;
            format!(
                "{} days ({} year{})",
                validity_days,
                years,
                if years == 1 { "" } else { "s" }
            )
        } else {
            format!("{} days", validity_days)
        };

        let remaining_display = if days_left < 0 {
            format!(
                "{} {}",
                "EXPIRED".red().bold(),
                format!("{} days ago", -days_left).red()
            )
        } else if days_left == 0 {
            format!("{}", "EXPIRES TODAY!".red().bold())
        } else if days_left <= 7 {
            format!(
                "{} {} days",
                "⚠".red().bold(),
                days_left.to_string().red().bold()
            )
        } else if days_left <= 30 {
            format!("{} {} days", "⚠".yellow(), days_left.to_string().yellow())
        } else {
            format!("{} days", days_left.to_string().green())
        };

        output.push_str(&format!(
            "    Validity:       {} ({} remaining)\n",
            validity_display.dimmed(),
            remaining_display
        ));

        // Lifetime progress bar
        let lifetime_pct = cert.lifetime_used_percent();
        let bar_width = 20;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let filled =
            ((lifetime_pct / 100.0) * bar_width as f64).clamp(0.0, bar_width as f64) as usize;
        let empty = bar_width - filled;

        let (bar, status_text) = if lifetime_pct >= 100.0 {
            (
                format!("{}", "█".repeat(bar_width).red()),
                "EXPIRED".red().bold().to_string(),
            )
        } else if lifetime_pct >= 70.0 {
            (
                format!(
                    "{}{}",
                    "█".repeat(filled).yellow(),
                    "░".repeat(empty).dimmed()
                ),
                format!("{:.1}% - {}", lifetime_pct, "RENEW NOW".yellow().bold()),
            )
        } else {
            (
                format!(
                    "{}{}",
                    "█".repeat(filled).green(),
                    "░".repeat(empty).dimmed()
                ),
                format!("{:.1}%", lifetime_pct).green().to_string(),
            )
        };

        output.push_str(&format!("    Lifetime:       [{}] {}\n", bar, status_text));

        output.push('\n');

        // Status flags
        let san_count = cert.san.len();
        let ct_status = if !cert.ct_scts.is_empty() {
            format!("{} CT", "✓".green().bold())
        } else if self_signed || cert.is_ca {
            format!("{} CT", "-".dimmed())
        } else {
            format!("{} CT", "✗".red().bold())
        };
        let ocsp_status = if !cert.ocsp_urls.is_empty() {
            format!("{} OCSP", "✓".green().bold())
        } else {
            format!("{} OCSP", "✗".dimmed())
        };
        let crl_status = if !cert.crl_distribution_points.is_empty() {
            format!("{} CRL", "✓".green().bold())
        } else {
            format!("{} CRL", "✗".dimmed())
        };

        let san_display = if san_count > 0 {
            format!("SANs: {}", san_count.to_string().cyan())
        } else {
            format!("SANs: {}", "0".dimmed())
        };

        let must_staple = if cert.ocsp_must_staple {
            format!("  {} MustStaple", "✓".green().bold())
        } else {
            String::new()
        };

        output.push_str(&format!(
            "    Status:         {}  {}  {}  {}{}\n",
            ct_status, ocsp_status, crl_status, san_display, must_staple
        ));

        output.push('\n');

        // Certificate header
        output.push_str(&format!("{}\n", "Certificate:".bold()));
        output.push_str("    Data:\n");

        // Version
        output.push_str(&format!(
            "        {}: {} (0x{})\n",
            "Version".cyan(),
            cert.version,
            cert.version - 1
        ));

        // Serial Number - clean format without colons
        output.push_str(&format!("        {}\n", "Serial Number:".cyan()));
        // Show as clean hex (uppercase, no colons for the main display)
        let serial_clean = cert.serial.to_uppercase();
        output.push_str(&format!(
            "            {} (0x{})\n",
            serial_clean,
            serial_clean.to_lowercase()
        ));

        // Signature Algorithm (with OID)
        let sig_color = if cert.signature_algorithm_name.contains("SHA-1")
            || cert.signature_algorithm_name.contains("MD5")
        {
            cert.signature_algorithm_name.red()
        } else if cert.signature_algorithm_name.contains("SHA-256") {
            cert.signature_algorithm_name.green()
        } else {
            cert.signature_algorithm_name.normal()
        };
        output.push_str(&format!(
            "        {}: {} ({})\n",
            "Signature Algorithm".cyan(),
            sig_color,
            cert.signature_algorithm.dimmed()
        ));

        // Issuer
        output.push_str(&format!(
            "        {}: {}\n",
            "Issuer".cyan(),
            cert.issuer.yellow()
        ));

        // Validity
        output.push_str(&format!("        {}:\n", "Validity".cyan()));
        output.push_str(&format!(
            "            Not Before: {}\n",
            cert.not_before.format("%b %e %H:%M:%S %Y %Z")
        ));

        let lifetime_pct = cert.lifetime_used_percent();
        let days = cert.days_until_expiry();
        let expiry_note = if cert.is_expired() {
            format!(" {}", "(EXPIRED)".red().bold())
        } else if days < 30 {
            format!(" {} days", days.to_string().yellow().bold())
        } else {
            format!(" {} days", days.to_string().green())
        };
        output.push_str(&format!(
            "            Not After : {}{}\n",
            cert.not_after.format("%b %e %H:%M:%S %Y %Z"),
            expiry_note
        ));

        // Lifetime progress bar (enhanced)
        let bar_width = 40;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let filled =
            ((lifetime_pct / 100.0) * bar_width as f64).clamp(0.0, bar_width as f64) as usize;
        let empty = bar_width - filled;

        let (bar, status_text) = if lifetime_pct >= 100.0 {
            (
                format!("{}", "█".repeat(bar_width).red()),
                "EXPIRED".red().bold().to_string(),
            )
        } else if lifetime_pct >= 70.0 {
            (
                format!(
                    "{}{}",
                    "█".repeat(filled).yellow(),
                    "░".repeat(empty).dimmed()
                ),
                format!("{:.1}% - {}", lifetime_pct, "RENEW NOW".yellow().bold()),
            )
        } else {
            (
                format!(
                    "{}{}",
                    "█".repeat(filled).green(),
                    "░".repeat(empty).dimmed()
                ),
                format!("{:.1}%", lifetime_pct).green().to_string(),
            )
        };

        output.push_str(&format!(
            "            Lifetime : [{}] {}\n",
            bar, status_text
        ));

        // Subject
        output.push_str(&format!(
            "        {}: {}\n",
            "Subject".cyan(),
            cert.subject.white().bold()
        ));

        // Subject Public Key Info
        output.push_str(&format!("        {}:\n", "Subject Public Key Info".cyan()));

        let key_strength = if cert.key_algorithm_name == "RSA" {
            if cert.key_size < 2048 {
                "WEAK".red().bold()
            } else if cert.key_size == 2048 {
                "OK".yellow()
            } else {
                "STRONG".green()
            }
        } else if cert.key_algorithm_name == "EC" {
            if cert.key_size < 256 {
                "WEAK".red().bold()
            } else {
                "STRONG".green()
            }
        } else if cert.key_algorithm_name.starts_with("ML-DSA") {
            "QUANTUM-SAFE".green().bold()
        } else {
            "".normal()
        };

        if cert.key_algorithm_name.starts_with("ML-DSA") {
            let nist_level = match cert.key_algorithm_name.as_str() {
                "ML-DSA-44" => "2",
                "ML-DSA-65" => "3",
                "ML-DSA-87" => "5",
                _ => "?",
            };
            output.push_str(&format!(
                "            Algorithm: {} (NIST Level {}) {} ({})\n",
                cert.key_algorithm_name.cyan(),
                nist_level,
                key_strength,
                cert.key_algorithm.dimmed()
            ));
        } else {
            output.push_str(&format!(
                "            Algorithm: {} ({} bit) {} ({})\n",
                cert.key_algorithm_name.cyan(),
                cert.key_size,
                key_strength,
                cert.key_algorithm.dimmed()
            ));
        }

        if let Some(ref curve) = cert.ec_curve {
            output.push_str(&format!("            Curve: {}\n", curve.green()));
        }

        // RSA Modulus and Exponent
        if cert.key_algorithm_name == "RSA" {
            if let Some(ref modulus) = cert.rsa_modulus {
                let total_bytes = modulus.len() / 2;
                output.push_str(&format!(
                    "            {} ({} bytes):\n",
                    "Modulus".dimmed(),
                    total_bytes
                ));
                // Show first 2 lines (128 hex chars) then truncation notice
                let chunks: Vec<&[u8]> = modulus.as_bytes().chunks(64).collect();
                let max_lines = 2;
                for chunk in chunks.iter().take(max_lines) {
                    let line = std::str::from_utf8(chunk).unwrap_or("");
                    output.push_str(&format!("                {}\n", line.dimmed()));
                }
                if chunks.len() > max_lines {
                    output.push_str(&format!(
                        "                {} ({} more lines, use -f forensic for full)\n",
                        "...".dimmed(),
                        chunks.len() - max_lines,
                    ));
                }
            }
            if let Some(exponent) = cert.rsa_exponent {
                output.push_str(&format!(
                    "            {}: {} (0x{:x})\n",
                    "Exponent".dimmed(),
                    exponent,
                    exponent
                ));
            }
        }

        // X509v3 extensions
        output.push_str(&format!("        {}:\n", "X509v3 Extensions".cyan()));

        // Basic Constraints (OID: 2.5.29.19)
        if cert.is_ca || cert.basic_constraints_critical {
            let critical = if cert.basic_constraints_critical {
                " (critical)".yellow()
            } else {
                "".normal()
            };
            output.push_str(&format!(
                "            X509v3 Basic Constraints {}:{}\n",
                "(2.5.29.19)".dimmed(),
                critical
            ));
            let ca_str = if cert.is_ca {
                "TRUE".magenta().bold()
            } else {
                "FALSE".normal()
            };
            if cert.path_length >= 0 {
                output.push_str(&format!(
                    "                CA:{}, pathlen:{}\n",
                    ca_str, cert.path_length
                ));
            } else {
                output.push_str(&format!("                CA:{}\n", ca_str));
            }
        }

        // Key Usage (OID: 2.5.29.15)
        if !cert.key_usage.is_empty() {
            let critical = if cert.key_usage_critical {
                " (critical)".yellow()
            } else {
                "".normal()
            };
            output.push_str(&format!(
                "            X509v3 Key Usage {}:{}\n",
                "(2.5.29.15)".dimmed(),
                critical
            ));
            output.push_str(&format!("                {}\n", cert.key_usage.join(", ")));
        }

        // Extended Key Usage (OID: 2.5.29.37)
        if !cert.extended_key_usage.is_empty() {
            output.push_str(&format!(
                "            X509v3 Extended Key Usage {}:\n",
                "(2.5.29.37)".dimmed()
            ));
            // Show each EKU on its own line with OID
            for eku in &cert.extended_key_usage {
                output.push_str(&format!("                {}\n", eku.green()));
            }
        }

        // Subject Alternative Name (OID: 2.5.29.17)
        if !cert.san.is_empty() {
            output.push_str(&format!(
                "            X509v3 Subject Alternative Name {}:\n",
                "(2.5.29.17)".dimmed()
            ));
            for san in &cert.san {
                output.push_str(&format!("                {}\n", san.to_string().green()));
            }
        }

        // Key Identifiers
        if let Some(ref ski) = cert.subject_key_id {
            output.push_str(&format!(
                "            X509v3 Subject Key Identifier {}:\n",
                "(2.5.29.14)".dimmed()
            ));
            output.push_str(&format!("                {}\n", ski.dimmed()));
        }

        if let Some(ref aki) = cert.authority_key_id {
            output.push_str(&format!(
                "            X509v3 Authority Key Identifier {}:\n",
                "(2.5.29.35)".dimmed()
            ));
            output.push_str(&format!("                keyid:{}\n", aki.dimmed()));
        }

        // Authority Information Access (OID: 1.3.6.1.5.5.7.1.1)
        if !cert.ocsp_urls.is_empty() || !cert.ca_issuer_urls.is_empty() {
            output.push_str(&format!(
                "            Authority Information Access {}:\n",
                "(1.3.6.1.5.5.7.1.1)".dimmed()
            ));
            for url in &cert.ocsp_urls {
                output.push_str(&format!(
                    "                OCSP {} - URI:{}\n",
                    "(1.3.6.1.5.5.7.48.1)".dimmed(),
                    url.blue()
                ));
            }
            for url in &cert.ca_issuer_urls {
                output.push_str(&format!(
                    "                CA Issuers {} - URI:{}\n",
                    "(1.3.6.1.5.5.7.48.2)".dimmed(),
                    url.blue()
                ));
            }
        }

        // CRL Distribution Points (OID: 2.5.29.31)
        if !cert.crl_distribution_points.is_empty() {
            output.push_str(&format!(
                "            X509v3 CRL Distribution Points {}:\n",
                "(2.5.29.31)".dimmed()
            ));
            for url in &cert.crl_distribution_points {
                output.push_str(&format!("                URI:{}\n", url.blue()));
            }
        }

        // Certificate Policies (OID: 2.5.29.32)
        if !cert.certificate_policies.is_empty() {
            output.push_str(&format!(
                "            X509v3 Certificate Policies {}:\n",
                "(2.5.29.32)".dimmed()
            ));
            for policy in &cert.certificate_policies {
                let policy_name = Self::policy_oid_to_name(policy);
                output.push_str(&format!("                Policy: {}\n", policy_name));
            }
        }

        // CT SCTs (OID: 1.3.6.1.4.1.11129.2.4.2)
        if !cert.ct_scts.is_empty() {
            output.push_str(&format!(
                "            CT Precertificate SCTs {} : {} {}\n",
                "(1.3.6.1.4.1.11129.2.4.2)".dimmed(),
                cert.ct_scts.len().to_string().green(),
                "embedded".dimmed()
            ));
        }

        // Signature
        output.push_str(&format!(
            "    {}: {}\n",
            "Signature Algorithm".cyan(),
            cert.signature_algorithm_name
        ));

        // Signature hex dump (like openssl x509 -text)
        if !cert.signature_bytes.is_empty() {
            output.push_str(&format!("    {}:\n", "Signature Value".cyan()));
            let hex = hex::encode(&cert.signature_bytes);
            for chunk in hex.as_bytes().chunks(36) {
                let line = std::str::from_utf8(chunk).unwrap_or("");
                // Format as colon-separated pairs
                let formatted: String = line
                    .as_bytes()
                    .chunks(2)
                    .map(|pair| std::str::from_utf8(pair).unwrap_or(""))
                    .collect::<Vec<&str>>()
                    .join(":");
                output.push_str(&format!("        {}\n", formatted.dimmed()));
            }
        }

        // Fingerprints section
        output.push_str(&format!("\n{}:\n", "Fingerprints".cyan().bold()));
        output.push_str(&format!(
            "    SHA-256:        {}\n",
            cert.fingerprint_sha256.cyan()
        ));
        output.push_str(&format!(
            "    SHA-1:          {}\n",
            cert.fingerprint_sha1.dimmed()
        ));
        output.push_str(&format!(
            "    SPKI Pin:       {}\n",
            cert.spki_sha256_b64.green()
        ));

        // PEM certificate
        if !cert.der.is_empty() {
            output.push_str(&format!("\n{}:\n", "PEM".cyan().bold()));
            let pem_data = pem::Pem::new("CERTIFICATE", cert.der.clone());
            output.push_str(&format!("{}\n", pem::encode(&pem_data).dimmed()));
        }

        output
    }

    /// Convert policy OIDs to human-readable names (uses OID registry).
    fn policy_oid_to_name(oid: &str) -> String {
        oid_registry::policy_name(oid)
    }

    // ========================================================================
    // FORENSIC MODE — "OpenSSL on crack"
    // ========================================================================

    /// Format a certificate in forensic deep-dive mode.
    ///
    /// Dumps every field with maximum detail: hex values, OIDs with names,
    /// security assessments per field, DER size breakdown, key material hex,
    /// extension criticality details, and compliance notes.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn format_forensic(cert: &Certificate, colored: bool) -> String {
        if colored {
            Self::format_forensic_colored(cert)
        } else {
            Self::format_forensic_plain(cert)
        }
    }

    /// Forensic format with ANSI colors.
    #[allow(clippy::too_many_lines)]
    fn format_forensic_colored(cert: &Certificate) -> String {
        let mut o = String::with_capacity(8192);

        let validation = Self::detect_validation_type(cert);
        let purpose = Self::get_cert_purpose(cert);
        let self_signed = Self::is_self_signed(cert);
        let ca_vendor = Self::detect_ca_vendor(&cert.issuer);
        let (grade, grade_reason) = Self::calculate_grade(cert);
        let has_wildcard = Self::has_wildcard(cert);

        // ── Banner ──────────────────────────────────────────────────────
        let banner = "═".repeat(72);
        o.push_str(&format!("{}\n", banner.cyan()));
        o.push_str(&format!(
            "  {}  —  Forensic Certificate Analysis\n",
            "PKI CLIENT".cyan().bold()
        ));
        o.push_str(&format!("{}\n\n", banner.cyan()));

        // ── Quick verdict ───────────────────────────────────────────────
        let type_label = if cert.is_ca && self_signed {
            "Root CA".magenta().bold()
        } else if cert.is_ca {
            "Intermediate CA".magenta().bold()
        } else if self_signed {
            "Self-Signed End Entity".yellow().bold()
        } else {
            "End Entity".green().bold()
        };

        let validation_badge = match validation {
            "EV" => " EV ".on_green().white().bold(),
            "OV" => " OV ".on_cyan().white().bold(),
            "DV" => " DV ".on_blue().white().bold(),
            "IV" => " IV ".on_yellow().white().bold(),
            _ => " ?? ".on_bright_black().white(),
        };

        let grade_badge = match grade {
            "A" => " A ".on_green().white().bold(),
            "B" => " B ".on_cyan().white().bold(),
            "C" => " C ".on_yellow().black().bold(),
            "D" => " D ".on_red().white().bold(),
            _ => " F ".on_red().white().bold(),
        };

        o.push_str(&format!(
            "  {} {} {} {}\n",
            grade_badge,
            validation_badge,
            type_label,
            purpose.green()
        ));
        if !grade_reason.is_empty() {
            o.push_str(&format!(
                "  {} {}\n",
                "WARNING:".yellow().bold(),
                grade_reason.yellow()
            ));
        }
        o.push('\n');

        // ── Section: Identity ───────────────────────────────────────────
        Self::forensic_section_header(&mut o, "IDENTITY", true);

        let cn = cert.common_name().unwrap_or("(none)");
        o.push_str(&format!("  Common Name (CN):     {}\n", cn.white().bold()));
        o.push_str(&format!(
            "  Full Subject DN:      {}\n",
            cert.subject.white()
        ));
        o.push_str(&format!(
            "  Full Issuer DN:       {}\n",
            cert.issuer.yellow()
        ));
        if let Some(vendor) = ca_vendor {
            o.push_str(&format!(
                "  Known CA Vendor:      {}\n",
                vendor.cyan().bold()
            ));
        }
        o.push_str(&format!(
            "  Self-Signed:          {}\n",
            if self_signed {
                "Yes".yellow().bold()
            } else {
                "No".green()
            }
        ));
        o.push_str(&format!(
            "  Wildcard:             {}\n",
            if has_wildcard {
                "Yes".magenta().bold()
            } else {
                "No".dimmed()
            }
        ));

        // ── Section: Serial & Version ───────────────────────────────────
        Self::forensic_section_header(&mut o, "VERSION & SERIAL", true);

        o.push_str(&format!(
            "  Version:              {} (0x{:02x})\n",
            cert.version,
            cert.version - 1
        ));

        let serial_upper = cert.serial.to_uppercase();
        o.push_str(&format!(
            "  Serial Number:        {}\n",
            serial_upper.white().bold()
        ));

        // Serial length analysis
        let serial_bytes = cert.serial.len().div_ceil(2);
        let serial_note = if serial_bytes >= 16 {
            "20+ bytes — excellent entropy".green()
        } else if serial_bytes >= 8 {
            "sufficient entropy".green()
        } else {
            "short serial — weak entropy".yellow()
        };
        o.push_str(&format!(
            "  Serial Length:         ~{} bytes ({})\n",
            serial_bytes, serial_note
        ));

        // ── Section: Validity ───────────────────────────────────────────
        Self::forensic_section_header(&mut o, "VALIDITY & LIFETIME", true);

        o.push_str(&format!(
            "  Not Before:           {}\n",
            cert.not_before
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string()
                .white()
        ));
        o.push_str(&format!(
            "  Not After:            {}\n",
            cert.not_after
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string()
                .white()
        ));

        let total_days = (cert.not_after - cert.not_before).num_days();
        let total_hours = (cert.not_after - cert.not_before).num_hours();
        let years = total_days / 365;
        let months = (total_days % 365) / 30;
        let rem_days = (total_days % 365) % 30;

        o.push_str(&format!(
            "  Total Validity:       {} days ({} year{}, {} month{}, {} day{})\n",
            total_days,
            years,
            if years == 1 { "" } else { "s" },
            months,
            if months == 1 { "" } else { "s" },
            rem_days,
            if rem_days == 1 { "" } else { "s" },
        ));
        o.push_str(&format!(
            "  Total Hours:          {}\n",
            total_hours.to_string().dimmed()
        ));

        // Compliance check: CAB Forum says max 398 days for TLS
        let is_tls = cert
            .extended_key_usage
            .iter()
            .any(|e| e.contains("Server Authentication") || e.contains("Client Authentication"));
        if !cert.is_ca && is_tls {
            let cab_note = if total_days <= 398 {
                "Compliant with CA/B Forum 398-day max".green()
            } else {
                "EXCEEDS CA/B Forum 398-day max for public TLS".red().bold()
            };
            o.push_str(&format!("  CA/B Forum:           {}\n", cab_note));
        }

        let days_left = cert.days_until_expiry();
        let status = if cert.is_expired() {
            format!(
                "{} — expired {} days ago",
                "EXPIRED".red().bold(),
                -days_left
            )
        } else if days_left <= 7 {
            format!("{} — {} days remaining", "CRITICAL".red().bold(), days_left)
        } else if days_left <= 30 {
            format!(
                "{} — {} days remaining",
                "EXPIRING SOON".yellow().bold(),
                days_left
            )
        } else {
            format!("{} days remaining", days_left.to_string().green())
        };
        o.push_str(&format!("  Days Remaining:       {}\n", status));

        // Enhanced lifetime bar (60 chars wide)
        let pct = cert.lifetime_used_percent();
        let bar_w = 50;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let filled = ((pct / 100.0) * bar_w as f64).clamp(0.0, bar_w as f64) as usize;
        let empty = bar_w - filled;

        let bar_char = if pct >= 100.0 {
            "█".repeat(bar_w).red().to_string()
        } else if pct >= 70.0 {
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

        let pct_label = if pct >= 100.0 {
            "EXPIRED".red().bold().to_string()
        } else if pct >= 70.0 {
            format!("{:.2}% — {}", pct, "RENEW NOW".yellow().bold())
        } else {
            format!("{:.2}%", pct).green().to_string()
        };

        o.push_str(&format!(
            "  Lifetime Used:        [{}] {}\n",
            bar_char, pct_label
        ));

        // ── Section: Signature ──────────────────────────────────────────
        Self::forensic_section_header(&mut o, "SIGNATURE ALGORITHM", true);

        let sig_security = Self::assess_signature(&cert.signature_algorithm_name);
        o.push_str(&format!(
            "  Algorithm:            {} ({})\n",
            cert.signature_algorithm_name.white().bold(),
            cert.signature_algorithm.dimmed()
        ));
        o.push_str(&format!(
            "  OID:                  {}\n",
            cert.signature_algorithm.dimmed()
        ));
        o.push_str(&format!("  Security:             {}\n", sig_security));

        // ── Section: Public Key ─────────────────────────────────────────
        Self::forensic_section_header(&mut o, "SUBJECT PUBLIC KEY", true);

        o.push_str(&format!(
            "  Algorithm:            {} ({})\n",
            cert.key_algorithm_name.cyan().bold(),
            cert.key_algorithm.dimmed()
        ));
        o.push_str(&format!(
            "  Key Size:             {} bits\n",
            cert.key_size.to_string().white().bold()
        ));

        let key_security = Self::assess_key_strength(&cert.key_algorithm_name, cert.key_size);
        o.push_str(&format!("  Strength:             {}\n", key_security));

        if let Some(ref curve) = cert.ec_curve {
            o.push_str(&format!(
                "  EC Named Curve:       {} ({})\n",
                curve.green().bold(),
                Self::curve_oid(curve).dimmed()
            ));
        }

        if let Some(ref modulus) = cert.rsa_modulus {
            o.push_str("  RSA Modulus (hex):\n");
            for chunk in modulus.as_bytes().chunks(64) {
                let line = std::str::from_utf8(chunk).unwrap_or("");
                o.push_str(&format!("      {}\n", line.dimmed()));
            }
        }
        if let Some(exp) = cert.rsa_exponent {
            let exp_note = if exp == 65537 {
                "standard F4".green()
            } else if exp == 3 {
                "WEAK — e=3 is vulnerable".red().bold()
            } else {
                "non-standard".yellow()
            };
            o.push_str(&format!(
                "  RSA Exponent:         {} (0x{:x}) — {}\n",
                exp, exp, exp_note
            ));
        }

        // ── Section: Extensions ─────────────────────────────────────────
        Self::forensic_section_header(&mut o, "X.509v3 EXTENSIONS", true);

        // Basic Constraints
        o.push_str(&format!(
            "  {} [OID: 2.5.29.19]\n",
            "Basic Constraints".white().bold()
        ));
        o.push_str(&format!(
            "    Critical:           {}\n",
            Self::critical_display(cert.basic_constraints_critical, true)
        ));
        o.push_str(&format!(
            "    CA:                 {}\n",
            if cert.is_ca {
                "TRUE".magenta().bold()
            } else {
                "FALSE".normal()
            }
        ));
        if cert.path_length >= 0 {
            o.push_str(&format!(
                "    Path Length:         {} (max {} intermediate CAs)\n",
                cert.path_length, cert.path_length
            ));
        } else {
            o.push_str(&format!(
                "    Path Length:         {}\n",
                "unlimited".dimmed()
            ));
        }

        // Key Usage
        if !cert.key_usage.is_empty() {
            o.push('\n');
            o.push_str(&format!(
                "  {} [OID: 2.5.29.15]\n",
                "Key Usage".white().bold()
            ));
            o.push_str(&format!(
                "    Critical:           {}\n",
                Self::critical_display(cert.key_usage_critical, true)
            ));
            for ku in &cert.key_usage {
                let ku_note = Self::key_usage_note(ku);
                o.push_str(&format!("    - {}", ku.green()));
                if !ku_note.is_empty() {
                    o.push_str(&format!(" {}", ku_note.dimmed()));
                }
                o.push('\n');
            }
            // Compliance: CA must have keyCertSign
            if cert.is_ca && !cert.key_usage.iter().any(|k| k == "Certificate Sign") {
                o.push_str(&format!(
                    "    {} {}\n",
                    "!!".red().bold(),
                    "CA cert MISSING keyCertSign — non-compliant".red()
                ));
            }
        }

        // Extended Key Usage
        if !cert.extended_key_usage.is_empty() {
            o.push('\n');
            o.push_str(&format!(
                "  {} [OID: 2.5.29.37]\n",
                "Extended Key Usage".white().bold()
            ));
            for eku in &cert.extended_key_usage {
                let eku_oid = Self::eku_to_oid(eku);
                o.push_str(&format!(
                    "    - {} {}\n",
                    eku.green(),
                    format!("({})", eku_oid).dimmed()
                ));
            }
            // anyExtendedKeyUsage warning
            if cert
                .extended_key_usage
                .iter()
                .any(|e| e.contains("Any Extended Key Usage"))
            {
                o.push_str(&format!(
                    "    {} {}\n",
                    "NOTE:".yellow().bold(),
                    "anyExtendedKeyUsage allows all purposes — broad trust scope".yellow()
                ));
            }
        }

        // Subject Alternative Names
        if !cert.san.is_empty() {
            o.push('\n');
            o.push_str(&format!(
                "  {} [OID: 2.5.29.17] — {} entries\n",
                "Subject Alternative Name".white().bold(),
                cert.san.len().to_string().cyan().bold()
            ));
            for (i, san) in cert.san.iter().enumerate() {
                let (san_type, san_value) = match san {
                    crate::SanEntry::Dns(v) => ("DNS", v.as_str()),
                    crate::SanEntry::Ip(v) => ("IP", v.as_str()),
                    crate::SanEntry::Email(v) => ("Email", v.as_str()),
                    crate::SanEntry::Uri(v) => ("URI", v.as_str()),
                    crate::SanEntry::Other(v) => ("Other", v.as_str()),
                };
                let idx = format!("[{}]", i + 1).dimmed();
                o.push_str(&format!(
                    "    {} {:>5}: {}\n",
                    idx,
                    san_type.cyan(),
                    san_value.green()
                ));
            }
        } else if !cert.is_ca {
            o.push('\n');
            o.push_str(&format!(
                "  {} [OID: 2.5.29.17]\n",
                "Subject Alternative Name".white().bold()
            ));
            o.push_str(&format!(
                "    {} {}\n",
                "!!".red().bold(),
                "MISSING — modern TLS requires SAN extension".red()
            ));
        }

        // Key Identifiers
        o.push('\n');
        o.push_str(&format!(
            "  {} [OID: 2.5.29.14]\n",
            "Subject Key Identifier".white().bold()
        ));
        if let Some(ref ski) = cert.subject_key_id {
            o.push_str(&format!("    {}\n", Self::format_hex_colons(ski)));
        } else {
            o.push_str(&format!("    {}\n", "(not present)".dimmed()));
        }

        o.push('\n');
        o.push_str(&format!(
            "  {} [OID: 2.5.29.35]\n",
            "Authority Key Identifier".white().bold()
        ));
        if let Some(ref aki) = cert.authority_key_id {
            o.push_str(&format!("    keyid: {}\n", Self::format_hex_colons(aki)));
            // Chain linkage check
            if self_signed {
                if let Some(ref ski) = cert.subject_key_id {
                    if aki == ski {
                        o.push_str(&format!(
                            "    {} {}\n",
                            "OK".green().bold(),
                            "AKI matches SKI (self-signed root)".green()
                        ));
                    } else {
                        o.push_str(&format!(
                            "    {} {}\n",
                            "NOTE:".yellow(),
                            "AKI differs from SKI (common with some CAs)".dimmed()
                        ));
                    }
                }
            }
        } else {
            o.push_str(&format!("    {}\n", "(not present)".dimmed()));
            if !self_signed {
                o.push_str(&format!(
                    "    {} {}\n",
                    "!!".yellow().bold(),
                    "Non-root cert without AKI — chain building may fail".yellow()
                ));
            }
        }

        // Authority Information Access
        o.push('\n');
        o.push_str(&format!(
            "  {} [OID: 1.3.6.1.5.5.7.1.1]\n",
            "Authority Information Access".white().bold()
        ));
        if cert.ocsp_urls.is_empty() && cert.ca_issuer_urls.is_empty() {
            if cert.is_ca && self_signed {
                o.push_str(&format!(
                    "    {}\n",
                    "(not present — normal for root CAs)".dimmed()
                ));
            } else {
                o.push_str(&format!(
                    "    {} {}\n",
                    "!!".yellow().bold(),
                    "No AIA — clients cannot fetch issuer cert or check OCSP".yellow()
                ));
            }
        } else {
            for url in &cert.ocsp_urls {
                o.push_str(&format!(
                    "    OCSP Responder:     {} {}\n",
                    url.blue(),
                    "(1.3.6.1.5.5.7.48.1)".dimmed()
                ));
            }
            for url in &cert.ca_issuer_urls {
                o.push_str(&format!(
                    "    CA Issuers:         {} {}\n",
                    url.blue(),
                    "(1.3.6.1.5.5.7.48.2)".dimmed()
                ));
            }
        }

        // CRL Distribution Points
        o.push('\n');
        o.push_str(&format!(
            "  {} [OID: 2.5.29.31]\n",
            "CRL Distribution Points".white().bold()
        ));
        if cert.crl_distribution_points.is_empty() {
            if cert.is_ca && self_signed {
                o.push_str(&format!(
                    "    {}\n",
                    "(not present — normal for root CAs)".dimmed()
                ));
            } else if !cert.ocsp_urls.is_empty() {
                o.push_str(&format!(
                    "    {}\n",
                    "(not present — OCSP available as alternative)".dimmed()
                ));
            } else {
                o.push_str(&format!(
                    "    {} {}\n",
                    "!!".yellow().bold(),
                    "No CRL and no OCSP — no revocation checking possible".red()
                ));
            }
        } else {
            for url in &cert.crl_distribution_points {
                o.push_str(&format!("    URI: {}\n", url.blue()));
            }
        }

        // Certificate Policies
        if !cert.certificate_policies.is_empty() {
            o.push('\n');
            o.push_str(&format!(
                "  {} [OID: 2.5.29.32]\n",
                "Certificate Policies".white().bold()
            ));
            for policy in &cert.certificate_policies {
                let name = Self::policy_oid_to_name(policy);
                o.push_str(&format!("    - {}\n", name.green()));
            }
        }

        // OCSP Must-Staple
        o.push('\n');
        o.push_str(&format!(
            "  {} [OID: 1.3.6.1.5.5.7.1.24]\n",
            "TLS Feature (OCSP Must-Staple)".white().bold()
        ));
        if cert.ocsp_must_staple {
            o.push_str(&format!(
                "    {} — server MUST staple OCSP response\n",
                "ENABLED".green().bold()
            ));
        } else {
            o.push_str(&format!("    {}\n", "Not present".dimmed()));
        }

        // CT SCTs
        o.push('\n');
        o.push_str(&format!(
            "  {} [OID: 1.3.6.1.4.1.11129.2.4.2]\n",
            "Certificate Transparency SCTs".white().bold()
        ));
        if cert.ct_scts.is_empty() {
            if cert.is_ca || self_signed {
                o.push_str(&format!(
                    "    {}\n",
                    "(not applicable for CA certs)".dimmed()
                ));
            } else {
                o.push_str(&format!(
                    "    {} {}\n",
                    "!!".yellow().bold(),
                    "No embedded SCTs — may be rejected by Chrome/Apple".yellow()
                ));
            }
        } else {
            o.push_str(&format!(
                "    {} SCT(s) embedded\n",
                cert.ct_scts.len().to_string().green().bold()
            ));
            for (i, sct) in cert.ct_scts.iter().enumerate() {
                o.push_str(&format!(
                    "    [{}] Log: {}  Timestamp: {}\n",
                    i + 1,
                    sct.log_id.dimmed(),
                    sct.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
                ));
            }
        }

        // ── Section: Fingerprints ───────────────────────────────────────
        Self::forensic_section_header(&mut o, "FINGERPRINTS & PINNING", true);

        o.push_str(&format!(
            "  SHA-256:              {}\n",
            cert.fingerprint_sha256.cyan()
        ));
        o.push_str(&format!(
            "  SHA-256 (colons):     {}\n",
            Self::format_hex_colons(&cert.fingerprint_sha256).dimmed()
        ));
        o.push_str(&format!(
            "  SHA-1:                {} {}\n",
            cert.fingerprint_sha1.dimmed(),
            "(deprecated — do not use for pinning)".dimmed()
        ));
        o.push_str(&format!(
            "  SPKI Pin (SHA-256):   {}\n",
            cert.spki_sha256_b64.green().bold()
        ));
        o.push_str(&format!(
            "  Pin Header:           {}\n",
            format!("pin-sha256=\"{}\"", cert.spki_sha256_b64).green()
        ));

        // ── Section: DER Analysis ───────────────────────────────────────
        Self::forensic_section_header(&mut o, "DER ENCODING", true);

        let der_len = cert.der.len();
        o.push_str(&format!(
            "  Total Size:           {} bytes ({:.1} KB)\n",
            der_len,
            der_len as f64 / 1024.0
        ));

        if !cert.der.is_empty() {
            // Show first and last 32 bytes
            let preview_len = 32.min(cert.der.len());
            let hex_start: String = cert.der[..preview_len]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            o.push_str(&format!(
                "  First {} bytes:      {}\n",
                preview_len,
                hex_start.dimmed()
            ));

            if cert.der.len() > 64 {
                let tail_start = cert.der.len() - 32.min(cert.der.len());
                let hex_end: String = cert.der[tail_start..]
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                o.push_str(&format!(
                    "  Last {} bytes:       {}\n",
                    cert.der.len() - tail_start,
                    hex_end.dimmed()
                ));
            }

            // ASN.1 outer tag check
            if cert.der[0] == 0x30 {
                o.push_str(&format!(
                    "  ASN.1 Outer Tag:      {} (SEQUENCE)\n",
                    "0x30".green()
                ));
            } else {
                o.push_str(&format!(
                    "  ASN.1 Outer Tag:      {} {}\n",
                    format!("0x{:02x}", cert.der[0]).red(),
                    "UNEXPECTED — should be 0x30 SEQUENCE".red()
                ));
            }
        }

        // ── Section: Security Assessment ────────────────────────────────
        Self::forensic_section_header(&mut o, "SECURITY ASSESSMENT", true);

        let mut issues: Vec<(String, String)> = Vec::new();
        let mut good: Vec<String> = Vec::new();

        // Key
        if cert.key_algorithm_name == "RSA" && cert.key_size < 2048 {
            issues.push((
                "CRITICAL".to_string(),
                format!(
                    "RSA key only {} bits — factoring attacks feasible",
                    cert.key_size
                ),
            ));
        } else if cert.key_algorithm_name == "RSA" && cert.key_size == 2048 {
            issues.push((
                "NOTICE".to_string(),
                "RSA 2048 is minimum acceptable — consider 3072+ for longevity".to_string(),
            ));
        } else if cert.key_algorithm_name == "RSA" && cert.key_size >= 3072 {
            good.push(format!("RSA {} bit key — strong", cert.key_size));
        }

        if cert.key_algorithm_name == "EC" {
            good.push(format!(
                "ECDSA {} — strong with smaller key size",
                cert.ec_curve.as_deref().unwrap_or("unknown curve")
            ));
        }

        if cert.key_algorithm_name == "Ed25519" {
            good.push("Ed25519 — modern, fast, strong (128-bit security)".to_string());
        }

        if cert.key_algorithm_name.starts_with("ML-DSA") {
            good.push(format!(
                "{} — post-quantum safe (FIPS 204)",
                cert.key_algorithm_name
            ));
        }

        // Signature
        if cert.signature_algorithm_name.contains("SHA-1")
            || cert.signature_algorithm_name.contains("sha1")
        {
            issues.push((
                "CRITICAL".to_string(),
                "SHA-1 signature — collision attacks demonstrated (SHAttered)".to_string(),
            ));
        } else if cert.signature_algorithm_name.contains("MD5") {
            issues.push((
                "CRITICAL".to_string(),
                "MD5 signature — trivially breakable, collision attacks since 2004".to_string(),
            ));
        } else {
            good.push(format!(
                "Signature algorithm {} — acceptable",
                cert.signature_algorithm_name
            ));
        }

        // Expiry
        if cert.is_expired() {
            issues.push((
                "CRITICAL".to_string(),
                "Certificate has EXPIRED".to_string(),
            ));
        } else if days_left <= 7 {
            issues.push((
                "URGENT".to_string(),
                format!("Expires in {} days", days_left),
            ));
        } else if days_left <= 30 {
            issues.push((
                "WARNING".to_string(),
                format!("Expires in {} days — renew soon", days_left),
            ));
        }

        // Revocation
        if !cert.is_ca
            && !self_signed
            && cert.ocsp_urls.is_empty()
            && cert.crl_distribution_points.is_empty()
        {
            issues.push((
                "WARNING".to_string(),
                "No revocation endpoints (OCSP/CRL) — cert cannot be revoked".to_string(),
            ));
        }

        // CT
        if !cert.is_ca && !self_signed && cert.ct_scts.is_empty() {
            issues.push((
                "NOTICE".to_string(),
                "No Certificate Transparency — may fail browser CT policies".to_string(),
            ));
        }

        // SANs
        if !cert.is_ca && cert.san.is_empty() {
            issues.push((
                "WARNING".to_string(),
                "No SAN extension — CN-only matching deprecated since RFC 6125".to_string(),
            ));
        }

        // Print results
        if issues.is_empty() {
            o.push_str(&format!(
                "  {} {}\n",
                "ALL CLEAR".green().bold(),
                "No security issues detected".green()
            ));
        } else {
            for (severity, msg) in &issues {
                let icon = match severity.as_str() {
                    "CRITICAL" => "██".red().bold(),
                    "URGENT" => "▓▓".red(),
                    "WARNING" => "▒▒".yellow(),
                    "NOTICE" => "░░".blue(),
                    _ => "  ".normal(),
                };
                let severity_colored = match severity.as_str() {
                    "CRITICAL" => severity.red().bold(),
                    "URGENT" => severity.red(),
                    "WARNING" => severity.yellow(),
                    "NOTICE" => severity.blue(),
                    _ => severity.normal(),
                };
                o.push_str(&format!("  {} {:>8}  {}\n", icon, severity_colored, msg));
            }
        }

        if !good.is_empty() {
            o.push('\n');
            for item in &good {
                o.push_str(&format!("  {} {}\n", "OK".green().bold(), item.green()));
            }
        }

        // ── Footer ──────────────────────────────────────────────────────
        o.push('\n');
        o.push_str(&format!("{}\n", banner.cyan()));

        o
    }

    /// Forensic format without colors (plain text).
    #[allow(clippy::too_many_lines)]
    fn format_forensic_plain(cert: &Certificate) -> String {
        let mut o = String::with_capacity(8192);

        let validation = Self::detect_validation_type(cert);
        let purpose = Self::get_cert_purpose(cert);
        let self_signed = Self::is_self_signed(cert);
        let ca_vendor = Self::detect_ca_vendor(&cert.issuer);
        let (grade, grade_reason) = Self::calculate_grade(cert);
        let has_wildcard = Self::has_wildcard(cert);

        let banner = "=".repeat(72);
        o.push_str(&format!("{}\n", banner));
        o.push_str("  PKI CLIENT  --  Forensic Certificate Analysis\n");
        o.push_str(&format!("{}\n\n", banner));

        // Verdict
        let type_label = if cert.is_ca && self_signed {
            "Root CA"
        } else if cert.is_ca {
            "Intermediate CA"
        } else if self_signed {
            "Self-Signed End Entity"
        } else {
            "End Entity"
        };
        o.push_str(&format!(
            "  [{}] [{}] {} — {}\n",
            grade, validation, type_label, purpose
        ));
        if !grade_reason.is_empty() {
            o.push_str(&format!("  WARNING: {}\n", grade_reason));
        }
        o.push('\n');

        // Identity
        Self::forensic_section_header(&mut o, "IDENTITY", false);
        let cn = cert.common_name().unwrap_or("(none)");
        o.push_str(&format!("  Common Name (CN):     {}\n", cn));
        o.push_str(&format!("  Full Subject DN:      {}\n", cert.subject));
        o.push_str(&format!("  Full Issuer DN:       {}\n", cert.issuer));
        if let Some(vendor) = ca_vendor {
            o.push_str(&format!("  Known CA Vendor:      {}\n", vendor));
        }
        o.push_str(&format!(
            "  Self-Signed:          {}\n",
            if self_signed { "Yes" } else { "No" }
        ));
        o.push_str(&format!(
            "  Wildcard:             {}\n",
            if has_wildcard { "Yes" } else { "No" }
        ));

        // Version & Serial
        Self::forensic_section_header(&mut o, "VERSION & SERIAL", false);
        o.push_str(&format!(
            "  Version:              {} (0x{:02x})\n",
            cert.version,
            cert.version - 1
        ));
        let serial_upper = cert.serial.to_uppercase();
        o.push_str(&format!("  Serial Number:        {}\n", serial_upper));
        let serial_bytes = cert.serial.len().div_ceil(2);
        o.push_str(&format!(
            "  Serial Length:         ~{} bytes\n",
            serial_bytes
        ));

        // Validity
        Self::forensic_section_header(&mut o, "VALIDITY & LIFETIME", false);
        o.push_str(&format!(
            "  Not Before:           {}\n",
            cert.not_before.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        o.push_str(&format!(
            "  Not After:            {}\n",
            cert.not_after.format("%Y-%m-%d %H:%M:%S UTC")
        ));
        let total_days = (cert.not_after - cert.not_before).num_days();
        o.push_str(&format!("  Total Validity:       {} days\n", total_days));
        let days_left = cert.days_until_expiry();
        o.push_str(&format!(
            "  Days Remaining:       {}{}\n",
            days_left,
            if cert.is_expired() { " (EXPIRED)" } else { "" }
        ));
        let pct = cert.lifetime_used_percent();
        o.push_str(&format!("  Lifetime Used:        {:.2}%\n", pct));

        // Signature
        Self::forensic_section_header(&mut o, "SIGNATURE ALGORITHM", false);
        o.push_str(&format!(
            "  Algorithm:            {}\n",
            cert.signature_algorithm_name
        ));
        o.push_str(&format!(
            "  OID:                  {}\n",
            cert.signature_algorithm
        ));

        // Public Key
        Self::forensic_section_header(&mut o, "SUBJECT PUBLIC KEY", false);
        o.push_str(&format!(
            "  Algorithm:            {}\n",
            cert.key_algorithm_name
        ));
        o.push_str(&format!("  Key Size:             {} bits\n", cert.key_size));
        if let Some(ref curve) = cert.ec_curve {
            o.push_str(&format!("  EC Named Curve:       {}\n", curve));
        }
        if let Some(ref modulus) = cert.rsa_modulus {
            o.push_str("  RSA Modulus (hex):\n");
            for chunk in modulus.as_bytes().chunks(64) {
                let line = std::str::from_utf8(chunk).unwrap_or("");
                o.push_str(&format!("      {}\n", line));
            }
        }
        if let Some(exp) = cert.rsa_exponent {
            o.push_str(&format!("  RSA Exponent:         {} (0x{:x})\n", exp, exp));
        }

        // Extensions
        Self::forensic_section_header(&mut o, "X.509v3 EXTENSIONS", false);

        o.push_str("  Basic Constraints [2.5.29.19]\n");
        o.push_str(&format!(
            "    Critical:           {}\n",
            if cert.basic_constraints_critical {
                "yes"
            } else {
                "no"
            }
        ));
        o.push_str(&format!(
            "    CA:                 {}\n",
            if cert.is_ca { "TRUE" } else { "FALSE" }
        ));
        if cert.path_length >= 0 {
            o.push_str(&format!("    Path Length:         {}\n", cert.path_length));
        } else {
            o.push_str("    Path Length:         unlimited\n");
        }

        if !cert.key_usage.is_empty() {
            o.push_str(&format!(
                "\n  Key Usage [2.5.29.15] (critical: {})\n",
                if cert.key_usage_critical { "yes" } else { "no" }
            ));
            for ku in &cert.key_usage {
                o.push_str(&format!("    - {}\n", ku));
            }
        }

        if !cert.extended_key_usage.is_empty() {
            o.push_str("\n  Extended Key Usage [2.5.29.37]\n");
            for eku in &cert.extended_key_usage {
                o.push_str(&format!("    - {}\n", eku));
            }
        }

        if !cert.san.is_empty() {
            o.push_str(&format!(
                "\n  Subject Alternative Name [2.5.29.17] -- {} entries\n",
                cert.san.len()
            ));
            for (i, san) in cert.san.iter().enumerate() {
                o.push_str(&format!("    [{}] {}\n", i + 1, san));
            }
        }

        if let Some(ref ski) = cert.subject_key_id {
            o.push_str("\n  Subject Key Identifier [2.5.29.14]\n");
            o.push_str(&format!("    {}\n", Self::format_hex_colons(ski)));
        }
        if let Some(ref aki) = cert.authority_key_id {
            o.push_str("\n  Authority Key Identifier [2.5.29.35]\n");
            o.push_str(&format!("    keyid: {}\n", Self::format_hex_colons(aki)));
        }

        if !cert.ocsp_urls.is_empty() || !cert.ca_issuer_urls.is_empty() {
            o.push_str("\n  Authority Information Access [1.3.6.1.5.5.7.1.1]\n");
            for url in &cert.ocsp_urls {
                o.push_str(&format!("    OCSP:       {}\n", url));
            }
            for url in &cert.ca_issuer_urls {
                o.push_str(&format!("    CA Issuers: {}\n", url));
            }
        }

        if !cert.crl_distribution_points.is_empty() {
            o.push_str("\n  CRL Distribution Points [2.5.29.31]\n");
            for url in &cert.crl_distribution_points {
                o.push_str(&format!("    URI: {}\n", url));
            }
        }

        if !cert.certificate_policies.is_empty() {
            o.push_str("\n  Certificate Policies [2.5.29.32]\n");
            for policy in &cert.certificate_policies {
                o.push_str(&format!("    - {}\n", Self::policy_oid_to_name(policy)));
            }
        }

        o.push_str(&format!(
            "\n  OCSP Must-Staple [1.3.6.1.5.5.7.1.24]: {}\n",
            if cert.ocsp_must_staple {
                "ENABLED"
            } else {
                "not present"
            }
        ));

        o.push_str(&format!(
            "  CT SCTs [1.3.6.1.4.1.11129.2.4.2]: {}\n",
            if cert.ct_scts.is_empty() {
                "none".to_string()
            } else {
                format!("{} embedded", cert.ct_scts.len())
            }
        ));

        // Fingerprints
        Self::forensic_section_header(&mut o, "FINGERPRINTS & PINNING", false);
        o.push_str(&format!(
            "  SHA-256:              {}\n",
            cert.fingerprint_sha256
        ));
        o.push_str(&format!(
            "  SHA-1:                {}\n",
            cert.fingerprint_sha1
        ));
        o.push_str(&format!(
            "  SPKI Pin (SHA-256):   {}\n",
            cert.spki_sha256_b64
        ));

        // DER
        Self::forensic_section_header(&mut o, "DER ENCODING", false);
        let der_len = cert.der.len();
        o.push_str(&format!(
            "  Total Size:           {} bytes ({:.1} KB)\n",
            der_len,
            der_len as f64 / 1024.0
        ));

        // Security Assessment (plain)
        Self::forensic_section_header(&mut o, "SECURITY ASSESSMENT", false);

        let days_left = cert.days_until_expiry();

        if cert.key_algorithm_name == "RSA" && cert.key_size < 2048 {
            o.push_str(&format!(
                "  CRITICAL: RSA key only {} bits\n",
                cert.key_size
            ));
        }
        if cert.signature_algorithm_name.contains("SHA-1")
            || cert.signature_algorithm_name.contains("sha1")
        {
            o.push_str("  CRITICAL: SHA-1 signature\n");
        }
        if cert.signature_algorithm_name.contains("MD5") {
            o.push_str("  CRITICAL: MD5 signature\n");
        }
        if cert.is_expired() {
            o.push_str("  CRITICAL: Certificate has EXPIRED\n");
        } else if days_left <= 30 {
            o.push_str(&format!("  WARNING: Expires in {} days\n", days_left));
        }
        if !cert.is_ca
            && !self_signed
            && cert.ocsp_urls.is_empty()
            && cert.crl_distribution_points.is_empty()
        {
            o.push_str("  WARNING: No revocation endpoints (OCSP/CRL)\n");
        }
        if !cert.is_ca && cert.san.is_empty() {
            o.push_str("  WARNING: No SAN extension\n");
        }
        if !cert.is_ca && !self_signed && cert.ct_scts.is_empty() {
            o.push_str("  NOTICE: No Certificate Transparency SCTs\n");
        }

        o.push_str(&format!("{}\n", banner));

        o
    }

    // ── Forensic helpers ────────────────────────────────────────────────

    /// Write a section header.
    fn forensic_section_header(o: &mut String, title: &str, colored: bool) {
        o.push('\n');
        if colored {
            let line = "─".repeat(68usize.saturating_sub(title.len()));
            o.push_str(&format!("  {} {}\n", title.cyan().bold(), line.dimmed()));
        } else {
            let line = "-".repeat(68usize.saturating_sub(title.len()));
            o.push_str(&format!("  {} {}\n", title, line));
        }
    }

    /// Format a hex string with colon separators (aa:bb:cc:dd...).
    fn format_hex_colons(hex: &str) -> String {
        // If it already has colons, return as-is
        if hex.contains(':') {
            return hex.to_string();
        }
        hex.as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or("??"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Assess signature algorithm security.
    fn assess_signature(name: &str) -> String {
        use colored::Colorize;
        let lower = name.to_lowercase();
        if lower.contains("md5") {
            format!("{} — broken, trivially forgeable", "CRITICAL".red().bold())
        } else if lower.contains("sha-1") || lower.contains("sha1") {
            format!(
                "{} — collision attacks demonstrated (SHAttered, 2017)",
                "WEAK".red().bold()
            )
        } else if lower.contains("sha-256") || lower.contains("sha256") {
            format!("{} — current standard", "STRONG".green().bold())
        } else if lower.contains("sha-384")
            || lower.contains("sha384")
            || lower.contains("sha-512")
            || lower.contains("sha512")
        {
            format!("{} — exceeds requirements", "STRONG".green().bold())
        } else if lower.contains("ed25519") || lower.contains("ed448") {
            format!(
                "{} — modern EdDSA, no hash truncation",
                "STRONG".green().bold()
            )
        } else if lower.contains("ml-dsa") {
            format!(
                "{} — post-quantum (FIPS 204)",
                "FUTURE-PROOF".green().bold()
            )
        } else if lower.contains("slh-dsa") {
            format!(
                "{} — post-quantum stateless hash-based (FIPS 205)",
                "FUTURE-PROOF".green().bold()
            )
        } else if lower.contains("pss") {
            format!(
                "{} — RSA-PSS probabilistic padding",
                "STRONG".green().bold()
            )
        } else {
            format!("{}", "UNKNOWN — manual review needed".yellow())
        }
    }

    /// Assess key algorithm strength.
    fn assess_key_strength(algo: &str, bits: u32) -> String {
        use colored::Colorize;
        match algo {
            "RSA" => match bits {
                0..=1023 => format!(
                    "{} — {} bits, factoring attacks practical",
                    "BROKEN".red().bold(),
                    bits
                ),
                1024..=2047 => format!(
                    "{} — {} bits, below minimum (NIST deprecates < 2048)",
                    "WEAK".red().bold(),
                    bits
                ),
                2048 => format!(
                    "{} — minimum acceptable, ~112-bit security",
                    "ACCEPTABLE".yellow()
                ),
                2049..=3071 => format!("{} — ~112-128-bit security equivalent", "GOOD".green()),
                3072..=4095 => format!(
                    "{} — ~128-bit security, recommended",
                    "STRONG".green().bold()
                ),
                _ => format!(
                    "{} — {} bits, exceeds requirements",
                    "STRONG".green().bold(),
                    bits
                ),
            },
            "EC" => match bits {
                256 => format!("{} — ~128-bit security (P-256)", "STRONG".green().bold()),
                384 => format!("{} — ~192-bit security (P-384)", "STRONG".green().bold()),
                521 => format!("{} — ~256-bit security (P-521)", "STRONG".green().bold()),
                _ => format!("{} — {} bits", "UNKNOWN".yellow(), bits),
            },
            "Ed25519" => format!(
                "{} — 128-bit security, modern curve",
                "STRONG".green().bold()
            ),
            "Ed448" => format!(
                "{} — 224-bit security, modern curve",
                "STRONG".green().bold()
            ),
            _ if algo.starts_with("ML-DSA") => format!(
                "{} — NIST post-quantum standard (FIPS 204)",
                "FUTURE-PROOF".green().bold()
            ),
            _ if algo.starts_with("SLH-DSA") => format!(
                "{} — stateless hash-based PQ (FIPS 205)",
                "FUTURE-PROOF".green().bold()
            ),
            _ => format!("{} — manual review needed", "UNKNOWN".yellow()),
        }
    }

    /// Return OID for known EC curves.
    fn curve_oid(curve: &str) -> &'static str {
        match curve {
            "P-256" => "1.2.840.10045.3.1.7 (prime256v1/secp256r1)",
            "P-384" => "1.3.132.0.34 (secp384r1)",
            "P-521" => "1.3.132.0.35 (secp521r1)",
            "secp256k1" => "1.3.132.0.10 (secp256k1/Bitcoin)",
            _ => "unknown",
        }
    }

    /// Display critical flag with context.
    fn critical_display(is_critical: bool, colored: bool) -> String {
        if colored {
            if is_critical {
                format!(
                    "{} — MUST be processed, reject if unrecognized",
                    "Yes (critical)".yellow().bold()
                )
            } else {
                format!("{} — MAY be ignored if unrecognized", "No".dimmed())
            }
        } else if is_critical {
            "Yes (critical) -- MUST be processed".to_string()
        } else {
            "No -- MAY be ignored".to_string()
        }
    }

    /// Return explanatory note for key usage flag.
    fn key_usage_note(usage: &str) -> &'static str {
        match usage {
            "Digital Signature" => "(sign data, TLS handshakes)",
            "Non Repudiation" => "(content commitment, cannot deny signing)",
            "Key Encipherment" => "(encrypt session keys, RSA key exchange)",
            "Data Encipherment" => "(directly encrypt data — rare)",
            "Key Agreement" => "(DH/ECDH key agreement)",
            "Certificate Sign" => "(sign other certificates — CA only)",
            "CRL Sign" => "(sign CRLs — CA only)",
            "Encipher Only" => "(key agreement: encrypt only)",
            "Decipher Only" => "(key agreement: decrypt only)",
            _ => "",
        }
    }

    /// Map EKU display name back to OID.
    fn eku_to_oid(name: &str) -> &'static str {
        match name {
            "TLS Web Server Authentication" | "Server Authentication" => "1.3.6.1.5.5.7.3.1",
            "TLS Web Client Authentication" | "Client Authentication" => "1.3.6.1.5.5.7.3.2",
            "Code Signing" => "1.3.6.1.5.5.7.3.3",
            "E-mail Protection" | "Email Protection" => "1.3.6.1.5.5.7.3.4",
            "Time Stamping" => "1.3.6.1.5.5.7.3.8",
            "OCSP Signing" => "1.3.6.1.5.5.7.3.9",
            "Any Extended Key Usage" => "2.5.29.37.0",
            _ => "unknown",
        }
    }

    // ── OpenSSL-compatible format ─────────────────────────────────────

    /// Format a certificate in OpenSSL `x509 -text -noout` style with optional
    /// colors and PKI Client extension sections (lifetime bar, trust chain).
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn format_openssl(cert: &Certificate, colored: bool) -> String {
        let mut out = String::new();

        // ── Certificate: / Data: ──────────────────────────────────────
        out.push_str("Certificate:\n");
        out.push_str("    Data:\n");

        // Version
        out.push_str(&format!(
            "        Version: {} (0x{})\n",
            cert.version,
            cert.version - 1
        ));

        // Serial Number
        out.push_str("        Serial Number:\n");
        let serial_formatted = Self::os_format_serial(&cert.serial);
        out.push_str(&format!("            {}\n", serial_formatted));

        // Signature Algorithm (in Data section)
        out.push_str(&format!(
            "        Signature Algorithm: {}\n",
            cert.signature_algorithm_name
        ));

        // Issuer
        out.push_str(&format!("        Issuer: {}\n", cert.issuer));

        // Validity (no colon — matches openssl)
        out.push_str("        Validity\n");
        out.push_str(&format!(
            "            Not Before: {}\n",
            cert.not_before.format("%b %e %H:%M:%S %Y GMT")
        ));
        out.push_str(&format!(
            "            Not After : {}\n",
            cert.not_after.format("%b %e %H:%M:%S %Y GMT")
        ));

        // Subject
        out.push_str(&format!("        Subject: {}\n", cert.subject));

        // Subject Public Key Info
        out.push_str("        Subject Public Key Info:\n");
        let algo_display = Self::os_key_algorithm_display(cert);
        out.push_str(&format!(
            "            Public Key Algorithm: {}\n",
            algo_display
        ));

        if let Some(ref curve) = cert.ec_curve {
            out.push_str(&format!(
                "                Public-Key: ({} bit)\n",
                cert.key_size
            ));
            out.push_str(&format!(
                "                ASN1 OID: {}\n",
                curve.to_lowercase()
            ));
        } else if cert.key_algorithm_name == "RSA" {
            out.push_str(&format!(
                "                Public-Key: ({} bit)\n",
                cert.key_size
            ));
            if let Some(ref modulus) = cert.rsa_modulus {
                out.push_str("                Modulus:\n");
                let colon_hex = Self::os_format_hex_block(modulus);
                for line in colon_hex.lines() {
                    out.push_str(&format!("                    {}\n", line));
                }
            }
            if let Some(exponent) = cert.rsa_exponent {
                out.push_str(&format!(
                    "                Exponent: {} (0x{:x})\n",
                    exponent, exponent
                ));
            }
        } else {
            out.push_str(&format!(
                "                Public-Key: ({} bit)\n",
                cert.key_size
            ));
        }

        // X509v3 extensions
        out.push_str("        X509v3 extensions:\n");

        // Basic Constraints
        if cert.is_ca || cert.basic_constraints_critical {
            let crit = if cert.basic_constraints_critical {
                " critical"
            } else {
                ""
            };
            out.push_str(&format!("            X509v3 Basic Constraints:{}\n", crit));
            let ca_str = if cert.is_ca { "TRUE" } else { "FALSE" };
            if cert.path_length >= 0 {
                out.push_str(&format!(
                    "                CA:{}, pathlen:{}\n",
                    ca_str, cert.path_length
                ));
            } else {
                out.push_str(&format!("                CA:{}\n", ca_str));
            }
        }

        // Key Usage
        if !cert.key_usage.is_empty() {
            let crit = if cert.key_usage_critical {
                " critical"
            } else {
                ""
            };
            out.push_str(&format!("            X509v3 Key Usage:{}\n", crit));
            out.push_str(&format!("                {}\n", cert.key_usage.join(", ")));
        }

        // Extended Key Usage
        if !cert.extended_key_usage.is_empty() {
            out.push_str("            X509v3 Extended Key Usage:\n");
            out.push_str(&format!(
                "                {}\n",
                cert.extended_key_usage.join(", ")
            ));
        }

        // SAN
        if !cert.san.is_empty() {
            out.push_str("            X509v3 Subject Alternative Name:\n");
            let san_strs: Vec<String> = cert.san.iter().map(|s| s.to_string()).collect();
            out.push_str(&format!("                {}\n", san_strs.join(", ")));
        }

        // Subject Key Identifier
        if let Some(ref ski) = cert.subject_key_id {
            out.push_str("            X509v3 Subject Key Identifier: \n");
            out.push_str(&format!("                {}\n", Self::os_colonize_hex(ski)));
        }

        // Authority Key Identifier
        if let Some(ref aki) = cert.authority_key_id {
            out.push_str("            X509v3 Authority Key Identifier: \n");
            out.push_str(&format!(
                "                keyid:{}\n",
                Self::os_colonize_hex(aki)
            ));
        }

        // Authority Information Access
        if !cert.ocsp_urls.is_empty() || !cert.ca_issuer_urls.is_empty() {
            out.push_str("            Authority Information Access: \n");
            for url in &cert.ocsp_urls {
                out.push_str(&format!("                OCSP - URI:{}\n", url));
            }
            for url in &cert.ca_issuer_urls {
                out.push_str(&format!("                CA Issuers - URI:{}\n", url));
            }
        }

        // CRL Distribution Points
        if !cert.crl_distribution_points.is_empty() {
            out.push_str("            X509v3 CRL Distribution Points: \n");
            out.push('\n');
            out.push_str("                Full Name:\n");
            for url in &cert.crl_distribution_points {
                out.push_str(&format!("                  URI:{}\n", url));
            }
        }

        // Certificate Policies
        if !cert.certificate_policies.is_empty() {
            out.push_str("            X509v3 Certificate Policies: \n");
            for policy in &cert.certificate_policies {
                out.push_str(&format!(
                    "                Policy: {}\n",
                    Self::policy_oid_to_name(policy)
                ));
            }
        }

        // CT SCTs
        if !cert.ct_scts.is_empty() {
            out.push_str(&format!(
                "            CT Precertificate SCTs: {} embedded\n",
                cert.ct_scts.len()
            ));
        }

        // OCSP Must-Staple
        if cert.ocsp_must_staple {
            out.push_str("            TLS Feature: \n");
            out.push_str("                status_request\n");
        }

        // ── Trailing Signature Algorithm + Value ──────────────────────
        out.push_str(&format!(
            "    Signature Algorithm: {}\n",
            cert.signature_algorithm_name
        ));

        if !cert.signature_bytes.is_empty() {
            let sig_hex = Self::os_format_signature(&cert.signature_bytes);
            for line in sig_hex.lines() {
                out.push_str(&format!("         {}\n", line));
            }
        }

        // ── Fingerprints (bonus — openssl shows with -fingerprint) ───
        out.push_str(&format!(
            "SHA-256 Fingerprint={}\n",
            Self::os_colonize_hex(&cert.fingerprint_sha256)
        ));
        out.push_str(&format!(
            "SHA-1 Fingerprint={}\n",
            Self::os_colonize_hex(&cert.fingerprint_sha1)
        ));

        // ── PKI Client Extensions (our custom additions) ─────────────
        out.push_str("\n--- PKI Client Extensions ---\n");

        // Lifetime bar
        let pct = cert.lifetime_used_percent();
        let days_left = cert.days_until_expiry();
        let total_days = (cert.not_after - cert.not_before).num_days();
        let elapsed_days = total_days - days_left;
        let bar = Self::os_lifetime_bar(pct, colored);
        out.push_str(&format!(
            "    Lifetime:  {} {:.0}% ({}/{} days)\n",
            bar,
            pct.min(100.0),
            elapsed_days.max(0),
            total_days.max(0)
        ));

        // Trust chain
        let cn = cert.common_name().unwrap_or(&cert.subject);
        let issuer_cn = cert
            .issuer
            .split(", ")
            .find(|p| p.starts_with("CN="))
            .map(|p| &p[3..])
            .unwrap_or(&cert.issuer);
        if cert.is_self_signed() {
            out.push_str(&format!("    Trust:     {} (self-signed)\n", cn));
        } else {
            out.push_str(&format!("    Trust:     {} \u{2190} {}\n", cn, issuer_cn));
        }

        // Apply colors if requested
        if colored {
            Self::os_colorize(&out)
        } else {
            out
        }
    }

    // ── OpenSSL format helpers ────────────────────────────────────────

    /// Format serial as colon-separated uppercase hex (OpenSSL style).
    fn os_format_serial(serial: &str) -> String {
        // serial is already hex; insert colons every 2 chars
        let upper = serial.to_uppercase();
        // Pad to even length
        let padded = if !upper.len().is_multiple_of(2) {
            format!("0{}", upper)
        } else {
            upper
        };
        padded
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or("??"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Map key algorithm to OpenSSL display name.
    fn os_key_algorithm_display(cert: &Certificate) -> String {
        match cert.key_algorithm_name.as_str() {
            "RSA" => "rsaEncryption".to_string(),
            "EC" => "id-ecPublicKey".to_string(),
            "Ed25519" => "ED25519".to_string(),
            "Ed448" => "ED448".to_string(),
            other => other.to_string(),
        }
    }

    /// Colonize a plain hex string: "aabb" → "AA:BB".
    fn os_colonize_hex(hex: &str) -> String {
        // If already colonized, uppercase it
        if hex.contains(':') {
            return hex.to_uppercase();
        }
        let upper = hex.to_uppercase();
        let padded = if !upper.len().is_multiple_of(2) {
            format!("0{}", upper)
        } else {
            upper
        };
        padded
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or("??"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Format a hex string as OpenSSL modulus block (colon-separated, 15 pairs per line).
    fn os_format_hex_block(hex: &str) -> String {
        let colonized = Self::os_colonize_hex(hex);
        let pairs: Vec<&str> = colonized.split(':').collect();
        let mut lines = Vec::new();
        for chunk in pairs.chunks(15) {
            let mut line = chunk.join(":");
            // Add trailing colon if not the last chunk
            line.push(':');
            lines.push(line);
        }
        // Remove trailing colon from last line
        if let Some(last) = lines.last_mut() {
            if last.ends_with(':') {
                last.pop();
            }
        }
        lines.join("\n")
    }

    /// Format signature bytes as colon-separated hex, 18 pairs per line.
    fn os_format_signature(bytes: &[u8]) -> String {
        let pairs: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let mut lines = Vec::new();
        for chunk in pairs.chunks(18) {
            let mut line = chunk.join(":");
            // Check if this is NOT the last chunk
            if chunk.len() == 18 {
                line.push(':');
            }
            lines.push(line);
        }
        lines.join("\n         ")
    }

    /// Build lifetime progress bar.
    fn os_lifetime_bar(pct: f64, _colored: bool) -> String {
        let width: usize = 20;
        let filled = ((pct / 100.0) * width as f64).round() as usize;
        let empty = width.saturating_sub(filled);
        format!(
            "[{}{}]",
            "\u{2588}".repeat(filled),
            "\u{2591}".repeat(empty)
        )
    }

    /// Apply ANSI colors to the full OpenSSL output.
    fn os_colorize(plain: &str) -> String {
        let mut out = String::with_capacity(plain.len() * 2);
        for line in plain.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("Certificate:")
                || trimmed.starts_with("Data:")
                || trimmed == "--- PKI Client Extensions ---"
            {
                out.push_str(&format!("{}\n", line.cyan().bold()));
            } else if trimmed.starts_with("Version:")
                || trimmed.starts_with("Serial Number:")
                || trimmed.starts_with("Signature Algorithm:")
                || trimmed.starts_with("Issuer:")
                || trimmed.starts_with("Validity")
                || trimmed.starts_with("Subject:")
                || trimmed.starts_with("Subject Public Key Info:")
                || trimmed.starts_with("Public Key Algorithm:")
                || trimmed.starts_with("X509v3 extensions:")
            {
                out.push_str(&format!("{}\n", line.white().bold()));
            } else if trimmed.starts_with("Not Before:") || trimmed.starts_with("Not After :") {
                out.push_str(&format!("{}\n", line.yellow()));
            } else if trimmed.starts_with("X509v3 ")
                || trimmed.starts_with("Authority Information")
                || trimmed.starts_with("TLS Feature")
                || trimmed.starts_with("CT Precertificate")
            {
                out.push_str(&format!("{}\n", line.green()));
            } else if trimmed.starts_with("SHA-256 Fingerprint")
                || trimmed.starts_with("SHA-1 Fingerprint")
            {
                out.push_str(&format!("{}\n", line.dimmed()));
            } else if trimmed.starts_with("Lifetime:") {
                // Color the lifetime bar based on percentage
                out.push_str(&Self::os_colorize_lifetime(line));
                out.push('\n');
            } else if trimmed.starts_with("Trust:") {
                out.push_str(&format!("{}\n", line.cyan()));
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        // Remove trailing newline to match original
        if out.ends_with('\n') {
            out.pop();
            out.push('\n');
        }
        out
    }

    /// Colorize the lifetime line based on the percentage value.
    fn os_colorize_lifetime(line: &str) -> String {
        // Parse percentage from the line
        if let Some(pct_str) = line
            .split('%')
            .next()
            .and_then(|s| s.rsplit_once(' ').map(|(_, n)| n))
        {
            if let Ok(pct) = pct_str.parse::<f64>() {
                return if pct >= 100.0 {
                    line.red().bold().to_string()
                } else if pct >= 70.0 {
                    line.yellow().bold().to_string()
                } else {
                    line.green().to_string()
                };
            }
        }
        line.to_string()
    }

    /// Format a certificate without colors (plain text, OpenSSL-style).
    #[must_use]
    pub fn format_plain(cert: &Certificate) -> String {
        let mut output = String::new();

        let validation = Self::detect_validation_type(cert);
        let purpose = Self::get_cert_purpose(cert);
        let self_signed = Self::is_self_signed(cert);
        let (grade, _) = Self::calculate_grade(cert);

        // Type indicators
        let type_str = if cert.is_ca {
            "CA Certificate"
        } else if self_signed {
            "Self-Signed"
        } else {
            "End Entity"
        };

        output.push_str("Certificate Summary:\n");
        output.push_str(&format!(
            "    Type:           {} ({})\n",
            type_str, validation
        ));
        output.push_str(&format!("    Grade:          {}\n", grade));
        output.push_str(&format!("    Purpose:        {}\n", purpose));
        output.push('\n');

        output.push_str("Certificate:\n");
        output.push_str("    Data:\n");
        output.push_str(&format!(
            "        Version: {} (0x{})\n",
            cert.version,
            cert.version - 1
        ));
        output.push_str("        Serial Number:\n");
        output.push_str(&format!("            {}\n", cert.serial.to_uppercase()));
        output.push_str(&format!(
            "        Signature Algorithm: {}\n",
            cert.signature_algorithm_name
        ));
        output.push_str(&format!("        Issuer: {}\n", cert.issuer));
        output.push_str("        Validity:\n");
        output.push_str(&format!(
            "            Not Before: {}\n",
            cert.not_before.format("%b %e %H:%M:%S %Y %Z")
        ));
        output.push_str(&format!(
            "            Not After : {} ({} days)\n",
            cert.not_after.format("%b %e %H:%M:%S %Y %Z"),
            cert.days_until_expiry()
        ));

        let lifetime_pct = cert.lifetime_used_percent();
        let lifetime_status = if lifetime_pct >= 100.0 {
            "EXPIRED"
        } else if lifetime_pct >= 70.0 {
            "RENEW NOW"
        } else {
            "OK"
        };
        output.push_str(&format!(
            "            Lifetime  : {:.1}% used ({})\n",
            lifetime_pct.min(100.0),
            lifetime_status
        ));

        output.push_str(&format!("        Subject: {}\n", cert.subject));
        output.push_str("        Subject Public Key Info:\n");
        if cert.key_algorithm_name.starts_with("ML-DSA") {
            let nist_level = match cert.key_algorithm_name.as_str() {
                "ML-DSA-44" => "2",
                "ML-DSA-65" => "3",
                "ML-DSA-87" => "5",
                _ => "?",
            };
            output.push_str(&format!(
                "            Algorithm: {} (NIST Level {})  ({})\n",
                cert.key_algorithm_name, nist_level, cert.key_algorithm
            ));
        } else {
            output.push_str(&format!(
                "            Algorithm: {} ({} bit)  ({})\n",
                cert.key_algorithm_name, cert.key_size, cert.key_algorithm
            ));
        }

        if let Some(ref curve) = cert.ec_curve {
            output.push_str(&format!("            Curve: {}\n", curve));
        }

        if cert.key_algorithm_name == "RSA" {
            if let Some(ref modulus) = cert.rsa_modulus {
                output.push_str("            Modulus:\n");
                for chunk in modulus.as_bytes().chunks(64) {
                    let line = std::str::from_utf8(chunk).unwrap_or("");
                    output.push_str(&format!("                {}\n", line));
                }
            }
            if let Some(exponent) = cert.rsa_exponent {
                output.push_str(&format!(
                    "            Exponent: {} (0x{:x})\n",
                    exponent, exponent
                ));
            }
        }

        output.push_str("        X509v3 extensions:\n");

        if cert.is_ca || cert.basic_constraints_critical {
            let critical = if cert.basic_constraints_critical {
                " critical"
            } else {
                ""
            };
            output.push_str(&format!(
                "            X509v3 Basic Constraints:{}\n",
                critical
            ));
            let ca_str = if cert.is_ca { "TRUE" } else { "FALSE" };
            if cert.path_length >= 0 {
                output.push_str(&format!(
                    "                CA:{}, pathlen:{}\n",
                    ca_str, cert.path_length
                ));
            } else {
                output.push_str(&format!("                CA:{}\n", ca_str));
            }
        }

        if !cert.key_usage.is_empty() {
            let critical = if cert.key_usage_critical {
                " critical"
            } else {
                ""
            };
            output.push_str(&format!("            X509v3 Key Usage:{}\n", critical));
            output.push_str(&format!("                {}\n", cert.key_usage.join(", ")));
        }

        if !cert.extended_key_usage.is_empty() {
            output.push_str("            X509v3 Extended Key Usage:\n");
            output.push_str(&format!(
                "                {}\n",
                cert.extended_key_usage.join(", ")
            ));
        }

        if !cert.san.is_empty() {
            output.push_str("            X509v3 Subject Alternative Name:\n");
            for san in &cert.san {
                output.push_str(&format!("                {}\n", san));
            }
        }

        if let Some(ref ski) = cert.subject_key_id {
            output.push_str("            X509v3 Subject Key Identifier:\n");
            output.push_str(&format!("                {}\n", ski));
        }

        if let Some(ref aki) = cert.authority_key_id {
            output.push_str("            X509v3 Authority Key Identifier:\n");
            output.push_str(&format!("                keyid:{}\n", aki));
        }

        if !cert.ocsp_urls.is_empty() || !cert.ca_issuer_urls.is_empty() {
            output.push_str("            Authority Information Access:\n");
            for url in &cert.ocsp_urls {
                output.push_str(&format!("                OCSP - URI:{}\n", url));
            }
            for url in &cert.ca_issuer_urls {
                output.push_str(&format!("                CA Issuers - URI:{}\n", url));
            }
        }

        if !cert.crl_distribution_points.is_empty() {
            output.push_str("            X509v3 CRL Distribution Points:\n");
            for url in &cert.crl_distribution_points {
                output.push_str(&format!("                URI:{}\n", url));
            }
        }

        if !cert.certificate_policies.is_empty() {
            output.push_str("            X509v3 Certificate Policies:\n");
            for policy in &cert.certificate_policies {
                output.push_str(&format!(
                    "                Policy: {}\n",
                    Self::policy_oid_to_name(policy)
                ));
            }
        }

        if !cert.ct_scts.is_empty() {
            output.push_str(&format!(
                "            CT Precertificate SCTs: {} embedded\n",
                cert.ct_scts.len()
            ));
        }

        output.push_str(&format!(
            "    Signature Algorithm: {}\n",
            cert.signature_algorithm_name
        ));

        output.push_str("\nFingerprints:\n");
        output.push_str(&format!(
            "    SHA-256:        {}\n",
            cert.fingerprint_sha256
        ));
        output.push_str(&format!("    SHA-1:          {}\n", cert.fingerprint_sha1));
        output.push_str(&format!("    SPKI Pin:       {}\n", cert.spki_sha256_b64));

        output
    }
}

impl Formatter for Certificate {
    fn to_text(&self, colored: bool) -> String {
        CertFormatter::format(self, colored)
    }

    fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    fn to_compact(&self) -> String {
        let cn = self.common_name().unwrap_or(&self.subject);
        let days = self.days_until_expiry();
        let lifetime = self.lifetime_used_percent();
        let status = if days < 0 {
            "EXPIRED"
        } else if lifetime >= 70.0 {
            "RENEW"
        } else if days < 30 {
            "EXPIRING"
        } else {
            "OK"
        };
        format!("{} | {} | {}d | {:.0}%", cn, status, days, lifetime)
    }

    fn to_forensic(&self, colored: bool) -> String {
        CertFormatter::format_forensic(self, colored)
    }

    fn to_openssl(&self, colored: bool) -> String {
        CertFormatter::format_openssl(self, colored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SanEntry;
    use chrono::{Duration, Utc};

    fn make_cert() -> Certificate {
        Certificate {
            version: 3,
            serial: "01".to_string(),
            subject: "CN=test.example.com".to_string(),
            issuer: "CN=Test CA".to_string(),
            not_before: Utc::now() - Duration::days(30),
            not_after: Utc::now() + Duration::days(335),
            signature_algorithm: "1.2.840.10045.4.3.2".to_string(),
            signature_algorithm_name: "SHA-256 with ECDSA".to_string(),
            key_algorithm: "1.2.840.10045.2.1".to_string(),
            key_algorithm_name: "EC".to_string(),
            key_size: 256,
            ec_curve: Some("P-256".to_string()),
            rsa_modulus: None,
            rsa_exponent: None,
            is_ca: false,
            path_length: -1,
            basic_constraints_critical: false,
            key_usage: vec!["Digital Signature".to_string()],
            key_usage_critical: true,
            extended_key_usage: vec!["TLS Web Server Authentication".to_string()],
            san: vec![SanEntry::Dns("test.example.com".to_string())],
            subject_key_id: Some("aabb".to_string()),
            authority_key_id: Some("ccdd".to_string()),
            ocsp_urls: vec!["http://ocsp.example.com".to_string()],
            ca_issuer_urls: vec![],
            crl_distribution_points: vec!["http://crl.example.com/ca.crl".to_string()],
            certificate_policies: vec![],
            ocsp_must_staple: false,
            ct_scts: vec![],
            fingerprint_sha256: "aa:bb".to_string(),
            fingerprint_sha1: "cc:dd".to_string(),
            spki_sha256_b64: "base64==".to_string(),
            signature_bytes: vec![],
            der: vec![],
        }
    }

    // ========== detect_validation_type tests ==========

    #[test]
    fn test_validation_type_ev() {
        let mut cert = make_cert();
        cert.certificate_policies = vec!["2.23.140.1.1".to_string()];
        assert_eq!(CertFormatter::detect_validation_type(&cert), "EV");
    }

    #[test]
    fn test_validation_type_ov() {
        let mut cert = make_cert();
        cert.certificate_policies = vec!["2.23.140.1.2.2".to_string()];
        assert_eq!(CertFormatter::detect_validation_type(&cert), "OV");
    }

    #[test]
    fn test_validation_type_dv() {
        let mut cert = make_cert();
        cert.certificate_policies = vec!["2.23.140.1.2.1".to_string()];
        assert_eq!(CertFormatter::detect_validation_type(&cert), "DV");
    }

    #[test]
    fn test_validation_type_iv() {
        let mut cert = make_cert();
        cert.certificate_policies = vec!["2.23.140.1.2.3".to_string()];
        assert_eq!(CertFormatter::detect_validation_type(&cert), "IV");
    }

    #[test]
    fn test_validation_type_unknown() {
        let cert = make_cert();
        assert_eq!(CertFormatter::detect_validation_type(&cert), "Unknown");
    }

    // ========== detect_ca_vendor tests ==========

    #[test]
    fn test_ca_vendor_letsencrypt() {
        assert_eq!(
            CertFormatter::detect_ca_vendor("Let's Encrypt Authority X3"),
            Some("Let's Encrypt")
        );
        assert_eq!(
            CertFormatter::detect_ca_vendor("LETSENCRYPT R3"),
            Some("Let's Encrypt")
        );
    }

    #[test]
    fn test_ca_vendor_digicert() {
        assert_eq!(
            CertFormatter::detect_ca_vendor("DigiCert Global Root G2"),
            Some("DigiCert")
        );
    }

    #[test]
    fn test_ca_vendor_sectigo() {
        assert_eq!(
            CertFormatter::detect_ca_vendor("Comodo RSA CA"),
            Some("Sectigo")
        );
        assert_eq!(
            CertFormatter::detect_ca_vendor("Sectigo RSA Domain Validation"),
            Some("Sectigo")
        );
    }

    #[test]
    fn test_ca_vendor_google() {
        assert_eq!(
            CertFormatter::detect_ca_vendor("Google Trust Services GTS CA 1C3"),
            Some("Google Trust Services")
        );
    }

    #[test]
    fn test_ca_vendor_amazon() {
        assert_eq!(
            CertFormatter::detect_ca_vendor("Amazon RSA 2048 M01"),
            Some("Amazon/AWS")
        );
    }

    #[test]
    fn test_ca_vendor_unknown() {
        assert_eq!(CertFormatter::detect_ca_vendor("SPORK Root CA"), None);
        assert_eq!(CertFormatter::detect_ca_vendor("My Custom CA"), None);
    }

    // ========== get_cert_purpose tests ==========

    #[test]
    fn test_purpose_server() {
        let cert = make_cert();
        assert_eq!(CertFormatter::get_cert_purpose(&cert), "Server");
    }

    #[test]
    fn test_purpose_ca_server() {
        let mut cert = make_cert();
        cert.is_ca = true;
        assert_eq!(CertFormatter::get_cert_purpose(&cert), "CA, Server");
    }

    #[test]
    fn test_purpose_client() {
        let mut cert = make_cert();
        cert.extended_key_usage = vec!["TLS Web Client Authentication".to_string()];
        assert_eq!(CertFormatter::get_cert_purpose(&cert), "Client");
    }

    #[test]
    fn test_purpose_code_signing() {
        let mut cert = make_cert();
        cert.extended_key_usage = vec!["Code Signing".to_string()];
        assert_eq!(CertFormatter::get_cert_purpose(&cert), "Code Signing");
    }

    #[test]
    fn test_purpose_multiple() {
        let mut cert = make_cert();
        cert.extended_key_usage = vec![
            "TLS Web Server Authentication".to_string(),
            "TLS Web Client Authentication".to_string(),
        ];
        assert_eq!(CertFormatter::get_cert_purpose(&cert), "Server, Client");
    }

    #[test]
    fn test_purpose_general() {
        let mut cert = make_cert();
        cert.extended_key_usage = vec![];
        assert_eq!(CertFormatter::get_cert_purpose(&cert), "General Purpose");
    }

    // ========== is_self_signed / has_wildcard tests ==========

    #[test]
    fn test_self_signed() {
        let mut cert = make_cert();
        cert.issuer = cert.subject.clone();
        assert!(CertFormatter::is_self_signed(&cert));
    }

    #[test]
    fn test_not_self_signed() {
        let cert = make_cert();
        assert!(!CertFormatter::is_self_signed(&cert));
    }

    #[test]
    fn test_has_wildcard() {
        let mut cert = make_cert();
        cert.san = vec![SanEntry::Dns("*.example.com".to_string())];
        assert!(CertFormatter::has_wildcard(&cert));
    }

    #[test]
    fn test_no_wildcard() {
        let cert = make_cert();
        assert!(!CertFormatter::has_wildcard(&cert));
    }

    // ========== calculate_grade tests ==========

    #[test]
    fn test_grade_a_strong_ecdsa() {
        let mut cert = make_cert();
        cert.ocsp_urls = vec!["http://ocsp.example.com".to_string()];
        cert.ct_scts = vec![crate::CtSct {
            log_id: "aa".to_string(),
            timestamp: Utc::now(),
        }];
        let (grade, _) = CertFormatter::calculate_grade(&cert);
        assert_eq!(grade, "A");
    }

    #[test]
    fn test_grade_f_expired() {
        let mut cert = make_cert();
        cert.not_after = Utc::now() - Duration::days(1);
        let (grade, reason) = CertFormatter::calculate_grade(&cert);
        assert_eq!(grade, "F");
        assert_eq!(reason, "expired");
    }

    #[test]
    fn test_grade_penalty_weak_rsa() {
        let mut cert = make_cert();
        cert.key_algorithm_name = "RSA".to_string();
        cert.key_size = 1024;
        let (grade, reason) = CertFormatter::calculate_grade(&cert);
        assert!(grade == "D" || grade == "F");
        assert_eq!(reason, "weak key");
    }

    #[test]
    fn test_grade_penalty_sha1() {
        let mut cert = make_cert();
        cert.signature_algorithm_name = "SHA-1 with RSA".to_string();
        let (grade, reason) = CertFormatter::calculate_grade(&cert);
        assert!(grade != "A");
        assert_eq!(reason, "SHA-1");
    }

    #[test]
    fn test_grade_penalty_md5() {
        let mut cert = make_cert();
        cert.signature_algorithm_name = "MD5 with RSA".to_string();
        let (_grade, reason) = CertFormatter::calculate_grade(&cert);
        assert_eq!(reason, "MD5");
    }

    #[test]
    fn test_grade_ca_no_san_penalty() {
        // CA certs should NOT be penalized for missing SANs, CT, or OCSP
        let mut cert = make_cert();
        cert.is_ca = true;
        cert.issuer = cert.subject.clone(); // self-signed
        cert.san = vec![];
        cert.ct_scts = vec![];
        cert.ocsp_urls = vec![];
        cert.crl_distribution_points = vec![];
        let (grade, _) = CertFormatter::calculate_grade(&cert);
        assert_eq!(grade, "A");
    }

    #[test]
    fn test_grade_end_entity_no_san_penalty() {
        let mut cert = make_cert();
        cert.san = vec![];
        cert.ct_scts = vec![];
        cert.ocsp_urls = vec![];
        cert.crl_distribution_points = vec![];
        let (grade, reason) = CertFormatter::calculate_grade(&cert);
        // -5 (no CT) -10 (no revocation) -15 (no SAN) = 70 → C
        assert_eq!(grade, "C");
        assert_eq!(reason, "no SAN");
    }

    // ========== format_plain tests ==========

    #[test]
    fn test_format_plain_contains_subject() {
        let cert = make_cert();
        let output = CertFormatter::format_plain(&cert);
        assert!(output.contains("test.example.com"));
        assert!(output.contains("Test CA"));
    }

    #[test]
    fn test_format_plain_no_ansi() {
        let cert = make_cert();
        let output = CertFormatter::format_plain(&cert);
        assert!(!output.contains("\x1b["));
    }

    // ========== compact format tests ==========

    #[test]
    fn test_compact_output_valid_cert() {
        let cert = make_cert();
        let output = cert.to_compact();
        assert!(output.contains("test.example.com"));
        assert!(output.contains("OK"));
        assert!(output.contains("|"));
    }

    #[test]
    fn test_compact_output_expired_cert() {
        let mut cert = make_cert();
        cert.not_after = Utc::now() - Duration::days(10);
        let output = cert.to_compact();
        assert!(output.contains("EXPIRED"));
    }

    #[test]
    fn test_compact_output_expiring_soon() {
        let mut cert = make_cert();
        cert.not_after = Utc::now() + Duration::days(15);
        let output = cert.to_compact();
        assert!(output.contains("EXPIRING") || output.contains("RENEW"));
    }

    #[test]
    fn test_compact_output_renew_threshold() {
        let mut cert = make_cert();
        // 365-day cert, 300 days in => ~82% lifetime used
        cert.not_before = Utc::now() - Duration::days(300);
        cert.not_after = Utc::now() + Duration::days(65);
        let output = cert.to_compact();
        assert!(output.contains("RENEW"));
    }

    #[test]
    fn test_compact_output_single_line() {
        let cert = make_cert();
        let output = cert.to_compact();
        assert_eq!(output.lines().count(), 1, "compact must be single line");
    }

    #[test]
    fn test_compact_via_formatter_trait() {
        let cert = make_cert();
        let output = cert.format(crate::OutputFormat::Compact, false);
        assert!(output.contains("test.example.com"));
        assert!(output.contains("|"));
    }

    // ========== forensic_section_header tests ==========

    #[test]
    fn test_forensic_section_header_long_title_no_panic() {
        let mut o = String::new();
        // Title longer than 68 chars should not panic thanks to saturating_sub
        let long_title = "A".repeat(100);
        CertFormatter::forensic_section_header(&mut o, &long_title, false);
        assert!(o.contains(&long_title));
    }

    // ========== signature_bytes / format_colored tests ==========

    #[test]
    fn test_format_colored_signature_hex_present_when_bytes_set() {
        let mut cert = make_cert();
        cert.signature_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let _plain = CertFormatter::format(&cert, false);
        // format_plain does NOT include the signature hex dump; the colored path does.
        // Verify via the colored path directly.
        let colored_output = CertFormatter::format(&cert, true);
        assert!(
            colored_output.contains("Signature Value"),
            "colored output must include Signature Value header when signature_bytes is non-empty"
        );
    }

    #[test]
    fn test_format_colored_signature_hex_omitted_when_bytes_empty() {
        let cert = make_cert(); // signature_bytes is vec![] in make_cert()
        let colored_output = CertFormatter::format(&cert, true);
        assert!(
            !colored_output.contains("Signature Value"),
            "colored output must NOT include Signature Value header when signature_bytes is empty"
        );
    }

    #[test]
    fn test_format_colored_signature_hex_encoding_correct() {
        // 4 bytes -> 8 hex chars -> fits in one 36-char chunk -> "de:ad:be:ef"
        let mut cert = make_cert();
        cert.signature_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let colored_output = CertFormatter::format(&cert, true);
        // Strip ANSI escape codes so we can match plain text
        let plain = strip_ansi(&colored_output);
        assert!(
            plain.contains("de:ad:be:ef"),
            "hex dump must be colon-separated byte pairs, got: {}",
            plain
        );
    }

    #[test]
    fn test_format_colored_signature_hex_chunks_across_lines() {
        // 20 bytes = 40 hex chars, which spans two 36-char chunks
        let mut cert = make_cert();
        cert.signature_bytes = (0u8..20).collect();
        let colored_output = CertFormatter::format(&cert, true);
        let plain = strip_ansi(&colored_output);
        // Each chunk line must contain colon-separated pairs
        let sig_section: Vec<&str> = plain
            .lines()
            .skip_while(|l| !l.contains("Signature Value"))
            .skip(1) // skip the header line
            .take_while(|l| l.starts_with("        "))
            .collect();
        assert!(
            sig_section.len() >= 2,
            "20 bytes should produce at least 2 hex dump lines, got {} lines",
            sig_section.len()
        );
        for line in &sig_section {
            assert!(
                line.contains(':'),
                "every hex dump line must contain colon separators, got: '{}'",
                line
            );
        }
    }

    #[test]
    fn test_format_colored_signature_hex_single_byte() {
        let mut cert = make_cert();
        cert.signature_bytes = vec![0xff];
        let colored_output = CertFormatter::format(&cert, true);
        let plain = strip_ansi(&colored_output);
        assert!(
            plain.contains("ff"),
            "single-byte signature must render as 'ff'"
        );
    }

    // ========== PEM output in format_colored tests ==========

    #[test]
    fn test_format_colored_pem_present_when_der_set() {
        let mut cert = make_cert();
        // Minimal non-empty DER blob (content doesn't need to be valid ASN.1 for the formatter)
        cert.der = vec![0x30, 0x00];
        let colored_output = CertFormatter::format(&cert, true);
        assert!(
            colored_output.contains("BEGIN CERTIFICATE"),
            "colored output must include PEM block when der is non-empty"
        );
        assert!(
            colored_output.contains("END CERTIFICATE"),
            "colored output must close PEM block"
        );
    }

    #[test]
    fn test_format_colored_pem_omitted_when_der_empty() {
        let cert = make_cert(); // der is vec![] in make_cert()
        let colored_output = CertFormatter::format(&cert, true);
        assert!(
            !colored_output.contains("BEGIN CERTIFICATE"),
            "colored output must NOT include PEM block when der is empty"
        );
    }

    #[test]
    fn test_format_plain_no_signature_hex_dump() {
        // format_plain intentionally omits signature bytes — this is by design
        let mut cert = make_cert();
        cert.signature_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let plain_output = CertFormatter::format_plain(&cert);
        assert!(
            !plain_output.contains("Signature Value"),
            "format_plain must NOT include Signature Value hex dump (no ANSI color support)"
        );
    }

    #[test]
    fn test_format_plain_no_pem_block() {
        // format_plain intentionally omits PEM output — this is by design
        let mut cert = make_cert();
        cert.der = vec![0x30, 0x00];
        let plain_output = CertFormatter::format_plain(&cert);
        assert!(
            !plain_output.contains("BEGIN CERTIFICATE"),
            "format_plain must NOT include PEM block"
        );
    }

    // ========== signature_bytes serde skip tests ==========

    #[test]
    fn test_signature_bytes_skipped_in_json_serialization() {
        use crate::Formatter;
        let mut cert = make_cert();
        cert.signature_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let json = cert.to_json();
        assert!(
            !json.contains("signature_bytes"),
            "signature_bytes must be skipped in JSON output (#[serde(skip)])"
        );
    }

    #[test]
    fn test_der_skipped_in_json_serialization() {
        use crate::Formatter;
        let mut cert = make_cert();
        cert.der = vec![0x30, 0x00];
        let json = cert.to_json();
        assert!(
            !json.contains("\"der\""),
            "der field must be skipped in JSON output (#[serde(skip)])"
        );
    }

    /// Strip ANSI escape codes for plain-text assertions on colored output.
    fn strip_ansi(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                // consume until 'm'
                for next in chars.by_ref() {
                    if next == 'm' {
                        break;
                    }
                }
            } else {
                result.push(c);
            }
        }
        result
    }

    // ========== RSA modulus truncation tests ==========

    #[test]
    fn test_modulus_truncated_in_text_mode() {
        let mut cert = make_cert();
        cert.key_algorithm_name = "RSA".to_string();
        cert.key_size = 2048;
        // 256 bytes = 512 hex chars (8 lines of 64)
        cert.rsa_modulus = Some("A4".repeat(256));
        cert.rsa_exponent = Some(65537);

        let output = CertFormatter::format_colored(&cert);
        // Should show "Modulus (256 bytes):"
        assert!(
            output.contains("256 bytes"),
            "Modulus should show byte count"
        );
        // Should show truncation notice
        assert!(
            output.contains("more lines"),
            "Modulus should show truncation notice for long moduli"
        );
        // Should NOT contain all 8 lines of hex
        let hex_lines: Vec<&str> = output
            .lines()
            .filter(|l| l.trim().starts_with("A4A4"))
            .collect();
        assert_eq!(
            hex_lines.len(),
            2,
            "Should show exactly 2 lines of modulus, got {}",
            hex_lines.len()
        );
    }

    #[test]
    fn test_short_modulus_not_truncated() {
        let mut cert = make_cert();
        cert.key_algorithm_name = "RSA".to_string();
        cert.key_size = 512;
        // 64 bytes = 128 hex chars (2 lines of 64) — fits within limit
        cert.rsa_modulus = Some("BB".repeat(64));
        cert.rsa_exponent = Some(65537);

        let output = CertFormatter::format_colored(&cert);
        // Should NOT show truncation notice
        assert!(
            !output.contains("more lines"),
            "Short modulus should not be truncated"
        );
    }

    // ========== OpenSSL format tests ==========

    #[test]
    fn test_openssl_format_starts_with_certificate() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.starts_with("Certificate:\n"),
            "OpenSSL format must start with 'Certificate:\\n'"
        );
    }

    #[test]
    fn test_openssl_format_has_data_section() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("    Data:\n"),
            "OpenSSL format must have '    Data:' section"
        );
    }

    #[test]
    fn test_openssl_format_has_version() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("        Version: 3 (0x2)\n"),
            "OpenSSL format must show 'Version: 3 (0x2)'"
        );
    }

    #[test]
    fn test_openssl_format_has_serial_number() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("        Serial Number:\n"),
            "OpenSSL format must have Serial Number header"
        );
    }

    #[test]
    fn test_openssl_format_has_signature_algorithm() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("        Signature Algorithm:"),
            "OpenSSL format must have Signature Algorithm in Data section"
        );
    }

    #[test]
    fn test_openssl_format_has_issuer() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("        Issuer:"),
            "OpenSSL format must have Issuer field"
        );
    }

    #[test]
    fn test_openssl_format_has_validity_section() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("        Validity\n"),
            "OpenSSL format must have 'Validity' section (no colon, matching openssl)"
        );
        assert!(
            output.contains("            Not Before:"),
            "Must have Not Before"
        );
        assert!(
            output.contains("            Not After :"),
            "Must have Not After (with space before colon, matching openssl)"
        );
    }

    #[test]
    fn test_openssl_format_has_subject() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("        Subject:"),
            "OpenSSL format must have Subject field"
        );
    }

    #[test]
    fn test_openssl_format_has_public_key_info() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("        Subject Public Key Info:\n"),
            "OpenSSL format must have Subject Public Key Info section"
        );
        assert!(
            output.contains("            Public Key Algorithm:"),
            "Must have Public Key Algorithm"
        );
    }

    #[test]
    fn test_openssl_format_has_extensions() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("        X509v3 extensions:\n"),
            "OpenSSL format must have X509v3 extensions section"
        );
    }

    #[test]
    fn test_openssl_format_has_key_usage() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("            X509v3 Key Usage:"),
            "Must show X509v3 Key Usage"
        );
    }

    #[test]
    fn test_openssl_format_has_trailing_signature() {
        let mut cert = make_cert();
        cert.signature_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("    Signature Algorithm:"),
            "OpenSSL format must have trailing Signature Algorithm"
        );
        assert!(
            output.contains("         de:ad:be:ef"),
            "OpenSSL format must have hex signature value"
        );
    }

    #[test]
    fn test_openssl_format_has_fingerprints() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("SHA-256 Fingerprint="),
            "OpenSSL format must show SHA-256 fingerprint"
        );
    }

    #[test]
    fn test_openssl_format_has_pki_extensions() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("--- PKI Client Extensions ---"),
            "Must have PKI Client Extensions separator"
        );
        assert!(output.contains("    Lifetime:"), "Must have Lifetime bar");
        assert!(output.contains("    Trust:"), "Must have Trust chain info");
    }

    #[test]
    fn test_openssl_format_lifetime_bar_shows_progress() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        // The lifetime bar should contain block characters
        let lifetime_line = output.lines().find(|l| l.contains("Lifetime:")).unwrap();
        assert!(
            lifetime_line.contains('[') && lifetime_line.contains(']'),
            "Lifetime bar must use [brackets]: {lifetime_line}"
        );
        assert!(
            lifetime_line.contains('%'),
            "Lifetime bar must show percentage: {lifetime_line}"
        );
    }

    #[test]
    fn test_openssl_format_colored_has_ansi() {
        colored::control::set_override(true);
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, true);
        colored::control::unset_override();
        assert!(
            output.contains('\x1b'),
            "Colored OpenSSL format must contain ANSI escape codes"
        );
    }

    #[test]
    fn test_openssl_format_plain_has_no_ansi() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            !output.contains('\x1b'),
            "Plain OpenSSL format must NOT contain ANSI escape codes"
        );
    }

    #[test]
    fn test_openssl_format_san_entries() {
        let cert = make_cert();
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(
            output.contains("X509v3 Subject Alternative Name:"),
            "Must show SAN section"
        );
        assert!(
            output.contains("DNS:test.example.com"),
            "Must show DNS SAN entries"
        );
    }

    #[test]
    fn test_openssl_format_ca_cert() {
        let mut cert = make_cert();
        cert.is_ca = true;
        cert.basic_constraints_critical = true;
        cert.path_length = 0;
        cert.key_usage = vec!["Certificate Sign".to_string(), "CRL Sign".to_string()];
        let output = CertFormatter::format_openssl(&cert, false);
        assert!(output.contains("CA:TRUE"), "CA cert must show CA:TRUE");
    }
}
