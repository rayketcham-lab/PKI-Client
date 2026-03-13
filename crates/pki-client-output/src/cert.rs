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
                "TLS Web Server Authentication" | "Server Authentication" => {
                    if !purposes.contains(&"Server") {
                        purposes.push("Server");
                    }
                }
                "TLS Web Client Authentication" | "Client Authentication" => {
                    if !purposes.contains(&"Client") {
                        purposes.push("Client");
                    }
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
        } else {
            "".normal()
        };

        output.push_str(&format!(
            "            Algorithm: {} ({} bit) {} ({})\n",
            cert.key_algorithm_name.cyan(),
            cert.key_size,
            key_strength,
            cert.key_algorithm.dimmed()
        ));

        if let Some(ref curve) = cert.ec_curve {
            output.push_str(&format!("            Curve: {}\n", curve.green()));
        }

        // RSA Modulus and Exponent
        if cert.key_algorithm_name == "RSA" {
            if let Some(ref modulus) = cert.rsa_modulus {
                output.push_str(&format!("            {}:\n", "Modulus".dimmed()));
                // Format modulus in wrapped lines
                for chunk in modulus.as_bytes().chunks(64) {
                    let line = std::str::from_utf8(chunk).unwrap_or("");
                    output.push_str(&format!("                {}\n", line.dimmed()));
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

        output
    }

    /// Convert policy OIDs to human-readable names (uses OID registry).
    fn policy_oid_to_name(oid: &str) -> String {
        oid_registry::policy_name(oid)
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
        output.push_str(&format!(
            "            Algorithm: {} ({} bit)\n",
            cert.key_algorithm_name, cert.key_size
        ));

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
}
