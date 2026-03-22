//! Certificate linting - checks for common issues and best practices.

use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};

/// Severity level for lint findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LintSeverity {
    /// Informational - not a problem.
    Info,
    /// Warning - should be addressed.
    Warning,
    /// Error - security issue.
    Error,
    /// Critical - severe security issue.
    Critical,
}

impl std::fmt::Display for LintSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Result of a lint check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LintResult {
    /// Lint rule ID.
    pub rule_id: String,
    /// Severity level.
    pub severity: LintSeverity,
    /// Human-readable message.
    pub message: String,
    /// Which certificate (by position) this applies to.
    pub cert_index: Option<usize>,
    /// Additional details.
    pub details: Option<String>,
}

/// Certificate linter.
#[derive(Debug, Default)]
pub struct CertLinter {
    /// Skip informational findings.
    skip_info: bool,
    /// Custom rules to skip.
    skip_rules: Vec<String>,
}

impl CertLinter {
    /// Create a new certificate linter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            skip_info: false,
            skip_rules: Vec::new(),
        }
    }

    /// Skip informational findings.
    #[must_use]
    pub fn skip_info(mut self) -> Self {
        self.skip_info = true;
        self
    }

    /// Skip specific rules.
    #[must_use]
    pub fn skip_rules(mut self, rules: Vec<String>) -> Self {
        self.skip_rules = rules;
        self
    }

    /// Lint a certificate chain.
    #[must_use]
    pub fn lint_chain(&self, certs: &[Vec<u8>]) -> Vec<LintResult> {
        let mut results = Vec::new();

        for (i, cert_der) in certs.iter().enumerate() {
            let cert_results = self.lint_cert(cert_der, i);
            results.extend(cert_results);
        }

        // Chain-level checks
        results.extend(self.lint_chain_structure(certs));

        // Filter results
        results.retain(|r| {
            if self.skip_info && r.severity == LintSeverity::Info {
                return false;
            }
            if self.skip_rules.contains(&r.rule_id) {
                return false;
            }
            true
        });

        results
    }

    /// Lint a single certificate.
    fn lint_cert(&self, cert_der: &[u8], index: usize) -> Vec<LintResult> {
        let mut results = Vec::new();

        let cert = match x509_parser::parse_x509_certificate(cert_der) {
            Ok((_, c)) => c,
            Err(e) => {
                results.push(LintResult {
                    rule_id: "PARSE_ERROR".to_string(),
                    severity: LintSeverity::Critical,
                    message: format!("Failed to parse certificate: {e}"),
                    cert_index: Some(index),
                    details: None,
                });
                return results;
            }
        };

        // Check validity period
        results.extend(self.check_validity(&cert, index));

        // Check key strength
        results.extend(self.check_key_strength(&cert, index));

        // Check signature algorithm
        results.extend(self.check_signature_algorithm(&cert, index));

        // Check extensions
        results.extend(self.check_extensions(&cert, index));

        // Check subject/issuer
        results.extend(self.check_naming(&cert, index));

        results
    }

    /// Check certificate validity period.
    #[allow(clippy::unused_self)]
    fn check_validity(
        &self,
        cert: &x509_parser::certificate::X509Certificate,
        index: usize,
    ) -> Vec<LintResult> {
        let mut results = Vec::new();

        let not_before = Utc
            .timestamp_opt(cert.validity.not_before.timestamp(), 0)
            .single()
            .unwrap_or_else(Utc::now);

        let not_after = Utc
            .timestamp_opt(cert.validity.not_after.timestamp(), 0)
            .single()
            .unwrap_or_else(Utc::now);

        let now = Utc::now();

        // Check if expired
        if now > not_after {
            results.push(LintResult {
                rule_id: "CERT_EXPIRED".to_string(),
                severity: LintSeverity::Critical,
                message: format!("Certificate expired on {}", not_after.format("%Y-%m-%d")),
                cert_index: Some(index),
                details: None,
            });
        }

        // Check if not yet valid
        if now < not_before {
            results.push(LintResult {
                rule_id: "CERT_NOT_YET_VALID".to_string(),
                severity: LintSeverity::Error,
                message: format!(
                    "Certificate not valid until {}",
                    not_before.format("%Y-%m-%d")
                ),
                cert_index: Some(index),
                details: None,
            });
        }

        // Check if expiring soon (30 days)
        let days_until = (not_after - now).num_days();
        if days_until > 0 && days_until < 30 {
            results.push(LintResult {
                rule_id: "CERT_EXPIRING_SOON".to_string(),
                severity: LintSeverity::Warning,
                message: format!("Certificate expires in {days_until} days"),
                cert_index: Some(index),
                details: None,
            });
        }

        // Check lifetime percentage (70% threshold for renewal)
        #[allow(clippy::cast_precision_loss)]
        let total_lifetime = (not_after - not_before).num_seconds() as f64;
        if total_lifetime > 0.0 {
            #[allow(clippy::cast_precision_loss)]
            let elapsed = (now - not_before).num_seconds() as f64;
            let lifetime_pct = (elapsed / total_lifetime * 100.0).clamp(0.0, 100.0);
            if lifetime_pct >= 70.0 && days_until >= 30 {
                results.push(LintResult {
                    rule_id: "CERT_RENEWAL_THRESHOLD".to_string(),
                    severity: LintSeverity::Info,
                    message: format!(
                        "Certificate is {lifetime_pct:.0}% through its lifetime - consider renewal"
                    ),
                    cert_index: Some(index),
                    details: Some(
                        "Industry best practice is to renew certificates at 70% of lifetime"
                            .to_string(),
                    ),
                });
            }
        }

        // Check validity period length (leaf certs should be max 398 days per CA/B Forum)
        let validity_days = (not_after - not_before).num_days();
        let is_ca_cert = cert
            .basic_constraints()
            .ok()
            .and_then(|bc| bc.map(|e| e.value.ca))
            .unwrap_or(false);
        if index == 0 && !is_ca_cert && validity_days > 398 {
            results.push(LintResult {
                rule_id: "VALIDITY_TOO_LONG".to_string(),
                severity: LintSeverity::Warning,
                message: format!(
                    "Validity period ({validity_days} days) exceeds 398-day recommendation"
                ),
                cert_index: Some(index),
                details: Some(
                    "CA/Browser Forum requires max 398-day validity for leaf certs".to_string(),
                ),
            });
        }

        results
    }

    /// Check key strength.
    #[allow(clippy::unused_self)]
    fn check_key_strength(
        &self,
        cert: &x509_parser::certificate::X509Certificate,
        index: usize,
    ) -> Vec<LintResult> {
        let mut results = Vec::new();

        let algo = cert.public_key().algorithm.algorithm.to_string();
        let key_bits = crate::parse_rsa_modulus_bits(&cert.public_key().subject_public_key.data);

        // RSA key checks
        if algo == "1.2.840.113549.1.1.1" {
            if key_bits < 2048 {
                results.push(LintResult {
                    rule_id: "WEAK_RSA_KEY".to_string(),
                    severity: LintSeverity::Critical,
                    message: format!("RSA key size ({key_bits} bits) is below 2048-bit minimum"),
                    cert_index: Some(index),
                    details: Some("NIST requires minimum 2048-bit RSA keys".to_string()),
                });
            } else if key_bits < 3072 {
                results.push(LintResult {
                    rule_id: "RSA_KEY_TRANSITIONING".to_string(),
                    severity: LintSeverity::Info,
                    message: format!(
                        "RSA key size ({key_bits} bits) - consider upgrading to 3072+ bits"
                    ),
                    cert_index: Some(index),
                    details: Some(
                        "NIST recommends 3072-bit RSA for security beyond 2030".to_string(),
                    ),
                });
            }
        }

        // EC key checks
        if algo == "1.2.840.10045.2.1" {
            // Check curve
            if let Some(params) = &cert.public_key().algorithm.parameters {
                let params_str = format!("{params:?}");
                if params_str.contains("secp192") || params_str.contains("prime192") {
                    results.push(LintResult {
                        rule_id: "WEAK_EC_CURVE".to_string(),
                        severity: LintSeverity::Critical,
                        message: "EC key uses weak P-192 curve".to_string(),
                        cert_index: Some(index),
                        details: Some("Use P-256, P-384, or P-521".to_string()),
                    });
                }
            }
        }

        results
    }

    /// Check signature algorithm.
    #[allow(clippy::unused_self)]
    fn check_signature_algorithm(
        &self,
        cert: &x509_parser::certificate::X509Certificate,
        index: usize,
    ) -> Vec<LintResult> {
        let mut results = Vec::new();

        let sig_algo = cert.signature_algorithm.algorithm.to_string();

        // Check for SHA-1
        // sha1WithRSAEncryption: 1.2.840.113549.1.1.5
        // ecdsa-with-SHA1: 1.2.840.10045.4.1
        if sig_algo == "1.2.840.113549.1.1.5" || sig_algo == "1.2.840.10045.4.1" {
            results.push(LintResult {
                rule_id: "SHA1_SIGNATURE".to_string(),
                severity: LintSeverity::Critical,
                message: "Certificate uses deprecated SHA-1 signature".to_string(),
                cert_index: Some(index),
                details: Some(
                    "SHA-1 is cryptographically broken - use SHA-256 or better".to_string(),
                ),
            });
        }

        // Check for MD5
        // md5WithRSAEncryption: 1.2.840.113549.1.1.4
        if sig_algo == "1.2.840.113549.1.1.4" {
            results.push(LintResult {
                rule_id: "MD5_SIGNATURE".to_string(),
                severity: LintSeverity::Critical,
                message: "Certificate uses broken MD5 signature".to_string(),
                cert_index: Some(index),
                details: Some(
                    "MD5 is completely broken - immediate replacement required".to_string(),
                ),
            });
        }

        results
    }

    /// Check certificate extensions.
    #[allow(clippy::unused_self)]
    fn check_extensions(
        &self,
        cert: &x509_parser::certificate::X509Certificate,
        index: usize,
    ) -> Vec<LintResult> {
        let mut results = Vec::new();

        // Check for Basic Constraints on CA certs
        let is_ca = cert
            .basic_constraints()
            .ok()
            .and_then(|bc| bc.map(|e| e.value.ca))
            .unwrap_or(false);

        if is_ca && cert.basic_constraints().is_err() {
            results.push(LintResult {
                rule_id: "CA_MISSING_BASIC_CONSTRAINTS".to_string(),
                severity: LintSeverity::Error,
                message: "CA certificate missing Basic Constraints extension".to_string(),
                cert_index: Some(index),
                details: None,
            });
        }

        // Check leaf cert has SAN (skip CA certs — they don't need SANs)
        if index == 0 && !is_ca && cert.subject_alternative_name().ok().flatten().is_none() {
            results.push(LintResult {
                rule_id: "MISSING_SAN".to_string(),
                severity: LintSeverity::Warning,
                message: "Leaf certificate missing Subject Alternative Name".to_string(),
                cert_index: Some(index),
                details: Some("Modern browsers require SAN extension".to_string()),
            });
        }

        // Check Key Usage
        if let Ok(Some(ku)) = cert.key_usage() {
            if is_ca && !ku.value.key_cert_sign() {
                results.push(LintResult {
                    rule_id: "CA_KEY_USAGE_MISSING_CERT_SIGN".to_string(),
                    severity: LintSeverity::Error,
                    message: "CA certificate Key Usage missing keyCertSign".to_string(),
                    cert_index: Some(index),
                    details: None,
                });
            }
        }

        results
    }

    /// Check naming conventions.
    #[allow(clippy::unused_self)]
    fn check_naming(
        &self,
        cert: &x509_parser::certificate::X509Certificate,
        index: usize,
    ) -> Vec<LintResult> {
        let mut results = Vec::new();

        // Check for empty subject
        if cert.subject.iter().count() == 0 {
            results.push(LintResult {
                rule_id: "EMPTY_SUBJECT".to_string(),
                severity: LintSeverity::Warning,
                message: "Certificate has empty subject".to_string(),
                cert_index: Some(index),
                details: Some("Subject should identify the certificate holder".to_string()),
            });
        }

        // Check for wildcard in wrong position
        let subject_str = cert.subject.to_string();
        if subject_str.contains("*.*.") {
            results.push(LintResult {
                rule_id: "INVALID_WILDCARD".to_string(),
                severity: LintSeverity::Error,
                message: "Multi-level wildcard in subject".to_string(),
                cert_index: Some(index),
                details: Some("Wildcards should only be in leftmost position".to_string()),
            });
        }

        results
    }

    /// Lint chain structure.
    #[allow(clippy::unused_self)]
    fn lint_chain_structure(&self, certs: &[Vec<u8>]) -> Vec<LintResult> {
        let mut results = Vec::new();

        if certs.is_empty() {
            results.push(LintResult {
                rule_id: "EMPTY_CHAIN".to_string(),
                severity: LintSeverity::Critical,
                message: "No certificates in chain".to_string(),
                cert_index: None,
                details: None,
            });
            return results;
        }

        // Check chain order
        for i in 0..certs.len().saturating_sub(1) {
            if let (Ok((_, cert)), Ok((_, issuer))) = (
                x509_parser::parse_x509_certificate(&certs[i]),
                x509_parser::parse_x509_certificate(&certs[i + 1]),
            ) {
                if cert.issuer != issuer.subject {
                    results.push(LintResult {
                        rule_id: "CHAIN_ORDER_INVALID".to_string(),
                        severity: LintSeverity::Error,
                        message: format!(
                            "Certificate {} issuer doesn't match certificate {} subject",
                            i,
                            i + 1
                        ),
                        cert_index: Some(i),
                        details: Some("Chain should be ordered from leaf to root".to_string()),
                    });
                }
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lint_severity_display() {
        assert_eq!(LintSeverity::Info.to_string(), "INFO");
        assert_eq!(LintSeverity::Warning.to_string(), "WARN");
        assert_eq!(LintSeverity::Error.to_string(), "ERROR");
        assert_eq!(LintSeverity::Critical.to_string(), "CRITICAL");
    }

    #[test]
    fn test_linter_builder() {
        let linter = CertLinter::new()
            .skip_info()
            .skip_rules(vec!["RULE1".to_string()]);

        assert!(linter.skip_info);
        assert_eq!(linter.skip_rules, vec!["RULE1".to_string()]);
    }

    #[test]
    fn test_linter_default() {
        let linter = CertLinter::default();
        assert!(!linter.skip_info);
        assert!(linter.skip_rules.is_empty());
    }

    #[test]
    fn test_lint_empty_chain() {
        let linter = CertLinter::new();
        let results = linter.lint_chain(&[]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].rule_id, "EMPTY_CHAIN");
        assert_eq!(results[0].severity, LintSeverity::Critical);
        assert!(results[0].cert_index.is_none());
    }

    #[test]
    fn test_lint_invalid_cert_der() {
        let linter = CertLinter::new();
        let results = linter.lint_chain(&[vec![0x00, 0x01, 0x02]]);
        assert!(results.iter().any(|r| r.rule_id == "PARSE_ERROR"));
        assert!(results.iter().any(|r| r.severity == LintSeverity::Critical));
    }

    #[test]
    fn test_lint_severity_ordering() {
        // Verify all severity levels can be compared
        assert_ne!(LintSeverity::Info, LintSeverity::Warning);
        assert_ne!(LintSeverity::Warning, LintSeverity::Error);
        assert_ne!(LintSeverity::Error, LintSeverity::Critical);
        assert_eq!(LintSeverity::Info, LintSeverity::Info);
    }

    #[test]
    fn test_lint_result_fields() {
        let result = LintResult {
            rule_id: "TEST_RULE".to_string(),
            severity: LintSeverity::Warning,
            message: "Test message".to_string(),
            cert_index: Some(0),
            details: Some("Extra info".to_string()),
        };

        assert_eq!(result.rule_id, "TEST_RULE");
        assert_eq!(result.severity, LintSeverity::Warning);
        assert_eq!(result.cert_index, Some(0));
        assert_eq!(result.details.as_deref(), Some("Extra info"));
    }

    #[test]
    fn test_lint_skip_info_filtering() {
        let linter = CertLinter::new().skip_info();
        // Empty chain produces a Critical result, not Info, so it should survive filtering
        let results = linter.lint_chain(&[]);
        assert!(results.iter().all(|r| r.severity != LintSeverity::Info));
    }

    #[test]
    fn test_lint_skip_rules_filtering() {
        let linter = CertLinter::new().skip_rules(vec!["EMPTY_CHAIN".to_string()]);
        let results = linter.lint_chain(&[]);
        assert!(!results.iter().any(|r| r.rule_id == "EMPTY_CHAIN"));
    }

    #[test]
    fn test_severity_serde_roundtrip() {
        let severities = [
            LintSeverity::Info,
            LintSeverity::Warning,
            LintSeverity::Error,
            LintSeverity::Critical,
        ];
        for sev in severities {
            let json = serde_json::to_string(&sev).unwrap();
            let restored: LintSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, sev);
        }
    }
}
