//! Compliance Validator for FIPS 140-3, NIST SP 800-57, and FBCA Requirements
//!
//! Validates CA configurations and certificate hierarchies against the
//! requirements defined by the security level framework. This module
//! generates compliance reports that can be used for:
//!
//! - Pre-deployment validation (before submitting for cross-certification)
//! - Ongoing compliance monitoring (scheduled checks)
//! - Audit evidence (compliance report generation)
//!
//! ## Checked Requirements
//!
//! | Category | Checks |
//! |----------|--------|
//! | Algorithm | FIPS-approved algorithms, minimum key sizes |
//! | Key Protection | Software vs hardware, FIPS module level |
//! | Validity | CA and EE cert max lifetimes |
//! | Revocation | CRL interval, OCSP availability |
//! | Policy | Certificate policy OIDs, policy mappings |
//! | Operational | Dual control, audit logging, key attestation |
//!
//! ## References
//!
//! - NIST SP 800-57 Part 1 Rev 5 (Key Management)
//! - NIST SP 800-131A Rev 2 (Algorithm Transitions)
//! - FIPS 140-3 (Cryptographic Module Security)
//! - NIST SP 800-89 (Recommendation for Obtaining Assurances for Digital Signature Applications)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::security_level::{KeyProtection, LevelRequirements, SecurityLevel};
use crate::algo::AlgorithmId;
use crate::key_lifecycle::{KeyLifecycleTracker, KeyState};

/// A single compliance finding (pass, fail, or warning).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    /// Category of the finding.
    pub category: ComplianceCategory,

    /// Severity of the finding.
    pub severity: FindingSeverity,

    /// Short identifier (e.g., "FIPS-ALG-001").
    pub code: String,

    /// Human-readable title.
    pub title: String,

    /// Detailed description of what was checked and the result.
    pub detail: String,

    /// The requirement reference (e.g., "NIST SP 800-131A Rev 2 §3").
    pub reference: String,

    /// Remediation guidance (for failures/warnings).
    pub remediation: Option<String>,
}

/// Category of compliance check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceCategory {
    /// Algorithm and key size requirements.
    Algorithm,
    /// Key storage and protection.
    KeyProtection,
    /// Certificate validity periods.
    Validity,
    /// Revocation services (CRL, OCSP).
    Revocation,
    /// Certificate policy extensions.
    Policy,
    /// Operational controls (dual control, audit).
    Operational,
}

impl ComplianceCategory {
    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Algorithm => "Algorithm & Key Size",
            Self::KeyProtection => "Key Protection",
            Self::Validity => "Validity Period",
            Self::Revocation => "Revocation Services",
            Self::Policy => "Certificate Policy",
            Self::Operational => "Operational Controls",
        }
    }
}

impl std::fmt::Display for ComplianceCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Severity of a compliance finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    /// Requirement met.
    Pass,
    /// Not a hard failure but should be addressed.
    Warning,
    /// Requirement not met — blocks compliance.
    Fail,
}

impl FindingSeverity {
    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warning => "WARNING",
            Self::Fail => "FAIL",
        }
    }
}

impl std::fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// A compliance report aggregating all findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// The security level being validated against.
    pub target_level: SecurityLevel,

    /// When the report was generated.
    pub generated_at: DateTime<Utc>,

    /// All findings from the compliance check.
    pub findings: Vec<ComplianceFinding>,

    /// Overall compliance status.
    pub compliant: bool,

    /// Summary counts.
    pub pass_count: u32,
    pub warning_count: u32,
    pub fail_count: u32,
}

impl ComplianceReport {
    /// Create a new empty report.
    fn new(target_level: SecurityLevel) -> Self {
        Self {
            target_level,
            generated_at: Utc::now(),
            findings: Vec::new(),
            compliant: true,
            pass_count: 0,
            warning_count: 0,
            fail_count: 0,
        }
    }

    /// Add a finding to the report.
    fn add_finding(&mut self, finding: ComplianceFinding) {
        match finding.severity {
            FindingSeverity::Pass => self.pass_count += 1,
            FindingSeverity::Warning => self.warning_count += 1,
            FindingSeverity::Fail => {
                self.fail_count += 1;
                self.compliant = false;
            }
        }
        self.findings.push(finding);
    }

    /// Get findings by category.
    pub fn findings_by_category(&self, category: ComplianceCategory) -> Vec<&ComplianceFinding> {
        self.findings
            .iter()
            .filter(|f| f.category == category)
            .collect()
    }

    /// Get only failures.
    pub fn failures(&self) -> Vec<&ComplianceFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Fail)
            .collect()
    }

    /// Get only warnings.
    pub fn warnings(&self) -> Vec<&ComplianceFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Warning)
            .collect()
    }

    /// Format a text summary of the report.
    pub fn summary(&self) -> String {
        let status = if self.compliant {
            "COMPLIANT"
        } else {
            "NON-COMPLIANT"
        };
        format!(
            "Compliance Report — {} ({})\n\
             Target: {}\n\
             Generated: {}\n\
             Results: {} pass, {} warning, {} fail\n\
             Status: {}",
            self.target_level,
            self.target_level.numeric(),
            self.target_level.name(),
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            self.pass_count,
            self.warning_count,
            self.fail_count,
            status,
        )
    }
}

/// Input describing a CA's configuration for compliance validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaComplianceInput {
    /// Algorithm used for the CA signing key.
    pub algorithm: AlgorithmId,

    /// Key protection mechanism in use.
    pub key_protection: KeyProtection,

    /// CA certificate validity period (days).
    pub ca_validity_days: u32,

    /// Maximum end-entity certificate validity issued by this CA (days).
    pub max_ee_validity_days: u32,

    /// Whether CRL generation is automated.
    pub automated_crl: bool,

    /// CRL publication interval (hours). 0 if not configured.
    pub crl_interval_hours: u32,

    /// Whether OCSP responder is available.
    pub ocsp_available: bool,

    /// Whether crypto operations are audit-logged.
    pub crypto_audit_enabled: bool,

    /// Whether key attestation was obtained.
    pub key_attestation_present: bool,

    /// Whether dual control is enforced for key operations.
    pub dual_control_enabled: bool,

    /// Certificate policy OIDs asserted in the CA certificate.
    pub certificate_policy_oids: Vec<String>,

    /// Key lifecycle tracker (SP 800-57 key state and cryptoperiod).
    /// When present, compliance checks validate key state, cryptoperiod enforcement,
    /// and hardware key destruction requirements at Level 3+.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key_lifecycle: Option<KeyLifecycleTracker>,
}

/// Run compliance validation against a security level.
///
/// Returns a detailed compliance report with all findings.
pub fn validate_compliance(
    input: &CaComplianceInput,
    target_level: SecurityLevel,
) -> ComplianceReport {
    let requirements = LevelRequirements::for_level(target_level);
    let mut report = ComplianceReport::new(target_level);

    check_algorithm(&input.algorithm, &requirements, &mut report);
    check_key_protection(&input.key_protection, &requirements, &mut report);
    check_validity(input, &requirements, &mut report);
    check_revocation(input, &requirements, &mut report);
    check_policy(input, &requirements, &mut report);
    check_operational(input, &requirements, &mut report);
    check_key_lifecycle(input, target_level, &mut report);

    report
}

fn check_key_lifecycle(
    input: &CaComplianceInput,
    target_level: SecurityLevel,
    report: &mut ComplianceReport,
) {
    let tracker = match &input.key_lifecycle {
        Some(t) => t,
        None => {
            // At Level 3+, missing lifecycle tracking is a warning
            if target_level >= SecurityLevel::Level3 {
                report.add_finding(ComplianceFinding {
                    category: ComplianceCategory::Operational,
                    severity: FindingSeverity::Warning,
                    code: "NIST-KLC-001".into(),
                    title: "Key lifecycle tracking".into(),
                    detail: "No key lifecycle tracker configured; SP 800-57 requires \
                             key state tracking at this assurance level"
                        .into(),
                    reference: "NIST SP 800-57 Part 1 Rev 5 §8.2; SP 800-152 §4".into(),
                    remediation: Some(
                        "Enable key lifecycle tracking with KeyLifecycleTracker".into(),
                    ),
                });
            }
            return;
        }
    };

    // KLC-002: Key must be Active for signing operations
    let is_active = tracker.state() == KeyState::Active;
    report.add_finding(ComplianceFinding {
        category: ComplianceCategory::Operational,
        severity: if is_active {
            FindingSeverity::Pass
        } else {
            FindingSeverity::Fail
        },
        code: "NIST-KLC-002".into(),
        title: "Key state is Active for signing".into(),
        detail: format!(
            "Key state: {}. {}",
            tracker.state(),
            if is_active {
                "Key is authorized for signing operations."
            } else {
                "Key is NOT in Active state — signing operations are prohibited."
            }
        ),
        reference: "NIST SP 800-57 Part 1 Rev 5 §8.2".into(),
        remediation: if is_active {
            None
        } else {
            Some(format!(
                "Key is in {} state; transition to Active before signing",
                tracker.state()
            ))
        },
    });

    // KLC-003: Key must be within originator cryptoperiod
    let within_period = tracker.is_within_cryptoperiod();
    report.add_finding(ComplianceFinding {
        category: ComplianceCategory::Operational,
        severity: if within_period {
            FindingSeverity::Pass
        } else if is_active {
            // Active but expired cryptoperiod is a hard fail
            FindingSeverity::Fail
        } else {
            // Not active — already covered by KLC-002
            FindingSeverity::Warning
        },
        code: "NIST-KLC-003".into(),
        title: "Key within originator cryptoperiod".into(),
        detail: format!(
            "Within cryptoperiod: {}. Algorithm: {}",
            within_period,
            tracker.algorithm(),
        ),
        reference: "NIST SP 800-57 Part 1 Rev 5 §5.3".into(),
        remediation: if within_period {
            None
        } else {
            Some("Key has exceeded its originator usage period; rotate to a new key".into())
        },
    });

    // KLC-004: Algorithm strength for current year (SP 800-131A schedule)
    let current_year = Utc::now()
        .format("%Y")
        .to_string()
        .parse::<u32>()
        .unwrap_or(2026);
    let algo_ok =
        crate::key_lifecycle::validate_algorithm_strength(&tracker.algorithm(), current_year)
            .is_ok();
    report.add_finding(ComplianceFinding {
        category: ComplianceCategory::Algorithm,
        severity: if algo_ok {
            FindingSeverity::Pass
        } else {
            FindingSeverity::Fail
        },
        code: "NIST-KLC-004".into(),
        title: "Algorithm strength for current year".into(),
        detail: format!(
            "Algorithm {} {} for year {}",
            tracker.algorithm(),
            if algo_ok {
                "meets strength requirements"
            } else {
                "does NOT meet strength requirements"
            },
            current_year,
        ),
        reference: "NIST SP 800-131A Rev 2 §3".into(),
        remediation: if algo_ok {
            None
        } else {
            Some("Migrate to a stronger algorithm (ECDSA P-256+, RSA-3072+)".into())
        },
    });

    // KLC-005: At Level 3+, hardware key destruction must be feasible
    if target_level >= SecurityLevel::Level3 {
        let has_hardware = matches!(
            input.key_protection,
            KeyProtection::Hardware | KeyProtection::HardwareLevel3
        );
        report.add_finding(ComplianceFinding {
            category: ComplianceCategory::KeyProtection,
            severity: if has_hardware {
                FindingSeverity::Pass
            } else {
                FindingSeverity::Warning
            },
            code: "NIST-KLC-005".into(),
            title: "Hardware key destruction capability".into(),
            detail: format!(
                "Key protection: {}. {}",
                input.key_protection,
                if has_hardware {
                    "Hardware-backed keys support secure destruction."
                } else {
                    "Software keys cannot guarantee secure destruction \
                     (data remanence risk)."
                }
            ),
            reference: "NIST SP 800-57 Part 1 Rev 5 §8.3.4; SP 800-152 §6.7".into(),
            remediation: if has_hardware {
                None
            } else {
                Some("Use hardware key storage (HSM/TPM) for secure key destruction".into())
            },
        });
    }
}

fn check_algorithm(algo: &AlgorithmId, req: &LevelRequirements, report: &mut ComplianceReport) {
    // Check if algorithm is permitted at target level
    let permitted = req.level.is_algorithm_permitted(algo);
    report.add_finding(ComplianceFinding {
        category: ComplianceCategory::Algorithm,
        severity: if permitted {
            FindingSeverity::Pass
        } else {
            FindingSeverity::Fail
        },
        code: "FIPS-ALG-001".into(),
        title: "Algorithm permitted at target level".into(),
        detail: format!(
            "Algorithm {} is {} at {}",
            algo,
            if permitted {
                "permitted"
            } else {
                "NOT permitted"
            },
            req.level,
        ),
        reference: "NIST SP 800-131A Rev 2; FIPS 186-5".into(),
        remediation: if permitted {
            None
        } else {
            Some(format!(
                "Use one of: {:?}",
                req.level.permitted_algorithms()
            ))
        },
    });

    // Check FIPS approval if required
    if req.fips_algorithms_required {
        let fips_approved = crate::fips::is_fips_approved(algo);
        report.add_finding(ComplianceFinding {
            category: ComplianceCategory::Algorithm,
            severity: if fips_approved {
                FindingSeverity::Pass
            } else {
                FindingSeverity::Fail
            },
            code: "FIPS-ALG-002".into(),
            title: "FIPS 140-3 approved algorithm".into(),
            detail: format!(
                "Algorithm {} is {} for FIPS 140-3",
                algo,
                if fips_approved {
                    "approved"
                } else {
                    "NOT approved"
                },
            ),
            reference: "FIPS 140-3; FIPS 186-5; SP 800-131A Rev 2".into(),
            remediation: if fips_approved {
                None
            } else {
                Some("Use ECDSA P-256/P-384, RSA-3072+, or RSA-PSS 3072+".into())
            },
        });
    }
}

fn check_key_protection(
    actual: &KeyProtection,
    req: &LevelRequirements,
    report: &mut ComplianceReport,
) {
    let satisfies = actual.satisfies(&req.key_protection);
    report.add_finding(ComplianceFinding {
        category: ComplianceCategory::KeyProtection,
        severity: if satisfies {
            FindingSeverity::Pass
        } else {
            FindingSeverity::Fail
        },
        code: "FIPS-KEY-001".into(),
        title: "Key protection level".into(),
        detail: format!(
            "Current: {}. Required: {} (FIPS 140-3 Level {}+)",
            actual,
            req.key_protection,
            req.key_protection.min_fips_level(),
        ),
        reference: "FIPS 140-3; NIST SP 800-57 Part 1".into(),
        remediation: if satisfies {
            None
        } else {
            Some(format!("Migrate keys to {} storage", req.key_protection))
        },
    });
}

fn check_validity(
    input: &CaComplianceInput,
    req: &LevelRequirements,
    report: &mut ComplianceReport,
) {
    // CA validity
    let ca_ok = input.ca_validity_days <= req.max_ca_validity_days;
    report.add_finding(ComplianceFinding {
        category: ComplianceCategory::Validity,
        severity: if ca_ok {
            FindingSeverity::Pass
        } else {
            FindingSeverity::Fail
        },
        code: "NIST-VAL-001".into(),
        title: "CA certificate validity period".into(),
        detail: format!(
            "CA validity: {} days (max: {} days)",
            input.ca_validity_days, req.max_ca_validity_days,
        ),
        reference: "NIST SP 800-57 Part 1 Rev 5 §5.3".into(),
        remediation: if ca_ok {
            None
        } else {
            Some(format!(
                "Reduce CA validity to {} days or less",
                req.max_ca_validity_days
            ))
        },
    });

    // EE validity
    let ee_ok = input.max_ee_validity_days <= req.max_ee_validity_days;
    report.add_finding(ComplianceFinding {
        category: ComplianceCategory::Validity,
        severity: if ee_ok {
            FindingSeverity::Pass
        } else if input.max_ee_validity_days <= req.max_ee_validity_days + 30 {
            FindingSeverity::Warning
        } else {
            FindingSeverity::Fail
        },
        code: "NIST-VAL-002".into(),
        title: "End-entity certificate validity period".into(),
        detail: format!(
            "Max EE validity: {} days (max allowed: {} days)",
            input.max_ee_validity_days, req.max_ee_validity_days,
        ),
        reference: "CA/Browser Forum BRs §6.3.2; NIST SP 800-57".into(),
        remediation: if ee_ok {
            None
        } else {
            Some(format!(
                "Reduce max EE validity to {} days",
                req.max_ee_validity_days
            ))
        },
    });
}

fn check_revocation(
    input: &CaComplianceInput,
    req: &LevelRequirements,
    report: &mut ComplianceReport,
) {
    // CRL automation
    if req.automated_crl_required {
        report.add_finding(ComplianceFinding {
            category: ComplianceCategory::Revocation,
            severity: if input.automated_crl {
                FindingSeverity::Pass
            } else {
                FindingSeverity::Fail
            },
            code: "REV-CRL-001".into(),
            title: "Automated CRL generation".into(),
            detail: format!(
                "Automated CRL: {}",
                if input.automated_crl {
                    "enabled"
                } else {
                    "disabled"
                },
            ),
            reference: "RFC 5280 §5; FPKI CP §4.9".into(),
            remediation: if input.automated_crl {
                None
            } else {
                Some("Enable automated CRL generation via scheduler".into())
            },
        });
    }

    // CRL interval
    if req.max_crl_interval_hours > 0 {
        let interval_ok =
            input.crl_interval_hours > 0 && input.crl_interval_hours <= req.max_crl_interval_hours;
        report.add_finding(ComplianceFinding {
            category: ComplianceCategory::Revocation,
            severity: if interval_ok {
                FindingSeverity::Pass
            } else if input.crl_interval_hours == 0 {
                FindingSeverity::Fail
            } else {
                FindingSeverity::Warning
            },
            code: "REV-CRL-002".into(),
            title: "CRL publication interval".into(),
            detail: format!(
                "CRL interval: {} hours (max: {} hours)",
                input.crl_interval_hours, req.max_crl_interval_hours,
            ),
            reference: "FPKI CP §4.9.7; NIST SP 800-57".into(),
            remediation: if interval_ok {
                None
            } else {
                Some(format!(
                    "Set CRL interval to {} hours or less",
                    req.max_crl_interval_hours
                ))
            },
        });
    }

    // OCSP
    if req.ocsp_required {
        report.add_finding(ComplianceFinding {
            category: ComplianceCategory::Revocation,
            severity: if input.ocsp_available {
                FindingSeverity::Pass
            } else {
                FindingSeverity::Fail
            },
            code: "REV-OCSP-001".into(),
            title: "OCSP responder availability".into(),
            detail: format!(
                "OCSP: {}",
                if input.ocsp_available {
                    "available"
                } else {
                    "not available"
                },
            ),
            reference: "RFC 6960; FPKI CP §4.9.9".into(),
            remediation: if input.ocsp_available {
                None
            } else {
                Some("Deploy OCSP responder service".into())
            },
        });
    }
}

fn check_policy(input: &CaComplianceInput, req: &LevelRequirements, report: &mut ComplianceReport) {
    // Check Ogjos policy OID
    let has_ogjos = input
        .certificate_policy_oids
        .contains(&req.ogjos_policy_oid);
    report.add_finding(ComplianceFinding {
        category: ComplianceCategory::Policy,
        severity: if has_ogjos {
            FindingSeverity::Pass
        } else {
            FindingSeverity::Warning
        },
        code: "POL-OID-001".into(),
        title: "SPORK certificate policy OID".into(),
        detail: format!(
            "Expected OID {} in certificate policies. {}",
            req.ogjos_policy_oid,
            if has_ogjos { "Found." } else { "Not found." },
        ),
        reference: "RFC 5280 §4.2.1.4".into(),
        remediation: if has_ogjos {
            None
        } else {
            Some(format!(
                "Add policy OID {} to CA certificate",
                req.ogjos_policy_oid
            ))
        },
    });
}

fn check_operational(
    input: &CaComplianceInput,
    req: &LevelRequirements,
    report: &mut ComplianceReport,
) {
    // Crypto audit
    if req.crypto_audit_required {
        report.add_finding(ComplianceFinding {
            category: ComplianceCategory::Operational,
            severity: if input.crypto_audit_enabled {
                FindingSeverity::Pass
            } else {
                FindingSeverity::Fail
            },
            code: "OPS-AUD-001".into(),
            title: "Cryptographic operation audit logging".into(),
            detail: format!(
                "Crypto audit: {}",
                if input.crypto_audit_enabled {
                    "enabled"
                } else {
                    "disabled"
                },
            ),
            reference: "NIST SP 800-92; FPKI CP §5.4".into(),
            remediation: if input.crypto_audit_enabled {
                None
            } else {
                Some("Enable audit logging for all cryptographic operations".into())
            },
        });
    }

    // Key attestation
    if req.key_attestation_required {
        report.add_finding(ComplianceFinding {
            category: ComplianceCategory::Operational,
            severity: if input.key_attestation_present {
                FindingSeverity::Pass
            } else {
                FindingSeverity::Fail
            },
            code: "OPS-ATT-001".into(),
            title: "Key attestation".into(),
            detail: format!(
                "Key attestation: {}",
                if input.key_attestation_present {
                    "present"
                } else {
                    "not present"
                },
            ),
            reference: "NIST SP 800-57 Part 2 Rev 1; FIPS 140-3 AS".into(),
            remediation: if input.key_attestation_present {
                None
            } else {
                Some("Obtain key attestation from HSM".into())
            },
        });
    }

    // Dual control
    if req.dual_control_required {
        report.add_finding(ComplianceFinding {
            category: ComplianceCategory::Operational,
            severity: if input.dual_control_enabled {
                FindingSeverity::Pass
            } else {
                FindingSeverity::Fail
            },
            code: "OPS-DC-001".into(),
            title: "Dual control for key operations".into(),
            detail: format!(
                "Dual control: {}",
                if input.dual_control_enabled {
                    "enforced"
                } else {
                    "not enforced"
                },
            ),
            reference: "NIST SP 800-57 Part 2 Rev 1 §6.1; FPKI CP §6.2.2".into(),
            remediation: if input.dual_control_enabled {
                None
            } else {
                Some("Enable dual-control (multi-custodian) for CA key operations".into())
            },
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compliant_level2_input() -> CaComplianceInput {
        CaComplianceInput {
            algorithm: AlgorithmId::EcdsaP384,
            key_protection: KeyProtection::Software,
            ca_validity_days: 3650,
            max_ee_validity_days: 397,
            automated_crl: true,
            crl_interval_hours: 12,
            ocsp_available: true,
            crypto_audit_enabled: true,
            key_attestation_present: false,
            dual_control_enabled: false,
            certificate_policy_oids: vec![
                "1.3.6.1.4.1.56266.1.1.3".to_string(), // id-ogjos-cp-medium
            ],
            key_lifecycle: None,
        }
    }

    fn compliant_level3_input() -> CaComplianceInput {
        CaComplianceInput {
            algorithm: AlgorithmId::EcdsaP384,
            key_protection: KeyProtection::Hardware,
            ca_validity_days: 7300,
            max_ee_validity_days: 397,
            automated_crl: true,
            crl_interval_hours: 12,
            ocsp_available: true,
            crypto_audit_enabled: true,
            key_attestation_present: false,
            dual_control_enabled: false,
            certificate_policy_oids: vec![
                "1.3.6.1.4.1.56266.1.1.4".to_string(), // id-ogjos-cp-medium-hardware
            ],
            key_lifecycle: None,
        }
    }

    fn compliant_level4_input() -> CaComplianceInput {
        CaComplianceInput {
            algorithm: AlgorithmId::EcdsaP384,
            key_protection: KeyProtection::HardwareLevel3,
            ca_validity_days: 7300,
            max_ee_validity_days: 397,
            automated_crl: true,
            crl_interval_hours: 6,
            ocsp_available: true,
            crypto_audit_enabled: true,
            key_attestation_present: true,
            dual_control_enabled: true,
            certificate_policy_oids: vec![
                "1.3.6.1.4.1.56266.1.1.5".to_string(), // id-ogjos-cp-high
            ],
            key_lifecycle: None,
        }
    }

    // ---- Level 2 compliance ----

    #[test]
    fn test_level2_fully_compliant() {
        let input = compliant_level2_input();
        let report = validate_compliance(&input, SecurityLevel::Level2);
        assert!(
            report.compliant,
            "Should be compliant: {}",
            report.summary()
        );
        assert_eq!(report.fail_count, 0);
    }

    #[test]
    fn test_level2_bad_algorithm() {
        let mut input = compliant_level2_input();
        input.algorithm = AlgorithmId::Rsa2048;
        let report = validate_compliance(&input, SecurityLevel::Level2);
        assert!(!report.compliant);
        assert!(report.fail_count >= 1);
        let failures = report.failures();
        assert!(failures.iter().any(|f| f.code == "FIPS-ALG-001"));
    }

    #[test]
    fn test_level2_no_ocsp() {
        let mut input = compliant_level2_input();
        input.ocsp_available = false;
        let report = validate_compliance(&input, SecurityLevel::Level2);
        assert!(!report.compliant);
        let failures = report.failures();
        assert!(failures.iter().any(|f| f.code == "REV-OCSP-001"));
    }

    #[test]
    fn test_level2_no_crl_automation() {
        let mut input = compliant_level2_input();
        input.automated_crl = false;
        let report = validate_compliance(&input, SecurityLevel::Level2);
        assert!(!report.compliant);
        let failures = report.failures();
        assert!(failures.iter().any(|f| f.code == "REV-CRL-001"));
    }

    #[test]
    fn test_level2_ee_validity_too_long() {
        let mut input = compliant_level2_input();
        input.max_ee_validity_days = 825;
        let report = validate_compliance(&input, SecurityLevel::Level2);
        // Should fail (825 >> 397 + 30)
        assert!(!report.compliant);
    }

    #[test]
    fn test_level2_no_audit() {
        let mut input = compliant_level2_input();
        input.crypto_audit_enabled = false;
        let report = validate_compliance(&input, SecurityLevel::Level2);
        assert!(!report.compliant);
        let failures = report.failures();
        assert!(failures.iter().any(|f| f.code == "OPS-AUD-001"));
    }

    // ---- Level 3 compliance ----

    #[test]
    fn test_level3_fully_compliant() {
        let input = compliant_level3_input();
        let report = validate_compliance(&input, SecurityLevel::Level3);
        assert!(
            report.compliant,
            "Should be compliant: {}",
            report.summary()
        );
        assert_eq!(report.fail_count, 0);
    }

    #[test]
    fn test_level3_software_keys_fail() {
        let mut input = compliant_level3_input();
        input.key_protection = KeyProtection::Software;
        let report = validate_compliance(&input, SecurityLevel::Level3);
        assert!(!report.compliant);
        let failures = report.failures();
        assert!(failures.iter().any(|f| f.code == "FIPS-KEY-001"));
    }

    // ---- Level 4 compliance ----

    #[test]
    fn test_level4_fully_compliant() {
        let input = compliant_level4_input();
        let report = validate_compliance(&input, SecurityLevel::Level4);
        assert!(
            report.compliant,
            "Should be compliant: {}",
            report.summary()
        );
        assert_eq!(report.fail_count, 0);
    }

    #[test]
    fn test_level4_no_attestation() {
        let mut input = compliant_level4_input();
        input.key_attestation_present = false;
        let report = validate_compliance(&input, SecurityLevel::Level4);
        assert!(!report.compliant);
        let failures = report.failures();
        assert!(failures.iter().any(|f| f.code == "OPS-ATT-001"));
    }

    #[test]
    fn test_level4_no_dual_control() {
        let mut input = compliant_level4_input();
        input.dual_control_enabled = false;
        let report = validate_compliance(&input, SecurityLevel::Level4);
        assert!(!report.compliant);
        let failures = report.failures();
        assert!(failures.iter().any(|f| f.code == "OPS-DC-001"));
    }

    #[test]
    fn test_level4_hardware_l2_fails() {
        let mut input = compliant_level4_input();
        input.key_protection = KeyProtection::Hardware; // L2, need L3
        let report = validate_compliance(&input, SecurityLevel::Level4);
        assert!(!report.compliant);
    }

    #[test]
    fn test_level4_p256_fails() {
        let mut input = compliant_level4_input();
        input.algorithm = AlgorithmId::EcdsaP256; // Not permitted at L4
        let report = validate_compliance(&input, SecurityLevel::Level4);
        assert!(!report.compliant);
    }

    #[test]
    fn test_level4_crl_interval_too_long() {
        let mut input = compliant_level4_input();
        input.crl_interval_hours = 24; // Max 6
        let report = validate_compliance(&input, SecurityLevel::Level4);
        // Should be warning (not fatal for interval)
        assert!(report.warning_count > 0 || report.fail_count > 0);
    }

    // ---- Level 1 is permissive ----

    #[test]
    fn test_level1_minimal_passes() {
        let input = CaComplianceInput {
            algorithm: AlgorithmId::Rsa2048,
            key_protection: KeyProtection::Software,
            ca_validity_days: 3650,
            max_ee_validity_days: 825,
            automated_crl: false,
            crl_interval_hours: 0,
            ocsp_available: false,
            crypto_audit_enabled: false,
            key_attestation_present: false,
            dual_control_enabled: false,
            certificate_policy_oids: vec!["1.3.6.1.4.1.56266.1.1.1".to_string()],
            key_lifecycle: None,
        };
        let report = validate_compliance(&input, SecurityLevel::Level1);
        assert!(report.compliant, "Level 1 should pass with minimal config");
    }

    // ---- Report methods ----

    #[test]
    fn test_report_summary_format() {
        let input = compliant_level2_input();
        let report = validate_compliance(&input, SecurityLevel::Level2);
        let summary = report.summary();
        assert!(summary.contains("COMPLIANT"));
        assert!(summary.contains("Level 2"));
    }

    #[test]
    fn test_report_findings_by_category() {
        let input = compliant_level2_input();
        let report = validate_compliance(&input, SecurityLevel::Level2);
        let algo_findings = report.findings_by_category(ComplianceCategory::Algorithm);
        assert!(!algo_findings.is_empty());
    }

    #[test]
    fn test_report_serde_roundtrip() {
        let input = compliant_level2_input();
        let report = validate_compliance(&input, SecurityLevel::Level2);
        let json = serde_json::to_string(&report).unwrap();
        let restored: ComplianceReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.compliant, report.compliant);
        assert_eq!(restored.pass_count, report.pass_count);
        assert_eq!(restored.target_level, report.target_level);
    }

    // ---- Severity ordering ----

    #[test]
    fn test_severity_ordering() {
        assert!(FindingSeverity::Pass < FindingSeverity::Warning);
        assert!(FindingSeverity::Warning < FindingSeverity::Fail);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(FindingSeverity::Pass.to_string(), "PASS");
        assert_eq!(FindingSeverity::Warning.to_string(), "WARNING");
        assert_eq!(FindingSeverity::Fail.to_string(), "FAIL");
    }

    // ---- Category display ----

    // ---- Key lifecycle compliance ----

    fn active_tracker() -> KeyLifecycleTracker {
        use crate::key_lifecycle::CryptoperiodPolicy;
        use chrono::Duration;
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP384,
            chrono::Utc::now() - Duration::hours(1),
            CryptoperiodPolicy::new(Duration::days(365 * 20), Duration::days(365 * 30)),
        );
        tracker.transition(KeyState::Active).unwrap();
        tracker
    }

    #[test]
    fn test_key_lifecycle_active_passes() {
        let mut input = compliant_level3_input();
        input.key_lifecycle = Some(active_tracker());
        let report = validate_compliance(&input, SecurityLevel::Level3);
        let klc_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.code.starts_with("NIST-KLC"))
            .collect();
        assert!(
            klc_findings
                .iter()
                .all(|f| f.severity != FindingSeverity::Fail),
            "Active key with valid cryptoperiod should pass all KLC checks"
        );
    }

    #[test]
    fn test_key_lifecycle_deactivated_fails() {
        use crate::key_lifecycle::CryptoperiodPolicy;
        use chrono::Duration;
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP384,
            chrono::Utc::now() - Duration::hours(1),
            CryptoperiodPolicy::new(Duration::days(365 * 20), Duration::days(365 * 30)),
        );
        tracker.transition(KeyState::Active).unwrap();
        tracker.transition(KeyState::Deactivated).unwrap();

        let mut input = compliant_level3_input();
        input.key_lifecycle = Some(tracker);
        let report = validate_compliance(&input, SecurityLevel::Level3);
        let klc002 = report.findings.iter().find(|f| f.code == "NIST-KLC-002");
        assert!(klc002.is_some());
        assert_eq!(klc002.unwrap().severity, FindingSeverity::Fail);
    }

    #[test]
    fn test_key_lifecycle_expired_cryptoperiod_fails() {
        use crate::key_lifecycle::CryptoperiodPolicy;
        use chrono::Duration;
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP384,
            // Activated 25 years ago — well past 20-year originator period
            chrono::Utc::now() - Duration::days(365 * 25),
            CryptoperiodPolicy::new(Duration::days(365 * 20), Duration::days(365 * 30)),
        );
        tracker.transition(KeyState::Active).unwrap();

        let mut input = compliant_level3_input();
        input.key_lifecycle = Some(tracker);
        let report = validate_compliance(&input, SecurityLevel::Level3);
        let klc003 = report.findings.iter().find(|f| f.code == "NIST-KLC-003");
        assert!(klc003.is_some());
        assert_eq!(klc003.unwrap().severity, FindingSeverity::Fail);
    }

    #[test]
    fn test_key_lifecycle_none_level3_warns() {
        let input = compliant_level3_input(); // key_lifecycle: None
        let report = validate_compliance(&input, SecurityLevel::Level3);
        let klc001 = report.findings.iter().find(|f| f.code == "NIST-KLC-001");
        assert!(
            klc001.is_some(),
            "Level 3 should warn about missing lifecycle tracker"
        );
        assert_eq!(klc001.unwrap().severity, FindingSeverity::Warning);
    }

    #[test]
    fn test_key_lifecycle_none_level1_no_warning() {
        let input = CaComplianceInput {
            algorithm: AlgorithmId::EcdsaP384,
            key_protection: KeyProtection::Software,
            ca_validity_days: 3650,
            max_ee_validity_days: 397,
            automated_crl: false,
            crl_interval_hours: 0,
            ocsp_available: false,
            crypto_audit_enabled: false,
            key_attestation_present: false,
            dual_control_enabled: false,
            certificate_policy_oids: vec!["1.3.6.1.4.1.56266.1.1.1".to_string()],
            key_lifecycle: None,
        };
        let report = validate_compliance(&input, SecurityLevel::Level1);
        let klc_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.code.starts_with("NIST-KLC"))
            .collect();
        assert!(
            klc_findings.is_empty(),
            "Level 1 should not warn about missing lifecycle"
        );
    }

    #[test]
    fn test_key_lifecycle_software_level3_warns_destruction() {
        let mut input = compliant_level3_input();
        input.key_protection = KeyProtection::Software;
        input.key_lifecycle = Some(active_tracker());
        let report = validate_compliance(&input, SecurityLevel::Level3);
        let klc005 = report.findings.iter().find(|f| f.code == "NIST-KLC-005");
        assert!(klc005.is_some());
        assert_eq!(klc005.unwrap().severity, FindingSeverity::Warning);
    }

    #[test]
    fn test_key_lifecycle_hardware_level3_destruction_passes() {
        let mut input = compliant_level3_input();
        input.key_lifecycle = Some(active_tracker());
        let report = validate_compliance(&input, SecurityLevel::Level3);
        let klc005 = report.findings.iter().find(|f| f.code == "NIST-KLC-005");
        assert!(klc005.is_some());
        assert_eq!(klc005.unwrap().severity, FindingSeverity::Pass);
    }

    #[test]
    fn test_key_lifecycle_compromised_fails() {
        use crate::key_lifecycle::CryptoperiodPolicy;
        use chrono::Duration;
        let mut tracker = KeyLifecycleTracker::new(
            AlgorithmId::EcdsaP384,
            chrono::Utc::now() - Duration::hours(1),
            CryptoperiodPolicy::new(Duration::days(365 * 20), Duration::days(365 * 30)),
        );
        tracker.transition(KeyState::Active).unwrap();
        tracker.transition(KeyState::Compromised).unwrap();

        let mut input = compliant_level3_input();
        input.key_lifecycle = Some(tracker);
        let report = validate_compliance(&input, SecurityLevel::Level3);
        let klc002 = report.findings.iter().find(|f| f.code == "NIST-KLC-002");
        assert!(klc002.is_some());
        assert_eq!(klc002.unwrap().severity, FindingSeverity::Fail);
    }

    #[test]
    fn test_category_display() {
        assert_eq!(
            ComplianceCategory::Algorithm.to_string(),
            "Algorithm & Key Size"
        );
        assert_eq!(
            ComplianceCategory::KeyProtection.to_string(),
            "Key Protection"
        );
        assert_eq!(ComplianceCategory::Validity.to_string(), "Validity Period");
        assert_eq!(
            ComplianceCategory::Revocation.to_string(),
            "Revocation Services"
        );
        assert_eq!(ComplianceCategory::Policy.to_string(), "Certificate Policy");
        assert_eq!(
            ComplianceCategory::Operational.to_string(),
            "Operational Controls"
        );
    }
}
