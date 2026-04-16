//! Certificate Policy Engine
//!
//! Provides policy evaluation for certificate issuance, including:
//! - Validity period constraints
//! - Algorithm constraints
//! - Subject DN requirements and patterns
//! - SAN constraints
//! - Extension requirements
//! - Rate limiting
//! - Approval workflow control

/// Compliance validation for FIPS 140-3, NIST SP 800-57, and FBCA.
pub mod compliance;
/// CP/CPS document generation per RFC 3647.
pub mod cps;
mod evaluator;
/// Federal Bridge CA cross-certification support.
pub mod fedbridge;
/// FPKI policy OID definitions and policy mapping structs.
pub mod fpki;
/// NIST SP 800-56A/B/C — Key establishment scheme validation.
pub mod key_establishment;
/// NIST SP 800-175B + SP 800-57 Pt.2 — Cryptographic mechanisms and key management compliance.
pub mod nist_compliance;
/// Policy presets for common use cases.
pub mod presets;
/// Security level framework — NIST SP 800-63 / FIPS 140-3 / FBCA aligned.
pub mod security_level;
/// NIST SP 800-89 — Digital signature assurance validation.
pub mod signature_assurance;

pub use evaluator::PolicyEvaluator;
pub use presets::*;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A certificate issuance policy bound to a CA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaPolicy {
    pub id: Uuid,
    pub ca_id: Uuid,
    pub name: String,

    // Validity constraints
    pub max_validity_days: Option<i32>,
    pub min_validity_days: i32,

    // Algorithm constraints
    pub allowed_algorithms: Vec<String>,
    pub min_rsa_bits: i32,

    // Subject constraints
    pub require_cn: bool,
    pub require_org: bool,
    pub require_country: bool,
    pub allowed_cn_patterns: Vec<String>,
    pub denied_cn_patterns: Vec<String>,

    // SAN constraints
    pub allowed_san_dns_patterns: Vec<String>,
    pub denied_san_dns_patterns: Vec<String>,
    pub allow_san_ip: bool,
    pub allow_san_email: bool,
    pub max_san_count: i32,

    // Extension constraints
    pub require_key_usage: bool,
    pub require_eku: bool,
    pub allowed_ekus: Vec<String>,

    // Approval requirements
    pub require_approval: bool,
    pub auto_approve_matching_patterns: Vec<String>,

    // Rate limits
    pub max_certs_per_day: Option<i32>,
    pub max_certs_per_hour: Option<i32>,

    pub enabled: bool,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Default for CaPolicy {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            ca_id: Uuid::nil(),
            name: String::new(),
            max_validity_days: None,
            min_validity_days: 1,
            allowed_algorithms: Vec::new(),
            min_rsa_bits: 2048,
            require_cn: true,
            require_org: false,
            require_country: false,
            allowed_cn_patterns: Vec::new(),
            denied_cn_patterns: Vec::new(),
            allowed_san_dns_patterns: Vec::new(),
            denied_san_dns_patterns: Vec::new(),
            allow_san_ip: true,
            allow_san_email: true,
            max_san_count: 100,
            require_key_usage: true,
            require_eku: true,
            allowed_ekus: Vec::new(),
            require_approval: false,
            auto_approve_matching_patterns: Vec::new(),
            max_certs_per_day: None,
            max_certs_per_hour: None,
            enabled: true,
            priority: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

/// A certificate request to evaluate against policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRequest {
    /// Common Name from subject
    pub common_name: Option<String>,
    /// Organization from subject
    pub organization: Option<String>,
    /// Country from subject
    pub country: Option<String>,
    /// Full subject DN
    pub subject_dn: String,
    /// DNS SANs
    pub san_dns: Vec<String>,
    /// IP SANs
    pub san_ip: Vec<String>,
    /// Email SANs
    pub san_email: Vec<String>,
    /// Requested validity in days
    pub validity_days: i32,
    /// Algorithm identifier (e.g., "ECDSA-P256", "RSA-2048")
    pub algorithm: String,
    /// RSA key bits (if RSA)
    pub rsa_bits: Option<i32>,
    /// Requested key usages
    pub key_usages: Vec<String>,
    /// Requested extended key usages (OIDs)
    pub extended_key_usages: Vec<String>,
    /// Whether this is a CA certificate request
    pub is_ca: bool,
}

impl PolicyRequest {
    /// Create a new policy request for evaluation.
    pub fn new(common_name: Option<String>, algorithm: String) -> Self {
        Self {
            common_name,
            organization: None,
            country: None,
            subject_dn: String::new(),
            san_dns: Vec::new(),
            san_ip: Vec::new(),
            san_email: Vec::new(),
            validity_days: 365,
            algorithm,
            rsa_bits: None,
            key_usages: Vec::new(),
            extended_key_usages: Vec::new(),
            is_ca: false,
        }
    }

    /// Get all SANs as a single count.
    pub fn total_san_count(&self) -> usize {
        self.san_dns.len() + self.san_ip.len() + self.san_email.len()
    }
}

/// Result of policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    /// Whether the request is allowed by policy.
    pub allowed: bool,
    /// List of policy violations.
    pub violations: Vec<PolicyViolation>,
    /// List of policy warnings (non-blocking).
    pub warnings: Vec<PolicyWarning>,
    /// Name of the policy that matched (for tracking).
    pub matched_policy: Option<String>,
    /// Whether the request should be auto-approved.
    pub auto_approve: bool,
    /// Whether the request requires manual approval.
    pub requires_approval: bool,
}

impl PolicyResult {
    /// Create a passing result.
    pub fn allowed(policy_name: Option<String>) -> Self {
        Self {
            allowed: true,
            violations: Vec::new(),
            warnings: Vec::new(),
            matched_policy: policy_name,
            auto_approve: false,
            requires_approval: false,
        }
    }

    /// Create a result with violations.
    pub fn denied(violations: Vec<PolicyViolation>, policy_name: Option<String>) -> Self {
        Self {
            allowed: false,
            violations,
            warnings: Vec::new(),
            matched_policy: policy_name,
            auto_approve: false,
            requires_approval: false,
        }
    }

    /// Add a warning to the result.
    pub fn with_warning(mut self, warning: PolicyWarning) -> Self {
        self.warnings.push(warning);
        self
    }

    /// Set approval status.
    pub fn with_approval(mut self, auto_approve: bool, requires_approval: bool) -> Self {
        self.auto_approve = auto_approve;
        self.requires_approval = requires_approval;
        self
    }
}

/// A policy violation that prevents issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// Name of the policy that was violated.
    pub policy_name: String,
    /// Type of violation.
    pub violation_type: ViolationType,
    /// Field that caused the violation.
    pub field: String,
    /// Human-readable message.
    pub message: String,
    /// The violating value (for debugging).
    pub value: Option<String>,
}

impl PolicyViolation {
    /// Create a new policy violation.
    pub fn new(
        policy_name: impl Into<String>,
        violation_type: ViolationType,
        field: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            policy_name: policy_name.into(),
            violation_type,
            field: field.into(),
            message: message.into(),
            value: None,
        }
    }

    /// Add the violating value.
    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }
}

/// Types of policy violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationType {
    /// CN pattern violation
    CnPattern,
    /// CN is required but missing
    CnRequired,
    /// Organization is required but missing
    OrgRequired,
    /// Country is required but missing
    CountryRequired,
    /// SAN DNS pattern violation
    SanDnsPattern,
    /// SAN IP not allowed
    SanIpNotAllowed,
    /// SAN email not allowed
    SanEmailNotAllowed,
    /// Too many SANs
    SanCountExceeded,
    /// Algorithm not allowed
    AlgorithmNotAllowed,
    /// RSA key too small
    RsaKeyTooSmall,
    /// Validity period too long
    ValidityTooLong,
    /// Validity period too short
    ValidityTooShort,
    /// Key usage required but not present
    KeyUsageRequired,
    /// EKU required but not present
    EkuRequired,
    /// EKU not in allowed list
    EkuNotAllowed,
    /// Rate limit exceeded
    RateLimitExceeded,
}

impl ViolationType {
    /// Get the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CnPattern => "cn_pattern",
            Self::CnRequired => "cn_required",
            Self::OrgRequired => "org_required",
            Self::CountryRequired => "country_required",
            Self::SanDnsPattern => "san_dns_pattern",
            Self::SanIpNotAllowed => "san_ip_not_allowed",
            Self::SanEmailNotAllowed => "san_email_not_allowed",
            Self::SanCountExceeded => "san_count_exceeded",
            Self::AlgorithmNotAllowed => "algorithm_not_allowed",
            Self::RsaKeyTooSmall => "rsa_key_too_small",
            Self::ValidityTooLong => "validity_too_long",
            Self::ValidityTooShort => "validity_too_short",
            Self::KeyUsageRequired => "key_usage_required",
            Self::EkuRequired => "eku_required",
            Self::EkuNotAllowed => "eku_not_allowed",
            Self::RateLimitExceeded => "rate_limit_exceeded",
        }
    }
}

/// A policy warning that doesn't prevent issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyWarning {
    /// Name of the policy that generated the warning.
    pub policy_name: String,
    /// Field that triggered the warning.
    pub field: String,
    /// Human-readable message.
    pub message: String,
}

impl PolicyWarning {
    /// Create a new policy warning.
    pub fn new(
        policy_name: impl Into<String>,
        field: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            policy_name: policy_name.into(),
            field: field.into(),
            message: message.into(),
        }
    }
}

/// The policy engine that evaluates requests against policies.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policies: Vec<CaPolicy>,
    /// Whether to stop at first violation or collect all.
    fail_fast: bool,
}

impl PolicyEngine {
    /// Create a new policy engine with the given policies.
    pub fn new(mut policies: Vec<CaPolicy>) -> Self {
        // Sort by priority (higher first)
        policies.sort_by_key(|p| std::cmp::Reverse(p.priority));
        Self {
            policies,
            fail_fast: false,
        }
    }

    /// Set whether to stop at first violation.
    pub fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }

    /// Evaluate a request against all enabled policies.
    pub fn evaluate(&self, request: &PolicyRequest) -> PolicyResult {
        PolicyEvaluator::new(&self.policies, self.fail_fast).evaluate(request)
    }

    /// Evaluate a request and also check rate limits.
    pub fn evaluate_with_rate_limits(
        &self,
        request: &PolicyRequest,
        hourly_count: i32,
        daily_count: i32,
    ) -> PolicyResult {
        PolicyEvaluator::new(&self.policies, self.fail_fast)
            .with_rate_counts(hourly_count, daily_count)
            .evaluate(request)
    }

    /// Get the policies.
    pub fn policies(&self) -> &[CaPolicy] {
        &self.policies
    }
}

/// Common EKU OIDs.
pub mod eku {
    /// Server Authentication (1.3.6.1.5.5.7.3.1)
    pub const SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
    /// Client Authentication (1.3.6.1.5.5.7.3.2)
    pub const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
    /// Code Signing (1.3.6.1.5.5.7.3.3)
    pub const CODE_SIGNING: &str = "1.3.6.1.5.5.7.3.3";
    /// Email Protection (1.3.6.1.5.5.7.3.4)
    pub const EMAIL_PROTECTION: &str = "1.3.6.1.5.5.7.3.4";
    /// Time Stamping (1.3.6.1.5.5.7.3.8)
    pub const TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
    /// OCSP Signing (1.3.6.1.5.5.7.3.9)
    pub const OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = CaPolicy::default();
        assert!(policy.require_cn);
        assert!(!policy.require_org);
        assert!(policy.enabled);
    }

    #[test]
    fn test_policy_request() {
        let mut request = PolicyRequest::new(Some("test.example.com".into()), "ECDSA-P256".into());
        request.san_dns.push("test.example.com".into());
        request.san_dns.push("www.example.com".into());
        request.san_ip.push("192.168.1.1".into());

        assert_eq!(request.total_san_count(), 3);
    }

    #[test]
    fn test_policy_result() {
        let result = PolicyResult::allowed(Some("test".into()));
        assert!(result.allowed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_policy_result_denied() {
        let violations = vec![PolicyViolation::new(
            "test-policy",
            ViolationType::CnRequired,
            "cn",
            "Common Name is required",
        )];
        let result = PolicyResult::denied(violations, Some("test-policy".into()));
        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(result.matched_policy.as_deref(), Some("test-policy"));
    }

    #[test]
    fn test_policy_result_with_warning() {
        let result = PolicyResult::allowed(None).with_warning(PolicyWarning::new(
            "test",
            "validity",
            "Short validity period",
        ));
        assert!(result.allowed);
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(result.warnings[0].field, "validity");
    }

    #[test]
    fn test_policy_result_with_approval() {
        let result = PolicyResult::allowed(None).with_approval(true, false);
        assert!(result.auto_approve);
        assert!(!result.requires_approval);

        let result2 = PolicyResult::allowed(None).with_approval(false, true);
        assert!(!result2.auto_approve);
        assert!(result2.requires_approval);
    }

    #[test]
    fn test_policy_violation_with_value() {
        let v = PolicyViolation::new(
            "web-tls",
            ViolationType::ValidityTooLong,
            "validity_days",
            "Exceeds maximum",
        )
        .with_value("730");

        assert_eq!(v.policy_name, "web-tls");
        assert_eq!(v.violation_type, ViolationType::ValidityTooLong);
        assert_eq!(v.value.as_deref(), Some("730"));
    }

    #[test]
    fn test_violation_type_as_str() {
        assert_eq!(ViolationType::CnPattern.as_str(), "cn_pattern");
        assert_eq!(ViolationType::CnRequired.as_str(), "cn_required");
        assert_eq!(ViolationType::OrgRequired.as_str(), "org_required");
        assert_eq!(ViolationType::SanDnsPattern.as_str(), "san_dns_pattern");
        assert_eq!(
            ViolationType::SanIpNotAllowed.as_str(),
            "san_ip_not_allowed"
        );
        assert_eq!(
            ViolationType::AlgorithmNotAllowed.as_str(),
            "algorithm_not_allowed"
        );
        assert_eq!(ViolationType::RsaKeyTooSmall.as_str(), "rsa_key_too_small");
        assert_eq!(ViolationType::ValidityTooLong.as_str(), "validity_too_long");
        assert_eq!(
            ViolationType::ValidityTooShort.as_str(),
            "validity_too_short"
        );
        assert_eq!(
            ViolationType::RateLimitExceeded.as_str(),
            "rate_limit_exceeded"
        );
    }

    #[test]
    fn test_policy_request_san_counting() {
        let mut req = PolicyRequest::new(Some("test.com".into()), "ECDSA-P256".into());
        assert_eq!(req.total_san_count(), 0);

        req.san_dns.push("a.com".into());
        req.san_dns.push("b.com".into());
        req.san_ip.push("10.0.0.1".into());
        req.san_email.push("admin@test.com".into());
        assert_eq!(req.total_san_count(), 4);
    }

    #[test]
    fn test_default_policy_values() {
        let policy = CaPolicy::default();
        assert_eq!(policy.min_validity_days, 1);
        assert_eq!(policy.min_rsa_bits, 2048);
        assert!(policy.require_cn);
        assert!(!policy.require_org);
        assert!(!policy.require_country);
        assert!(policy.allow_san_ip);
        assert!(policy.allow_san_email);
        assert_eq!(policy.max_san_count, 100);
        assert!(policy.require_key_usage);
        assert!(policy.require_eku);
        assert!(!policy.require_approval);
        assert!(policy.enabled);
        assert_eq!(policy.priority, 0);
        assert!(policy.max_validity_days.is_none());
        assert!(policy.max_certs_per_day.is_none());
    }

    #[test]
    fn test_eku_constants() {
        assert_eq!(eku::SERVER_AUTH, "1.3.6.1.5.5.7.3.1");
        assert_eq!(eku::CLIENT_AUTH, "1.3.6.1.5.5.7.3.2");
        assert_eq!(eku::CODE_SIGNING, "1.3.6.1.5.5.7.3.3");
        assert_eq!(eku::EMAIL_PROTECTION, "1.3.6.1.5.5.7.3.4");
        assert_eq!(eku::TIME_STAMPING, "1.3.6.1.5.5.7.3.8");
        assert_eq!(eku::OCSP_SIGNING, "1.3.6.1.5.5.7.3.9");
    }

    #[test]
    fn test_policy_engine_creation() {
        let p1 = CaPolicy {
            priority: 5,
            ..Default::default()
        };
        let p2 = CaPolicy {
            priority: 10,
            ..Default::default()
        };
        let p3 = CaPolicy {
            priority: 1,
            ..Default::default()
        };

        let engine = PolicyEngine::new(vec![p1, p2, p3]);
        // Should be sorted by priority descending
        assert_eq!(engine.policies()[0].priority, 10);
        assert_eq!(engine.policies()[1].priority, 5);
        assert_eq!(engine.policies()[2].priority, 1);
    }

    #[test]
    fn test_policy_engine_fail_fast() {
        let engine = PolicyEngine::new(vec![]).with_fail_fast(true);
        assert!(engine.fail_fast);
    }

    #[test]
    fn test_violation_type_serde_roundtrip() {
        let types = [
            ViolationType::CnPattern,
            ViolationType::SanCountExceeded,
            ViolationType::EkuNotAllowed,
            ViolationType::RateLimitExceeded,
        ];
        for vt in types {
            let json = serde_json::to_string(&vt).unwrap();
            let restored: ViolationType = serde_json::from_str(&json).unwrap();
            assert_eq!(restored, vt);
        }
    }
}
