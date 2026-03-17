//! Policy evaluation logic.

use regex::Regex;

use super::{CaPolicy, PolicyRequest, PolicyResult, PolicyViolation, PolicyWarning, ViolationType};

/// Evaluates certificate requests against policies.
pub struct PolicyEvaluator<'a> {
    policies: &'a [CaPolicy],
    fail_fast: bool,
    hourly_count: i32,
    daily_count: i32,
}

impl<'a> PolicyEvaluator<'a> {
    /// Create a new evaluator.
    pub fn new(policies: &'a [CaPolicy], fail_fast: bool) -> Self {
        Self {
            policies,
            fail_fast,
            hourly_count: 0,
            daily_count: 0,
        }
    }

    /// Set rate limit counts.
    pub fn with_rate_counts(mut self, hourly: i32, daily: i32) -> Self {
        self.hourly_count = hourly;
        self.daily_count = daily;
        self
    }

    /// Evaluate the request against all enabled policies.
    pub fn evaluate(&self, request: &PolicyRequest) -> PolicyResult {
        let enabled_policies: Vec<_> = self.policies.iter().filter(|p| p.enabled).collect();

        if enabled_policies.is_empty() {
            // No policies means everything is allowed
            return PolicyResult::allowed(None);
        }

        let mut all_violations = Vec::new();
        let mut all_warnings = Vec::new();
        let mut matched_policy: Option<String> = None;

        for policy in enabled_policies {
            let (violations, warnings) = self.evaluate_policy(policy, request);

            if violations.is_empty() {
                // Policy passed - check approval settings
                matched_policy = Some(policy.name.clone());
                let requires_approval = policy.require_approval;

                // Check auto-approve patterns
                let auto_approve = if !policy.auto_approve_matching_patterns.is_empty() {
                    self.check_auto_approve(policy, request)
                } else {
                    false
                };

                return PolicyResult::allowed(matched_policy)
                    .with_approval(auto_approve, requires_approval && !auto_approve);
            }

            all_violations.extend(violations);
            all_warnings.extend(warnings);

            if self.fail_fast && !all_violations.is_empty() {
                return PolicyResult::denied(all_violations, Some(policy.name.clone()));
            }
        }

        // All policies had violations
        PolicyResult::denied(all_violations, matched_policy)
    }

    /// Evaluate a single policy.
    fn evaluate_policy(
        &self,
        policy: &CaPolicy,
        request: &PolicyRequest,
    ) -> (Vec<PolicyViolation>, Vec<PolicyWarning>) {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();

        // Check subject constraints
        self.check_subject_constraints(policy, request, &mut violations);

        // Check SAN constraints
        self.check_san_constraints(policy, request, &mut violations);

        // Check algorithm constraints
        self.check_algorithm_constraints(policy, request, &mut violations);

        // Check validity constraints
        self.check_validity_constraints(policy, request, &mut violations);

        // Check extension constraints
        self.check_extension_constraints(policy, request, &mut violations, &mut warnings);

        // Check rate limits
        self.check_rate_limits(policy, &mut violations);

        (violations, warnings)
    }

    /// Check subject DN constraints.
    fn check_subject_constraints(
        &self,
        policy: &CaPolicy,
        request: &PolicyRequest,
        violations: &mut Vec<PolicyViolation>,
    ) {
        // Check required fields
        if policy.require_cn && request.common_name.is_none() {
            violations.push(PolicyViolation::new(
                &policy.name,
                ViolationType::CnRequired,
                "common_name",
                "Common Name (CN) is required",
            ));
        }

        if policy.require_org && request.organization.is_none() {
            violations.push(PolicyViolation::new(
                &policy.name,
                ViolationType::OrgRequired,
                "organization",
                "Organization (O) is required",
            ));
        }

        if policy.require_country && request.country.is_none() {
            violations.push(PolicyViolation::new(
                &policy.name,
                ViolationType::CountryRequired,
                "country",
                "Country (C) is required",
            ));
        }

        // Check CN patterns
        if let Some(ref cn) = request.common_name {
            // Check denied patterns first (any match = deny)
            for pattern in &policy.denied_cn_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(cn) {
                        violations.push(
                            PolicyViolation::new(
                                &policy.name,
                                ViolationType::CnPattern,
                                "common_name",
                                format!("CN matches denied pattern: {}", pattern),
                            )
                            .with_value(cn),
                        );
                    }
                }
            }

            // Check allowed patterns (if specified, at least one must match)
            if !policy.allowed_cn_patterns.is_empty() {
                let matches_any = policy.allowed_cn_patterns.iter().any(|pattern| {
                    Regex::new(pattern)
                        .map(|re| re.is_match(cn))
                        .unwrap_or(false)
                });

                if !matches_any {
                    violations.push(
                        PolicyViolation::new(
                            &policy.name,
                            ViolationType::CnPattern,
                            "common_name",
                            "CN does not match any allowed pattern",
                        )
                        .with_value(cn),
                    );
                }
            }
        }
    }

    /// Check SAN constraints.
    fn check_san_constraints(
        &self,
        policy: &CaPolicy,
        request: &PolicyRequest,
        violations: &mut Vec<PolicyViolation>,
    ) {
        // Check SAN count
        let total_sans = request.total_san_count();
        if total_sans > policy.max_san_count as usize {
            violations.push(
                PolicyViolation::new(
                    &policy.name,
                    ViolationType::SanCountExceeded,
                    "san",
                    format!(
                        "Too many SANs: {} exceeds maximum of {}",
                        total_sans, policy.max_san_count
                    ),
                )
                .with_value(total_sans.to_string()),
            );
        }

        // Check IP SANs allowed
        if !policy.allow_san_ip && !request.san_ip.is_empty() {
            violations.push(
                PolicyViolation::new(
                    &policy.name,
                    ViolationType::SanIpNotAllowed,
                    "san_ip",
                    "IP addresses are not allowed in SANs",
                )
                .with_value(request.san_ip.join(", ")),
            );
        }

        // Check email SANs allowed
        if !policy.allow_san_email && !request.san_email.is_empty() {
            violations.push(
                PolicyViolation::new(
                    &policy.name,
                    ViolationType::SanEmailNotAllowed,
                    "san_email",
                    "Email addresses are not allowed in SANs",
                )
                .with_value(request.san_email.join(", ")),
            );
        }

        // Check DNS SAN patterns
        for dns in &request.san_dns {
            // Check denied patterns
            for pattern in &policy.denied_san_dns_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(dns) {
                        violations.push(
                            PolicyViolation::new(
                                &policy.name,
                                ViolationType::SanDnsPattern,
                                "san_dns",
                                format!("DNS SAN matches denied pattern: {}", pattern),
                            )
                            .with_value(dns),
                        );
                    }
                }
            }

            // Check allowed patterns
            if !policy.allowed_san_dns_patterns.is_empty() {
                let matches_any = policy.allowed_san_dns_patterns.iter().any(|pattern| {
                    Regex::new(pattern)
                        .map(|re| re.is_match(dns))
                        .unwrap_or(false)
                });

                if !matches_any {
                    violations.push(
                        PolicyViolation::new(
                            &policy.name,
                            ViolationType::SanDnsPattern,
                            "san_dns",
                            "DNS SAN does not match any allowed pattern",
                        )
                        .with_value(dns),
                    );
                }
            }
        }
    }

    /// Check algorithm constraints.
    fn check_algorithm_constraints(
        &self,
        policy: &CaPolicy,
        request: &PolicyRequest,
        violations: &mut Vec<PolicyViolation>,
    ) {
        // Check allowed algorithms
        if !policy.allowed_algorithms.is_empty() {
            let algo_upper = request.algorithm.to_uppercase();
            let allowed = policy
                .allowed_algorithms
                .iter()
                .any(|a| a.to_uppercase() == algo_upper);

            if !allowed {
                violations.push(
                    PolicyViolation::new(
                        &policy.name,
                        ViolationType::AlgorithmNotAllowed,
                        "algorithm",
                        format!(
                            "Algorithm '{}' is not allowed. Allowed: {}",
                            request.algorithm,
                            policy.allowed_algorithms.join(", ")
                        ),
                    )
                    .with_value(&request.algorithm),
                );
            }
        }

        // Check RSA key size
        if request.algorithm.to_uppercase().contains("RSA") {
            if let Some(bits) = request.rsa_bits {
                if bits < policy.min_rsa_bits {
                    violations.push(
                        PolicyViolation::new(
                            &policy.name,
                            ViolationType::RsaKeyTooSmall,
                            "rsa_bits",
                            format!(
                                "RSA key size {} bits is below minimum of {} bits",
                                bits, policy.min_rsa_bits
                            ),
                        )
                        .with_value(bits.to_string()),
                    );
                }
            }
        }
    }

    /// Check validity period constraints.
    fn check_validity_constraints(
        &self,
        policy: &CaPolicy,
        request: &PolicyRequest,
        violations: &mut Vec<PolicyViolation>,
    ) {
        if let Some(max_days) = policy.max_validity_days {
            if request.validity_days > max_days {
                violations.push(
                    PolicyViolation::new(
                        &policy.name,
                        ViolationType::ValidityTooLong,
                        "validity_days",
                        format!(
                            "Validity period {} days exceeds maximum of {} days",
                            request.validity_days, max_days
                        ),
                    )
                    .with_value(request.validity_days.to_string()),
                );
            }
        }

        if request.validity_days < policy.min_validity_days {
            violations.push(
                PolicyViolation::new(
                    &policy.name,
                    ViolationType::ValidityTooShort,
                    "validity_days",
                    format!(
                        "Validity period {} days is below minimum of {} days",
                        request.validity_days, policy.min_validity_days
                    ),
                )
                .with_value(request.validity_days.to_string()),
            );
        }
    }

    /// Check extension constraints.
    fn check_extension_constraints(
        &self,
        policy: &CaPolicy,
        request: &PolicyRequest,
        violations: &mut Vec<PolicyViolation>,
        warnings: &mut Vec<PolicyWarning>,
    ) {
        // Check key usage requirement
        if policy.require_key_usage && request.key_usages.is_empty() && !request.is_ca {
            violations.push(PolicyViolation::new(
                &policy.name,
                ViolationType::KeyUsageRequired,
                "key_usage",
                "Key Usage extension is required",
            ));
        }

        // Check EKU requirement
        if policy.require_eku && request.extended_key_usages.is_empty() && !request.is_ca {
            violations.push(PolicyViolation::new(
                &policy.name,
                ViolationType::EkuRequired,
                "extended_key_usage",
                "Extended Key Usage extension is required",
            ));
        }

        // Check allowed EKUs
        if !policy.allowed_ekus.is_empty() {
            for eku in &request.extended_key_usages {
                if !policy.allowed_ekus.contains(eku) {
                    violations.push(
                        PolicyViolation::new(
                            &policy.name,
                            ViolationType::EkuNotAllowed,
                            "extended_key_usage",
                            format!("EKU '{}' is not in allowed list", eku),
                        )
                        .with_value(eku),
                    );
                }
            }
        }

        // Add warning if no EKU is specified but allowed_ekus is set
        if !policy.allowed_ekus.is_empty()
            && request.extended_key_usages.is_empty()
            && !request.is_ca
        {
            warnings.push(PolicyWarning::new(
                &policy.name,
                "extended_key_usage",
                "No EKU specified but policy has allowed EKU list",
            ));
        }
    }

    /// Check rate limits.
    fn check_rate_limits(&self, policy: &CaPolicy, violations: &mut Vec<PolicyViolation>) {
        if let Some(max_hourly) = policy.max_certs_per_hour {
            if self.hourly_count >= max_hourly {
                violations.push(
                    PolicyViolation::new(
                        &policy.name,
                        ViolationType::RateLimitExceeded,
                        "rate_limit",
                        format!(
                            "Hourly rate limit exceeded: {} of {} certificates",
                            self.hourly_count, max_hourly
                        ),
                    )
                    .with_value(format!("{}/{}", self.hourly_count, max_hourly)),
                );
            }
        }

        if let Some(max_daily) = policy.max_certs_per_day {
            if self.daily_count >= max_daily {
                violations.push(
                    PolicyViolation::new(
                        &policy.name,
                        ViolationType::RateLimitExceeded,
                        "rate_limit",
                        format!(
                            "Daily rate limit exceeded: {} of {} certificates",
                            self.daily_count, max_daily
                        ),
                    )
                    .with_value(format!("{}/{}", self.daily_count, max_daily)),
                );
            }
        }
    }

    /// Check if request matches auto-approve patterns.
    fn check_auto_approve(&self, policy: &CaPolicy, request: &PolicyRequest) -> bool {
        if policy.auto_approve_matching_patterns.is_empty() {
            return false;
        }

        // Check CN against auto-approve patterns
        if let Some(ref cn) = request.common_name {
            for pattern in &policy.auto_approve_matching_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(cn) {
                        return true;
                    }
                }
            }
        }

        // Check DNS SANs against auto-approve patterns
        for dns in &request.san_dns {
            for pattern in &policy.auto_approve_matching_patterns {
                if let Ok(re) = Regex::new(pattern) {
                    if re.is_match(dns) {
                        return true;
                    }
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::CaPolicy;

    fn test_policy() -> CaPolicy {
        CaPolicy {
            name: "Test Policy".into(),
            enabled: true,
            // Permissive defaults for testing
            require_cn: false,
            require_key_usage: false,
            require_eku: false,
            ..Default::default()
        }
    }

    #[test]
    fn test_empty_policies_allows_all() {
        let evaluator = PolicyEvaluator::new(&[], false);
        let request = PolicyRequest::new(Some("test.example.com".into()), "ECDSA-P256".into());
        let result = evaluator.evaluate(&request);
        assert!(result.allowed);
    }

    #[test]
    fn test_cn_required() {
        let mut policy = test_policy();
        policy.require_cn = true;

        let binding = [policy];
        let evaluator = PolicyEvaluator::new(&binding, false);
        let request = PolicyRequest::new(None, "ECDSA-P256".into());
        let result = evaluator.evaluate(&request);

        assert!(!result.allowed);
        assert_eq!(result.violations.len(), 1);
        assert_eq!(
            result.violations[0].violation_type,
            ViolationType::CnRequired
        );
    }

    #[test]
    fn test_cn_pattern_allowed() {
        let mut policy = test_policy();
        policy.allowed_cn_patterns = vec![r".*\.example\.com$".into()];

        let binding = [policy];
        let evaluator = PolicyEvaluator::new(&binding, false);

        // Should pass
        let request = PolicyRequest::new(Some("test.example.com".into()), "ECDSA-P256".into());
        let result = evaluator.evaluate(&request);
        assert!(result.allowed);

        // Should fail
        let request = PolicyRequest::new(Some("test.evil.com".into()), "ECDSA-P256".into());
        let result = evaluator.evaluate(&request);
        assert!(!result.allowed);
    }

    #[test]
    fn test_cn_pattern_denied() {
        let mut policy = test_policy();
        policy.denied_cn_patterns = vec![r".*\.evil\.com$".into()];

        let binding = [policy];
        let evaluator = PolicyEvaluator::new(&binding, false);

        // Should pass
        let request = PolicyRequest::new(Some("test.example.com".into()), "ECDSA-P256".into());
        let result = evaluator.evaluate(&request);
        assert!(result.allowed);

        // Should fail
        let request = PolicyRequest::new(Some("test.evil.com".into()), "ECDSA-P256".into());
        let result = evaluator.evaluate(&request);
        assert!(!result.allowed);
    }

    #[test]
    fn test_validity_constraints() {
        let mut policy = test_policy();
        policy.max_validity_days = Some(365);
        policy.min_validity_days = 30;

        let binding = [policy];
        let evaluator = PolicyEvaluator::new(&binding, false);

        // Should pass
        let mut request = PolicyRequest::new(Some("test.example.com".into()), "ECDSA-P256".into());
        request.validity_days = 180;
        let result = evaluator.evaluate(&request);
        assert!(result.allowed);

        // Too long
        request.validity_days = 500;
        let result = evaluator.evaluate(&request);
        assert!(!result.allowed);

        // Too short
        request.validity_days = 7;
        let result = evaluator.evaluate(&request);
        assert!(!result.allowed);
    }

    #[test]
    fn test_algorithm_constraints() {
        let mut policy = test_policy();
        policy.allowed_algorithms = vec!["ECDSA-P256".into(), "ECDSA-P384".into()];

        let binding = [policy];
        let evaluator = PolicyEvaluator::new(&binding, false);

        // Should pass
        let request = PolicyRequest::new(Some("test.example.com".into()), "ECDSA-P256".into());
        let result = evaluator.evaluate(&request);
        assert!(result.allowed);

        // Should fail
        let request = PolicyRequest::new(Some("test.example.com".into()), "RSA-2048".into());
        let result = evaluator.evaluate(&request);
        assert!(!result.allowed);
    }

    #[test]
    fn test_rate_limits() {
        let mut policy = test_policy();
        policy.max_certs_per_hour = Some(10);

        let binding = [policy];
        let evaluator = PolicyEvaluator::new(&binding, false).with_rate_counts(10, 0);

        let request = PolicyRequest::new(Some("test.example.com".into()), "ECDSA-P256".into());
        let result = evaluator.evaluate(&request);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.violation_type == ViolationType::RateLimitExceeded));
    }

    #[test]
    fn test_conflicting_policies_first_match_wins() {
        // First policy allows only .example.com, second allows only .evil.com
        // PolicyEvaluator returns on first policy that passes (no violations)
        let mut policy1 = test_policy();
        policy1.name = "TLS-External".into();
        policy1.allowed_cn_patterns = vec![r".*\.example\.com$".into()];

        let mut policy2 = test_policy();
        policy2.name = "TLS-Internal".into();
        policy2.allowed_cn_patterns = vec![r".*\.internal\.local$".into()];

        let binding = [policy1, policy2];
        let evaluator = PolicyEvaluator::new(&binding, false);

        // Matches policy1 only
        let request = PolicyRequest::new(Some("web.example.com".into()), "ECDSA-P256".into());
        let result = evaluator.evaluate(&request);
        assert!(result.allowed);
        assert_eq!(result.matched_policy.as_deref(), Some("TLS-External"));

        // Matches policy2 only
        let request = PolicyRequest::new(Some("app.internal.local".into()), "ECDSA-P256".into());
        let result = evaluator.evaluate(&request);
        assert!(result.allowed);
        assert_eq!(result.matched_policy.as_deref(), Some("TLS-Internal"));

        // Matches neither — should be denied
        let request = PolicyRequest::new(Some("hack.evil.com".into()), "ECDSA-P256".into());
        let result = evaluator.evaluate(&request);
        assert!(!result.allowed);
    }

    #[test]
    fn test_disabled_policy_is_skipped() {
        let mut policy = test_policy();
        policy.enabled = false;
        policy.require_cn = true; // Would fail, but should be skipped

        let binding = [policy];
        let evaluator = PolicyEvaluator::new(&binding, false);

        // No CN but disabled policy should not block
        let request = PolicyRequest::new(None, "ECDSA-P256".into());
        let result = evaluator.evaluate(&request);
        assert!(result.allowed);
    }

    #[test]
    fn test_fail_fast_stops_on_first_violation() {
        let mut policy = test_policy();
        policy.require_cn = true;
        policy.require_org = true;

        // fail_fast = true
        let binding = [policy.clone()];
        let evaluator_fast = PolicyEvaluator::new(&binding, true);
        let request = PolicyRequest::new(None, "ECDSA-P256".into());
        let result = evaluator_fast.evaluate(&request);
        assert!(!result.allowed);
        // Might stop after first violation
        assert!(!result.violations.is_empty());

        // fail_fast = false — collects all violations
        let binding = [policy];
        let evaluator_slow = PolicyEvaluator::new(&binding, false);
        let result = evaluator_slow.evaluate(&request);
        assert!(!result.allowed);
        // Should have at least 2 violations (CN + Org both missing)
        assert!(
            result.violations.len() >= 2,
            "Non-fail-fast should collect multiple violations, got {}",
            result.violations.len()
        );
    }

    #[test]
    fn test_rsa_min_key_size() {
        let mut policy = test_policy();
        policy.min_rsa_bits = 4096;

        let binding = [policy];
        let evaluator = PolicyEvaluator::new(&binding, false);

        // 2048-bit RSA should be rejected
        let mut request = PolicyRequest::new(Some("test.example.com".into()), "RSA-2048".into());
        request.rsa_bits = Some(2048);
        let result = evaluator.evaluate(&request);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.violation_type == ViolationType::RsaKeyTooSmall));

        // 4096-bit RSA should pass
        let mut request = PolicyRequest::new(Some("test.example.com".into()), "RSA-4096".into());
        request.rsa_bits = Some(4096);
        let result = evaluator.evaluate(&request);
        assert!(result.allowed);
    }

    #[test]
    fn test_san_count_exceeded() {
        let mut policy = test_policy();
        policy.max_san_count = 3;

        let binding = [policy];
        let evaluator = PolicyEvaluator::new(&binding, false);

        let mut request = PolicyRequest::new(Some("test.example.com".into()), "ECDSA-P256".into());
        request.san_dns = vec![
            "a.example.com".into(),
            "b.example.com".into(),
            "c.example.com".into(),
            "d.example.com".into(),
        ];
        let result = evaluator.evaluate(&request);
        assert!(!result.allowed);
        assert!(result
            .violations
            .iter()
            .any(|v| v.violation_type == ViolationType::SanCountExceeded));
    }

    #[test]
    fn test_daily_rate_limit() {
        let mut policy = test_policy();
        policy.max_certs_per_day = Some(100);

        let binding = [policy];
        let evaluator = PolicyEvaluator::new(&binding, false).with_rate_counts(0, 100);

        let request = PolicyRequest::new(Some("test.example.com".into()), "ECDSA-P256".into());
        let result = evaluator.evaluate(&request);
        assert!(!result.allowed);
    }
}
