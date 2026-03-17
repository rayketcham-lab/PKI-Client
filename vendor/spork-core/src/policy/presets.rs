//! Policy presets for common use cases.

use uuid::Uuid;

use super::{eku, CaPolicy};

/// Create a Web Server TLS policy following CA/B Forum guidelines.
pub fn preset_web_server(ca_id: Uuid) -> CaPolicy {
    CaPolicy {
        id: Uuid::new_v4(),
        ca_id,
        name: "Web Server TLS".into(),
        max_validity_days: Some(398), // CA/B Forum maximum
        min_validity_days: 1,
        allowed_algorithms: vec![
            "ECDSA-P256".into(),
            "ECDSA-P384".into(),
            "RSA-2048".into(),
            "RSA-4096".into(),
        ],
        min_rsa_bits: 2048,
        require_cn: true,
        require_org: false,
        require_country: false,
        allowed_cn_patterns: Vec::new(),
        denied_cn_patterns: Vec::new(),
        allowed_san_dns_patterns: Vec::new(),
        denied_san_dns_patterns: Vec::new(),
        allow_san_ip: false, // Public TLS should not have IP SANs
        allow_san_email: false,
        max_san_count: 100,
        require_key_usage: true,
        require_eku: true,
        allowed_ekus: vec![eku::SERVER_AUTH.into()],
        require_approval: true,
        auto_approve_matching_patterns: Vec::new(),
        max_certs_per_day: None,
        max_certs_per_hour: None,
        enabled: true,
        priority: 10,
        ..Default::default()
    }
}

/// Create an Internal Server policy with more permissive settings.
pub fn preset_internal_server(ca_id: Uuid) -> CaPolicy {
    CaPolicy {
        id: Uuid::new_v4(),
        ca_id,
        name: "Internal Server".into(),
        max_validity_days: Some(825), // ~2.25 years for internal use
        min_validity_days: 1,
        allowed_algorithms: vec![
            "ECDSA-P256".into(),
            "ECDSA-P384".into(),
            "RSA-2048".into(),
            "RSA-4096".into(),
            "ML-DSA-65".into(),
        ],
        min_rsa_bits: 2048,
        require_cn: true,
        require_org: false,
        require_country: false,
        allowed_cn_patterns: Vec::new(),
        denied_cn_patterns: Vec::new(),
        allowed_san_dns_patterns: Vec::new(),
        denied_san_dns_patterns: Vec::new(),
        allow_san_ip: true,
        allow_san_email: false,
        max_san_count: 100,
        require_key_usage: true,
        require_eku: true,
        allowed_ekus: vec![eku::SERVER_AUTH.into(), eku::CLIENT_AUTH.into()],
        require_approval: false,
        auto_approve_matching_patterns: Vec::new(),
        max_certs_per_day: None,
        max_certs_per_hour: None,
        enabled: true,
        priority: 5,
        ..Default::default()
    }
}

/// Create a Client Authentication policy.
pub fn preset_client_auth(ca_id: Uuid) -> CaPolicy {
    CaPolicy {
        id: Uuid::new_v4(),
        ca_id,
        name: "Client Authentication".into(),
        max_validity_days: Some(365), // 1 year max
        min_validity_days: 1,
        allowed_algorithms: vec![
            "ECDSA-P256".into(),
            "ECDSA-P384".into(),
            "RSA-2048".into(),
            "RSA-4096".into(),
        ],
        min_rsa_bits: 2048,
        require_cn: true,
        require_org: false,
        require_country: false,
        allowed_cn_patterns: Vec::new(),
        denied_cn_patterns: Vec::new(),
        allowed_san_dns_patterns: Vec::new(),
        denied_san_dns_patterns: Vec::new(),
        allow_san_ip: false,
        allow_san_email: true,
        max_san_count: 10,
        require_key_usage: true,
        require_eku: true,
        allowed_ekus: vec![eku::CLIENT_AUTH.into()],
        require_approval: false,
        auto_approve_matching_patterns: Vec::new(),
        max_certs_per_day: None,
        max_certs_per_hour: None,
        enabled: true,
        priority: 5,
        ..Default::default()
    }
}

/// Create a Code Signing policy.
pub fn preset_code_signing(ca_id: Uuid) -> CaPolicy {
    CaPolicy {
        id: Uuid::new_v4(),
        ca_id,
        name: "Code Signing".into(),
        max_validity_days: Some(365 * 3), // 3 years
        min_validity_days: 1,
        allowed_algorithms: vec!["ECDSA-P256".into(), "ECDSA-P384".into(), "RSA-4096".into()],
        min_rsa_bits: 4096, // Higher security for code signing
        require_cn: true,
        require_org: true, // Organization required for code signing
        require_country: true,
        allowed_cn_patterns: Vec::new(),
        denied_cn_patterns: Vec::new(),
        allowed_san_dns_patterns: Vec::new(),
        denied_san_dns_patterns: Vec::new(),
        allow_san_ip: false,
        allow_san_email: true,
        max_san_count: 1,
        require_key_usage: true,
        require_eku: true,
        allowed_ekus: vec![eku::CODE_SIGNING.into()],
        require_approval: true, // Always require approval for code signing
        auto_approve_matching_patterns: Vec::new(),
        max_certs_per_day: Some(10), // Rate limited
        max_certs_per_hour: Some(3),
        enabled: true,
        priority: 20,
        ..Default::default()
    }
}

/// Create an Email/S-MIME policy.
pub fn preset_email_smime(ca_id: Uuid) -> CaPolicy {
    CaPolicy {
        id: Uuid::new_v4(),
        ca_id,
        name: "Email S/MIME".into(),
        max_validity_days: Some(365 * 2), // 2 years
        min_validity_days: 1,
        allowed_algorithms: vec![
            "ECDSA-P256".into(),
            "ECDSA-P384".into(),
            "RSA-2048".into(),
            "RSA-4096".into(),
        ],
        min_rsa_bits: 2048,
        require_cn: true,
        require_org: false,
        require_country: false,
        allowed_cn_patterns: Vec::new(),
        denied_cn_patterns: Vec::new(),
        allowed_san_dns_patterns: Vec::new(),
        denied_san_dns_patterns: Vec::new(),
        allow_san_ip: false,
        allow_san_email: true, // Email required
        max_san_count: 5,
        require_key_usage: true,
        require_eku: true,
        allowed_ekus: vec![eku::EMAIL_PROTECTION.into()],
        require_approval: false,
        auto_approve_matching_patterns: Vec::new(),
        max_certs_per_day: None,
        max_certs_per_hour: None,
        enabled: true,
        priority: 5,
        ..Default::default()
    }
}

/// Create a DevOps/Automation policy with auto-approve for known patterns.
pub fn preset_devops(ca_id: Uuid, domain: &str) -> CaPolicy {
    CaPolicy {
        id: Uuid::new_v4(),
        ca_id,
        name: "DevOps Automation".into(),
        max_validity_days: Some(90), // Short-lived for automation
        min_validity_days: 1,
        allowed_algorithms: vec!["ECDSA-P256".into(), "ECDSA-P384".into()],
        min_rsa_bits: 2048,
        require_cn: true,
        require_org: false,
        require_country: false,
        allowed_cn_patterns: vec![format!(r".*\.{}$", regex::escape(domain))],
        denied_cn_patterns: Vec::new(),
        allowed_san_dns_patterns: vec![format!(r".*\.{}$", regex::escape(domain))],
        denied_san_dns_patterns: Vec::new(),
        allow_san_ip: true,
        allow_san_email: false,
        max_san_count: 20,
        require_key_usage: true,
        require_eku: true,
        allowed_ekus: vec![eku::SERVER_AUTH.into(), eku::CLIENT_AUTH.into()],
        require_approval: true,
        auto_approve_matching_patterns: vec![format!(r".*\.{}$", regex::escape(domain))],
        max_certs_per_day: Some(100),
        max_certs_per_hour: Some(20),
        enabled: true,
        priority: 15,
        ..Default::default()
    }
}

/// Get all available preset names.
pub fn available_presets() -> Vec<(&'static str, &'static str)> {
    vec![
        ("web_server", "Web Server TLS - CA/B Forum compliant"),
        (
            "internal_server",
            "Internal Server - Permissive internal use",
        ),
        (
            "client_auth",
            "Client Authentication - User/device certificates",
        ),
        (
            "code_signing",
            "Code Signing - Software signing with approval",
        ),
        ("email_smime", "Email S/MIME - Secure email"),
        (
            "devops",
            "DevOps Automation - Auto-approve for specific domain",
        ),
    ]
}

/// Create a policy from a preset name.
pub fn create_from_preset(
    ca_id: Uuid,
    preset_name: &str,
    domain: Option<&str>,
) -> Option<CaPolicy> {
    match preset_name {
        "web_server" => Some(preset_web_server(ca_id)),
        "internal_server" => Some(preset_internal_server(ca_id)),
        "client_auth" => Some(preset_client_auth(ca_id)),
        "code_signing" => Some(preset_code_signing(ca_id)),
        "email_smime" => Some(preset_email_smime(ca_id)),
        "devops" => domain.map(|d| preset_devops(ca_id, d)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_web_server_preset() {
        let policy = preset_web_server(Uuid::new_v4());
        assert_eq!(policy.name, "Web Server TLS");
        assert_eq!(policy.max_validity_days, Some(398));
        assert!(!policy.allow_san_ip);
        assert!(policy.require_approval);
    }

    #[test]
    fn test_internal_preset() {
        let policy = preset_internal_server(Uuid::new_v4());
        assert!(policy.allow_san_ip);
        assert!(!policy.require_approval);
    }

    #[test]
    fn test_devops_preset() {
        let policy = preset_devops(Uuid::new_v4(), "example.com");
        assert!(!policy.auto_approve_matching_patterns.is_empty());
        assert!(policy.allowed_cn_patterns[0].contains("example\\.com"));
    }

    #[test]
    fn test_available_presets() {
        let presets = available_presets();
        assert!(!presets.is_empty());
        assert!(presets.iter().any(|(name, _)| *name == "web_server"));
    }

    #[test]
    fn test_client_auth_preset() {
        let policy = preset_client_auth(Uuid::new_v4());
        assert_eq!(policy.name, "Client Authentication");
        assert_eq!(policy.max_validity_days, Some(365));
        assert!(!policy.allow_san_ip);
        assert!(policy.allow_san_email);
        assert_eq!(policy.max_san_count, 10);
        assert!(policy.allowed_ekus.contains(&eku::CLIENT_AUTH.to_string()));
    }

    #[test]
    fn test_code_signing_preset() {
        let policy = preset_code_signing(Uuid::new_v4());
        assert_eq!(policy.name, "Code Signing");
        assert_eq!(policy.max_validity_days, Some(365 * 3));
        assert_eq!(policy.min_rsa_bits, 4096);
        assert!(policy.require_org);
        assert!(policy.require_country);
        assert!(policy.require_approval);
        assert_eq!(policy.max_san_count, 1);
        assert_eq!(policy.max_certs_per_day, Some(10));
        assert_eq!(policy.max_certs_per_hour, Some(3));
    }

    #[test]
    fn test_email_smime_preset() {
        let policy = preset_email_smime(Uuid::new_v4());
        assert_eq!(policy.name, "Email S/MIME");
        assert_eq!(policy.max_validity_days, Some(365 * 2));
        assert!(policy.allow_san_email);
        assert!(!policy.allow_san_ip);
        assert_eq!(policy.max_san_count, 5);
        assert!(policy
            .allowed_ekus
            .contains(&eku::EMAIL_PROTECTION.to_string()));
    }

    #[test]
    fn test_devops_preset_domain_patterns() {
        let policy = preset_devops(Uuid::new_v4(), "rk.local");
        assert_eq!(policy.max_validity_days, Some(90));
        assert!(policy.allow_san_ip);
        assert_eq!(policy.max_certs_per_day, Some(100));
        assert_eq!(policy.max_certs_per_hour, Some(20));
        // Domain should be escaped in patterns
        assert!(policy.allowed_cn_patterns[0].contains("rk\\.local"));
        assert!(policy.auto_approve_matching_patterns[0].contains("rk\\.local"));
    }

    #[test]
    fn test_create_from_preset_valid() {
        let ca_id = Uuid::new_v4();
        assert!(create_from_preset(ca_id, "web_server", None).is_some());
        assert!(create_from_preset(ca_id, "internal_server", None).is_some());
        assert!(create_from_preset(ca_id, "client_auth", None).is_some());
        assert!(create_from_preset(ca_id, "code_signing", None).is_some());
        assert!(create_from_preset(ca_id, "email_smime", None).is_some());
    }

    #[test]
    fn test_create_from_preset_devops_needs_domain() {
        let ca_id = Uuid::new_v4();
        // DevOps without domain returns None
        assert!(create_from_preset(ca_id, "devops", None).is_none());
        // DevOps with domain returns Some
        assert!(create_from_preset(ca_id, "devops", Some("example.com")).is_some());
    }

    #[test]
    fn test_create_from_preset_unknown() {
        assert!(create_from_preset(Uuid::new_v4(), "nonexistent", None).is_none());
    }

    #[test]
    fn test_all_presets_have_unique_names() {
        let ca_id = Uuid::new_v4();
        let policies: Vec<CaPolicy> = vec![
            preset_web_server(ca_id),
            preset_internal_server(ca_id),
            preset_client_auth(ca_id),
            preset_code_signing(ca_id),
            preset_email_smime(ca_id),
            preset_devops(ca_id, "test.com"),
        ];
        let names: std::collections::HashSet<_> = policies.iter().map(|p| p.name.clone()).collect();
        assert_eq!(
            names.len(),
            policies.len(),
            "All presets should have unique names"
        );
    }

    #[test]
    fn test_available_presets_count() {
        let presets = available_presets();
        assert_eq!(presets.len(), 6);
        let names: Vec<_> = presets.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"web_server"));
        assert!(names.contains(&"internal_server"));
        assert!(names.contains(&"client_auth"));
        assert!(names.contains(&"code_signing"));
        assert!(names.contains(&"email_smime"));
        assert!(names.contains(&"devops"));
    }

    #[test]
    fn test_web_server_strict_security() {
        let policy = preset_web_server(Uuid::new_v4());
        // CA/B Forum: no IP SANs, no email SANs
        assert!(!policy.allow_san_ip);
        assert!(!policy.allow_san_email);
        // Require EKU
        assert!(policy.require_eku);
        // Only Server Auth
        assert_eq!(policy.allowed_ekus.len(), 1);
        assert_eq!(policy.allowed_ekus[0], eku::SERVER_AUTH);
    }

    #[test]
    fn test_internal_server_allows_pqc() {
        let policy = preset_internal_server(Uuid::new_v4());
        assert!(policy.allowed_algorithms.contains(&"ML-DSA-65".to_string()));
    }
}
