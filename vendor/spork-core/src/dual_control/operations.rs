//! Operation definitions and categories

use super::ControlLevel;
use serde::{Deserialize, Serialize};

/// Operation category with default/min/max control levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperationCategory {
    /// Critical CA operations - cannot lower below DUAL
    CriticalCa,
    /// High-impact operations
    HighImpact,
    /// Standard operations
    Standard,
    /// Low-impact (view only)
    LowImpact,
}

impl OperationCategory {
    /// Get default control level for this category
    pub fn default_level(&self) -> ControlLevel {
        match self {
            OperationCategory::CriticalCa => ControlLevel::Triple,
            OperationCategory::HighImpact => ControlLevel::Dual,
            OperationCategory::Standard => ControlLevel::Single,
            OperationCategory::LowImpact => ControlLevel::Single,
        }
    }

    /// Get minimum control level (hard limit, cannot be lowered)
    pub fn minimum_level(&self) -> ControlLevel {
        match self {
            OperationCategory::CriticalCa => ControlLevel::Dual, // HARD MINIMUM
            OperationCategory::HighImpact => ControlLevel::Single,
            OperationCategory::Standard => ControlLevel::Single,
            OperationCategory::LowImpact => ControlLevel::Single,
        }
    }

    /// Get maximum control level (cannot be raised above)
    pub fn maximum_level(&self) -> ControlLevel {
        match self {
            OperationCategory::CriticalCa => ControlLevel::Triple,
            OperationCategory::HighImpact => ControlLevel::Triple,
            OperationCategory::Standard => ControlLevel::Dual,
            OperationCategory::LowImpact => ControlLevel::Single,
        }
    }

    /// Get category name
    pub fn name(&self) -> &'static str {
        match self {
            OperationCategory::CriticalCa => "Critical CA",
            OperationCategory::HighImpact => "High Impact",
            OperationCategory::Standard => "Standard",
            OperationCategory::LowImpact => "Low Impact",
        }
    }

    /// Get category description
    pub fn description(&self) -> &'static str {
        match self {
            OperationCategory::CriticalCa => "Critical CA operations (key export, CA revocation)",
            OperationCategory::HighImpact => {
                "High impact operations (policy changes, user management)"
            }
            OperationCategory::Standard => "Standard operations (certificate issuance)",
            OperationCategory::LowImpact => "Low impact operations (read-only, status checks)",
        }
    }
}

impl std::fmt::Display for OperationCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Specific operations
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operation {
    // Critical CA (DUAL minimum, TRIPLE default)
    /// Create Root CA
    CreateRootCa,
    /// Revoke CA certificate
    RevokeCa,
    /// Destroy CA private key
    DestroyCaKey,
    /// Export CA private key
    ExportCaPrivateKey,
    /// Modify recovery shares
    ModifyRecoveryShares,

    // High Impact (SINGLE minimum, DUAL default)
    /// Create Intermediate CA
    CreateIntermediateCa,
    /// Cross-certification
    CrossCertification,
    /// Mass certificate revocation
    MassRevocation,
    /// Modify certificate template
    ModifyTemplate,
    /// Modify CA policy
    ModifyPolicy,
    /// Create admin user
    CreateAdminUser,
    /// Reset user password
    ResetUserPassword,

    // Standard (SINGLE minimum, SINGLE default)
    /// Issue certificate
    IssueCertificate,
    /// Revoke single certificate
    RevokeCertificate,
    /// Generate CRL
    GenerateCrl,
    /// Create user
    CreateUser,
    /// Modify user
    ModifyUser,

    // Low Impact (SINGLE only)
    /// View certificate
    ViewCertificate,
    /// View audit log
    ViewAuditLog,
    /// View configuration
    ViewConfig,
    /// Generate report
    GenerateReport,
}

impl Operation {
    /// Get the category for this operation
    pub fn category(&self) -> OperationCategory {
        match self {
            // Critical CA
            Operation::CreateRootCa
            | Operation::RevokeCa
            | Operation::DestroyCaKey
            | Operation::ExportCaPrivateKey
            | Operation::ModifyRecoveryShares => OperationCategory::CriticalCa,

            // High Impact
            Operation::CreateIntermediateCa
            | Operation::CrossCertification
            | Operation::MassRevocation
            | Operation::ModifyTemplate
            | Operation::ModifyPolicy
            | Operation::CreateAdminUser
            | Operation::ResetUserPassword => OperationCategory::HighImpact,

            // Standard
            Operation::IssueCertificate
            | Operation::RevokeCertificate
            | Operation::GenerateCrl
            | Operation::CreateUser
            | Operation::ModifyUser => OperationCategory::Standard,

            // Low Impact
            Operation::ViewCertificate
            | Operation::ViewAuditLog
            | Operation::ViewConfig
            | Operation::GenerateReport => OperationCategory::LowImpact,
        }
    }

    /// Get machine-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Operation::CreateRootCa => "ca.create_root",
            Operation::RevokeCa => "ca.revoke",
            Operation::DestroyCaKey => "ca.destroy_key",
            Operation::ExportCaPrivateKey => "ca.export_private_key",
            Operation::ModifyRecoveryShares => "recovery.modify_shares",
            Operation::CreateIntermediateCa => "ca.create_intermediate",
            Operation::CrossCertification => "ca.cross_certify",
            Operation::MassRevocation => "certificate.mass_revoke",
            Operation::ModifyTemplate => "template.modify",
            Operation::ModifyPolicy => "policy.modify",
            Operation::CreateAdminUser => "user.create_admin",
            Operation::ResetUserPassword => "user.reset_password",
            Operation::IssueCertificate => "certificate.issue",
            Operation::RevokeCertificate => "certificate.revoke",
            Operation::GenerateCrl => "crl.generate",
            Operation::CreateUser => "user.create",
            Operation::ModifyUser => "user.modify",
            Operation::ViewCertificate => "certificate.view",
            Operation::ViewAuditLog => "audit.view",
            Operation::ViewConfig => "config.view",
            Operation::GenerateReport => "report.generate",
        }
    }

    /// Parse from name
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ca.create_root" => Some(Operation::CreateRootCa),
            "ca.revoke" => Some(Operation::RevokeCa),
            "ca.destroy_key" => Some(Operation::DestroyCaKey),
            "ca.export_private_key" => Some(Operation::ExportCaPrivateKey),
            "recovery.modify_shares" => Some(Operation::ModifyRecoveryShares),
            "ca.create_intermediate" => Some(Operation::CreateIntermediateCa),
            "ca.cross_certify" => Some(Operation::CrossCertification),
            "certificate.mass_revoke" => Some(Operation::MassRevocation),
            "template.modify" => Some(Operation::ModifyTemplate),
            "policy.modify" => Some(Operation::ModifyPolicy),
            "user.create_admin" => Some(Operation::CreateAdminUser),
            "user.reset_password" => Some(Operation::ResetUserPassword),
            "certificate.issue" => Some(Operation::IssueCertificate),
            "certificate.revoke" => Some(Operation::RevokeCertificate),
            "crl.generate" => Some(Operation::GenerateCrl),
            "user.create" => Some(Operation::CreateUser),
            "user.modify" => Some(Operation::ModifyUser),
            "certificate.view" => Some(Operation::ViewCertificate),
            "audit.view" => Some(Operation::ViewAuditLog),
            "config.view" => Some(Operation::ViewConfig),
            "report.generate" => Some(Operation::GenerateReport),
            _ => None,
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Operation::CreateRootCa => "Create Root CA",
            Operation::RevokeCa => "Revoke CA certificate",
            Operation::DestroyCaKey => "Destroy CA private key",
            Operation::ExportCaPrivateKey => "Export CA private key",
            Operation::ModifyRecoveryShares => "Modify recovery shares",
            Operation::CreateIntermediateCa => "Create Intermediate CA",
            Operation::CrossCertification => "Cross-certification",
            Operation::MassRevocation => "Mass certificate revocation",
            Operation::ModifyTemplate => "Modify certificate template",
            Operation::ModifyPolicy => "Modify CA policy",
            Operation::CreateAdminUser => "Create admin user",
            Operation::ResetUserPassword => "Reset user password",
            Operation::IssueCertificate => "Issue certificate",
            Operation::RevokeCertificate => "Revoke certificate",
            Operation::GenerateCrl => "Generate CRL",
            Operation::CreateUser => "Create user",
            Operation::ModifyUser => "Modify user",
            Operation::ViewCertificate => "View certificate",
            Operation::ViewAuditLog => "View audit log",
            Operation::ViewConfig => "View configuration",
            Operation::GenerateReport => "Generate report",
        }
    }

    /// Get all operations in a category
    pub fn by_category(category: OperationCategory) -> Vec<Operation> {
        Self::all()
            .into_iter()
            .filter(|op| op.category() == category)
            .collect()
    }

    /// Get all operations
    pub fn all() -> Vec<Operation> {
        vec![
            Operation::CreateRootCa,
            Operation::RevokeCa,
            Operation::DestroyCaKey,
            Operation::ExportCaPrivateKey,
            Operation::ModifyRecoveryShares,
            Operation::CreateIntermediateCa,
            Operation::CrossCertification,
            Operation::MassRevocation,
            Operation::ModifyTemplate,
            Operation::ModifyPolicy,
            Operation::CreateAdminUser,
            Operation::ResetUserPassword,
            Operation::IssueCertificate,
            Operation::RevokeCertificate,
            Operation::GenerateCrl,
            Operation::CreateUser,
            Operation::ModifyUser,
            Operation::ViewCertificate,
            Operation::ViewAuditLog,
            Operation::ViewConfig,
            Operation::GenerateReport,
        ]
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_critical_ca_minimum() {
        // Critical CA operations must have DUAL minimum
        let critical_ops = Operation::by_category(OperationCategory::CriticalCa);
        for op in critical_ops {
            assert_eq!(
                op.category().minimum_level(),
                ControlLevel::Dual,
                "Operation {} should have DUAL minimum",
                op.name()
            );
        }
    }

    #[test]
    fn test_operation_from_name() {
        assert_eq!(
            Operation::from_name("ca.create_root"),
            Some(Operation::CreateRootCa)
        );
        assert_eq!(
            Operation::from_name("certificate.issue"),
            Some(Operation::IssueCertificate)
        );
        assert_eq!(Operation::from_name("invalid"), None);
    }

    #[test]
    fn test_category_levels() {
        let category = OperationCategory::CriticalCa;
        assert_eq!(category.default_level(), ControlLevel::Triple);
        assert_eq!(category.minimum_level(), ControlLevel::Dual);
        assert_eq!(category.maximum_level(), ControlLevel::Triple);
    }

    #[test]
    fn test_all_operations_have_categories() {
        for op in Operation::all() {
            // Should not panic
            let _ = op.category();
            let _ = op.name();
            let _ = op.description();
        }
    }

    #[test]
    fn test_all_operations_round_trip_name() {
        for op in Operation::all() {
            let name = op.name();
            let restored = Operation::from_name(name);
            assert_eq!(
                restored,
                Some(op.clone()),
                "Operation::from_name({:?}) should return {:?}",
                name,
                op
            );
        }
    }

    #[test]
    fn test_operation_count() {
        let all = Operation::all();
        assert_eq!(all.len(), 21);
    }

    #[test]
    fn test_by_category_counts() {
        let critical = Operation::by_category(OperationCategory::CriticalCa);
        assert_eq!(critical.len(), 5);

        let high = Operation::by_category(OperationCategory::HighImpact);
        assert_eq!(high.len(), 7);

        let standard = Operation::by_category(OperationCategory::Standard);
        assert_eq!(standard.len(), 5);

        let low = Operation::by_category(OperationCategory::LowImpact);
        assert_eq!(low.len(), 4);

        // Total should be 21
        assert_eq!(critical.len() + high.len() + standard.len() + low.len(), 21);
    }

    #[test]
    fn test_category_name_and_description() {
        assert_eq!(OperationCategory::CriticalCa.name(), "Critical CA");
        assert_eq!(OperationCategory::HighImpact.name(), "High Impact");
        assert_eq!(OperationCategory::Standard.name(), "Standard");
        assert_eq!(OperationCategory::LowImpact.name(), "Low Impact");

        // Description should be non-empty
        for cat in [
            OperationCategory::CriticalCa,
            OperationCategory::HighImpact,
            OperationCategory::Standard,
            OperationCategory::LowImpact,
        ] {
            assert!(!cat.description().is_empty());
        }
    }

    #[test]
    fn test_category_display() {
        assert_eq!(OperationCategory::CriticalCa.to_string(), "Critical CA");
        assert_eq!(OperationCategory::LowImpact.to_string(), "Low Impact");
    }

    #[test]
    fn test_operation_display() {
        assert_eq!(Operation::CreateRootCa.to_string(), "Create Root CA");
        assert_eq!(Operation::IssueCertificate.to_string(), "Issue certificate");
        assert_eq!(Operation::ViewAuditLog.to_string(), "View audit log");
    }

    #[test]
    fn test_low_impact_single_only() {
        let cat = OperationCategory::LowImpact;
        assert_eq!(cat.default_level(), ControlLevel::Single);
        assert_eq!(cat.minimum_level(), ControlLevel::Single);
        assert_eq!(cat.maximum_level(), ControlLevel::Single);
    }

    #[test]
    fn test_standard_levels() {
        let cat = OperationCategory::Standard;
        assert_eq!(cat.default_level(), ControlLevel::Single);
        assert_eq!(cat.minimum_level(), ControlLevel::Single);
        assert_eq!(cat.maximum_level(), ControlLevel::Dual);
    }

    #[test]
    fn test_high_impact_levels() {
        let cat = OperationCategory::HighImpact;
        assert_eq!(cat.default_level(), ControlLevel::Dual);
        assert_eq!(cat.minimum_level(), ControlLevel::Single);
        assert_eq!(cat.maximum_level(), ControlLevel::Triple);
    }
}
