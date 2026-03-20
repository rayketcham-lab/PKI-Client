//! Recovery levels with configurable thresholds

use serde::{Deserialize, Serialize};

/// Recovery system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryConfig {
    /// Total shares (always 3)
    pub total_shares: u8,

    /// Level 1 threshold (minimum 2)
    pub level1_threshold: u8,

    /// Level 2 threshold (minimum 2, recommended 3)
    pub level2_threshold: u8,

    /// Level 1 session timeout (seconds)
    pub level1_timeout_secs: u64,

    /// Level 2 session timeout (seconds)
    pub level2_timeout_secs: u64,

    /// Custodian names (for documentation)
    pub custodians: [String; 3],
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            total_shares: 3,
            level1_threshold: 2,
            level2_threshold: 3,
            level1_timeout_secs: 900, // 15 minutes
            level2_timeout_secs: 600, // 10 minutes
            custodians: [String::new(), String::new(), String::new()],
        }
    }
}

impl RecoveryConfig {
    /// Validate configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.total_shares != 3 {
            return Err(ConfigError::InvalidValue("total_shares must be 3".into()));
        }

        if self.level1_threshold < 2 || self.level1_threshold > 3 {
            return Err(ConfigError::InvalidValue(
                "level1_threshold must be 2 or 3".into(),
            ));
        }

        if self.level2_threshold < 2 || self.level2_threshold > 3 {
            return Err(ConfigError::InvalidValue(
                "level2_threshold must be 2 or 3".into(),
            ));
        }

        if self.level2_threshold < self.level1_threshold {
            return Err(ConfigError::InvalidValue(
                "level2_threshold must be >= level1_threshold".into(),
            ));
        }

        Ok(())
    }

    /// Create with custom thresholds
    pub fn with_thresholds(level1: u8, level2: u8) -> Result<Self, ConfigError> {
        let config = Self {
            level1_threshold: level1,
            level2_threshold: level2,
            ..Default::default()
        };
        config.validate()?;
        Ok(config)
    }

    /// Set custodian names
    pub fn with_custodians(mut self, c1: &str, c2: &str, c3: &str) -> Self {
        self.custodians = [c1.to_string(), c2.to_string(), c3.to_string()];
        self
    }
}

/// Recovery level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryLevel {
    /// Operational recovery - view, unlock accounts
    Level1,
    /// Administrative recovery - password reset, create admin
    Level2,
}

impl RecoveryLevel {
    /// Get required shares for this level
    pub fn required_shares(&self, config: &RecoveryConfig) -> u8 {
        match self {
            RecoveryLevel::Level1 => config.level1_threshold,
            RecoveryLevel::Level2 => config.level2_threshold,
        }
    }

    /// Get session timeout for this level
    pub fn timeout_secs(&self, config: &RecoveryConfig) -> u64 {
        match self {
            RecoveryLevel::Level1 => config.level1_timeout_secs,
            RecoveryLevel::Level2 => config.level2_timeout_secs,
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            RecoveryLevel::Level1 => "Operational Recovery (Level 1)",
            RecoveryLevel::Level2 => "Administrative Recovery (Level 2)",
        }
    }

    /// Get description
    pub fn description(&self) -> &'static str {
        match self {
            RecoveryLevel::Level1 => "View status, unlock accounts, generate CRL",
            RecoveryLevel::Level2 => "Reset passwords, create admin, revoke certificates",
        }
    }
}

impl std::fmt::Display for RecoveryLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Actions available during recovery
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryAction {
    // Level 1 actions
    /// View CA status and health
    ViewCaStatus,
    /// View audit logs
    ViewAuditLogs,
    /// View certificate inventory
    ViewCertificates,
    /// Unlock locked user account
    UnlockAccount,
    /// Generate certificate revocation list
    GenerateCrl,

    // Level 2 actions
    /// Reset user password
    ResetPassword,
    /// Create emergency admin account
    CreateAdmin,
    /// Disable or delete user account
    DisableUser,
    /// Revoke certificate
    RevokeCertificate,
    /// Modify CA configuration
    ModifyCaConfig,
    /// Export CA certificate (public only)
    ExportCaCertificate,
}

impl RecoveryAction {
    /// Get the required recovery level for this action
    pub fn required_level(&self) -> RecoveryLevel {
        match self {
            // Level 1
            RecoveryAction::ViewCaStatus
            | RecoveryAction::ViewAuditLogs
            | RecoveryAction::ViewCertificates
            | RecoveryAction::UnlockAccount
            | RecoveryAction::GenerateCrl => RecoveryLevel::Level1,

            // Level 2
            RecoveryAction::ResetPassword
            | RecoveryAction::CreateAdmin
            | RecoveryAction::DisableUser
            | RecoveryAction::RevokeCertificate
            | RecoveryAction::ModifyCaConfig
            | RecoveryAction::ExportCaCertificate => RecoveryLevel::Level2,
        }
    }

    /// Get machine-readable name
    pub fn name(&self) -> &'static str {
        match self {
            RecoveryAction::ViewCaStatus => "view_ca_status",
            RecoveryAction::ViewAuditLogs => "view_audit_logs",
            RecoveryAction::ViewCertificates => "view_certificates",
            RecoveryAction::UnlockAccount => "unlock_account",
            RecoveryAction::GenerateCrl => "generate_crl",
            RecoveryAction::ResetPassword => "reset_password",
            RecoveryAction::CreateAdmin => "create_admin",
            RecoveryAction::DisableUser => "disable_user",
            RecoveryAction::RevokeCertificate => "revoke_certificate",
            RecoveryAction::ModifyCaConfig => "modify_ca_config",
            RecoveryAction::ExportCaCertificate => "export_ca_certificate",
        }
    }

    /// Get human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            RecoveryAction::ViewCaStatus => "View CA status and health",
            RecoveryAction::ViewAuditLogs => "View audit logs",
            RecoveryAction::ViewCertificates => "View certificate inventory",
            RecoveryAction::UnlockAccount => "Unlock locked user account",
            RecoveryAction::GenerateCrl => "Generate certificate revocation list",
            RecoveryAction::ResetPassword => "Reset user password",
            RecoveryAction::CreateAdmin => "Create emergency admin account",
            RecoveryAction::DisableUser => "Disable or delete user account",
            RecoveryAction::RevokeCertificate => "Revoke certificate",
            RecoveryAction::ModifyCaConfig => "Modify CA configuration",
            RecoveryAction::ExportCaCertificate => "Export CA certificate (public only)",
        }
    }

    /// Parse from name
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "view_ca_status" => Some(RecoveryAction::ViewCaStatus),
            "view_audit_logs" => Some(RecoveryAction::ViewAuditLogs),
            "view_certificates" => Some(RecoveryAction::ViewCertificates),
            "unlock_account" => Some(RecoveryAction::UnlockAccount),
            "generate_crl" => Some(RecoveryAction::GenerateCrl),
            "reset_password" => Some(RecoveryAction::ResetPassword),
            "create_admin" => Some(RecoveryAction::CreateAdmin),
            "disable_user" => Some(RecoveryAction::DisableUser),
            "revoke_certificate" => Some(RecoveryAction::RevokeCertificate),
            "modify_ca_config" => Some(RecoveryAction::ModifyCaConfig),
            "export_ca_certificate" => Some(RecoveryAction::ExportCaCertificate),
            _ => None,
        }
    }

    /// List all Level 1 actions
    pub fn level1_actions() -> &'static [RecoveryAction] {
        &[
            RecoveryAction::ViewCaStatus,
            RecoveryAction::ViewAuditLogs,
            RecoveryAction::ViewCertificates,
            RecoveryAction::UnlockAccount,
            RecoveryAction::GenerateCrl,
        ]
    }

    /// List all Level 2 actions
    pub fn level2_actions() -> &'static [RecoveryAction] {
        &[
            RecoveryAction::ResetPassword,
            RecoveryAction::CreateAdmin,
            RecoveryAction::DisableUser,
            RecoveryAction::RevokeCertificate,
            RecoveryAction::ModifyCaConfig,
            RecoveryAction::ExportCaCertificate,
        ]
    }
}

impl std::fmt::Display for RecoveryAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Configuration error
#[derive(Debug)]
pub enum ConfigError {
    /// Invalid configuration value
    InvalidValue(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::InvalidValue(msg) => write!(f, "Invalid config: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = RecoveryConfig::default();
        assert_eq!(config.total_shares, 3);
        assert_eq!(config.level1_threshold, 2);
        assert_eq!(config.level2_threshold, 3);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation() {
        // Valid configs
        assert!(RecoveryConfig::with_thresholds(2, 2).is_ok());
        assert!(RecoveryConfig::with_thresholds(2, 3).is_ok());
        assert!(RecoveryConfig::with_thresholds(3, 3).is_ok());

        // Invalid: level1 < 2
        let config = RecoveryConfig {
            level1_threshold: 1,
            ..RecoveryConfig::default()
        };
        assert!(config.validate().is_err());

        // Invalid: level2 < level1
        let config = RecoveryConfig {
            level1_threshold: 3,
            level2_threshold: 2,
            ..RecoveryConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_action_levels() {
        assert_eq!(
            RecoveryAction::ViewCaStatus.required_level(),
            RecoveryLevel::Level1
        );
        assert_eq!(
            RecoveryAction::CreateAdmin.required_level(),
            RecoveryLevel::Level2
        );
    }

    #[test]
    fn test_action_from_name() {
        assert_eq!(
            RecoveryAction::from_name("view_ca_status"),
            Some(RecoveryAction::ViewCaStatus)
        );
        assert_eq!(
            RecoveryAction::from_name("create_admin"),
            Some(RecoveryAction::CreateAdmin)
        );
        assert_eq!(RecoveryAction::from_name("invalid"), None);
    }

    #[test]
    fn test_level_actions_coverage() {
        // All Level 1 actions should have Level1 requirement
        for action in RecoveryAction::level1_actions() {
            assert_eq!(action.required_level(), RecoveryLevel::Level1);
        }

        // All Level 2 actions should have Level2 requirement
        for action in RecoveryAction::level2_actions() {
            assert_eq!(action.required_level(), RecoveryLevel::Level2);
        }
    }
}
