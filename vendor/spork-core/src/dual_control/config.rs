//! Dual control configuration

use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Control level for operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[derive(Default)]
pub enum ControlLevel {
    /// Single person can execute
    #[default]
    Single,
    /// Two people required
    Dual,
    /// Three people required
    Triple,
}

impl ControlLevel {
    /// Get number of approvers required
    pub fn required_approvers(&self) -> usize {
        match self {
            ControlLevel::Single => 1,
            ControlLevel::Dual => 2,
            ControlLevel::Triple => 3,
        }
    }

    /// Get all control levels
    pub fn all() -> &'static [ControlLevel] {
        &[
            ControlLevel::Single,
            ControlLevel::Dual,
            ControlLevel::Triple,
        ]
    }
}

impl FromStr for ControlLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "SINGLE" => Ok(ControlLevel::Single),
            "DUAL" => Ok(ControlLevel::Dual),
            "TRIPLE" => Ok(ControlLevel::Triple),
            _ => Err(format!("Unknown control level: {}", s)),
        }
    }
}

impl std::fmt::Display for ControlLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlLevel::Single => write!(f, "SINGLE"),
            ControlLevel::Dual => write!(f, "DUAL"),
            ControlLevel::Triple => write!(f, "TRIPLE"),
        }
    }
}

/// Dual control system configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualControlConfig {
    /// Approval request timeout (seconds)
    pub approval_timeout_secs: u64,

    /// Require different users for each approval
    pub require_different_users: bool,

    /// Require different sessions for each approval
    pub require_different_sessions: bool,
}

impl Default for DualControlConfig {
    fn default() -> Self {
        Self {
            approval_timeout_secs: 600, // 10 minutes
            require_different_users: true,
            require_different_sessions: true,
        }
    }
}

impl DualControlConfig {
    /// Create with custom timeout
    pub fn with_timeout(timeout_secs: u64) -> Self {
        Self {
            approval_timeout_secs: timeout_secs,
            ..Default::default()
        }
    }

    /// Allow same user to approve multiple times (for testing)
    pub fn allow_same_user(mut self) -> Self {
        self.require_different_users = false;
        self
    }

    /// Allow same session to approve multiple times
    pub fn allow_same_session(mut self) -> Self {
        self.require_different_sessions = false;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_level_approvers() {
        assert_eq!(ControlLevel::Single.required_approvers(), 1);
        assert_eq!(ControlLevel::Dual.required_approvers(), 2);
        assert_eq!(ControlLevel::Triple.required_approvers(), 3);
    }

    #[test]
    fn test_control_level_from_str() {
        assert_eq!(ControlLevel::from_str("SINGLE"), Ok(ControlLevel::Single));
        assert_eq!(ControlLevel::from_str("dual"), Ok(ControlLevel::Dual));
        assert_eq!(ControlLevel::from_str("Triple"), Ok(ControlLevel::Triple));
        assert!(ControlLevel::from_str("invalid").is_err());
    }

    #[test]
    fn test_control_level_display() {
        assert_eq!(ControlLevel::Single.to_string(), "SINGLE");
        assert_eq!(ControlLevel::Dual.to_string(), "DUAL");
        assert_eq!(ControlLevel::Triple.to_string(), "TRIPLE");
    }

    #[test]
    fn test_default_config() {
        let config = DualControlConfig::default();
        assert_eq!(config.approval_timeout_secs, 600);
        assert!(config.require_different_users);
        assert!(config.require_different_sessions);
    }

    #[test]
    fn test_config_with_timeout() {
        let config = DualControlConfig::with_timeout(300);
        assert_eq!(config.approval_timeout_secs, 300);
        assert!(config.require_different_users);
        assert!(config.require_different_sessions);
    }

    #[test]
    fn test_config_builder_chain() {
        let config = DualControlConfig::with_timeout(120)
            .allow_same_user()
            .allow_same_session();
        assert_eq!(config.approval_timeout_secs, 120);
        assert!(!config.require_different_users);
        assert!(!config.require_different_sessions);
    }

    #[test]
    fn test_control_level_default() {
        assert_eq!(ControlLevel::default(), ControlLevel::Single);
    }

    #[test]
    fn test_control_level_all() {
        let levels = ControlLevel::all();
        assert_eq!(levels.len(), 3);
        assert_eq!(levels[0], ControlLevel::Single);
        assert_eq!(levels[1], ControlLevel::Dual);
        assert_eq!(levels[2], ControlLevel::Triple);
    }

    #[test]
    fn test_control_level_serde_roundtrip() {
        for level in ControlLevel::all() {
            let json = serde_json::to_string(level).unwrap();
            let restored: ControlLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(&restored, level);
        }
    }

    #[test]
    fn test_control_level_serde_uppercase() {
        let json = serde_json::to_string(&ControlLevel::Dual).unwrap();
        assert_eq!(json, "\"DUAL\"");
    }

    #[test]
    fn test_control_level_from_str_case_insensitive() {
        assert_eq!(ControlLevel::from_str("single"), Ok(ControlLevel::Single));
        assert_eq!(ControlLevel::from_str("SINGLE"), Ok(ControlLevel::Single));
        assert_eq!(ControlLevel::from_str("Single"), Ok(ControlLevel::Single));
        assert_eq!(ControlLevel::from_str("sInGlE"), Ok(ControlLevel::Single));
    }
}
