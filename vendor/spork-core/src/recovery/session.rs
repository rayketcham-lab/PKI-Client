//! Recovery session management

use super::{
    RecoveryAction, RecoveryConfig, RecoveryLevel, RecoveryShare, RecoveryShares, ShareError,
};
use std::time::Instant;

/// Active recovery session
pub struct RecoverySession {
    /// Session token (hex encoded)
    pub token: String,
    /// Recovery level
    pub level: RecoveryLevel,
    /// Which share numbers were used
    pub shares_used: Vec<u8>,
    /// When session was created
    created_at: Instant,
    /// When session expires
    expires_at: Instant,
}

impl RecoverySession {
    /// Create a new recovery session
    fn new(level: RecoveryLevel, shares_used: Vec<u8>, timeout_secs: u64) -> Self {
        let mut token_bytes = [0u8; 16];
        getrandom::getrandom(&mut token_bytes).expect("Failed to generate token");

        Self {
            token: hex::encode(token_bytes),
            level,
            shares_used,
            created_at: Instant::now(),
            expires_at: Instant::now() + std::time::Duration::from_secs(timeout_secs),
        }
    }

    /// Check if session is still valid
    pub fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
    }

    /// Get remaining seconds until expiration
    pub fn remaining_secs(&self) -> u64 {
        if !self.is_valid() {
            return 0;
        }
        self.expires_at.duration_since(Instant::now()).as_secs()
    }

    /// Check if session can perform a given action
    pub fn can_perform(&self, action: RecoveryAction) -> bool {
        if !self.is_valid() {
            return false;
        }

        match (self.level, action.required_level()) {
            // Level 2 can do anything
            (RecoveryLevel::Level2, _) => true,
            // Level 1 can only do Level 1 actions
            (RecoveryLevel::Level1, RecoveryLevel::Level1) => true,
            (RecoveryLevel::Level1, RecoveryLevel::Level2) => false,
        }
    }

    /// Get session age in seconds
    pub fn age_secs(&self) -> u64 {
        Instant::now().duration_since(self.created_at).as_secs()
    }
}

impl std::fmt::Debug for RecoverySession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoverySession")
            .field("token", &format!("{}...", &self.token[..8]))
            .field("level", &self.level)
            .field("shares_used", &self.shares_used)
            .field("remaining_secs", &self.remaining_secs())
            .finish()
    }
}

/// Session manager
pub struct RecoverySessionManager {
    /// Configuration
    config: RecoveryConfig,
    /// Stored hash for verification
    stored_hash: String,
    /// Currently active session (if any)
    active_session: Option<RecoverySession>,
}

impl RecoverySessionManager {
    /// Create a new session manager
    pub fn new(config: RecoveryConfig, stored_hash: String) -> Self {
        Self {
            config,
            stored_hash,
            active_session: None,
        }
    }

    /// Start a recovery session with provided shares
    pub fn start_session(
        &mut self,
        shares: Vec<RecoveryShare>,
        requested_level: RecoveryLevel,
    ) -> Result<&RecoverySession, SessionError> {
        // Check share count for requested level
        let required = requested_level.required_shares(&self.config) as usize;
        if shares.len() < required {
            return Err(SessionError::InsufficientShares {
                required,
                provided: shares.len(),
            });
        }

        // Verify shares
        let valid = RecoveryShares::verify_shares(&shares, &self.stored_hash)
            .map_err(SessionError::ShareError)?;

        if !valid {
            return Err(SessionError::InvalidShares);
        }

        // Record which shares were used
        let shares_used: Vec<u8> = shares.iter().map(|s| s.number).collect();

        // Create session
        let timeout = requested_level.timeout_secs(&self.config);
        let session = RecoverySession::new(requested_level, shares_used, timeout);

        self.active_session = Some(session);

        Ok(self.active_session.as_ref().unwrap())
    }

    /// Get active session if valid
    pub fn get_session(&self) -> Option<&RecoverySession> {
        self.active_session.as_ref().filter(|s| s.is_valid())
    }

    /// Get active session mutably if valid
    pub fn get_session_mut(&mut self) -> Option<&mut RecoverySession> {
        self.active_session.as_mut().filter(|s| s.is_valid())
    }

    /// Check if there's an active session
    pub fn has_active_session(&self) -> bool {
        self.get_session().is_some()
    }

    /// End current session
    pub fn end_session(&mut self) {
        self.active_session = None;
    }

    /// Execute action in current session (validates permissions)
    pub fn execute_action(&self, action: RecoveryAction) -> Result<(), SessionError> {
        let session = self
            .active_session
            .as_ref()
            .ok_or(SessionError::NoActiveSession)?;

        if !session.is_valid() {
            return Err(SessionError::SessionExpired);
        }

        if !session.can_perform(action) {
            return Err(SessionError::InsufficientLevel {
                required: action.required_level(),
                current: session.level,
            });
        }

        Ok(())
    }

    /// Get current session token (if active)
    pub fn current_token(&self) -> Option<&str> {
        self.get_session().map(|s| s.token.as_str())
    }

    /// Validate a token matches the current session
    pub fn validate_token(&self, token: &str) -> bool {
        self.get_session()
            .map(|s| s.token == token)
            .unwrap_or(false)
    }

    /// Get the configuration
    pub fn config(&self) -> &RecoveryConfig {
        &self.config
    }
}

/// Session errors
#[derive(Debug)]
pub enum SessionError {
    /// No active recovery session
    NoActiveSession,
    /// Recovery session expired
    SessionExpired,
    /// Invalid recovery shares
    InvalidShares,
    /// Insufficient shares for requested level
    InsufficientShares {
        /// Required number of shares
        required: usize,
        /// Number provided
        provided: usize,
    },
    /// Insufficient level for action
    InsufficientLevel {
        /// Required level
        required: RecoveryLevel,
        /// Current level
        current: RecoveryLevel,
    },
    /// Share-related error
    ShareError(ShareError),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::NoActiveSession => write!(f, "No active recovery session"),
            SessionError::SessionExpired => write!(f, "Recovery session expired"),
            SessionError::InvalidShares => write!(f, "Invalid recovery shares"),
            SessionError::InsufficientShares { required, provided } => {
                write!(
                    f,
                    "Insufficient shares: {} required, {} provided",
                    required, provided
                )
            }
            SessionError::InsufficientLevel { required, current } => {
                write!(
                    f,
                    "Insufficient level: {:?} required, {:?} current",
                    required, current
                )
            }
            SessionError::ShareError(e) => write!(f, "Share error: {}", e),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SessionError::ShareError(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_manager() -> (RecoverySessionManager, RecoveryShares) {
        let shares = RecoveryShares::generate("Alice", "Bob", "Charlie").unwrap();
        let manager =
            RecoverySessionManager::new(RecoveryConfig::default(), shares.secret_hash.clone());
        (manager, shares)
    }

    #[test]
    fn test_start_level1_session() {
        let (mut manager, shares) = create_test_manager();

        // 2 shares should work for Level 1
        let result = manager.start_session(
            vec![shares.shares[0].clone(), shares.shares[1].clone()],
            RecoveryLevel::Level1,
        );

        assert!(result.is_ok());
        assert!(manager.has_active_session());
    }

    #[test]
    fn test_start_level2_session() {
        let (mut manager, shares) = create_test_manager();

        // Need 3 shares for Level 2 (default config)
        let result = manager.start_session(
            vec![
                shares.shares[0].clone(),
                shares.shares[1].clone(),
                shares.shares[2].clone(),
            ],
            RecoveryLevel::Level2,
        );

        assert!(result.is_ok());
        let session = manager.get_session().unwrap();
        assert_eq!(session.level, RecoveryLevel::Level2);
    }

    #[test]
    fn test_insufficient_shares_for_level2() {
        let (mut manager, shares) = create_test_manager();

        // Only 2 shares for Level 2 should fail
        let result = manager.start_session(
            vec![shares.shares[0].clone(), shares.shares[1].clone()],
            RecoveryLevel::Level2,
        );

        assert!(matches!(
            result,
            Err(SessionError::InsufficientShares {
                required: 3,
                provided: 2
            })
        ));
    }

    #[test]
    fn test_action_permissions() {
        let (mut manager, shares) = create_test_manager();

        // Start Level 1 session
        manager
            .start_session(
                vec![shares.shares[0].clone(), shares.shares[1].clone()],
                RecoveryLevel::Level1,
            )
            .unwrap();

        // Level 1 action should work
        assert!(manager.execute_action(RecoveryAction::ViewCaStatus).is_ok());

        // Level 2 action should fail
        assert!(matches!(
            manager.execute_action(RecoveryAction::CreateAdmin),
            Err(SessionError::InsufficientLevel { .. })
        ));
    }

    #[test]
    fn test_end_session() {
        let (mut manager, shares) = create_test_manager();

        manager
            .start_session(
                vec![shares.shares[0].clone(), shares.shares[1].clone()],
                RecoveryLevel::Level1,
            )
            .unwrap();

        assert!(manager.has_active_session());

        manager.end_session();

        assert!(!manager.has_active_session());
        assert!(matches!(
            manager.execute_action(RecoveryAction::ViewCaStatus),
            Err(SessionError::NoActiveSession)
        ));
    }

    #[test]
    fn test_token_validation() {
        let (mut manager, shares) = create_test_manager();

        manager
            .start_session(
                vec![shares.shares[0].clone(), shares.shares[1].clone()],
                RecoveryLevel::Level1,
            )
            .unwrap();

        let token = manager.current_token().unwrap().to_string();
        assert!(manager.validate_token(&token));
        assert!(!manager.validate_token("invalid-token"));
    }

    #[test]
    fn test_level2_can_do_level1_actions() {
        let (mut manager, shares) = create_test_manager();

        // Start Level 2 session
        manager
            .start_session(
                vec![
                    shares.shares[0].clone(),
                    shares.shares[1].clone(),
                    shares.shares[2].clone(),
                ],
                RecoveryLevel::Level2,
            )
            .unwrap();

        // Both Level 1 and Level 2 actions should work
        assert!(manager.execute_action(RecoveryAction::ViewCaStatus).is_ok());
        assert!(manager.execute_action(RecoveryAction::CreateAdmin).is_ok());
    }

    // ===== Session-level threshold enforcement =====

    /// Providing 1 share for Level1 (which requires 2) must fail with
    /// InsufficientShares { required: 2, provided: 1 }.
    /// This verifies the session manager enforces the threshold before
    /// attempting Shamir reconstruction.
    #[test]
    fn test_one_share_for_level1_returns_insufficient() {
        let (mut manager, shares) = create_test_manager();

        let result = manager.start_session(vec![shares.shares[0].clone()], RecoveryLevel::Level1);

        assert!(
            matches!(
                result,
                Err(SessionError::InsufficientShares {
                    required: 2,
                    provided: 1
                })
            ),
            "Expected InsufficientShares {{ required: 2, provided: 1 }}, got: {:?}",
            result
        );
    }

    /// Providing zero shares for Level1 must fail with
    /// InsufficientShares { required: 2, provided: 0 }.
    #[test]
    fn test_zero_shares_for_level1_returns_insufficient() {
        let (mut manager, _shares) = create_test_manager();

        let result = manager.start_session(vec![], RecoveryLevel::Level1);

        assert!(
            matches!(
                result,
                Err(SessionError::InsufficientShares {
                    required: 2,
                    provided: 0
                })
            ),
            "Expected InsufficientShares {{ required: 2, provided: 0 }}, got: {:?}",
            result
        );
    }

    /// Providing zero shares for Level2 must fail with
    /// InsufficientShares { required: 3, provided: 0 }.
    #[test]
    fn test_zero_shares_for_level2_returns_insufficient() {
        let (mut manager, _shares) = create_test_manager();

        let result = manager.start_session(vec![], RecoveryLevel::Level2);

        assert!(
            matches!(
                result,
                Err(SessionError::InsufficientShares {
                    required: 3,
                    provided: 0
                })
            ),
            "Expected InsufficientShares {{ required: 3, provided: 0 }}, got: {:?}",
            result
        );
    }
}
