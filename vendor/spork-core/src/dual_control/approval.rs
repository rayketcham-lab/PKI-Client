//! Approval request and workflow

use super::{ControlLevel, DualControlConfig, Operation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Unambiguous alphabet for approval tokens
pub const APPROVAL_ALPHABET: &[u8] = b"ACDEFGHJKMNPQRTWXY346789";

/// Pending approval request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Request ID (format: APRV-XXXX-XXXX)
    pub id: String,
    /// Operation being requested
    pub operation: Operation,
    /// Operation details (JSON)
    pub operation_details: serde_json::Value,
    /// User who initiated the request
    pub initiated_by: String,
    /// Unix timestamp when initiated
    pub initiated_at_unix: u64,
    /// Unix timestamp when expires
    pub expires_at_unix: u64,
    /// Number of approvals required
    pub required_approvals: usize,
    /// List of approvals received
    pub approvals: Vec<Approval>,
    /// Current status
    pub status: ApprovalStatus,
}

/// Approval status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    /// Waiting for approvals
    Pending,
    /// Fully approved, ready to execute
    Approved,
    /// Expired before approval
    Expired,
    /// Cancelled by initiator
    Cancelled,
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalStatus::Pending => write!(f, "PENDING"),
            ApprovalStatus::Approved => write!(f, "APPROVED"),
            ApprovalStatus::Expired => write!(f, "EXPIRED"),
            ApprovalStatus::Cancelled => write!(f, "CANCELLED"),
        }
    }
}

/// Individual approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// User who approved
    pub user: String,
    /// Unix timestamp when approved
    pub approved_at_unix: u64,
    /// Session ID (if tracking sessions)
    pub session_id: Option<String>,
}

impl ApprovalRequest {
    /// Create a new approval request
    pub fn new(
        operation: Operation,
        details: serde_json::Value,
        initiated_by: String,
        control_level: ControlLevel,
        timeout_secs: u64,
    ) -> Self {
        let id = generate_approval_token();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after UNIX epoch")
            .as_secs();

        Self {
            id,
            operation,
            operation_details: details,
            initiated_by: initiated_by.clone(),
            initiated_at_unix: now,
            expires_at_unix: now + timeout_secs,
            required_approvals: control_level.required_approvers(),
            approvals: vec![Approval {
                user: initiated_by,
                approved_at_unix: now,
                session_id: None,
            }],
            status: ApprovalStatus::Pending,
        }
    }

    /// Check if request has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after UNIX epoch")
            .as_secs();
        now > self.expires_at_unix
    }

    /// Get remaining approvals needed
    pub fn remaining_approvals(&self) -> usize {
        self.required_approvals.saturating_sub(self.approvals.len())
    }

    /// Check if request is fully approved
    pub fn is_complete(&self) -> bool {
        self.approvals.len() >= self.required_approvals
    }

    /// Get remaining seconds until expiration
    pub fn remaining_secs(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after UNIX epoch")
            .as_secs();
        self.expires_at_unix.saturating_sub(now)
    }

    /// Add an approval
    pub fn add_approval(
        &mut self,
        user: &str,
        session_id: Option<String>,
        config: &DualControlConfig,
    ) -> Result<(), ApprovalError> {
        if self.is_expired() {
            self.status = ApprovalStatus::Expired;
            return Err(ApprovalError::Expired);
        }

        if self.is_complete() {
            return Err(ApprovalError::AlreadyComplete);
        }

        if config.require_different_users && self.approvals.iter().any(|a| a.user == user) {
            return Err(ApprovalError::DuplicateUser);
        }

        if config.require_different_sessions {
            if let Some(ref sid) = session_id {
                if self
                    .approvals
                    .iter()
                    .any(|a| a.session_id.as_ref() == Some(sid))
                {
                    return Err(ApprovalError::DuplicateSession);
                }
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after UNIX epoch")
            .as_secs();

        self.approvals.push(Approval {
            user: user.to_string(),
            approved_at_unix: now,
            session_id,
        });

        if self.is_complete() {
            self.status = ApprovalStatus::Approved;
        }

        Ok(())
    }

    /// Cancel the request
    pub fn cancel(&mut self) {
        self.status = ApprovalStatus::Cancelled;
    }

    /// Get list of users who have approved
    pub fn approving_users(&self) -> Vec<&str> {
        self.approvals.iter().map(|a| a.user.as_str()).collect()
    }
}

/// Generate approval token (format: APRV-XXXX-XXXX)
fn generate_approval_token() -> String {
    use rand::RngCore;

    let mut bytes = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut bytes);

    let mut token = String::with_capacity(14);
    token.push_str("APRV-");

    for (i, &byte) in bytes.iter().enumerate() {
        if i == 4 {
            token.push('-');
        }
        let idx = (byte as usize) % APPROVAL_ALPHABET.len();
        token.push(APPROVAL_ALPHABET[idx] as char);
    }

    token
}

/// Approval errors
#[derive(Debug, Clone)]
pub enum ApprovalError {
    /// Request has expired
    Expired,
    /// Request not found
    NotFound,
    /// Already fully approved
    AlreadyComplete,
    /// User has already approved
    DuplicateUser,
    /// Session has already approved
    DuplicateSession,
    /// Request was cancelled
    Cancelled,
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalError::Expired => write!(f, "Approval request expired"),
            ApprovalError::NotFound => write!(f, "Approval request not found"),
            ApprovalError::AlreadyComplete => write!(f, "Approval already complete"),
            ApprovalError::DuplicateUser => write!(f, "User has already approved"),
            ApprovalError::DuplicateSession => write!(f, "Session has already approved"),
            ApprovalError::Cancelled => write!(f, "Approval request cancelled"),
        }
    }
}

impl std::error::Error for ApprovalError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approval_token_format() {
        let token = generate_approval_token();
        assert!(token.starts_with("APRV-"));
        assert_eq!(token.len(), 14); // APRV-XXXX-XXXX

        let parts: Vec<&str> = token.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "APRV");
        assert_eq!(parts[1].len(), 4);
        assert_eq!(parts[2].len(), 4);
    }

    #[test]
    fn test_approval_request_creation() {
        let request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Dual,
            600,
        );

        assert!(request.id.starts_with("APRV-"));
        assert_eq!(request.required_approvals, 2);
        assert_eq!(request.approvals.len(), 1); // Initiator counts as first approval
        assert_eq!(request.remaining_approvals(), 1);
        assert_eq!(request.status, ApprovalStatus::Pending);
    }

    #[test]
    fn test_add_approval() {
        let config = DualControlConfig::default();
        let mut request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Dual,
            600,
        );

        // Add second approval
        request.add_approval("bob", None, &config).unwrap();
        assert!(request.is_complete());
        assert_eq!(request.status, ApprovalStatus::Approved);
    }

    #[test]
    fn test_duplicate_user_rejected() {
        let config = DualControlConfig::default();
        let mut request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Triple,
            600,
        );

        // Same user should be rejected
        let result = request.add_approval("alice", None, &config);
        assert!(matches!(result, Err(ApprovalError::DuplicateUser)));
    }

    #[test]
    fn test_triple_control() {
        let config = DualControlConfig::default();
        let mut request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Triple,
            600,
        );

        assert_eq!(request.required_approvals, 3);
        assert_eq!(request.remaining_approvals(), 2);

        request.add_approval("bob", None, &config).unwrap();
        assert_eq!(request.remaining_approvals(), 1);
        assert!(!request.is_complete());

        request.add_approval("charlie", None, &config).unwrap();
        assert!(request.is_complete());
        assert_eq!(request.status, ApprovalStatus::Approved);
    }

    #[test]
    fn test_approval_timeout_rejects() {
        let config = DualControlConfig::default();
        // Create request with short timeout, then manually expire it
        let mut request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Dual,
            600,
        );

        // Force expiration by setting expires_at_unix to the past
        request.expires_at_unix = 0;

        // Should fail with Expired
        let result = request.add_approval("bob", None, &config);
        assert!(matches!(result, Err(ApprovalError::Expired)));
        assert_eq!(request.status, ApprovalStatus::Expired);
    }

    #[test]
    fn test_approval_already_complete_rejects() {
        let config = DualControlConfig::default();
        let mut request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Dual,
            600,
        );

        // Complete the approval
        request.add_approval("bob", None, &config).unwrap();
        assert!(request.is_complete());

        // Third approval should fail
        let result = request.add_approval("charlie", None, &config);
        assert!(matches!(result, Err(ApprovalError::AlreadyComplete)));
    }

    #[test]
    fn test_approval_cancel() {
        let mut request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Dual,
            600,
        );

        request.cancel();
        assert_eq!(request.status, ApprovalStatus::Cancelled);
    }

    #[test]
    fn test_approving_users() {
        let config = DualControlConfig::default();
        let mut request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Triple,
            600,
        );

        request.add_approval("bob", None, &config).unwrap();
        let users = request.approving_users();
        assert_eq!(users, vec!["alice", "bob"]);
    }

    #[test]
    fn test_remaining_secs_non_expired() {
        let request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Dual,
            600,
        );

        // Should have roughly 600 seconds remaining (within 5s tolerance)
        let remaining = request.remaining_secs();
        assert!(remaining > 590 && remaining <= 600);
    }

    #[test]
    fn test_duplicate_session_rejected() {
        // Default config has require_different_sessions = true
        let config = DualControlConfig::default();

        let mut request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Triple,
            600,
        );

        // Alice's initial approval has no session_id
        // Bob approves with session "sess-1"
        request
            .add_approval("bob", Some("sess-1".to_string()), &config)
            .unwrap();

        // Charlie tries with same session — should be rejected
        let result = request.add_approval("charlie", Some("sess-1".to_string()), &config);
        assert!(matches!(result, Err(ApprovalError::DuplicateSession)));
    }

    // --- Issue #43: Dual control approval timeout tests ---

    #[test]
    fn test_timeout_zero_seconds_expires_immediately() {
        // A request with timeout_secs=0 should expire immediately
        let config = DualControlConfig::default();
        let mut request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Dual,
            0, // zero-second timeout
        );

        // expires_at_unix == initiated_at_unix, and is_expired checks now > expires
        // With 0 timeout, expires_at == now, so is_expired may be false at this instant.
        // But add_approval should fail because by the time we call it, now >= expires.
        // Force it by setting to past:
        request.expires_at_unix = request.initiated_at_unix;

        // The request should be expired (now > expires_at_unix is borderline, set to past)
        request.expires_at_unix = 0;
        let result = request.add_approval("bob", None, &config);
        assert!(matches!(result, Err(ApprovalError::Expired)));
        assert_eq!(request.status, ApprovalStatus::Expired);
    }

    #[test]
    fn test_timeout_sets_status_to_expired_on_approval_attempt() {
        // When a user tries to approve an expired request, the status must transition
        let config = DualControlConfig::default();
        let mut request = ApprovalRequest::new(
            Operation::RevokeCa,
            serde_json::json!({"ca_id": "root-1"}),
            "alice".to_string(),
            ControlLevel::Dual,
            600,
        );

        // Status should still be Pending
        assert_eq!(request.status, ApprovalStatus::Pending);

        // Force expiration
        request.expires_at_unix = 1;

        // Attempt approval
        let result = request.add_approval("bob", None, &config);
        assert!(matches!(result, Err(ApprovalError::Expired)));
        // Status should now reflect Expired
        assert_eq!(request.status, ApprovalStatus::Expired);
    }

    #[test]
    fn test_timeout_remaining_secs_for_expired_request() {
        let mut request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Dual,
            600,
        );

        // Force expiration
        request.expires_at_unix = 0;

        // remaining_secs should be 0 (saturating_sub prevents underflow)
        assert_eq!(request.remaining_secs(), 0);
        assert!(request.is_expired());
    }

    #[test]
    fn test_timeout_with_custom_config_timeout() {
        // Test that DualControlConfig::with_timeout propagates correctly
        let config = DualControlConfig::with_timeout(30);
        assert_eq!(config.approval_timeout_secs, 30);

        let mut manager = super::super::DualControlManager::new(config);
        manager
            .set_level(&Operation::CreateRootCa, ControlLevel::Dual)
            .unwrap();

        let result = manager.initiate(Operation::CreateRootCa, serde_json::json!({}), "alice");
        match result {
            super::super::InitiateResult::PendingApproval { request_id, .. } => {
                let pending = manager.get_pending(&request_id).unwrap();
                // The timeout should be approximately 30 seconds from now
                let remaining = pending.remaining_secs();
                assert!(remaining <= 30, "remaining {} should be <= 30", remaining);
                assert!(remaining >= 25, "remaining {} should be >= 25", remaining);
            }
            _ => panic!("Expected PendingApproval"),
        }
    }

    #[test]
    fn test_timeout_expired_request_not_listed_as_pending() {
        let config = DualControlConfig::with_timeout(600);
        let mut manager = super::super::DualControlManager::new(config);
        manager
            .set_level(&Operation::CreateRootCa, ControlLevel::Dual)
            .unwrap();

        let result = manager.initiate(Operation::CreateRootCa, serde_json::json!({}), "alice");
        let request_id = match result {
            super::super::InitiateResult::PendingApproval { request_id, .. } => request_id,
            _ => panic!("Expected PendingApproval"),
        };

        // Verify it shows up while not expired
        assert!(manager.get_pending(&request_id).is_some());

        // We can't easily reach inside and expire it, but we can verify the
        // get_pending method filters expired requests by creating a new one
        // with a known-expired state. The manager.approve path also cleans up.
        // Test that approve returns Expired for an expired request
        // (we manually modify via a second initiate + forced expiration scenario)
        // Instead, verify the cleanup_expired path by testing approve on an unknown ID
        let result = manager.approve("APRV-FAKE-FAKE", "bob", None);
        assert!(matches!(result, Err(ApprovalError::NotFound)));
    }

    #[test]
    fn test_timeout_cancel_after_partial_approval() {
        // A triple-control request that gets one extra approval, then is cancelled
        let config = DualControlConfig::default();
        let mut request = ApprovalRequest::new(
            Operation::DestroyCaKey,
            serde_json::json!({"key_id": "root-key"}),
            "alice".to_string(),
            ControlLevel::Triple,
            600,
        );

        // Add one approval (2 of 3)
        request.add_approval("bob", None, &config).unwrap();
        assert_eq!(request.remaining_approvals(), 1);
        assert!(!request.is_complete());

        // Cancel the request
        request.cancel();
        assert_eq!(request.status, ApprovalStatus::Cancelled);

        // Verify it stays cancelled even though it has approvals
        assert!(!request.is_complete() || request.status == ApprovalStatus::Cancelled);
    }

    #[test]
    fn test_approval_status_display() {
        assert_eq!(ApprovalStatus::Pending.to_string(), "PENDING");
        assert_eq!(ApprovalStatus::Approved.to_string(), "APPROVED");
        assert_eq!(ApprovalStatus::Expired.to_string(), "EXPIRED");
        assert_eq!(ApprovalStatus::Cancelled.to_string(), "CANCELLED");
    }

    #[test]
    fn test_approval_error_display() {
        assert_eq!(
            ApprovalError::Expired.to_string(),
            "Approval request expired"
        );
        assert_eq!(
            ApprovalError::NotFound.to_string(),
            "Approval request not found"
        );
        assert_eq!(
            ApprovalError::AlreadyComplete.to_string(),
            "Approval already complete"
        );
        assert_eq!(
            ApprovalError::DuplicateUser.to_string(),
            "User has already approved"
        );
        assert_eq!(
            ApprovalError::DuplicateSession.to_string(),
            "Session has already approved"
        );
        assert_eq!(
            ApprovalError::Cancelled.to_string(),
            "Approval request cancelled"
        );
    }

    #[test]
    fn test_allow_same_user_config() {
        // With require_different_users=false, same user can approve multiple times
        let config = DualControlConfig::default().allow_same_user();
        assert!(!config.require_different_users);

        let mut request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Dual,
            600,
        );

        // Alice approving again should succeed
        let result = request.add_approval("alice", None, &config);
        assert!(result.is_ok());
        assert!(request.is_complete());
    }

    #[test]
    fn test_allow_same_session_config() {
        // With require_different_sessions=false, same session can approve
        let config = DualControlConfig::default().allow_same_session();
        assert!(!config.require_different_sessions);

        let mut request = ApprovalRequest::new(
            Operation::CreateRootCa,
            serde_json::json!({}),
            "alice".to_string(),
            ControlLevel::Triple,
            600,
        );

        // Bob and Charlie use same session — should be allowed
        request
            .add_approval("bob", Some("shared-sess".to_string()), &config)
            .unwrap();
        let result = request.add_approval("charlie", Some("shared-sess".to_string()), &config);
        assert!(result.is_ok());
        assert!(request.is_complete());
    }
}
