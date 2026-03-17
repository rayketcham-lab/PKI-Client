//! Dual control manager

use super::{
    ApprovalError, ApprovalRequest, ApprovalStatus, ControlLevel, DualControlConfig, Operation,
};
use std::collections::HashMap;

/// Manages dual control configuration and pending approvals
pub struct DualControlManager {
    /// Configuration
    config: DualControlConfig,
    /// Per-operation control level overrides
    operation_levels: HashMap<String, ControlLevel>,
    /// Pending approval requests
    pending: HashMap<String, ApprovalRequest>,
}

impl DualControlManager {
    /// Create a new dual control manager
    pub fn new(config: DualControlConfig) -> Self {
        Self {
            config,
            operation_levels: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Load operation levels from storage
    pub fn load_operation_levels(&mut self, levels: HashMap<String, ControlLevel>) {
        self.operation_levels = levels;
    }

    /// Get control level for an operation
    pub fn get_level(&self, op: &Operation) -> ControlLevel {
        // Check operation-specific override
        if let Some(level) = self.operation_levels.get(op.name()) {
            return *level;
        }

        // Use category default
        op.category().default_level()
    }

    /// Set control level for an operation (validates against category limits)
    pub fn set_level(&mut self, op: &Operation, level: ControlLevel) -> Result<(), ConfigError> {
        let category = op.category();
        let min = category.minimum_level();
        let max = category.maximum_level();

        let level_num = level.required_approvers();
        let min_num = min.required_approvers();
        let max_num = max.required_approvers();

        if level_num < min_num {
            return Err(ConfigError::BelowMinimum {
                operation: op.name().to_string(),
                minimum: min,
                requested: level,
            });
        }

        if level_num > max_num {
            return Err(ConfigError::AboveMaximum {
                operation: op.name().to_string(),
                maximum: max,
                requested: level,
            });
        }

        self.operation_levels.insert(op.name().to_string(), level);
        Ok(())
    }

    /// Check if operation requires multi-person approval
    pub fn requires_approval(&self, op: &Operation) -> bool {
        self.get_level(op).required_approvers() > 1
    }

    /// Initiate an operation
    pub fn initiate(
        &mut self,
        operation: Operation,
        details: serde_json::Value,
        user: &str,
    ) -> InitiateResult {
        // Clean expired
        self.cleanup_expired();

        let level = self.get_level(&operation);

        // If single control, execute immediately
        if level == ControlLevel::Single {
            return InitiateResult::Immediate;
        }

        let request = ApprovalRequest::new(
            operation,
            details,
            user.to_string(),
            level,
            self.config.approval_timeout_secs,
        );

        let id = request.id.clone();
        let remaining = request.remaining_approvals();

        self.pending.insert(id.clone(), request);

        InitiateResult::PendingApproval {
            request_id: id,
            remaining_approvals: remaining,
        }
    }

    /// Approve a pending request
    pub fn approve(
        &mut self,
        request_id: &str,
        user: &str,
        session_id: Option<String>,
    ) -> Result<ApproveResult, ApprovalError> {
        self.cleanup_expired();

        let request = self
            .pending
            .get_mut(request_id)
            .ok_or(ApprovalError::NotFound)?;

        if request.status == ApprovalStatus::Cancelled {
            return Err(ApprovalError::Cancelled);
        }

        request.add_approval(user, session_id, &self.config)?;

        if request.is_complete() {
            let completed = self
                .pending
                .remove(request_id)
                .expect("request exists — verified by get_mut above");
            Ok(ApproveResult::Complete(completed))
        } else {
            Ok(ApproveResult::Pending {
                remaining: request.remaining_approvals(),
            })
        }
    }

    /// Cancel a pending request
    pub fn cancel(&mut self, request_id: &str, user: &str) -> Result<(), ApprovalError> {
        let request = self
            .pending
            .get_mut(request_id)
            .ok_or(ApprovalError::NotFound)?;

        // Only initiator can cancel
        if request.initiated_by != user {
            return Err(ApprovalError::NotFound); // Don't leak existence
        }

        request.cancel();
        self.pending.remove(request_id);
        Ok(())
    }

    /// Get pending request by ID
    pub fn get_pending(&self, request_id: &str) -> Option<&ApprovalRequest> {
        self.pending.get(request_id).filter(|r| !r.is_expired())
    }

    /// List all pending requests
    pub fn list_pending(&self) -> Vec<&ApprovalRequest> {
        self.pending
            .values()
            .filter(|r| !r.is_expired() && r.status == ApprovalStatus::Pending)
            .collect()
    }

    /// List pending requests for a specific user
    pub fn list_pending_for_user(&self, user: &str) -> Vec<&ApprovalRequest> {
        self.pending
            .values()
            .filter(|r| {
                !r.is_expired()
                    && r.status == ApprovalStatus::Pending
                    && (r.initiated_by == user || !r.approvals.iter().any(|a| a.user == user))
            })
            .collect()
    }

    /// Get pending requests that user can approve
    pub fn actionable_for_user(&self, user: &str) -> Vec<&ApprovalRequest> {
        self.pending
            .values()
            .filter(|r| {
                !r.is_expired()
                    && r.status == ApprovalStatus::Pending
                    && !r.approvals.iter().any(|a| a.user == user)
            })
            .collect()
    }

    /// Get configuration
    pub fn config(&self) -> &DualControlConfig {
        &self.config
    }

    /// Get all operation level overrides
    pub fn operation_levels(&self) -> &HashMap<String, ControlLevel> {
        &self.operation_levels
    }

    /// Cleanup expired requests
    fn cleanup_expired(&mut self) {
        let expired_ids: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, r)| r.is_expired())
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired_ids {
            if let Some(mut request) = self.pending.remove(&id) {
                request.status = ApprovalStatus::Expired;
                // Could log or store expired requests here
            }
        }
    }
}

/// Result of initiating an operation
pub enum InitiateResult {
    /// Operation can proceed immediately (single control)
    Immediate,
    /// Requires additional approval
    PendingApproval {
        /// Request ID for approval
        request_id: String,
        /// Number of approvals still needed
        remaining_approvals: usize,
    },
}

/// Result of approving a request
pub enum ApproveResult {
    /// All approvals received, operation can proceed
    Complete(ApprovalRequest),
    /// More approvals needed
    Pending {
        /// Number of approvals still needed
        remaining: usize,
    },
}

/// Configuration error
#[derive(Debug)]
pub enum ConfigError {
    /// Cannot set below category minimum
    BelowMinimum {
        /// Operation name
        operation: String,
        /// Minimum level
        minimum: ControlLevel,
        /// Requested level
        requested: ControlLevel,
    },
    /// Cannot set above category maximum
    AboveMaximum {
        /// Operation name
        operation: String,
        /// Maximum level
        maximum: ControlLevel,
        /// Requested level
        requested: ControlLevel,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::BelowMinimum {
                operation,
                minimum,
                requested,
            } => {
                write!(
                    f,
                    "Cannot set {} below {} (requested {})",
                    operation, minimum, requested
                )
            }
            ConfigError::AboveMaximum {
                operation,
                maximum,
                requested,
            } => {
                write!(
                    f,
                    "Cannot set {} above {} (requested {})",
                    operation, maximum, requested
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_control_immediate() {
        let mut manager = DualControlManager::new(DualControlConfig::default());

        // View operations are single control
        let result = manager.initiate(Operation::ViewCertificate, serde_json::json!({}), "alice");

        assert!(matches!(result, InitiateResult::Immediate));
    }

    #[test]
    fn test_dual_control_pending() {
        let mut manager = DualControlManager::new(DualControlConfig::default());

        // Critical CA operations require approval
        let result = manager.initiate(Operation::CreateRootCa, serde_json::json!({}), "alice");

        match result {
            InitiateResult::PendingApproval {
                request_id,
                remaining_approvals,
            } => {
                assert!(request_id.starts_with("APRV-"));
                assert_eq!(remaining_approvals, 2); // TRIPLE - 1 (initiator)
            }
            _ => panic!("Expected pending approval"),
        }
    }

    #[test]
    fn test_approval_flow() {
        let mut manager = DualControlManager::new(DualControlConfig::default());

        // Set to DUAL for easier testing
        manager
            .set_level(&Operation::CreateRootCa, ControlLevel::Dual)
            .unwrap();

        let result = manager.initiate(Operation::CreateRootCa, serde_json::json!({}), "alice");

        let request_id = match result {
            InitiateResult::PendingApproval { request_id, .. } => request_id,
            _ => panic!("Expected pending"),
        };

        // Bob approves
        let result = manager.approve(&request_id, "bob", None).unwrap();
        assert!(matches!(result, ApproveResult::Complete(_)));
    }

    #[test]
    fn test_cannot_lower_critical_below_dual() {
        let mut manager = DualControlManager::new(DualControlConfig::default());

        let result = manager.set_level(&Operation::CreateRootCa, ControlLevel::Single);
        assert!(matches!(result, Err(ConfigError::BelowMinimum { .. })));
    }

    #[test]
    fn test_can_set_critical_to_dual() {
        let mut manager = DualControlManager::new(DualControlConfig::default());

        let result = manager.set_level(&Operation::CreateRootCa, ControlLevel::Dual);
        assert!(result.is_ok());
        assert_eq!(
            manager.get_level(&Operation::CreateRootCa),
            ControlLevel::Dual
        );
    }

    #[test]
    fn test_cancel_request() {
        let mut manager = DualControlManager::new(DualControlConfig::default());

        let result = manager.initiate(Operation::CreateRootCa, serde_json::json!({}), "alice");

        let request_id = match result {
            InitiateResult::PendingApproval { request_id, .. } => request_id,
            _ => panic!("Expected pending"),
        };

        // Only initiator can cancel
        assert!(manager.cancel(&request_id, "bob").is_err());
        assert!(manager.cancel(&request_id, "alice").is_ok());
        assert!(manager.get_pending(&request_id).is_none());
    }

    #[test]
    fn test_actionable_for_user() {
        let mut manager = DualControlManager::new(DualControlConfig::default());

        manager.initiate(Operation::CreateRootCa, serde_json::json!({}), "alice");

        // Alice can't approve her own request (already did)
        let actionable = manager.actionable_for_user("alice");
        assert!(actionable.is_empty());

        // Bob can approve
        let actionable = manager.actionable_for_user("bob");
        assert_eq!(actionable.len(), 1);
    }
}
