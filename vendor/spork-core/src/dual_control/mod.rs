//! Dual Control (Two-Person Rule) System
//!
//! Provides configurable multi-person approval for sensitive operations.
//! - SINGLE: One person can execute
//! - DUAL: Two people required
//! - TRIPLE: Three people required
//!
//! Critical CA operations have a hard minimum of DUAL that cannot be lowered.

pub mod approval;
pub mod config;
pub mod manager;
pub mod operations;

pub use approval::{Approval, ApprovalError, ApprovalRequest, ApprovalStatus, APPROVAL_ALPHABET};
pub use config::{ControlLevel, DualControlConfig};
pub use manager::{ApproveResult, ConfigError, DualControlManager, InitiateResult};
pub use operations::{Operation, OperationCategory};
