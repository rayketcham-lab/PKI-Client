//! CA Owner Recovery System
//!
//! Provides emergency access using Shamir secret sharing.
//! - 3 shares generated during first ceremony
//! - Level 1 (2/3): Operational recovery
//! - Level 2 (3/3): Administrative recovery

pub mod levels;
pub mod session;
pub mod shares;

pub use levels::{ConfigError, RecoveryAction, RecoveryConfig, RecoveryLevel};
pub use session::{RecoverySession, RecoverySessionManager, SessionError};
pub use shares::{RecoveryShare, RecoveryShares, ShareError, SHARE_ALPHABET};
