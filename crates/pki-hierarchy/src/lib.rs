#![forbid(unsafe_code)]
//! Declarative PKI Hierarchy Builder
//!
//! Build complete CA hierarchies from TOML configuration files.
//! Supports root CAs, intermediate CAs, policy CAs, and issuing CAs
//! with full extension support (CDP, AIA, policies, EKU).

mod builder;
mod config;
mod error;
mod export;
mod preview;
mod topology;
mod validate;

pub use builder::{build_hierarchy, BuildResult, BuiltCa};
pub use config::{
    AiaConfig, CaEntry, CdpConfig, DefaultsConfig, DistributionConfig, HierarchyConfig,
    HierarchyMeta,
};
pub use error::HierarchyError;
pub use export::export_hierarchy;
pub use preview::preview_hierarchy;
pub use topology::{build_tree, HierarchyTree, TreeNode};
pub use validate::{validate_hierarchy, ValidationResult, ValidationWarning};

/// Parse a TOML hierarchy configuration file
pub fn parse_config(toml_str: &str) -> Result<HierarchyConfig, HierarchyError> {
    toml::from_str(toml_str).map_err(HierarchyError::Toml)
}
