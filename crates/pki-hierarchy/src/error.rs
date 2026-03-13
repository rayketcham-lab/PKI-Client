//! Hierarchy error types

/// Errors that can occur during hierarchy operations
#[derive(Debug, thiserror::Error)]
pub enum HierarchyError {
    /// Configuration parsing error
    #[error("configuration error: {0}")]
    Config(String),

    /// Topology error (cycles, missing parents, etc.)
    #[error("topology error: {0}")]
    Topology(String),

    /// Validation error (path length, validity, etc.)
    #[error("validation error: {0}")]
    Validation(String),

    /// Build error during CA ceremony
    #[error("build error: {0}")]
    Build(String),

    /// Export/IO error
    #[error("export error: {0}")]
    Export(String),

    /// TOML parsing error
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Core CA error
    #[error("CA error: {0}")]
    Core(#[from] spork_core::error::Error),
}

pub type Result<T> = std::result::Result<T, HierarchyError>;
