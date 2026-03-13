//! Global configuration for CLI commands.

use pki_client_output::OutputFormat;

/// Global configuration passed to all commands.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Some fields are for future use
pub struct GlobalConfig {
    /// Output format
    pub format: OutputFormat,
    /// Suppress non-essential output
    pub quiet: bool,
    /// Show verbose output
    pub verbose: bool,
    /// Use colored output
    pub colored: bool,
    /// FIPS mode enabled (future use)
    pub fips: bool,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Text,
            quiet: false,
            verbose: false,
            colored: true,
            fips: false,
        }
    }
}
