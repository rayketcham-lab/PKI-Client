//! CLI command implementations.

pub mod cert;
pub mod chain;
pub mod completions;
pub mod compliance;
pub mod convert;
pub mod crl;
pub mod csr;
pub mod dane;
pub mod diff;
pub mod key;
pub mod pki;
pub mod probe;
pub mod revoke;
pub mod show;

/// Result of a command execution.
#[derive(Debug)]
pub enum CmdResult {
    /// Command succeeded
    Success,
    /// Command completed with specific exit code
    ExitCode(i32),
}
