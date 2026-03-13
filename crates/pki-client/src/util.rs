//! Utility functions for sensitive file operations.

use anyhow::{Context, Result};
use std::path::Path;

/// Write data to a file with restricted permissions (0600) atomically.
///
/// On Unix, uses `OpenOptionsExt::mode()` to set permissions at file creation
/// time, eliminating the TOCTOU race window between `fs::write()` and
/// `set_permissions()`. On non-Unix platforms, falls back to `std::fs::write()`.
///
/// Use this for writing private keys, passphrases, PFX files, and any other
/// sensitive material to disk.
pub fn write_sensitive_file(path: &Path, data: impl AsRef<[u8]>) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to create sensitive file {}", path.display()))?;
        file.write_all(data.as_ref())
            .with_context(|| format!("Failed to write sensitive file {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
            .with_context(|| format!("Failed to write sensitive file {}", path.display()))?;
    }
    Ok(())
}
