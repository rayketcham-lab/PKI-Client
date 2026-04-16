//! Utility functions for sensitive file operations.

use anyhow::{Context, Result};
use std::path::Path;

/// Write data to a file with restricted permissions (0600) atomically.
///
/// On Unix, uses `OpenOptionsExt::mode()` to set permissions at file creation
/// time (no TOCTOU window between `fs::write` and `set_permissions`) and
/// `O_NOFOLLOW` to refuse to follow a symlink at the target path — an attacker
/// who can pre-plant a symlink in a predictable output directory would
/// otherwise redirect the write to an arbitrary file. On non-Unix platforms,
/// falls back to `std::fs::write()`.
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
            .custom_flags(libc::O_NOFOLLOW)
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn refuses_to_follow_symlink_at_target() {
        let dir = tempfile::tempdir().unwrap();
        let decoy = dir.path().join("decoy.txt");
        std::fs::write(&decoy, b"pre-existing").unwrap();

        let target = dir.path().join("key.pem");
        std::os::unix::fs::symlink(&decoy, &target).unwrap();

        let err = write_sensitive_file(&target, b"secret-key-material").unwrap_err();
        let io_err = err
            .chain()
            .find_map(|e| e.downcast_ref::<std::io::Error>())
            .expect("error chain should contain io::Error");
        assert_eq!(
            io_err.raw_os_error(),
            Some(libc::ELOOP),
            "expected ELOOP from O_NOFOLLOW, got: {io_err}"
        );

        let decoy_contents = std::fs::read(&decoy).unwrap();
        assert_eq!(
            decoy_contents, b"pre-existing",
            "decoy file must not be clobbered via symlink"
        );
    }

    #[test]
    fn writes_file_with_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("key.pem");
        write_sensitive_file(&target, b"secret").unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "file must be created with mode 0600");
        assert_eq!(std::fs::read(&target).unwrap(), b"secret");
    }
}
