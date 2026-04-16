//! Backup and restore system for web server configurations.
//!
//! Creates timestamped backups before certificate deployment and supports
//! one-command rollback to restore previous state.

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Maximum number of backups to retain per domain.
const MAX_BACKUPS: usize = 10;

/// A single file that was backed up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackedUpFile {
    /// Original path on the filesystem.
    pub original: PathBuf,
    /// Filename within the backup directory.
    pub backup_name: String,
}

/// Manifest describing a backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Unique backup identifier (timestamp-based).
    pub id: String,
    /// When the backup was created.
    pub timestamp: DateTime<Utc>,
    /// Web server type (apache, nginx, iis).
    pub server_type: String,
    /// Domain this backup is for.
    pub domain: String,
    /// Files that were backed up.
    pub files: Vec<BackedUpFile>,
    /// Path to the backup directory.
    pub backup_dir: PathBuf,
}

impl BackupManifest {
    /// Load a manifest from a backup directory.
    pub fn load(backup_dir: &Path) -> Result<Self> {
        let manifest_path = backup_dir.join("backup.json");
        let data = fs::read_to_string(&manifest_path).with_context(|| {
            format!(
                "Failed to read backup manifest: {}",
                manifest_path.display()
            )
        })?;
        serde_json::from_str(&data).context("Failed to parse backup manifest")
    }

    /// Save the manifest to the backup directory.
    pub fn save(&self) -> Result<()> {
        let manifest_path = self.backup_dir.join("backup.json");
        let data = serde_json::to_string_pretty(self)?;
        fs::write(&manifest_path, data).with_context(|| {
            format!(
                "Failed to write backup manifest: {}",
                manifest_path.display()
            )
        })
    }
}

/// Get the default backup root directory (~/.pki-client/backups/).
pub fn default_backup_root() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow!("Cannot determine home directory"))?;
    Ok(home.join(".pki-client").join("backups"))
}

/// Create a new backup directory with a timestamp-based name.
pub fn create_backup_dir(backup_root: &Path) -> Result<(PathBuf, String)> {
    let now = Utc::now();
    let id = now.format("%Y-%m-%d-%H%M%S").to_string();
    let backup_dir = backup_root.join(&id);

    fs::create_dir_all(&backup_dir).with_context(|| {
        format!(
            "Failed to create backup directory: {}",
            backup_dir.display()
        )
    })?;

    Ok((backup_dir, id))
}

/// Back up a single file into the backup directory.
#[allow(dead_code)]
pub fn backup_file(source: &Path, backup_dir: &Path) -> Result<BackedUpFile> {
    let file_name = source
        .file_name()
        .ok_or_else(|| anyhow!("Invalid source path: {}", source.display()))?
        .to_string_lossy()
        .to_string();

    // Handle duplicate filenames by appending a counter
    let mut dest_name = file_name.clone();
    let mut counter = 1;
    while backup_dir.join(&dest_name).exists() {
        let stem = source
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let ext = source
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy()))
            .unwrap_or_default();
        dest_name = format!("{}-{}{}", stem, counter, ext);
        counter += 1;
    }

    let dest = backup_dir.join(&dest_name);
    fs::copy(source, &dest).with_context(|| {
        format!(
            "Failed to backup {} to {}",
            source.display(),
            dest.display()
        )
    })?;

    Ok(BackedUpFile {
        original: source.to_path_buf(),
        backup_name: dest_name,
    })
}

/// Allowed restore path prefixes. Restore targets must start with one of these
/// to prevent a tampered manifest from overwriting arbitrary system files.
const ALLOWED_RESTORE_PREFIXES: &[&str] = &[
    "/etc/apache2/",
    "/etc/httpd/",
    "/etc/nginx/",
    "/etc/ssl/",
    "/etc/letsencrypt/",
];

/// Validate that a restore target path is within allowed directories.
fn is_allowed_restore_path(path: &Path) -> bool {
    // Skip validation for IIS sentinel paths (not real filesystem paths)
    let s = path.to_string_lossy();
    if s.starts_with("__") && s.ends_with("__") {
        return true;
    }

    // Must be absolute
    if !path.is_absolute() {
        return false;
    }

    // Must start with an allowed prefix
    ALLOWED_RESTORE_PREFIXES
        .iter()
        .any(|prefix| s.starts_with(prefix))
}

/// Restore all files from a backup manifest.
pub fn restore_from_manifest(manifest: &BackupManifest) -> Result<()> {
    // Validate all restore paths before restoring anything
    for file in &manifest.files {
        if !is_allowed_restore_path(&file.original) {
            return Err(anyhow!(
                "Backup contains disallowed restore path: {}. \
                 Only web server config directories are allowed.",
                file.original.display()
            ));
        }
    }

    for file in &manifest.files {
        // Skip IIS sentinel entries (metadata, not files to restore)
        let name = file.original.to_string_lossy();
        if name.starts_with("__") && name.ends_with("__") {
            continue;
        }

        let backup_path = manifest.backup_dir.join(&file.backup_name);
        if !backup_path.exists() {
            return Err(anyhow!("Backup file missing: {}", backup_path.display()));
        }

        // Create parent directory if needed
        if let Some(parent) = file.original.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::copy(&backup_path, &file.original).with_context(|| {
            format!(
                "Failed to restore {} to {}",
                backup_path.display(),
                file.original.display()
            )
        })?;
    }

    Ok(())
}

/// List all available backups, sorted by timestamp (newest first).
pub fn list_backups(backup_root: &Path) -> Result<Vec<BackupManifest>> {
    if !backup_root.exists() {
        return Ok(Vec::new());
    }

    let mut backups = Vec::new();

    for entry in fs::read_dir(backup_root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let manifest_path = path.join("backup.json");
            if manifest_path.exists() {
                if let Ok(manifest) = BackupManifest::load(&path) {
                    backups.push(manifest);
                }
            }
        }
    }

    // Sort newest first
    backups.sort_by_key(|b| std::cmp::Reverse(b.timestamp));
    Ok(backups)
}

/// Clean up old backups, keeping only the most recent MAX_BACKUPS.
pub fn cleanup_old_backups(backup_root: &Path) -> Result<()> {
    let backups = list_backups(backup_root)?;

    if backups.len() <= MAX_BACKUPS {
        return Ok(());
    }

    // Remove oldest backups beyond the limit
    for backup in backups.iter().skip(MAX_BACKUPS) {
        if backup.backup_dir.exists() {
            fs::remove_dir_all(&backup.backup_dir).with_context(|| {
                format!(
                    "Failed to remove old backup: {}",
                    backup.backup_dir.display()
                )
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_backup_dir() {
        let tmp = TempDir::new().unwrap();
        let (dir, id) = create_backup_dir(tmp.path()).unwrap();
        assert!(dir.exists());
        assert!(!id.is_empty());
    }

    #[test]
    fn test_backup_file() {
        let tmp = TempDir::new().unwrap();
        let backup_dir = tmp.path().join("backup");
        fs::create_dir_all(&backup_dir).unwrap();

        // Create a source file
        let source = tmp.path().join("test.conf");
        fs::write(&source, "original content").unwrap();

        // Back it up
        let backed_up = backup_file(&source, &backup_dir).unwrap();
        assert_eq!(backed_up.original, source);

        // Verify backup exists and has correct content
        let backup_path = backup_dir.join(&backed_up.backup_name);
        assert!(backup_path.exists());
        assert_eq!(
            fs::read_to_string(&backup_path).unwrap(),
            "original content"
        );
    }

    #[test]
    fn test_restore_rejects_disallowed_paths() {
        let tmp = TempDir::new().unwrap();
        let backup_dir = tmp.path().join("backup");
        fs::create_dir_all(&backup_dir).unwrap();

        // Create a fake backup file
        fs::write(backup_dir.join("evil.conf"), "pwned").unwrap();

        let manifest = BackupManifest {
            id: "test".to_string(),
            timestamp: Utc::now(),
            server_type: "test".to_string(),
            domain: "example.com".to_string(),
            files: vec![BackedUpFile {
                original: PathBuf::from("/etc/passwd"),
                backup_name: "evil.conf".to_string(),
            }],
            backup_dir,
        };

        let err = restore_from_manifest(&manifest).unwrap_err();
        assert!(err.to_string().contains("disallowed restore path"));
    }

    #[test]
    fn test_allowed_restore_paths() {
        // Valid paths
        assert!(is_allowed_restore_path(Path::new(
            "/etc/apache2/sites-enabled/example.conf"
        )));
        assert!(is_allowed_restore_path(Path::new(
            "/etc/nginx/conf.d/example.conf"
        )));
        assert!(is_allowed_restore_path(Path::new(
            "/etc/ssl/pki-client/example.com/cert.pem"
        )));
        assert!(is_allowed_restore_path(Path::new(
            "/etc/httpd/conf.d/ssl.conf"
        )));
        assert!(is_allowed_restore_path(Path::new(
            "/etc/letsencrypt/live/example.com/cert.pem"
        )));
        // IIS sentinel paths
        assert!(is_allowed_restore_path(Path::new("__iis_binding_info__")));
        assert!(is_allowed_restore_path(Path::new(
            "__iis_cert_thumbprint__"
        )));

        // Disallowed paths
        assert!(!is_allowed_restore_path(Path::new("/etc/passwd")));
        assert!(!is_allowed_restore_path(Path::new("/etc/shadow")));
        assert!(!is_allowed_restore_path(Path::new("/tmp/evil.conf")));
        assert!(!is_allowed_restore_path(Path::new("relative/path.conf")));
        assert!(!is_allowed_restore_path(Path::new("/home/user/.bashrc")));
    }

    #[test]
    fn test_manifest_save_load() {
        let tmp = TempDir::new().unwrap();
        let backup_dir = tmp.path().join("backup");
        fs::create_dir_all(&backup_dir).unwrap();

        let manifest = BackupManifest {
            id: "2026-02-11-120000".to_string(),
            timestamp: Utc::now(),
            server_type: "apache".to_string(),
            domain: "example.com".to_string(),
            files: vec![BackedUpFile {
                original: PathBuf::from("/etc/apache2/sites-enabled/example.conf"),
                backup_name: "example.conf".to_string(),
            }],
            backup_dir: backup_dir.clone(),
        };

        manifest.save().unwrap();

        let loaded = BackupManifest::load(&backup_dir).unwrap();
        assert_eq!(loaded.id, manifest.id);
        assert_eq!(loaded.domain, manifest.domain);
        assert_eq!(loaded.files.len(), 1);
    }

    #[test]
    fn test_list_backups_empty() {
        let tmp = TempDir::new().unwrap();
        let backups = list_backups(tmp.path()).unwrap();
        assert!(backups.is_empty());
    }

    #[test]
    fn test_list_backups_nonexistent_dir() {
        let backups = list_backups(Path::new("/nonexistent/path")).unwrap();
        assert!(backups.is_empty());
    }
}
