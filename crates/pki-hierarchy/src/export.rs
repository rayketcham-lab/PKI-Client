//! Hierarchy export — write certificates and keys to disk

use std::fs;
use std::path::Path;

use crate::builder::BuildResult;
use crate::error::Result;

/// Export a built hierarchy to disk
///
/// Creates directory structure:
/// ```text
/// {output_dir}/
///   {ca_id}/
///     {ca_id}.cert.pem
///     {ca_id}.cert.der
///     {ca_id}.key.pem     (mode 0600)
///     {ca_id}.chain.pem
/// ```
pub fn export_hierarchy(result: &BuildResult, output_dir: &str) -> Result<Vec<String>> {
    let base = Path::new(output_dir);
    let mut exported_files = Vec::new();

    for id in &result.build_order {
        let ca = &result.cas[id];
        let ca_dir = base.join(id);
        fs::create_dir_all(&ca_dir)?;

        // Write certificate PEM
        let cert_pem_path = ca_dir.join(format!("{}.cert.pem", id));
        fs::write(&cert_pem_path, &ca.certificate_pem)?;
        exported_files.push(cert_pem_path.display().to_string());

        // Write certificate DER
        let cert_der_path = ca_dir.join(format!("{}.cert.der", id));
        fs::write(&cert_der_path, &ca.certificate_der)?;
        exported_files.push(cert_der_path.display().to_string());

        // Write private key PEM (restricted permissions, atomic)
        let key_path = ca_dir.join(format!("{}.key.pem", id));
        write_key_file(&key_path, ca.private_key_pem.as_bytes())?;
        exported_files.push(key_path.display().to_string());

        // Write chain PEM
        let chain_path = ca_dir.join(format!("{}.chain.pem", id));
        fs::write(&chain_path, &ca.chain_pem)?;
        exported_files.push(chain_path.display().to_string());
    }

    Ok(exported_files)
}

/// Write data to a file with restricted permissions (0o600) atomically.
///
/// On Unix, uses `OpenOptionsExt::mode()` to set permissions at file creation
/// time, eliminating the TOCTOU race window between `fs::write()` and
/// `set_permissions()`.
fn write_key_file(path: &Path, data: &[u8]) -> Result<()> {
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
            .open(path)?;
        file.write_all(data)?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, data)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::{BuildResult, BuiltCa};
    use std::collections::HashMap;
    use zeroize::Zeroizing;

    fn mock_build_result() -> BuildResult {
        let mut cas = HashMap::new();
        cas.insert(
            "root".to_string(),
            BuiltCa {
                id: "root".to_string(),
                certificate_pem: "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n"
                    .to_string(),
                certificate_der: vec![0x30, 0x82],
                private_key_pem: Zeroizing::new(
                    "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n".to_string(),
                ),
                chain_pem: "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n"
                    .to_string(),
            },
        );
        BuildResult {
            cas,
            build_order: vec!["root".to_string()],
        }
    }

    #[test]
    fn test_export_key_file_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let result = mock_build_result();
        let output_dir = dir.path().to_str().unwrap();

        export_hierarchy(&result, output_dir).unwrap();

        let key_path = dir.path().join("root").join("root.key.pem");
        assert!(key_path.exists(), "Key file must be created");

        let metadata = std::fs::metadata(&key_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "CA key file must have 0600 permissions, got {:o}",
            mode
        );
    }

    #[test]
    fn test_export_creates_all_expected_files() {
        let dir = tempfile::tempdir().unwrap();
        let result = mock_build_result();
        let output_dir = dir.path().to_str().unwrap();

        let files = export_hierarchy(&result, output_dir).unwrap();
        assert_eq!(
            files.len(),
            4,
            "Expected 4 files per CA (cert.pem, cert.der, key.pem, chain.pem)"
        );

        let root_dir = dir.path().join("root");
        assert!(root_dir.join("root.cert.pem").exists());
        assert!(root_dir.join("root.cert.der").exists());
        assert!(root_dir.join("root.key.pem").exists());
        assert!(root_dir.join("root.chain.pem").exists());
    }
}
